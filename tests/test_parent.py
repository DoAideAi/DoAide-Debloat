"""Behaviour tests for parent mode (tools/parent.py) against a scripted fake phone.

Run:  python3 -m unittest discover -s tests -v     (stdlib only; pytest also works)
"""
from __future__ import annotations

import contextlib
import io
import json
import re
import shlex
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "tools"))
sys.path.insert(0, str(ROOT / "tests"))

import debloat  # noqa: E402
import parent  # noqa: E402
import parentcard  # noqa: E402
from test_debloat import BASE_PACKAGES, HOME, IME, SAMSUNG_PROPS, SMS, FakeDevice  # noqa: E402

PLAY = "com.android.vending"
PKG_INSTALLER = "com.google.android.packageinstaller"
INSTALL = "android.permission.REQUEST_INSTALL_PACKAGES"
READ_SMS = "android.permission.READ_SMS"
RECEIVE_SMS = "android.permission.RECEIVE_SMS"
CONTACTS = "android.permission.READ_CONTACTS"
CALL_LOG = "android.permission.READ_CALL_LOG"
RUNTIME = {READ_SMS, RECEIVE_SMS, CONTACTS, CALL_LOG, "android.permission.SEND_SMS"}

WHATSAPP = "com.whatsapp"
CHROME = "com.android.chrome"
UPDATER = "com.oem.appupdater"
ANYDESK = "com.anydesk.anydeskandroid"
LOAN = "com.quickcash.loan"
BANK = "com.examplebank.mobile"
HELPER = "com.helper.cleaner"
GAME = "com.fun.game"
A11Y = f"{HELPER}/{HELPER}.A11yService"
LISTENER = f"{HELPER}/{HELPER}.OtpListener$Service"      # `$` as in real component names
ADMIN = f"{HELPER}/{HELPER}.AdminReceiver"
TALKBACK = "com.google.android.marvin.talkback/com.google.android.marvin.talkback.TalkBackService"
MUTATING = ("pm disable-user", "pm enable", "pm uninstall", "pm revoke", "pm grant", "appops set",
            "settings put", "settings delete", "cmd notification", "cmd package install-existing")


def sh_expand(cmd: str) -> str:
    """What the phone's /system/bin/sh does to `$Name` outside single quotes: expands it to ''."""
    out, quoted, i = [], False, 0
    while i < len(cmd):
        ch = cmd[i]
        if ch == "'":
            quoted = not quoted
        elif ch == "$" and not quoted:
            match = re.match(r"\$[A-Za-z_][A-Za-z0-9_]*", cmd[i:])
            if match:
                i += len(match.group(0))
                continue
        out.append(ch)
        i += 1
    return "".join(out)


def mutating(cmd: str) -> bool:
    return any(verb in cmd for verb in MUTATING)


def mum_apps():
    return {
        WHATSAPP: {"installer": PLAY, "requested": [INSTALL, CONTACTS], "granted": [CONTACTS]},
        ANYDESK: {"installer": PLAY},
        LOAN: {"installer": PKG_INSTALLER, "initiator": WHATSAPP,
               "requested": [READ_SMS, CONTACTS, CALL_LOG], "granted": [READ_SMS, CONTACTS]},
        BANK: {"installer": PLAY, "requested": [READ_SMS, RECEIVE_SMS], "granted": [READ_SMS, RECEIVE_SMS]},
        HELPER: {"installer": None},
        GAME: {"installer": PKG_INSTALLER, "initiator": CHROME, "requested": [INSTALL]},
        CHROME: {"system": True, "requested": [INSTALL]},
        UPDATER: {"system": True, "requested": [INSTALL]},
        PLAY: {"system": True, "requested": [INSTALL]},
    }


class FakePhone(FakeDevice):
    """FakeDevice plus what parent mode reads and changes: installers, permissions, app ops,
    accessibility / notification access, device admins, settings, WhatsApp storage."""

    def __init__(self, apps=None, install_allowed=(), uid_mode=(), accessibility=(), listeners=(),
                 admins=(), consent="1", patch="2026-08-01", sdk="34", whatsapp_kb=None,
                 ignore_appops_set=(), **kw):
        apps = mum_apps() if apps is None else apps
        packages = list(BASE_PACKAGES) + [p for p in apps if p not in BASE_PACKAGES]
        props = dict(SAMSUNG_PROPS)
        props.update({"ro.build.version.security_patch": patch, "ro.build.version.sdk": sdk})
        super().__init__(props=props, packages=packages, **kw)
        self.apps = {p: {"system": bool(a.get("system")), "installer": a.get("installer"),
                         "initiator": a.get("initiator"), "requested": set(a.get("requested", ())),
                         "granted": set(a.get("granted", ()))} for p, a in apps.items()}
        # Android keeps a package mode and a uid mode; a uid mode that is set wins.
        self.modes = {p: "allow" for p in install_allowed if p not in uid_mode}
        self.uid_modes = {p: "allow" for p in install_allowed if p in uid_mode}
        self.ignore_appops_set = set(ignore_appops_set)
        self.secure = {"default_input_method": f"{IME}/.service.HoneyBoardService",
                       "sms_default_application": SMS}
        if accessibility:
            self.secure["enabled_accessibility_services"] = ":".join(accessibility)
            self.secure["accessibility_enabled"] = "1"
        if listeners:
            self.secure["enabled_notification_listeners"] = ":".join(listeners)
        self.global_ = {"adb_enabled": "1", "adb_wifi_enabled": "0", "development_settings_enabled": "1"}
        if consent is not None:
            self.global_["package_verifier_user_consent"] = consent
        self.admins = list(admins)
        self.whatsapp_kb = dict(whatsapp_kb or {})
        self.shell_overrides = {}          # exact command -> output, for odd firmware answers

    # -- adb transport: once USB debugging is off the phone is gone
    def __call__(self, args):
        if self.global_.get("adb_enabled") != "1":
            args = list(args)
            if args[-2:] == ["devices", "-l"]:
                return 0, "List of devices attached\n\n"
            return 1, "error: no devices/emulators found\n"
        return super().__call__(args)

    def effective_mode(self, pkg):
        return self.uid_modes.get(pkg) or self.modes.get(pkg) or "default"

    def third_party(self):
        return [p for p in self.installed() if p in self.apps and not self.apps[p]["system"]]

    def store(self, namespace):
        return self.secure if namespace == "secure" else self.global_ if namespace == "global" else {}

    def dump_block(self, pkg, requested=None):
        app = self.apps.get(pkg, {"installer": None, "initiator": None, "requested": set(), "granted": set()})
        requested = app["requested"] if requested is None else requested
        lines = [f"  Package [{pkg}] (4f2a1c):", "    userId=10234", f"    pkg=Package{{4f2a1c {pkg}}}",
                 "    firstInstallTime=2026-01-02 10:00:00"]
        if app["installer"]:
            lines.append(f"    installerPackageName={app['installer']}")
        if app.get("initiator"):
            lines.append(f"    installInitiatingPackageName={app['initiator']}")
        if requested:
            lines.append("    requested permissions:")
            lines += [f"      {perm}" + (": restricted=true" if "SMS" in perm or "CALL_LOG" in perm else "")
                      for perm in sorted(requested)]
        lines += ["    install permissions:", "      android.permission.INTERNET: granted=true",
                  "    User 0: ceDataInode=1 installed=true hidden=false suspended=false stopped=false enabled=0",
                  "      gids=[3003]"]
        runtime = sorted(p for p in requested if p in RUNTIME)
        if runtime:
            lines.append("      runtime permissions:")
            for perm in runtime:
                granted = "true" if perm in app["granted"] else "false"
                lines.append(f"        {perm}: granted={granted}, flags=[ USER_SET ]")
        return lines

    def shell(self, cmd):
        if cmd in self.shell_overrides:
            self.log.append(cmd)
            return 0, self.shell_overrides[cmd]
        expanded = sh_expand(cmd)
        parts = shlex.split(expanded)
        if parts[:4] == ["pm", "list", "packages", "-3"]:
            self.log.append(cmd)
            if "-i" in parts:
                return 0, "".join(f"package:{p}  installer={self.apps[p]['installer'] or 'null'}\r\n"
                                  for p in self.third_party())
            return 0, "".join(f"package:{p}\r\n" for p in self.third_party())
        if parts[:3] == ["dumpsys", "package", "packages"]:
            self.log.append(cmd)
            lines = ["Packages:"]
            for pkg in self.installed():
                lines += self.dump_block(pkg)
            lines += ["", "Hidden system packages:"] + self.dump_block(CHROME, requested=set()) + [""]
            return 0, "\n".join(lines) + "\n"
        if parts[:2] == ["dumpsys", "package"] and len(parts) == 3:
            self.log.append(cmd)
            return 0, "\n".join(["Activity Resolver Table:", "  Non-Data Actions:", "", "Packages:"]
                                + self.dump_block(parts[2])) + "\n"
        if parts[:2] == ["dumpsys", "device_policy"]:
            self.log.append(cmd)
            lines = ["Current Device Policy Manager state:", "  Immutable state:", "    mHasFeature=true", "",
                     "  Enabled Device Admins (User 0, provisioningState: 0):"]
            for comp in self.admins:
                lines += [f"    {comp}:", "      uid=10150", "      testOnlyAdmin=false", "      policies:",
                          "        force-lock"]
            lines += ["", "  mPasswordOwner=-1"]
            return 0, "\n".join(lines) + "\n"
        if parts[:2] == ["appops", "get"]:
            self.log.append(cmd)
            pkg, op = parts[2], parts[3]
            lines = []
            if pkg in self.uid_modes:
                lines.append(f"Uid mode: {op}: {self.uid_modes[pkg]}")
            if pkg in self.modes:
                lines.append(f"{op}: {self.modes[pkg]}; time=+2d1h ago")
            if not lines:
                return 0, "No operations.\nDefault mode: default\n"
            return 0, "\n".join(lines) + "\n"
        if parts[:2] == ["appops", "set"]:
            self.log.append(cmd)
            args = parts[2:]
            target = self.modes
            if args[0] == "--uid":
                target, args = self.uid_modes, args[1:]
            pkg, mode = args[0], args[2]
            if pkg not in self.ignore_appops_set:
                if mode == "default":
                    target.pop(pkg, None)
                else:
                    target[pkg] = mode
            return 0, ""
        if parts[:2] == ["settings", "get"]:
            self.log.append(cmd)
            return 0, self.store(parts[2]).get(parts[3], "null") + "\n"
        if parts[:2] == ["settings", "put"]:
            self.log.append(cmd)
            self.store(parts[2])[parts[3]] = parts[4] if len(parts) > 4 else ""
            return 0, ""
        if parts[:2] == ["settings", "delete"]:
            self.log.append(cmd)
            existed = self.store(parts[2]).pop(parts[3], None) is not None
            return 0, f"Deleted {int(existed)} rows\n"
        if parts[:2] == ["cmd", "notification"]:
            self.log.append(cmd)
            component = parts[3]
            entries = [e for e in self.secure.get("enabled_notification_listeners", "").split(":") if e]
            if parts[2] == "disallow_listener":
                entries = [e for e in entries if e != component]
            elif parts[2] == "allow_listener" and component not in entries:
                entries.append(component)
            self.secure["enabled_notification_listeners"] = ":".join(entries)
            return 0, ""
        if parts[:2] in (["pm", "revoke"], ["pm", "grant"]):
            self.log.append(cmd)
            pkg, perm = parts[2], parts[3]
            granted = self.apps[pkg]["granted"]
            if parts[1] == "revoke":
                granted.discard(perm)
            else:
                granted.add(perm)
            return 0, ""
        if parts[0] == "du":
            self.log.append(cmd)
            if not self.whatsapp_kb:
                return 1, ""
            base = "/storage/emulated/0/Android/media/com.whatsapp/WhatsApp/Media"
            return 0, "".join(f"{kb}\t{base}/{folder}\n" for folder, kb in self.whatsapp_kb.items())
        return super().shell(cmd)


def mum_phone(**kw) -> FakePhone:
    defaults: dict = dict(install_allowed=(WHATSAPP, CHROME, UPDATER, PLAY), uid_mode=(WHATSAPP,),
                    accessibility=(TALKBACK, A11Y), listeners=(LISTENER, "com.oplus.notificationmanager"),
                    admins=(ADMIN, "com.google.android.gms/.mdm.receivers.MdmDeviceAdminReceiver"),
                    whatsapp_kb={"WhatsApp Images": 2_500_000, "WhatsApp Video": 5_200_000,
                                 "WhatsApp Animated Gifs": 400_000})
    defaults.update(kw)
    return FakePhone(**defaults)


def make(fake) -> debloat.Adb:
    return debloat.Adb(runner=fake)


def all_fixes(audit):
    return {fix.id: fix for finding in audit.findings for fix in finding.fixes}


def findings(audit, check):
    return [f for f in audit.findings if f.check == check]


TODAY = "2026-10-30"


class AuditTests(unittest.TestCase):
    def audit(self, fake):
        return parent.run_audit(make(fake), today=TODAY)

    def test_audit_only_reads(self):
        fake = mum_phone()
        self.audit(fake)
        self.assertEqual([c for c in fake.log if mutating(c)], [])

    def test_remote_control_app_is_flagged_for_the_owner_to_decide(self):
        audit = self.audit(mum_phone())
        (remote,) = findings(audit, "remote-access")
        self.assertEqual(remote.severity, "high")
        self.assertIn("AnyDesk", remote.title)
        self.assertIn("installed by Google Play Store", remote.evidence)    # a name, not a package
        fix = all_fixes(audit)[f"disable:{ANYDESK}"]
        self.assertFalse(fix.recommended)     # some families use it to help; never switched off unasked

    def test_apps_allowed_to_install_apks_get_a_recommended_deny(self):
        fixes = all_fixes(self.audit(mum_phone()))
        self.assertTrue(fixes[f"install:{WHATSAPP}"].recommended)   # "Uid mode: ..." output parsed too
        self.assertTrue(fixes[f"install:{CHROME}"].recommended)     # a browser, even as a system app
        self.assertFalse(fixes[f"install:{UPDATER}"].recommended)   # unknown system app: owner decides
        self.assertNotIn(f"install:{PLAY}", fixes)                  # installing apps is a store's job
        self.assertNotIn(f"install:{GAME}", fixes)                  # requests it, but was never allowed

    def test_sideloaded_app_reading_sms_is_high_and_store_apps_keep_their_sms_access(self):
        audit = self.audit(mum_phone())
        loan = next(f for f in findings(audit, "sideloaded") if f.subject == LOAN)
        self.assertEqual(loan.severity, "high")
        self.assertIn("WhatsApp", loan.title + " ".join(loan.evidence))      # who installed it
        self.assertEqual({fix.id for fix in loan.fixes},
                         {f"revoke:{LOAN}:READ_SMS", f"revoke:{LOAN}:READ_CONTACTS", f"disable:{LOAN}"})
        self.assertTrue(all(not fix.recommended for fix in loan.fixes))
        self.assertFalse(any(BANK in fix_id for fix_id in all_fixes(audit)))  # UPI/bank apps need SMS

    def test_harmless_sideloaded_app_is_low(self):
        audit = self.audit(mum_phone())
        game = next(f for f in findings(audit, "sideloaded") if f.subject == GAME)
        self.assertEqual(game.severity, "low")
        self.assertEqual([fix.id for fix in game.fixes], [f"disable:{GAME}"])

    def test_third_party_accessibility_notification_and_admin_access(self):
        audit = self.audit(mum_phone())
        (a11y,) = findings(audit, "accessibility")              # TalkBack (not third-party) ignored
        self.assertEqual((a11y.subject, a11y.severity), (A11Y, "high"))
        self.assertFalse(all_fixes(audit)[f"accessibility:{A11Y}"].recommended)
        (listener,) = findings(audit, "notification-access")     # the OEM's own entry ignored
        self.assertEqual(listener.subject, LISTENER)
        self.assertIn(f"listener:{LISTENER}", all_fixes(audit))
        (admin,) = findings(audit, "device-admin")              # Find My Device (system) ignored
        self.assertEqual((admin.subject, admin.fixes), (ADMIN, []))
        self.assertTrue(admin.by_hand)
        helper = next(f for f in findings(audit, "sideloaded") if f.subject == HELPER)
        self.assertEqual(helper.severity, "high")               # special access makes it high

    def test_play_protect_patch_age_and_whatsapp_storage(self):
        quiet = self.audit(mum_phone())
        self.assertEqual(findings(quiet, "play-protect") + findings(quiet, "security-patch"), [])
        audit = self.audit(mum_phone(consent="-1", patch="2024-01-05"))
        (protect,) = findings(audit, "play-protect")
        self.assertEqual(protect.severity, "high")
        self.assertTrue(protect.by_hand)
        (patch,) = findings(audit, "security-patch")
        self.assertEqual(patch.severity, "medium")
        self.assertIn("2024-01", patch.title)
        (whatsapp,) = findings(audit, "whatsapp-storage")
        self.assertIn("8.3 GB", whatsapp.title)               # 8,100,000 KiB from du -sk
        self.assertEqual(audit.stats["whatsapp_bytes"], 8_100_000 * 1024)

    def test_legacy_unknown_sources_only_before_android_8(self):
        old = mum_phone(sdk="25")
        old.secure["install_non_market_apps"] = "1"
        fixes = all_fixes(self.audit(old))
        self.assertTrue(fixes["unknown-sources:legacy"].recommended)
        self.assertFalse(any(fix_id.startswith("install:") for fix_id in fixes))   # no per-app op before 8
        new = mum_phone()
        new.secure["install_non_market_apps"] = "1"                 # meaningless on Android 8+
        self.assertNotIn("unknown-sources:legacy", all_fixes(self.audit(new)))

    def test_protected_apps_get_no_disable_or_revoke_fix(self):
        apps = mum_apps()
        apps[SMS] = {"installer": PKG_INSTALLER, "requested": [READ_SMS], "granted": [READ_SMS]}
        audit = self.audit(mum_phone(apps=apps))
        self.assertFalse(any(SMS in fix_id for fix_id in all_fixes(audit)))
        (sms_app,) = findings(audit, "sms-app")
        self.assertEqual(sms_app.severity, "high")
        self.assertTrue(sms_app.by_hand)

    def test_unreadable_app_details_are_reported_never_treated_as_all_clear(self):
        fake = mum_phone()
        fake.dump_block = lambda pkg, requested=None: []         # a dumpsys format we cannot read
        (incomplete,) = findings(self.audit(fake), "audit-incomplete")
        self.assertEqual(incomplete.severity, "high")
        self.assertTrue(incomplete.by_hand)
        unknown = mum_phone()
        unknown.shell_overrides = {f"appops get {CHROME} {INSTALL.rsplit('.', 1)[-1]}": "Error: unknown command"}
        (incomplete,) = findings(self.audit(unknown), "audit-incomplete")
        self.assertIn("Chrome", " ".join(incomplete.evidence))
        self.assertEqual(findings(self.audit(mum_phone()), "audit-incomplete"), [])

    def test_audit_round_trips_through_json_without_identifiers(self):
        audit = self.audit(mum_phone())
        text = json.dumps(parent.audit_to_dict(audit))
        self.assertNotIn("FAKE123", text)
        back = parent.audit_from_dict(json.loads(text))
        self.assertEqual(sorted(all_fixes(back)), sorted(all_fixes(audit)))
        self.assertEqual(back.device["serial_hash"], audit.device["serial_hash"])


class ApplyTests(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.dir = Path(tmp.name)
        self.record_path = self.dir / "record.json"

    def audit(self, fake):
        return parent.run_audit(make(fake), today=TODAY)

    def apply(self, fake, audit, fix=(), skip=()):
        return parent.apply_audit(make(fake), audit, fix_ids=fix, skip_ids=skip,
                                  record_path=self.record_path)

    def test_apply_makes_only_the_recommended_changes_by_default(self):
        fake = mum_phone()
        record = self.apply(fake, self.audit(fake))
        self.assertEqual(fake.effective_mode(WHATSAPP), "deny")   # its allow was a uid mode
        self.assertEqual(fake.effective_mode(CHROME), "deny")
        self.assertEqual(fake.effective_mode(UPDATER), "allow")   # the owner's call
        self.assertTrue(fake.packages[ANYDESK]["enabled"])        # never switched off unasked
        self.assertIn(READ_SMS, fake.apps[LOAN]["granted"])
        self.assertEqual(sorted(c.id for c in record.changes if c.status == "done"),
                         [f"install:{CHROME}", f"install:{WHATSAPP}"])
        on_disk = json.loads(self.record_path.read_text())
        self.assertEqual((on_disk["kind"], len(on_disk["changes"])), ("parent-record", 2))

    def test_named_changes_apply_and_restore_puts_the_phone_back_exactly(self):
        fake = mum_phone()
        a11y_before = fake.secure["enabled_accessibility_services"]
        listeners_before = fake.secure["enabled_notification_listeners"]
        record = self.apply(fake, self.audit(fake), fix=[
            f"disable:{ANYDESK}", f"revoke:{LOAN}:READ_SMS", f"accessibility:{A11Y}", f"listener:{LISTENER}"])
        self.assertEqual([c.status for c in record.changes], ["done"] * 6, record.changes)
        self.assertFalse(fake.packages[ANYDESK]["enabled"])
        self.assertNotIn(READ_SMS, fake.apps[LOAN]["granted"])
        self.assertIn(CONTACTS, fake.apps[LOAN]["granted"])                  # only what was named
        self.assertEqual(fake.secure["enabled_accessibility_services"], TALKBACK)
        self.assertEqual(fake.secure["enabled_notification_listeners"], "com.oplus.notificationmanager")
        for cmd in fake.log:                                                 # one change per call
            self.assertLessEqual(sum(cmd.count(verb) for verb in MUTATING), 1, cmd)

        results = parent.restore_record(make(fake), record)
        self.assertEqual([r.status for r in results], ["done"] * 6, results)
        self.assertTrue(fake.packages[ANYDESK]["enabled"])
        self.assertIn(READ_SMS, fake.apps[LOAN]["granted"])
        self.assertEqual((fake.uid_modes.get(WHATSAPP), fake.modes.get(WHATSAPP)), ("allow", None))
        self.assertEqual((fake.uid_modes.get(CHROME), fake.modes.get(CHROME)), (None, "allow"))
        self.assertEqual(set(fake.secure["enabled_accessibility_services"].split(":")),
                         set(a11y_before.split(":")))
        self.assertEqual(set(fake.secure["enabled_notification_listeners"].split(":")),
                         set(listeners_before.split(":")))

    def test_legacy_unknown_sources_switch_off_and_back(self):
        fake = mum_phone(sdk="25")
        fake.secure["install_non_market_apps"] = "1"
        record = self.apply(fake, self.audit(fake))
        self.assertEqual([c.id for c in record.changes if c.status == "done"], ["unknown-sources:legacy"])
        self.assertEqual(fake.secure["install_non_market_apps"], "0")
        parent.restore_record(make(fake), record)
        self.assertEqual(fake.secure["install_non_market_apps"], "1")

    def test_fix_ids_that_are_not_in_the_audit_are_refused(self):
        fake = mum_phone()
        audit = self.audit(fake)
        with self.assertRaises(debloat.PlanError):
            self.apply(fake, audit, fix=["disable:com.android.settings"])
        self.assertEqual([c for c in fake.log if mutating(c)], [])

    def test_an_audit_from_another_phone_is_refused(self):
        fake = mum_phone()
        audit = self.audit(fake)
        audit.device["serial_hash"] = "0123456789ab"
        with self.assertRaises(debloat.PlanError):
            self.apply(fake, audit)
        self.assertEqual([c for c in fake.log if mutating(c)], [])

    def test_protected_apps_and_other_permissions_are_refused_even_in_an_edited_audit(self):
        fake = mum_phone()
        fake.apps[LOAN]["granted"].add("android.permission.CAMERA")
        audit = self.audit(fake)
        audit.findings[0].fixes += [
            parent.Fix(f"disable:{HOME}", "disable", HOME, recommended=True),
            parent.Fix(f"revoke:{SMS}:READ_SMS", "revoke", SMS, READ_SMS, recommended=True),
            parent.Fix(f"revoke:{LOAN}:CAMERA", "revoke", LOAN, "android.permission.CAMERA", recommended=True)]
        record = self.apply(fake, audit)
        refused = {c.id for c in record.changes if c.output.startswith("refused")}
        self.assertEqual(refused, {f"disable:{HOME}", f"revoke:{SMS}:READ_SMS", f"revoke:{LOAN}:CAMERA"})
        self.assertTrue(fake.packages[HOME]["enabled"])
        self.assertIn("android.permission.CAMERA", fake.apps[LOAN]["granted"])
        self.assertFalse(any(HOME in c or "CAMERA" in c for c in fake.log if mutating(c)))

    def test_a_change_that_does_not_take_is_recorded_as_failed_and_never_undone(self):
        fake = mum_phone(ignore_appops_set=(CHROME,))
        record = self.apply(fake, self.audit(fake))
        chrome = next(c for c in record.changes if c.id == f"install:{CHROME}")
        self.assertEqual(chrome.status, "failed")
        self.assertEqual(fake.effective_mode(CHROME), "allow")
        fake.log.clear()
        parent.restore_record(make(fake), record)
        self.assertFalse(any(CHROME in c for c in fake.log if mutating(c)))


class CardTests(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        fake = mum_phone()
        self.audit = parent.run_audit(make(fake), today=TODAY)
        self.record = parent.apply_audit(
            make(fake), self.audit, fix_ids=[f"disable:{ANYDESK}", f"revoke:{LOAN}:READ_SMS", f"accessibility:{A11Y}"],
            record_path=Path(tmp.name) / "record.json")
        self.record.debugging_off = True

    def test_card_states_what_changed_as_counts(self):
        facts = parent.card_facts(self.record, self.audit)
        self.assertEqual((facts["install"], facts["remote"], facts["permissions"], facts["access"]), (2, 1, 1, 1))
        text = parentcard.svg(facts, who="Mum")
        for line in ("Mum's phone", "2 apps can no longer install APK files",
                     "1 remote-control app switched off", "USB debugging switched off again"):
            self.assertIn(line, text)

    def test_card_never_shows_app_names_or_identifiers(self):
        text = parentcard.svg(parent.card_facts(self.record, self.audit), who="Mum")
        for secret in ("com.", "AnyDesk", "FAKE123", self.audit.device["serial_hash"],
                       str(self.audit.device["model"])):
            self.assertNotIn(secret, text)

    def test_who_must_be_a_name_not_a_number_or_an_address(self):
        facts = parent.card_facts(self.record, self.audit)
        for bad in ("9876543210", "mum@example.com", "Mum 2", "x" * 30):
            with self.assertRaises(ValueError):
                parentcard.svg(facts, who=bad)
        self.assertIn("माँ", parentcard.svg(facts, who="माँ"))             # any script is a name

    def test_no_card_when_nothing_was_changed(self):
        empty = parent.ParentRecord(created="", device={}, audit_file="")
        with self.assertRaises(ValueError):
            parentcard.svg(parent.card_facts(empty, self.audit))


class CliTests(unittest.TestCase):
    def run_cli(self, fake, argv):
        buf = io.StringIO()
        real_adb = debloat.Adb
        debloat.Adb = lambda serial=None, adb_path=None, runner=None: real_adb(serial=serial, runner=fake)
        try:
            with contextlib.redirect_stdout(buf):
                rc = debloat.main(argv)
        finally:
            debloat.Adb = real_adb
        return rc, buf.getvalue()

    def test_audit_apply_card_restore_finish_through_the_cli(self):
        fake = mum_phone()
        with tempfile.TemporaryDirectory() as tmp:
            old_backup_dir, debloat.BACKUP_DIR = debloat.BACKUP_DIR, Path(tmp)
            try:
                rc, text = self.run_cli(fake, ["parent", "audit"])
                self.assertEqual(rc, 0, text)
                self.assertIn("Nothing on the phone has been changed", text)
                self.assertIn(f"disable:{ANYDESK}", text)                 # ids the owner can name
                (audit_file,) = Path(tmp).glob("parent-audit-*.json")
                fix = ["parent", "apply", "--audit", str(audit_file), "--fix", f"disable:{ANYDESK}"]

                rc, text = self.run_cli(fake, fix + ["--dry-run"])
                self.assertEqual(rc, 0, text)
                rc, text = self.run_cli(fake, fix)                         # no --yes, no tty
                self.assertEqual(rc, 2, text)
                self.assertEqual([c for c in fake.log if mutating(c)], [])

                rc, text = self.run_cli(fake, fix + ["--yes"])
                self.assertEqual(rc, 0, text)
                self.assertFalse(fake.packages[ANYDESK]["enabled"])
                self.assertEqual(fake.effective_mode(WHATSAPP), "deny")
                self.assertIn("Verified", text)
                (record_file,) = Path(tmp).glob("parent-record-*.json")

                rc, text = self.run_cli(fake, ["parent", "card", "--record", str(record_file), "--who", "Mum"])
                self.assertEqual(rc, 0, text)
                (card,) = Path(tmp).glob("parent-card-*.svg")
                self.assertIn("Mum's phone", card.read_text(encoding="utf-8"))
                self.assertTrue(card.with_suffix(".html").exists())

                rc, text = self.run_cli(fake, ["parent", "restore", "--record", str(record_file)])
                self.assertEqual(rc, 0, text)
                self.assertTrue(fake.packages[ANYDESK]["enabled"])
                self.assertEqual(fake.effective_mode(WHATSAPP), "allow")

                finish = ["parent", "finish", "--record", str(record_file)]
                rc, text = self.run_cli(fake, finish)                      # no --yes, no tty
                self.assertEqual((rc, fake.global_["adb_enabled"]), (2, "1"), text)
                rc, text = self.run_cli(fake, finish + ["--yes"])
                self.assertEqual(rc, 0, text)
                self.assertEqual((fake.global_["adb_enabled"], fake.global_["adb_wifi_enabled"]), ("0", "0"))
                self.assertTrue(json.loads(record_file.read_text())["debugging_off"])
            finally:
                debloat.BACKUP_DIR = old_backup_dir

    def test_audit_output_keeps_long_change_ids_whole_for_copy_paste(self):
        listener = (f"{HELPER}/{HELPER}.notifications.SharedNotificationListenerManager"
                    "$ListenerServiceWithALongName")                      # real ones reach 128 chars
        fake = mum_phone(listeners=(listener,))
        with tempfile.TemporaryDirectory() as tmp:
            old_backup_dir, debloat.BACKUP_DIR = debloat.BACKUP_DIR, Path(tmp)
            try:
                rc, text = self.run_cli(fake, ["parent", "audit"])
            finally:
                debloat.BACKUP_DIR = old_backup_dir
        self.assertEqual(rc, 0, text)
        self.assertIn(f"listener:{listener}", text)

    def test_finish_switches_off_the_transport_in_use_last(self):
        usb = parent.finish_commands("R58N12ABCDE")
        wifi = parent.finish_commands("192.168.1.20:37099")
        mdns = parent.finish_commands("adb-R58N12ABCDE-x1Yz._adb-tls-connect._tcp")
        self.assertIn("adb_enabled 0", usb[-1])
        self.assertIn("adb_wifi_enabled 0", wifi[-1])
        self.assertIn("adb_wifi_enabled 0", mdns[-1])
        self.assertEqual(len(usb), 2)


class ParsingTests(unittest.TestCase):
    def test_package_dump_keeps_first_block_and_user_0_runtime_grants(self):
        dump = "\n".join([
            "Packages:",
            "  Package [com.a] (11):",
            "    installerPackageName=com.google.android.packageinstaller",
            "    installInitiatingPackageName=com.whatsapp",
            "    requested permissions:",
            "      android.permission.READ_SMS: restricted=true",
            "      android.permission.REQUEST_INSTALL_PACKAGES",
            "    install permissions:",
            "      android.permission.INTERNET: granted=true",
            "    User 0: ceDataInode=1 installed=true",
            "      runtime permissions:",
            "        android.permission.READ_SMS: granted=true, flags=[ USER_SET ]",
            "    User 10: ceDataInode=2 installed=true",
            "      runtime permissions:",
            "        android.permission.READ_CONTACTS: granted=true, flags=[ USER_SET ]",
            "",
            "Hidden system packages:",
            "  Package [com.a] (22):",
            "    requested permissions:",
            "      android.permission.CAMERA",
        ])
        apps = parent.parse_package_dump(dump)
        info = apps["com.a"]
        self.assertEqual(info.installer, "com.google.android.packageinstaller")
        self.assertEqual(info.initiator, "com.whatsapp")
        self.assertEqual(info.requested, {"android.permission.READ_SMS", INSTALL})
        self.assertEqual(info.granted, {"android.permission.READ_SMS"})    # user 10's grant is not user 0's

    def test_appops_modes(self):
        self.assertEqual(parent.parse_appop_mode("REQUEST_INSTALL_PACKAGES: allow; time=+2d ago\n"), "allow")
        self.assertEqual(parent.parse_appop_mode("Uid mode: REQUEST_INSTALL_PACKAGES: deny\n"), "deny")
        self.assertEqual(parent.parse_appop_mode("No operations.\nDefault mode: default\n"), "default")

    def test_component_lists(self):
        value = "a.b/a.b.S$Inner:com.oplus.notificationmanager::null"
        self.assertEqual(parent.split_components(value), ["a.b/a.b.S$Inner", "com.oplus.notificationmanager"])
        self.assertEqual(parent.split_components("null\n"), [])

    def test_bundled_parent_lists_parse(self):
        remote = parent.load_patterns(parent.REMOTE_FILE)
        self.assertTrue(any(debloat.fnmatch.fnmatchcase(ANYDESK, p.pattern) for p in remote))
        self.assertIn(PLAY, parent.load_stores())
        with self.assertRaises(ValueError):
            parent.parse_patterns_with_notes("not a package! | x", "t")


if __name__ == "__main__":
    unittest.main()

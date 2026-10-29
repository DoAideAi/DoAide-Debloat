"""Behaviour tests for tools/debloat.py against a scripted fake device.

Run:  python3 -m unittest discover -s tests -v     (stdlib only; pytest also works)
"""
from __future__ import annotations

import json
import os
import re
import shlex
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "tools"))

import debloat  # noqa: E402

SAMSUNG_PROPS = {
    "ro.product.manufacturer": "samsung",
    "ro.product.brand": "samsung",
    "ro.product.model": "SM-A546E",
    "ro.product.device": "a54x",
    "ro.product.name": "a54xnsxx",
    "ro.build.version.release": "14",
    "ro.build.version.sdk": "34",
    "ro.build.display.id": "UP1A.231005.007.A546EXXS9CXK1",
}

HOME = "com.sec.android.app.launcher"
IME = "com.samsung.android.honeyboard"
DIALER = "com.samsung.android.dialer"
SMS = "com.samsung.android.messaging"

BASE_PACKAGES = [
    "android", "com.android.systemui", "com.android.settings", "com.android.providers.contacts",
    "com.google.android.gms", "com.android.vending",
    HOME, IME, DIALER, SMS,
    "com.samsung.android.rubin.app",      # telemetry -> plan
    "com.samsung.android.app.spage",      # ads -> plan (fake device refuses disable-user)
    "com.samsung.android.app.tips",       # junk -> plan
    "com.samsung.android.spay",           # ask
    "com.samsung.android.bixby.agent",    # ask
    "com.glance.internet",                # ads (generic) -> plan
    "com.facebook.system",                # junk, already disabled on the fake
    "com.samsung.android.kgclient",       # never-disable
    "com.example.thirdparty",             # user-installed, unknown
    "com.oem.unknownthing",               # unknown system package
]


class FakeDevice:
    """Just enough of `adb` to drive the tool. Mutations are recorded in `log`."""

    def __init__(self, props=None, packages=None, disabled=(), refuse_disable=(), serial="FAKE123",
                 roles=True):
        self.props = dict(props or SAMSUNG_PROPS)
        self.packages = {p: {"installed": True, "enabled": True} for p in (packages or BASE_PACKAGES)}
        for p in disabled:
            self.packages[p]["enabled"] = False
        self.refuse_disable = set(refuse_disable)
        self.serial = serial
        self.roles_supported = roles
        self.log = []

    # -- state helpers
    def installed(self):
        return [p for p, s in self.packages.items() if s["installed"]]

    def __call__(self, args):
        args = list(args)
        if args[:2] == ["-s", self.serial]:
            args = args[2:]
        if args[:2] == ["devices", "-l"]:
            return 0, f"List of devices attached\n{self.serial}   device usb:1-1 product:x model:SM_A546E device:a54x transport_id:1\n"
        if args[0] == "shell":
            return self.shell(args[1])
        return 1, f"unsupported: {args}"

    def shell(self, cmd):
        self.log.append(cmd)
        parts = shlex.split(cmd)
        if parts == ["getprop"]:
            return 0, "".join(f"[{k}]: [{v}]\n" for k, v in self.props.items())
        if parts[0] == "getprop":
            return 0, self.props.get(parts[1], "") + "\n"
        if parts[:3] == ["pm", "list", "packages"]:
            flag = parts[3] if len(parts) > 3 else ""
            if flag == "-d":
                pkgs = [p for p, s in self.packages.items() if s["installed"] and not s["enabled"]]
            elif flag == "-u":
                pkgs = list(self.packages)
            elif flag == "-3":
                pkgs = [p for p in self.installed() if p.startswith("com.example.")]
            else:
                pkgs = self.installed()
            return 0, "".join(f"package:{p}\r\n" for p in pkgs)   # CRLF on purpose
        if parts[:3] == ["cmd", "package", "resolve-activity"]:
            return 0, ("priority=0 preferredOrder=0 match=0x108000 specificIndex=-1 isDefault=true\n"
                       f"{HOME}/.activities.LauncherActivity\n")
        if parts[:3] == ["settings", "get", "secure"]:
            key = parts[3]
            values = {"default_input_method": f"{IME}/.service.HoneyBoardService",
                      "sms_default_application": SMS}
            return 0, values.get(key, "null") + "\n"
        if parts[:2] == ["settings", "list"]:
            return 0, "some_setting=1\n"
        if parts[:3] == ["cmd", "role", "get-role-holders"]:
            if not self.roles_supported:
                return 1, "Error: unknown command 'role'\n"
            holders = {"android.app.role.HOME": HOME, "android.app.role.DIALER": DIALER,
                       "android.app.role.SMS": SMS}
            return 0, holders.get(parts[3], "") + "\n"
        if parts[:2] == ["pm", "disable-user"]:
            pkg = parts[-1]
            if pkg not in self.packages or not self.packages[pkg]["installed"]:
                return 0, f"Error: java.lang.IllegalArgumentException: Unknown package: {pkg}\n"
            if pkg in self.refuse_disable:
                return 0, f"Error: java.lang.SecurityException: Cannot disable a protected package: {pkg}\n"
            self.packages[pkg]["enabled"] = False
            return 0, f"Package {pkg} new state: disabled-user\n"
        if parts[:2] == ["pm", "enable"]:
            pkg = parts[-1]
            if pkg in self.packages and self.packages[pkg]["installed"]:
                self.packages[pkg]["enabled"] = True
                return 0, f"Package {pkg} new state: enabled\n"
            return 0, f"Error: Unknown package: {pkg}\n"
        if parts[:2] == ["pm", "uninstall"]:
            pkg = parts[-1]
            if pkg in self.packages:
                self.packages[pkg]["installed"] = False
                return 0, "Success\n"
            return 0, "Failure [not installed for 0]\n"
        if parts[:3] == ["cmd", "package", "install-existing"]:
            pkg = parts[-1]
            if pkg in self.packages:
                self.packages[pkg]["installed"] = True
                self.packages[pkg]["enabled"] = True
                return 0, f"Package {pkg} installed for user: 0\n"
            return 0, f"Error: Package {pkg} doesn't exist\n"
        return 1, f"/system/bin/sh: {parts[0]}: not found\n"


def make(fake: FakeDevice) -> debloat.Adb:
    return debloat.Adb(runner=fake)


class ProbeTests(unittest.TestCase):
    def test_probe_reads_state_and_protects_live_roles(self):
        fake = FakeDevice(disabled=["com.facebook.system"])
        state = debloat.probe_device(make(fake))
        self.assertEqual(state.oem, "samsung")
        self.assertEqual(state.home, HOME)
        self.assertEqual(state.ime, IME)
        self.assertEqual(state.roles["android.app.role.DIALER"], [DIALER])
        self.assertIn("com.facebook.system", state.disabled)
        self.assertEqual(state.third_party, {"com.example.thirdparty"})
        self.assertNotIn("FAKE123", json.dumps(state.summary()))   # no serial in anything we write
        protected = debloat.protected_packages(state, debloat.load_never())
        for pkg in (HOME, IME, DIALER, SMS, "com.samsung.android.kgclient", "android",
                    "com.android.providers.contacts", "com.google.android.gms"):
            self.assertIn(pkg, protected, pkg)

    def test_roles_fall_back_to_settings_on_old_android(self):
        fake = FakeDevice(roles=False)
        state = debloat.probe_device(make(fake))
        self.assertEqual(state.roles.get("android.app.role.SMS"), [SMS])
        self.assertNotIn("android.app.role.DIALER", state.roles)   # no setting on the fake
        self.assertEqual(state.home, HOME)

    def test_crlf_package_lists_are_parsed(self):
        self.assertEqual(debloat.parse_package_list("package:a.b\r\npackage:c.d\r\n"), {"a.b", "c.d"})

    def test_oem_detection(self):
        self.assertEqual(debloat.detect_oem({"ro.product.manufacturer": "Xiaomi"}), "xiaomi")
        self.assertEqual(debloat.detect_oem({"ro.product.manufacturer": "OnePlus"}), "oppo")
        self.assertEqual(debloat.detect_oem({"ro.product.manufacturer": "realme"}), "oppo")
        self.assertEqual(debloat.detect_oem({"ro.product.manufacturer": "iQOO", "ro.product.brand": "vivo"}), "vivo")
        self.assertEqual(debloat.detect_oem({"ro.product.manufacturer": "Fairphone"}), "other")

    def test_no_device_gives_instructions(self):
        def runner(args):
            return 0, "List of devices attached\n\n"
        with self.assertRaises(debloat.AdbError) as ctx:
            debloat.probe_device(debloat.Adb(runner=runner))
        self.assertIn("USB debugging", str(ctx.exception))

    def test_unauthorized_device_is_explained(self):
        def runner(args):
            return 0, "List of devices attached\nABC\tunauthorized\n"
        with self.assertRaises(debloat.AdbError) as ctx:
            debloat.probe_device(debloat.Adb(runner=runner))
        self.assertIn("Allow USB debugging", str(ctx.exception))


class PlanTests(unittest.TestCase):
    def setUp(self):
        self.fake = FakeDevice(disabled=["com.facebook.system"])
        self.state = debloat.probe_device(make(self.fake))
        self.never = debloat.load_never()
        self.entries = debloat.load_entries(debloat.profile_files("samsung"))

    def plan(self, **kw):
        return debloat.build_plan(self.state, self.entries, self.never, profiles=["generic.txt", "samsung.txt"], **kw)

    def test_default_plan_has_only_installed_active_categories(self):
        plan = self.plan()
        pkgs = set(plan.packages())
        self.assertEqual(pkgs, {"com.samsung.android.rubin.app", "com.samsung.android.app.spage",
                                "com.samsung.android.app.tips", "com.glance.internet"})
        self.assertIn("com.facebook.system", plan.skipped["already_disabled"])
        self.assertIn("com.samsung.android.kgclient", plan.protected)
        self.assertNotIn("com.samsung.android.kgclient", pkgs)
        self.assertTrue(plan.skipped["not_installed"])          # most of the profile is not on this phone
        self.assertNotIn("com.oem.unknownthing", pkgs)            # never invents packages

    def test_ask_items_become_questions_until_named(self):
        plan = self.plan()
        asked = {q["package"] for q in plan.questions}
        self.assertEqual(asked, {"com.samsung.android.spay", "com.samsung.android.bixby.agent"})
        plan2 = self.plan(remove=["com.samsung.android.spay"])
        self.assertIn("com.samsung.android.spay", plan2.packages())
        self.assertEqual({q["package"] for q in plan2.questions}, {"com.samsung.android.bixby.agent"})

    def test_keep_wins_and_remove_refuses_protected(self):
        plan = self.plan(keep=["com.glance.internet"])
        self.assertNotIn("com.glance.internet", plan.packages())
        self.assertIn("com.glance.internet", plan.skipped["kept"])
        with self.assertRaises(debloat.PlanError):
            self.plan(remove=[HOME])
        with self.assertRaises(debloat.PlanError):
            self.plan(remove=["com.samsung.android.kgclient"])

    def test_remove_of_unlisted_installed_package_is_allowed(self):
        plan = self.plan(remove=["com.example.thirdparty"])
        self.assertIn("com.example.thirdparty", plan.packages())
        plan2 = self.plan(remove=["com.not.installed"])
        self.assertNotIn("com.not.installed", plan2.packages())
        self.assertTrue(any("not installed" in w for w in plan2.warnings))

    def test_broad_uses_community_recommended_only(self):
        uad = {
            "com.oem.unknownthing": {"list": "Oem", "removal": "Recommended", "description": "Some OEM thing\nmore"},
            "com.example.thirdparty": {"list": "Misc", "removal": "Expert", "description": "x"},
            HOME: {"list": "Oem", "removal": "Recommended", "description": "launcher"},
            "com.samsung.android.app.tips": {"list": "Oem", "removal": "Recommended",
                                             "description": "Tips", "neededBy": ["com.oem.unknownthing"]},
        }
        plan = self.plan(broad="oem", uad=uad)
        self.assertIn("com.oem.unknownthing", plan.packages())
        self.assertNotIn("com.example.thirdparty", plan.packages())
        self.assertNotIn(HOME, plan.packages())
        tips = next(i for i in plan.items if i.package == "com.samsung.android.app.tips")
        self.assertEqual(tips.uad_removal, "Recommended")
        self.assertEqual(tips.uad_description, "Tips")
        plan_no_uad = self.plan(broad="oem", uad=None)
        self.assertTrue(any("unavailable" in w for w in plan_no_uad.warnings))

    def test_needed_by_warning_when_dependant_stays(self):
        uad = {"com.samsung.android.app.tips": {"list": "Oem", "removal": "Recommended", "description": "Tips",
                                                 "neededBy": ["com.example.thirdparty"]}}
        plan = self.plan(uad=uad)
        self.assertTrue(any("needed by com.example.thirdparty" in w for w in plan.warnings))

    def test_plan_round_trips_through_json(self):
        plan = self.plan(remove=["com.samsung.android.spay"])
        data = json.loads(json.dumps(debloat.plan_to_dict(plan)))
        back = debloat.plan_from_dict(data)
        self.assertEqual(back.packages(), plan.packages())
        self.assertEqual(back.device["serial_hash"], self.state.serial_hash)


class ApplyRestoreTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.record_path = Path(self.tmp.name) / "record.json"

    def tearDown(self):
        self.tmp.cleanup()

    def run_apply(self, fake, allow_uninstall=False, remove=()):
        adb = make(fake)
        self.before = {p: dict(s) for p, s in fake.packages.items()}
        state = debloat.probe_device(adb)
        entries = debloat.load_entries(debloat.profile_files("samsung"))
        plan = debloat.build_plan(state, entries, debloat.load_never(), remove=remove)
        record = debloat.apply_plan(adb, plan, state, "plan.json", allow_uninstall, self.record_path)
        return adb, state, plan, record

    def test_apply_disables_records_and_leaves_refusals_alone(self):
        fake = FakeDevice(disabled=["com.facebook.system"], refuse_disable=["com.samsung.android.app.spage"])
        adb, state, plan, record = self.run_apply(fake)
        ok = {a.package for a in record.actions if a.ok}
        self.assertEqual(ok, {"com.samsung.android.rubin.app", "com.samsung.android.app.tips", "com.glance.internet"})
        failed = [a for a in record.actions if not a.ok]
        self.assertEqual([a.package for a in failed], ["com.samsung.android.app.spage"])
        self.assertTrue(fake.packages["com.samsung.android.app.spage"]["enabled"])   # untouched
        self.assertTrue(fake.packages["com.samsung.android.app.spage"]["installed"])
        self.assertFalse(fake.packages["com.glance.internet"]["enabled"])
        self.assertTrue(all(cmd.count("pm ") <= 1 for cmd in fake.log))             # one pm per shell call
        on_disk = json.loads(self.record_path.read_text())
        self.assertEqual(len(on_disk["actions"]), len(record.actions))
        self.assertNotIn("FAKE123", self.record_path.read_text())
        after = debloat.probe_device(adb)
        self.assertEqual(debloat.verify(state, after), [])

    def test_uninstall_fallback_only_when_allowed_and_restore_reinstalls(self):
        fake = FakeDevice(disabled=["com.facebook.system"], refuse_disable=["com.samsung.android.app.spage"])
        adb, state, plan, record = self.run_apply(fake, allow_uninstall=True)
        spage = next(a for a in record.actions if a.package == "com.samsung.android.app.spage")
        self.assertTrue(spage.ok)
        self.assertEqual(spage.method, "uninstall-user")
        self.assertFalse(fake.packages["com.samsung.android.app.spage"]["installed"])

        results = debloat.restore_record(adb, record)
        self.assertTrue(all(r.ok for r in results), results)
        self.assertEqual(fake.packages, self.before)   # exactly the pre-apply state

    def test_restore_from_backup_without_a_record(self):
        fake = FakeDevice(disabled=["com.facebook.system"])
        adb = make(fake)
        state = debloat.probe_device(adb)
        backup = debloat.make_backup(adb, state)
        self.assertIn("settings", backup)
        self.assertIn("com.facebook.system", backup["disabled"])
        # someone disables and user-removes things afterwards
        fake.shell("pm disable-user --user 0 com.glance.internet")
        fake.shell("pm uninstall -k --user 0 com.samsung.android.app.tips")
        now = debloat.probe_device(adb)
        results = debloat.restore_from_backup(adb, backup, now)
        self.assertEqual({r.package for r in results}, {"com.glance.internet", "com.samsung.android.app.tips"})
        self.assertTrue(fake.packages["com.glance.internet"]["enabled"])
        self.assertTrue(fake.packages["com.samsung.android.app.tips"]["installed"])
        self.assertFalse(fake.packages["com.facebook.system"]["enabled"])   # was disabled before: stays

    def test_apply_refuses_plan_from_another_device(self):
        fake = FakeDevice()
        adb = make(fake)
        state = debloat.probe_device(adb)
        plan = debloat.build_plan(state, debloat.load_entries(debloat.profile_files("samsung")), debloat.load_never())
        plan.device["serial_hash"] = "000000000000"
        with self.assertRaises(debloat.PlanError):
            debloat.apply_plan(adb, plan, state, "plan.json", False, self.record_path)

    def test_apply_rechecks_protection_live(self):
        """A plan file edited by hand to include the launcher is still refused at apply time."""
        fake = FakeDevice()
        adb = make(fake)
        state = debloat.probe_device(adb)
        plan = debloat.build_plan(state, debloat.load_entries(debloat.profile_files("samsung")), debloat.load_never())
        plan.items.append(debloat.PlanItem(HOME, "junk", "edited in", "hand"))
        record = debloat.apply_plan(adb, plan, state, "plan.json", False, self.record_path)
        home_action = next(a for a in record.actions if a.package == HOME)
        self.assertEqual(home_action.method, "skip")
        self.assertTrue(fake.packages[HOME]["enabled"])

    def test_check_detects_drift_after_update(self):
        fake = FakeDevice()
        adb, state, plan, record = self.run_apply(fake)
        self.assertEqual(debloat.drift(record, debloat.probe_device(adb)), [])
        fake.shell("pm enable --user 0 com.glance.internet")    # "firmware update"
        undone = debloat.drift(record, debloat.probe_device(adb))
        self.assertEqual([a.package for a in undone], ["com.glance.internet"])


class ListFileTests(unittest.TestCase):
    def test_bundled_lists_parse_and_do_not_overlap_never(self):
        never = debloat.load_never()
        entries = debloat.load_all_entries()
        self.assertGreater(len(entries), 100)
        for entry in entries:
            self.assertIsNone(debloat.matches_never(entry.package, never),
                              f"{entry.package} is both listed and protected")
        seen = set()
        for entry in entries:
            self.assertNotIn(entry.package, seen, f"{entry.package} listed twice")
            seen.add(entry.package)

    def test_parse_rejects_bad_lines(self):
        with self.assertRaises(ValueError):
            debloat.parse_list("com.foo | nonsense | x", "t")
        with self.assertRaises(ValueError):
            debloat.parse_list("not a package!! | ads", "t")
        entries = debloat.parse_list("# comment\n\ncom.foo | ads | note # trailing\ncom.bar\n", "t")
        self.assertEqual([(e.package, e.category, e.note) for e in entries],
                         [("com.foo", "ads", "note"), ("com.bar", "junk", "")])

    def test_never_patterns_glob(self):
        patterns = debloat.parse_patterns("com.android.providers.*\n*knox*\nandroid\n", "t")
        self.assertEqual(debloat.matches_never("com.android.providers.media", patterns), "com.android.providers.*")
        self.assertEqual(debloat.matches_never("com.samsung.knox.securefolder", patterns), "*knox*")
        self.assertEqual(debloat.matches_never("android", patterns), "android")
        self.assertIsNone(debloat.matches_never("com.glance.internet", patterns))


class CliTests(unittest.TestCase):
    def run_cli(self, fake, argv):
        import contextlib
        import io
        buf = io.StringIO()
        real_adb = debloat.Adb
        debloat.Adb = lambda serial=None, adb_path=None, runner=None: real_adb(serial=serial, runner=fake)
        try:
            with contextlib.redirect_stdout(buf):
                rc = debloat.main(argv)
        finally:
            debloat.Adb = real_adb
        return rc, buf.getvalue()

    def test_cli_plan_dry_run_apply_restore_check(self):
        fake = FakeDevice(disabled=["com.facebook.system"], refuse_disable=["com.samsung.android.app.spage"])
        with tempfile.TemporaryDirectory() as tmp:
            old_backup_dir = debloat.BACKUP_DIR
            debloat.BACKUP_DIR = Path(tmp)
            try:
                out = Path(tmp) / "plan.json"
                rc, text = self.run_cli(fake, ["plan", "--no-uad", "--out", str(out), "--remove", "com.samsung.android.spay"])
                self.assertEqual(rc, 0, text)
                data = json.loads(out.read_text())
                planned = [i["package"] for i in data["items"]]
                self.assertIn("com.glance.internet", planned)
                self.assertIn("com.samsung.android.spay", planned)
                self.assertIn("Bixby Voice", text)                      # still a question

                rc, text = self.run_cli(fake, ["apply", "--plan", str(out), "--dry-run"])
                self.assertEqual(rc, 0, text)
                self.assertTrue(fake.packages["com.glance.internet"]["enabled"])   # dry run changed nothing

                rc, text = self.run_cli(fake, ["apply", "--plan", str(out)])      # no --yes, no tty
                self.assertEqual(rc, 2, text)
                self.assertTrue(fake.packages["com.glance.internet"]["enabled"])

                rc, text = self.run_cli(fake, ["apply", "--plan", str(out), "--yes"])
                self.assertEqual(rc, 0, text)
                self.assertFalse(fake.packages["com.glance.internet"]["enabled"])
                self.assertFalse(fake.packages["com.samsung.android.spay"]["enabled"])
                self.assertTrue(fake.packages["com.samsung.android.app.spage"]["enabled"])   # refused, reported
                self.assertIn("--allow-uninstall", text)
                self.assertIn("Verified", text)
                backups = sorted(Path(tmp).glob("backup-*.json"))
                records = sorted(Path(tmp).glob("record-*.json"))
                self.assertEqual(len(backups), 1)
                self.assertEqual(len(records), 1)

                fake.shell("pm enable --user 0 com.glance.internet")           # "firmware update"
                rc, text = self.run_cli(fake, ["check", "--record", str(records[0])])
                self.assertEqual(rc, 1, text)
                rc, text = self.run_cli(fake, ["check", "--record", str(records[0]), "--fix"])
                self.assertEqual(rc, 0, text)
                self.assertFalse(fake.packages["com.glance.internet"]["enabled"])

                rc, text = self.run_cli(fake, ["restore", "--record", str(records[0])])
                self.assertEqual(rc, 0, text)
                self.assertTrue(fake.packages["com.glance.internet"]["enabled"])
                self.assertTrue(fake.packages["com.samsung.android.spay"]["enabled"])
                self.assertFalse(fake.packages["com.facebook.system"]["enabled"])  # was disabled before us
            finally:
                debloat.BACKUP_DIR = old_backup_dir

    def test_cli_reports_missing_adb_cleanly(self):
        import contextlib
        import io
        err = io.StringIO()
        with contextlib.redirect_stderr(err):
            rc = debloat.main(["--adb", "/nonexistent/adb", "probe"])
        self.assertEqual(rc, 1)
        self.assertIn("adb was not found", err.getvalue())


if __name__ == "__main__":
    unittest.main()

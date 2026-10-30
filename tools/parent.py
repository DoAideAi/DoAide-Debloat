#!/usr/bin/env python3
"""Parent mode for DoAide Debloat: make an Android phone harder to scam, over ADB, reversibly.

    parent audit    read-only: what on this phone a scam caller or a fake APK could use;
                    writes an audit file and changes nothing
    parent apply    make the recommended changes, plus the ones the owner names with --fix
    parent restore  undo a parent-mode record
    parent card     a shareable before/after card: counts only, never app names or identifiers
    parent finish   turn USB and wireless debugging off; always the last step

What the audit looks at: remote-control apps a caller can talk someone into installing; apps
allowed to install other apps (how fake "KYC update" APKs arrive); apps installed from outside an
app store that can read SMS, contacts or the call log; accessibility and notification access
(how banking malware reads one-time passwords); device admins; the default SMS app; Play Protect;
the security patch date; WhatsApp's storage.

What it may change, and only after the owner agreed: the "install unknown apps" permission (set
to deny), remote-control and sideloaded apps (disabled with `pm disable-user`, never uninstalled),
accessibility and notification access of third-party apps, and SMS / contacts / call-log
permissions of apps installed from outside a store. Every change is written to a record before
the next one and is undone by `parent restore`. It never deletes an app, a message or a photo.

Stdlib only, Python 3.9+. Shares the adb layer, device probe and protections with debloat.py.
"""
from __future__ import annotations

import argparse
import fnmatch
import functools
import json
import re
import shlex
import textwrap
import time
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Callable, Dict, List, Optional, Sequence, Set

import debloat as core
import parentcard

PARENT_DIR = core.DATA_DIR / "parent"
REMOTE_FILE = PARENT_DIR / "remote-access.txt"
STORES_FILE = PARENT_DIR / "app-stores.txt"

INSTALL_OP = "REQUEST_INSTALL_PACKAGES"
INSTALL_PERMISSION = "android.permission." + INSTALL_OP
SENSITIVE = {
    "android.permission.READ_SMS": "read SMS, including one-time passwords",
    "android.permission.RECEIVE_SMS": "receive SMS, including one-time passwords",
    "android.permission.SEND_SMS": "send SMS",
    "android.permission.READ_CALL_LOG": "read the call log",
    "android.permission.READ_CONTACTS": "read contacts",
}
SEVERITIES = ("high", "medium", "low", "info")
CHECK_ORDER = ("audit-incomplete", "remote-access", "install-apps", "sms-app", "accessibility",
               "notification-access", "device-admin", "sideloaded", "play-protect", "security-patch",
               "whatsapp-storage", "debugging")

# Display names for apps that come up often. Display only: nothing is decided by this table.
NAMES = {
    "com.whatsapp": "WhatsApp",
    "com.whatsapp.w4b": "WhatsApp Business",
    "org.telegram.messenger": "Telegram",
    "com.android.chrome": "Chrome",
    "com.sec.android.app.sbrowser": "Samsung Internet",
    "com.UCMobile.intl": "UC Browser",
    "com.opera.mini.native": "Opera Mini",
    "org.mozilla.firefox": "Firefox",
    "com.microsoft.emmx": "Microsoft Edge",
    "com.brave.browser": "Brave",
    "com.google.android.gm": "Gmail",
    "com.google.android.apps.nbu.files": "Files by Google",
    "com.sec.android.app.myfiles": "Samsung My Files",
    "com.mi.android.globalFileexplorer": "Xiaomi File Manager",
    "com.truecaller": "Truecaller",
    "com.facebook.katana": "Facebook",
    "com.instagram.android": "Instagram",
}
# Messengers, browsers, mail and file managers: how fake APKs reach a phone. Their "install
# unknown apps" permission is switched off by default even when they ship with the phone. The
# preinstalled ones were cross-checked against the community UAD list on 2026-10-30; the rest only
# ever arrive as third-party apps, whose permission is switched off by default anyway.
INSTALL_VECTORS = set(NAMES) - {"com.truecaller", "com.facebook.katana", "com.instagram.android"}

WHATSAPP_MEDIA = (
    "/sdcard/Android/media/com.whatsapp/WhatsApp/Media/*",
    "'/sdcard/Android/media/com.whatsapp.w4b/WhatsApp Business/Media'/*",
    "/sdcard/WhatsApp/Media/*",
)

CHECKLIST = [
    "WhatsApp > Settings > Privacy > Calls > Silence unknown callers: on.",
    "WhatsApp > Settings > Account > Two-step verification: on, with a PIN the family knows.",
    "WhatsApp > Settings > Privacy > Groups: My contacts, so strangers cannot add them to groups.",
    "Agree a family code word for any call that asks for money; a cloned voice cannot know it.",
    "Save 1930 (National Cyber Crime Helpline) in contacts. If money is lost, call it within the "
    "hour and file at cybercrime.gov.in.",
    "Say it out loud: no police officer, bank or courier asks you to install an app, share your "
    "screen or stay on a video call. 'Digital arrest' does not exist.",
]


# --------------------------------------------------------------------------- data files


@dataclass
class Pattern:
    pattern: str
    note: str


def parse_patterns_with_notes(text: str, source: str) -> List[Pattern]:
    patterns: List[Pattern] = []
    for lineno, raw in enumerate(text.splitlines(), 1):
        line = raw.split("#", 1)[0].strip()
        if not line:
            continue
        parts = [p.strip() for p in line.split("|", 1)]
        if not core.PATTERN_RE.fullmatch(parts[0]):
            raise ValueError(f"{source}:{lineno}: '{parts[0]}' is not a package pattern")
        patterns.append(Pattern(parts[0], parts[1] if len(parts) > 1 else ""))
    return patterns


def load_patterns(path: Path) -> List[Pattern]:
    return parse_patterns_with_notes(path.read_text(encoding="utf-8"), path.name)


def load_stores(path: Path = STORES_FILE) -> Set[str]:
    return {p.pattern for p in load_patterns(path)}


@functools.lru_cache(maxsize=None)
def store_names() -> Dict[str, str]:
    return {p.pattern: p.note.split("(", 1)[0].strip() for p in load_patterns(STORES_FILE) if p.note}


def match_pattern(package: str, patterns: Sequence[Pattern]) -> Optional[Pattern]:
    for pattern in patterns:
        if fnmatch.fnmatchcase(package, pattern.pattern):
            return pattern
    return None


# --------------------------------------------------------------------------- parsing adb output


@dataclass
class AppInfo:
    package: str
    installer: Optional[str] = None
    initiator: Optional[str] = None
    requested: Set[str] = field(default_factory=set)
    granted: Set[str] = field(default_factory=set)


PACKAGE_HEADER = re.compile(r"^\s*Package \[([^\]]+)\]")
PERMISSION_LINE = re.compile(r"^([A-Za-z0-9_.]+)(?::.*)?$")


def _value(line: str) -> Optional[str]:
    value = line.split("=", 1)[1].strip()
    return None if value in ("", "null") else value


def _indent(line: str) -> int:
    return len(line) - len(line.lstrip(" "))


def parse_package_dump(out: str) -> Dict[str, AppInfo]:
    """`dumpsys package packages` (or `dumpsys package <pkg>`) -> installer, install initiator,
    requested permissions and user 0's granted runtime permissions per package. The first block
    of a package wins: later ones are the "Hidden system packages" copies of updated system apps."""
    apps: Dict[str, AppInfo] = {}
    current: Optional[AppInfo] = None
    section: Optional[str] = None
    section_indent = 0
    user0 = False
    for raw in out.splitlines():
        line = raw.rstrip()
        stripped = line.strip()
        if not stripped:
            continue
        header = PACKAGE_HEADER.match(line)
        if header:
            pkg = header.group(1)
            current = None if pkg in apps else apps.setdefault(pkg, AppInfo(pkg))
            section, user0 = None, False
            continue
        if current is None:
            continue
        if _indent(line) == 0:                       # "Hidden system packages:", "Queries:", ...
            current = None
            continue
        if section and _indent(line) <= section_indent:
            section = None
        if stripped.startswith("installerPackageName="):
            current.installer = _value(stripped)
        elif re.match(r"(install)?[Ii]nitiatingPackageName=", stripped):
            current.initiator = _value(stripped)
        elif stripped.startswith("User "):
            user0 = stripped.startswith("User 0:")
            section = None
        elif stripped == "requested permissions:":
            section, section_indent = "requested", _indent(line)
        elif stripped == "runtime permissions:":
            section, section_indent = ("runtime" if user0 else "skip"), _indent(line)
        elif section == "requested":
            match = PERMISSION_LINE.match(stripped)
            if match and "." in match.group(1):
                current.requested.add(match.group(1))
        elif section == "runtime" and ": granted=" in stripped:
            permission, rest = stripped.split(":", 1)
            if "granted=true" in rest:
                current.granted.add(permission.strip())
    return apps


def parse_installers(out: str) -> Dict[str, Optional[str]]:
    """`pm list packages -3 -i` -> package -> installer (None when the device says null)."""
    installers: Dict[str, Optional[str]] = {}
    for line in out.splitlines():
        match = re.match(r"package:(\S+)\s+installer=(\S+)", line.strip())
        if match:
            installers[match.group(1)] = None if match.group(2) == "null" else match.group(2)
    return installers


def parse_appop_modes(out: str, op: str = INSTALL_OP) -> Dict[str, Optional[str]]:
    """`appops get <pkg> <op>` -> {"uid": mode or None, "package": mode or None}. Android keeps
    both; a uid mode that is set wins over the package mode."""
    uid = re.search(rf"Uid mode: {re.escape(op)}: ([a-z]+)", out)
    package = re.search(rf"^\s*{re.escape(op)}: ([a-z]+)", out, re.M)
    return {"uid": uid.group(1) if uid else None, "package": package.group(1) if package else None}


def effective_mode(modes: Dict[str, Optional[str]]) -> str:
    if modes.get("uid") not in (None, "default"):
        return str(modes["uid"])
    return modes.get("package") or "default"


def parse_appop_mode(out: str, op: str = INSTALL_OP) -> str:
    """`appops get <pkg> <op>` -> the effective mode: allow / deny / ignore / default /
    foreground, or unknown when the output is not appops output."""
    modes = parse_appop_modes(out, op)
    if modes["uid"] is None and modes["package"] is None and "No operations" not in out:
        return "unknown"
    return effective_mode(modes)


def split_components(value: str) -> List[str]:
    """A colon-separated settings value of components (pkg/cls) or bare packages."""
    value = (value or "").strip()
    if value in ("", "null"):
        return []
    return [c for c in value.split(":") if c and c != "null"]


def component_package(component: str) -> str:
    return component.split("/", 1)[0]


def parse_device_admins(out: str) -> List[str]:
    """Active admin components for user 0 from `dumpsys device_policy`."""
    admins: List[str] = []
    inside, header_indent = False, 0
    for raw in out.splitlines():
        stripped = raw.strip()
        if not stripped:
            continue
        if stripped.startswith("Enabled Device Admins"):
            inside, header_indent = "User 0" in stripped, _indent(raw)
            continue
        if inside:
            if _indent(raw) <= header_indent:
                inside = False
                continue
            match = re.fullmatch(r"([A-Za-z0-9_.]+/[A-Za-z0-9_.$]+):", stripped)
            if match:
                admins.append(match.group(1))
    return admins


def parse_du_bytes(out: str) -> Optional[int]:
    total, seen = 0, False
    for line in out.splitlines():
        match = re.match(r"^(\d+)\s+\S", line.strip())
        if match:
            total += int(match.group(1)) * 1024
            seen = True
    return total if seen else None


def months_between(patch: str, today: str) -> Optional[int]:
    a = re.match(r"(\d{4})-(\d{2})", patch or "")
    b = re.match(r"(\d{4})-(\d{2})", today or "")
    if not a or not b:
        return None
    return (int(b.group(1)) - int(a.group(1))) * 12 + int(b.group(2)) - int(a.group(2))


# --------------------------------------------------------------------------- reading the phone


@dataclass
class Facts:
    sdk: int
    security_patch: str
    apps: Dict[str, AppInfo]
    install_modes: Dict[str, str]
    legacy_unknown_sources: Optional[str]
    accessibility: List[str]
    listeners: List[str]
    admins: List[str]
    play_protect: Optional[str]
    whatsapp_bytes: Optional[int]
    packages_read: int = 0                 # installed packages whose details dumpsys gave us
    install_unreadable: List[str] = field(default_factory=list)   # appops answered nonsense


def setting(adb: core.Adb, namespace: str, key: str) -> Optional[str]:
    value = adb.shell(f"settings get {namespace} {key}", check=False).strip()
    return None if value in ("", "null") else value


def gather(adb: core.Adb, state: core.DeviceState) -> Facts:
    """Everything the audit needs, read-only. One `dumpsys package packages` instead of one call
    per app: a phone with 250 third-party apps is a normal phone."""
    try:
        sdk = int(state.props.get("ro.build.version.sdk") or 0)
    except ValueError:
        sdk = 0
    apps = parse_package_dump(adb.shell("dumpsys package packages", check=False))
    packages_read = len(set(apps) & state.packages)
    for pkg, installer in parse_installers(adb.shell("pm list packages -3 -i", check=False)).items():
        info = apps.setdefault(pkg, AppInfo(pkg))
        if installer:
            info.installer = installer
    enabled = state.packages - state.disabled
    install_modes: Dict[str, str] = {}
    legacy: Optional[str] = None
    if sdk >= 26:
        for pkg in sorted(p for p, info in apps.items() if INSTALL_PERMISSION in info.requested
                          and p in enabled):
            install_modes[pkg] = parse_appop_mode(
                adb.shell(f"appops get {pkg} {INSTALL_OP}", check=False))
    elif sdk >= 21:
        legacy = setting(adb, "secure", "install_non_market_apps")
    du = adb.shell("du -sk " + " ".join(WHATSAPP_MEDIA) + " 2>/dev/null", check=False)
    return Facts(
        sdk=sdk,
        security_patch=adb.shell("getprop ro.build.version.security_patch", check=False).strip(),
        apps=apps,
        install_modes=install_modes,
        legacy_unknown_sources=legacy,
        accessibility=split_components(setting(adb, "secure", "enabled_accessibility_services") or ""),
        listeners=split_components(setting(adb, "secure", "enabled_notification_listeners") or ""),
        admins=parse_device_admins(adb.shell("dumpsys device_policy", check=False)),
        play_protect=setting(adb, "global", "package_verifier_user_consent"),
        whatsapp_bytes=parse_du_bytes(du),
        packages_read=packages_read,
        install_unreadable=[p for p, mode in install_modes.items() if mode == "unknown"],
    )


# --------------------------------------------------------------------------- the audit


@dataclass
class Fix:
    id: str
    kind: str              # install | unknown-sources | disable | accessibility | listener | revoke
    target: str            # package, component, or the setting name
    detail: str = ""       # the permission, for revoke
    recommended: bool = False
    label: str = ""
    check: str = ""        # the finding it belongs to (remote-access, sideloaded, ...)


@dataclass
class Finding:
    check: str
    severity: str
    title: str
    why: str = ""
    subject: str = ""
    evidence: List[str] = field(default_factory=list)
    fixes: List[Fix] = field(default_factory=list)
    by_hand: List[str] = field(default_factory=list)


@dataclass
class Audit:
    created: str
    device: Dict[str, object]
    findings: List[Finding]
    checklist: List[str]
    stats: Dict[str, object]

    def fixes(self) -> Dict[str, Fix]:
        return {fix.id: fix for finding in self.findings for fix in finding.fixes}


def app_name(package: str, remote: Sequence[Pattern] = ()) -> str:
    if package in NAMES:
        return NAMES[package]
    if package in store_names():
        return store_names()[package]
    hit = match_pattern(package, remote)
    if hit and ":" in hit.note:
        return hit.note.split(":", 1)[0].strip()
    return package


def install_source(info: AppInfo) -> str:
    if info.initiator and info.initiator != info.installer:
        return f"installed from {app_name(info.initiator)}"
    if info.installer:
        return f"installed by {app_name(info.installer)}"
    return "no app store recorded as its installer (apps preloaded by the seller can look like this)"


def _join(items: Sequence[str]) -> str:
    items = list(items)
    return items[0] if len(items) == 1 else ", ".join(items[:-1]) + " and " + items[-1]


def short_permission(permission: str) -> str:
    return permission.rsplit(".", 1)[-1]


def disable_fix(pkg: str, name: str) -> Fix:
    return Fix(f"disable:{pkg}", "disable", pkg, label=f"Switch off {name} (it can be switched back on)")


def build_audit(facts: Facts, state: core.DeviceState, today: str,
                remote: Optional[Sequence[Pattern]] = None, stores: Optional[Set[str]] = None,
                never: Optional[Sequence[str]] = None) -> Audit:
    remote = load_patterns(REMOTE_FILE) if remote is None else remote
    stores = load_stores() if stores is None else stores
    never = core.load_never() if never is None else never
    protected = core.protected_packages(state, never)
    enabled = state.packages - state.disabled
    findings: List[Finding] = []

    def name(pkg: str) -> str:
        return app_name(pkg, remote)

    def from_store(pkg: str) -> bool:
        return (facts.apps.get(pkg) or AppInfo(pkg)).installer in stores

    # an unreadable check is not a passed check
    unread = []
    if facts.packages_read < len(state.packages) / 2:
        unread.append(f"app details (install source, permissions) were readable for "
                      f"{facts.packages_read} of {len(state.packages)} apps")
    if facts.install_unreadable:
        unread.append("could not read whether these may install apps: "
                      + ", ".join(name(p) for p in facts.install_unreadable))
    if unread:
        findings.append(Finding(
            "audit-incomplete", "high", "Parts of this audit could not be read on this phone",
            why="Until these are checked by hand, do not tell the owner the phone is clean.",
            evidence=unread,
            by_hand=["Settings > search 'Install unknown apps': only app stores should be allowed.",
                     "Settings > Apps: look for apps the owner does not recognise, and for apps with "
                     "SMS or Contacts permission that did not come from an app store.",
                     "Report the phone model and Android version (.github/ISSUE_TEMPLATE/device-report.yml) "
                     "so the tool learns this firmware."]))

    # remote control
    remote_hits = set()
    for pkg in sorted(enabled):
        hit = match_pattern(pkg, remote)
        if not hit:
            continue
        remote_hits.add(pkg)
        info = facts.apps.get(pkg) or AppInfo(pkg)
        findings.append(Finding(
            "remote-access", "high", f"{name(pkg)}: someone with its code can see and control this phone",
            why=("Callers posing as bank, courier or police staff ask people to install an app like "
                 "this and read out the code. With it they watch the screen, including the banking app."),
            subject=pkg, evidence=[hit.note, install_source(info)],
            fixes=[] if pkg in protected else [disable_fix(pkg, name(pkg))],
            by_hand=["If the family uses it to help, keep it, and agree: never read its code to anyone "
                     "who calls."]))

    # installing apps
    if facts.sdk >= 26:
        for pkg, mode in sorted(facts.install_modes.items()):
            if mode != "allow" or pkg in stores:
                continue
            recommended = pkg in state.third_party or pkg in INSTALL_VECTORS
            findings.append(Finding(
                "install-apps", "high" if recommended else "medium", f"{name(pkg)} can install apps (APK files)",
                why=("Fake 'KYC update', 'electricity bill' and 'courier' apps arrive as APK files through "
                     "messengers, browsers and file managers. Switching this off does not stop the app "
                     "working; it only stops it installing other apps."),
                subject=pkg,
                fixes=[Fix(f"install:{pkg}", "install", pkg, recommended=recommended,
                           label=f"Stop {name(pkg)} installing apps")],
                by_hand=[] if recommended else [
                    "A system app: if it is how the phone updates its own apps, keep this on."]))
    elif facts.legacy_unknown_sources == "1":
        findings.append(Finding(
            "install-apps", "high", "Apps from unknown sources can be installed",
            why="Any downloaded APK file installs with one tap, including fake bank and KYC apps.",
            fixes=[Fix("unknown-sources:legacy", "unknown-sources", "install_non_market_apps",
                       recommended=True, label="Turn off 'Unknown sources'")]))

    # the default SMS app sees every one-time password
    for pkg in state.roles.get("android.app.role.SMS", []):
        if pkg in state.third_party and not from_store(pkg):
            findings.append(Finding(
                "sms-app", "high", f"The default SMS app ({name(pkg)}) was installed from outside an app store",
                why="The default SMS app receives every one-time password.", subject=pkg,
                evidence=[install_source(facts.apps.get(pkg) or AppInfo(pkg))],
                by_hand=["Settings > Apps > Default apps > SMS app: choose the phone's own Messages app."]))

    sideloaded = {p for p in state.third_party & enabled if not from_store(p)}

    for comp in facts.accessibility:
        pkg = component_package(comp)
        if pkg not in state.third_party:
            continue
        findings.append(Finding(
            "accessibility", "high", f"{name(pkg)} can read the screen and tap buttons (accessibility service)",
            why=("Banking malware uses accessibility access to read one-time passwords and approve "
                 "payments. Screen readers and some remote-help apps use it legitimately."),
            subject=comp, evidence=[install_source(facts.apps.get(pkg) or AppInfo(pkg))],
            fixes=[] if pkg in protected else [Fix(
                f"accessibility:{comp}", "accessibility", comp,
                label=f"Remove {name(pkg)}'s accessibility access")],
            by_hand=["Settings > Accessibility > Installed (or Downloaded) apps: switch it off there."]))

    for entry in facts.listeners:
        pkg = component_package(entry)
        if pkg not in state.third_party:
            continue
        findings.append(Finding(
            "notification-access", "high" if pkg in sideloaded else "medium",
            f"{name(pkg)} can read every notification, including one-time passwords",
            why="Notification access shows an app every message preview and OTP that arrives.",
            subject=entry, evidence=[install_source(facts.apps.get(pkg) or AppInfo(pkg))],
            fixes=[] if pkg in protected or "/" not in entry else [Fix(
                f"listener:{entry}", "listener", entry, label=f"Remove {name(pkg)}'s notification access")],
            by_hand=["Settings > search 'notification access' > switch it off for this app."]))

    for comp in facts.admins:
        pkg = component_package(comp)
        if pkg not in state.third_party:
            continue
        findings.append(Finding(
            "device-admin", "high" if pkg in sideloaded else "medium",
            f"{name(pkg)} is a device admin: it can lock the phone and resist being removed",
            why="Device admin rights are how some loan and spy apps stop people uninstalling them.",
            subject=comp, evidence=[install_source(facts.apps.get(pkg) or AppInfo(pkg))],
            by_hand=["Settings > search 'device admin' > untick this app; it can then be removed "
                     "normally. (adb cannot remove another app's admin rights.)"]))

    special = {component_package(c) for c in facts.accessibility + facts.listeners + facts.admins}
    for pkg in sorted(sideloaded - remote_hits):
        if pkg in protected:
            continue
        info = facts.apps.get(pkg) or AppInfo(pkg)
        perms = sorted(p for p in info.granted if p in SENSITIVE)
        if perms:
            title = (f"{name(pkg)} came from outside an app store and can "
                     f"{_join([SENSITIVE[p] for p in perms])}")
        elif pkg in special:
            title = f"{name(pkg)} came from outside an app store and has special access (listed above)"
        else:
            title = f"{name(pkg)} came from outside an app store"
        fixes = [Fix(f"revoke:{pkg}:{short_permission(p)}", "revoke", pkg, detail=p,
                     label=f"Take away: {SENSITIVE[p]}") for p in perms]
        fixes.append(disable_fix(pkg, name(pkg)))
        findings.append(Finding(
            "sideloaded", "high" if perms or pkg in special else "low", title,
            why=("Fake bank, KYC and loan apps are installed from files, not from a store; loan apps "
                 "use contacts and SMS access to harass and blackmail."),
            subject=pkg, evidence=[install_source(info)], fixes=fixes))

    if "com.android.vending" in enabled:
        protect_steps = ["Play Store > profile picture > Play Protect > settings (gear) > "
                         "Scan apps with Play Protect: on."]
        if facts.play_protect == "-1":
            findings.append(Finding(
                "play-protect", "high", "Play Protect scanning is off",
                why="Play Protect checks every app for known malware, including APK files.",
                by_hand=protect_steps))
        elif facts.play_protect != "1":
            findings.append(Finding("play-protect", "low", "Could not confirm that Play Protect is on",
                                    by_hand=protect_steps))

    age = months_between(facts.security_patch, today)
    if age is not None and age >= 12:
        findings.append(Finding(
            "security-patch", "medium",
            f"Last security update: {facts.security_patch[:7]} ({age} months ago)",
            why="Known holes in old Android versions are what malicious APKs use.",
            by_hand=["Settings > System update (Software update): install anything offered. If nothing "
                     "is offered, the phone no longer gets fixes: keep its apps updated and be extra "
                     "careful with links."]))

    if facts.whatsapp_bytes:
        findings.append(Finding(
            "whatsapp-storage", "info", f"WhatsApp media: {facts.whatsapp_bytes / 1e9:.1f} GB on this phone",
            why="Forwarded videos and images fill phones; a full phone stops updating its apps.",
            by_hand=["WhatsApp > Settings > Storage and data > Manage storage: start with 'Forwarded "
                     "many times' and 'Larger than 5 MB'. This tool never deletes media."]))

    findings.append(Finding("debugging", "info", "USB debugging is on (this tool needs it)",
                            by_hand=["The last step, `parent finish`, turns USB and wireless debugging off."]))

    findings.sort(key=lambda f: (SEVERITIES.index(f.severity), CHECK_ORDER.index(f.check)))
    for finding in findings:
        for fix in finding.fixes:
            fix.check = finding.check
    fixes = [fix for finding in findings for fix in finding.fixes]
    return Audit(
        created=time.strftime("%Y-%m-%dT%H:%M:%S%z"),
        device=state.summary(),
        findings=findings,
        checklist=list(CHECKLIST),
        stats={
            "severity": {s: sum(1 for f in findings if f.severity == s) for s in SEVERITIES},
            "recommended": sum(1 for fix in fixes if fix.recommended),
            "ask": sum(1 for fix in fixes if not fix.recommended),
            "whatsapp_bytes": facts.whatsapp_bytes,
        },
    )


def run_audit(adb: core.Adb, today: Optional[str] = None) -> Audit:
    state = core.probe_device(adb)
    facts = gather(adb, state)
    return build_audit(facts, state, today or time.strftime("%Y-%m-%d"))


def audit_to_dict(audit: Audit) -> Dict[str, object]:
    data = asdict(audit)
    data["version"] = 1
    data["kind"] = "parent-audit"
    return data


def audit_from_dict(data: Dict[str, object]) -> Audit:
    findings = []
    for raw in data.get("findings", []):  # type: ignore[union-attr]
        item = dict(raw)
        item["fixes"] = [Fix(**fix) for fix in item.get("fixes", [])]
        findings.append(Finding(**item))
    return Audit(created=str(data.get("created", "")), device=dict(data.get("device", {})),  # type: ignore[arg-type]
                 findings=findings, checklist=list(data.get("checklist", [])),  # type: ignore[arg-type]
                 stats=dict(data.get("stats", {})))  # type: ignore[arg-type]


def quote(value: str) -> str:
    """Quote for the phone's /system/bin/sh: component names contain `$` (Outer$Inner)."""
    return shlex.quote(value)


# --------------------------------------------------------------------------- applying


@dataclass
class Change:
    id: str
    kind: str
    target: str
    detail: str
    status: str                    # done | failed | skipped; only "done" is ever undone
    before: Dict[str, Optional[str]] = field(default_factory=dict)
    output: str = ""
    check: str = ""


@dataclass
class ParentRecord:
    created: str
    device: Dict[str, object]
    audit_file: str
    changes: List[Change] = field(default_factory=list)
    debugging_off: bool = False


def _change(fix: Fix, status: str, before: Optional[Dict[str, Optional[str]]] = None,
            output: str = "") -> Change:
    return Change(fix.id, fix.kind, fix.target, fix.detail, status, dict(before or {}), output.strip(),
                  check=fix.check)


def read_install_modes(adb: core.Adb, pkg: str) -> Dict[str, Optional[str]]:
    return parse_appop_modes(adb.shell(f"appops get {pkg} {INSTALL_OP}", check=False))


def _deny_install(adb: core.Adb, fix: Fix, state: core.DeviceState) -> Change:
    pkg = fix.target
    if pkg not in state.packages:
        return _change(fix, "skipped", output="not installed")
    before = read_install_modes(adb, pkg)
    if effective_mode(before) != "allow":
        return _change(fix, "skipped", before, f"already {effective_mode(before)}")
    outputs = [adb.shell(f"appops set {pkg} {INSTALL_OP} deny", check=False)]
    after = read_install_modes(adb, pkg)
    if effective_mode(after) != "deny" and after.get("uid") not in (None, "default"):
        # the allow was set for the app's uid, which wins over the package mode
        outputs.append(adb.shell(f"appops set --uid {pkg} {INSTALL_OP} deny", check=False))
        after = read_install_modes(adb, pkg)
    output = "\n".join(o.strip() for o in outputs if o.strip()) or f"now {effective_mode(after)}"
    if effective_mode(after) == "deny":
        return _change(fix, "done", before, output)
    adb.shell(f"appops set {pkg} {INSTALL_OP} {before.get('package') or 'default'}", check=False)
    return _change(fix, "failed", before, output)


POLL_TRIES, POLL_DELAY = 5, 0.4


def _poll(read: Callable[[], bool], tries: int = POLL_TRIES) -> bool:
    """True once read() is. The system persists notification access on a background thread, so
    the setting can lag the command by a moment; adbd takes a moment to go away."""
    for attempt in range(tries):
        if read():
            return True
        if attempt < tries - 1:
            time.sleep(POLL_DELAY)
    return False


def granted_permissions(adb: core.Adb, pkg: str) -> Set[str]:
    info = parse_package_dump(adb.shell(f"dumpsys package {pkg}", check=False)).get(pkg)
    return info.granted if info else set()


def secure_components(adb: core.Adb, key: str) -> List[str]:
    return split_components(setting(adb, "secure", key) or "")


def put_components(adb: core.Adb, key: str, components: Sequence[str]) -> None:
    if components:
        adb.shell(f"settings put secure {key} {quote(':'.join(components))}", check=False)
    else:
        adb.shell(f"settings delete secure {key}", check=False)


def _disable(adb: core.Adb, fix: Fix, state: core.DeviceState) -> Change:
    if fix.target not in state.packages:
        return _change(fix, "skipped", output="not installed")
    if fix.target in state.disabled:
        return _change(fix, "skipped", output="already switched off")
    action = core.disable_package(adb, fix.target, allow_uninstall=False)   # never uninstalls
    return _change(fix, "done" if action.ok else "failed", output=action.output)


def _revoke(adb: core.Adb, fix: Fix, state: core.DeviceState) -> Change:
    pkg, permission = fix.target, fix.detail
    if permission not in SENSITIVE:
        return _change(fix, "skipped", output=f"refused: parent mode does not take away {permission}")
    if pkg not in state.packages:
        return _change(fix, "skipped", output="not installed")
    if permission not in granted_permissions(adb, pkg):
        return _change(fix, "skipped", output="not granted")
    out = adb.shell(f"pm revoke {pkg} {permission}", check=False)
    ok = permission not in granted_permissions(adb, pkg)
    return _change(fix, "done" if ok else "failed", {"granted": "true"},
                   out.strip() or ("taken away" if ok else "still granted"))


def _remove_accessibility(adb: core.Adb, fix: Fix, state: core.DeviceState) -> Change:
    key = "enabled_accessibility_services"
    before = setting(adb, "secure", key) or ""
    entries = split_components(before)
    if fix.target not in entries:
        return _change(fix, "skipped", output="already off")
    put_components(adb, key, [e for e in entries if e != fix.target])
    ok = fix.target not in secure_components(adb, key)
    return _change(fix, "done" if ok else "failed", {"value": before}, "removed" if ok else "still on")


def _remove_listener(adb: core.Adb, fix: Fix, state: core.DeviceState) -> Change:
    key = "enabled_notification_listeners"
    before = setting(adb, "secure", key) or ""
    if "/" not in fix.target:
        return _change(fix, "skipped", output="not a component; switch it off in Settings")
    if fix.target not in split_components(before):
        return _change(fix, "skipped", output="already off")
    out = adb.shell(f"cmd notification disallow_listener {quote(fix.target)}", check=False)
    ok = _poll(lambda: fix.target not in secure_components(adb, key))
    return _change(fix, "done" if ok else "failed", {"value": before},
                   out.strip() or ("removed" if ok else "still allowed"))


def _legacy_unknown_sources_off(adb: core.Adb, fix: Fix, state: core.DeviceState) -> Change:
    before = setting(adb, "secure", "install_non_market_apps")
    if before != "1":
        return _change(fix, "skipped", output=f"already {before or 'off'}")
    adb.shell("settings put secure install_non_market_apps 0", check=False)
    ok = setting(adb, "secure", "install_non_market_apps") == "0"
    return _change(fix, "done" if ok else "failed", {"value": before}, "off" if ok else "still on")


APPLIERS = {
    "install": _deny_install,
    "unknown-sources": _legacy_unknown_sources_off,
    "disable": _disable,
    "revoke": _revoke,
    "accessibility": _remove_accessibility,
    "listener": _remove_listener,
}
TOUCHES_APP = {"disable", "revoke", "accessibility", "listener"}


# --------------------------------------------------------------------------- undoing


def _undone(change: Change, ok: bool, output: str) -> Change:
    return Change(change.id, change.kind, change.target, change.detail, "done" if ok else "failed",
                  dict(change.before), output.strip(), check=change.check)


def _undo_install(adb: core.Adb, change: Change) -> Change:
    pkg, before = change.target, change.before
    if before.get("uid") is not None:
        adb.shell(f"appops set --uid {pkg} {INSTALL_OP} {before['uid']}", check=False)
    adb.shell(f"appops set {pkg} {INSTALL_OP} {before.get('package') or 'default'}", check=False)
    now = effective_mode(read_install_modes(adb, pkg))
    return _undone(change, now == effective_mode(before), f"now {now}")


def _undo_legacy_unknown_sources(adb: core.Adb, change: Change) -> Change:
    value = change.before.get("value") or "1"
    adb.shell(f"settings put secure install_non_market_apps {quote(value)}", check=False)
    ok = setting(adb, "secure", "install_non_market_apps") == value
    return _undone(change, ok, "back on" if ok else "could not switch back on")


def _undo_disable(adb: core.Adb, change: Change) -> Change:
    action = core.enable_package(adb, change.target, "disable")
    return _undone(change, action.ok, action.output)


def _undo_revoke(adb: core.Adb, change: Change) -> Change:
    out = adb.shell(f"pm grant {change.target} {change.detail}", check=False)
    ok = change.detail in granted_permissions(adb, change.target)
    return _undone(change, ok, out.strip() or ("granted again" if ok else "still not granted"))


def _undo_accessibility(adb: core.Adb, change: Change) -> Change:
    key = "enabled_accessibility_services"
    entries = secure_components(adb, key)
    if change.target not in entries:          # keep whatever was switched on since
        put_components(adb, key, entries + [change.target])
    ok = change.target in secure_components(adb, key)
    return _undone(change, ok, "on again" if ok else "could not switch back on")


def _undo_listener(adb: core.Adb, change: Change) -> Change:
    out = adb.shell(f"cmd notification allow_listener {quote(change.target)}", check=False)
    ok = _poll(lambda: change.target in secure_components(adb, "enabled_notification_listeners"))
    return _undone(change, ok, out.strip() or ("allowed again" if ok else "still not allowed"))


UNDO = {
    "install": _undo_install,
    "unknown-sources": _undo_legacy_unknown_sources,
    "disable": _undo_disable,
    "revoke": _undo_revoke,
    "accessibility": _undo_accessibility,
    "listener": _undo_listener,
}


def restore_record(adb: core.Adb, record: ParentRecord,
                   progress: Optional[Callable[[Change], None]] = None) -> List[Change]:
    """Undo every change that was made, newest first. Failed and skipped ones changed nothing."""
    results: List[Change] = []
    for change in reversed(record.changes):
        undo = UNDO.get(change.kind)
        if change.status != "done" or undo is None:
            continue
        result = undo(adb, change)
        results.append(result)
        if progress:
            progress(result)
    return results


def apply_fix(adb: core.Adb, fix: Fix, state: core.DeviceState, protected: Dict[str, str]) -> Change:
    applier = APPLIERS.get(fix.kind)
    if applier is None:
        return _change(fix, "skipped", output=f"unknown kind of change: {fix.kind}")
    pkg = component_package(fix.target)
    if fix.kind in TOUCHES_APP and pkg in protected:
        return _change(fix, "skipped", output=f"refused: {protected[pkg]}")
    return applier(adb, fix, state)


def check_device(saved: Dict[str, object], state: core.DeviceState, what: str) -> None:
    if saved.get("serial_hash") not in ("", None, state.serial_hash):
        raise core.PlanError(f"this {what} was made on a different phone; run `parent audit` on this one")


def select_fixes(audit: Audit, fix_ids: Sequence[str] = (), skip_ids: Sequence[str] = ()) -> List[Fix]:
    """The audit's recommended fixes minus `skip_ids`, plus `fix_ids`; ids must be the audit's."""
    available = audit.fixes()
    unknown = [i for i in list(fix_ids) + list(skip_ids) if i not in available]
    if unknown:
        raise core.PlanError("not in the audit: " + ", ".join(unknown))
    return [fix for fix in available.values()
            if (fix.recommended and fix.id not in skip_ids) or fix.id in fix_ids]


def apply_audit(adb: core.Adb, audit: Audit, fix_ids: Sequence[str] = (), skip_ids: Sequence[str] = (),
                record_path: Optional[Path] = None, audit_file: str = "",
                state: Optional[core.DeviceState] = None,
                progress: Optional[Callable[[Change], None]] = None) -> ParentRecord:
    """Make the selected fixes. Each change is read back and written to the record before the
    next one starts."""
    state = state or core.probe_device(adb)
    check_device(audit.device, state, "audit")
    chosen = select_fixes(audit, fix_ids, skip_ids)
    protected = core.protected_packages(state, core.load_never())
    record_path = record_path or core.BACKUP_DIR / f"parent-record-{core.timestamp()}.json"
    record = ParentRecord(created=time.strftime("%Y-%m-%dT%H:%M:%S%z"), device=state.summary(),
                          audit_file=audit_file)
    core.write_json(record_path, record_to_dict(record))
    for fix in chosen:
        change = apply_fix(adb, fix, state, protected)
        record.changes.append(change)
        core.write_json(record_path, record_to_dict(record))     # survive an interrupted run
        if progress:
            progress(change)
    return record


def record_to_dict(record: ParentRecord) -> Dict[str, object]:
    data = asdict(record)
    data["version"] = 1
    data["kind"] = "parent-record"
    return data


def record_from_dict(data: Dict[str, object]) -> ParentRecord:
    if data.get("kind") != "parent-record":
        raise ValueError("not a parent-mode record (debloat records are undone with "
                         "`debloat.py restore --record`)")
    return ParentRecord(created=str(data.get("created", "")), device=dict(data.get("device", {})),  # type: ignore[arg-type]
                        audit_file=str(data.get("audit_file", "")),
                        changes=[Change(**c) for c in data.get("changes", [])],  # type: ignore[union-attr]
                        debugging_off=bool(data.get("debugging_off", False)))


# --------------------------------------------------------------------------- card and finish


def finding_fixed(finding: Finding, done_ids: Set[str]) -> bool:
    """Honest "fixed": the app was switched off, or every other change the finding offered was
    made. Taking away one of two permissions does not count."""
    if any(fix.id in done_ids for fix in finding.fixes if fix.kind == "disable"):
        return True
    others = [fix for fix in finding.fixes if fix.kind != "disable"]
    return bool(others) and all(fix.id in done_ids for fix in others)


def card_facts(record: ParentRecord, audit: Optional[Audit] = None) -> Dict[str, int]:
    """The integers a card may state. Nothing else from the phone reaches the card."""
    done = [c for c in record.changes if c.status == "done"]

    def count(kinds: Set[str], check: str = "") -> int:
        return sum(1 for c in done if c.kind in kinds and (not check or c.check == check))

    facts = {
        "install": count({"install"}),
        "legacy": count({"unknown-sources"}),
        "remote": count({"disable"}, "remote-access"),
        "sideloaded": count({"disable"}, "sideloaded"),
        "permissions": count({"revoke"}),
        "access": count({"accessibility", "listener"}),
        "debugging_off": int(record.debugging_off),
        "changes": len(done),
        "found": 0,
        "fixed": 0,
        "whatsapp_gb_tenths": 0,
    }
    if audit is not None:
        risks = [f for f in audit.findings if f.severity in ("high", "medium")]
        done_ids = {c.id for c in done}
        facts["found"] = len(risks)
        facts["fixed"] = sum(1 for f in risks if finding_fixed(f, done_ids))
        facts["whatsapp_gb_tenths"] = int(round(float(audit.stats.get("whatsapp_bytes") or 0) / 1e8))  # type: ignore[arg-type]
    return facts


def finish_commands(serial: str) -> List[str]:
    """Switch both debugging transports off, the one this session uses last: switching it off
    ends the connection, so anything after it would never run."""
    wifi = ":" in serial or "_adb-tls-connect" in serial
    first, last = ("adb_enabled", "adb_wifi_enabled") if wifi else ("adb_wifi_enabled", "adb_enabled")
    return [f"settings put global {first} 0", f"settings put global {last} 0"]


def connected(adb: core.Adb, serial: str) -> bool:
    try:
        return any(d["serial"] == serial and d["state"] == "device" for d in adb.devices())
    except core.AdbError:
        return False


# --------------------------------------------------------------------------- output


SECTION = {"high": "FIX NOW", "medium": "WORTH A LOOK", "low": "FOR YOUR INFORMATION", "info": "GOOD TO KNOW"}


def _wrap(prefix: str, text: str) -> None:
    # never split a word or at a hyphen: change ids and package names are copied into --fix
    print(textwrap.fill(text, width=100, initial_indent=prefix, subsequent_indent=" " * len(prefix),
                        break_long_words=False, break_on_hyphens=False))


def print_audit(audit: Audit) -> None:
    print(f"Device: {core.device_line(audit.device)}")
    print("Parent mode audit. Nothing on the phone has been changed.")
    for severity in SEVERITIES:
        group = [f for f in audit.findings if f.severity == severity]
        if not group:
            continue
        print()
        print(f"{SECTION[severity]} ({len(group)})")
        for finding in group:
            _wrap("  - ", finding.title)
            if finding.why:
                _wrap("      why: ", finding.why)
            for line in finding.evidence:
                _wrap("      seen: ", line)
            for fix in finding.fixes:
                _wrap(f"      [{'auto' if fix.recommended else 'ask '}] ", f"{fix.label}  ({fix.id})")
            for step in finding.by_hand:
                _wrap("      by hand: ", step)
    print()
    print("TOGETHER WITH THEM (no tool can do these)")
    for number, item in enumerate(audit.checklist, 1):
        _wrap(f"  {number}. ", item)
    print()
    print(f"[auto] changes, made by `parent apply` unless named with --skip: {audit.stats.get('recommended', 0)}")
    print(f"[ask]  changes, made only when the owner agrees and they are named with --fix: "
          f"{audit.stats.get('ask', 0)}")


def print_change(change: Change) -> None:
    mark = {"done": "ok  ", "failed": "FAIL", "skipped": "skip"}.get(change.status, change.status)
    first = change.output.splitlines()[0] if change.output else ""
    print(f"  {mark} {change.id}   {first}")


def _tool(args: argparse.Namespace) -> str:
    return "python3 tools/debloat.py " + (f"--serial {args.serial} " if args.serial else "") + "parent"


# --------------------------------------------------------------------------- commands


def cmd_audit(args: argparse.Namespace) -> int:
    adb = core.make_adb(args)
    state = core.probe_device(adb)
    audit = build_audit(gather(adb, state), state, time.strftime("%Y-%m-%d"))
    model = core.slug(str(state.summary()["model"]))
    path = Path(args.out) if args.out else core.BACKUP_DIR / f"parent-audit-{model}-{core.timestamp()}.json"
    core.write_json(path, audit_to_dict(audit))
    if args.json:
        print(json.dumps(audit_to_dict(audit), indent=2, sort_keys=True))
        return 0
    print_audit(audit)
    print()
    print(f"Audit written: {path}")
    print("Next: go through it with the owner, in their words. With their yes:")
    print(f"  {_tool(args)} apply --audit {path} --yes [--fix <id>,<id>] [--skip <id>]")
    return 0


def cmd_apply(args: argparse.Namespace) -> int:
    audit_path = Path(args.audit)
    audit = audit_from_dict(core.read_json(audit_path))
    fix_ids, skip_ids = core.split_csv(args.fix), core.split_csv(args.skip)
    adb = core.make_adb(args)
    state = core.probe_device(adb)
    check_device(audit.device, state, "audit")
    chosen = select_fixes(audit, fix_ids, skip_ids)
    if args.dry_run:
        for fix in chosen:
            print(f"{fix.id}   {fix.label}")
        return 0
    if not chosen:
        print("Nothing to change: the audit recommends nothing and no --fix was named.")
        return 0
    print(f"Device: {core.device_line(state.summary())}")
    print(f"WILL CHANGE ({len(chosen)}), each one undoable:")
    for fix in chosen:
        print(f"  {fix.label}  ({fix.id})")
    print()
    if not args.yes and not core.confirm(f"Make these {len(chosen)} changes now?"):
        print("Not applied. Re-run with --yes once the owner has agreed.")
        return 2
    model = core.slug(str(state.summary()["model"]))
    backup_path = core.BACKUP_DIR / f"backup-{model}-{core.timestamp()}.json"
    core.write_json(backup_path, core.make_backup(adb, state))
    record_path = core.BACKUP_DIR / f"parent-record-{model}-{core.timestamp()}.json"
    print(f"Backup written: {backup_path}")
    print(f"Applying; record: {record_path}")
    record = apply_audit(adb, audit, fix_ids, skip_ids, record_path, str(audit_path), state=state,
                         progress=print_change)
    problems = core.verify(state, core.probe_device(adb))
    counts = {s: sum(1 for c in record.changes if c.status == s) for s in ("done", "failed", "skipped")}
    print()
    print(f"Done: {counts['done']} changed, {counts['failed']} failed, {counts['skipped']} skipped "
          "(failed and skipped ones were left as they were).")
    if problems:
        print("VERIFY FAILED, undoing:")
        for problem in problems:
            print(f"  - {problem}")
        restore_record(adb, record, progress=print_change)
        return 1
    print("Verified: home screen, keyboard, phone and messaging apps unchanged.")
    print(f"Undo any time:   {_tool(args)} restore --record {record_path}")
    print(f"Shareable card:  {_tool(args)} card --record {record_path} --who Mum")
    print(f"Last step:       {_tool(args)} finish --record {record_path} --yes")
    return 0


def cmd_restore(args: argparse.Namespace) -> int:
    record = record_from_dict(core.read_json(Path(args.record)))
    adb = core.make_adb(args)
    state = core.probe_device(adb)
    check_device(record.device, state, "record")
    results = restore_record(adb, record, progress=print_change)
    ok = sum(1 for r in results if r.status == "done")
    print(f"Undone {ok}/{len(results)} changes.")
    return 0 if ok == len(results) else 1


def cmd_card(args: argparse.Namespace) -> int:
    record = record_from_dict(core.read_json(Path(args.record)))
    audit_path = Path(args.audit) if args.audit else Path(record.audit_file) if record.audit_file else None
    audit = audit_from_dict(core.read_json(audit_path)) if audit_path and audit_path.exists() else None
    svg_text = parentcard.svg(card_facts(record, audit), who=args.who or "")
    prefix = Path(args.out) if args.out else core.BACKUP_DIR / f"parent-card-{core.timestamp()}"
    svg_path, html_path = prefix.with_suffix(".svg"), prefix.with_suffix(".html")
    svg_path.parent.mkdir(parents=True, exist_ok=True)
    svg_path.write_text(svg_text, encoding="utf-8")
    html_path.write_text(parentcard.page(svg_text), encoding="utf-8")
    print(f"Card: {html_path}  (open it; its button saves or shares a PNG)")
    print(f"      {svg_path}")
    if args.png:
        print(f"      {parentcard.render_png(svg_text, prefix.with_suffix('.png'))}")
    print("The card shows counts only: no app names, phone model, numbers or personal details.")
    return 0


def cmd_finish(args: argparse.Namespace) -> int:
    adb = core.make_adb(args)
    serial = core.select_device(adb)
    print("This switches USB debugging and wireless debugging off on the phone; adb disconnects.")
    print("To use this tool on it again later: Settings > About phone > tap Build number 7 times, "
          "then Developer options > USB debugging.")
    if not args.yes and not core.confirm("Switch debugging off now?"):
        print("Not done. Re-run with --yes when everything else is finished.")
        return 2
    for command in finish_commands(serial):
        adb.shell(command, check=False)
    if not _poll(lambda: not connected(adb, serial), tries=12):
        still_on = [key for key in ("adb_enabled", "adb_wifi_enabled")
                    if setting(adb, "global", key) not in (None, "0")]
        if still_on:
            print(f"Debugging is still on ({', '.join(still_on)}). Switch it off by hand: Settings > "
                  "System > Developer options > USB debugging and Wireless debugging.")
            return 1
    if args.record:
        path = Path(args.record)
        record = record_from_dict(core.read_json(path))
        record.debugging_off = True
        core.write_json(path, record_to_dict(record))
    print("USB and wireless debugging are off; adb is disconnected from the phone.")
    print("Optional, by hand: Settings > System > Developer options > switch the whole menu off.")
    return 0


def add_commands(parser: argparse.ArgumentParser) -> None:
    sub = parser.add_subparsers(dest="parent_command", required=True)
    p = sub.add_parser("audit", help="read-only: what on this phone a scam caller or fake APK could use")
    p.add_argument("--out", help="audit file (default: backups/parent-audit-<model>-<time>.json)")
    p.set_defaults(func=cmd_audit)

    p = sub.add_parser("apply", help="make the [auto] changes and the [ask] ones named with --fix")
    p.add_argument("--audit", required=True)
    p.add_argument("--fix", action="append",
                   help="[ask] change ids the owner agreed to (comma-separated, repeatable)")
    p.add_argument("--skip", action="append", help="[auto] change ids to leave out")
    p.add_argument("--yes", action="store_true", help="the owner has agreed")
    p.add_argument("--dry-run", action="store_true", help="list what would change and exit")
    p.set_defaults(func=cmd_apply)

    p = sub.add_parser("restore", help="undo a parent-mode record")
    p.add_argument("--record", required=True)
    p.set_defaults(func=cmd_restore)

    p = sub.add_parser("card", help="a shareable card: counts only, no app names or personal details")
    p.add_argument("--record", required=True)
    p.add_argument("--audit", help="the audit file (default: the one the record names)")
    p.add_argument("--who", help="a first name or relation for the card: Mum, Papa, Nani")
    p.add_argument("--out", help="output path without extension (default: backups/parent-card-<time>)")
    p.add_argument("--png", action="store_true", help="also render a PNG (needs Chrome or Chromium)")
    p.set_defaults(func=cmd_card)

    p = sub.add_parser("finish", help="switch USB and wireless debugging off; always the last step")
    p.add_argument("--record", help="mark this parent-mode record as finished")
    p.add_argument("--yes", action="store_true", help="everything else is done")
    p.set_defaults(func=cmd_finish)

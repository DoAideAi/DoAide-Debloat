#!/usr/bin/env python3
"""DoAide Debloat: reversible, agent-friendly debloating of Android phones and tablets over ADB.

    probe    what the device is, what owns Home/keyboard/phone/SMS, how many packages
    backup   snapshot package state and settings to backups/ (always before a change)
    plan     what would be disabled, grouped by reason; writes a plan file; changes nothing
    apply    disable the packages in a plan file; writes a record file for restore
    restore  undo a record file, or re-enable everything from a backup file
    check    report (and optionally fix) what a firmware update re-enabled
    lookup   what a package is, from the bundled profiles and the community (UAD) list
    connect  adb connect / pair helpers for Wi-Fi debugging

Design rules the code enforces, not just documents:
  * nothing is ever uninstalled from the system image; `pm disable-user` is the default,
    `pm uninstall -k --user 0` is an opt-in fallback and is undone by `install-existing`
  * the current home screen, keyboard, phone, SMS and browser apps are never touched,
    nor anything matching data/never-disable.txt
  * only packages that are actually installed on the connected device are acted on
  * every change is written to a record file before the next one is made

Stdlib only, Python 3.9+.
"""
from __future__ import annotations

import argparse
import fnmatch
import hashlib
import json
import os
import re
import shutil
import subprocess
import sys
import time
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Callable, Dict, Iterable, List, Optional, Sequence, Set, Tuple

sys.path.insert(0, str(Path(__file__).resolve().parent))
import uadlist  # noqa: E402

REPO = Path(__file__).resolve().parent.parent
DATA_DIR = REPO / "data"
PROFILES_DIR = DATA_DIR / "profiles"
NEVER_FILE = DATA_DIR / "never-disable.txt"
BACKUP_DIR = Path(os.environ.get("DOAIDE_DEBLOAT_HOME", str(REPO / "backups")))

USER = "0"
CATEGORIES = ("ads", "telemetry", "junk", "ask")
ACTIVE_CATEGORIES = ("ads", "telemetry", "junk")
HOME_INTENT = "-a android.intent.action.MAIN -c android.intent.category.HOME"
ROLES = {
    "android.app.role.HOME": "home screen",
    "android.app.role.DIALER": "phone app",
    "android.app.role.SMS": "messaging app",
    "android.app.role.BROWSER": "default browser",
    "android.app.role.EMERGENCY": "emergency app",
}
PROPS = (
    "ro.product.manufacturer",
    "ro.product.brand",
    "ro.product.model",
    "ro.product.device",
    "ro.product.name",
    "ro.build.version.release",
    "ro.build.version.sdk",
    "ro.build.display.id",
)
OEM_ALIASES = {
    "samsung": "samsung",
    "xiaomi": "xiaomi",
    "redmi": "xiaomi",
    "poco": "xiaomi",
    "oppo": "oppo",
    "oneplus": "oppo",
    "realme": "oppo",
    "vivo": "vivo",
    "iqoo": "vivo",
    "motorola": "motorola",
    "google": "google",
    "amazon": "amazon",
}

Runner = Callable[[Sequence[str]], Tuple[int, str]]


class AdbError(RuntimeError):
    pass


class PlanError(RuntimeError):
    pass


# --------------------------------------------------------------------------- adb


class Adb:
    """Thin wrapper over the adb binary. `runner` is injectable for tests."""

    def __init__(self, serial: Optional[str] = None, runner: Optional[Runner] = None,
                 adb_path: Optional[str] = None) -> None:
        self.serial = serial
        self.adb_path = adb_path or shutil.which("adb") or "adb"
        self._runner = runner or self._subprocess_runner

    def _subprocess_runner(self, args: Sequence[str]) -> Tuple[int, str]:
        try:
            proc = subprocess.run([self.adb_path, *args], capture_output=True, text=True,
                                  timeout=180, errors="replace")
        except FileNotFoundError:
            raise AdbError(
                "adb was not found. Install Android platform-tools: macOS `brew install "
                "android-platform-tools`, Windows `winget install Google.PlatformTools`, "
                "Debian/Ubuntu `sudo apt install adb`; or pass --adb /path/to/adb."
            ) from None
        except subprocess.TimeoutExpired:
            raise AdbError(f"adb timed out: {' '.join(args)}") from None
        return proc.returncode, (proc.stdout or "") + (proc.stderr or "")

    def run(self, *args: str, check: bool = True) -> str:
        full: List[str] = []
        if self.serial:
            full += ["-s", self.serial]
        full += list(args)
        rc, out = self._runner(full)
        out = out.replace("\r\n", "\n").replace("\r", "\n")
        if check and rc != 0:
            raise AdbError(f"adb {' '.join(args)} failed (rc={rc}): {out.strip()}")
        return out

    def shell(self, cmd: str, check: bool = True) -> str:
        return self.run("shell", cmd, check=check)

    def devices(self) -> List[Dict[str, str]]:
        out = self.run("devices", "-l")
        found: List[Dict[str, str]] = []
        for line in out.splitlines():
            line = line.strip()
            if not line or line.startswith("List of devices") or line.startswith("*"):
                continue
            parts = line.split()
            if len(parts) < 2:
                continue
            dev = {"serial": parts[0], "state": parts[1]}
            for extra in parts[2:]:
                if ":" in extra:
                    key, val = extra.split(":", 1)
                    dev[key] = val
            found.append(dev)
        return found


def select_device(adb: Adb) -> str:
    devices = adb.devices()
    if adb.serial:
        for dev in devices:
            if dev["serial"] == adb.serial:
                _assert_ready(dev)
                return adb.serial
        raise AdbError(f"device {adb.serial} is not connected; `adb devices -l` shows: {devices}")
    if not devices:
        raise AdbError(
            "no device is connected. Enable USB debugging on the phone (Settings > About > tap "
            "Build number 7 times > Developer options > USB debugging), plug it in and accept the "
            "'Allow USB debugging?' prompt. For Wi-Fi see recipes/android-phone.md."
        )
    if len(devices) > 1:
        listing = ", ".join(f"{d['serial']} ({d['state']})" for d in devices)
        raise AdbError(
            f"more than one device is connected; pass --serial. Connected: {listing}. "
            "A phone on Wi-Fi debugging is often listed twice (ip:port and an adb-...._adb-tls-connect "
            "name): that is one device, use --serial <ip:port>."
        )
    _assert_ready(devices[0])
    adb.serial = devices[0]["serial"]
    return adb.serial


def _assert_ready(dev: Dict[str, str]) -> None:
    if dev["state"] == "unauthorized":
        raise AdbError("the device is connected but unauthorized: accept 'Allow USB debugging?' on "
                       "its screen (tick 'Always allow'), then run again")
    if dev["state"] != "device":
        raise AdbError(f"the device is in state '{dev['state']}', not ready for adb")


# --------------------------------------------------------------------------- device state


@dataclass
class DeviceState:
    serial_hash: str
    props: Dict[str, str]
    packages: Set[str]            # installed for user 0, enabled or disabled
    disabled: Set[str]            # subset of packages
    uninstalled: Set[str]         # user-uninstalled (still on the system image)
    third_party: Set[str]
    home: Optional[str]
    ime: Optional[str]
    roles: Dict[str, List[str]]

    @property
    def oem(self) -> str:
        return detect_oem(self.props)

    def summary(self) -> Dict[str, object]:
        return {
            "serial_hash": self.serial_hash,
            "manufacturer": self.props.get("ro.product.manufacturer", ""),
            "brand": self.props.get("ro.product.brand", ""),
            "model": self.props.get("ro.product.model", ""),
            "device": self.props.get("ro.product.device", ""),
            "android": self.props.get("ro.build.version.release", ""),
            "sdk": self.props.get("ro.build.version.sdk", ""),
            "build": self.props.get("ro.build.display.id", ""),
            "oem_profile": self.oem,
            "packages": len(self.packages),
            "disabled": len(self.disabled),
            "user_uninstalled": len(self.uninstalled),
            "third_party": len(self.third_party),
            "home": self.home,
            "keyboard": self.ime,
            "roles": self.roles,
        }


def detect_oem(props: Dict[str, str]) -> str:
    for key in ("ro.product.manufacturer", "ro.product.brand"):
        value = props.get(key, "").strip().lower()
        if value in OEM_ALIASES:
            return OEM_ALIASES[value]
        for alias, oem in OEM_ALIASES.items():
            if alias in value:
                return oem
    return "other"


def parse_getprop(out: str) -> Dict[str, str]:
    props: Dict[str, str] = {}
    for match in re.finditer(r"^\[([^\]]+)\]: \[(.*)\]$", out, re.M):
        props[match.group(1)] = match.group(2)
    return props


def parse_package_list(out: str) -> Set[str]:
    pkgs: Set[str] = set()
    for line in out.splitlines():
        line = line.strip()
        if line.startswith("package:"):
            pkgs.add(line[len("package:"):].strip())
    return pkgs


def package_of(component: str) -> Optional[str]:
    component = component.strip()
    if not component or component.lower().startswith("null"):
        return None
    return component.split("/", 1)[0]


def probe_device(adb: Adb) -> DeviceState:
    serial = select_device(adb)
    props_all = parse_getprop(adb.shell("getprop"))
    props = {p: props_all.get(p, "") for p in PROPS}
    for p in PROPS:
        if not props[p]:
            props[p] = adb.shell(f"getprop {p}", check=False).strip()
    packages = parse_package_list(adb.shell("pm list packages"))
    disabled = parse_package_list(adb.shell("pm list packages -d")) & packages
    with_uninstalled = parse_package_list(adb.shell("pm list packages -u", check=False))
    uninstalled = with_uninstalled - packages
    third_party = parse_package_list(adb.shell("pm list packages -3", check=False)) & packages

    home = None
    out = adb.shell(f"cmd package resolve-activity --brief {HOME_INTENT}", check=False)
    for line in reversed(out.splitlines()):
        if "/" in line and not line.startswith("priority"):
            home = package_of(line)
            break
    ime = package_of(adb.shell("settings get secure default_input_method", check=False))

    roles: Dict[str, List[str]] = {}
    for role in ROLES:
        out = adb.shell(f"cmd role get-role-holders {role}", check=False).strip()
        if not out or "Error" in out or "Exception" in out or "not found" in out.lower():
            continue
        holders = [h for h in re.split(r"[;\s]+", out) if re.fullmatch(r"[A-Za-z0-9_.]+", h)]
        if holders:
            roles[role] = holders
    # Android 9 and older: no role manager, fall back to secure settings
    if "android.app.role.SMS" not in roles:
        pkg = package_of(adb.shell("settings get secure sms_default_application", check=False))
        if pkg:
            roles["android.app.role.SMS"] = [pkg]
    if "android.app.role.DIALER" not in roles:
        pkg = package_of(adb.shell("settings get secure dialer_default_application", check=False))
        if pkg:
            roles["android.app.role.DIALER"] = [pkg]

    return DeviceState(
        serial_hash=hashlib.sha256(serial.encode()).hexdigest()[:12],
        props=props, packages=packages, disabled=disabled, uninstalled=uninstalled,
        third_party=third_party, home=home, ime=ime, roles=roles,
    )


# --------------------------------------------------------------------------- lists


@dataclass
class Entry:
    package: str
    category: str
    note: str
    source: str


PACKAGE_RE = re.compile(r"[A-Za-z0-9_.]+")
PATTERN_RE = re.compile(r"[A-Za-z0-9_.*?]+")


def parse_list(text: str, source: str) -> List[Entry]:
    entries: List[Entry] = []
    for lineno, raw in enumerate(text.splitlines(), 1):
        line = raw.split("#", 1)[0].strip()
        if not line:
            continue
        parts = [p.strip() for p in line.split("|")]
        pkg = parts[0]
        category = parts[1] if len(parts) > 1 and parts[1] else "junk"
        note = parts[2] if len(parts) > 2 else ""
        if not PACKAGE_RE.fullmatch(pkg):
            raise ValueError(f"{source}:{lineno}: '{pkg}' is not a package name")
        if category not in CATEGORIES:
            raise ValueError(f"{source}:{lineno}: unknown category '{category}' "
                             f"(expected one of {', '.join(CATEGORIES)})")
        entries.append(Entry(pkg, category, note, source))
    return entries


def parse_patterns(text: str, source: str) -> List[str]:
    patterns: List[str] = []
    for lineno, raw in enumerate(text.splitlines(), 1):
        line = raw.split("#", 1)[0].strip()
        if not line:
            continue
        pattern = line.split("|", 1)[0].strip()
        if not PATTERN_RE.fullmatch(pattern):
            raise ValueError(f"{source}:{lineno}: '{pattern}' is not a package pattern")
        patterns.append(pattern)
    return patterns


def load_never(path: Path = NEVER_FILE) -> List[str]:
    return parse_patterns(path.read_text(encoding="utf-8"), str(path))


def profile_files(oem: str, profiles_dir: Path = PROFILES_DIR) -> List[Path]:
    files = [profiles_dir / "generic.txt"]
    oem_file = profiles_dir / f"{oem}.txt"
    if oem != "other" and oem_file.exists():
        files.append(oem_file)
    return [f for f in files if f.exists()]


def load_entries(files: Iterable[Path]) -> List[Entry]:
    entries: List[Entry] = []
    for path in files:
        entries.extend(parse_list(path.read_text(encoding="utf-8"), path.name))
    return entries


def load_all_entries(profiles_dir: Path = PROFILES_DIR) -> List[Entry]:
    return load_entries(sorted(profiles_dir.glob("*.txt")))


def matches_never(package: str, patterns: Sequence[str]) -> Optional[str]:
    for pattern in patterns:
        if fnmatch.fnmatchcase(package, pattern):
            return pattern
    return None


def protected_packages(state: DeviceState, never_patterns: Sequence[str]) -> Dict[str, str]:
    """Package -> reason it must not be touched. Computed live from the device."""
    protected: Dict[str, str] = {}
    for pkg in state.packages | state.disabled:
        pattern = matches_never(pkg, never_patterns)
        if pattern:
            protected[pkg] = f"never-disable list ({pattern})"
    if state.home:
        protected[state.home] = "current home screen"
    if state.ime:
        protected[state.ime] = "current keyboard"
    for role, holders in state.roles.items():
        for holder in holders:
            protected.setdefault(holder, f"current {ROLES.get(role, role)}")
    return protected


# --------------------------------------------------------------------------- plan


@dataclass
class PlanItem:
    package: str
    category: str
    note: str
    source: str
    uad_removal: str = ""
    uad_description: str = ""


@dataclass
class Plan:
    created: str
    device: Dict[str, object]
    oem: str
    profiles: List[str]
    protected: Dict[str, str]
    items: List[PlanItem]
    questions: List[Dict[str, str]]
    warnings: List[str]
    skipped: Dict[str, List[str]]

    def packages(self) -> List[str]:
        return [item.package for item in self.items]


def build_plan(state: DeviceState, entries: Sequence[Entry], never_patterns: Sequence[str],
               keep: Iterable[str] = (), remove: Iterable[str] = (), broad: Optional[str] = None,
               uad: Optional[Dict[str, dict]] = None, profiles: Sequence[str] = ()) -> Plan:
    keep_set = set(keep)
    remove_set = set(remove)
    protected = protected_packages(state, never_patterns)
    skipped: Dict[str, List[str]] = {"not_installed": [], "protected": [], "kept": [],
                                     "already_disabled": []}
    items: Dict[str, PlanItem] = {}
    questions: List[Dict[str, str]] = []
    warnings: List[str] = []

    def eligible(pkg: str, bucket_on_fail: bool = True) -> bool:
        if pkg not in state.packages:
            if bucket_on_fail:
                skipped["not_installed"].append(pkg)
            return False
        if pkg in protected:
            skipped["protected"].append(pkg)
            return False
        if pkg in keep_set:
            skipped["kept"].append(pkg)
            return False
        if pkg in state.disabled:
            skipped["already_disabled"].append(pkg)
            return False
        return True

    for entry in entries:
        if entry.package in items:
            continue
        if not eligible(entry.package):
            continue
        if entry.category == "ask" and entry.package not in remove_set:
            questions.append({"package": entry.package, "note": entry.note, "source": entry.source})
            continue
        items[entry.package] = PlanItem(entry.package, entry.category, entry.note, entry.source)

    for pkg in sorted(remove_set):
        if pkg in items:
            continue
        if pkg not in state.packages:
            warnings.append(f"--remove {pkg}: not installed on this device, ignored")
            continue
        if pkg in protected:
            raise PlanError(f"--remove {pkg} refused: {protected[pkg]}")
        if pkg in state.disabled:
            skipped["already_disabled"].append(pkg)
            continue
        items[pkg] = PlanItem(pkg, "owner", "named by the owner", "owner")

    if broad:
        if not uad:
            warnings.append("--broad requested but the community (UAD) list is unavailable; "
                            "only the bundled profiles were used")
        else:
            allowed = {"Oem", "Misc", "Carrier"} if broad == "oem" else {"Oem", "Misc", "Carrier",
                                                                            "Google", "Aosp"}
            for pkg in sorted(state.packages):
                if pkg in items or pkg in protected or pkg in keep_set or pkg in state.disabled:
                    continue
                meta = uadlist.info(uad, pkg)
                if not meta or meta["removal"] != "Recommended" or meta["list"] not in allowed:
                    continue
                items[pkg] = PlanItem(pkg, "community", uadlist.first_line(meta["description"]),
                                      "uad")

    for item in items.values():
        meta = uadlist.info(uad, item.package)
        if not meta:
            continue
        item.uad_removal = meta["removal"]
        item.uad_description = uadlist.first_line(meta["description"])
        if meta["removal"] == "Unsafe":
            warnings.append(f"{item.package} is marked Unsafe by the community list; "
                            f"disabling it may break the device. Keep it unless you are sure.")
        for needer in meta["neededBy"]:
            if needer in state.packages and needer not in items and needer not in state.disabled:
                warnings.append(f"{item.package} is needed by {needer}, which stays enabled")

    for pkg in items:
        if pkg in protected:  # belt and braces: the plan can never contain a protected package
            raise PlanError(f"internal error: protected package {pkg} reached the plan")

    return Plan(
        created=time.strftime("%Y-%m-%dT%H:%M:%S%z"),
        device=state.summary(),
        oem=state.oem,
        profiles=list(profiles),
        protected=protected,
        items=sorted(items.values(), key=lambda i: (i.category, i.package)),
        questions=questions,
        warnings=warnings,
        skipped=skipped,
    )


def plan_to_dict(plan: Plan) -> Dict[str, object]:
    data = asdict(plan)
    data["version"] = 1
    return data


def plan_from_dict(data: Dict[str, object]) -> Plan:
    items = [PlanItem(**i) for i in data.get("items", [])]  # type: ignore[arg-type]
    return Plan(
        created=str(data.get("created", "")),
        device=dict(data.get("device", {})),  # type: ignore[arg-type]
        oem=str(data.get("oem", "")),
        profiles=list(data.get("profiles", [])),  # type: ignore[arg-type]
        protected=dict(data.get("protected", {})),  # type: ignore[arg-type]
        items=items,
        questions=list(data.get("questions", [])),  # type: ignore[arg-type]
        warnings=list(data.get("warnings", [])),  # type: ignore[arg-type]
        skipped=dict(data.get("skipped", {})),  # type: ignore[arg-type]
    )


# --------------------------------------------------------------------------- apply / restore


@dataclass
class Action:
    package: str
    method: str          # "disable" or "uninstall-user"
    ok: bool
    output: str


@dataclass
class Record:
    created: str
    device: Dict[str, object]
    plan_file: str
    allow_uninstall: bool
    actions: List[Action] = field(default_factory=list)


def disable_package(adb: Adb, pkg: str, allow_uninstall: bool) -> Action:
    # Success is judged on the text, never the exit code: ColorOS/OxygenOS answers a refusal with
    # "Package X new state: default" and exit 0; Samsung with a SecurityException and exit 0.
    out = adb.shell(f"pm disable-user --user {USER} {pkg}", check=False)
    if "new state: disabled" in out:
        return Action(pkg, "disable", True, out.strip())
    if not allow_uninstall:
        return Action(pkg, "disable", False, out.strip())
    out2 = adb.shell(f"pm uninstall -k --user {USER} {pkg}", check=False)
    if out2.strip().startswith("Success"):
        return Action(pkg, "uninstall-user", True, out2.strip())
    return Action(pkg, "uninstall-user", False, (out.strip() + "\n" + out2.strip()).strip())


def apply_plan(adb: Adb, plan: Plan, state: DeviceState, plan_file: str, allow_uninstall: bool,
               record_path: Path, progress: Optional[Callable[[Action], None]] = None) -> Record:
    live_protected = protected_packages(state, load_never())
    record = Record(created=time.strftime("%Y-%m-%dT%H:%M:%S%z"), device=state.summary(),
                    plan_file=plan_file, allow_uninstall=allow_uninstall)
    if plan.device.get("serial_hash") not in ("", None, state.serial_hash):
        raise PlanError("this plan was made for a different device; make a new plan")
    write_json(record_path, record_to_dict(record))
    for item in plan.items:
        pkg = item.package
        if pkg in live_protected:
            action = Action(pkg, "skip", False, f"refused: {live_protected[pkg]}")
        elif pkg not in state.packages:
            action = Action(pkg, "skip", False, "not installed")
        elif pkg in state.disabled:
            action = Action(pkg, "skip", True, "already disabled")
        else:
            action = disable_package(adb, pkg, allow_uninstall)
        record.actions.append(action)
        write_json(record_path, record_to_dict(record))   # survive an interrupted run
        if progress:
            progress(action)
    return record


def record_to_dict(record: Record) -> Dict[str, object]:
    data = asdict(record)
    data["version"] = 1
    return data


def record_from_dict(data: Dict[str, object]) -> Record:
    actions = [Action(**a) for a in data.get("actions", [])]  # type: ignore[arg-type]
    return Record(created=str(data.get("created", "")), device=dict(data.get("device", {})),  # type: ignore[arg-type]
                  plan_file=str(data.get("plan_file", "")),
                  allow_uninstall=bool(data.get("allow_uninstall", False)), actions=actions)


def enable_package(adb: Adb, pkg: str, method: str) -> Action:
    if method == "uninstall-user":
        out = adb.shell(f"cmd package install-existing --user {USER} {pkg}", check=False)
        ok = "installed for user" in out or out.strip().startswith("Success")
        if ok:
            out2 = adb.shell(f"pm enable --user {USER} {pkg}", check=False)
            out = (out.strip() + "\n" + out2.strip()).strip()
        return Action(pkg, "install-existing", ok, out.strip())
    out = adb.shell(f"pm enable --user {USER} {pkg}", check=False)
    return Action(pkg, "enable", "new state: enabled" in out, out.strip())


def restore_record(adb: Adb, record: Record,
                   progress: Optional[Callable[[Action], None]] = None) -> List[Action]:
    results: List[Action] = []
    for action in reversed(record.actions):
        if not action.ok or action.method not in ("disable", "uninstall-user"):
            continue
        result = enable_package(adb, action.package, action.method)
        results.append(result)
        if progress:
            progress(result)
    return results


def restore_from_backup(adb: Adb, backup: Dict[str, object], state: DeviceState,
                        progress: Optional[Callable[[Action], None]] = None) -> List[Action]:
    """Re-enable whatever the backup says was enabled and is now disabled or user-removed."""
    was_installed = set(backup.get("packages", []))  # type: ignore[arg-type]
    was_disabled = set(backup.get("disabled", []))  # type: ignore[arg-type]
    was_enabled = was_installed - was_disabled
    results: List[Action] = []
    for pkg in sorted(was_installed & state.uninstalled):
        result = enable_package(adb, pkg, "uninstall-user")
        results.append(result)
        if progress:
            progress(result)
    for pkg in sorted(was_enabled & state.disabled):
        result = enable_package(adb, pkg, "disable")
        results.append(result)
        if progress:
            progress(result)
    return results


def drift(record: Record, state: DeviceState) -> List[Action]:
    """Actions from the record that a firmware update (or a person) has undone."""
    undone: List[Action] = []
    for action in record.actions:
        if not action.ok:
            continue
        if action.method == "disable" and action.package in state.packages \
                and action.package not in state.disabled:
            undone.append(action)
        elif action.method == "uninstall-user" and action.package in state.packages:
            undone.append(action)
    return undone


def verify(state_before: DeviceState, state_after: DeviceState) -> List[str]:
    problems: List[str] = []
    if state_before.home and state_after.home != state_before.home:
        problems.append(f"home screen changed from {state_before.home} to {state_after.home}")
    if state_before.ime and state_after.ime != state_before.ime:
        problems.append(f"keyboard changed from {state_before.ime} to {state_after.ime}")
    for role, holders in state_before.roles.items():
        for holder in holders:
            if holder in state_after.disabled or holder not in state_after.packages:
                problems.append(f"{ROLES.get(role, role)} {holder} is no longer enabled")
    for pkg in (state_before.home, state_before.ime):
        if pkg and (pkg in state_after.disabled or pkg not in state_after.packages):
            problems.append(f"{pkg} is no longer enabled")
    return problems


# --------------------------------------------------------------------------- backup


def make_backup(adb: Adb, state: DeviceState) -> Dict[str, object]:
    return {
        "version": 1,
        "created": time.strftime("%Y-%m-%dT%H:%M:%S%z"),
        "device": state.summary(),
        "props": state.props,
        "packages": sorted(state.packages),
        "disabled": sorted(state.disabled),
        "user_uninstalled": sorted(state.uninstalled),
        "third_party": sorted(state.third_party),
        "home": state.home,
        "keyboard": state.ime,
        "roles": state.roles,
        "settings": {
            "global": adb.shell("settings list global", check=False),
            "secure": adb.shell("settings list secure", check=False),
            "system": adb.shell("settings list system", check=False),
        },
    }


# --------------------------------------------------------------------------- files & output


def slug(text: str) -> str:
    return re.sub(r"[^A-Za-z0-9]+", "-", text).strip("-").lower() or "device"


def timestamp() -> str:
    return time.strftime("%Y%m%d-%H%M%S")


def write_json(path: Path, data: Dict[str, object]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(path.suffix + ".tmp")
    tmp.write_text(json.dumps(data, indent=2, sort_keys=True), encoding="utf-8")
    tmp.replace(path)


def read_json(path: Path) -> Dict[str, object]:
    return json.loads(path.read_text(encoding="utf-8"))


def device_line(summary: Dict[str, object]) -> str:
    return (f"{summary.get('manufacturer')} {summary.get('model')} "
            f"(Android {summary.get('android')}, build {summary.get('build')})")


def print_plan(plan: Plan) -> None:
    print(f"Device: {device_line(plan.device)}")
    print(f"Profiles: {', '.join(plan.profiles) or 'none'}   OEM: {plan.oem}")
    print(f"Protected (never touched): {len(plan.protected)} packages, including "
          f"home={plan.device.get('home')} keyboard={plan.device.get('keyboard')}")
    print()
    if plan.items:
        print(f"WILL DISABLE ({len(plan.items)}):")
        width = max(len(i.package) for i in plan.items)
        for item in plan.items:
            note = item.note or item.uad_description
            level = f" [{item.uad_removal}]" if item.uad_removal else ""
            print(f"  {item.category:<10} {item.package:<{width}}  {note}{level}")
    else:
        print("WILL DISABLE: nothing (no listed package is installed and enabled)")
    if plan.questions:
        print()
        print(f"ASK THE OWNER ({len(plan.questions)}) - disabled only when named with --remove:")
        width = max(len(q["package"]) for q in plan.questions)
        for idx, q in enumerate(plan.questions, 1):
            print(f"  [{idx:>2}] {q['package']:<{width}}  {q['note']}")
    counts = {k: len(v) for k, v in plan.skipped.items() if v}
    if counts:
        print()
        print("Skipped: " + ", ".join(f"{n} {k.replace('_', ' ')}" for k, n in counts.items()))
    if plan.warnings:
        print()
        print("Warnings:")
        for warning in plan.warnings:
            print(f"  - {warning}")


def print_action(action: Action) -> None:
    mark = "ok " if action.ok else "FAIL"
    print(f"  {mark} {action.method:<16} {action.package}   {action.output.splitlines()[0] if action.output else ''}")


# --------------------------------------------------------------------------- commands


def make_adb(args: argparse.Namespace) -> Adb:
    return Adb(serial=args.serial, adb_path=args.adb)


def cmd_probe(args: argparse.Namespace) -> int:
    adb = make_adb(args)
    state = probe_device(adb)
    protected = protected_packages(state, load_never())
    summary = state.summary()
    summary["protected"] = len(protected)
    summary["profiles"] = [p.name for p in profile_files(state.oem)]
    if args.json:
        print(json.dumps(summary, indent=2, sort_keys=True))
        return 0
    print(f"Device:      {device_line(summary)}")
    print(f"OEM profile: {state.oem}  ({', '.join(summary['profiles'])})")  # type: ignore[arg-type]
    print(f"Packages:    {len(state.packages)} installed, {len(state.disabled)} disabled, "
          f"{len(state.uninstalled)} user-removed, {len(state.third_party)} third-party")
    print(f"Home:        {state.home}")
    print(f"Keyboard:    {state.ime}")
    for role, holders in state.roles.items():
        if role == "android.app.role.HOME" and holders == [state.home]:
            continue
        print(f"{ROLES.get(role, role).capitalize() + ':':<13}{', '.join(holders)}")
    print(f"Protected:   {len(protected)} packages will never be touched")
    return 0


def cmd_backup(args: argparse.Namespace) -> int:
    adb = make_adb(args)
    state = probe_device(adb)
    backup = make_backup(adb, state)
    path = BACKUP_DIR / f"backup-{slug(str(state.summary()['model']))}-{timestamp()}.json"
    write_json(path, backup)
    print(f"Backup written: {path}")
    print(f"  {len(state.packages)} packages ({len(state.disabled)} disabled), settings snapshot, "
          f"home={state.home}")
    return 0


def split_csv(values: Optional[List[str]]) -> List[str]:
    out: List[str] = []
    for value in values or []:
        out.extend(v.strip() for v in value.split(",") if v.strip())
    return out


def cmd_plan(args: argparse.Namespace) -> int:
    adb = make_adb(args)
    state = probe_device(adb)
    oem = args.profile or state.oem
    files = profile_files(oem)
    entries = load_entries(files)
    uad = None if args.no_uad else uadlist.load(offline=args.offline)
    plan = build_plan(state, entries, load_never(), keep=split_csv(args.keep),
                      remove=split_csv(args.remove), broad=args.broad, uad=uad,
                      profiles=[f.name for f in files])
    path = Path(args.out) if args.out else BACKUP_DIR / f"plan-{slug(str(state.summary()['model']))}-{timestamp()}.json"
    write_json(path, plan_to_dict(plan))
    if args.json:
        print(json.dumps(plan_to_dict(plan), indent=2, sort_keys=True))
    else:
        print_plan(plan)
        print()
        print(f"Plan written: {path}")
        print("Nothing has been changed. Review, answer the questions with --remove, then: "
              f"apply --plan {path} --yes")
    return 0


def confirm(prompt: str) -> bool:
    if not sys.stdin.isatty():
        return False
    return input(f"{prompt} [y/N] ").strip().lower() in ("y", "yes")


def cmd_apply(args: argparse.Namespace) -> int:
    plan = plan_from_dict(read_json(Path(args.plan)))
    adb = make_adb(args)
    state = probe_device(adb)
    if args.dry_run:
        for item in plan.items:
            print(f"adb shell pm disable-user --user {USER} {item.package}")
        return 0
    if not plan.items:
        print("The plan has nothing to disable.")
        return 0
    print_plan(plan)
    print()
    if not args.yes and not confirm(f"Disable these {len(plan.items)} packages now?"):
        print("Not applied. Re-run with --yes once the owner has agreed.")
        return 2
    backup = make_backup(adb, state)
    model = slug(str(state.summary()["model"]))
    backup_path = BACKUP_DIR / f"backup-{model}-{timestamp()}.json"
    write_json(backup_path, backup)
    record_path = BACKUP_DIR / f"record-{model}-{timestamp()}.json"
    print(f"Backup written: {backup_path}")
    print(f"Applying; record: {record_path}")
    record = apply_plan(adb, plan, state, args.plan, args.allow_uninstall, record_path,
                        progress=print_action)
    after = probe_device(adb)
    problems = verify(state, after)
    done = sum(1 for a in record.actions if a.ok and a.method in ("disable", "uninstall-user"))
    failed = [a for a in record.actions if not a.ok]
    print()
    print(f"Done: {done} disabled, {len(failed)} failed, "
          f"{len(after.disabled)} packages now disabled on the device.")
    if failed:
        print("Failed (left as they were):")
        for action in failed:
            print(f"  {action.package}: {action.output.splitlines()[0] if action.output else ''}")
        if not args.allow_uninstall and any(a.method == "disable" for a in failed):
            print("  Some OEMs refuse `pm disable-user` for a few packages. Re-run with "
                  "--allow-uninstall to fall back to `pm uninstall -k --user 0` (reversible with "
                  "restore), if the owner agrees.")
    if problems:
        print("VERIFY FAILED, restoring:")
        for problem in problems:
            print(f"  - {problem}")
        restore_record(adb, record, progress=print_action)
        return 1
    print(f"Verified: home, keyboard, phone and messaging apps unchanged.")
    print(f"Undo any time: tools/debloat.py restore --record {record_path}")
    return 0


def cmd_restore(args: argparse.Namespace) -> int:
    adb = make_adb(args)
    if args.record:
        record = record_from_dict(read_json(Path(args.record)))
        state = probe_device(adb)
        if record.device.get("serial_hash") not in ("", None, state.serial_hash):
            raise PlanError("this record belongs to a different device")
        results = restore_record(adb, record, progress=print_action)
    else:
        backup = read_json(Path(args.backup))
        state = probe_device(adb)
        dev = backup.get("device") or {}
        if dev.get("serial_hash") not in ("", None, state.serial_hash):  # type: ignore[union-attr]
            raise PlanError("this backup belongs to a different device")
        results = restore_from_backup(adb, backup, state, progress=print_action)
    ok = sum(1 for r in results if r.ok)
    print(f"Restored {ok}/{len(results)} packages.")
    return 0 if ok == len(results) else 1


def cmd_check(args: argparse.Namespace) -> int:
    adb = make_adb(args)
    record = record_from_dict(read_json(Path(args.record)))
    state = probe_device(adb)
    undone = drift(record, state)
    if not undone:
        print("No drift: everything in the record is still disabled.")
        return 0
    print(f"Drift: {len(undone)} packages are enabled again (a firmware update, most likely):")
    for action in undone:
        print(f"  {action.package}")
    if not args.fix:
        print("Re-run with --fix to disable them again.")
        return 1
    live_protected = protected_packages(state, load_never())
    fixed = 0
    for action in undone:
        if action.package in live_protected:
            print(f"  skip {action.package}: {live_protected[action.package]}")
            continue
        result = disable_package(adb, action.package, record.allow_uninstall)
        print_action(result)
        fixed += int(result.ok)
    print(f"Fixed {fixed}/{len(undone)}.")
    return 0 if fixed == len(undone) else 1


def cmd_lookup(args: argparse.Namespace) -> int:
    entries = load_all_entries()
    uad = None if args.no_uad else uadlist.load(offline=args.offline)
    state = probe_device(make_adb(args)) if args.device else None
    for term in args.terms:
        needle = term.lower()
        print(f"== {term}")
        hits = [e for e in entries if needle in e.package.lower() or needle in e.note.lower()]
        for entry in hits:
            print(f"  profile {entry.source:<12} {entry.category:<10} {entry.package}  {entry.note}")
        meta = uadlist.info(uad, term)
        shown = set()
        if meta:
            shown.add(term)
            print(f"  community {meta['list']}/{meta['removal']}: {term}")
            for line in meta["description"].splitlines()[:6]:
                print(f"      {line}")
        for pkg, info in uadlist.search(uad, term, limit=args.limit):
            if pkg in shown:
                continue
            print(f"  community {info.get('list', '')}/{info.get('removal', '')}: {pkg}  "
                  f"{uadlist.first_line(info.get('description', ''))}")
        if state:
            for pkg in sorted(p for p in state.packages if needle in p.lower()):
                status = "disabled" if pkg in state.disabled else "enabled"
                print(f"  on device: {pkg} ({status})")
        if not hits and not meta and not uad:
            print("  (not in the bundled profiles; community list unavailable offline)")
    return 0


def parse_mdns_services(out: str) -> Dict[str, List[str]]:
    """`adb mdns services` -> {"pairing": [ip:port, ...], "connect": [ip:port, ...]}."""
    found: Dict[str, List[str]] = {"pairing": [], "connect": []}
    for line in out.splitlines():
        parts = line.split()
        if len(parts) < 3 or ":" not in parts[-1]:
            continue
        service, addr = parts[1], parts[-1]
        if "_adb-tls-pairing" in service:
            found["pairing"].append(addr)
        elif "_adb-tls-connect" in service or "_adb._tcp" in service:
            found["connect"].append(addr)
    return found


def cmd_connect(args: argparse.Namespace) -> int:
    adb = make_adb(args)
    pair_target = args.pair
    host = args.host
    if args.discover or not host:
        services = parse_mdns_services(adb.run("mdns", "services", check=False))
        if not services["connect"] and not services["pairing"]:
            raise AdbError("no device advertises Wi-Fi debugging on this network. On the phone: "
                           "Developer options > Wireless debugging > on, then 'Pair device with "
                           "pairing code' and pass --code.")
        if args.code and not pair_target and services["pairing"]:
            pair_target = services["pairing"][0]
        if not host and services["connect"]:
            host = services["connect"][0]
        print(f"Discovered: pairing={services['pairing'] or '-'} connect={services['connect'] or '-'}")
    if pair_target:
        if not args.code:
            raise AdbError("--pair needs --code (the six-digit code shown on the phone)")
        print(adb.run("pair", pair_target, args.code, check=False).strip())
    if not host:
        raise AdbError("nothing to connect to: pass a host or run --discover with Wireless debugging on")
    target = host if ":" in host else f"{host}:5555"
    print(adb.run("connect", target, check=False).strip())
    print(f"Use --serial {target} for the other commands.")
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="debloat.py", description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--serial", "-s", help="adb serial when more than one device is connected")
    parser.add_argument("--adb", help="path to the adb binary")
    parser.add_argument("--json", action="store_true", help="machine-readable output")
    sub = parser.add_subparsers(dest="command", required=True)

    sub.add_parser("probe", help="describe the connected device").set_defaults(func=cmd_probe)
    sub.add_parser("backup", help="snapshot package state and settings").set_defaults(func=cmd_backup)

    p = sub.add_parser("plan", help="compute what would be disabled; changes nothing")
    p.add_argument("--profile", help="force an OEM profile (samsung, xiaomi, oppo, vivo, motorola, "
                                     "google, amazon); default: detect")
    p.add_argument("--keep", action="append", help="packages to leave alone (comma-separated, repeatable)")
    p.add_argument("--remove", action="append", help="'ask' packages the owner wants gone "
                                                      "(comma-separated, repeatable)")
    p.add_argument("--broad", nargs="?", const="oem", choices=["oem", "all"],
                   help="also include everything the community list marks Recommended for OEM/"
                        "carrier/misc packages ('all' adds Google and AOSP ones). Aggressive; "
                        "review every line.")
    p.add_argument("--no-uad", action="store_true", help="do not consult the community list")
    p.add_argument("--offline", action="store_true", help="never download the community list")
    p.add_argument("--out", help="plan file path (default: backups/plan-<model>-<time>.json)")
    p.set_defaults(func=cmd_plan)

    p = sub.add_parser("apply", help="disable the packages in a plan file")
    p.add_argument("--plan", required=True)
    p.add_argument("--yes", action="store_true", help="the owner has agreed to the plan")
    p.add_argument("--allow-uninstall", action="store_true",
                   help="if `pm disable-user` is refused, fall back to `pm uninstall -k --user 0` "
                        "(reversible with restore)")
    p.add_argument("--dry-run", action="store_true", help="print the adb commands and exit")
    p.set_defaults(func=cmd_apply)

    p = sub.add_parser("restore", help="undo a record, or re-enable everything from a backup")
    g = p.add_mutually_exclusive_group(required=True)
    g.add_argument("--record")
    g.add_argument("--backup")
    p.set_defaults(func=cmd_restore)

    p = sub.add_parser("check", help="what a firmware update re-enabled")
    p.add_argument("--record", required=True)
    p.add_argument("--fix", action="store_true")
    p.set_defaults(func=cmd_check)

    p = sub.add_parser("lookup", help="what a package is")
    p.add_argument("terms", nargs="+", help="package names or words (e.g. 'glance', 'bixby')")
    p.add_argument("--device", action="store_true", help="also show matches installed on the device")
    p.add_argument("--limit", type=int, default=10)
    p.add_argument("--no-uad", action="store_true")
    p.add_argument("--offline", action="store_true")
    p.set_defaults(func=cmd_lookup)

    p = sub.add_parser("connect", help="adb connect (and pair) over Wi-Fi")
    p.add_argument("host", nargs="?", help="ip or ip:port of the device (omit with --discover)")
    p.add_argument("--discover", action="store_true",
                   help="find the pairing/connect ports with `adb mdns services` (same Wi-Fi)")
    p.add_argument("--pair", help="ip:port shown under 'Pair device with pairing code'")
    p.add_argument("--code", help="the six-digit pairing code")
    p.set_defaults(func=cmd_connect)
    return parser


def main(argv: Optional[Sequence[str]] = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        return int(args.func(args))
    except (AdbError, PlanError, ValueError, FileNotFoundError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())

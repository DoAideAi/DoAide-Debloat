#!/usr/bin/env python3
"""DoAide Debloat X-ray: what your phone sends home while nobody is using it, before and after.

    setup    is PCAPdroid on the phone? (--open-store opens its Play Store page there)
    capture  record N idle minutes of the phone's traffic with PCAPdroid and analyse it
    analyze  analyse a PCAP you captured yourself with PCAPdroid
    card     the shareable before/after card, the public summary and the Phone-Home Index link
    show     print a saved report again

How a capture works. PCAPdroid (open source, no root) runs a local VPN on the phone and writes a
PCAP file to Download/PCAPdroid/. This tool starts and stops it over adb through PCAPdroid's
documented intent API, wakes the lock screen a few times the way a person glances at a phone,
pulls the file, deletes it from the phone, and reads server names out of it (DNS, TLS SNI, HTTP
Host) without decrypting anything. A server counts as ad or tracking when one of HaGeZi's lists
names it; Exodus Privacy's list adds the company name. The raw capture is deleted afterwards
unless --keep-pcap is given. Reports stay in backups/, which is git-ignored.

What leaves the computer is only what `card` writes to share.json, and only if the owner posts
it: counts, plus the tracker domains that preinstalled apps contacted. Never the serial, IP
addresses, other servers, or anything about apps the owner installed.

Stdlib only, Python 3.9+.
"""
from __future__ import annotations

import argparse
import html
import json
import os
import re
import shlex
import shutil
import subprocess
import sys
import tempfile
import textwrap
import time
import urllib.parse
from collections import Counter
from pathlib import Path
from typing import Callable, Dict, List, Optional, Sequence, Set, Tuple

sys.path.insert(0, str(Path(__file__).resolve().parent))
import debloat  # noqa: E402
import pcapscan  # noqa: E402
import trackerdb  # noqa: E402

PCAPDROID = "com.emanuelef.remote_capture"
CTRL = f"{PCAPDROID}/.activities.CaptureCtrl"
MIN_VERSION = 79              # dump_extensions; block_quic needs 73, pcap_name 62 (PCAPdroid app_api.md)
DEVICE_DIR = "/sdcard/Download/PCAPdroid"
PLAY_URL = f"market://details?id={PCAPDROID}"
STORE_LINKS = (f"https://play.google.com/store/apps/details?id={PCAPDROID}",
               f"https://f-droid.org/packages/{PCAPDROID}/")
API_KEY_ENV = "PCAPDROID_API_KEY"
MAX_DUMP = 256 * 1024 * 1024
WAKE_SECONDS = 8
POLL_SECONDS = 3
START_TIMEOUT = 120
STOP_TIMEOUT = 120
REPO_URL = "https://github.com/DoAideAi/DoAide-Debloat"
SHORT_URL = "github.com/DoAideAi/DoAide-Debloat"
ISSUE_TEMPLATE = "xray-report.yml"
SCHEMA = "doaide-xray/1"
SHARE_SCHEMA = "doaide-xray-share/1"
URL_LIMIT = 7500

SLEEP: Callable[[float], None] = time.sleep   # tests replace this


class XrayError(RuntimeError):
    pass


# --------------------------------------------------------------------------- PCAPdroid over adb


def am_command(action: str, extras: Sequence[Tuple[str, str]] = (), api_key: Optional[str] = None) -> str:
    parts = ["am", "start", "-n", CTRL, "-e", "action", action]
    for key, value in extras:
        parts += ["-e", key, value]
    if api_key:
        parts += ["-e", "api_key", api_key]
    return " ".join(shlex.quote(p) for p in parts)


def _am(adb: debloat.Adb, action: str, extras: Sequence[Tuple[str, str]], api_key: Optional[str]) -> str:
    try:
        out = adb.shell(am_command(action, extras, api_key), check=False)
    except debloat.AdbError as exc:
        message = str(exc)
        raise XrayError(message.replace(api_key, "<api key>") if api_key else message) from None
    if "Error" in out or "Exception" in out:
        line = next((l for l in out.splitlines() if "Error" in l or "Exception" in l), out.strip())
        raise XrayError(f"PCAPdroid did not accept '{action}': {line.strip()}")
    return out


def pcapdroid_version(adb: debloat.Adb) -> Tuple[Optional[int], Optional[str]]:
    out = adb.shell(f"dumpsys package {PCAPDROID}", check=False)
    code = re.search(r"versionCode=(\d+)", out)
    name = re.search(r"versionName=(\S+)", out)
    return (int(code.group(1)) if code else None), (name.group(1) if name else None)


def ensure_pcapdroid(adb: debloat.Adb, state: debloat.DeviceState) -> Dict[str, object]:
    if PCAPDROID not in state.packages:
        raise XrayError("PCAPdroid is not installed on the phone. `tools/xray.py setup --open-store` opens "
                        "its Play Store page on the phone (it is also on F-Droid): tap Install, open it "
                        "once, then run capture again.")
    if PCAPDROID in state.disabled:
        raise XrayError("PCAPdroid is disabled on the phone; enable it in Settings > Apps first.")
    code, name = pcapdroid_version(adb)
    if code is not None and code < MIN_VERSION:
        raise XrayError(f"PCAPdroid {name or code} is too old: the X-ray needs version code {MIN_VERSION} or "
                        "newer. Update it from the Play Store or F-Droid.")
    return {"version_code": code, "version_name": name}


def capture_running(adb: debloat.Adb) -> bool:
    return "CaptureService" in adb.shell(f"dumpsys activity services {PCAPDROID}", check=False)


def remote_size(adb: debloat.Adb, path: str) -> Optional[int]:
    out = adb.shell(f"stat -c %s {shlex.quote(path)}", check=False).strip()
    return int(out) if out.isdigit() else None


def wait_until(predicate: Callable[[], bool], timeout: float, sleep: Callable[[float], None]) -> bool:
    waited = 0.0
    while True:
        if predicate():
            return True
        if waited >= timeout:
            return False
        sleep(POLL_SECONDS)
        waited += POLL_SECONDS


def wait_stable(adb: debloat.Adb, path: str, sleep: Callable[[float], None], timeout: float = 60) -> Optional[int]:
    """The file size once it stops growing (PCAPdroid flushes its buffer when it stops)."""
    last = remote_size(adb, path)
    waited = 0.0
    while waited < timeout:
        sleep(POLL_SECONDS)
        waited += POLL_SECONDS
        size = remote_size(adb, path)
        if size is not None and size == last:
            return size
        last = size
    return last


def run_capture(adb: debloat.Adb, label: str, minutes: float, wakes: int, api_key: Optional[str],
                out_dir: Path, keep_on_device: bool = False, sleep: Callable[[float], None] = time.sleep,
                say: Callable[[str], None] = print) -> Tuple[Path, Dict[str, object]]:
    """Start PCAPdroid, wait out the idle period with lock-screen wake-ups, stop, pull, clean up."""
    name = f"doaide-xray-{debloat.slug(label)}-{debloat.timestamp()}.pcap"
    remote = f"{DEVICE_DIR}/{name}"
    if capture_running(adb):
        raise XrayError("PCAPdroid is already capturing. Stop that capture on the phone first.")
    extras = [
        ("pcap_dump_mode", "pcap_file"), ("pcap_name", name),
        ("dump_extensions", "true"),        # per-packet trailer with the app's uid
        ("ip_mode", "both"),                # the default is IPv4 only, and IPv6 traffic would bypass it
        ("block_quic", "always"),           # apps fall back to TLS over TCP, whose server name is visible
        ("auto_block_private_dns", "true"),  # Private DNS falls back to plain DNS, which is visible
        ("max_dump_size", str(MAX_DUMP)),
    ]
    _am(adb, "start", extras, api_key)
    if not api_key:
        say("On the phone: tap Allow in the PCAPdroid dialog (the first time, also OK on the VPN request).")
    if not wait_until(lambda: capture_running(adb) or remote_size(adb, remote) is not None, START_TIMEOUT, sleep):
        raise XrayError("PCAPdroid did not start capturing within two minutes. Was the dialog on the phone "
                        "allowed? Another VPN (or Always-on VPN) also blocks it.")
    total = float(minutes) * 60
    say(f"Capturing for {minutes:g} minutes. Leave the phone alone; the screen wakes {wakes} times by itself.")
    adb.shell("input keyevent KEYCODE_SLEEP", check=False)
    elapsed = 0.0
    for i in range(wakes):
        at = total * (i + 0.5) / wakes
        sleep(max(0.0, at - elapsed))
        adb.shell("input keyevent KEYCODE_WAKEUP", check=False)
        sleep(WAKE_SECONDS)
        adb.shell("input keyevent KEYCODE_SLEEP", check=False)
        elapsed = at + WAKE_SECONDS
        say(f"  lock-screen wake-up {i + 1}/{wakes}")
    sleep(max(0.0, total - elapsed))
    if not api_key:
        adb.shell("input keyevent KEYCODE_WAKEUP", check=False)
        say("On the phone: unlock it and tap Allow to stop the capture.")
    _am(adb, "stop", (), api_key)
    if not wait_until(lambda: not capture_running(adb), STOP_TIMEOUT, sleep):
        say("warning: PCAPdroid still shows a running capture. Stop it from its notification on the phone.")
    size = wait_stable(adb, remote, sleep)
    if size is None:
        raise XrayError(f"PCAPdroid wrote no file at {remote}. Open PCAPdroid on the phone to see why.")
    out_dir.mkdir(parents=True, exist_ok=True)
    local = out_dir / name
    adb.run("pull", remote, str(local))
    if not keep_on_device:
        adb.shell(f"rm -f {shlex.quote(remote)}", check=False)
        if remote_size(adb, remote) is not None:
            say(f"warning: could not delete {remote} from the phone; delete it in Files > Download > PCAPdroid.")
    protocol: Dict[str, object] = {
        "minutes": minutes, "wakes": wakes, "wake_seconds": WAKE_SECONDS, "idle": True,
        "ip_mode": "both", "block_quic": "always", "dump_extensions": True, "source": "xray capture",
    }
    return local, protocol


def parse_uid_list(out: str) -> Dict[int, List[str]]:
    """`pm list packages -U` -> {uid: [packages]} (several packages can share one uid)."""
    uids: Dict[int, Set[str]] = {}
    for match in re.finditer(r"^package:(\S+)\s+uid:(\d+)", out, re.M):
        uids.setdefault(int(match.group(2)), set()).add(match.group(1))
    return {uid: sorted(pkgs) for uid, pkgs in uids.items()}


# --------------------------------------------------------------------------- analysis


def _app(uid: int, packages: Dict[int, List[str]], third_party: Set[str], trailer_names: Dict[int, str]) -> dict:
    pkgs = packages.get(uid, [])
    if uid < 0:
        label, system = "not attributed to an app", None
    elif pkgs:
        label = pkgs[0] if len(pkgs) == 1 else f"{pkgs[0]} (+{len(pkgs) - 1} more sharing uid {uid})"
        system = not any(p in third_party for p in pkgs)
    else:
        name = trailer_names.get(uid)
        label = f"{name} (uid {uid})" if name else f"uid {uid}"
        system = True if uid < 10000 else None       # app uids start at 10000
    return {"uid": uid, "label": label, "packages": pkgs, "system": system, "flows": 0, "bytes": 0,
            "hosts": set(), "tracker_hosts": set(), "tracker_flows": 0, "tracker_bytes": 0, "unnamed_flows": 0}


def analyze(cap: pcapscan.Capture, db: trackerdb.TrackerDB, packages: Optional[Dict[int, List[str]]] = None,
            third_party: Optional[Set[str]] = None, device: Optional[Dict[str, object]] = None,
            protocol: Optional[Dict[str, object]] = None, label: str = "") -> Dict[str, object]:
    packages = packages or {}
    third_party = set(third_party or ())
    own = {uid for uid, pkgs in packages.items() if PCAPDROID in pkgs}
    counts: Counter = Counter()
    kept: List[Tuple[pcapscan.Flow, int, Optional[str]]] = []
    apps: Dict[int, dict] = {}
    hosts: Dict[str, dict] = {}
    for flow in cap.flows:
        uid = flow.uid
        if uid in own:
            counts["pcapdroid_flows"] += 1
        elif flow.server_port == 53:
            counts["dns_flows"] += 1
        elif pcapscan.is_local(flow.server):
            counts["local_flows"] += 1
        else:
            kept.append((flow, uid, flow.name))
            if uid not in apps:
                apps[uid] = _app(uid, packages, third_party, cap.app_names)
            if flow.name and flow.name not in hosts:
                hosts[flow.name] = {"host": flow.name, "flows": 0, "bytes": 0, "uids": set(), "via": set()}
    for name, host in hosts.items():
        cnames = sorted(cap.cnames.get(name, ()))
        matches: List[Dict[str, str]] = []
        for candidate in [name] + cnames:
            for hit in db.classify(candidate):
                if hit not in matches:
                    matches.append(hit)
        host.update(trackers=matches, domain=db.registrable(name), cname=cnames)
    for flow, uid, name in kept:
        app = apps[uid]
        counts["flows"] += 1
        counts["bytes"] += flow.bytes
        app["flows"] += 1
        app["bytes"] += flow.bytes
        if not name:
            counts["unnamed_flows"] += 1
            app["unnamed_flows"] += 1
            continue
        host = hosts[name]
        host["flows"] += 1
        host["bytes"] += flow.bytes
        host["uids"].add(uid)
        host["via"].add(flow.via)
        app["hosts"].add(name)
        if host["trackers"]:
            app["tracker_hosts"].add(name)
            app["tracker_flows"] += 1
            app["tracker_bytes"] += flow.bytes

    def is_system(uid: int) -> bool:
        return apps[uid]["system"] is True

    trackers = [h for h in hosts.values() if h["trackers"]]
    domains: Dict[str, dict] = {}
    for host in trackers:
        entry = domains.setdefault(host["domain"], {"domain": host["domain"], "hosts": 0, "system_hosts": 0,
                                                    "flows": 0, "bytes": 0, "lists": []})
        entry["hosts"] += 1
        entry["system_hosts"] += int(any(is_system(u) for u in host["uids"]))
        entry["flows"] += host["flows"]
        entry["bytes"] += host["bytes"]
        for hit in host["trackers"]:
            if hit["name"] not in entry["lists"]:
                entry["lists"].append(hit["name"])
    looked_up = {q.name for q in cap.queries}
    lookups_only = sorted(looked_up - set(hosts))
    tracker_lookups_only = [n for n in lookups_only if db.classify(n)]

    warnings = list(cap.warnings)
    if not db.available:
        warnings.append("no tracker list was available: the tracker counts are zero because nothing was "
                        "checked, not because nothing was found")
    if cap.packets and not cap.trailer_packets:
        warnings.append("the capture has no app information (PCAPdroid's dump extensions were off), so no "
                        "connection is attributed to an app and nothing can be named in a public summary")
    if counts["unnamed_flows"]:
        warnings.append(f"{counts['unnamed_flows']} connections had no server name (no SNI, Host header or "
                        "earlier DNS answer); they are counted but not classified")

    return {
        "schema": SCHEMA,
        "label": label,
        "created": time.strftime("%Y-%m-%dT%H:%M:%S%z"),
        "device": device or {},
        "protocol": protocol or {},
        "capture": {"packets": cap.packets, "bytes": cap.bytes, "seconds": round(cap.seconds, 1),
                    "attributed_packets": cap.trailer_packets, "skipped_packets": cap.skipped},
        "lists": db.sources,
        "lists_available": db.available,
        "totals": {
            "hosts": len(hosts),
            "domains": len({h["domain"] for h in hosts.values()}),
            "tracker_hosts": len(trackers),
            "tracker_domains": len(domains),
            "flows": counts["flows"],
            "tracker_flows": sum(h["flows"] for h in trackers),
            "bytes": counts["bytes"],
            "tracker_bytes": sum(h["bytes"] for h in trackers),
            "unnamed_flows": counts["unnamed_flows"],
            "local_flows": counts["local_flows"],
            "dns_flows": counts["dns_flows"],
            "pcapdroid_flows": counts["pcapdroid_flows"],
            "lookups": len(looked_up),
            "tracker_lookups_without_connection": len(tracker_lookups_only),
        },
        "tracker_domains": sorted(domains.values(), key=lambda d: (-d["flows"], d["domain"])),
        "hosts": [
            {"host": h["host"], "domain": h["domain"], "flows": h["flows"], "bytes": h["bytes"],
             "via": sorted(v for v in h["via"] if v), "cname": h["cname"], "trackers": h["trackers"],
             "apps": sorted(apps[u]["label"] for u in h["uids"]),
             "system": any(is_system(u) for u in h["uids"])}
            for h in sorted(hosts.values(), key=lambda h: (not h["trackers"], -h["flows"], h["host"]))
        ],
        "apps": [
            {"uid": a["uid"], "label": a["label"], "packages": a["packages"], "system": a["system"],
             "flows": a["flows"], "bytes": a["bytes"], "hosts": len(a["hosts"]),
             "tracker_hosts": sorted(a["tracker_hosts"]), "tracker_flows": a["tracker_flows"],
             "tracker_bytes": a["tracker_bytes"], "unnamed_flows": a["unnamed_flows"]}
            for a in sorted(apps.values(), key=lambda a: (-a["tracker_flows"], -a["flows"], a["uid"]))
        ],
        "lookups_without_connection": {"total": len(lookups_only), "trackers": tracker_lookups_only[:200]},
        "warnings": warnings,
    }


# --------------------------------------------------------------------------- the public summary


def maker(device: Dict[str, object]) -> str:
    name = str(device.get("manufacturer") or device.get("brand") or "").strip()
    return name[:1].upper() + name[1:] if name else ""


def device_name(device: Dict[str, object]) -> str:
    return " ".join(x for x in (maker(device), str(device.get("model") or "").strip()) if x) or "Android phone"


def share_summary(before: Dict[str, object], after: Optional[Dict[str, object]] = None,
                  disabled: Optional[int] = None, top: int = 10) -> Dict[str, object]:
    """What may leave the computer: counts, plus tracker domains and packages of preinstalled apps."""

    def side(report: Dict[str, object]) -> Dict[str, object]:
        totals = report["totals"]  # type: ignore[index]
        system_apps = [a for a in report["apps"]  # type: ignore[union-attr]
                       if a.get("system") is True and a.get("packages") and a.get("tracker_hosts")]
        system_apps.sort(key=lambda a: (-len(a["tracker_hosts"]), a["packages"][0]))
        domains = [d for d in report["tracker_domains"] if d.get("system_hosts")]  # type: ignore[union-attr]
        return {
            "hosts": int(totals["hosts"]),
            "tracker_hosts": int(totals["tracker_hosts"]),
            "tracker_domains": int(totals["tracker_domains"]),
            "tracker_connections": int(totals["tracker_flows"]),
            "tracker_kb": int(round(int(totals["tracker_bytes"]) / 1024)),
            "top_tracker_domains": [{"domain": d["domain"], "hosts": int(d["system_hosts"])} for d in domains[:top]],
            "system_apps": [{"package": a["packages"][0], "tracker_hosts": len(a["tracker_hosts"])}
                            for a in system_apps[:top]],
        }

    device = before.get("device") or {}
    protocol = before.get("protocol") or {}
    share: Dict[str, object] = {
        "schema": SHARE_SCHEMA,
        "month": str(before.get("created", ""))[:7],
        "device": {k: str(device.get(k) or "")[:60] for k in ("manufacturer", "brand", "model", "android", "build")},  # type: ignore[union-attr]
        "protocol": {"minutes": protocol.get("minutes"), "wakes": protocol.get("wakes")},  # type: ignore[union-attr]
        "lists": sorted((before.get("lists") or {}).keys()),  # type: ignore[union-attr]
        "before": side(before),
    }
    if after is not None:
        share["after"] = side(after)
    if disabled is not None:
        share["packages_disabled"] = int(disabled)
    return share


def issue_url(share: Dict[str, object], repo: str = REPO_URL) -> Optional[str]:
    name = device_name(share["device"])  # type: ignore[arg-type]
    before = share["before"]["tracker_hosts"]  # type: ignore[index]
    after = share["after"]["tracker_hosts"] if "after" in share else None  # type: ignore[index]
    title = f"[x-ray] {name}: {before} → {after} tracker servers" if after is not None \
        else f"[x-ray] {name}: {before} tracker servers"
    params = [("template", ISSUE_TEMPLATE), ("title", title), ("device", name),
              ("report", json.dumps(share, sort_keys=True, separators=(",", ":")))]
    url = f"{repo}/issues/new?" + urllib.parse.urlencode(params, quote_via=urllib.parse.quote)
    return url if len(url) <= URL_LIMIT else None


def count_disabled(record: Dict[str, object]) -> int:
    return sum(1 for a in record.get("actions", [])  # type: ignore[union-attr]
               if a.get("ok") and a.get("method") in ("disable", "uninstall-user"))


def comparable(before: Dict[str, object], after: Dict[str, object]) -> List[str]:
    problems = []
    b_dev, a_dev = before.get("device") or {}, after.get("device") or {}
    if b_dev.get("serial_hash") and a_dev.get("serial_hash") and b_dev["serial_hash"] != a_dev["serial_hash"]:  # type: ignore[union-attr,index]
        problems.append("the two reports come from different phones")
    b_pro, a_pro = before.get("protocol") or {}, after.get("protocol") or {}
    for key in ("minutes", "wakes"):
        if b_pro.get(key) != a_pro.get(key):  # type: ignore[union-attr]
            problems.append(f"different {key}: {b_pro.get(key)} before, {a_pro.get(key)} after")  # type: ignore[union-attr]
    if str(after.get("created", "")) < str(before.get("created", "")):
        problems.append("the 'after' report is older than the 'before' report")
    return problems


def load_report(path: str) -> Dict[str, object]:
    report = debloat.read_json(Path(path))
    if report.get("schema") != SCHEMA:
        raise XrayError(f"{path} is not an X-ray report")
    if not report.get("lists_available"):
        raise XrayError(f"{path} was made without any tracker list; re-run analyze on the PCAP while online")
    return report


# --------------------------------------------------------------------------- the card

W, H = 1080, 1350
MARGIN = 80
FOOT = 1080
FONT = "Inter, 'SF Pro Display', 'Segoe UI', Roboto, 'Noto Sans', 'Helvetica Neue', Arial, sans-serif"
RED, GREEN, TEXT, MUTED, BLUE = "#ff6b81", "#7be0a6", "#f2f2f2", "#a3a7b3", "#0a66ff"
CHROME_PATHS = (
    "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome",
    "/Applications/Chromium.app/Contents/MacOS/Chromium",
)


def human_bytes(n: float) -> str:
    if n >= 1024 * 1024:
        return f"{n / 1024 / 1024:.1f} MB"
    return f"{max(n, 0) / 1024:.0f} KB"


def _text(x, y, content, size, fill, weight=400, anchor="start", spacing=0, opacity=1.0) -> str:
    extra = f' letter-spacing="{spacing}"' if spacing else ""
    extra += f' opacity="{opacity}"' if opacity != 1.0 else ""
    return (f'<text x="{x}" y="{y}" font-family="{html.escape(FONT)}" font-size="{size}" '
            f'font-weight="{weight}" fill="{fill}" text-anchor="{anchor}"{extra}>{html.escape(str(content))}</text>')


def _fit(text: str, widest: int, largest: int) -> int:
    """A font size that keeps text within `widest` px (about 0.58em per glyph for this stack)."""
    return max(28, min(largest, int(widest / (0.58 * max(len(text), 1)))))


def _chips(parts: List[str], domains: List[Tuple[str, bool]], y: int, bottom: int) -> int:
    x = MARGIN
    for domain, gone in domains:
        width = int(len(domain) * 0.56 * 30) + 48
        if x + width > W - MARGIN:
            x, y = MARGIN, y + 76
        if y + 56 > bottom:
            break
        color = GREEN if gone else RED
        parts.append(f'<rect x="{x}" y="{y}" width="{width}" height="56" rx="28" fill="{color}" '
                     f'fill-opacity="0.10" stroke="{color}" stroke-opacity="0.55"/>')
        parts.append(_text(x + width // 2, y + 38, domain, 30, color, 600, anchor="middle"))
        if gone:
            parts.append(f'<line x1="{x + 22}" y1="{y + 28}" x2="{x + width - 22}" y2="{y + 28}" '
                         f'stroke="{GREEN}" stroke-width="3"/>')
        x += width + 14
    return y + 76


def card_svg(share: Dict[str, object]) -> str:
    before = share["before"]  # type: ignore[index]
    after = share.get("after")
    device = share["device"]  # type: ignore[index]
    protocol = share.get("protocol") or {}
    minutes = protocol.get("minutes")  # type: ignore[union-attr]
    wakes = protocol.get("wakes")  # type: ignore[union-attr]
    timed = isinstance(minutes, (int, float)) and not isinstance(minutes, bool)
    span = f"{minutes:g} MINUTES" if timed else "A WHILE"
    parts = [
        f'<svg xmlns="http://www.w3.org/2000/svg" width="{W}" height="{H}" viewBox="0 0 {W} {H}">',
        '<defs><linearGradient id="bg" x1="0" y1="0" x2="0.4" y2="1">'
        '<stop offset="0" stop-color="#2a0b16"/><stop offset="1" stop-color="#0b0b10"/>'
        '</linearGradient></defs>',
        f'<rect width="{W}" height="{H}" fill="url(#bg)"/>',
    ]
    android = device.get("android")  # type: ignore[union-attr]
    line = device_name(device) + (f" · Android {android}" if android else "")  # type: ignore[arg-type]
    top_domains = [d["domain"] for d in before["top_tracker_domains"]][:8]  # type: ignore[index]
    caption = "ad & tracking servers it talked to"
    parts.append(_text(MARGIN, 150, f"MY PHONE, LEFT ALONE FOR {span}", 32, MUTED, 700, spacing=5))
    parts.append(_text(MARGIN, 210, line, _fit(line, W - 2 * MARGIN, 42), TEXT, 600))
    if after:
        column = W // 2 + 70                                  # where the "after" column starts
        b, a = str(before["tracker_hosts"]), str(after["tracker_hosts"])  # type: ignore[index]
        size = _fit(max(b, a, key=len), column - MARGIN - 150, 250)
        y = 280 + size
        parts.append(_text(MARGIN, y, b, size, RED, 800))
        parts.append(_text(column - 98, y - size // 3, "→", 100, MUTED, 400, anchor="middle"))
        parts.append(_text(column, y, a, size, GREEN, 800))
        parts.append(_text(MARGIN, y + 60, "before", 34, MUTED, 600))
        parts.append(_text(column, y + 60, "after debloat", 34, MUTED, 600))
        y += 160
        parts.append(_text(MARGIN, y, caption, _fit(caption, W - 2 * MARGIN, 58), TEXT, 700))
        y += 66
        parts.append(_text(MARGIN, y, f"{before['tracker_connections']:,} → {after['tracker_connections']:,} "  # type: ignore[index]
                                      "connections to them", 38, MUTED))
        if int(before["tracker_kb"]) >= 100:  # type: ignore[index]
            y += 52
            parts.append(_text(MARGIN, y, f"{human_bytes(before['tracker_kb'] * 1024)} → "  # type: ignore[index]
                                          f"{human_bytes(after['tracker_kb'] * 1024)} of data", 38, MUTED))  # type: ignore[index]
        still = {d["domain"] for d in after["top_tracker_domains"]}  # type: ignore[index]
        _chips(parts, [(d, d not in still) for d in top_domains], y + 50, FOOT - 70)
        disabled = share.get("packages_disabled")
        headline = (f"{disabled} preinstalled apps turned off by a coding agent" if disabled
                    else "Debloated by a coding agent over ADB")
        sub = "No root. Nothing deleted. One-line undo."
        small = (f"Two idle {minutes:g}-minute captures with PCAPdroid, {wakes} lock-screen wake-ups each. "
                 if timed else "Two idle captures with PCAPdroid. ")
    else:
        number = str(before["tracker_hosts"])  # type: ignore[index]
        size = _fit(number, W - 2 * MARGIN, 300)
        y = 270 + size
        parts.append(_text(MARGIN, y, number, size, RED, 800))
        y += 90
        parts.append(_text(MARGIN, y, caption, _fit(caption, W - 2 * MARGIN, 58), TEXT, 700))
        y += 66
        detail = f"{before['tracker_connections']:,} connections"  # type: ignore[index]
        if int(before["tracker_kb"]) >= 100:  # type: ignore[index]
            detail += f", {human_bytes(before['tracker_kb'] * 1024)} of data"  # type: ignore[index]
        parts.append(_text(MARGIN, y, detail, 38, MUTED))
        _chips(parts, [(d, False) for d in top_domains], y + 50, FOOT - 70)
        headline = "What does yours send home?"
        sub = "Point your coding agent at the repo and say: X-ray my phone."
        small = (f"One idle {minutes:g}-minute capture with PCAPdroid, {wakes} lock-screen wake-ups. "
                 if timed else "One idle capture with PCAPdroid. ")
    small += "Ad and tracking servers as listed by HaGeZi, company names from Exodus Privacy. Counts vary run to run."
    parts.append(_text(MARGIN, FOOT, headline, _fit(headline, W - 2 * MARGIN, 42), TEXT, 700))
    parts.append(_text(MARGIN, FOOT + 52, sub, _fit(sub, W - 2 * MARGIN, 34), MUTED))
    brand = f"DoAide Debloat X-ray  ·  {SHORT_URL}"
    parts.append(f'<circle cx="{MARGIN + 12}" cy="{FOOT + 113}" r="12" fill="{BLUE}"/>')
    parts.append(_text(MARGIN + 36, FOOT + 125, brand, _fit(brand, W - 2 * MARGIN - 36, 32), TEXT, 700))
    for i, row in enumerate(textwrap.wrap(small, 78)):
        parts.append(_text(MARGIN, FOOT + 175 + i * 30, row, 22, MUTED, opacity=0.85))
    parts.append("</svg>")
    return "\n".join(parts) + "\n"


PAGE = """<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>DoAide Debloat X-ray card</title>
<style>
body{{margin:0;background:#111;color:#eee;font-family:system-ui,sans-serif;display:flex;
flex-direction:column;align-items:center;gap:16px;padding:16px}}
#card svg{{width:min(100%,540px);height:auto;border-radius:18px}}
button{{font-size:18px;padding:12px 22px;border-radius:999px;border:0;background:#0a66ff;color:#fff}}
</style></head><body>
<div id="card">{svg}</div>
<button id="save">Save or share as PNG</button>
<script>
document.getElementById("save").onclick = function () {{
  var svg = document.querySelector("#card svg");
  var img = new Image();
  img.onload = function () {{
    var canvas = document.createElement("canvas");
    canvas.width = {w}; canvas.height = {h};
    canvas.getContext("2d").drawImage(img, 0, 0, {w}, {h});
    canvas.toBlob(function (blob) {{
      var file = new File([blob], "xray-card.png", {{type: "image/png"}});
      if (navigator.canShare && navigator.canShare({{files: [file]}})) {{
        navigator.share({{files: [file]}}).catch(function () {{}});
        return;
      }}
      var link = document.createElement("a");
      link.href = URL.createObjectURL(blob);
      link.download = "xray-card.png";
      link.click();
    }}, "image/png");
  }};
  img.src = "data:image/svg+xml;charset=utf-8," +
    encodeURIComponent(new XMLSerializer().serializeToString(svg));
}};
</script>
</body></html>
"""


def find_chrome() -> Optional[str]:
    for name in ("google-chrome", "google-chrome-stable", "chromium", "chromium-browser", "chrome"):
        found = shutil.which(name)
        if found:
            return found
    for path in CHROME_PATHS:
        if Path(path).exists():
            return path
    return None


def render_png(svg_text: str, out_png: Path, chrome: Optional[str] = None) -> Path:
    chrome = chrome or find_chrome()
    if not chrome:
        raise XrayError("a PNG needs Chrome or Chromium; open card.html and use its save button instead")
    out_png = Path(out_png).resolve()
    with tempfile.TemporaryDirectory() as tmp:
        sheet = Path(tmp) / "card.html"
        sheet.write_text('<!doctype html><html><head><meta charset="utf-8"><style>html,body{margin:0;'
                         f'padding:0;background:#000}}svg{{display:block}}</style></head><body>{svg_text}'
                         '</body></html>', encoding="utf-8")
        command = [chrome, "--headless=new", "--disable-gpu", "--hide-scrollbars", "--no-first-run",
                   "--no-default-browser-check", "--force-device-scale-factor=1",
                   f"--user-data-dir={Path(tmp) / 'profile'}", f"--window-size={W},{H}",
                   f"--screenshot={out_png}", sheet.as_uri()]
        try:
            subprocess.run(command, check=True, capture_output=True, timeout=90)
        except (subprocess.CalledProcessError, subprocess.TimeoutExpired) as exc:
            detail = (getattr(exc, "stderr", b"") or b"").decode("utf-8", "replace").strip()[-300:]
            raise XrayError(f"Chrome could not render the PNG ({exc.__class__.__name__}) {detail}") from None
    if not out_png.exists():
        raise XrayError(f"Chrome did not write {out_png}")
    return out_png


# --------------------------------------------------------------------------- output


def print_report(report: Dict[str, object], limit: int = 8) -> None:
    totals = report["totals"]  # type: ignore[index]
    protocol = report.get("protocol") or {}
    capture = report["capture"]  # type: ignore[index]
    device = report.get("device") or {}
    print(f"X-ray '{report.get('label')}': " + (debloat.device_line(device) if device.get("model") else "no device details"))  # type: ignore[union-attr,arg-type]
    span = f"{protocol.get('minutes'):g} idle minutes" if isinstance(protocol.get("minutes"), (int, float)) else "capture"  # type: ignore[union-attr]
    wakes = protocol.get("wakes")  # type: ignore[union-attr]
    print(f"  {span}" + (f", {wakes} lock-screen wake-ups" if wakes else "") +
          f": {capture['packets']:,} packets, {human_bytes(capture['bytes'])}")  # type: ignore[index]
    print(f"  Talked to {totals['hosts']} servers ({totals['domains']} domains); "  # type: ignore[index]
          f"{totals['tracker_hosts']} are on ad/tracking lists ({totals['tracker_domains']} domains)")  # type: ignore[index]
    print(f"  Connections to them: {totals['tracker_flows']} of {totals['flows']}, "  # type: ignore[index]
          f"{human_bytes(totals['tracker_bytes'])} of {human_bytes(totals['bytes'])}")  # type: ignore[index]
    domains = report.get("tracker_domains") or []
    if domains:
        print("  Tracker domains (by connections):")
        for d in domains[:limit]:  # type: ignore[index]
            print(f"    {d['domain']:<32} {d['hosts']:>3} servers {d['flows']:>5} connections   {', '.join(d['lists'][:3])}")
    apps = [a for a in report.get("apps") or [] if a["tracker_hosts"]]  # type: ignore[union-attr]
    system = [a for a in apps if a["system"] is True]
    others = [a for a in apps if a["system"] is not True]
    if system:
        print("  Preinstalled apps that contacted them:")
        for a in system[:limit]:
            print(f"    {a['label']:<44} {len(a['tracker_hosts']):>3} servers {a['tracker_flows']:>5} connections")
    if others:
        named = [a for a in others if a["uid"] >= 0]
        unattributed = [a for a in others if a["uid"] < 0]
        if named:
            print(f"  Apps installed by the owner, or not identified: {len(named)} apps, "
                  f"{sum(len(a['tracker_hosts']) for a in named)} tracker servers (kept out of public summaries)")
        for a in unattributed:
            print(f"  Not attributed to an app: {a['tracker_flows']} tracker connections")
    for warning in report.get("warnings") or []:  # type: ignore[union-attr]
        print(f"  note: {warning}")


# --------------------------------------------------------------------------- commands


def make_adb(args: argparse.Namespace) -> debloat.Adb:
    return debloat.Adb(serial=args.serial, adb_path=args.adb)


def cmd_setup(args: argparse.Namespace) -> int:
    adb = make_adb(args)
    state = debloat.probe_device(adb)
    print(f"Device: {debloat.device_line(state.summary())}")
    if PCAPDROID in state.packages:
        info = ensure_pcapdroid(adb, state)
        print(f"PCAPdroid {info['version_name'] or ''} is installed (version code {info['version_code']}). Ready.")
        if os.environ.get(API_KEY_ENV):
            print(f"{API_KEY_ENV} is set: captures start and stop without a tap on the phone.")
        else:
            print("Each capture asks for two taps on the phone (Allow to start, Allow to stop). To skip them,")
            print("generate an API key in PCAPdroid's Control permissions screen (its menu > Generate API key)")
            print(f"and export it here: export {API_KEY_ENV}=<key>")
        return 0
    print("PCAPdroid is not installed on the phone. It is free and open source, needs no root, and does the")
    print("capturing on the phone; this tool only starts it, stops it and reads the file.")
    if args.open_store:
        adb.shell(f"am start -a android.intent.action.VIEW -d {shlex.quote(PLAY_URL)}", check=False)
        print("Its Play Store page is now open on the phone: tap Install, open the app once, then run setup again.")
    else:
        for link in STORE_LINKS:
            print(f"  {link}")
        print("Or re-run with --open-store to open the Play Store page on the phone.")
    return 2


def cmd_capture(args: argparse.Namespace) -> int:
    if not 0 < args.minutes <= 120:
        raise XrayError("--minutes must be between 0 and 120")
    if not 0 <= args.wakes <= 60 or args.wakes * (WAKE_SECONDS + 2) > args.minutes * 60:
        raise XrayError("--wakes must be between 0 and 60 and fit into the capture")
    adb = make_adb(args)
    state = debloat.probe_device(adb)
    summary = state.summary()
    version = ensure_pcapdroid(adb, state)
    db = trackerdb.load(offline=args.offline, pro=not args.no_pro)
    if not db.available:
        raise XrayError("the HaGeZi tracker lists could not be loaded. Run once with internet access so they "
                        "are cached in ~/.cache/doaide-debloat/xray/, then capture.")
    print(f"Device: {debloat.device_line(summary)}")
    print(f"X-ray '{args.label}': {args.minutes:g} idle minutes, {args.wakes} lock-screen wake-ups, "
          "captured by PCAPdroid on the phone.")
    print("The capture lists the servers the phone talks to. It stays on this computer; only counts and the")
    print("tracker domains of preinstalled apps are ever shared, and only if the owner posts them.")
    if not args.yes and not debloat.confirm("Start the capture now?"):
        print("Not started. Re-run with --yes once the owner has agreed.")
        return 2
    api_key = os.environ.get(API_KEY_ENV) or None
    pcap, protocol = run_capture(adb, args.label, args.minutes, args.wakes, api_key, debloat.BACKUP_DIR,
                                 keep_on_device=args.keep_on_device, sleep=SLEEP)
    protocol["pcapdroid_version"] = version["version_code"]
    packages = parse_uid_list(adb.shell("pm list packages -U", check=False))
    report = analyze(pcapscan.scan(pcap), db, packages, state.third_party, summary, protocol, args.label)
    path = debloat.BACKUP_DIR / f"xray-{debloat.slug(str(summary['model']))}-{debloat.slug(args.label)}-{debloat.timestamp()}.json"
    debloat.write_json(path, report)
    if args.keep_pcap:
        print(f"Raw capture kept: {pcap} (it names every server the phone talked to; never share it)")
    else:
        pcap.unlink()
    print()
    print_report(report)
    print()
    print(f"Report: {path}")
    if args.label == "before":
        print("Next: debloat (AGENTS.md), then the same capture with --label after, then: card <before> <after>")
    else:
        print("Next: tools/xray.py card <before report> <this report> --record <debloat record>")
    return 0


def cmd_analyze(args: argparse.Namespace) -> int:
    pcap = Path(args.pcap)
    db = trackerdb.load(offline=args.offline, pro=not args.no_pro)
    packages: Dict[int, List[str]] = {}
    third_party: Set[str] = set()
    device: Dict[str, object] = {}
    if args.device:
        adb = make_adb(args)
        state = debloat.probe_device(adb)
        packages = parse_uid_list(adb.shell("pm list packages -U", check=False))
        third_party, device = state.third_party, state.summary()
    cap = pcapscan.scan(pcap)
    minutes = args.minutes if args.minutes else round(cap.seconds / 60, 1)
    protocol = {"minutes": minutes, "wakes": args.wakes, "source": "manual capture"}
    report = analyze(cap, db, packages, third_party, device, protocol, args.label)
    stem = debloat.slug(str(device.get("model") or pcap.stem))
    path = Path(args.out) if args.out else debloat.BACKUP_DIR / f"xray-{stem}-{debloat.slug(args.label)}-{debloat.timestamp()}.json"
    debloat.write_json(path, report)
    print_report(report)
    print()
    print(f"Report: {path}")
    return 0


def cmd_card(args: argparse.Namespace) -> int:
    before = load_report(args.before)
    after = load_report(args.after) if args.after else None
    if after is not None:
        problems = comparable(before, after)
        if problems and not args.allow_mismatch:
            raise XrayError("these two reports should not be compared: " + "; ".join(problems) +
                            " (--allow-mismatch to make the card anyway)")
    disabled = count_disabled(debloat.read_json(Path(args.record))) if args.record else None
    share = share_summary(before, after, disabled)
    model = debloat.slug(str(share["device"].get("model") or "phone"))  # type: ignore[union-attr]
    out = Path(args.out) if args.out else debloat.BACKUP_DIR / f"xray-card-{model}-{debloat.timestamp()}"
    out.mkdir(parents=True, exist_ok=True)
    svg_text = card_svg(share)
    (out / "card.svg").write_text(svg_text, encoding="utf-8")
    (out / "card.html").write_text(PAGE.format(svg=svg_text, w=W, h=H), encoding="utf-8")
    (out / "share.json").write_text(json.dumps(share, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    written = [out / "card.svg", out / "card.html", out / "share.json"]
    if args.png:
        written.append(render_png(svg_text, out / "card.png"))
    b = share["before"]  # type: ignore[index]
    line = f"{b['tracker_hosts']} ad/tracking servers"  # type: ignore[index]
    if after is not None:
        line += f" before, {share['after']['tracker_hosts']} after"  # type: ignore[index]
    print(f"{device_name(share['device'])}: {line}.")  # type: ignore[arg-type]
    for path in written:
        print(f"  {path}")
    print("share.json is all that would be public: counts, plus the tracker domains and packages of")
    print("preinstalled apps. Read it before posting.")
    url = issue_url(share)
    if url:
        print("Add this phone to the Phone-Home Index (opens a filled-in GitHub issue; nothing is posted until you submit):")
        print(url)
    else:
        print(f"Add this phone to the Phone-Home Index: {REPO_URL}/issues/new?template={ISSUE_TEMPLATE} "
              "and paste share.json into the report field.")
    return 0


def cmd_show(args: argparse.Namespace) -> int:
    report = debloat.read_json(Path(args.report))
    if report.get("schema") != SCHEMA:
        raise XrayError(f"{args.report} is not an X-ray report")
    if args.json:
        print(json.dumps(report, indent=2, sort_keys=True))
    else:
        print_report(report, limit=args.limit)
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="xray.py", description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--serial", "-s", help="adb serial when more than one device is connected")
    parser.add_argument("--adb", help="path to the adb binary")
    sub = parser.add_subparsers(dest="command", required=True)

    p = sub.add_parser("setup", help="check that PCAPdroid is on the phone")
    p.add_argument("--open-store", action="store_true", help="open PCAPdroid's Play Store page on the phone")
    p.set_defaults(func=cmd_setup)

    p = sub.add_parser("capture", help="record idle traffic on the phone and analyse it")
    p.add_argument("--label", required=True, help="'before' or 'after' (any word works)")
    p.add_argument("--minutes", type=float, default=10.0, help="idle minutes to capture (default 10)")
    p.add_argument("--wakes", type=int, default=10, help="lock-screen wake-ups during the capture (default 10)")
    p.add_argument("--yes", action="store_true", help="the owner agreed to the capture")
    p.add_argument("--keep-pcap", action="store_true", help="keep the raw capture in backups/")
    p.add_argument("--keep-on-device", action="store_true", help="leave the capture file on the phone")
    p.add_argument("--offline", action="store_true", help="use only cached tracker lists")
    p.add_argument("--no-pro", action="store_true", help="skip the 4 MB HaGeZi Pro list")
    p.set_defaults(func=cmd_capture)

    p = sub.add_parser("analyze", help="analyse a PCAP captured with PCAPdroid by hand")
    p.add_argument("pcap")
    p.add_argument("--label", default="manual")
    p.add_argument("--device", action="store_true",
                   help="read app names from the connected phone (the one the capture came from)")
    p.add_argument("--minutes", type=float, help="the capture's idle minutes (default: its length)")
    p.add_argument("--wakes", type=int, default=0, help="lock-screen wake-ups during it")
    p.add_argument("--out", help="report path (default backups/xray-<model>-<label>-<time>.json)")
    p.add_argument("--offline", action="store_true")
    p.add_argument("--no-pro", action="store_true")
    p.set_defaults(func=cmd_analyze)

    p = sub.add_parser("card", help="the shareable card and public summary")
    p.add_argument("before", help="the report from the first capture")
    p.add_argument("after", nargs="?", help="the report from the capture after debloating")
    p.add_argument("--record", help="the debloat record file, to say how many apps were turned off")
    p.add_argument("--png", action="store_true", help="also render card.png with headless Chrome")
    p.add_argument("--out", help="output folder (default backups/xray-card-<model>-<time>/)")
    p.add_argument("--allow-mismatch", action="store_true",
                   help="compare reports from different phones or capture settings anyway")
    p.set_defaults(func=cmd_card)

    p = sub.add_parser("show", help="print a saved report")
    p.add_argument("report")
    p.add_argument("--json", action="store_true")
    p.add_argument("--limit", type=int, default=15)
    p.set_defaults(func=cmd_show)
    return parser


def main(argv: Optional[Sequence[str]] = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        return int(args.func(args))
    except (XrayError, debloat.AdbError, debloat.PlanError, pcapscan.ScanError, ValueError,
            FileNotFoundError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())

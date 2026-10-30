#!/usr/bin/env python3
"""The Phone-Home Index: X-ray reports filed as GitHub issues, grouped by phone model.

    python3 tools/xray_index.py --fetch                 # public issues via the GitHub API, no token needed
    python3 tools/xray_index.py --issues issues.json    # or an export made with the GitHub CLI:
        gh issue list --repo DoAideAi/DoAide-Debloat --label xray-report --state all --limit 1000 \\
            --json number,title,body,labels,url,createdAt > issues.json

Writes site/phone-home.json and site/phone-home.html. Every row links to the issues it was built
from. Left out: issues labelled invalid, duplicate or spam; anything that does not parse as a
doaide-xray-share/1 report or has numbers out of range; and reports captured with other settings
than the standard 10 idle minutes and 10 lock-screen wake-ups (--any-protocol keeps them).

Stdlib only, Python 3.9+.
"""
from __future__ import annotations

import argparse
import html
import json
import os
import re
import statistics
import sys
import time
import urllib.parse
import urllib.request
from collections import Counter
from pathlib import Path
from typing import Dict, List, Optional, Sequence, Tuple

REPO = Path(__file__).resolve().parent.parent
GITHUB_REPO = "DoAideAi/DoAide-Debloat"
LABEL = "xray-report"
SHARE_SCHEMA = "doaide-xray-share/1"
STANDARD = {"minutes": 10, "wakes": 10}
SKIP_LABELS = {"invalid", "duplicate", "spam", "wontfix"}
FENCE_RE = re.compile(r"```[a-zA-Z]*[ \t]*\r?\n(.*?)\r?\n[ \t]*```", re.S)
MARKET_RE = re.compile(r"###\s*Where was the phone sold\?\s*\n+\s*([^\n]+)")
HOST_RE = re.compile(r"^(?=.{3,253}$)[a-z0-9_-]+(\.[a-z0-9_-]+)+$")
PACKAGE_RE = re.compile(r"^[A-Za-z0-9_]+(\.[A-Za-z0-9_]+)*$")       # "android" itself has no dot
MONTH_RE = re.compile(r"^\d{4}-\d{2}$")
SIDE_FIELDS = ("hosts", "tracker_hosts", "tracker_domains", "tracker_connections", "tracker_kb")


# --------------------------------------------------------------------------- validation


def _int(value: object, high: int = 1_000_000) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or not 0 <= value <= high:
        raise ValueError(f"not a count: {value!r}")
    return value


def _text(value: object, limit: int = 60) -> str:
    text = str(value if value is not None else "").strip()
    if len(text) > limit or any(ord(c) < 32 for c in text):
        raise ValueError(f"bad text field: {text[:20]!r}")
    return text


def _side(data: object) -> Dict[str, object]:
    if not isinstance(data, dict):
        raise ValueError("missing counts")
    side: Dict[str, object] = {key: _int(data.get(key)) for key in SIDE_FIELDS}
    if side["tracker_hosts"] > side["hosts"] or side["tracker_domains"] > side["tracker_hosts"]:  # type: ignore[operator]
        raise ValueError("counts do not add up")
    domains = data.get("top_tracker_domains") or []
    apps = data.get("system_apps") or []
    if not isinstance(domains, list) or not isinstance(apps, list) or len(domains) > 10 or len(apps) > 10:
        raise ValueError("bad lists")
    side["top_tracker_domains"] = []
    for item in domains:
        domain = _text(item.get("domain") if isinstance(item, dict) else None, 253).lower()
        if not HOST_RE.match(domain):
            raise ValueError(f"bad domain {domain[:40]!r}")
        side["top_tracker_domains"].append({"domain": domain, "hosts": _int(item.get("hosts"), 1000)})  # type: ignore[union-attr]
    side["system_apps"] = []
    for item in apps:
        package = _text(item.get("package") if isinstance(item, dict) else None, 200)
        if not PACKAGE_RE.match(package):
            raise ValueError(f"bad package {package[:40]!r}")
        side["system_apps"].append({"package": package, "tracker_hosts": _int(item.get("tracker_hosts"), 1000)})  # type: ignore[union-attr]
    return side


def validate(data: object) -> Dict[str, object]:
    if not isinstance(data, dict) or data.get("schema") != SHARE_SCHEMA:
        raise ValueError("not an X-ray share report")
    device = data.get("device")
    if not isinstance(device, dict):
        raise ValueError("no device")
    clean: Dict[str, object] = {
        "device": {k: _text(device.get(k)) for k in ("manufacturer", "brand", "model", "android", "build")},
    }
    if not clean["device"]["model"]:  # type: ignore[index]
        raise ValueError("no model")
    protocol = data.get("protocol") if isinstance(data.get("protocol"), dict) else {}
    minutes, wakes = protocol.get("minutes"), protocol.get("wakes")  # type: ignore[union-attr]
    if minutes is not None and (isinstance(minutes, bool) or not isinstance(minutes, (int, float))
                                or not 0 < minutes <= 120):
        raise ValueError("bad minutes")
    if wakes is not None:
        _int(wakes, 60)
    clean["protocol"] = {"minutes": minutes, "wakes": wakes}
    month = _text(data.get("month"), 7)
    clean["month"] = month if MONTH_RE.match(month) else ""
    clean["before"] = _side(data.get("before"))
    if data.get("after") is not None:
        clean["after"] = _side(data.get("after"))
    if data.get("packages_disabled") is not None:
        clean["packages_disabled"] = _int(data.get("packages_disabled"), 1000)
    return clean


def standard(report: Dict[str, object]) -> bool:
    protocol = report["protocol"]
    return protocol.get("minutes") == STANDARD["minutes"] and protocol.get("wakes") == STANDARD["wakes"]  # type: ignore[union-attr]


def extract(issue: Dict[str, object]) -> Tuple[Optional[Dict[str, object]], str]:
    """(report, "") or (None, reason) for one issue."""
    labels = set()
    for label in issue.get("labels") or []:  # type: ignore[union-attr]
        labels.add(str(label.get("name", "") if isinstance(label, dict) else label).lower())
    if labels & SKIP_LABELS:
        return None, "labelled " + ", ".join(sorted(labels & SKIP_LABELS))
    body = str(issue.get("body") or "")
    for block in FENCE_RE.findall(body):
        try:
            data = json.loads(block)
        except ValueError:
            continue
        if not isinstance(data, dict) or data.get("schema") != SHARE_SCHEMA:
            continue
        try:
            report = validate(data)
        except ValueError as exc:
            return None, f"invalid report ({exc})"
        market = MARKET_RE.search(body)
        value = market.group(1).strip() if market else ""
        report["market"] = "" if value in ("", "_No response_") else value[:40]
        report["issue"] = {"number": int(issue.get("number") or 0),  # type: ignore[arg-type]
                           "url": str(issue.get("url") or issue.get("html_url") or "")}
        return report, ""
    return None, "no X-ray report in the issue"


# --------------------------------------------------------------------------- the index


def maker(device: Dict[str, object]) -> str:
    name = str(device.get("manufacturer") or device.get("brand") or "").strip()
    return name[:1].upper() + name[1:]


def _median(values: List[int]) -> Optional[float]:
    return round(float(statistics.median(values)), 1) if values else None


def aggregate(reports: List[Dict[str, object]]) -> List[Dict[str, object]]:
    groups: Dict[Tuple[str, str], List[Dict[str, object]]] = {}
    for report in reports:
        device = report["device"]
        groups.setdefault((maker(device).lower(), str(device["model"]).lower()), []).append(report)  # type: ignore[arg-type,index]
    rows: List[Dict[str, object]] = []
    for group in groups.values():
        device = group[0]["device"]
        befores = [int(r["before"]["tracker_hosts"]) for r in group]  # type: ignore[index]
        afters = [int(r["after"]["tracker_hosts"]) for r in group if "after" in r]  # type: ignore[index]
        domains: Counter = Counter()
        apps: Counter = Counter()
        for report in group:
            domains.update(d["domain"] for d in report["before"]["top_tracker_domains"])  # type: ignore[index]
            apps.update(a["package"] for a in report["before"]["system_apps"])  # type: ignore[index]
        rows.append({
            "maker": maker(device),  # type: ignore[arg-type]
            "model": device["model"],  # type: ignore[index]
            "reports": len(group),
            "android": sorted({str(r["device"]["android"]) for r in group if r["device"]["android"]}),  # type: ignore[index]
            "markets": sorted({str(r["market"]) for r in group if r["market"]}),
            "before_tracker_hosts": _median(befores),
            "after_tracker_hosts": _median(afters),
            "after_reports": len(afters),
            "top_domains": [d for d, _ in sorted(domains.items(), key=lambda kv: (-kv[1], kv[0]))[:5]],
            "top_apps": [a for a, _ in sorted(apps.items(), key=lambda kv: (-kv[1], kv[0]))[:5]],
            "issues": sorted((r["issue"] for r in group), key=lambda i: i["number"]),  # type: ignore[index]
        })
    rows.sort(key=lambda r: (-(r["before_tracker_hosts"] or 0), r["maker"], r["model"]))  # type: ignore[operator]
    return rows


def build(issues: List[Dict[str, object]], any_protocol: bool = False) -> Dict[str, object]:
    reports: List[Dict[str, object]] = []
    skipped: List[Dict[str, object]] = []
    for issue in issues:
        report, reason = extract(issue)
        if report is not None and not any_protocol and not standard(report):
            report, reason = None, "not the standard capture (10 idle minutes, 10 wake-ups)"
        if report is None:
            skipped.append({"number": issue.get("number"), "reason": reason})
        else:
            reports.append(report)
    return {
        "generated": time.strftime("%Y-%m-%d"),
        "standard": STANDARD,
        "reports": len(reports),
        "rows": aggregate(reports),
        "skipped": skipped,
    }


# --------------------------------------------------------------------------- the page

PAGE = """<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Phone-Home Index: what Android phones send home when nobody is using them</title>
<meta name="description" content="How many ad and tracking servers each Android phone model contacts in ten idle minutes, before and after debloating. Crowd-sourced X-ray reports, each linked to its source.">
<meta property="og:title" content="Phone-Home Index">
<meta property="og:description" content="Ten idle minutes, lock screen woken ten times: how many ad and tracking servers does your phone talk to?">
<meta property="og:url" content="https://debloat.doaide.com/phone-home.html">
<style>
  :root {{ --fg:#111; --muted:#555; --line:#e5e5e5; --accent:#0a66ff; --bg:#fff; --red:#c0233f; --green:#13804a; }}
  @media (prefers-color-scheme: dark) {{ :root {{ --fg:#eee; --muted:#aaa; --line:#2a2a2a; --accent:#6ea8ff; --bg:#0d0d0d; --red:#ff6b81; --green:#7be0a6; }} }}
  * {{ box-sizing:border-box }}
  body {{ margin:0; font:17px/1.55 -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif; color:var(--fg); background:var(--bg) }}
  main {{ max-width:980px; margin:0 auto; padding:56px 20px 80px }}
  h1 {{ font-size:2.2rem; line-height:1.15; margin:0 0 .4em; letter-spacing:-.01em }}
  h2 {{ font-size:1.25rem; margin:2.2em 0 .6em }}
  p.lead {{ font-size:1.2rem; color:var(--muted); margin:0 0 1.4em }}
  a {{ color:var(--accent) }}
  .cta {{ display:inline-block; padding:12px 18px; border-radius:8px; background:var(--accent); color:#fff; text-decoration:none; font-weight:600; margin:4px 8px 4px 0 }}
  .cta.alt {{ background:transparent; color:var(--accent); border:1px solid var(--accent) }}
  table {{ border-collapse:collapse; width:100%; font-size:.95rem }}
  td, th {{ text-align:left; padding:8px 6px; border-bottom:1px solid var(--line); vertical-align:top }}
  td.num {{ font-variant-numeric:tabular-nums; font-weight:700 }}
  .before {{ color:var(--red) }} .after {{ color:var(--green) }}
  .small {{ color:var(--muted); font-size:.9rem }}
  footer {{ margin-top:3em; color:var(--muted); font-size:.9rem }}
</style>
</head>
<body>
<main>
  <h1>What does your phone send home?</h1>
  <p class="lead">Ten minutes, phone untouched, lock screen woken ten times. Each row is the median of the X-ray reports filed by owners of that model: how many ad and tracking servers it talked to, before and after debloating.</p>
  <p>
    <a class="cta" href="https://github.com/DoAideAi/DoAide-Debloat/blob/main/recipes/xray.md">X-ray your phone</a>
    <a class="cta alt" href="index.html">DoAide Debloat</a>
  </p>
{body}
  <h2>How it is measured</h2>
  <ul>
    <li>PCAPdroid, an open-source app that needs no root, records the phone's traffic for ten idle minutes. The lock screen is woken ten times, the way a person glances at a phone.</li>
    <li>Server names come from DNS, the TLS server name and the HTTP Host header. Nothing is decrypted.</li>
    <li>A server counts as ad or tracking when one of <a href="https://github.com/hagezi/dns-blocklists">HaGeZi's lists</a> names it: the phone makers' own telemetry, and the broad Pro list. <a href="https://reports.exodus-privacy.eu.org/en/trackers/">Exodus Privacy</a> supplies the company names.</li>
    <li>Counts vary from run to run with the network, the time of day and app updates. A row with one report is one phone on one evening.</li>
    <li>Reports are filed by their owners as public GitHub issues and hold counts, plus the tracker domains and package names of preinstalled apps. Never serial numbers, IP addresses or the owner's own apps.</li>
  </ul>
  <footer>
    Updated {generated}. {reports} reports. Free and open source, MIT. A <a href="https://doaide.com">DoAide</a> project. Not affiliated with any manufacturer. This page sets no cookies.
  </footer>
</main>
</body>
</html>
"""


def _cell(value: Optional[float], cls: str) -> str:
    if value is None:
        return '<td class="num small">–</td>'
    return f'<td class="num {cls}">{value:g}</td>'


def render(index: Dict[str, object]) -> str:
    rows = index["rows"]
    if not rows:
        body = ('  <p><strong>No reports yet.</strong> Be the first: run the X-ray before and after debloating, '
                'and the <code>card</code> step prints a link that files your report.</p>')
    else:
        lines = ['  <table>',
                 '    <tr><th>Phone</th><th>Reports</th><th>Before</th><th>After</th>'
                 '<th>Most seen tracker domains</th><th>Preinstalled apps behind them</th><th>Sources</th></tr>']
        for row in rows:  # type: ignore[union-attr]
            name = html.escape(f"{row['maker']} {row['model']}".strip())
            android = ", ".join(row["android"])
            if android:
                name += f'<br><span class="small">Android {html.escape(android)}</span>'
            if row["markets"]:
                name += f'<br><span class="small">{html.escape(", ".join(row["markets"]))}</span>'
            sources = " ".join(f'<a href="{html.escape(i["url"])}">#{int(i["number"])}</a>' for i in row["issues"])
            lines.append(
                f'    <tr><td>{name}</td><td class="num">{int(row["reports"])}</td>'
                f'{_cell(row["before_tracker_hosts"], "before")}{_cell(row["after_tracker_hosts"], "after")}'
                f'<td>{html.escape(", ".join(row["top_domains"]))}</td>'
                f'<td class="small">{html.escape(", ".join(row["top_apps"]))}</td>'
                f'<td>{sources}</td></tr>')
        lines.append('  </table>')
        lines.append('  <p class="small">Before and After: ad and tracking servers contacted in ten idle '
                     'minutes (median of the reports). Sources: the GitHub issues each row is built from.</p>')
        body = "\n".join(lines)
    return PAGE.format(body=body, generated=html.escape(str(index["generated"])), reports=int(index["reports"]))  # type: ignore[arg-type]


# --------------------------------------------------------------------------- input


def fetch_issues(repo: str = GITHUB_REPO, label: str = LABEL, timeout: int = 60) -> List[Dict[str, object]]:
    issues: List[Dict[str, object]] = []
    for page in range(1, 51):
        query = urllib.parse.urlencode({"labels": label, "state": "all", "per_page": 100, "page": page})
        req = urllib.request.Request(f"https://api.github.com/repos/{repo}/issues?{query}",
                                     headers={"Accept": "application/vnd.github+json", "User-Agent": "doaide-debloat"})
        token = os.environ.get("GITHUB_TOKEN")
        if token:
            req.add_header("Authorization", f"Bearer {token}")
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            batch = json.loads(resp.read())
        for item in batch:
            if "pull_request" in item:
                continue
            issues.append({"number": item.get("number"), "title": item.get("title", ""),
                           "body": item.get("body") or "", "url": item.get("html_url", ""),
                           "labels": [{"name": l.get("name", "")} for l in item.get("labels", [])],
                           "createdAt": item.get("created_at", "")})
        if len(batch) < 100:
            break
    return issues


def main(argv: Optional[Sequence[str]] = None) -> int:
    parser = argparse.ArgumentParser(prog="xray_index.py", description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    source = parser.add_mutually_exclusive_group(required=True)
    source.add_argument("--fetch", action="store_true", help="read the issues from the GitHub API")
    source.add_argument("--issues", help="a JSON file of issues (gh issue list --json ...)")
    parser.add_argument("--repo", default=GITHUB_REPO)
    parser.add_argument("--out", default=str(REPO / "site"), help="folder for phone-home.json and .html")
    parser.add_argument("--any-protocol", action="store_true", help="keep reports with other capture settings")
    args = parser.parse_args(argv)
    try:
        issues = fetch_issues(args.repo) if args.fetch else json.loads(Path(args.issues).read_text(encoding="utf-8"))
        if not isinstance(issues, list):
            raise ValueError("the issues file must hold a JSON list")
    except (OSError, ValueError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    index = build(issues, any_protocol=args.any_protocol)
    out = Path(args.out)
    out.mkdir(parents=True, exist_ok=True)
    (out / "phone-home.json").write_text(json.dumps(index, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    (out / "phone-home.html").write_text(render(index), encoding="utf-8")
    print(f"{index['reports']} reports from {len(issues)} issues, {len(index['skipped'])} left out, "  # type: ignore[arg-type]
          f"{len(index['rows'])} phone models -> {out / 'phone-home.html'}")  # type: ignore[arg-type]
    for item in index["skipped"]:  # type: ignore[union-attr]
        print(f"  left out #{item['number']}: {item['reason']}")
    return 0


if __name__ == "__main__":
    sys.exit(main())

"""Ad and tracker lists for the X-ray, fetched at runtime and cached; nothing is redistributed here.

  * HaGeZi's native tracker lists (github.com/hagezi/dns-blocklists, GPL-3.0): the telemetry that
    Xiaomi, Samsung, OPPO / realme / OnePlus, vivo, Huawei and Amazon build into their firmware.
  * HaGeZi Pro (same repo, GPL-3.0, ~4 MB): a broad ad, tracking and telemetry domain list. It
    is what knows lock-screen content services such as Glance. --no-pro skips it, and then only
    phone-maker telemetry counts.
  * Exodus Privacy's tracker list (reports.exodus-privacy.eu.org, public API): ~430 named trackers
    such as Google AdMob, Facebook Ads, InMobi or AppsFlyer, about 260 with a network signature.
    It names the company behind a server the HaGeZi lists flag; on its own it decides nothing,
    because some signatures are too broad for a whole phone's traffic (see TrackerDB.classify).
  * The Public Suffix List (publicsuffix.org, MPL-2.0), to fold host names into the domain that
    owns them: ads.example.co.in -> example.co.in.

Everything is cached under ~/.cache/doaide-debloat/xray/ (or $DOAIDE_DEBLOAT_CACHE/xray/).

Stdlib only, Python 3.9+.
"""
from __future__ import annotations

import json
import re
import sys
import time
import urllib.error
import urllib.request
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, Iterable, List, Optional, Set, Tuple

sys.path.insert(0, str(Path(__file__).resolve().parent))
import uadlist  # noqa: E402

HAGEZI = "https://raw.githubusercontent.com/hagezi/dns-blocklists/main/wildcard/{}-onlydomains.txt"
NATIVE_VENDORS = {
    "xiaomi": "Xiaomi",
    "samsung": "Samsung",
    "oppo-realme": "OPPO / realme / OnePlus",
    "vivo": "vivo",
    "huawei": "Huawei",
    "amazon": "Amazon",
}
SECOND_LEVELS = {"ac", "co", "com", "edu", "firm", "gen", "gov", "ind", "ltd", "net", "nic", "org", "plc", "res"}


@dataclass(frozen=True)
class Source:
    key: str
    url: str
    file: str
    max_age_days: int
    kind: str          # "exodus" | "domains" | "psl"
    label: str


SOURCES: Tuple[Source, ...] = (
    Source("exodus", "https://reports.exodus-privacy.eu.org/api/trackers", "exodus-trackers.json", 30,
           "exodus", "Exodus Privacy trackers"),
    *(Source(f"native.{v}", HAGEZI.format(f"native.{v}"), f"hagezi-native.{v}.txt", 7, "domains",
             f"HaGeZi {name} native tracker list") for v, name in NATIVE_VENDORS.items()),
    Source("pro", HAGEZI.format("pro"), "hagezi-pro.txt", 7, "domains", "HaGeZi Pro"),
    Source("psl", "https://publicsuffix.org/list/public_suffix_list.dat", "public_suffix_list.dat", 30,
           "psl", "Public Suffix List"),
)


def cache_dir() -> Path:
    return uadlist.cache_dir() / "xray"


# --------------------------------------------------------------------------- parsing


def parse_exodus(text: str) -> Tuple[List[Tuple[str, re.Pattern]], int]:
    """[(tracker name, compiled network signature)], number of signatures that did not compile."""
    data = json.loads(text)
    trackers = data.get("trackers") if isinstance(data, dict) else None
    if not isinstance(trackers, dict):
        raise ValueError("not an Exodus tracker list")
    out: List[Tuple[str, re.Pattern]] = []
    bad = 0
    for item in trackers.values():
        signature = (item.get("network_signature") or "").strip()
        name = (item.get("name") or "").strip()
        if not signature or not name:
            continue
        try:
            out.append((name, re.compile(signature, re.I)))
        except re.error:
            bad += 1
    out.sort(key=lambda pair: pair[0].lower())
    return out, bad


def parse_domains(text: str) -> Set[str]:
    """One domain per line, '#' comments; each entry covers its subdomains (HaGeZi wildcard)."""
    domains: Set[str] = set()
    for line in text.splitlines():
        line = line.split("#", 1)[0].strip().lower().lstrip("*.").rstrip(".")
        if line and " " not in line and "." in line:
            domains.add(line)
    return domains


class PublicSuffixList:
    def __init__(self, text: str) -> None:
        self.rules: Set[str] = set()
        self.wildcards: Set[str] = set()
        self.exceptions: Set[str] = set()
        for line in text.splitlines():
            line = line.strip()
            if not line or line.startswith("//"):
                continue
            rule = line.split()[0].lower()
            try:
                rule = ".".join(label if label in ("*", "!") or label.isascii()
                                else label.encode("idna").decode("ascii") for label in rule.split("."))
            except UnicodeError:
                continue
            if rule.startswith("!"):
                self.exceptions.add(rule[1:])
            elif rule.startswith("*."):
                self.wildcards.add(rule[2:])
            else:
                self.rules.add(rule)

    def registrable(self, host: str) -> str:
        labels = host.split(".")
        n = len(labels)
        suffix = 1                                          # the implicit "*" rule
        for i in range(n):
            candidate = ".".join(labels[i:])
            if candidate in self.exceptions:
                suffix = n - i - 1
                break
            if candidate in self.rules or (i + 1 < n and ".".join(labels[i + 1:]) in self.wildcards):
                suffix = n - i
                break
        if suffix >= n:
            return host
        return ".".join(labels[n - suffix - 1:])


def guess_registrable(host: str) -> str:
    """Without the Public Suffix List: last two labels, three for co.in-style suffixes."""
    labels = host.split(".")
    if len(labels) >= 3 and len(labels[-1]) == 2 and labels[-2] in SECOND_LEVELS:
        return ".".join(labels[-3:])
    return ".".join(labels[-2:])


# --------------------------------------------------------------------------- matching


def in_domains(host: str, domains: Set[str]) -> Optional[str]:
    """The list entry that covers `host` (itself or a parent domain), if any."""
    labels = host.split(".")
    for i in range(len(labels) - 1):
        candidate = ".".join(labels[i:])
        if candidate in domains:
            return candidate
    return None


def signature_hits(pattern: re.Pattern, host: str) -> bool:
    """An Exodus signature matching whole labels of `host`.

    Exodus signatures are unanchored (`go\\.link`, `\\.facebook\\.com`); a plain search would let
    `go\\.link` match ago.linkedin.com. A hit has to start at the beginning of the host, at a dot
    or just after one, and end at the end of the host or at a dot.
    """
    if not pattern.search(host):
        return False
    starts = [0] + [i for i, c in enumerate(host) if c == "."] + [i + 1 for i, c in enumerate(host) if c == "."]
    ends = [len(host)] + [i for i, c in enumerate(host) if c == "."]
    for start in sorted(set(starts)):
        for end in ends:
            if end > start and pattern.fullmatch(host, start, end):
                return True
    return False


class TrackerDB:
    def __init__(self, exodus: Optional[List[Tuple[str, re.Pattern]]] = None,
                 native: Optional[Dict[str, Set[str]]] = None, pro: Optional[Set[str]] = None,
                 psl: Optional[PublicSuffixList] = None,
                 sources: Optional[Dict[str, Dict[str, object]]] = None) -> None:
        self.exodus = exodus or []
        self.native = native or {}
        self.pro = pro or set()
        self.psl = psl
        self.sources = sources or {}
        self._memo: Dict[str, List[Dict[str, str]]] = {}

    @property
    def available(self) -> bool:
        """True when a list that decides is loaded (HaGeZi); Exodus alone only names companies."""
        return bool(self.native or self.pro)

    def classify(self, host: str) -> List[Dict[str, str]]:
        """The lists that call `host` an ad, tracking or telemetry server: [{source, name}].

        HaGeZi's lists decide. Exodus only adds company names to what they flag: its network
        signatures were written to spot an SDK inside one app, and some are far too broad for a
        whole phone's traffic (Google Ads is `\\.google\\.com`, so every Google service would count).
        """
        if host in self._memo:
            return self._memo[host]
        hits: List[Dict[str, str]] = []
        for vendor, domains in sorted(self.native.items()):
            if in_domains(host, domains):
                hits.append({"source": "hagezi-native", "name": vendor})
        if in_domains(host, self.pro):
            hits.append({"source": "hagezi-pro", "name": "HaGeZi Pro"})
        if hits:
            names: List[Dict[str, str]] = []
            for name, pattern in self.exodus:
                if signature_hits(pattern, host) and {"source": "exodus", "name": name} not in names:
                    names.append({"source": "exodus", "name": name})
            hits = names + hits
        self._memo[host] = hits
        return hits

    def registrable(self, host: str) -> str:
        return self.psl.registrable(host) if self.psl else guess_registrable(host)


# --------------------------------------------------------------------------- fetch and load


def _validate(source: Source, payload: bytes) -> None:
    text = payload.decode("utf-8", "replace")
    if source.kind == "exodus":
        parse_exodus(text)
    elif source.kind == "domains":
        if len(parse_domains(text)) < 10:
            raise ValueError("the list is empty")
    elif "===BEGIN ICANN DOMAINS===" not in text:
        raise ValueError("not the Public Suffix List")


def fetch(source: Source, dest: Path, timeout: int = 90) -> None:
    dest.parent.mkdir(parents=True, exist_ok=True)
    req = urllib.request.Request(source.url, headers={"User-Agent": "doaide-debloat"})
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        payload = resp.read()
    _validate(source, payload)  # never cache an error page
    tmp = dest.with_suffix(dest.suffix + ".tmp")
    tmp.write_bytes(payload)
    tmp.replace(dest)


def load(offline: bool = False, refresh: bool = False, pro: bool = True,
         sources: Iterable[Source] = SOURCES) -> TrackerDB:
    """Whatever lists are available; a missing one is a warning, not an error."""
    exodus: List[Tuple[str, re.Pattern]] = []
    native: Dict[str, Set[str]] = {}
    pro_set: Set[str] = set()
    psl: Optional[PublicSuffixList] = None
    used: Dict[str, Dict[str, object]] = {}
    for source in sources:
        if source.key == "pro" and not pro:
            continue
        path = cache_dir() / source.file
        stale = (not path.exists()) or (time.time() - path.stat().st_mtime > source.max_age_days * 86400)
        if (refresh or stale) and not offline:
            try:
                fetch(source, path)
            except (urllib.error.URLError, OSError, ValueError) as exc:
                verb = "refresh" if path.exists() else "fetch"
                tail = "using the cached copy" if path.exists() else "continuing without it"
                print(f"warning: could not {verb} the {source.label} ({exc}); {tail}", file=sys.stderr)
        if not path.exists():
            continue
        text = path.read_text(encoding="utf-8", errors="replace")
        try:
            if source.kind == "exodus":
                exodus, bad = parse_exodus(text)
                entries = len(exodus)
            elif source.kind == "psl":
                psl = PublicSuffixList(text)
                entries = len(psl.rules) + len(psl.wildcards)
            else:
                domains = parse_domains(text)
                entries = len(domains)
                if source.key == "pro":
                    pro_set = domains
                else:
                    native[NATIVE_VENDORS.get(source.key.split(".", 1)[1], source.key)] = domains
        except ValueError as exc:
            print(f"warning: the cached {source.label} is unreadable ({exc}); skipping it", file=sys.stderr)
            continue
        used[source.key] = {
            "label": source.label,
            "url": source.url,
            "entries": entries,
            "fetched": time.strftime("%Y-%m-%d", time.gmtime(path.stat().st_mtime)),
        }
    return TrackerDB(exodus=exodus, native=native, pro=pro_set, psl=psl, sources=used)

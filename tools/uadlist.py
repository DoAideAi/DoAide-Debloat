"""Read-only access to the community package list of Universal Android Debloater NG.

The list (GPL-3.0, maintained by the Universal Debloater Alliance) describes ~5,000
preinstalled Android packages with a removal recommendation: Recommended, Advanced,
Expert or Unsafe. It is fetched at runtime and cached; it is never redistributed here.

Only stdlib is used so the tools run on a bare Python 3.9+.
"""
from __future__ import annotations

import json
import os
import sys
import time
import urllib.error
import urllib.request
from pathlib import Path
from typing import Dict, List, Optional, Tuple

UAD_URL = (
    "https://raw.githubusercontent.com/Universal-Debloater-Alliance/"
    "universal-android-debloater-next-generation/main/resources/assets/uad_lists.json"
)
LEVELS = ("Recommended", "Advanced", "Expert", "Unsafe")


def cache_dir() -> Path:
    override = os.environ.get("DOAIDE_DEBLOAT_CACHE")
    if override:
        return Path(override)
    return Path.home() / ".cache" / "doaide-debloat"


def cache_file() -> Path:
    return cache_dir() / "uad_lists.json"


def fetch(dest: Path, timeout: int = 60) -> None:
    dest.parent.mkdir(parents=True, exist_ok=True)
    req = urllib.request.Request(UAD_URL, headers={"User-Agent": "doaide-debloat"})
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        payload = resp.read()
    json.loads(payload)  # refuse to cache anything that is not valid JSON
    tmp = dest.with_suffix(".tmp")
    tmp.write_bytes(payload)
    tmp.replace(dest)


def load(refresh: bool = False, offline: bool = False, max_age_days: int = 30) -> Optional[Dict[str, dict]]:
    """Return the package database, or None when it is unavailable offline."""
    path = cache_file()
    stale = (not path.exists()) or (time.time() - path.stat().st_mtime > max_age_days * 86400)
    if (refresh or stale) and not offline:
        try:
            fetch(path)
        except (urllib.error.URLError, OSError, ValueError) as exc:
            if not path.exists():
                print(f"warning: could not fetch the UAD package list ({exc}); continuing without it",
                      file=sys.stderr)
                return None
            print(f"warning: could not refresh the UAD package list ({exc}); using the cached copy",
                  file=sys.stderr)
    if not path.exists():
        return None
    with path.open(encoding="utf-8") as fh:
        return json.load(fh)


def info(db: Optional[Dict[str, dict]], package: str) -> Optional[dict]:
    if not db:
        return None
    entry = db.get(package)
    if not entry:
        return None
    return {
        "list": entry.get("list", ""),
        "removal": entry.get("removal", ""),
        "description": (entry.get("description") or "").strip(),
        "dependencies": list(entry.get("dependencies") or []),
        "neededBy": list(entry.get("neededBy") or []),
        "labels": list(entry.get("labels") or []),
    }


def search(db: Optional[Dict[str, dict]], term: str, limit: int = 25) -> List[Tuple[str, dict]]:
    """Case-insensitive substring search over package names and descriptions."""
    if not db:
        return []
    needle = term.lower()
    hits: List[Tuple[str, dict]] = []
    for pkg, entry in db.items():
        if needle in pkg.lower() or needle in (entry.get("description") or "").lower():
            hits.append((pkg, info(db, pkg) or {}))
            if len(hits) >= limit:
                break
    return hits


def first_line(text: str, width: int = 90) -> str:
    line = text.strip().splitlines()[0] if text.strip() else ""
    return line if len(line) <= width else line[: width - 1] + "…"

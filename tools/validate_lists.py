#!/usr/bin/env python3
"""Check the bundled lists: syntax, duplicates, overlap with never-disable, and (with --uad)
cross-check every profile entry against the community UAD list.

Exit 1 on an error. Run before committing a profile change:
    python3 tools/validate_lists.py --uad
"""
from __future__ import annotations

import argparse
import sys
from collections import Counter
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import debloat  # noqa: E402
import uadlist  # noqa: E402


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--uad", action="store_true", help="cross-check against the community list")
    parser.add_argument("--offline", action="store_true")
    parser.add_argument("--show-unknown", action="store_true",
                        help="list entries the community list does not know (informational)")
    args = parser.parse_args()

    errors: list[str] = []
    warnings: list[str] = []

    never = debloat.load_never()
    files = sorted(debloat.PROFILES_DIR.glob("*.txt"))
    entries = []
    for path in files:
        try:
            entries.extend(debloat.parse_list(path.read_text(encoding="utf-8"), path.name))
        except ValueError as exc:
            errors.append(str(exc))

    seen = Counter(e.package for e in entries)
    for pkg, count in seen.items():
        if count > 1:
            where = [e.source for e in entries if e.package == pkg]
            errors.append(f"{pkg} listed {count} times: {', '.join(where)}")

    for entry in entries:
        pattern = debloat.matches_never(entry.package, never)
        if pattern:
            errors.append(f"{entry.source}: {entry.package} is also protected by never-disable "
                          f"pattern '{pattern}'; remove one of them")
        if entry.category != "ask" and not entry.note:
            warnings.append(f"{entry.source}: {entry.package} has no note")

    print(f"{len(files)} profiles, {len(entries)} entries, {len(never)} never-disable patterns")
    by_cat = Counter(e.category for e in entries)
    print("  " + ", ".join(f"{c}: {n}" for c, n in sorted(by_cat.items())))

    if args.uad:
        db = uadlist.load(offline=args.offline)
        if not db:
            errors.append("community list unavailable; cannot cross-check")
        else:
            unknown = []
            for entry in entries:
                meta = uadlist.info(db, entry.package)
                if not meta:
                    unknown.append(entry)
                    continue
                level = meta["removal"]
                if level == "Unsafe":
                    errors.append(f"{entry.source}: {entry.package} is Unsafe in the community list "
                                  f"- {uadlist.first_line(meta['description'])}")
                elif level == "Expert" and entry.category != "ask":
                    errors.append(f"{entry.source}: {entry.package} is Expert in the community list "
                                  f"but listed as '{entry.category}' (must be 'ask' or removed) "
                                  f"- {uadlist.first_line(meta['description'])}")
                elif level == "Advanced" and entry.category != "ask":
                    warnings.append(f"{entry.source}: {entry.package} is Advanced in the community "
                                    f"list, listed as '{entry.category}' "
                                    f"- {uadlist.first_line(meta['description'])}")
            print(f"  community cross-check: {len(entries) - len(unknown)} known, {len(unknown)} unknown")
            if args.show_unknown:
                for entry in unknown:
                    print(f"    unknown: {entry.source} {entry.package}")

    for warning in warnings:
        print(f"warning: {warning}")
    for error in errors:
        print(f"ERROR: {error}")
    print("OK" if not errors else f"{len(errors)} error(s)")
    return 0 if not errors else 1


if __name__ == "__main__":
    sys.exit(main())

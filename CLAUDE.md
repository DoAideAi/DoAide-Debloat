This repository's instructions for coding agents live in [AGENTS.md](AGENTS.md). Read all of it
before running anything; it is the procedure, the hard rules and the scope.

Short version: use `python3 tools/debloat.py` for every change (probe, backup, plan, apply,
restore, check, lookup); never write `pm` commands by hand; never root, remount, flash or reset;
disable only, never uninstall from the system image; ask the owner before the first change; keep
every identifier out of anything you publish.

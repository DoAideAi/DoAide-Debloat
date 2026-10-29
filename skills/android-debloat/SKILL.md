---
name: android-debloat
description: Debloat an Android phone or tablet over ADB with DoAide Debloat. Use when someone asks to remove ads, bloatware, tracking or preinstalled junk from an Android device, or to undo such a cleanup. No root, disable-only, one-line restore.
---

# Android debloat (DoAide Debloat)

Use this skill when the user wants ads, bloatware, tracking or preinstalled apps removed from an
Android phone or tablet (Samsung, Xiaomi/Redmi/POCO, OnePlus/OPPO/realme, vivo/iQOO, Motorola,
Pixel, Amazon Fire tablets), or wants such a cleanup undone. Not for TVs: send Android/Google TV
owners to https://github.com/Gathin23/cleanyourtv and Fire TV owners to
https://github.com/humblemuzzu/dumbtv. Samsung Tizen, LG webOS, Roku and iPhone cannot be done
without rooting; say so.

## Setup

1. `adb` must be installed: macOS `brew install --cask android-platform-tools`, Windows
   `winget install Google.PlatformTools`, Debian/Ubuntu `sudo apt install adb`.
2. Get the repository if it is not already present, and work from its root:
   ```sh
   git clone https://github.com/DoAideAi/DoAide-Debloat && cd DoAide-Debloat
   ```
3. Read `AGENTS.md` in that repository in full. It is the procedure and the hard rules; this skill
   only tells you when to use it and how to get there.

## The procedure, in one paragraph

Help the owner enable USB debugging (per-brand paths in `recipes/android-phone.md`; Wi-Fi:
`python3 tools/debloat.py connect --discover --code <six digits>`), then run
`python3 tools/debloat.py probe`, `backup`, `plan`. Explain the plan in plain words, ask the owner
which of the "ASK THE OWNER" apps they use, re-run `plan --remove a,b --keep x` with their answers,
get an explicit yes, then `apply --plan <file> --yes`. Ask the owner to check the phone and reboot
once. Report what was turned off, the record file, the undo command
(`restore --record <file>`), that an update may bring packages back (`check --record <file> --fix`),
and that they should turn USB debugging off.

## Rules that are not negotiable (full list in AGENTS.md)

- Use `tools/debloat.py` for every change; never write `pm` commands by hand.
- Never root, remount, flash, factory reset, or uninstall from the system image. Disable only;
  `--allow-uninstall` (still reversible) only after the owner agreed.
- Never touch the home screen, keyboard, phone, SMS, browser or emergency apps, or anything in
  `data/never-disable.txt`; the tools refuse these and must not be worked around.
- Never invent a package name; act only on what `plan` prints from the real device.
- Ask before the first change; the owner answers the ask list, not you.
- Keep serial numbers, IMEIs, phone numbers, emails and Wi-Fi names out of anything you publish.

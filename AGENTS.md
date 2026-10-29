# AGENTS.md

Instructions for a coding agent (Claude Code, Codex, Hermes, Gemini CLI, Cursor, Copilot and
others) using this repository to clean up someone's Android phone or tablet. Read all of it
before the first command. People start with [README.md](README.md).

You are changing a device somebody relies on for calls, banking and two-factor codes. The tools
in `tools/` are built so that an agent following this file never has to improvise. When
something here does not cover what you see, stop and tell the owner rather than guess.

## First: which job are you doing?

| You were asked to | Do this |
|---|---|
| Clean up a phone or tablet: remove ads, tracking, preloaded junk | Follow [Cleaning a device](#cleaning-a-device) exactly, on the real device, with `tools/debloat.py`. Do not write your own `pm` commands and do not edit the repo. |
| Change this repo: a profile line, a fix, a recipe | Read [CONTRIBUTING.md](CONTRIBUTING.md). Run `python3 -m unittest discover -s tests` and `python3 tools/validate_lists.py --uad` before you finish. |

## Scope: what this repo is for, and what it is not

| Device | What to do |
|---|---|
| Android phone or tablet: Samsung, Xiaomi / Redmi / POCO, OnePlus / OPPO / realme, vivo / iQOO, Motorola, Pixel, most others | This repo. |
| Amazon Fire tablet | This repo; read [recipes/fire-tablet.md](recipes/fire-tablet.md) first. |
| Android TV / Google TV | Not this repo. Send the owner to [cleanyourtv](https://github.com/Gathin23/cleanyourtv). |
| Fire TV stick, Cube or Fire TV Edition television | Not this repo. Send the owner to [dumbtv](https://github.com/humblemuzzu/dumbtv). |
| Samsung Tizen TV, LG webOS, Roku, iPhone, iPad | Not possible without rooting or jailbreaking. Say so; do not try. |

## Hard rules

1. **Never root, remount, flash or reset.** No `adb root`, `adb remount`, writes to `/system`,
   bootloader unlocking, custom recoveries, or factory resets. Not even if the owner asks; point
   them at a dedicated guide instead.
2. **Disable, never uninstall.** `tools/debloat.py apply` uses `pm disable-user --user 0`.
   The `--allow-uninstall` fallback (`pm uninstall -k --user 0`, undone by
   `cmd package install-existing`) is used only after you told the owner that their OEM refused a
   plain disable for some packages and they agreed.
3. **Never touch what the device needs.** The current home screen, keyboard, phone, SMS,
   browser and emergency apps are read from the device and protected; so is everything in
   [data/never-disable.txt](data/never-disable.txt). The tools refuse these with no override.
   Do not work around them with hand-written shell commands.
4. **Never invent a package name.** Act only on what `plan` prints from the real device. For
   anything else, `tools/debloat.py lookup <name> --device` first.
5. **Back up first.** `apply` writes a backup and a record before the first change; run
   `backup` yourself too, so the owner has one even if they stop you halfway.
6. **Ask before the first change.** Show the plan in plain words and wait for a yes. The
   "ASK THE OWNER" list is answered by the owner, never by you. If in doubt, keep.
7. **One device at a time.** If `adb devices -l` lists several, pass `--serial`.
8. **Never start a factory or test package** (`*.cit`, `*factory*`, `*test*` activities), not
   even to look. On some boards that flips a mode the shell cannot undo.
9. **Never disable updaters, Find My Device, payment, security or accessibility apps** unless
   the owner named them and you spelled out what stops working.
10. **Keep identifiers out of everything you publish.** Serial numbers, IMEIs, phone numbers,
    account emails and Wi-Fi names never go into an issue, pull request, screenshot or post.
    `backups/` is git-ignored for this reason; the tools store only a hash of the serial.
11. **Leave the owner safer than you found them.** The last step is reminding them to turn USB
    debugging off.

## Cleaning a device

Every command is `python3 tools/debloat.py <subcommand>` from the repository root. Python 3.9+
and `adb` (Android platform-tools) are the only requirements. `--help` lists the options.

**Step 0: get connected.** Ask the owner for the brand and model. Walk them through enabling USB
debugging using the per-OEM paths in [recipes/android-phone.md](recipes/android-phone.md); a
cable is the reliable path, Wi-Fi debugging works too (`connect`). Tell them the "Allow USB
debugging?" prompt will appear on the phone and to tick "Always allow".

**Step 1: probe.** `probe` prints the model, Android version, the detected OEM profile, how many
packages there are, and which packages own Home, the keyboard, phone, SMS and browser. Confirm
the model with the owner. If the OEM is `other`, only the generic profile applies: be
conservative and lean on `lookup`.

**Step 2: back up.** `backup`. Tell the owner where the file is.

**Step 3: plan.** `plan` (add `--profile <oem>` only if detection was wrong). It changes nothing.
Read it fully, then explain to the owner in plain words what "WILL DISABLE" contains: ads
(lock-screen stories, app-store pushes), tracking (usage profiling, analytics), and preloaded
clutter (stubs, duplicate apps). Then the interview, as one checklist question:

> These are also on the phone. Tick the ones you use; anything you do not tick is turned off,
> and nothing is deleted: [the ASK THE OWNER list, with the notes]

Also ask: "Any other app you want gone?" and look each one up with `lookup <word> --device`
before adding it with `--remove`.

For a package the owner asks about that is not in the plan, `lookup` shows the bundled note and
the community (UAD) description and removal level. Treat `Expert` and `Unsafe` as keep.

Only if the owner explicitly asks for an aggressive clean: `plan --broad`. It adds everything the
community list marks Recommended for OEM, carrier and preloaded packages. Read every added line
to the owner; it will include apps some people use.

**Step 4: final plan.** Re-run `plan` with `--remove a,b,c` for the apps the owner did not tick
and `--keep x,y` for anything they want left alone. Note the plan file path it prints.

**Step 5: apply.** Only after the owner's explicit yes: `apply --plan <file> --yes`. It writes a
backup and a record, disables one package per command, re-probes the device, and verifies that
Home, keyboard, phone and SMS are unchanged; if that check fails it restores on its own. Read the
output. If some packages failed with a refusal and the owner wants them gone, explain the
fallback and re-run with `--allow-uninstall`.

**Step 6: verify with the owner.** Ask them to: unlock the phone, go Home, open the phone app and
Messages, open the camera, open Settings, check Wi-Fi and mobile data, open their bank or
payment app if they use one. Then reboot once and check again. If anything is wrong:
`restore --record <file>` immediately, then re-plan with `--keep`.

**Step 7: report.** Tell the owner: how many packages were turned off and what they were in
plain words; the record file path; the one-line undo
(`python3 tools/debloat.py restore --record <file>`); that a system update may re-enable some of
them and `check --record <file> --fix` puts them back; and to turn USB debugging off now.

## When something goes wrong

| Symptom | Do |
|---|---|
| `error: no device is connected` | USB debugging is off, the cable is charge-only, or the driver is missing (Windows). See the recipe. |
| `unauthorized` | The owner has to accept the prompt on the phone. |
| `pm disable-user` refused for a package | Normal on Samsung and some ColorOS builds. Report it; offer `--allow-uninstall`. |
| An app or feature stopped working | `restore --record <file>` now, ask what they were doing, re-plan with `--keep`. |
| The computer cannot reach the phone any more | The owner can re-enable any package on the phone: Settings > Apps > (show system apps) > the app > Enable. |
| Something looks like a boot loop | Should not happen with the guards. Do not attempt fixes over adb; it is the owner's decision to use safe mode or a factory reset, and you must say that a reset erases the phone. |
| macOS: `adb connect` says "No route to host" | macOS Local Network privacy. Use a cable, or allow the terminal app under System Settings > Privacy & Security > Local Network. |

## Dumbphone extras

[recipes/dumbphone.md](recipes/dumbphone.md) has the optional finishing touches: greyscale,
faster animations, a minimal launcher. Every step there carries its undo. Offer them; do not
apply them unasked.

## Contributing a result back

The most useful thing an agent can send back is a profile improvement: a package that was on the
device and clearly belongs in `data/profiles/<oem>.txt`, with a one-line note of what it is, or a
note that a listed package no longer exists. Follow [CONTRIBUTING.md](CONTRIBUTING.md), run the
tests and the validator, and never include device identifiers or the owner's backups.

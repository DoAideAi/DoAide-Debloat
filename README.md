# DoAide Debloat

**dumbtv for the rest of your devices.** Strip the ads, the tracking and the preloaded junk from
any Android phone or tablet over ADB. No root, nothing uninstalled from the system, every step
undone by one command. Built to be driven by a coding agent: point Claude Code, Codex, Hermes or
Gemini CLI at this repository and say "clean up my phone".

> Status: early but real. Verified end to end on one physical device (OnePlus CPH2487, OxygenOS 16 /
> Android 16: probe, backup, plan, apply, drift check, restore, re-apply), 28 behaviour tests
> against a simulated device, and package lists cross-checked against the community UAD list. Other
> OEMs are community-verified, not yet device-verified: reports from real devices are the most
> useful contribution right now; see [CONTRIBUTING.md](CONTRIBUTING.md).

## Why

Phones sold in India and much of Asia come with Glance stories on the lock screen, Xiaomi's
"MSA" ads inside Settings, Samsung's Customization Service profiling everything you do, three app
stores, two browsers, a dozen stubs that nag you to install Facebook, and a games launcher nobody
asked for. Settings lets you disable some of it; the rest is "system" and cannot be touched from
the phone. Over ADB it can, and has been for years, with tools like Universal Android Debloater.
What changed in October 2026 is that a coding agent can do the whole thing for your parents' phone
while you watch: discover the model, back it up, explain what each package is, ask what they use,
turn the rest off, verify, and leave a restore file.

## What it does

| Step | What happens |
|---|---|
| Probe | Reads model, Android version, OEM, and which apps own Home, the keyboard, phone, SMS and browser. Those are protected for the rest of the run. |
| Back up | Package list, disabled list, user-removed list, props and settings go to `backups/`. |
| Plan | Matches the installed packages against a per-OEM profile (ads, tracking, clutter, and an "ask the owner" list), enriched with the community UAD list. Prints what would change. Changes nothing. |
| Apply | `pm disable-user --user 0`, one package per command, record file written as it goes, then a re-probe verifies Home, keyboard, phone and SMS are unchanged (it restores by itself if not). |
| Restore | `restore --record` undoes exactly what was done; `restore --backup` re-enables anything the backup says was enabled. |
| Check | After a firmware update, `check --record --fix` re-disables what came back. |

Nothing is ever deleted from the system image. `--allow-uninstall` opts into
`pm uninstall -k --user 0` for the few packages some OEMs refuse to disable; that is undone by
`cmd package install-existing`, and the tool knows how.

## Quick start: with a coding agent

1. **On the phone:** Settings > About phone > tap *Build number* seven times. Then Settings >
   Developer options > *USB debugging* on. Per-brand paths in
   [recipes/android-phone.md](recipes/android-phone.md).
2. **On the computer:** install `adb` (`brew install android-platform-tools`,
   `winget install Google.PlatformTools`, or `sudo apt install adb`), plug in the phone with a
   data cable, then:
   ```sh
   git clone https://github.com/DoAideAi/DoAide-Debloat && cd DoAide-Debloat
   ```
   Open your agent in that folder and paste [PROMPT.md](PROMPT.md), or just say
   *"Clean up my Samsung phone, follow AGENTS.md"*.
3. **Follow along:** accept *Allow USB debugging?* on the phone, then answer the checklist:
   which of the optional apps (Samsung Pay, Bixby, Mi Video, Alexa...) you actually use. Only
   what you do not tick is turned off.

Fifteen minutes, including the questions.

## Quick start: as an installed skill

If your agent supports skills you do not even need to clone first:
`npx skills add DoAideAi/DoAide-Debloat` (skills.sh) installs
[`skills/android-debloat/SKILL.md`](skills/android-debloat/SKILL.md) into Claude Code, Codex,
Cursor and others; Hermes and OpenClaw users can point their skills hub at the same path. The skill
tells the agent to clone this repo and follow `AGENTS.md`.

## Quick start: by hand

```sh
python3 tools/debloat.py probe                          # what is this device, what is protected
python3 tools/debloat.py backup                         # snapshot to backups/
python3 tools/debloat.py plan                           # what would be disabled; writes a plan file
python3 tools/debloat.py plan --remove com.samsung.android.spay,com.samsung.android.bixby.agent
python3 tools/debloat.py apply --plan backups/plan-<model>-<time>.json --yes
python3 tools/debloat.py restore --record backups/record-<model>-<time>.json   # undo
python3 tools/debloat.py check --record backups/record-<model>-<time>.json --fix  # after an update
python3 tools/debloat.py lookup glance bixby --device   # what is this package?
```

Python 3.9+ and `adb`. No other dependencies. Wi-Fi instead of a cable: turn on Wireless
debugging on the phone, open "Pair device with pairing code", then
`python3 tools/debloat.py connect --discover --code 123456` (it finds the ports itself on the same
Wi-Fi) and use the `--serial ip:port` it prints for every other command.

## Devices

| Device | Profile | Status |
|---|---|---|
| OnePlus CPH2487, OxygenOS 16 (Android 16) | `oppo.txt` + generic | **device-verified**: full loop incl. restore. OxygenOS refuses to disable its App Market; everything else applied. |
| Other OnePlus, OPPO, realme (ColorOS, OxygenOS) | `oppo.txt` | lists community-verified |
| Samsung (One UI) | `data/profiles/samsung.txt` + generic | lists community-verified, awaiting device reports |
| Xiaomi, Redmi, POCO (MIUI, HyperOS) | `xiaomi.txt` | same |
| vivo, iQOO | `vivo.txt` | same |
| Motorola | `motorola.txt` | same |
| Google Pixel | `google.txt` | same |
| Amazon Fire tablets | `amazon.txt`, see [recipes/fire-tablet.md](recipes/fire-tablet.md) | package names from community lists, untested here |
| Any other Android | generic profile only; `plan --broad` uses the community list | |
| Android TV / Google TV | use [cleanyourtv](https://github.com/Gathin23/cleanyourtv) | |
| Fire TV | use [dumbtv](https://github.com/humblemuzzu/dumbtv) | |
| Samsung Tizen, LG webOS, Roku, iPhone | not possible without root/jailbreak | |

"Community-verified" means every non-`ask` entry is marked Recommended or Advanced in the
[UAD](https://github.com/Universal-Debloater-Alliance/universal-android-debloater-next-generation)
list (`tools/validate_lists.py --uad` enforces this). "Device-verified" means someone ran the
full loop, including restore, on that model and filed a
[device report](https://github.com/DoAideAi/DoAide-Debloat/issues/new?template=device-report.yml).
Ran it on yours? That report is the most useful thing you can send: the next person with your
model skips the discovery. The list format is one line per package:

```
com.miui.msa.global | ads       | MSA (MIUI System Ads): the ads inside Settings, Security, Cleaner, Themes
com.samsung.android.spay | ask  | Samsung Wallet / Samsung Pay
```

`ads`, `telemetry` and `junk` go into the plan by default; `ask` only when the owner names it.

## Safety

* The current home screen, keyboard, phone, SMS, browser and emergency apps are read from the
  device and refused, whatever a list says. So is everything in
  [data/never-disable.txt](data/never-disable.txt): Android's own packages, Play Services,
  Samsung Knox and account services, Xiaomi's security centre and Find Device, OEM launchers.
* Only packages that are installed and enabled on the connected device are acted on. Nothing is
  invented from a list.
* The backup and the record are written before and during the change, so an interrupted run is
  still undoable.
* After applying, the device is re-probed; if Home, keyboard, phone or SMS changed, the run
  restores itself.
* A plan is bound to the device it was made for.
* Backups and records contain no serial number, only a hash; `backups/` is git-ignored.

A debloated phone is still a phone with ADB enabled. Turn USB debugging off when you are done
(`parent finish` does it).

## Dumbphone extras

Greyscale, instant animations, a minimal launcher: the optional finishing touches that make a
flagship as boring as a Light Phone, each with its undo, in
[recipes/dumbphone.md](recipes/dumbphone.md).

## Parent mode: make a parent's phone harder to scam

For the next visit home: plug in a parent's phone and tell your agent *"make this phone safe,
follow recipes/parent-mode.md"*. It runs a read-only audit, explains each finding in plain words,
makes the changes the owner agrees to, goes through what no tool can do, makes a shareable card
and switches USB debugging off. Nothing is deleted; every change is recorded and undoable.

| The audit finds | What can be done |
|---|---|
| Remote-control apps (AnyDesk, TeamViewer QuickSupport, RustDesk, AirDroid...) | switched off, if the owner agrees |
| Apps allowed to install APK files (WhatsApp, Chrome, file managers...) | denied, by default |
| Apps from outside an app store that read SMS, contacts or the call log | permission taken back, or the app switched off |
| Third-party accessibility and notification access, which is how one-time passwords get read | removed, if the owner agrees |
| Device admins, a sideloaded SMS app, Play Protect off, an old security patch, WhatsApp media | step-by-step instructions (adb cannot change these) |

```sh
python3 tools/debloat.py parent audit                        # read-only; writes backups/parent-audit-*.json
python3 tools/debloat.py parent apply --audit <file> --yes   # [auto] changes, plus --fix <id> for [ask] ones
python3 tools/debloat.py parent card --record <file> --who Mum
python3 tools/debloat.py parent finish --record <file> --yes # USB and wireless debugging off; last step
python3 tools/debloat.py parent restore --record <file>      # undo
```

The card shows counts only: never app names, the phone model or anything personal. If the audit
cannot read part of a phone, it says so instead of calling the phone clean.

> Status: 29 behaviour tests against a simulated phone. Not yet run on a real one: reports from
> real phones (especially Samsung, Xiaomi, vivo, OPPO and realme) are the most useful contribution.

## Development

[![CI](https://github.com/DoAideAi/DoAide-Debloat/actions/workflows/ci.yml/badge.svg)](https://github.com/DoAideAi/DoAide-Debloat/actions/workflows/ci.yml)

```sh
python3 -m unittest discover -s tests -v      # behaviour tests against scripted fake devices
python3 tools/validate_lists.py --uad         # list syntax, duplicates, never-disable overlap, UAD cross-check
```

## Related work and thanks

* [cleanyourtv](https://github.com/Gathin23/cleanyourtv) and [dumbtv](https://github.com/humblemuzzu/dumbtv):
  the October 2026 "point your agent at this repo" TV cleanups this project is modelled on.
* [Universal Android Debloater NG](https://github.com/Universal-Debloater-Alliance/universal-android-debloater-next-generation):
  the community package list (GPL-3.0) that `lookup` and `--broad` consult at runtime. It is
  downloaded to `~/.cache/doaide-debloat/` and never redistributed here.
* [android-cleanup-agent](https://willcoliveira.github.io/android-cleanup-agent/) and
  [android-tv-debloat](https://github.com/colefoster/android-tv-debloat): parallel efforts worth knowing.

MIT licence. Not affiliated with Google, Samsung, Xiaomi, Amazon or any other manufacturer.

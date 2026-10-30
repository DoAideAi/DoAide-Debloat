# X-ray: what the phone sends home, before and after

Optional, around a debloat: one ten-minute capture before, one after, and a card that shows the
difference. About 25 minutes on top of the debloat, most of it waiting. Every command is
`python3 tools/xray.py <subcommand>` from the repository root; `--help` lists the options.

## What it does, and what it does not

* [PCAPdroid](https://github.com/emanuele-f/PCAPdroid) (free, open source, no root) records the
  phone's traffic on the phone, through a local VPN. `xray.py` starts and stops it over adb with
  PCAPdroid's documented intent API, wakes the lock screen ten times during the capture (the way a
  person glances at a phone, which is when lock-screen services such as Glance load), pulls the
  file, deletes it from the phone, and reads server names out of it: DNS answers, the TLS server
  name and the HTTP Host header. Nothing is decrypted, no certificate is installed, nothing is
  blocked except QUIC and Private DNS for the length of the capture (see below).
* A server counts as ad or tracking when one of [HaGeZi's lists](https://github.com/hagezi/dns-blocklists)
  names it: the phone makers' own telemetry lists (Xiaomi, Samsung, OPPO / realme / OnePlus, vivo,
  Huawei, Amazon) and the broad Pro list. [Exodus Privacy](https://reports.exodus-privacy.eu.org/en/trackers/)
  adds company names. The lists are downloaded at runtime into `~/.cache/doaide-debloat/xray/`.
* The raw capture is deleted once it is analysed (`--keep-pcap` keeps it). The report goes to
  `backups/`, which is git-ignored. It names every server and every app, so it stays on the computer.
* `card` writes `share.json`, the only file meant to be public: counts, plus the tracker domains
  and package names of preinstalled apps. Never the serial, IP addresses, other servers, or
  anything about apps the owner installed.

## Steps

**0. Ask the owner.** Say: "To show what the phone sends home, I would record which servers it
talks to for ten minutes, before and after. The recording stays on this computer. Afterwards you
get a card with the counts, and you decide whether to share it." Continue only with a yes; `--yes`
on the commands below records that they agreed.

**1. PCAPdroid on the phone.** `setup --open-store` opens its Play Store page on the phone; the
owner taps Install and opens the app once (F-Droid works too). `setup` confirms it is ready.
Optional, saves two taps per capture: generate an API key in PCAPdroid's *Control permissions*
screen (its menu has *Generate API key*), then `export PCAPDROID_API_KEY=<key>` on the computer.
Without it the phone asks *Allow* when a capture starts (the first time also the VPN request) and
again, after unlocking, when it stops.

**2. Before.** `capture --label before --yes`. The phone lies untouched on the network it will
also be on for the after capture (Wi-Fi or mobile data, not both). It prints the summary and the
report path.

**3. Debloat.** [AGENTS.md](../AGENTS.md), steps 1 to 6, including the reboot.

**4. After.** Wait five minutes after the reboot so start-up syncing does not count, then
`capture --label after --yes` with the same `--minutes` and `--wakes` as before.

**5. The card.**

```sh
python3 tools/xray.py card backups/xray-<model>-before-<time>.json backups/xray-<model>-after-<time>.json \
    --record backups/record-<model>-<time>.json --png
```

Show the owner `card.png` (or open `card.html`, which has a save button) and `share.json`. The link
it prints opens a filled-in GitHub issue for the Phone-Home Index; nothing is posted until they
submit it themselves.

**6. Clean up.** PCAPdroid can stay or go; the owner uninstalls it like any other app. Then turn
USB debugging off (AGENTS.md step 7).

## Reading the numbers honestly

* Counts vary from run to run with the network, the time of day and pending updates. A difference
  of a few servers means nothing; 120 to 10 means something.
* *Servers* are distinct host names; *connections* are TCP and UDP flows; *data* is bytes in both
  directions. Connections to the DNS resolver, the local network and PCAPdroid itself are left out.
* `card` refuses to compare two reports from different phones or with different `--minutes` or
  `--wakes` (`--allow-mismatch` overrides, and then the card is not a fair comparison).
* During the capture QUIC is blocked so apps fall back to TLS over TCP, whose server name is
  visible, and Private DNS is blocked so lookups are visible. IPv6 is captured as well; the
  PCAPdroid default would let it bypass the capture, which matters on Jio and Airtel.
* What it cannot see: the real server behind Encrypted Client Hello (the public name is counted);
  connections to an address with no DNS answer in the capture (counted, not named); anything that
  bypasses the VPN.
* Apps are identified from the uid PCAPdroid stores with every packet. DNS lookups go through
  Android's resolver, so they are not attributed to an app.

## A capture made by hand

Without adb control: in PCAPdroid pick the PCAP file dump mode, turn on its dump extensions (they
add the app to every packet; older versions call them the PCAPdroid trailer), capture, copy the file
to the computer, then `analyze <file.pcap> --device` with the same phone connected, so app names can
be read. Without `--device` the report has no app names and the public summary names no domains.

## When something goes wrong

| Symptom | Do |
|---|---|
| `PCAPdroid did not start capturing` | The *Allow* dialog was dismissed, or another VPN (or Always-on VPN under Settings > Network > VPN) is active. Android 17 and newer also ask for local network access the first time. |
| `PCAPdroid still shows a running capture` | Stop it from PCAPdroid's notification on the phone. The file is analysed anyway. |
| `could not delete ... from the phone` | Delete it in Files > Download > PCAPdroid. |
| `the HaGeZi tracker lists could not be loaded` | Run once with internet access; after that the cached lists are used. |
| `these two reports should not be compared` | Different phone or settings. Capture again with the same `--minutes` and `--wakes`. |
| `PCAPdroid ... is too old` | Update it from the Play Store or F-Droid. |

## The Phone-Home Index

Reports filed through the link become GitHub issues labelled `xray-report`.
`python3 tools/xray_index.py --fetch` builds `site/phone-home.html` and `site/phone-home.json` from
them. Only reports with the standard settings (10 minutes, 10 wake-ups) count, and issues labelled
`invalid`, `duplicate` or `spam` are left out. Every row links to the issues it came from.

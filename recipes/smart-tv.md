# Smart TVs: go to the projects that already do this

This repository is for phones and tablets. The TV cleanups that started the "point your agent
at this repo" wave in October 2026 are maintained by their own authors with per-model lists:

| TV | Project |
|---|---|
| Android TV / Google TV (Xiaomi, TCL, Hisense, Sony, Philips, OnePlus, Nvidia Shield...) | [cleanyourtv](https://github.com/Gathin23/cleanyourtv): 170+ tested model lists, an Apple-TV-style launcher, one-line restore |
| Fire TV stick, Cube, Fire TV Edition television | [dumbtv](https://github.com/humblemuzzu/dumbtv): Amazon ad/ACR/telemetry packages off, on-TV DNS filter, its own launcher |
| Any Android TV, scan-first | [android-tv-debloat](https://github.com/colefoster/android-tv-debloat) |

**Samsung Tizen, LG webOS, Roku, Vizio SmartCast** have no ADB. Disabling their built-in ads
and viewing-data collection (ACR) means either rooting the TV (webOS homebrew; not covered
here, and it voids warranties) or blocking the domains at the network: an ad-blocking DNS
(AdGuard DNS `94.140.14.14`, NextDNS, or a Pi-hole/AdGuard Home on the LAN) set on the TV or
the router, plus turning off ACR in the TV's privacy settings ("Viewing Information Services"
on Samsung, "Live Plus" on LG, "Smart TV Experience" on Roku). That is a settings-and-router job,
not an ADB one.

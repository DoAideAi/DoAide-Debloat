# Amazon Fire tablets

Fire OS is Android underneath, so the same tools apply. The lock-screen ads ("Special Offers")
and most of the Amazon services can be disabled for the user without root.

**Not for Fire TV.** Sticks, Cubes and Fire TV Edition televisions have their own launcher,
DNS filter and tested lists at [dumbtv](https://github.com/humblemuzzu/dumbtv). Use that.

## Enable ADB

Settings > Device Options > About Fire Tablet > tap *Serial Number* seven times. Back to Device
Options > Developer Options > *Enable ADB*. Connect with a data cable and accept the prompt.

```sh
python3 tools/debloat.py probe      # should show manufacturer Amazon, OEM profile amazon
python3 tools/debloat.py backup
python3 tools/debloat.py plan
```

## What the profile does

* Turns off Special Offers (`com.amazon.kindle.kso`, `com.amazon.kso.blackbird`), device
  metrics and crash reporting, GameCircle and the Help app.
* Asks about Alexa, Amazon Kids, the Appstore, Kindle, Music, Prime Video, Photos, Silk,
  Shopping and Audible. Keep the **Appstore** (`com.amazon.venezia`) if you install or update
  any Amazon app; it is how they update.

The Fire launcher (`com.amazon.firelauncher`) is protected: replacing the home screen on Fire
OS needs a launcher-hijack helper that Amazon periodically breaks, and is out of scope here.
[Fire Toolbox](https://forum.xda-developers.com/t/windows-tool-fire-toolbox-v31-0.3889604/)
(Windows) does that and installs Google Play if you want the full conversion.

## Status

The Amazon package names come from community Fire-tablet debloat lists and have not been
re-verified on a device by this project. The guards still apply: nothing is touched that is not
installed, and the launcher, settings and account services are protected. If you run it, send
back what the plan showed and what worked: [CONTRIBUTING.md](../CONTRIBUTING.md).

# Dumbphone extras

Optional finishing touches after a cleanup. Each one is a plain `adb shell` setting with its
undo next to it; none needs root and none survives a factory reset. Offer them, do not apply
them unasked.

## Greyscale (the single most effective "use my phone less" change)

```sh
adb shell settings put secure accessibility_display_daltonizer_enabled 1
adb shell settings put secure accessibility_display_daltonizer 0        # 0 = monochromacy
```
Undo:
```sh
adb shell settings put secure accessibility_display_daltonizer_enabled 0
```
On Android 10+ the owner can also toggle it from Settings > Accessibility > Colour correction, or
add it to Quick Settings and bind it to Bedtime mode in Digital Wellbeing.

## Animations off (the phone feels twice as fast)

```sh
adb shell settings put global window_animation_scale 0
adb shell settings put global transition_animation_scale 0
adb shell settings put global animator_duration_scale 0
```
Undo: set all three to `1`.

## A minimal launcher

A home screen that is a list of app names, no icons, no widgets, no feed. Open source options:

| Launcher | Source |
|---|---|
| Olauncher | https://github.com/tanujnotes/Olauncher (F-Droid: `app.olauncher`) |
| Niagara Launcher (not open source, free tier) | Play Store |

Install the APK from the project's releases page, then make it the default from the phone
(Settings > Apps > Default apps > Home app). The stock launcher stays installed and protected;
this repository never disables a launcher.

```sh
adb install Olauncher.apk
```
Undo: Settings > Apps > Default apps > Home app > the stock launcher; then uninstall Olauncher.

## Fewer interruptions

Not a shell setting, but worth doing together: Settings > Notifications > App notifications,
turn off everything that is not a person. On Samsung also Settings > Notifications > Advanced
settings > *Notification pop-up style: Brief*. On Xiaomi: Settings > Notifications & status bar >
*Lock screen notifications: Hide*.

## Why not more

Battery "optimisers", task killers and most "privacy" toggles found in forum threads are either
no-ops on modern Android or break push notifications for the apps the owner relies on. Keep the
extras to the three above.

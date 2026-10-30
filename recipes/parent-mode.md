# Parent mode: make a parent's phone harder to scam

For the visit home: plug in a parent's phone, tell your agent *"make this phone safe, follow
recipes/parent-mode.md"*, and in about twenty minutes the phone has been checked, the changes its
owner agreed to are made, the family has done the few things no tool can do, and USB debugging is
off again. Nothing is deleted. Every change is recorded and undone by one command.

It targets what phone scams in India actually use: remote-control apps a "bank officer" or
"police officer" talks someone into installing, fake "KYC update" or "electricity bill" APK files
sent over WhatsApp, apps that read one-time passwords from SMS or notifications, loan apps that
harvest contacts, and the "digital arrest" video call.

## Rules (in addition to AGENTS.md)

1. **Audit first, every time.** `parent audit` only reads. Show its result before changing anything.
2. **Only `parent apply` changes the phone.** Never type your own `pm`, `appops` or `settings`
   commands, and never edit the repository during a session.
3. **`[auto]` changes are made by default; `[ask]` changes need a yes.** Explain each `[ask]` item
   in the owner's language, one or two sentences, from its `why:` line, and wait. A remote-control
   app the family uses to help stays on.
4. **Never delete anything.** No uninstalls, no deleting messages, photos or WhatsApp media. The
   tool switches apps off; the owner clears WhatsApp storage inside WhatsApp.
5. **"Harder to scam", never "scam-proof".** If the audit has an `audit-incomplete` finding, do its
   by-hand checks and do not call the phone clean.
6. **Nothing personal leaves the phone.** Do not paste the audit, app lists or screenshots into a
   chat or a post. The card is the shareable output and holds counts only.
7. **`parent finish` is the last command.** After it adb is gone; `restore` needs USB debugging on
   again.

## Steps

Commands run from the repository root. With more than one device, put `--serial <S>` right after
`debloat.py`.

1. **Connect.** USB debugging on, cable in, accept the prompt
   ([android-phone.md](android-phone.md); Wi-Fi works too).
2. **Audit:** `python3 tools/debloat.py parent audit`. Go through FIX NOW first, then WORTH A LOOK.
   Each finding has a `why:` line to explain it, `seen:` lines saying how the app got there, change
   ids in brackets, and `by hand:` steps for what adb cannot change.
3. **Ask about the `[ask]` items.** Useful questions: *"Does anyone in the family use AnyDesk to
   help you? Did someone ask you to install it on a call?"*, *"Do you know this app? Who sent it?"*
   An app installed from WhatsApp that reads SMS is the strongest signal on the list.
4. **Apply:** `python3 tools/debloat.py parent apply --audit <audit file> --yes --fix <id>,<id>`.
   `[auto]` changes are included unless named with `--skip <id>`. Quote ids that contain `$`
   (`--fix 'listener:com.x/com.x.Otp$Service'`). Report `FAIL` lines as they are: a failed change
   left the phone as it was.
5. **Do the by-hand items together**, on the phone, with the owner holding it: the audit's
   `by hand:` lines (Play Protect, device admins, default SMS app) and its checklist:
   * WhatsApp > Settings > Privacy > Calls > *Silence unknown callers*.
   * WhatsApp > Settings > Account > *Two-step verification*.
   * WhatsApp > Settings > Privacy > *Groups: My contacts*.
   * A family code word for any call that asks for money.
   * 1930 saved as the National Cyber Crime Helpline.
   * Said out loud: no police officer, bank or courier asks you to install an app, share your
     screen or stay on a video call. "Digital arrest" does not exist.
6. **Card:** `python3 tools/debloat.py parent card --record <record file> --who Mum`. Open the
   `.html` file; its button saves or shares a PNG. `--who` takes a first name or relation only.
7. **Finish:** `python3 tools/debloat.py parent finish --record <record file> --yes`. It switches
   USB and wireless debugging off; the connection ends.

Undo everything later (USB debugging on again): `python3 tools/debloat.py parent restore --record
<record file>`.

## What each change does

| Id | Made with | Undone with |
|---|---|---|
| `install:<pkg>` [auto for third-party apps, browsers, messengers, mail, file managers] | `appops set <pkg> REQUEST_INSTALL_PACKAGES deny`, plus `--uid` when the allow was set for the app's uid | the previous package and uid modes |
| `unknown-sources:legacy` [auto, Android 7 and older] | `settings put secure install_non_market_apps 0` | the previous value |
| `disable:<pkg>` [ask] | `pm disable-user --user 0 <pkg>` | `pm enable --user 0 <pkg>` |
| `revoke:<pkg>:<PERMISSION>` [ask; SMS, contacts and call log only] | `pm revoke <pkg> <permission>` | `pm grant` |
| `accessibility:<component>` [ask] | the component removed from `enabled_accessibility_services` | added back |
| `listener:<component>` [ask] | `cmd notification disallow_listener` | `cmd notification allow_listener` |

Every change is read back from the phone before it counts as done. The home screen, keyboard,
phone, SMS and browser apps and everything in `data/never-disable.txt` are refused, whatever the
audit file says. Apps installed by an app store keep their SMS access: banking and UPI apps need it.

## What the tool cannot do

| Not possible over adb | Do instead |
|---|---|
| Take device-admin rights from another app | Settings > search *device admin* > untick it, then remove the app normally |
| Change the default SMS app | Settings > Apps > Default apps > SMS app |
| Turn Play Protect back on | Play Store > profile picture > Play Protect > settings |
| Clear WhatsApp media | WhatsApp > Settings > Storage and data > Manage storage |
| Stop scam calls | WhatsApp's *Silence unknown callers*; the phone app's spam filter |

## If money has already been lost

Call **1930** (National Cyber Crime Helpline) at once and report at
[cybercrime.gov.in](https://cybercrime.gov.in); the first hour matters most. Call the bank to block
the account and cards. Do not install anything a caller suggests to "recover" the money: that is
the second half of the same scam.

## Testing a new phone model

Before calling a brand supported: audit, then compare the audit with the phone's own screens
(Settings > *Install unknown apps*, Accessibility, *Notification access*). Then apply one `[auto]`
and one `[ask]` change, restore, apply again, and finish. File a device report
(`.github/ISSUE_TEMPLATE/device-report.yml`) with what matched and what did not.

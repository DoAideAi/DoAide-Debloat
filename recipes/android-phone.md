# Android phones and tablets: getting connected, and per-brand notes

## Enable USB debugging

Everything starts with Developer options. The menu moves around per brand:

| Brand | Build number lives at | Then |
|---|---|---|
| Samsung (One UI) | Settings > About phone > Software information > Build number (tap 7x) | Settings > Developer options > USB debugging |
| Xiaomi, Redmi, POCO | Settings > About phone > MIUI/HyperOS version (tap 7x) | Settings > Additional settings > Developer options > USB debugging |
| OnePlus, OPPO, realme | Settings > About device > Version > Build number (tap 7x) | Settings > Additional settings > Developer options > USB debugging |
| vivo, iQOO | Settings > About phone > Software version > Build number (tap 7x) | Settings > System > Developer options > USB debugging |
| Motorola, Pixel, most others | Settings > About phone > Build number (tap 7x) | Settings > System > Developer options > USB debugging |

Plug in a **data** cable (many bundled cables are charge-only). On the phone, accept
*Allow USB debugging?* and tick *Always allow from this computer*. Then:

```sh
python3 tools/debloat.py probe
```

## Wi-Fi instead of a cable (Android 11+)

Developer options > Wireless debugging > on > *Pair device with pairing code*. The phone shows a
six-digit code (and an IP:port). On the same Wi-Fi the tool finds the ports by itself:

```sh
python3 tools/debloat.py connect --discover --code 123456
```

It prints the `--serial ip:port` to use afterwards. The phone then appears twice in
`adb devices -l` (as `ip:port` and as an `adb-...._adb-tls-connect` name): that is one device;
always pass `--serial ip:port`. Without mDNS, pass the ports by hand:
`connect 192.168.1.23:41234 --pair 192.168.1.23:37099 --code 123456`.

macOS may block the connection ("No route to host") under Local Network privacy. Allow your
terminal app in System Settings > Privacy & Security > Local Network, or use a cable.

## Per-brand notes

**Samsung.** One UI refuses `pm disable-user` for some packages (it answers with a
SecurityException). `apply --allow-uninstall` falls back to `pm uninstall -k --user 0`, which
keeps the app's data and is undone by `restore`. Samsung Pay/Wallet, Samsung Pass, Secure
Folder and Knox are deliberately protected or on the ask list: disabling the wrong one can lock
you out of payments or a work profile. Galaxy Store is on the ask list because Wallet and Galaxy
Wearable update through it.

**Xiaomi, Redmi, POCO.** You do not need a Mi account or "Install via USB" for disabling;
plain USB debugging is enough. Never disable `com.miui.securitycenter`, `com.xiaomi.finddevice`
or `com.xiaomi.account` (protected here): they are the known ways to boot-loop MIUI or lock the
phone. The ads come from `com.miui.msa.global`; the lock-screen feed from
`com.miui.android.fashiongallery` (Wallpaper Carousel) and, in India, `com.glance.internet`.
After an update, MIUI sometimes re-enables GetApps: `check --fix`.

**OnePlus, OPPO, realme (ColorOS, OxygenOS).** Device-verified on a OnePlus CPH2487 running
OxygenOS 16: the full loop works over Wi-Fi debugging, with one quirk. The system refuses
`pm disable-user` on its own App Market (`com.heytap.market`) by answering
`Package com.heytap.market new state: default` with exit 0, so the tool reports it as failed and
leaves it alone. The store is also how OnePlus updates its own apps; keeping it is reasonable, and
`apply --allow-uninstall` is the (reversible) way past it if the owner insists. If other `pm`
commands are refused, toggle *Disable permission monitoring* in Developer options for the session,
then turn it back on. The phone manager, OTA, SOS and account packages are protected. "Hot apps"
notifications come from `com.heytap.market`; the rotating lock-screen images from
`com.heytap.pictorial`.

**vivo, iQOO.** iManager (`com.iqoo.secure`) and the permission manager are protected; the
V-Appstore is the usual source of unwanted notifications.

**Motorola.** Little bloat; the OTA client and Moto app are on the ask list because Moto
Actions gestures live in the latter.

**Pixel.** Nothing to do beyond the generic Google apps you do not use. `--broad all` is the
only way to go further, and it will suggest things you probably want to keep.

## When the plan is empty

Either the phone is already clean, or the brand has no profile yet (`probe` shows `OEM: other`).
`plan --broad` consults the community list for everything marked Recommended; read each line.
Then please contribute what you learned: [CONTRIBUTING.md](../CONTRIBUTING.md).

## Afterwards

* A system update can re-enable packages: `python3 tools/debloat.py check --record <file> --fix`.
* To undo everything: `python3 tools/debloat.py restore --record <file>`.
* Turn USB debugging off: Developer options > USB debugging. You can also turn Developer
  options off entirely at the top of that screen.

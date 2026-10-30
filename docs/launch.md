# Launch kit

Drafts for the launch, in the order they go out. Replace the bracketed bits with what the real
before/after shows. Nothing here is public yet: the gate is one clean real-device run on the phone
in the post, plus the recording.

## 0. The artifact (make this first)

A 20-second screen recording and two screenshots:

1. Lock screen with the rotating magazine / Glance story, then the clean lock screen.
2. The `plan` output: the "WILL DISABLE" list with plain-English notes.
3. The last lines of `apply`: "6 disabled … Verified: home, keyboard, phone and messaging apps
   unchanged. Undo any time: …".

Blur nothing but keep the serial out of frame (the tools never print it).

## 1. X / Twitter

Post (media attached, no link in the post):

> Gave Claude Code my [mum's] OnePlus over Wi-Fi.
>
> [6] packages off: lock-screen magazine, the "hot apps" store pushes, three Facebook background
> services, Google's crash reporter. Nothing deleted. One-line undo.
>
> It asks which apps you actually use before touching anything.
>
> Point your agent at the repo and say "clean up my phone".

First reply:

> Repo: https://github.com/DoAideAi/DoAide-Debloat
> Works with Claude Code, Codex, Hermes, Gemini CLI. Samsung / Xiaomi / OnePlus / vivo / Moto /
> Pixel / Fire tablets. No root. MIT.
> Android TV: @gathint's cleanyourtv. Fire TV: @DevMuzzammil's dumbtv. This is the phone version.

Second reply (the ask that builds the moat):

> If you run it: reply with your phone model and what the plan showed. The lists improve with
> every report; your model's profile is the next person's shortcut.

Then reply in the cleanyourtv and dumbtv threads: "did the same for phones; here is what it
removed from a OnePlus" + the screenshot.

## 2. Hacker News (Sunday, ~12:00 UTC)

Title:

> Show HN: Point your coding agent at a repo to debloat your Android phone (no root, reversible)

Text:

> I built this after the smart-TV cleanups went round two weeks ago (cleanyourtv, dumbtv). Phones
> are the same problem with a bigger audience: lock-screen ads (Glance), OEM store pushes,
> Samsung's "Customization Service", stubs that nag you to install Facebook.
>
> It's a stdlib-only Python CLI over adb that a coding agent drives from AGENTS.md: probe the
> device, back up, build a plan from a per-OEM profile cross-checked against the UAD community
> list, ask the owner which optional apps they use, disable with `pm disable-user` one package per
> command, re-probe to verify Home/keyboard/phone/SMS are untouched, write a record file for
> one-line restore. Nothing is uninstalled from the system image. The home screen, keyboard,
> dialer, SMS and browser role holders are read live and refused no matter what a list says.
>
> Verified end to end on a OnePlus (OxygenOS 16) including the restore path; other OEM lists are
> community-verified and I'd like device reports. One finding: OxygenOS refuses to disable its own
> store by answering "new state: default" with exit 0, which is why the tool judges success on the
> text, not the exit code.
>
> https://github.com/DoAideAi/DoAide-Debloat

## 3. Reddit (stagger over a week)

r/Android, r/Xiaomi, r/samsung, r/Realme, r/oneplus, r/degoogle, r/privacy, r/ClaudeAI, r/india.

Title: "What a coding agent removed from my [OnePlus] without root (list inside, one-line undo)"

Body: the plain-English list from `plan`, what was refused and why, the restore command, then the
link. End with "if you run it on a [Samsung/Redmi], tell me what the plan showed".

## 4. Short video (Reels / Shorts / TikTok)

Payoff first: lock screen with ads → clean lock screen (3 s). Then the terminal: "6 packages off,
nothing deleted" (5 s). Then the hook: "point your agent at this repo and say: clean up my phone"
(5 s). Caption carries the repo name. Send the same clip to 5–10 mid-size tech creators who make
"remove ads from Redmi/Realme" videos.

## 5. Press

TechCrunch (Sarah Perez wrote the TV story on 19 Oct): "now people are vibe-coding their phones".
India: Gadgets360, Beebom, 91mobiles (Glance angle). Android Police, 9to5Google, XDA. One email:
the artifact, three lines on what it does, the OxygenOS finding, the link.

## 6. After launch

Merge profile reports fast. Add a "Tested devices" table to the README as reports arrive. Pin a
"send your model + plan output" issue. Once stars arrive: GitHub Sponsors and a sponsor line in
the README.

## 7. Parent mode, for Diwali (Lakshmi Puja: Sunday 8 November 2026)

Its own pitch, same repo, so the stars land in one place. The hook is the trip home: people
travel 5–7 November, so it goes out on Wednesday 4 November.

**Gate (no exceptions):** a clean real run on at least three phones from different brands
(Samsung, Xiaomi/Redmi, and vivo, OPPO or realme), each one audited, compared with the phone's own
Settings screens, one `[auto]` and one `[ask]` change applied, restored, applied again, then
`finish`. Breaking a parent's phone at Diwali is the worst possible demo. The card in the posts
comes from one of those runs.

**The artifact:** the card (counts only), plus a 30-second recording: `parent audit` showing
FIX NOW, the owner saying yes, `apply` ending in "Verified", the card.

**Never post:** an audit, an app list, the parent's screen, or "scam-proof". It is harder to scam.

### X (Wednesday 4 Nov, 19:00 IST)

> Going home for Diwali? Do this to your parents' phone.
>
> Plugged [Mum's] phone into my laptop, told Claude Code "make this phone safe".
> It found [AnyDesk, installed during a "KYC update" call], [2] apps allowed to install APK files
> from WhatsApp, and [an app that could read her OTPs].
>
> Read-only check first. Nothing deleted. Every change undoable. USB debugging off at the end.

First reply: the repo link, "Claude Code, Codex, Hermes, Gemini CLI. No root. MIT." Second reply:
"It makes a card with counts only, no app names. Share yours, tag the sibling who's going home."

### LinkedIn (same evening)

Lead with the number: Indians lost ₹1,935 crore to "digital arrest" scams in 2024 and ₹647 crore in
January–August 2026, and on 29 October the Supreme Court proposed making banks share the loss
([Indian Express](https://indianexpress.com/article/explained/digital-arrest-scams-supreme-court-rbi-bank-liability-explained-10943089)).
Then the visit home, what the audit found on [the real phone], the card.

### Hacker News (Thursday 5 Nov, ~12:00 UTC)

> Show HN: Make your parents' Android phone harder to scam with a coding agent (adb, reversible)

Text: what scams in India use (remote-control apps, APKs over WhatsApp, OTP-reading accessibility
and notification access, loan apps reading contacts); how the audit reads it (`dumpsys package`
install source and initiating app, the REQUEST_INSTALL_PACKAGES app-op, accessibility and
notification-access settings, device admins); that every change is read back and recorded; that the
card is counts-only by construction. Add one hardware finding [from the real runs].

### WhatsApp (the channel that matters here)

A forward for family and college groups: the card image, one line ("checked Mum's phone for
scam apps before Diwali, 20 minutes, nothing deleted"), the repo link. [Hindi and regional
versions: written by native speakers, not machine-translated.]

### Press

Indian outlets with the Supreme Court angle: Moneycontrol, Economic Times Tech, Gadgets360,
Beebom. TechCrunch (the 19 Oct smart-TV story) for the "agents doing family IT" angle.

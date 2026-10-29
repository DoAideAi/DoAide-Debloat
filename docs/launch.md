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

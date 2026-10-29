# Paste this into your coding agent

Clone the repository first and open the agent inside it; the agent then uses the tools in
`tools/` (backup, home/keyboard/phone guards, record and restore) instead of improvising.

```
git clone https://github.com/DoAideAi/DoAide-Debloat && cd DoAide-Debloat
```

Before you start, on the phone: Settings > About phone > tap "Build number" seven times, then
Settings > Developer options > turn on USB debugging. Plug the phone into the computer with a
data cable. (Per-brand menu paths: recipes/android-phone.md.)

Then say:

---

I want to clean up my Android phone: remove the ads, the tracking and the preloaded junk, without
rooting it and without deleting anything I cannot get back. My phone is: ____________.

Read AGENTS.md in this repository and follow it exactly, using `python3 tools/debloat.py` for
every step. Work on the real device. Back up before you change anything. Show me the plan in
plain words and ask me which of the optional apps I actually use before you disable anything.
When you are done, tell me how to undo it and remind me to turn USB debugging off.

---

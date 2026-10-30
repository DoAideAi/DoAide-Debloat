"""The parent-mode card: what was made safer, never whose phone it is or which apps it has.

The card is drawn from integers only (parent.card_facts) plus an optional first name or relation
("Mum", "Papa", "Nani", "माँ"), which is checked to be a name: no digits, no @, no links. Layout,
HTML save button and PNG rendering follow DoAide Reclaim's card.
"""
from __future__ import annotations

import html
import shutil
import subprocess
import tempfile
import unicodedata
from pathlib import Path
from typing import Dict, List, Optional

W, H = 1080, 1350
MARGIN = 80
FOOT = 1090  # baseline of the footer's first line; everything above must end before it
FONT = ("Inter, 'SF Pro Display', 'Segoe UI', Roboto, 'Noto Sans', 'Noto Sans Devanagari', "
        "'Helvetica Neue', Arial, sans-serif")
GOLD, SAFFRON, MINT, TEXT, MUTED = "#ffd166", "#ff9f1c", "#8be0b5", "#f2f2f2", "#a9b0c3"
URL = "github.com/DoAideAi/DoAide-Debloat"
CHROME_PATHS = (
    "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome",
    "/Applications/Chromium.app/Contents/MacOS/Chromium",
)


class CardError(ValueError):
    pass


def check_who(who: str) -> str:
    who = " ".join((who or "").split())
    if not who:
        return ""
    if len(who) > 20:
        raise CardError("--who is a first name or relation such as Mum, Papa or Nani (20 characters at most)")
    for ch in who:
        if ch not in " '’-." and unicodedata.category(ch)[0] not in ("L", "M"):
            raise CardError("--who is a first name or relation such as Mum, Papa or Nani: "
                            "no digits, @ or links on a card")
    return who


def _plural(n: int, one: str, many: str = "") -> str:
    return f"{n} {one if n == 1 else (many or one + 's')}"


def checklist(facts: Dict[str, int]) -> List[str]:
    """One line per kind of change that was made, most important first."""
    lines = []
    if facts.get("install"):
        lines.append(f"{_plural(facts['install'], 'app')} can no longer install APK files")
    if facts.get("legacy"):
        lines.append("Installing apps from unknown sources: off")
    if facts.get("remote"):
        lines.append(f"{_plural(facts['remote'], 'remote-control app')} switched off")
    if facts.get("access"):
        lines.append(f"{_plural(facts['access'], 'app')} lost screen or notification access")
    if facts.get("permissions"):
        lines.append(f"{_plural(facts['permissions'], 'SMS or contacts permission', 'SMS and contacts permissions')}"
                     " taken back")
    if facts.get("sideloaded"):
        lines.append(f"{_plural(facts['sideloaded'], 'unknown app')} switched off")
    if facts.get("debugging_off"):
        lines.append("USB debugging switched off again")
    return lines


def _text(x, y, content, size, fill, weight=400, anchor="start", spacing=0, opacity=1.0):
    extra = f' letter-spacing="{spacing}"' if spacing else ""
    extra += f' opacity="{opacity}"' if opacity != 1.0 else ""
    return (
        f'<text x="{x}" y="{y}" font-family="{html.escape(FONT)}" font-size="{size}" '
        f'font-weight="{weight}" fill="{fill}" text-anchor="{anchor}"{extra}>'
        f'{html.escape(content, quote=False)}</text>'
    )


def _fit(text: str, widest: int, largest: int) -> int:
    """A font size that keeps text within `widest` px (about 0.58em per glyph for this stack)."""
    return max(30, min(largest, int(widest / (0.58 * max(len(text), 1)))))


def _tick(x: int, y: int) -> str:
    return (f'<circle cx="{x}" cy="{y}" r="17" fill="{MINT}" fill-opacity="0.16"/>'
            f'<path d="M {x - 8} {y} l 5 6 l 10 -12" fill="none" stroke="{MINT}" stroke-width="4" '
            'stroke-linecap="round" stroke-linejoin="round"/>')


def svg(facts: Dict[str, int], who: str = "") -> str:
    who = check_who(who)
    lines = checklist(facts)
    if not lines:
        raise CardError("nothing was changed on the phone: a card is only made for changes")
    phone = f"{who}'s phone" if who else "this phone"
    if facts.get("fixed"):
        big, label = str(facts["fixed"]), ("scam risk fixed" if facts["fixed"] == 1 else "scam risks fixed")
        sub = f"on {phone}  ·  {facts.get('found', 0)} found"
    else:
        changes = facts.get("changes", 0) + facts.get("debugging_off", 0)
        big, label = str(changes), ("change" if changes == 1 else "changes") + " against scams"
        sub = f"on {phone}"
    parts = [
        f'<svg xmlns="http://www.w3.org/2000/svg" width="{W}" height="{H}" viewBox="0 0 {W} {H}">',
        '<defs><linearGradient id="bg" x1="0" y1="0" x2="0.35" y2="1">'
        '<stop offset="0" stop-color="#1d1238"/><stop offset="1" stop-color="#0b0b12"/></linearGradient>'
        f'<radialGradient id="glow" cx="0.85" cy="0.12" r="0.45"><stop offset="0" stop-color="{SAFFRON}" '
        f'stop-opacity="0.35"/><stop offset="1" stop-color="{SAFFRON}" stop-opacity="0"/></radialGradient></defs>',
        f'<rect width="{W}" height="{H}" fill="url(#bg)"/>',
        f'<rect width="{W}" height="{H}" fill="url(#glow)"/>',
        _text(MARGIN, 200, "PHONE SAFETY CHECK", 34, MINT, 700, spacing=6),
        _text(MARGIN, 500, big, 300, GOLD, 800),
        _text(MARGIN, 590, label, _fit(label, W - 2 * MARGIN, 72), TEXT, 700),
        _text(MARGIN, 650, sub, _fit(sub, W - 2 * MARGIN, 40), MUTED),
    ]
    y, step, last = 740, 64, FOOT - 94
    for line in lines:
        if y > last:
            break
        parts.append(_tick(MARGIN + 17, y - 12))
        parts.append(_text(MARGIN + 56, y, line, _fit(line, W - 2 * MARGIN - 56, 38), TEXT, 500))
        y += step
    tenths = facts.get("whatsapp_gb_tenths", 0)
    if tenths >= 10 and y <= last:
        parts.append(_text(MARGIN + 56, y, f"+ {tenths / 10:.1f} GB of WhatsApp media to clear", 34, MUTED))

    foot = FOOT
    parts.append(f'<rect x="{MARGIN}" y="{foot - 58}" width="{W - 2 * MARGIN}" height="2" fill="#ffffff" '
                 'fill-opacity="0.14"/>')
    parts.append(_text(MARGIN, foot, "Make your parents' phone harder to scam", 44, TEXT, 700))
    parts.append(_text(MARGIN, foot + 56, "Free and open source. Every change can be undone.", 34, MUTED))
    parts.append(f'<circle cx="{MARGIN + 12}" cy="{foot + 125}" r="12" fill="{SAFFRON}"/>')
    parts.append(_text(MARGIN + 36, foot + 137, "DoAide Debloat  ·  parent mode", 36, TEXT, 700))
    parts.append(_text(MARGIN + 36, foot + 180, URL, 28, MUTED))
    parts.append(_text(MARGIN, foot + 228, "No app names, phone numbers or personal details on this card.",
                       22, MUTED, opacity=0.8))
    parts.append("</svg>")
    return "\n".join(parts) + "\n"


PAGE = """<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>DoAide Debloat parent-mode card</title>
<style>
body{{margin:0;background:#111;color:#eee;font-family:system-ui,sans-serif;display:flex;
flex-direction:column;align-items:center;gap:16px;padding:16px}}
#card svg{{width:min(100%,540px);height:auto;border-radius:18px}}
button{{font-size:18px;padding:12px 22px;border-radius:999px;border:0;background:#ff9f1c;color:#111}}
</style></head><body>
<div id="card">{svg}</div>
<button id="save">Save or share as PNG</button>
<script>
document.getElementById("save").onclick = function () {{
  var svg = document.querySelector("#card svg");
  var img = new Image();
  img.onload = function () {{
    var canvas = document.createElement("canvas");
    canvas.width = {w}; canvas.height = {h};
    canvas.getContext("2d").drawImage(img, 0, 0, {w}, {h});
    canvas.toBlob(function (blob) {{
      var file = new File([blob], "parent-mode-card.png", {{type: "image/png"}});
      if (navigator.canShare && navigator.canShare({{files: [file]}})) {{
        navigator.share({{files: [file]}}).catch(function () {{}});
        return;
      }}
      var link = document.createElement("a");
      link.href = URL.createObjectURL(blob);
      link.download = "parent-mode-card.png";
      link.click();
    }}, "image/png");
  }};
  img.src = "data:image/svg+xml;charset=utf-8," +
    encodeURIComponent(new XMLSerializer().serializeToString(svg));
}};
</script>
</body></html>
"""


def page(svg_text: str) -> str:
    return PAGE.format(svg=svg_text, w=W, h=H)


def find_chrome() -> Optional[str]:
    for name in ("google-chrome", "google-chrome-stable", "chromium", "chromium-browser", "chrome"):
        found = shutil.which(name)
        if found:
            return found
    for path in CHROME_PATHS:
        if Path(path).exists():
            return path
    return None


def render_png(svg_text: str, out_png: Path, chrome: Optional[str] = None) -> Path:
    chrome = chrome or find_chrome()
    if not chrome:
        raise CardError("a PNG needs Chrome or Chromium; open the .html card and use its save button instead")
    out_png = Path(out_png).resolve()
    with tempfile.TemporaryDirectory() as tmp:
        sheet = Path(tmp) / "card.html"
        sheet.write_text(
            '<!doctype html><html><head><meta charset="utf-8"><style>html,body{margin:0;padding:0;'
            f'background:#000}}svg{{display:block}}</style></head><body>{svg_text}</body></html>',
            encoding="utf-8",
        )
        command = [
            chrome, "--headless=new", "--disable-gpu", "--hide-scrollbars", "--no-first-run",
            "--no-default-browser-check", "--force-device-scale-factor=1",
            f"--user-data-dir={Path(tmp) / 'profile'}", f"--window-size={W},{H}",
            f"--screenshot={out_png}", sheet.as_uri(),
        ]
        try:
            subprocess.run(command, check=True, capture_output=True, timeout=90)
        except (subprocess.CalledProcessError, subprocess.TimeoutExpired) as exc:
            detail = (getattr(exc, "stderr", b"") or b"").decode("utf-8", "replace").strip()[-300:]
            raise CardError(f"Chrome could not render the PNG ({exc.__class__.__name__}) {detail}") from None
    if not out_png.exists():
        raise CardError(f"Chrome did not write {out_png}")
    return out_png

"""Render messages as phone-style screenshots (PNG) for the image-mode demo, tests and eval.

    python -m eval.screenshots          # regenerates assets/demo/*.png

What a real screen shows is what gets rendered: invisible zero-width characters
are dropped and stylised math letters are shown as ordinary letters (NFKC).
Cyrillic homoglyphs are kept - they look identical to Latin on screen.
"""

from __future__ import annotations

import io
import sys
import unicodedata
from pathlib import Path

from PIL import Image, ImageDraw, ImageFont

ROOT = Path(__file__).resolve().parent.parent
DEMO_DIR = ROOT / "assets" / "demo"
_INVISIBLE = dict.fromkeys(map(ord, "​‌‍⁠﻿­᠎‎‏‪‫‬‭‮"))


def _font(size: int) -> ImageFont.FreeTypeFont | ImageFont.ImageFont:
    for name in ("arial.ttf", "segoeui.ttf", "DejaVuSans.ttf", "Arial.ttf", "Helvetica.ttc"):
        try:
            return ImageFont.truetype(name, size)
        except OSError:
            continue
    return ImageFont.load_default(size=size)


def screen_text(text: str) -> str:
    """What the user would actually see on screen."""
    out = []
    for ch in text.translate(_INVISIBLE):
        if 0x1D400 <= ord(ch) <= 0x1D7FF:
            ch = unicodedata.normalize("NFKC", ch)
        if unicodedata.category(ch) == "So" or ord(ch) > 0xFFFF:  # emoji: drawn as images on phones, skipped here
            continue
        out.append(ch)
    return "".join(out)


def _wrap(draw: ImageDraw.ImageDraw, text: str, font, max_width: int) -> list[str]:
    lines: list[str] = []
    for para in text.split("\n"):
        line = ""
        for word in para.split(" "):
            candidate = f"{line} {word}".strip()
            if draw.textlength(candidate, font=font) <= max_width:
                line = candidate
                continue
            if line:
                lines.append(line)
            # hard-wrap words wider than the bubble (long URLs), like phone UIs do
            while draw.textlength(word, font=font) > max_width:
                cut = len(word)
                while cut > 1 and draw.textlength(word[:cut], font=font) > max_width:
                    cut -= 1
                lines.append(word[:cut])
                word = word[cut:]
            line = word
        lines.append(line)
    return lines


def render_message(text: str, sender: str | None = None, *, width: int = 750) -> bytes:
    body_font, small_font, head_font = _font(30), _font(22), _font(28)
    probe = ImageDraw.Draw(Image.new("RGB", (10, 10)))
    bubble_w = int(width * 0.75)
    lines = _wrap(probe, screen_text(text), body_font, bubble_w - 48)
    line_h = 40
    header_h = 110
    bubble_h = 32 + line_h * len(lines)
    height = header_h + 70 + bubble_h + 60
    img = Image.new("RGB", (width, height), (255, 255, 255))
    d = ImageDraw.Draw(img)
    d.rectangle((0, 0, width, header_h), fill=(246, 246, 246))
    d.line((0, header_h, width, header_h), fill=(220, 220, 220), width=2)
    title = screen_text(sender or "Unknown sender")
    d.text(((width - d.textlength(title, font=head_font)) / 2, 40), title, font=head_font, fill=(20, 20, 20))
    stamp = "Today 9:41 AM"
    d.text(((width - d.textlength(stamp, font=small_font)) / 2, header_h + 22), stamp, font=small_font, fill=(140, 140, 140))
    top = header_h + 70
    d.rounded_rectangle((24, top, 24 + bubble_w, top + bubble_h), radius=28, fill=(233, 233, 235))
    for i, ln in enumerate(lines):
        d.text((48, top + 16 + i * line_h), ln, font=body_font, fill=(0, 0, 0))
    buf = io.BytesIO()
    img.save(buf, format="PNG")
    return buf.getvalue()


DEMO_SCREENSHOTS = {
    "fake_bank_otp.png": (
        "+1 (415) 555-0132",
        "Chase Alert: Unusual sign-in detected on your account. To avoid suspension, verify now at "
        "https://chase-secure-verify.com/login and reply with the 6-digit code we just sent you.",
    ),
    "genuine_bank_alert.png": (
        "24273",
        "Chase Fraud Alert: Did you make a $412.87 purchase at BESTBUY on 09/23? Reply YES or NO. "
        "We will never ask for your PIN, password or one-time code by text.",
    ),
    "delivery_fee_scam.png": (
        "+1 202 555 0178",
        "USPS: Your package is on hold due to an incomplete address. Pay the $1.99 redelivery fee within 24 hours: "
        "https://usps-redelivery-help.com/track",
    ),
}


def main() -> int:
    DEMO_DIR.mkdir(parents=True, exist_ok=True)
    for name, (sender, text) in DEMO_SCREENSHOTS.items():
        (DEMO_DIR / name).write_bytes(render_message(text, sender))
        print("wrote", DEMO_DIR / name)
    return 0


if __name__ == "__main__":
    sys.exit(main())

"""Realistic phone-screenshot renderer for OCR evaluation.

    python -m eval.phone_screens          # writes eval/screens/*.png|jpg + manifest.json

Styles mimic what people actually screenshot: iMessage light/dark (with status bar,
header, timestamp, blue links), Google Messages dark, WhatsApp light (patterned
wallpaper, green header) and dark, Gmail dark, a re-compressed low-resolution forward,
and a photo taken of a screen (tilt, blur, glare, noise, JPEG). Ground truth is what the
screen shows (zero-width characters invisible, stylised letters folded).
"""

from __future__ import annotations

import io
import json
import random
import re
import sys
from dataclasses import dataclass
from pathlib import Path

from PIL import Image, ImageDraw, ImageFilter, ImageFont

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from eval.screenshots import screen_text  # noqa: E402

OUT = ROOT / "eval" / "screens"
URL_RE = re.compile(r"(https?://\S+|www\.\S+|\b[a-z0-9-]+\.(?:com|net|org|info|xyz|top|shop|app|co|io|support)(?:/\S*)?)", re.I)


def font(size: int, bold: bool = False):
    names = ("segoeuib.ttf", "arialbd.ttf", "DejaVuSans-Bold.ttf") if bold else ("segoeui.ttf", "arial.ttf", "DejaVuSans.ttf")
    for name in names:
        try:
            return ImageFont.truetype(name, size)
        except OSError:
            continue
    return ImageFont.load_default(size=size)


@dataclass(frozen=True)
class Style:
    name: str
    width: int
    bg: tuple
    header_bg: tuple
    header_fg: tuple
    bubble: tuple
    text: tuple
    link: tuple
    meta: tuple
    font_px: int
    wallpaper: bool = False
    status_fg: tuple = (0, 0, 0)


STYLES = {
    "ios_light": Style("ios_light", 1170, (255, 255, 255), (248, 248, 248), (0, 0, 0), (233, 233, 235), (0, 0, 0), (10, 100, 220), (142, 142, 147), 51),
    "ios_dark": Style("ios_dark", 1170, (0, 0, 0), (22, 22, 24), (255, 255, 255), (38, 38, 41), (255, 255, 255), (255, 255, 255), (142, 142, 147), 51, status_fg=(255, 255, 255)),
    "android_dark": Style("android_dark", 1080, (18, 18, 20), (18, 18, 20), (227, 227, 227), (48, 48, 52), (227, 227, 227), (168, 199, 250), (160, 160, 165), 44, status_fg=(227, 227, 227)),
    "whatsapp_light": Style("whatsapp_light", 1080, (239, 234, 226), (0, 128, 105), (255, 255, 255), (255, 255, 255), (17, 27, 33), (2, 125, 200), (102, 119, 129), 42, wallpaper=True, status_fg=(255, 255, 255)),
    "whatsapp_dark": Style("whatsapp_dark", 1080, (11, 20, 26), (32, 44, 51), (233, 237, 239), (32, 44, 51), (233, 237, 239), (83, 189, 235), (134, 150, 160), 42, wallpaper=True, status_fg=(233, 237, 239)),
    "gmail_dark": Style("gmail_dark", 1080, (31, 31, 31), (31, 31, 31), (227, 227, 227), (31, 31, 31), (215, 215, 215), (138, 180, 248), (160, 160, 160), 40, status_fg=(227, 227, 227)),
}


def _wrap(draw, text: str, fnt, max_w: int) -> list[str]:
    out: list[str] = []
    for para in text.split("\n"):
        line = ""
        for word in para.split(" "):
            cand = f"{line} {word}".strip()
            if draw.textlength(cand, font=fnt) <= max_w:
                line = cand
                continue
            if line:
                out.append(line)
            while draw.textlength(word, font=fnt) > max_w:  # hard-wrap long URLs like phones do
                cut = len(word)
                while cut > 1 and draw.textlength(word[:cut], font=fnt) > max_w:
                    cut -= 1
                out.append(word[:cut])
                word = word[cut:]
            line = word
        out.append(line)
    return out


def _status_bar(d: ImageDraw.ImageDraw, s: Style, w: int) -> None:
    f = font(int(s.font_px * 0.85), bold=True)
    d.text((int(w * 0.08), 30), "9:41", font=f, fill=s.status_fg)
    x = w - int(w * 0.08)
    for i in range(4):  # signal bars
        h = 10 + i * 8
        d.rectangle((x - 150 + i * 16, 70 - h, x - 140 + i * 16, 70), fill=s.status_fg)
    d.rounded_rectangle((x - 70, 40, x - 10, 70), 8, outline=s.status_fg, width=3)
    d.rectangle((x - 66, 44, x - 30, 66), fill=s.status_fg)


def render(text: str, sender: str | None, style: Style, *, seed: int = 0) -> Image.Image:
    rnd = random.Random(seed)
    shown = screen_text(text)
    w = style.width
    body_f = font(style.font_px)
    meta_f = font(int(style.font_px * 0.62))
    head_f = font(int(style.font_px * 0.9), bold=True)
    probe = ImageDraw.Draw(Image.new("RGB", (10, 10)))
    gmail = style.name.startswith("gmail")
    pad = int(style.font_px * 0.7)
    bubble_max = int(w * (0.92 if gmail else 0.72))
    lines = _wrap(probe, shown, body_f, bubble_max - 2 * pad)
    line_h = int(style.font_px * 1.3)
    header_h = int(w * 0.23)
    bubble_h = 2 * pad + line_h * len(lines)
    h = max(int(w * 1.6), header_h + 200 + bubble_h + 400)
    img = Image.new("RGB", (w, h), style.bg)
    d = ImageDraw.Draw(img)
    if style.wallpaper:  # faint doodle pattern like WhatsApp wallpapers
        for _ in range(900):
            x, y, r = rnd.randrange(w), rnd.randrange(h), rnd.randrange(6, 26)
            shade = tuple(max(0, min(255, c + rnd.choice((-10, -7, 7, 10)))) for c in style.bg)
            d.ellipse((x - r, y - r, x + r, y + r), outline=shade, width=3)
    d.rectangle((0, 0, w, header_h), fill=style.header_bg)
    _status_bar(d, style, w)
    who = screen_text(sender or "Unknown")
    if gmail:
        subject = shown.split(".")[0][:60]
        d.text((pad * 2, header_h - int(style.font_px * 1.9)), subject, font=head_f, fill=style.header_fg)
        top = header_h + 40
        d.ellipse((pad * 2, top, pad * 2 + 90, top + 90), fill=(90, 120, 200))
        d.text((pad * 2 + 120, top), who, font=font(int(style.font_px * 0.8), bold=True), fill=style.header_fg)
        d.text((pad * 2 + 120, top + 50), "to me · 9:41 AM", font=meta_f, fill=style.meta)
        top += 160
        x0 = pad * 2
    else:
        cx = w // 2
        if style.name.startswith("ios"):
            d.ellipse((cx - 55, header_h - 190, cx + 55, header_h - 80), fill=(150, 150, 160))
            d.text((cx - probe.textlength(who, font=meta_f) / 2, header_h - 70), who, font=meta_f, fill=style.header_fg)
        else:
            d.text((pad * 5, header_h - int(style.font_px * 1.6)), who, font=head_f, fill=style.header_fg)
        stamp = "Text Message · Today 9:41 AM" if style.name.startswith("ios") else "Today"
        d.text((cx - probe.textlength(stamp, font=meta_f) / 2, header_h + 50), stamp, font=meta_f, fill=style.meta)
        top = header_h + 150
        x0 = int(w * 0.04)
        d.rounded_rectangle((x0, top, x0 + bubble_max, top + bubble_h), radius=int(style.font_px * 0.9), fill=style.bubble)
        x0 += pad
        top += pad
    for i, ln in enumerate(lines):
        y = top + i * line_h
        x = x0
        for part in URL_RE.split(ln):
            if not part:
                continue
            is_link = bool(URL_RE.fullmatch(part))
            fill = style.link if is_link else style.text
            d.text((x, y), part, font=body_f, fill=fill)
            tw = d.textlength(part, font=body_f)
            if is_link:
                d.line((x, y + style.font_px * 1.12, x + tw, y + style.font_px * 1.12), fill=fill, width=max(2, style.font_px // 20))
            x += tw
    if not gmail and style.name.startswith("whatsapp"):
        d.text((x0 + bubble_max - 2 * pad - 110, top + bubble_h - 2 * pad - int(style.font_px * 0.5)), "9:41", font=font(int(style.font_px * 0.55)), fill=style.meta)
    # keyboard-ish input bar at the bottom
    d.rounded_rectangle((int(w * 0.12), h - 170, int(w * 0.88), h - 90), 40, outline=style.meta, width=3)
    d.text((int(w * 0.16), h - 155), "Text Message" if style.name.startswith("ios") else "Message", font=meta_f, fill=style.meta)
    return img


def compress_forward(img: Image.Image) -> Image.Image:
    """Screenshot forwarded through a chat app: half resolution, heavy JPEG."""
    small = img.resize((img.width // 2, img.height // 2), Image.BILINEAR)
    buf = io.BytesIO()
    small.save(buf, "JPEG", quality=45)
    return Image.open(io.BytesIO(buf.getvalue())).convert("RGB")


def photo_of_screen(img: Image.Image, seed: int) -> Image.Image:
    """A phone photo of another screen: perspective tilt, blur, glare, noise, JPEG."""
    rnd = random.Random(seed)
    w, h = img.size
    dx, dy = int(w * 0.06), int(h * 0.03)
    quad = (rnd.randint(0, dx), rnd.randint(0, dy), rnd.randint(0, dx), h - rnd.randint(0, dy),
            w - rnd.randint(0, dx), h - rnd.randint(0, dy), w - rnd.randint(0, dx), rnd.randint(0, dy))
    warped = img.transform((w, h), Image.QUAD, quad, Image.BICUBIC, fillcolor=(40, 40, 40))
    warped = warped.filter(ImageFilter.GaussianBlur(1.6))
    glare = Image.new("L", (w, h), 0)
    ImageDraw.Draw(glare).ellipse((int(w * 0.5), -int(h * 0.1), int(w * 1.3), int(h * 0.5)), fill=70)
    warped = Image.composite(Image.new("RGB", (w, h), (255, 255, 255)), warped, glare.filter(ImageFilter.GaussianBlur(120)))
    px = warped.load()
    for _ in range(w * h // 12):
        x, y = rnd.randrange(w), rnd.randrange(h)
        r, g, b = px[x, y]
        n = rnd.randint(-28, 28)
        px[x, y] = (max(0, min(255, r + n)), max(0, min(255, g + n)), max(0, min(255, b + n)))
    small = warped.resize((int(w * 0.75), int(h * 0.75)), Image.BILINEAR)
    buf = io.BytesIO()
    small.save(buf, "JPEG", quality=60)
    return Image.open(io.BytesIO(buf.getvalue())).convert("RGB")


VARIANTS = ["ios_light", "ios_dark", "android_dark", "whatsapp_light", "whatsapp_dark", "gmail_dark", "forwarded_jpeg", "photo_of_screen"]

# A spread of scam and legit messages from the dataset (dev + holdout), incl. long URLs and amounts.
SAMPLE_IDS = ["d-s01", "d-s02", "d-s04", "d-s07", "d-s11", "d-s16", "d-a03", "h-s03", "h-s08",
              "d-l02", "d-l03", "d-l04", "d-l08", "h-l02"]


def main() -> int:
    OUT.mkdir(parents=True, exist_ok=True)
    rows = {json.loads(l)["id"]: json.loads(l) for l in (ROOT / "eval" / "dataset.jsonl").read_text(encoding="utf-8").splitlines() if l.strip()}
    manifest = []
    for i, rid in enumerate(SAMPLE_IDS):
        row = rows[rid]
        for j, variant in enumerate(VARIANTS):
            base_style = STYLES.get(variant, STYLES["ios_light" if variant == "photo_of_screen" else "whatsapp_light"])
            img = render(row["text"], row.get("sender_id"), base_style, seed=i * 31 + j)
            if variant == "forwarded_jpeg":
                img = compress_forward(img)
            elif variant == "photo_of_screen":
                img = photo_of_screen(img, seed=i * 7 + j)
            ext = "jpg" if variant in {"forwarded_jpeg", "photo_of_screen"} else "png"
            name = f"{rid}__{variant}.{ext}"
            if ext == "png":
                img.save(OUT / name, "PNG", optimize=True)
            else:
                img.save(OUT / name, "JPEG", quality=85)
            manifest.append({"file": name, "id": rid, "variant": variant, "label": row["label"], "channel": row["channel"],
                             "text": row["text"], "screen_text": screen_text(row["text"])})
    (OUT / "manifest.json").write_text(json.dumps(manifest, indent=1, ensure_ascii=False), encoding="utf-8")
    print(f"wrote {len(manifest)} screenshots to {OUT}")
    return 0




def write_demo_images() -> None:
    """Realistic demo screenshots used by the Streamlit Demo tab and the website examples."""
    from eval.screenshots import DEMO_SCREENSHOTS

    styles = {"fake_bank_otp.png": "ios_dark", "delivery_fee_scam.png": "android_dark", "genuine_bank_alert.png": "ios_light"}
    for name, (sender, text) in DEMO_SCREENSHOTS.items():
        img = render(text, sender, STYLES[styles[name]], seed=7)
        for folder in (ROOT / "assets" / "demo", ROOT / "public" / "demo"):
            folder.mkdir(parents=True, exist_ok=True)
            img.save(folder / name, "PNG", optimize=True)
        print("demo", name, styles[name])


if __name__ == "__main__":
    if "--demo" in sys.argv:
        write_demo_images()
    else:
        sys.exit(main())

"""public/ocr-core.js (the website's OCR preprocessing) exercised through Node."""

from __future__ import annotations

import json
import shutil
import subprocess

import pytest

from scamshield.config import REPO_ROOT

pytestmark = pytest.mark.skipif(shutil.which("node") is None, reason="node not installed")

SCRIPT = r"""
const core = require(process.argv[2]);
function img(w, h, bg, draw) {
  const d = new Uint8ClampedArray(w * h * 4);
  for (let i = 0; i < w * h; i++) { d[i*4] = d[i*4+1] = d[i*4+2] = bg; d[i*4+3] = 255; }
  draw && draw(d, w);
  return { data: d, width: w, height: h };
}
const px = (d, w, x, y, v) => { const i = (y * w + x) * 4; d[i] = d[i+1] = d[i+2] = v; };
const res = {};
// dark mode: black background with a white block of "text" -> becomes dark text on white
const dark = core.prepare(img(700, 400, 0, (d, w) => { for (let y = 180; y < 200; y++) for (let x = 100; x < 110; x++) px(d, w, x, y, 255); }), { targetWidth: 700 });
res.darkBg = dark.data[0]; res.darkText = dark.data[(190 * 700 + 105) * 4];
// underline: a long 3px-thick line under some glyph blocks is erased, the glyphs stay
const ul = core.prepare(img(700, 400, 255, (d, w) => {
  for (let y = 200; y < 203; y++) for (let x = 50; x < 650; x++) px(d, w, x, y, 20);
  for (let y = 160; y < 198; y++) for (let x = 60; x < 72; x++) px(d, w, x, y, 20);
}), { targetWidth: 700 });
res.underline = ul.data[(201 * 700 + 300) * 4]; res.glyph = ul.data[(180 * 700 + 65) * 4];
// scaling: narrow images are upscaled to the target width
res.width = core.prepare(img(350, 200, 255), {}).width;
console.log(JSON.stringify(res));
"""


def test_ocr_core_normalises_dark_mode_removes_underlines_and_scales(tmp_path):
    script = tmp_path / "t.js"
    script.write_text(SCRIPT, encoding="utf-8")
    out = subprocess.run(["node", str(script), str(REPO_ROOT / "public" / "ocr-core.js")], capture_output=True, text=True, timeout=60)
    assert out.returncode == 0, out.stderr
    res = json.loads(out.stdout)
    assert res["darkBg"] > 200 and res["darkText"] < 60  # inverted: dark text on light
    assert res["underline"] == 255 and res["glyph"] < 60  # underline erased, glyph kept
    assert res["width"] == 1400

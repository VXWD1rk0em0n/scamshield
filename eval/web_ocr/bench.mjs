// Runs the website's OCR path (Tesseract.js 5.1.1 + public/ocr-core.js preprocessing) over
// eval/screens and saves the recognised lines per config for eval/web_ocr/score.py.
//
//   cd eval/web_ocr && npm install && node bench.mjs [config ...]
import fs from "node:fs";
import path from "node:path";
import { createRequire } from "node:module";
import { fileURLToPath } from "node:url";
import { createWorker } from "tesseract.js";
import { PNG } from "pngjs";
import jpeg from "jpeg-js";

const require = createRequire(import.meta.url);
const HERE = path.dirname(fileURLToPath(import.meta.url));
const ROOT = path.resolve(HERE, "..", "..");
const core = require(path.join(ROOT, "public", "ocr-core.js"));
const SCREENS = path.join(ROOT, "eval", "screens");
const OUT = path.join(HERE, "out");

export const CONFIGS = {
  baseline: null, // what the site did before: original image, Tesseract's own binarisation
  gray: { method: "gray" },
  clean: { method: "clean" },
  clean_nolines: { method: "clean", removeUnderlines: false },
  clean_thick: { method: "clean", maxThickFrac: 0.007 },
  adaptive: { method: "adaptive" },
  adaptive_t18: { method: "adaptive", threshold: 18 },
  adaptive_t36: { method: "adaptive", threshold: 36 },
  adaptive_w06: { method: "adaptive", windowFrac: 0.06 },
};

function decode(file) {
  const buf = fs.readFileSync(file);
  if (file.endsWith(".png")) {
    const png = PNG.sync.read(buf);
    return { data: png.data, width: png.width, height: png.height, buf };
  }
  const j = jpeg.decode(buf, { useTArray: true, formatAsRGBA: true });
  return { data: j.data, width: j.width, height: j.height, buf };
}

function encode(img) {
  const png = new PNG({ width: img.width, height: img.height });
  png.data = Buffer.from(img.data.buffer, img.data.byteOffset, img.data.length);
  return PNG.sync.write(png);
}

async function main() {
  const wanted = process.argv.slice(2).length ? process.argv.slice(2) : Object.keys(CONFIGS);
  const manifest = JSON.parse(fs.readFileSync(path.join(SCREENS, "manifest.json"), "utf8"));
  fs.mkdirSync(OUT, { recursive: true });
  const tasks = [];
  for (const cfg of wanted) for (const item of manifest) tasks.push({ cfg, item });
  const results = Object.fromEntries(wanted.map((c) => [c, []]));
  const POOL = 4;
  const workers = await Promise.all(Array.from({ length: POOL }, () => createWorker("eng", 1)));
  let next = 0, done = 0;
  const t0 = Date.now();
  await Promise.all(workers.map(async (worker) => {
    while (next < tasks.length) {
      const { cfg, item } = tasks[next++];
      const img = decode(path.join(SCREENS, item.file));
      const started = Date.now();
      const input = CONFIGS[cfg] ? encode(core.prepare(img, CONFIGS[cfg])) : img.buf;
      const { data } = await worker.recognize(input);
      const lines = (data.lines || [])
        .map((l) => ({ text: (l.text || "").trim(), confidence: l.confidence, bbox: [l.bbox.x0, l.bbox.y0, l.bbox.x1, l.bbox.y1] }))
        .filter((l) => l.text);
      results[cfg].push({ file: item.file, id: item.id, variant: item.variant, ms: Date.now() - started, lines });
      if (++done % 28 === 0) console.log(`${done}/${tasks.length} (${((Date.now() - t0) / 1000).toFixed(0)}s)`);
    }
  }));
  await Promise.all(workers.map((w) => w.terminate()));
  for (const cfg of wanted) fs.writeFileSync(path.join(OUT, `${cfg}.json`), JSON.stringify(results[cfg]));
  console.log("done", wanted.join(", "));
}

main().catch((e) => { console.error(e); process.exit(1); });

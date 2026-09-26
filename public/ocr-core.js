/* ScamShield OCR preprocessing - pure functions on raw pixels, shared by the website
 * (browser) and the OCR benchmark (Node) so both run exactly the same code.
 *
 * Real screenshots defeat Tesseract's global binarisation: dark mode (light text on black),
 * coloured bubbles (white on blue, dark on grey) and wallpapers all in one image. The
 * "adaptive" method classifies a pixel as ink when it differs strongly from its local
 * neighbourhood in EITHER direction, so every text polarity comes out as black-on-white.
 */
(function (root, factory) {
  if (typeof module === "object" && module.exports) module.exports = factory();
  else root.ScamShieldOCRCore = factory();
})(typeof self !== "undefined" ? self : this, function () {
  "use strict";

  const DEFAULTS = {
    method: "clean", // "none" | "gray" | "clean" | "adaptive" (experimental, not recommended)
    targetWidth: 1400, // text in phone screenshots is ~4% of the width; this puts caps at ~35-45 px
    maxHeight: 6000,
    windowFrac: 0.035, // local-mean window as a fraction of the (scaled) width
    threshold: 26, // adaptive only: |pixel - local mean| above this (0-255) counts as ink
    polarityWindowFrac: 0.12, // clean: window deciding whether a region is dark-mode
    removeUnderlines: true, // clean: erase long thin horizontal lines (link underlines, bubble edges)
    minRunFrac: 0.05, // ...runs at least this fraction of the width
    maxThickFrac: 0.007, // ...and at most this thick (benchmarked in eval/web_ocr)
  };

  function luminance(rgba, n) {
    const g = new Uint8ClampedArray(n);
    for (let i = 0, j = 0; i < n; i++, j += 4) g[i] = (rgba[j] * 299 + rgba[j + 1] * 587 + rgba[j + 2] * 114) / 1000;
    return g;
  }

  function resizeGray(src, w, h, nw, nh) {
    if (nw === w && nh === h) return src;
    const out = new Uint8ClampedArray(nw * nh);
    const sx = w / nw, sy = h / nh;
    for (let y = 0; y < nh; y++) {
      const fy = Math.min(h - 1, Math.max(0, (y + 0.5) * sy - 0.5));
      const y0 = Math.floor(fy), y1 = Math.min(h - 1, y0 + 1), wy = fy - y0;
      for (let x = 0; x < nw; x++) {
        const fx = Math.min(w - 1, Math.max(0, (x + 0.5) * sx - 0.5));
        const x0 = Math.floor(fx), x1 = Math.min(w - 1, x0 + 1), wx = fx - x0;
        const a = src[y0 * w + x0], b = src[y0 * w + x1], c = src[y1 * w + x0], d = src[y1 * w + x1];
        out[y * nw + x] = (a * (1 - wx) + b * wx) * (1 - wy) + (c * (1 - wx) + d * wx) * wy;
      }
    }
    return out;
  }

  function adaptive(gray, w, h, win, thr) {
    // integral image of luminance -> O(1) local mean per pixel
    const W = w + 1;
    const integral = new Float64Array(W * (h + 1));
    for (let y = 1; y <= h; y++) {
      let row = 0;
      for (let x = 1; x <= w; x++) {
        row += gray[(y - 1) * w + (x - 1)];
        integral[y * W + x] = integral[(y - 1) * W + x] + row;
      }
    }
    const r = Math.max(4, win >> 1);
    const out = new Uint8ClampedArray(w * h);
    for (let y = 0; y < h; y++) {
      const ya = Math.max(0, y - r), yb = Math.min(h, y + r + 1);
      for (let x = 0; x < w; x++) {
        const xa = Math.max(0, x - r), xb = Math.min(w, x + r + 1);
        const sum = integral[yb * W + xb] - integral[ya * W + xb] - integral[yb * W + xa] + integral[ya * W + xa];
        const mean = sum / ((yb - ya) * (xb - xa));
        out[y * w + x] = Math.abs(gray[y * w + x] - mean) > thr ? 0 : 255;
      }
    }
    return out;
  }

  function integralOf(gray, w, h) {
    const W = w + 1;
    const integral = new Float64Array(W * (h + 1));
    for (let y = 1; y <= h; y++) {
      let row = 0;
      for (let x = 1; x <= w; x++) {
        row += gray[(y - 1) * w + (x - 1)];
        integral[y * W + x] = integral[(y - 1) * W + x] + row;
      }
    }
    return integral;
  }

  function localPolarity(gray, w, h, win) {
    // Invert regions whose surroundings are dark (dark mode, white-on-blue bubbles) so text is
    // dark-on-light everywhere. The window is large (several text lines) so text itself never
    // flips its own region.
    const integral = integralOf(gray, w, h);
    const W = w + 1, r = Math.max(8, win >> 1);
    const out = new Uint8ClampedArray(w * h);
    for (let y = 0; y < h; y++) {
      const ya = Math.max(0, y - r), yb = Math.min(h, y + r + 1);
      for (let x = 0; x < w; x++) {
        const xa = Math.max(0, x - r), xb = Math.min(w, x + r + 1);
        const mean = (integral[yb * W + xb] - integral[ya * W + xb] - integral[yb * W + xa] + integral[ya * W + xa]) / ((yb - ya) * (xb - xa));
        out[y * w + x] = mean < 118 ? 255 - gray[y * w + x] : gray[y * w + x];
      }
    }
    return out;
  }

  function otsu(gray, n) {
    const hist = new Float64Array(256);
    for (let i = 0; i < n; i++) hist[gray[i]]++;
    let sum = 0;
    for (let t = 0; t < 256; t++) sum += t * hist[t];
    let sumB = 0, wB = 0, best = 0, thr = 128;
    for (let t = 0; t < 256; t++) {
      wB += hist[t];
      if (!wB) continue;
      const wF = n - wB;
      if (!wF) break;
      sumB += t * hist[t];
      const mB = sumB / wB, mF = (sum - sumB) / wF;
      const between = wB * wF * (mB - mF) * (mB - mF);
      if (between > best) { best = between; thr = t; }
    }
    return thr;
  }

  function removeLines(gray, w, h, minRun, maxThick) {
    // Underlines under links (and bubble edges) make Tesseract classify a text line as a graphic
    // and skip it. Whiten long, thin horizontal runs of ink; letters are never that long and flat.
    const thr = otsu(gray, w * h);
    const ink = (x, y) => gray[y * w + x] <= thr;
    const erase = new Uint8Array(w * h);
    for (let y = 0; y < h; y++) {
      let x = 0;
      while (x < w) {
        if (!ink(x, y)) { x++; continue; }
        const start = x;
        while (x < w && ink(x, y)) x++;
        if (x - start < minRun) continue;
        for (let i = start; i < x; i++) {
          let up = y, down = y;
          while (up > 0 && y - up < maxThick + 1 && ink(i, up - 1)) up--;
          while (down < h - 1 && down - y < maxThick + 1 && ink(i, down + 1)) down++;
          if (down - up + 1 <= maxThick) erase[y * w + i] = 1;
        }
      }
    }
    for (let i = 0; i < w * h; i++) if (erase[i]) gray[i] = 255;
    return gray;
  }

  function normalizeGray(gray, n) {
    // light-on-dark screenshots -> invert, so text is always dark on light
    let sum = 0;
    for (let i = 0; i < n; i++) sum += gray[i];
    if (sum / n < 110) for (let i = 0; i < n; i++) gray[i] = 255 - gray[i];
    return gray;
  }

  /**
   * @param {{data: Uint8ClampedArray|Uint8Array, width: number, height: number}} img RGBA pixels
   * @returns {{data: Uint8ClampedArray, width: number, height: number, scale: number}} RGBA pixels ready for OCR
   */
  function prepare(img, options) {
    const o = Object.assign({}, DEFAULTS, options || {});
    const { width: w, height: h } = img;
    let scale = o.targetWidth / w;
    if (h * scale > o.maxHeight) scale = o.maxHeight / h;
    const nw = Math.max(1, Math.round(w * scale)), nh = Math.max(1, Math.round(h * scale));
    let gray = resizeGray(luminance(img.data, w * h), w, h, nw, nh);
    if (o.method === "adaptive") gray = adaptive(gray, nw, nh, Math.round(nw * o.windowFrac) | 1, o.threshold);
    else if (o.method === "gray") gray = normalizeGray(new Uint8ClampedArray(gray), nw * nh);
    else if (o.method === "clean") {
      gray = localPolarity(gray, nw, nh, Math.round(nw * o.polarityWindowFrac) | 1);
      if (o.removeUnderlines) gray = removeLines(gray, nw, nh, Math.round(nw * o.minRunFrac), Math.max(2, Math.round(nw * o.maxThickFrac)));
    }
    const rgba = new Uint8ClampedArray(nw * nh * 4);
    for (let i = 0, j = 0; i < nw * nh; i++, j += 4) {
      rgba[j] = rgba[j + 1] = rgba[j + 2] = gray[i];
      rgba[j + 3] = 255;
    }
    return { data: rgba, width: nw, height: nh, scale };
  }

  return { DEFAULTS, prepare };
});

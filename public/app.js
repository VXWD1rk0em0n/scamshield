"use strict";
/* ScamShield web front end.
 * Security: every string that comes from the message, the OCR, or the API is inserted with
 * textContent - never innerHTML - so a scam message can't inject markup into this page.
 * Privacy: screenshots are read in this browser (Tesseract.js); only the recognised text lines
 * are sent to /api/analyze. The trusted-sender list lives in localStorage only.
 */

const TESSERACT_SRC = "https://cdn.jsdelivr.net/npm/tesseract.js@5.1.1/dist/tesseract.min.js";
const TESSERACT_SRI = "sha384-GJqSu7vueQ9qN0E9yLPb3Wtpd7OrgK8KmYzC8T1IysG1bcvxvIO4qtYR/D3A991F";
const MAX_IMAGE_BYTES = 8 * 1024 * 1024;
const MAX_OCR_SIDE = 2000;
const TRUST_KEY = "scamshield.trusted.v1";

const CATEGORIES = {
  request: "Asks for money / codes",
  impersonation: "Impersonation",
  obfuscation: "Hidden tricks / AI manipulation",
  link: "Risky link",
  pressure: "Pressure / secrecy",
  lure: "Lure",
  benign: "Reassuring sign",
};
const TIER_ICON = { LOW: "✓", MEDIUM: "!", HIGH: "▲", CRITICAL: "⛔", NONE: "?" };
const MODE_LABEL = { hybrid: "Rules + AI", rules_only: "Rules only", rules_only_fallback: "Rules only (AI unavailable)" };

const $ = (id) => document.getElementById(id);
const ui = {
  message: $("message"), channel: $("channel"), sender: $("sender"), claimed: $("claimed"), known: $("known"),
  analyze: $("analyze"), status: $("status"), result: $("result"), examples: $("examples"),
  tabText: $("tab-text"), tabImage: $("tab-image"), imagePanel: $("image-panel"), fileInput: $("file-input"),
  cameraInput: $("camera-input"), drop: $("drop"), progress: $("ocr-progress"), preview: $("preview"),
  pill: $("mode-pill"), trustedCard: $("trusted-card"), trustedList: $("trusted-list"),
};

let lastOcr = null; // OCR lines for the current text; cleared as soon as the user edits it
let previewUrl = null;

/* ------------------------------------------------------------------ tiny DOM helper */
function el(tag, props = {}, ...children) {
  const node = document.createElement(tag);
  for (const [key, value] of Object.entries(props)) {
    if (value === undefined || value === null || value === false) continue;
    if (key === "text") node.textContent = value;
    else if (key === "className") node.className = value;
    else if (key === "onClick") node.addEventListener("click", value);
    else if (key === "style") Object.assign(node.style, value); // CSSOM - allowed under the strict CSP
    else node.setAttribute(key, value === true ? "" : value);
  }
  for (const child of children.flat()) {
    if (child === null || child === undefined || child === false) continue;
    node.append(child instanceof Node ? child : document.createTextNode(String(child)));
  }
  return node;
}

function setStatus(text, isError = false) {
  ui.status.textContent = text;
  ui.status.classList.toggle("error", isError);
}

/* ------------------------------------------------------------------ trusted senders (browser only) */
const normSender = (s) => (s || "").replace(/\s+/g, "").toLowerCase();
function loadTrusted() {
  try { return JSON.parse(localStorage.getItem(TRUST_KEY)) || []; } catch { return []; }
}
function saveTrusted(list) {
  try { localStorage.setItem(TRUST_KEY, JSON.stringify(list)); } catch { /* private mode: trust lasts this page only */ }
  renderTrusted();
}
const isTrusted = (sender) => !!normSender(sender) && loadTrusted().some((t) => t.key === normSender(sender));
function renderTrusted() {
  const list = loadTrusted();
  ui.trustedCard.hidden = list.length === 0;
  ui.trustedList.replaceChildren(
    ...list.map((t) =>
      el("li", {},
        el("span", { text: t.label }),
        el("button", { className: "btn", type: "button", text: "Remove",
          onClick: () => saveTrusted(loadTrusted().filter((x) => x.key !== t.key)) })))
  );
}

/* ------------------------------------------------------------------ input mode */
function setMode(mode) {
  const image = mode === "image";
  ui.tabText.setAttribute("aria-selected", String(!image));
  ui.tabImage.setAttribute("aria-selected", String(image));
  ui.imagePanel.hidden = !image;
  $("text-panel").hidden = image;
  ui.tabText.tabIndex = image ? -1 : 0;
  ui.tabImage.tabIndex = image ? 0 : -1;
  if (image) loadTesseract().catch(() => {}); // warm up the reader
}
ui.tabText.addEventListener("click", () => setMode("text"));
ui.tabImage.addEventListener("click", () => setMode("image"));
ui.message.addEventListener("input", () => { lastOcr = null; });
[ui.tabText, ui.tabImage].forEach((tab) => tab.addEventListener("keydown", (e) => {
  if (["ArrowLeft", "ArrowRight", "Home", "End"].includes(e.key)) {
    e.preventDefault();
    const image = e.key === "End" || (e.key !== "Home" && tab === ui.tabText);
    setMode(image ? "image" : "text");
    (image ? ui.tabImage : ui.tabText).focus();
  }
}));
setMode("text");
ui.message.addEventListener("keydown", (e) => { if (e.key === "Enter" && (e.ctrlKey || e.metaKey)) analyze(); });
ui.analyze.addEventListener("click", () => analyze());

/* ------------------------------------------------------------------ OCR in the browser */
let tesseractPromise = null;
let workerPromise = null;
let progressHandler = null;

function loadTesseract() {
  if (window.Tesseract) return Promise.resolve();
  if (!tesseractPromise) {
    tesseractPromise = new Promise((resolve, reject) => {
      const s = document.createElement("script");
      s.src = TESSERACT_SRC;
      s.integrity = TESSERACT_SRI; // refuse a tampered CDN file
      s.crossOrigin = "anonymous";
      s.onload = resolve;
      s.onerror = () => { tesseractPromise = null; reject(new Error("Couldn't load the text reader. Check your connection.")); };
      document.head.append(s);
    });
  }
  return tesseractPromise;
}

async function getWorker() {
  await loadTesseract();
  if (!workerPromise) {
    workerPromise = window.Tesseract.createWorker("eng", 1, {
      logger: (m) => progressHandler && progressHandler(m),
    }).catch((err) => { workerPromise = null; throw err; });
  }
  return workerPromise;
}

async function downscale(blob) {
  // Large phone photos are slow to OCR in the browser; cap the long side. Re-drawing also drops EXIF.
  const bitmap = await createImageBitmap(blob);
  const scale = Math.min(1, MAX_OCR_SIDE / Math.max(bitmap.width, bitmap.height));
  if (scale === 1) { bitmap.close(); return blob; }
  const canvas = document.createElement("canvas");
  canvas.width = Math.round(bitmap.width * scale);
  canvas.height = Math.round(bitmap.height * scale);
  canvas.getContext("2d").drawImage(bitmap, 0, 0, canvas.width, canvas.height);
  bitmap.close();
  return new Promise((resolve) => canvas.toBlob((b) => resolve(b || blob), "image/png"));
}

function showProgress(fraction) {
  ui.progress.hidden = fraction === null;
  if (fraction !== null) ui.progress.firstElementChild.style.width = `${Math.round(fraction * 100)}%`;
}

async function readImage(blob) {
  if (!/^image\/(png|jpeg|webp)$/.test(blob.type) && !/^image\//.test(blob.type)) {
    setStatus("That file isn't an image. Use a PNG, JPG or WEBP screenshot.", true);
    return;
  }
  if (blob.size > MAX_IMAGE_BYTES) {
    setStatus("That image is over 8 MB. Try a screenshot instead of a full photo.", true);
    return;
  }
  if (previewUrl) URL.revokeObjectURL(previewUrl);
  previewUrl = URL.createObjectURL(blob);
  ui.preview.src = previewUrl;
  ui.preview.hidden = false;
  ui.analyze.disabled = true;
  try {
    setStatus("Loading the text reader (first time only)...");
    showProgress(0);
    progressHandler = (m) => {
      if (m.status === "recognizing text") { setStatus("Reading the text on your device..."); showProgress(m.progress); }
    };
    const worker = await getWorker();
    const { data } = await worker.recognize(await downscale(blob));
    const lines = (data.lines || [])
      .map((l) => ({ text: (l.text || "").trim(), confidence: l.confidence, bbox: [l.bbox.x0, l.bbox.y0, l.bbox.x1, l.bbox.y1] }))
      .filter((l) => l.text);
    if (!lines.length) {
      setStatus("No readable text found in that image. Try a sharper screenshot, or paste the text.", true);
      return;
    }
    lastOcr = { lines: lines.slice(0, 400) };
    ui.message.value = lines.map((l) => l.text).join("\n");
    setMode("text");
    await analyze();
  } catch (err) {
    setStatus(err && err.message ? err.message : "Couldn't read that image.", true);
  } finally {
    progressHandler = null;
    showProgress(null);
    ui.analyze.disabled = false;
  }
}

function onFile(input) {
  const file = input.files && input.files[0];
  input.value = ""; // allow picking the same file again
  if (file) readImage(file);
}
document.querySelectorAll('label[role="button"]').forEach((label) => label.addEventListener("keydown", (e) => {
  if (e.key === "Enter" || e.key === " ") { e.preventDefault(); $(label.htmlFor).click(); }
}));
ui.fileInput.addEventListener("change", () => onFile(ui.fileInput));
ui.cameraInput.addEventListener("change", () => onFile(ui.cameraInput));
["dragenter", "dragover"].forEach((t) => ui.drop.addEventListener(t, (e) => { e.preventDefault(); ui.drop.classList.add("over"); }));
["dragleave", "drop"].forEach((t) => ui.drop.addEventListener(t, (e) => { e.preventDefault(); ui.drop.classList.remove("over"); }));
ui.drop.addEventListener("drop", (e) => { const f = e.dataTransfer.files[0]; if (f) readImage(f); });

/* ------------------------------------------------------------------ API */
async function analyze() {
  const sender = ui.sender.value.trim();
  const body = {
    channel: ui.channel.value,
    sender_id: sender || null,
    claimed_sender: ui.claimed.value.trim() || null,
    known_contact: ui.known.checked,
    trusted_sender: isTrusted(sender),
  };
  if (lastOcr) body.ocr = lastOcr; else body.text = ui.message.value;
  ui.analyze.disabled = true;
  setStatus("Checking...");
  try {
    const res = await fetch("/api/analyze", {
      method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify(body),
    });
    const data = await res.json().catch(() => ({}));
    if (!res.ok) {
      setStatus(data.error ? `Couldn't check it: ${data.error}` : `Couldn't check it (error ${res.status}).`, true);
      return;
    }
    if (lastOcr) {
      // show the cleaned-up text the server assembled, so the user can correct misreads and re-check
      ui.message.value = (data.segments || []).map((s) => s.text).join("");
      if (data.source && data.source.sender_hint && !ui.sender.value) ui.sender.value = data.source.sender_hint;
    }
    setStatus("");
    render(data, body);
    ui.result.focus({ preventScroll: true });
    if (window.matchMedia("(max-width: 700px)").matches) ui.result.scrollIntoView({ behavior: window.matchMedia("(prefers-reduced-motion: reduce)").matches ? "instant" : "smooth", block: "start" });
  } catch {
    setStatus("Network problem - please try again.", true);
  } finally {
    ui.analyze.disabled = false;
  }
}

/* ------------------------------------------------------------------ rendering */
function badge(tier) {
  const key = tier || "NONE";
  return el("span", { className: `badge ${key}` }, el("span", { "aria-hidden": "true", text: TIER_ICON[key] }), tier || "NOT ANALYSED");
}

function meter(score, tier, tiers) {
  const bands = [[0, tiers.medium, "LOW", "--good"], [tiers.medium, tiers.high, "MEDIUM", "--warning"],
    [tiers.high, tiers.critical, "HIGH", "--serious"], [tiers.critical, 100, "CRITICAL", "--critical"]];
  const track = el("div", { className: "meter", role: "meter", "aria-valuemin": "0", "aria-valuemax": "100",
    "aria-valuenow": String(score), "aria-label": `Risk score ${score} of 100, ${tier}` });
  for (const [a, b, name, token] of bands) {
    track.append(el("div", { className: `band${name === tier ? " on" : ""}`, title: `${name} ${a}-${b}`,
      style: { left: `calc(${a}% + 1px)`, width: `calc(${b - a}% - 2px)`, background: `var(${token})` } }));
  }
  track.append(el("div", { className: "marker", style: { left: `${score}%` } }));
  const ticks = el("div", { className: "ticks", "aria-hidden": "true" },
    [0, tiers.medium, tiers.high, tiers.critical, 100].map((v) => el("span", { text: String(v), style: { left: `${v}%` } })));
  return [track, ticks];
}

function highlighted(segments) {
  const box = el("div", { className: "msg" });
  for (const seg of segments) {
    if (seg.hidden_char) {
      box.append(el("span", { className: "zw", title: "Hidden zero-width character", text: "◆" }));
    } else if (seg.category) {
      const color = `var(--c-${seg.category})`;
      box.append(el("mark", { className: "hl", title: `${CATEGORIES[seg.category] || seg.category}: ${seg.labels.join("; ")}`,
        style: { background: `color-mix(in srgb, ${color} 24%, transparent)`, borderBottomColor: color }, text: seg.text }));
    } else {
      box.append(seg.text);
    }
  }
  return box;
}

function legend(segments) {
  const present = [...new Set(segments.filter((s) => s.category).map((s) => s.category))];
  const hidden = segments.some((s) => s.hidden_char);
  if (!present.length && !hidden) return null;
  return el("div", { className: "legend" },
    present.map((c) => el("span", {}, el("i", { style: { background: `color-mix(in srgb, var(--c-${c}) 40%, transparent)`, borderBottomColor: `var(--c-${c})` } }), CATEGORIES[c] || c)),
    hidden ? el("span", {}, el("span", { className: "zw", text: "◆" }), " hidden character") : null);
}

function factorsTable(factors) {
  const max = Math.max(1, ...factors.map((f) => Math.abs(f.points)));
  return el("div", { className: "table-scroll" }, el("table", { className: "factors" },
    el("thead", {}, el("tr", {}, el("th", { text: "Signal" }), el("th", { text: "Points" }), el("th", { text: "" }), el("th", { text: "Why" }))),
    el("tbody", {}, factors.map((f) => el("tr", {},
      el("td", { text: f.name.replaceAll("_", " ").toLowerCase() }),
      el("td", { className: "pts", text: `${f.points > 0 ? "+" : ""}${f.points}` }),
      el("td", { className: "barcell" }, el("div", { className: `bar${f.points < 0 ? " neg" : ""}`, style: { width: `${Math.round((Math.abs(f.points) / max) * 100)}%` } })),
      el("td", { className: "why", text: f.detail }))))));
}

function linksBlock(data, state, rerender) {
  if (!data.links.length) return null;
  const iv = data.intervention;
  const unlocked = !iv.links_disabled || state.appealed || state.revealed;
  const wrap = el("div", { className: "links" },
    el("h3", { text: `Links in this message (${data.links.length})` }),
    el("p", { className: "hint", text: "ScamShield never opens links. Shown as plain text - not clickable." }));
  if (unlocked) {
    data.links.forEach((l) => wrap.append(el("code", { text: l.raw })));
  } else if (iv.action === "INTERSTITIAL") {
    wrap.append(el("div", { className: "lock" }, `🔒 ${data.links.length} link(s) hidden.`,
      el("button", { className: "btn", type: "button", text: "I understand the risk - show them",
        onClick: () => { state.revealed = true; rerender(); } })));
  } else {
    wrap.append(el("div", { className: "lock", text: "⛔ Links blocked. If you're sure this message is genuine, use 'This is legitimate' in What to do next." }));
  }
  return wrap;
}

function feedbackBlock(data, request, state, rerender) {
  const sender = request.sender_id;
  const box = el("div", { className: "feedback" }, el("h3", { text: "Was this right?" }));
  box.append(el("div", { className: "row" },
    el("button", { className: "btn", type: "button", text: "This is legitimate", disabled: state.appealed,
      onClick: () => { state.appealed = true; rerender(); } }),
    el("button", { className: "btn", type: "button", text: "Reporting options", disabled: state.reported,
      onClick: () => { state.reported = true; rerender(); } })));
  if (state.appealed) {
    box.append(el("p", { className: "note", text: "OK - links are unlocked for this message. This public demo doesn't store appeals (in the full app they go to an analyst queue to fix the rules)." }));
    if (sender && !isTrusted(sender) && !state.trustDone) {
      if (!state.trustAsk) {
        box.append(el("button", { className: "btn", type: "button", text: "Also trust this sender...",
          onClick: () => { state.trustAsk = true; rerender(); } }));
      } else {
        const chk = el("input", { type: "checkbox", id: "trust-confirm" });
        const add = el("button", { className: "btn primary", type: "button", text: "Add to trusted senders", disabled: true,
          onClick: () => {
            saveTrusted([...loadTrusted().filter((t) => t.key !== normSender(sender)), { key: normSender(sender), label: sender }]);
            state.trustDone = true; state.trustAsk = false; rerender();
          } });
        chk.addEventListener("change", () => { add.disabled = !chk.checked; });
        box.append(el("div", { className: "confirm" },
          el("p", { text: `Second confirmation: trust ${sender}? Future messages from it get a lower risk score. Only do this for a sender you know personally. You can remove it any time.` }),
          el("div", { className: "check" }, chk, el("label", { for: "trust-confirm", text: "I know this sender personally" })),
          el("div", { className: "row", style: { marginTop: "10px" } }, add,
            el("button", { className: "btn", type: "button", text: "Cancel", onClick: () => { state.trustAsk = false; rerender(); } }))));
      }
    }
    if (state.trustDone) box.append(el("p", { className: "note", text: `${sender} is now on your trusted list (saved only in this browser).` }));
  }
  if (state.reported) {
    const a = (href, text) => el("a", { href, text, target: "_blank", rel: "noopener noreferrer" });
    box.append(el("div", { className: "note" },
      el("strong", { text: "Where to report it" }),
      el("ul", { className: "plain" },
        el("li", {}, "Forward scam texts to ", el("strong", { text: "7726" }), " (spells SPAM - US and UK carriers)."),
        el("li", {}, "US: ", a("https://reportfraud.ftc.gov/", "reportfraud.ftc.gov"), " · UK: ", a("https://www.ncsc.gov.uk/collection/phishing-scams/report-scam-email", "report to the NCSC")),
        el("li", { text: "If you shared a code, password or card number, or sent money: call your bank now using the number on your card." })),
      el("p", { className: "hint", text: "This public demo doesn't store reports." })));
  }
  return box;
}

function render(data, request) {
  const state = { appealed: false, revealed: false, reported: false, trustAsk: false, trustDone: false, tab: "signs", checked: new Set() };
  const draw = () => {
    const risk = data.risk;
    const iv = data.intervention;
    const nodes = [el("div", { className: "section-heading" }, el("h2", { text: "Your results" }), el("span", { className: "step-label", text: "02 / REVIEW" }))];
    if (!risk) {
      nodes.push(el("div", { className: "hero" }, badge(null)),
        el("div", { className: `banner ${iv.action}`, style: { marginTop: "12px" } }, el("strong", { text: iv.headline }), iv.message),
        el("p", { className: "hint", text: `Reason: ${data.quality_flags.join(", ").replaceAll("_", " ")}.` }));
      ui.result.replaceChildren(...nodes);
      ui.result.hidden = false;
      return;
    }
    const left = el("div", {},
      el("div", { className: "hero" }, el("span", { className: "num", text: String(risk.score) }), el("span", { className: "of", text: "/100 risk" }), badge(risk.tier)),
      ...meter(risk.score, risk.tier, data.tiers));
    const right = el("div", {},
      el("div", { className: `banner ${iv.action}` }, el("strong", { text: iv.headline }), iv.message),
      iv.review_note ? el("p", { className: "note", text: iv.review_note }) : null);
    nodes.push(el("div", { className: "result-head" }, left, right));
    const panels = {
      signs: el("div", { className: "result-panel", id: "panel-signs", role: "tabpanel", "aria-labelledby": "result-signs" }),
      steps: el("div", { className: "result-panel", id: "panel-steps", role: "tabpanel", "aria-labelledby": "result-steps" }),
    };
    const tabs = el("div", { className: "result-tabs", role: "tablist", "aria-label": "Result details" });
    const selectTab = (key) => {
      state.tab = key;
      Object.entries(panels).forEach(([k, panel]) => {
        panel.hidden = k !== key;
        const tab = tabs.querySelector(`#result-${k}`);
        tab.setAttribute("aria-selected", String(k === key));
        tab.tabIndex = k === key ? 0 : -1;
      });
    };
    [["signs", "Warning signs"], ["steps", "What to do next"]].forEach(([key, label]) => {
      const tab = el("button", { type: "button", role: "tab", id: `result-${key}`, "aria-controls": `panel-${key}`, text: label, onClick: () => selectTab(key) });
      tab.addEventListener("keydown", (e) => {
        if (["ArrowLeft", "ArrowRight", "Home", "End"].includes(e.key)) {
          e.preventDefault();
          const next = e.key === "Home" ? "signs" : e.key === "End" ? "steps" : key === "signs" ? "steps" : "signs";
          selectTab(next); tabs.querySelector(`#result-${next}`).focus();
        }
      });
      tabs.append(tab);
    });
    selectTab(state.tab);
    if (iv.tips.length) panels.signs.append(el("ul", { className: "plain" }, iv.tips.map((t) => el("li", { text: t }))));
    if (iv.checklist.length) {
      panels.steps.append(el("ul", { className: "checklist" }, iv.checklist.map((item, i) => {
        const check = el("input", { type: "checkbox", id: `chk-${i}`, checked: state.checked.has(i) });
        check.addEventListener("change", () => check.checked ? state.checked.add(i) : state.checked.delete(i));
        return el("li", {}, el("label", {}, check, item));
      })));
    } else panels.steps.append(el("p", { className: "hint", text: "If you are unsure, contact the sender through a number or app you already trust. A low score does not guarantee a message is safe." }));
    panels.steps.append(feedbackBlock(data, request, state, draw));
    nodes.push(tabs, panels.signs, panels.steps);
    if (data.source && data.source.source === "image") {
      const conf = data.source.ocr_confidence;
      nodes.push(el("p", { className: "note", text: `📷 Text read from your image on your device${conf != null ? ` (reading confidence ${Math.round(conf * 100)}%)` : ""}. If a word was misread, fix it in the message box and press Check again.` }));
    }
    panels.signs.append(el("h3", { text: "Words behind the result" }), ...[legend(data.segments), highlighted(data.segments)].filter(Boolean));
    const links = linksBlock(data, state, draw);
    if (links) panels.signs.append(links);



    const details = el("details", { className: "evidence", open: data.evidence.injection_detected },
      el("summary", { text: "View scoring & technical details" }),
      el("p", { className: "meta", text: `Confidence ${risk.confidence.toFixed(2)}${risk.degraded_confidence ? " (reduced)" : ""} · ${MODE_LABEL[risk.mode] || risk.mode}` }),
      el("p", { className: "explain", text: data.evidence.score_explanation }),
      risk.factors.length ? factorsTable(risk.factors) : null,
      data.evidence.injection_detected ? el("div", { className: "alert", text: "This message contains text aimed at tricking AI filters (prompt injection). That is itself a strong scam sign." }) : null,
      el("h3", { text: "Rules that fired" }),
      data.evidence.rule_explanations.length ? el("ul", { className: "plain" }, data.evidence.rule_explanations.map((r) => el("li", { text: r }))) : el("p", { text: "None." }));
    if (data.llm && data.llm.scam_type) {
      details.append(el("h3", { text: "AI classifier" }),
        el("p", { text: `${data.llm.scam_type.replaceAll("_", " ")} · scam probability ${data.llm.confidence.toFixed(2)} · tactics: ${data.llm.tactics.join(", ") || "none"}` }),
        el("ul", { className: "plain" }, data.llm.indicators.map((i) => el("li", { text: i }))),
        el("p", { className: "hint", text: data.llm.rationale }));
    } else if (data.llm) {
      details.append(el("p", { className: "hint", text: `AI classifier: ${data.llm.status}.` }));
    }
    details.append(el("p", { className: "hint", text: `Check ${data.case_id} · ${data.model_version} · ${data.latency_ms} ms` }));
    panels.signs.append(details);

    ui.result.replaceChildren(...nodes.filter(Boolean));
    ui.result.hidden = false;
  };
  draw();
}

/* ------------------------------------------------------------------ examples + boot */
async function boot() {
  renderTrusted();
  try {
    const res = await fetch("/api/analyze");
    const info = await res.json();
    ui.pill.textContent = "Messages aren’t stored · Links are never opened";
    const cases = info.demo_cases || [];
    const groups = new Map();
    const labels = { Normal: "Everyday messages", Attack: "Common scams", Negative: "Everyday messages", Screenshot: "Screenshot examples", Failure: "Advanced test cases", Adversarial: "Advanced test cases" };
    ui.examples.replaceChildren(el("option", { value: "", text: "Choose a sample message…" }));
    cases.forEach((c, i) => {
      const name = labels[c.group] || "More examples";
      if (!groups.has(name)) { const group = el("optgroup", { label: name }); groups.set(name, group); ui.examples.append(group); }
      groups.get(name).append(el("option", { value: String(i), text: c.title }));
    });
    ui.examples.addEventListener("change", async () => {
      if (ui.examples.value === "") return;
      ui.examples.disabled = true;
      try { await loadExample(cases[Number(ui.examples.value)]); }
      catch { setStatus("Couldn't load that example. Please try another.", true); }
      finally { ui.examples.disabled = false; }
    });
  } catch {
    ui.examples.replaceChildren(el("option", { text: "Examples unavailable right now" }));
    ui.examples.disabled = true;
  }
}

async function loadExample(c) {
  ui.channel.value = c.channel || "sms";
  ui.sender.value = c.sender || "";
  ui.claimed.value = c.claimed || "";
  ui.known.checked = false;
  if (c.image) {
    setMode("image");
    const res = await fetch(c.image);
    await readImage(await res.blob());
    return;
  }
  setMode("text");
  lastOcr = null;
  ui.message.value = c.text || "";
  await analyze();
}

boot();

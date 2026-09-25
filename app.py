"""ScamShield Streamlit UI.  Run:  streamlit run app.py"""

from __future__ import annotations

import html
import json
import os
from pathlib import Path

import pandas as pd
import streamlit as st
from dotenv import load_dotenv

ROOT = Path(__file__).resolve().parent
load_dotenv(ROOT / ".env")

from eval.run_eval import main as run_eval_main  # noqa: E402
from scamshield import feedback as fb  # noqa: E402
from scamshield.audit import AuditStore  # noqa: E402
from scamshield.demo_cases import DEMO_CASES  # noqa: E402
from scamshield.config import load_config  # noqa: E402
from scamshield.image_ingest import ClaudeVisionOCR, LocalOCR  # noqa: E402
from scamshield.evidence import CATEGORY_COLORS, CATEGORY_LABELS, render_highlighted_html, tint  # noqa: E402
from scamshield.llm_analyzer import LLMAnalyzer  # noqa: E402
from scamshield.logging_utils import configure_logging  # noqa: E402
from scamshield.models import Action, AnalysisResult, Channel, MessageInput, Tier  # noqa: E402
from scamshield.pipeline import Analyzer  # noqa: E402

st.set_page_config(page_title="ScamShield", page_icon="🛡️", layout="wide")
configure_logging()

# Status palette (fixed) - always paired with an icon and a text label.
TIER_STYLE = {
    "LOW": ("#0ca30c", "#ffffff", "✓"),
    "MEDIUM": ("#fab219", "#0b0b0b", "!"),
    "HIGH": ("#ec835a", "#0b0b0b", "▲"),
    "CRITICAL": ("#d03b3b", "#ffffff", "⛔"),
}
SEQ_BLUE = ["#cde2fb", "#9ec5f4", "#6da7ec", "#3987e5", "#256abf", "#184f95", "#0d366b"]

CSS = """
<style>
.ss-meter{max-width:520px;margin:4px 0 8px}
.ss-hero{display:flex;align-items:baseline;gap:10px;flex-wrap:wrap}
.ss-num{font-size:52px;font-weight:700;line-height:1}
.ss-of{opacity:.65;font-size:16px}
.ss-badge{display:inline-block;padding:3px 10px;border-radius:999px;font-weight:700;font-size:14px;letter-spacing:.02em}
.ss-track{position:relative;height:14px;margin:14px 0 4px}
.ss-band{position:absolute;top:3px;height:8px;border-radius:4px}
.ss-marker{position:absolute;top:-4px;width:6px;height:22px;margin-left:-3px;border-radius:3px;
  background:currentColor;box-shadow:0 0 0 2px var(--ss-surface, #fff)}
.ss-ticks{position:relative;height:16px;font-size:11px;opacity:.7}
.ss-ticks span{position:absolute;transform:translateX(-50%)}
.ss-msg{font-size:16px;line-height:1.7;padding:14px 16px;border-radius:8px;border:1px solid rgba(128,128,128,.35);
  white-space:normal;overflow-wrap:anywhere}
.ss-zw{color:#d03b3b;font-weight:700;padding:0 1px}
.ss-legend{display:flex;flex-wrap:wrap;gap:6px 14px;font-size:13px;margin:6px 0}
.ss-legend i{display:inline-block;width:12px;height:12px;border-radius:3px;margin-right:5px;vertical-align:-1px}
.ss-list{margin:0 0 0 18px;padding:0}
.ss-list li{margin:2px 0}
.ss-cm{border-collapse:separate;border-spacing:2px;font-size:14px}
.ss-cm th{font-weight:600;padding:4px 10px;text-align:center}
.ss-cm td{min-width:64px;padding:8px 10px;text-align:center;border-radius:4px;font-variant-numeric:tabular-nums}
</style>
"""


# ---------------------------------------------------------------- resources


@st.cache_resource
def get_config():
    return load_config()


@st.cache_resource
def get_store() -> AuditStore:
    return AuditStore(os.environ.get("SCAMSHIELD_DB") or ROOT / "data" / "scamshield.db")


@st.cache_resource
def get_llm() -> LLMAnalyzer:
    return LLMAnalyzer(get_config())


def _raise_timeout(system: str, user: str) -> str:
    raise TimeoutError("simulated LLM timeout")


def _garbage(system: str, user: str) -> str:
    return "Sure! This one is DEFINITELY a scam, trust me {not json"


def build_analyzer(simulate: str | None = None) -> Analyzer:
    cfg = get_config()
    if simulate == "timeout":
        return Analyzer(cfg, llm=LLMAnalyzer(cfg, completion_fn=_raise_timeout), store=get_store())
    if simulate == "garbage":
        return Analyzer(cfg, llm=LLMAnalyzer(cfg, completion_fn=_garbage), store=get_store())
    return Analyzer(cfg, llm=get_llm(), store=get_store(), use_llm=st.session_state.get("use_llm", True))


# ---------------------------------------------------------------- state helpers


def ui_state(case_id: str) -> dict:
    states = st.session_state.setdefault("ui", {})
    return states.setdefault(case_id, {"appealed": False, "revealed": False, "reported": False, "trust_req": None,
                                       "trusted": False, "msgs": []})


def run_analysis(payload, channel: str, sender: str | None, claimed: str | None, known: bool, simulate: str | None = None):
    analyzer = build_analyzer(simulate)
    result = analyzer.analyze(
        MessageInput(text=payload, channel=Channel(channel), sender_id=sender or None, claimed_sender=claimed or None,
                     known_contact=known),
        user_id=st.session_state.get("user_id", "demo-user"),
    )
    st.session_state["result"] = result
    st.session_state["raw_sender"] = sender or None
    st.session_state["simulated"] = simulate
    st.session_state["image_preview"] = None


def run_image_analysis(data: bytes, label: str):
    """Screenshot/photo -> OCR -> pipeline. The extracted text is put in the Message box so the
    user can fix OCR mistakes and re-run; the image itself only lives in this browser session."""
    engine = None
    llm = get_llm()
    if st.session_state.get("use_vision") and llm.available:
        engine = ClaudeVisionOCR(consent=True, model=llm.model)
    sender = st.session_state.in_sender.strip() or None
    result, extraction = build_analyzer().analyze_image(
        data,
        channel=Channel(st.session_state.in_channel),
        sender_id=sender,
        claimed_sender=st.session_state.in_claimed.strip() or None,
        known_contact=st.session_state.in_known,
        user_id=st.session_state.get("user_id", "demo-user"),
        engine=engine,
    )
    st.session_state.in_text = extraction.text
    if extraction.sender_hint and not sender:
        st.session_state.in_sender = extraction.sender_hint
    st.session_state["result"] = result
    st.session_state["raw_sender"] = sender or extraction.sender_hint
    st.session_state["simulated"] = None
    st.session_state["image_preview"] = data if extraction.width else None
    st.session_state["image_label"] = label


def on_image(key: str):
    uploaded = st.session_state.get(key)
    if uploaded is not None:
        run_image_analysis(uploaded.getvalue(), getattr(uploaded, "name", "camera photo"))


def on_submit():
    run_analysis(st.session_state.in_text, st.session_state.in_channel, st.session_state.in_sender.strip(),
                 st.session_state.in_claimed.strip(), st.session_state.in_known)


def load_case(case: dict):
    if "image" in case:
        st.session_state.in_channel = case["channel"]
        st.session_state.in_sender = ""
        st.session_state.in_claimed = ""
        st.session_state.in_known = False
        run_image_analysis((ROOT / "assets" / "demo" / case["image"]).read_bytes(), case["image"])
        return
    st.session_state.in_text = case.get("text", "") if "bytes" not in case else f"<binary payload, {len(case['bytes'])} bytes>"
    st.session_state.in_channel = case["channel"]
    st.session_state.in_sender = case.get("sender") or ""
    st.session_state.in_claimed = case.get("claimed") or ""
    st.session_state.in_known = case.get("known", False)
    run_analysis(case.get("bytes", case.get("text", "")), case["channel"], case.get("sender"), case.get("claimed"),
                 case.get("known", False), case.get("simulate"))


def do_appeal(case_id):
    s = ui_state(case_id)
    s["appealed"] = True
    s["msgs"].append(fb.appeal_legitimate(get_store(), case_id, st.session_state.user_id).message)


def do_report(case_id):
    s = ui_state(case_id)
    s["reported"] = True
    s["msgs"].append(fb.report_scam(get_store(), case_id, st.session_state.user_id).message)


def do_reveal(case_id):
    s = ui_state(case_id)
    s["revealed"] = True
    s["msgs"].append(fb.reveal_links(get_store(), case_id, st.session_state.user_id).message)


def do_trust_request(case_id, sender):
    out = fb.request_trust(get_store(), case_id, st.session_state.user_id, sender)
    s = ui_state(case_id)
    if isinstance(out, fb.TrustRequest):
        s["trust_req"] = out
    else:
        s["msgs"].append(out.message)


def do_trust_confirm(case_id, confirmed: bool):
    s = ui_state(case_id)
    req = s.get("trust_req")
    if req is None:
        return
    out = fb.confirm_trust(get_store(), req, confirmed)
    s["trust_req"] = None
    s["trusted"] = confirmed
    s["msgs"].append(out.message)


# ---------------------------------------------------------------- rendering


def esc(text: str) -> str:
    return html.escape(str(text))


def safe_list(items) -> str:
    """Untrusted strings (message snippets, LLM output) rendered as escaped HTML - never as Markdown."""
    return "<ul class='ss-list'>" + "".join(f"<li>{esc(i)}</li>" for i in items) + "</ul>"


def tier_badge(tier: str | None) -> str:
    if tier is None:
        return "<span class='ss-badge' style='background:#8a8985;color:#fff'>? NOT ANALYSED</span>"
    bg, fg, icon = TIER_STYLE[tier]
    return f"<span class='ss-badge' style='background:{bg};color:{fg}'>{icon} {tier}</span>"


def meter_html(score: int, tier: str) -> str:
    t = get_config().tiers
    bands = [(0, t.medium, "LOW"), (t.medium, t.high, "MEDIUM"), (t.high, t.critical, "HIGH"), (t.critical, 100, "CRITICAL")]
    segs = "".join(
        f"<div class='ss-band' title='{name} {a}-{b}' style='left:calc({a}% + 1px);width:calc({b - a}% - 2px);"
        f"background:{tint(TIER_STYLE[name][0], 0.9 if name == tier else 0.28)}'></div>"
        for a, b, name in bands
    )
    ticks = "".join(f"<span style='left:{v}%'>{v}</span>" for v in (0, t.medium, t.high, t.critical, 100))
    return (
        f"<div class='ss-meter' role='meter' aria-valuemin='0' aria-valuemax='100' aria-valuenow='{score}' "
        f"aria-label='Risk score {score} of 100, tier {tier}' title='Risk score {score}/100 - {tier}'>"
        f"<div class='ss-hero'><span class='ss-num'>{score}</span><span class='ss-of'>/100 risk</span>{tier_badge(tier)}</div>"
        f"<div class='ss-track'>{segs}<div class='ss-marker' style='left:{score}%'></div></div>"
        f"<div class='ss-ticks'>{ticks}</div></div>"
    )


def legend_html() -> str:
    return "<div class='ss-legend'>" + "".join(
        f"<span><i style='background:{tint(CATEGORY_COLORS[c], .45)};border-bottom:2px solid {CATEGORY_COLORS[c]}'></i>{esc(label)}</span>"
        for c, label in CATEGORY_LABELS.items()
    ) + "<span><span class='ss-zw'>◆</span>hidden character</span></div>"


def render_links(res: AnalysisResult, prefix: str):
    urls = res.signals.urls
    if not urls:
        return
    iv = res.intervention
    s = ui_state(res.case_id)
    unlocked = s["appealed"] or s["revealed"] or not iv.links_disabled
    st.markdown(f"**Links in this message ({len(urls)})** - never opened or fetched by ScamShield")
    if unlocked:
        for u in urls:
            st.code(u.raw, language=None)
        if iv.links_disabled:
            st.caption("Shown as plain text because you chose to proceed. Open only if you verified the sender.")
    elif iv.action is Action.INTERSTITIAL:
        st.warning(f"🔒 {len(urls)} link(s) disabled.")
        st.button("I understand the risk - show links as text", key=f"{prefix}reveal{res.case_id}",
                  on_click=do_reveal, args=(res.case_id,))
    else:
        st.error(f"⛔ {len(urls)} link(s) blocked. If you're sure this is legitimate, use 'This is legitimate' below.")


def render_feedback(res: AnalysisResult, prefix: str):
    s = ui_state(res.case_id)
    cid = res.case_id
    st.markdown("#### Was this right?")
    c1, c2, _ = st.columns([1, 1, 2])
    c1.button("✅ This is legitimate", key=f"{prefix}appeal{cid}", on_click=do_appeal, args=(cid,),
              disabled=s["appealed"], width="stretch")
    c2.button("🚩 Report scam", key=f"{prefix}report{cid}", on_click=do_report, args=(cid,),
              disabled=s["reported"], width="stretch")
    for m in s["msgs"]:
        st.info(m)
    sender = st.session_state.get("raw_sender")
    if s["appealed"] and sender and not s["trusted"]:
        if s["trust_req"] is None:
            st.button("Also add this sender to my trusted list...", key=f"{prefix}trust{cid}",
                      on_click=do_trust_request, args=(cid, sender))
        else:
            req = s["trust_req"]
            st.warning(
                f"Second confirmation: add `{req.sender_masked}` to your trusted list? Trusted senders get a lower "
                "risk score on future messages. Only do this for a sender you know personally."
            )
            ok = st.checkbox("I know this sender and want to trust them", key=f"{prefix}trustchk{cid}")
            b1, b2, _ = st.columns([1, 1, 2])
            b1.button("Add to trusted list", key=f"{prefix}trustyes{cid}", disabled=not ok,
                      on_click=do_trust_confirm, args=(cid, True))
            b2.button("Cancel", key=f"{prefix}trustno{cid}", on_click=do_trust_confirm, args=(cid, False))
    with st.expander("What happens if ScamShield is wrong?"):
        st.markdown(
            "- **False alarm?** Press *This is legitimate*: links unlock immediately, nothing is deleted, and an analyst "
            "reviews the case so the rules can be fixed.\n"
            "- **Trusting a sender** needs a second confirmation and can be undone any time from the sidebar.\n"
            "- **Missed scam?** Press *Report scam* - it goes to the analyst queue.\n"
            "- Every action here is logged in the audit trail and is reversible. ScamShield never deletes, blocks "
            "senders, or reports anything on its own."
        )


def render_result(res: AnalysisResult, prefix: str):
    iv = res.intervention
    sim = st.session_state.get("simulated")
    if sim:
        st.caption(f"Simulated LLM failure: **{sim}** (demo)")
    if res.source and res.source.get("source") == "image":
        conf = res.source.get("ocr_confidence")
        st.caption(
            f"📷 Text read from image with **{res.source['ocr_engine']}**"
            + (f" (OCR confidence {conf:.2f}, {res.source.get('ocr_ms', 0) / 1000:.1f} s)" if conf is not None else "")
            + " · the image is not stored. Fix any misread words in the Message box and press Analyze to re-check."
        )
        if "low_ocr_confidence" in res.signals.quality_flags:
            st.warning("The text in this image was hard to read. Check the extracted text before trusting the result.")
        if "vision_failed_fell_back_to_local_ocr" in res.signals.quality_flags:
            st.info("Claude vision failed, so local OCR was used instead.")
        preview = st.session_state.get("image_preview")
        if preview:
            with st.expander("Image you provided (kept only in this browser session)"):
                st.image(preview, width=280)
    if res.risk is None:
        c1, c2 = st.columns([1, 2])
        c1.html(f"<div class='ss-hero'>{tier_badge(None)}</div>")
        c2.warning(f"**{iv.headline}.** {iv.message}")
        st.caption(f"Data-quality flags: {', '.join(res.signals.quality_flags)} - original length "
                   f"{res.signals.original_length:,} chars. Case {res.case_id} logged.")
        return

    risk = res.risk
    left, right = st.columns([5, 7])
    with left:
        st.html(meter_html(risk.score, risk.tier.value))
        mode = {"hybrid": "Hybrid (rules + LLM)", "rules_only": "Rules only", "rules_only_fallback": "Rules only - LLM fallback"}
        st.caption(
            f"Confidence **{risk.confidence:.2f}**{' (degraded)' if risk.degraded_confidence else ''} · "
            f"{mode[risk.mode.value]} · rules {risk.rule_score}"
            + (f" · LLM {risk.llm_score}" if risk.llm_score is not None else "")
            + f" · case `{res.case_id}` · {res.latency_ms:.0f} ms"
        )
    with right:
        banner = {Action.ALLOW: st.success, Action.SOFT_WARN: st.warning, Action.INTERSTITIAL: st.warning,
                  Action.BLOCK_LINKS: st.error}[iv.action]
        banner(f"**{iv.headline}.** {iv.message}")
        if iv.review_note:
            st.info("🧑‍⚖️ " + iv.review_note)
        if iv.tips:
            st.markdown("**What to verify**")
            st.html(safe_list(iv.tips))

    if iv.checklist:
        with st.container(border=True):
            st.markdown("**Step-up check - verify with the sender through a number you already know**")
            for i, item in enumerate(iv.checklist):
                st.checkbox(item, key=f"{prefix}chk{res.case_id}{i}")

    st.markdown("#### Message with highlighted evidence")
    st.html(legend_html())
    st.html(
        "<div class='ss-msg'>"
        + render_highlighted_html(res.signals.display_text, res.evidence.spans, res.signals.obfuscation.zero_width_display_positions)
        + "</div>"
    )
    render_links(res, prefix)

    st.markdown("#### Why this score")
    st.caption(res.evidence.score_explanation)
    if risk.factors:
        st.dataframe(
            pd.DataFrame(
                [{"factor": f.name, "source": f.source, "points": f.contribution, "why": f.detail} for f in risk.factors]
            ),
            hide_index=True,
            width="stretch",
            column_config={"points": st.column_config.NumberColumn(format="%+.1f")},
        )
    with st.expander("Evidence detail (rules and LLM)", expanded=res.evidence.injection_detected):
        if res.evidence.injection_detected:
            st.error("Prompt-injection attempt detected: the message contains text aimed at manipulating AI filters.")
        st.markdown("**Triggered rules**")
        st.html(safe_list(res.evidence.rule_explanations) if res.evidence.rule_explanations else "<i>none</i>")
        if res.llm is not None:
            st.markdown(f"**LLM classifier** - status `{res.llm.status.value}`" + (f", model `{res.llm.model}`" if res.llm.model else ""))
            if res.llm.ok:
                v = res.llm.verdict
                st.html(
                    f"<p>Type <b>{esc(v.scam_type)}</b> · scam probability <b>{v.confidence:.2f}</b> · tactics: "
                    f"{esc(', '.join(v.manipulation_tactics) or 'none')}</p>"
                    + safe_list(v.indicators)
                    + f"<p><i>{esc(v.rationale)}</i></p>"
                )
        st.caption(f"Masked text stored in the audit log: {res.masked_text[:400]}")
    render_feedback(res, prefix)


# ---------------------------------------------------------------- sidebar


def sidebar():
    cfg = get_config()
    llm = get_llm()
    st.sidebar.title("🛡️ ScamShield")
    st.sidebar.caption("AI scam message analyser - AI Defense Lab 2026, Track 2")
    st.session_state.setdefault("user_id", "demo-user")
    st.sidebar.text_input("User ID (demo)", key="user_id")
    if llm.available:
        st.sidebar.success(f"LLM available: `{llm.model}`")
        st.sidebar.toggle("Use LLM (hybrid mode)", value=True, key="use_llm")
    else:
        st.session_state["use_llm"] = False
        st.sidebar.warning("LLM unavailable - running **rules-only** (offline). Set `ANTHROPIC_API_KEY` in `.env` for hybrid mode.")
    st.sidebar.caption(f"Config `{cfg.config_hash}` · thresholds {cfg.tiers.medium}/{cfg.tiers.high}/{cfg.tiers.critical} · "
                       f"retention {cfg.retention_days} days")

    st.sidebar.markdown("### Trusted senders")
    trusted = get_store().trusted_list(st.session_state.user_id)
    if not trusted:
        st.sidebar.caption("None yet. Added only after appeal + second confirmation.")
    for t in trusted:
        c1, c2 = st.sidebar.columns([3, 1])
        c1.write(f"`{t['sender_masked']}`")
        if c2.button("Remove", key=f"untrust{t['sender_hash']}"):
            fb.remove_trusted(get_store(), st.session_state.user_id, t["sender_hash"], t["case_id"])
            st.rerun()
    st.sidebar.markdown("### Privacy")
    st.sidebar.caption("PII is masked before storage and before anything is sent to the LLM. Links are never fetched. "
                       "No message content is written to logs.")


# ---------------------------------------------------------------- tabs


def tab_analyze():
    mode = st.radio(
        "Input", ["Paste text", "Upload screenshot / photo", "Take a photo"], horizontal=True, key="in_mode",
        label_visibility="collapsed",
    )
    if mode != "Paste text":
        if not LocalOCR.available():
            st.error("Local OCR isn't installed. Run `pip install -r requirements.txt` (rapidocr-onnxruntime).")
        st.caption(
            "Optional: set channel / sender below first. After the image is read, the extracted text appears in the "
            "Message box - fix any misread words and press Analyze to re-check."
        )
        if mode == "Upload screenshot / photo":
            st.file_uploader(
                "Screenshot or photo of the message (PNG, JPG or WEBP, max 8 MB)",
                type=["png", "jpg", "jpeg", "webp"], key="in_image", on_change=on_image, args=("in_image",),
            )
        else:
            st.camera_input("Point the camera at the message", key="in_camera", on_change=on_image, args=("in_camera",))
        if get_llm().available:
            st.checkbox(
                "Read the image with Claude vision instead of local OCR (better on photos, but sends the full, "
                "unmasked image to Anthropic)",
                key="use_vision",
            )
        else:
            st.caption("🔒 Text is read on this device with local OCR. The image is never stored or sent anywhere.")
    with st.form("analyze_form"):
        st.text_area("Message", key="in_text", height=140, placeholder="Paste an SMS, email or chat message...")
        c1, c2, c3, c4 = st.columns([1, 2, 2, 1])
        c1.selectbox("Channel", ["sms", "email", "chat"], key="in_channel")
        c2.text_input("Sender ID (optional)", key="in_sender", placeholder="+1 415 555 0132 or name@domain.com")
        c3.text_input("Claimed sender (optional)", key="in_claimed", placeholder="e.g. Chase, 'David (CEO)'")
        c4.checkbox("Known contact", key="in_known")
        st.form_submit_button("Analyze", type="primary", on_click=on_submit)
    res = st.session_state.get("result")
    if res is not None:
        render_result(res, "an_")


def tab_demo():
    st.caption("One click loads the case into the Analyze tab and runs it. The result also appears below.")
    groups: dict[str, list[dict]] = {}
    for case in DEMO_CASES:
        groups.setdefault(case["group"], []).append(case)
    cols = st.columns(len(groups))
    for col, (group, cases) in zip(cols, groups.items()):
        with col:
            st.markdown(f"**{group}**")
            for i, case in enumerate(cases):
                st.button(case["title"], key=f"demo{group}{i}", on_click=load_case, args=(case,), width="stretch")
                st.caption(f"Expect: {case['expect']}")
    res = st.session_state.get("result")
    if res is not None:
        st.divider()
        render_result(res, "demo_")


def tab_analyst():
    store = get_store()
    stats = fb.decision_stats(store)
    k = st.columns(6)
    k[0].metric("Cases", stats["total_cases"])
    k[1].metric("Flagged (≥ MEDIUM)", stats["flagged_cases"])
    k[2].metric("In queue", stats["queue_size"])
    k[3].metric("User appeals", stats["appeals"], help=f"appeal rate {stats['appeal_rate']:.0%} of flagged")
    k[4].metric("Confirmed scam", stats["confirmed_scam"])
    k[5].metric("Overturned", stats["overturned_legitimate"], help=f"overturn rate {stats['overturn_rate']:.0%} of decisions")

    queue = fb.analyst_queue(store)
    st.markdown("#### Review queue")
    st.caption("Priority: user appeals, then rules/LLM disagreements, then user reports, then HIGH/CRITICAL.")
    if not queue:
        st.success("Queue is empty.")
    else:
        st.dataframe(
            pd.DataFrame(queue)[["case_id", "ts", "tier", "score", "reasons", "channel", "user_action", "mode"]],
            hide_index=True, width="stretch",
        )
    recent = store.cases(200)
    options = [c["case_id"] for c in queue] + [c["case_id"] for c in recent if c["case_id"] not in {q["case_id"] for q in queue}]
    if not options:
        return
    labels = {c["case_id"]: f"{c['case_id']} · {c['tier'] or 'INSUFFICIENT'} · {c['score'] if c['score'] is not None else '-'} · "
              f"{c['analyst_outcome']}" for c in recent}
    cid = st.selectbox("Open case", options, format_func=lambda x: labels.get(x, x))
    case = store.get_case(cid)
    if not case:
        return
    c1, c2 = st.columns([3, 2])
    with c1:
        st.html(f"<div class='ss-hero'>{tier_badge(case['tier'])}<span class='ss-of'>score {case['score']} · "
                f"{esc(case['mode'] or '')} · {esc(case['channel'])} · sender {esc(case['sender_masked'] or '-')}</span></div>")
        st.markdown("**Masked message**")
        st.text(case["masked_message"] or "(no text stored)")
        hits = json.loads(case["rule_hits"] or "[]")
        if hits:
            st.dataframe(pd.DataFrame(hits), hide_index=True, width="stretch")
        if case["llm_output"]:
            st.markdown("**LLM output**")
            st.json(json.loads(case["llm_output"]))
    with c2:
        st.markdown("**Timeline**")
        st.dataframe(pd.DataFrame(store.events(cid))[["ts", "actor", "event_type"]], hide_index=True, width="stretch")
        st.markdown(f"Current outcome: `{case['analyst_outcome']}` · user action: `{case['user_action']}`")
        analyst = st.text_input("Analyst", value="analyst-1", key=f"analyst{cid}")
        note = st.text_input("Note", key=f"note{cid}")
        b1, b2 = st.columns(2)
        if b1.button("Confirm scam", key=f"confirm{cid}", type="primary", width="stretch"):
            fb.analyst_decide(store, cid, analyst, fb.AnalystOutcome.CONFIRMED_SCAM, note)
            st.rerun()
        if b2.button("Overturn (legitimate)", key=f"overturn{cid}", width="stretch"):
            fb.analyst_decide(store, cid, analyst, fb.AnalystOutcome.OVERTURNED_LEGITIMATE, note)
            st.rerun()
        st.caption("Decisions are appended, never overwritten - a later decision supersedes an earlier one.")


def confusion_html(matrix: dict) -> str:
    tiers = ["INSUFFICIENT", "LOW", "MEDIUM", "HIGH", "CRITICAL"]
    peak = max((v for row in matrix.values() for v in row.values()), default=1) or 1
    head = "<tr><th>label \\ tier</th>" + "".join(f"<th>{t}</th>" for t in tiers) + "</tr>"
    rows = []
    for label, row in matrix.items():
        cells = []
        for t in tiers:
            v = row.get(t, 0)
            step = 0 if v == 0 else min(len(SEQ_BLUE) - 1, 1 + round((v / peak) * (len(SEQ_BLUE) - 2)))
            bg = "transparent" if v == 0 else SEQ_BLUE[step]
            fg = "#ffffff" if step >= 3 else ("inherit" if v == 0 else "#0b0b0b")
            cells.append(f"<td style='background:{bg};color:{fg}' title='{label} messages rated {t}: {v}'>{v}</td>")
        rows.append(f"<tr><th>{label}</th>{''.join(cells)}</tr>")
    return f"<div style='overflow-x:auto'><table class='ss-cm'>{head}{''.join(rows)}</table></div>"


def tab_metrics():
    path = ROOT / "eval" / "results.json"
    c1, c2 = st.columns([1, 3])
    if c1.button("Re-run rules-only eval"):
        run_eval_main(["--modes", "rules", "--merge"])
        st.rerun()
    if get_llm().available and c1.button("Run hybrid eval (uses API)"):
        with st.spinner("Calling the LLM for every message..."):
            run_eval_main(["--modes", "rules", "hybrid", "--merge"])
        st.rerun()
    if not path.exists():
        st.info("No results yet - run `python -m eval.run_eval`.")
        return
    data = json.loads(path.read_text(encoding="utf-8"))
    c2.caption(f"Generated {data['generated']} · split `{data['split']}` · synthetic dataset - see LIMITATIONS.md")
    for res in data["results"]:
        st.markdown(f"### {res['mode']}" + (f" · `{res['model']}`" if res.get("model") else ""))
        if res.get("skipped"):
            st.warning(f"Skipped: {res['reason']}")
            continue
        st.caption(f"{res['n']} messages ({res['n_scam']} scam / {res['n_legit']} legit) · latency p50 "
                   f"{res['latency_ms']['p50']} ms, p95 {res['latency_ms']['p95']} ms · needs_review {res['needs_review']}")
        if res["mode"] == "image":
            st.caption(
                f"Image mode: messages rendered as phone screenshots, read by local OCR, no sender metadata. "
                f"OCR word recall {res.get('ocr_word_recall_mean') or 0:.3f}. Latency inside eval runs depends on machine "
                "load; standalone warm OCR measured about 1.7-1.8 s per image."
            )
        for op, label in (("warn", "Warn point (tier ≥ MEDIUM)"), ("interrupt", "Interrupt point (tier ≥ HIGH)")):
            m = res["operating_points"][op]
            st.markdown(f"**{label}**")
            k = st.columns(5)
            k[0].metric("Precision", f"{m['precision']:.3f}")
            k[1].metric("Recall", f"{m['recall']:.3f}")
            k[2].metric("F1", f"{m['f1']:.3f}")
            k[3].metric("False-positive rate", f"{m['false_positive_rate']:.3f}")
            k[4].metric("TP / FP / TN / FN", f"{m['tp']} / {m['fp']} / {m['tn']} / {m['fn']}")
        a, b = st.columns([3, 2])
        with a:
            st.markdown("**Confusion matrix (label × tier)**")
            st.html(confusion_html(res["confusion_label_by_tier"]))
            with st.expander("As a table"):
                st.dataframe(pd.DataFrame(res["confusion_label_by_tier"]).T, width="stretch")
        with b:
            st.markdown("**By split**")
            st.dataframe(
                pd.DataFrame([
                    {"split": sp, "n": blk["n"], "op": op, "precision": blk[op]["precision"], "recall": blk[op]["recall"],
                     "FPR": blk[op]["false_positive_rate"]}
                    for sp, blk in res["by_split"].items() for op in ("warn", "interrupt")
                ]),
                hide_index=True, width="stretch",
            )
        errors = [r for r in res["records"] if (r["label"] == "scam") != (r["tier"] in ("MEDIUM", "HIGH", "CRITICAL"))]
        st.markdown(f"**Misclassifications at the warn point: {len(errors)}**")
        if errors:
            st.dataframe(pd.DataFrame(errors)[["id", "split", "label", "category", "tier", "score", "rules", "masked_text"]],
                         hide_index=True, width="stretch")
    report = ROOT / "eval" / "report.md"
    if report.exists():
        st.download_button("Download report.md", report.read_bytes(), "report.md", "text/markdown")


def tab_audit():
    store = get_store()
    cfg = get_config()
    rows = store.cases(500)
    st.caption("Append-only log (UPDATE/DELETE blocked by triggers). Masked text only; sender and user are stored as masked/hashed values.")
    c1, c2, _ = st.columns([1, 1, 3])
    c1.download_button("Export CSV", store.export_csv(), "scamshield_audit.csv", "text/csv", width="stretch")
    if c2.button(f"Purge records older than {cfg.retention_days} days", width="stretch"):
        out = store.purge_expired(cfg.retention_days)
        st.success(f"Purged {out['cases_deleted']} case(s), {out['events_deleted']} event(s) older than {out['cutoff']}.")
    if not rows:
        st.info("No cases yet.")
        return
    df = pd.DataFrame(rows)[["ts", "case_id", "channel", "status", "tier", "score", "confidence", "mode", "intervention",
                             "user_action", "analyst_outcome", "sender_masked", "masked_message", "model_version", "config_hash"]]
    st.dataframe(df, hide_index=True, width="stretch")
    purges = store.query("SELECT * FROM purge_log ORDER BY ts DESC LIMIT 5")
    if purges:
        st.markdown("**Recent purges**")
        st.dataframe(pd.DataFrame(purges), hide_index=True)


def main():
    st.html(CSS)
    for key, default in (("in_text", ""), ("in_channel", "sms"), ("in_sender", ""), ("in_claimed", ""), ("in_known", False)):
        st.session_state.setdefault(key, default)
    sidebar()
    st.title("ScamShield")
    st.caption("Paste a message you received. ScamShield explains the warning signs before you click, pay, or share a code.")
    tabs = st.tabs(["Analyze", "Demo cases", "Analyst queue", "Metrics", "Audit log"])
    with tabs[0]:
        tab_analyze()
    with tabs[1]:
        tab_demo()
    with tabs[2]:
        tab_analyst()
    with tabs[3]:
        tab_metrics()
    with tabs[4]:
        tab_audit()


main()

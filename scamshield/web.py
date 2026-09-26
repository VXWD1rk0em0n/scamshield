"""Framework-free request handling for the public web API.

Used by the Vercel function (api/analyze.py) and the local dev server
(scripts/dev_server.py), and unit-tested directly.

Public-mode rules:
* Stateless - no audit DB, no analyst queue; nothing a visitor sends is stored.
* Rules-only unless the operator sets SCAMSHIELD_WEB_LLM=on *and* provides an
  API key (a public endpoint with a paid LLM behind it invites cost abuse).
* Screenshots are OCR'd in the visitor's browser; only the recognised lines
  (text + boxes) are sent here and re-assembled with the same logic as the
  desktop app. Images never reach the server.
* Strict input validation, body-size cap, and a per-instance rate limit.
"""

from __future__ import annotations

import json
import os
import threading
import time
from collections import deque

from scamshield import RULESET_VERSION, __version__
from scamshield.config import load_config
from scamshield.demo_cases import DEMO_CASES
from scamshield.image_ingest import OCRLine, extract_message
from scamshield.models import AnalysisResult, Channel, MessageInput
from scamshield.pipeline import Analyzer

MAX_BODY_BYTES = 64_000
MAX_OCR_LINES = 400
MAX_FIELD_CHARS = 200
RATE_LIMIT = 30  # requests per window per client, per instance
RATE_WINDOW_S = 60.0

_CONFIG = load_config()
_analyzer: Analyzer | None = None
_lock = threading.Lock()


class BadRequest(ValueError):
    pass


class RateLimiter:
    """Sliding-window limiter. In-memory, so it only protects a single warm instance;
    real protection belongs in the platform firewall (see README)."""

    def __init__(self, limit: int = RATE_LIMIT, window: float = RATE_WINDOW_S) -> None:
        self.limit, self.window = limit, window
        self._hits: dict[str, deque[float]] = {}
        self._lock = threading.Lock()

    def allow(self, key: str, now: float | None = None) -> bool:
        now = time.monotonic() if now is None else now
        with self._lock:
            q = self._hits.setdefault(key, deque())
            while q and now - q[0] > self.window:
                q.popleft()
            if len(q) >= self.limit:
                return False
            q.append(now)
            if len(self._hits) > 10_000:  # bound memory under address spraying
                self._hits = {k: v for k, v in self._hits.items() if v and now - v[-1] <= self.window}
            return True


limiter = RateLimiter()


def web_llm_enabled() -> bool:
    has_key = bool(os.environ.get("ANTHROPIC_API_KEY") or os.environ.get("ANTHROPIC_AUTH_TOKEN"))
    return has_key and os.environ.get("SCAMSHIELD_WEB_LLM", "off").lower() == "on"


def get_analyzer() -> Analyzer:
    global _analyzer
    with _lock:
        if _analyzer is None:
            _analyzer = Analyzer(_CONFIG, store=None, use_llm=web_llm_enabled())
        return _analyzer


# ------------------------------------------------------------------ serialisation


def segments(result: AnalysisResult) -> list[dict]:
    """The display text split into plain / highlighted / hidden-character segments.

    Returned as pieces rather than offsets because Python indexes code points and
    JavaScript indexes UTF-16 units (emoji would shift every offset)."""
    text = result.signals.display_text
    if not text:
        return []
    spans = result.evidence.spans if result.evidence else ()
    zw = set(result.signals.obfuscation.zero_width_display_positions)
    cut_points = {0, len(text)}
    for sp in spans:
        cut_points.update((sp.start, sp.end))
    for p in zw:
        cut_points.update((p, p + 1))
    bounds = sorted(b for b in cut_points if 0 <= b <= len(text))
    out: list[dict] = []
    for a, b in zip(bounds, bounds[1:]):
        span = next((s for s in spans if s.start <= a and b <= s.end), None)
        piece = {"text": text[a:b], "category": span.category if span else None, "labels": list(span.labels) if span else []}
        if a in zw and b == a + 1:
            piece["hidden_char"] = True
        prev = out[-1] if out else None
        if prev and not prev.get("hidden_char") and not piece.get("hidden_char") and prev["category"] == piece["category"] and prev["labels"] == piece["labels"]:
            prev["text"] += piece["text"]
        else:
            out.append(piece)
    return out


def serialize(result: AnalysisResult) -> dict:
    risk, iv, ev, llm = result.risk, result.intervention, result.evidence, result.llm
    body: dict = {
        "case_id": result.case_id,
        "status": result.signals.status.value,
        "quality_flags": list(result.signals.quality_flags),
        "original_length": result.signals.original_length,
        "segments": segments(result),
        "links": [{"raw": u.raw, "host": u.host} for u in result.signals.urls],
        "intervention": {
            "action": iv.action.value,
            "headline": iv.headline,
            "message": iv.message,
            "tips": list(iv.tips),
            "checklist": list(iv.checklist),
            "links_disabled": iv.links_disabled,
            "requires_confirmation": iv.requires_confirmation,
            "recommend_report": iv.recommend_report,
            "review_note": iv.review_note,
        },
        "model_version": result.model_version,
        "config_hash": result.config_hash,
        "latency_ms": round(result.latency_ms, 1),
        "tiers": {"medium": _CONFIG.tiers.medium, "high": _CONFIG.tiers.high, "critical": _CONFIG.tiers.critical},
    }
    if risk is not None:
        body["risk"] = {
            "score": risk.score,
            "tier": risk.tier.value,
            "confidence": risk.confidence,
            "mode": risk.mode.value,
            "rule_score": risk.rule_score,
            "llm_score": risk.llm_score,
            "needs_review": risk.needs_review,
            "degraded_confidence": risk.degraded_confidence,
            "adjustments": list(risk.adjustments),
            "factors": [
                {"name": f.name, "source": f.source, "points": f.contribution, "detail": f.detail} for f in risk.factors
            ],
        }
    if ev is not None:
        body["evidence"] = {
            "rule_explanations": list(ev.rule_explanations),
            "score_explanation": ev.score_explanation,
            "injection_detected": ev.injection_detected,
        }
    if llm is not None:
        body["llm"] = {"status": llm.status.value, "model": llm.model}
        if llm.ok and llm.verdict is not None:
            v = llm.verdict
            body["llm"].update(
                scam_type=v.scam_type,
                confidence=v.confidence,
                indicators=list(v.indicators),
                tactics=list(v.manipulation_tactics),
                rationale=v.rationale,
            )
    return body


# ------------------------------------------------------------------ validation


def _opt_str(payload: dict, key: str) -> str | None:
    value = payload.get(key)
    if value is None or value == "":
        return None
    if not isinstance(value, str):
        raise BadRequest(f"{key} must be a string")
    return value.strip()[:MAX_FIELD_CHARS] or None


def _ocr_text(ocr: object) -> tuple[str, str | None, str | None, float | None]:
    if not isinstance(ocr, dict) or not isinstance(ocr.get("lines"), list):
        raise BadRequest("ocr.lines must be a list")
    raw_lines = ocr["lines"]
    if len(raw_lines) > MAX_OCR_LINES:
        raise BadRequest("too many OCR lines")
    lines: list[OCRLine] = []
    for item in raw_lines:
        if not isinstance(item, dict) or not isinstance(item.get("text"), str):
            raise BadRequest("each OCR line needs text")
        bbox = item.get("bbox")
        if not (isinstance(bbox, list) and len(bbox) == 4 and all(isinstance(v, (int, float)) for v in bbox)):
            raise BadRequest("each OCR line needs bbox [x0, y0, x1, y1]")
        conf = item.get("confidence", 0)
        conf = float(conf) / (100.0 if isinstance(conf, (int, float)) and conf > 1 else 1.0) if isinstance(conf, (int, float)) else 0.0
        lines.append(OCRLine(item["text"][:1000], max(0.0, min(1.0, conf)), tuple(float(v) for v in bbox)))  # type: ignore[arg-type]
    extracted = extract_message(lines)
    mean = sum(l.confidence for l in lines) / len(lines) if lines else None
    return extracted.text, extracted.sender_hint, extracted.claimed_hint, mean


def parse_request(payload: object) -> tuple[MessageInput, dict | None]:
    if not isinstance(payload, dict):
        raise BadRequest("body must be a JSON object")
    channel_raw = payload.get("channel", "sms")
    try:
        channel = Channel(channel_raw)
    except ValueError:
        raise BadRequest("channel must be sms, email or chat") from None
    sender = _opt_str(payload, "sender_id")
    claimed = _opt_str(payload, "claimed_sender")
    for flag in ("known_contact", "trusted_sender"):
        if not isinstance(payload.get(flag, False), bool):
            raise BadRequest(f"{flag} must be a boolean")
    source = None
    if payload.get("ocr") is not None:
        text, sender_hint, claimed_hint, mean = _ocr_text(payload["ocr"])
        sender = sender or (sender_hint[:MAX_FIELD_CHARS] if sender_hint else None)
        claimed = claimed or (claimed_hint[:MAX_FIELD_CHARS] if claimed_hint else None)
        source = {
            "source": "image",
            "ocr_engine": "tesseract.js (in browser)",
            "ocr_confidence": None if mean is None else round(mean, 3),
            "ocr_lines": len(payload["ocr"]["lines"]),
            "sender_hint": sender_hint,
            "claimed_hint": claimed_hint,
        }
    else:
        text = payload.get("text", "")
        if not isinstance(text, str):
            raise BadRequest("text must be a string")
    msg = MessageInput(text=text, channel=channel, sender_id=sender, claimed_sender=claimed,
                       known_contact=bool(payload.get("known_contact", False)))
    return msg, source


# ------------------------------------------------------------------ handlers


def handle_get() -> tuple[int, dict]:
    demos = [
        {k: c.get(k) for k in ("group", "title", "expect", "channel", "sender", "claimed", "text")}
        | ({"image": f"/demo/{c['image']}"} if "image" in c else {})
        for c in DEMO_CASES
        if "bytes" not in c and not c.get("simulate")
    ]
    return 200, {
        "service": "scamshield",
        "version": f"{__version__}/{RULESET_VERSION}",
        "mode": "hybrid" if web_llm_enabled() else "rules_only",
        "stores_data": False,
        "demo_cases": demos,
    }


def handle_post(body: bytes, client_key: str = "anon") -> tuple[int, dict]:
    if len(body) > MAX_BODY_BYTES:
        return 413, {"error": "request too large"}
    if not limiter.allow(client_key):
        return 429, {"error": "too many requests - try again in a minute"}
    try:
        payload = json.loads(body.decode("utf-8"))
        msg, source = parse_request(payload)
    except (UnicodeDecodeError, json.JSONDecodeError):
        return 400, {"error": "body must be UTF-8 JSON"}
    except BadRequest as exc:
        return 400, {"error": str(exc)}
    result = get_analyzer().analyze(
        msg,
        user_id=None,
        record=False,
        source=source,
        trusted_sender=bool(payload.get("trusted_sender", False)),
        extra_flags=("from_image",) if source else (),
    )
    body_out = serialize(result)
    if source:
        body_out["source"] = source
    return 200, body_out

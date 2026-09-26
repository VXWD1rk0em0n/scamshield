"""Public web API (Vercel function) - validation, privacy defaults, serialisation."""

from __future__ import annotations

import importlib
import json

import pytest

from scamshield import web

ATTACK = (
    "Chase Alert: Unusual sign-in detected on your account. To avoid suspension, verify now at "
    "https://chase-secure-verify.com/login and reply with the 6-digit code we just sent you."
)


@pytest.fixture(autouse=True)
def _fresh_limiter(monkeypatch):
    monkeypatch.setattr(web, "limiter", web.RateLimiter())
    monkeypatch.setattr(web, "_analyzer", None)


def post(payload, key="t") -> tuple[int, dict]:
    return web.handle_post(json.dumps(payload).encode(), key)


def test_get_lists_demo_cases_and_stateless_rules_only_mode():
    status, body = web.handle_get()
    assert status == 200 and body["stores_data"] is False and body["mode"] == "rules_only"
    titles = [c["title"] for c in body["demo_cases"]]
    assert any("Fake bank SMS" in t for t in titles)
    assert not any((c.get("text") or "").startswith("<binary") for c in body["demo_cases"])
    assert any(c.get("image", "").startswith("/demo/") for c in body["demo_cases"])


def test_llm_needs_key_and_explicit_opt_in(monkeypatch):
    monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-ant-test")
    assert not web.web_llm_enabled()  # a key alone never turns on paid calls for a public endpoint
    monkeypatch.setenv("SCAMSHIELD_WEB_LLM", "on")
    assert web.web_llm_enabled()


def test_attack_is_critical_and_nothing_is_stored(tmp_path, monkeypatch):
    status, body = post({"text": ATTACK, "channel": "sms", "sender_id": "+1 (415) 555-0132"})
    assert status == 200
    assert body["risk"]["tier"] == "CRITICAL" and body["intervention"]["action"] == "BLOCK_LINKS"
    assert "".join(s["text"] for s in body["segments"]) == ATTACK
    assert any(s["category"] == "impersonation" and "chase-secure-verify.com" in s["text"] for s in body["segments"])
    assert body["links"][0]["host"] == "chase-secure-verify.com"
    assert web.get_analyzer().store is None


def test_segments_survive_emoji_and_mark_hidden_characters():
    text = "Hi Mum \U0001F648 this is my new number. Confirm your pass​word at https://m365-mailbox-upgrade.com now"
    _, body = post({"text": text})
    assert "".join(s["text"] for s in body["segments"]) == text
    hidden = [s for s in body["segments"] if s.get("hidden_char")]
    assert len(hidden) == 1 and hidden[0]["text"] == "​"


def test_insufficient_data_is_explicit():
    _, body = post({"text": "hi"})
    assert body["status"] == "INSUFFICIENT_DATA" and "risk" not in body
    assert body["intervention"]["action"] == "UNABLE_TO_ANALYZE"


def test_browser_ocr_lines_are_reassembled_server_side():
    lines = [
        {"text": "+1 (415) 555-0132", "confidence": 96, "bbox": [300, 30, 460, 60]},
        {"text": "Today 9:41 AM", "confidence": 95, "bbox": [320, 130, 440, 150]},
        {"text": "Chase Alert: verify now at https://chase-secure-", "confidence": 93, "bbox": [40, 200, 600, 230]},
        {"text": "verify.com/login and reply with the code", "confidence": 94, "bbox": [40, 240, 560, 270]},
    ]
    status, body = post({"ocr": {"lines": lines}, "channel": "sms"})
    assert status == 200
    text = "".join(s["text"] for s in body["segments"])
    assert text == "Chase Alert: verify now at https://chase-secure-verify.com/login and reply with the code"
    assert body["source"]["sender_hint"] == "+1 (415) 555-0132"
    assert body["source"]["ocr_confidence"] == pytest.approx(0.945)
    assert body["risk"]["tier"] in {"HIGH", "CRITICAL"}


def test_browser_side_trusted_list_is_applied():
    msg = {"text": "Can you review the Q4 deck before 5pm today? Thanks!", "sender_id": "@sam.lee", "channel": "chat"}
    _, plain = post(msg)
    _, trusted = post(msg | {"trusted_sender": True})
    assert not any(f["name"] == "TRUSTED_SENDER" for f in plain["risk"]["factors"])
    assert any(f["name"] == "TRUSTED_SENDER" for f in trusted["risk"]["factors"])


@pytest.mark.parametrize(
    "payload, message",
    [
        ([1, 2], "JSON object"),
        ({"text": 5}, "text must be a string"),
        ({"text": "hello there friend", "channel": "fax"}, "channel"),
        ({"text": "hello there friend", "known_contact": "yes"}, "boolean"),
        ({"text": "hello there friend", "sender_id": ["x"]}, "sender_id"),
        ({"ocr": {"lines": "nope"}}, "ocr.lines"),
        ({"ocr": {"lines": [{"text": "x", "bbox": [1, 2]}]}}, "bbox"),
        ({"ocr": {"lines": [{"text": "x", "bbox": [0, 0, 1, 1]}] * 401}}, "too many"),
    ],
)
def test_invalid_requests_are_rejected(payload, message):
    status, body = post(payload)
    assert status == 400 and message in body["error"]


def test_non_json_and_oversized_bodies():
    assert web.handle_post(b"\xff\xfe not json", "t")[0] == 400
    assert web.handle_post(b"{" + b" " * web.MAX_BODY_BYTES + b"}", "t")[0] == 413


def test_rate_limit_is_per_client():
    limiter = web.RateLimiter(limit=2, window=60)
    assert limiter.allow("a", 0) and limiter.allow("a", 1) and not limiter.allow("a", 2)
    assert limiter.allow("b", 2)
    assert limiter.allow("a", 62)  # window slides


def test_rate_limited_request_returns_429(monkeypatch):
    monkeypatch.setattr(web, "limiter", web.RateLimiter(limit=1, window=60))
    assert post({"text": ATTACK}, key="ip1")[0] == 200
    assert post({"text": ATTACK}, key="ip1")[0] == 429


def test_vercel_entrypoint_imports_and_exposes_handler():
    module = importlib.import_module("api.analyze")
    assert hasattr(module, "handler")


def test_vercel_config_keeps_function_small_and_headers_strict():
    from scamshield.config import REPO_ROOT

    cfg = json.loads((REPO_ROOT / "vercel.json").read_text())
    csp = next(h["value"] for block in cfg["headers"] for h in block["headers"] if h["key"] == "Content-Security-Policy")
    assert "'unsafe-inline'" not in csp and "frame-ancestors 'none'" in csp and "object-src 'none'" in csp
    reqs = (REPO_ROOT / "api" / "requirements.txt").read_text()
    assert "streamlit" not in reqs and "onnxruntime" not in reqs and "pydantic" in reqs
    ignored = (REPO_ROOT / ".vercelignore").read_text().split()
    assert "/requirements.txt" in ignored and ".env" in ignored

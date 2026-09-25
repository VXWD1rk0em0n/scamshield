"""Structured JSON logging that never carries message content or secrets."""

from __future__ import annotations

import json
import logging
import re

_SECRET_RE = re.compile(r"sk-ant-[A-Za-z0-9_\-]{8,}|(?i:x-api-key|authorization)\s*[:=]\s*\S+")
# Only these extra fields are emitted; anything else passed via ``extra`` is dropped,
# so a careless ``extra={"text": ...}`` cannot leak message content.
ALLOWED_FIELDS = frozenset(
    {
        "case_id", "tier", "score", "mode", "llm_status", "latency_ms", "rule_ids", "needs_review",
        "status", "quality_flags", "error_kind", "channel", "action", "model", "config_hash", "event",
    }
)


def redact(text: str) -> str:
    return _SECRET_RE.sub("[REDACTED]", text)


class JsonFormatter(logging.Formatter):
    def format(self, record: logging.LogRecord) -> str:
        payload = {
            "ts": self.formatTime(record, "%Y-%m-%dT%H:%M:%S"),
            "level": record.levelname,
            "logger": record.name,
            "event": redact(record.getMessage()),
        }
        for key in ALLOWED_FIELDS:
            if key in record.__dict__ and key != "event":
                payload[key] = record.__dict__[key]
        return redact(json.dumps(payload, default=str))


def configure_logging(level: int = logging.INFO) -> None:
    root = logging.getLogger("scamshield")
    if any(isinstance(h.formatter, JsonFormatter) for h in root.handlers):
        return
    handler = logging.StreamHandler()
    handler.setFormatter(JsonFormatter())
    root.addHandler(handler)
    root.setLevel(level)
    root.propagate = False
    # The SDK's own debug logging could include request bodies; keep it quiet.
    logging.getLogger("anthropic").setLevel(logging.WARNING)
    logging.getLogger("httpx").setLevel(logging.WARNING)

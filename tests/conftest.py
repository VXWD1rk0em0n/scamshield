from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from scamshield.audit import AuditStore  # noqa: E402
from scamshield.config import load_config  # noqa: E402
from scamshield.ingest import ingest  # noqa: E402
from scamshield.llm_analyzer import LLMAnalyzer  # noqa: E402
from scamshield.models import Channel, MessageInput  # noqa: E402
from scamshield.pipeline import Analyzer  # noqa: E402
from scamshield.rules import run_rules  # noqa: E402

ZW = "​"


@pytest.fixture(autouse=True)
def _isolate_env(monkeypatch):
    # Tests must never hit the network or depend on the developer's credentials.
    for var in ("ANTHROPIC_API_KEY", "ANTHROPIC_AUTH_TOKEN", "SCAMSHIELD_LLM_MODEL", "SCAMSHIELD_CONFIG"):
        monkeypatch.delenv(var, raising=False)
    monkeypatch.setenv("SCAMSHIELD_PEPPER", "test-pepper")


@pytest.fixture
def config():
    return load_config()


@pytest.fixture
def store(tmp_path):
    s = AuditStore(tmp_path / "audit.db")
    yield s
    s.close()


@pytest.fixture
def rules_only(config, store):
    return Analyzer(config, store=store, use_llm=False)


def verdict_json(scam_type="phishing", confidence=0.9, indicators=None, tactics=None, rationale="Looks like phishing.") -> str:
    return json.dumps(
        {
            "scam_type": scam_type,
            "indicators": indicators if indicators is not None else ["asks for one-time code"],
            "manipulation_tactics": tactics if tactics is not None else ["urgency", "authority"],
            "confidence": confidence,
            "rationale": rationale,
        }
    )


@pytest.fixture
def make_hybrid(config, store):
    """Analyzer whose LLM is a stub: fn(system, user) -> raw text, or raises."""

    def _make(fn):
        calls = []

        def wrapped(system, user):
            calls.append((system, user))
            return fn(system, user)

        analyzer = Analyzer(config, llm=LLMAnalyzer(config, completion_fn=wrapped), store=store)
        analyzer.calls = calls  # type: ignore[attr-defined]
        return analyzer

    return _make


def msg(text, channel="sms", sender=None, claimed=None, known=False) -> MessageInput:
    return MessageInput(text=text, channel=Channel(channel), sender_id=sender, claimed_sender=claimed, known_contact=known)


def signals_for(config, text, **kw):
    return ingest(msg(text, **kw), config)


def rules_for(config, text, trusted=False, **kw):
    return run_rules(signals_for(config, text, **kw), config, trusted_sender=trusted)

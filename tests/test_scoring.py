from __future__ import annotations

import dataclasses

from conftest import rules_for
from scamshield.config import load_config
from scamshield.llm_analyzer import LLMVerdict
from scamshield.models import AnalysisMode, LLMResult, LLMStatus, Tier
from scamshield.scoring import score, tier_for

ATTACK = "Chase: verify your account at https://chase-login-help.com and reply with your PIN."
BENIGN = "Lunch at noon tomorrow? The usual place works for me."


def _llm(confidence, scam_type="phishing"):
    v = LLMVerdict(scam_type=scam_type, indicators=[], manipulation_tactics=[], confidence=confidence, rationale="r")
    return LLMResult(LLMStatus.OK, v, "stub", 1.0)


def test_rules_only_score_equals_rule_score(config):
    rules = rules_for(config, BENIGN)
    risk = score(rules, None, config)
    assert risk.mode is AnalysisMode.RULES_ONLY and risk.score == rules.score and risk.tier is Tier.LOW


def test_hybrid_blend_uses_config_weights(config):
    rules = rules_for(config, "Congratulations! You won a prize, claim it at https://bit.ly/x now")
    risk = score(rules, _llm(0.8), config)
    expected = round(config.scoring.rules_weight * rules.score + config.scoring.llm_weight * 80)
    assert risk.mode is AnalysisMode.HYBRID and risk.score == expected
    assert any(f.name == "LLM_CLASSIFIER" for f in risk.factors)


def test_combo_reaches_critical_and_factors_are_sorted(config):
    risk = score(rules_for(config, ATTACK), _llm(0.95), config)
    assert risk.tier is Tier.CRITICAL
    contributions = [abs(f.contribution) for f in risk.factors]
    assert contributions == sorted(contributions, reverse=True)


def test_strong_disagreement_sets_review(config):
    risk = score(rules_for(config, ATTACK), _llm(0.1, "unclear"), config)
    assert risk.needs_review and risk.tier is Tier.HIGH
    assert any("disagree" in a for a in risk.adjustments)


def test_disagreement_never_auto_escalates_to_critical(config):
    rules = rules_for(
        config,
        "Chase Alert: your account will be suspended. Verify now at https://chase-secure-verify.com/login "
        "and reply with the 6-digit code we just sent you.",
        sender="+1 (415) 555-0132",
    )
    assert rules.score == 100 and rules.critical_combo
    risk = score(rules, _llm(0.55), config)  # blend 82 would be CRITICAL, but the engines disagree by 45
    assert risk.needs_review and risk.tier is Tier.HIGH
    assert any("never auto-escalated" in a for a in risk.adjustments)


def test_llm_only_suspicion_does_not_go_critical_and_is_reviewed(config):
    risk = score(rules_for(config, BENIGN), _llm(0.95), config)
    assert risk.needs_review and risk.tier.rank <= Tier.MEDIUM.rank


def test_critical_requires_combo(config):
    rules = rules_for(
        config,
        "Microsoft Security Warning: Your computer has been infected with a Trojan virus. Call Windows Support "
        "immediately at +1-844-555-0187. Do not shut down your computer. Our technician will connect via AnyDesk.",
        sender="alerts@windows-defender-center.com",
    )
    assert rules.score >= config.tiers.critical and not rules.critical_combo
    risk = score(rules, None, config)
    assert risk.tier is Tier.HIGH and risk.score == config.tiers.critical - 1


def test_combo_floor_raises_to_high(config):
    rules = rules_for(config, "Hi dad, new number! lost my phone. Send $50 on Venmo please")
    assert rules.critical_combo and rules.score < config.tiers.high
    assert score(rules, None, config).tier is Tier.HIGH


def test_fallback_confidence_is_degraded(config):
    rules = rules_for(config, ATTACK)
    ok = score(rules, None, config)
    failed = score(rules, LLMResult(LLMStatus.TIMEOUT, error="TimeoutError"), config)
    assert failed.mode is AnalysisMode.RULES_ONLY_FALLBACK and failed.degraded_confidence
    assert failed.confidence < ok.confidence


def test_thresholds_come_from_config(config, tmp_path):
    raw = open(config.path, encoding="utf-8").read().replace("medium = 30", "medium = 3")
    p = tmp_path / "c.toml"
    p.write_text(raw, encoding="utf-8")
    low_bar = load_config(p)
    assert tier_for(5, config) is Tier.LOW and tier_for(5, low_bar) is Tier.MEDIUM
    assert low_bar.config_hash != config.config_hash


def test_invalid_config_is_rejected(config):
    import pytest

    from scamshield.config import ConfigError, _validate

    with pytest.raises(ConfigError):
        _validate(dataclasses.replace(config, tiers=dataclasses.replace(config.tiers, high=10)))

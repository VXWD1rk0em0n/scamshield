"""Stage 3 - risk scoring.

final = rules_weight * rule_score + llm_weight * llm_score   (hybrid)
final = rule_score                                         (rules-only / fallback)

Then, in order:
1. combo floor  - a credential/payment request combined with impersonation is
                  never below ``scoring.combo_floor`` (default HIGH).
2. CRITICAL gate - CRITICAL requires that combo; otherwise capped at HIGH.
3. review cap   - if |rule_score - llm_score| >= disagreement_threshold the case
                  is marked needs_review and is never auto-escalated to CRITICAL.
If the message contains prompt-injection text and the LLM rated it *lower* than
the rules, the LLM verdict is treated as possibly manipulated and discarded.
All thresholds come from the config file.
"""

from __future__ import annotations

from scamshield.config import Config
from scamshield.models import AnalysisMode, Factor, LLMResult, RiskScore, RuleResult, Tier


def tier_for(score: int, config: Config) -> Tier:
    t = config.tiers
    if score >= t.critical:
        return Tier.CRITICAL
    if score >= t.high:
        return Tier.HIGH
    if score >= t.medium:
        return Tier.MEDIUM
    return Tier.LOW


def _threshold(tier: str, config: Config) -> int:
    return {"MEDIUM": config.tiers.medium, "HIGH": config.tiers.high, "CRITICAL": config.tiers.critical}[tier]


def score(rules: RuleResult, llm: LLMResult | None, config: Config) -> RiskScore:
    sc = config.scoring
    rule_score = rules.score
    adjustments: list[str] = []
    llm_score: int | None = None
    needs_review = False
    w_rules, w_llm = 1.0, 0.0

    if llm is not None and llm.ok:
        mode = AnalysisMode.HYBRID
        llm_score = round(llm.verdict.confidence * 100)  # type: ignore[union-attr]
        w_rules, w_llm = sc.rules_weight, sc.llm_weight
        if abs(rule_score - llm_score) >= sc.disagreement_threshold:
            needs_review = True
            adjustments.append(
                f"Rules ({rule_score}) and LLM ({llm_score}) disagree by >= {sc.disagreement_threshold} points: "
                "queued for analyst review"
            )
        # An LLM that rated an injection-bearing message lower than the rules *without*
        # noticing the injection may have been steered by it; don't let it pull the score down.
        if rules.fired("PROMPT_INJECTION") and llm_score < rule_score and not llm.verdict.injection_flagged:  # type: ignore[union-attr]
            w_rules, w_llm = 1.0, 0.0
            needs_review = True
            adjustments.append(
                "LLM verdict discarded: the message contains prompt-injection text the LLM did not flag, "
                "and the LLM rated it lower than the rules"
            )
    elif llm is not None and llm.status.is_failure:
        mode = AnalysisMode.RULES_ONLY_FALLBACK
        adjustments.append(f"LLM unavailable ({llm.status.value}); rules-only result with degraded confidence")
    else:
        mode = AnalysisMode.RULES_ONLY

    blended = w_rules * rule_score + w_llm * (llm_score or 0)
    final = max(0, min(100, round(blended)))

    if rules.critical_combo:
        floor = _threshold(sc.combo_floor, config)
        if final < floor:
            adjustments.append(f"Raised to {sc.combo_floor}: {rules.combo_reason}")
            final = floor

    tier = tier_for(final, config)
    if tier is Tier.CRITICAL and not rules.critical_combo:
        adjustments.append(
            "Capped at HIGH: CRITICAL requires a credential/payment request combined with impersonation"
        )
        tier, final = Tier.HIGH, config.tiers.critical - 1
    if tier is Tier.CRITICAL and needs_review:
        adjustments.append("Capped at HIGH: strong rules/LLM disagreement is never auto-escalated to CRITICAL")
        tier, final = Tier.HIGH, config.tiers.critical - 1

    # confidence: mode ceiling x agreement between engines x distance from nearest tier boundary
    cap = {
        AnalysisMode.HYBRID: sc.hybrid_confidence_cap,
        AnalysisMode.RULES_ONLY: sc.rules_only_confidence_cap,
        AnalysisMode.RULES_ONLY_FALLBACK: sc.fallback_confidence_cap,
    }[mode]
    agreement = 1.0 - abs(rule_score - llm_score) / 100 if llm_score is not None and w_llm > 0 else 1.0
    boundary = min(abs(final - t) for t in (config.tiers.medium, config.tiers.high, config.tiers.critical))
    margin = min(1.0, 0.5 + boundary / 20)
    confidence = round(cap * agreement * margin, 2)

    factors: list[Factor] = [
        Factor(h.name, "rule", round(h.weight * w_rules, 1), h.reason) for h in rules.hits
    ]
    if llm_score is not None and llm is not None and llm.verdict is not None:
        factors.append(
            Factor(
                "LLM_CLASSIFIER",
                "llm",
                round(llm_score * w_llm, 1),
                f"{llm.verdict.scam_type}, scam probability {llm.verdict.confidence:.2f}"
                + ("" if w_llm else " (discarded)"),
            )
        )
    factors.sort(key=lambda f: -abs(f.contribution))

    return RiskScore(
        score=final,
        tier=tier,
        confidence=confidence,
        mode=mode,
        rule_score=rule_score,
        llm_score=llm_score,
        needs_review=needs_review,
        degraded_confidence=mode is AnalysisMode.RULES_ONLY_FALLBACK,
        adjustments=tuple(adjustments),
        factors=tuple(factors),
    )

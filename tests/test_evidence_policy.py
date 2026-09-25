from __future__ import annotations

from conftest import ZW, msg
from scamshield.evidence import render_highlighted_html
from scamshield.models import Action, HighlightSpan, Tier


def test_spans_are_merged_non_overlapping_and_in_display_coordinates(rules_only):
    res = rules_only.analyze(msg(f"Chase: reply with your pass{ZW}word at https://chase-help-desk.com urgently"))
    spans = res.evidence.spans
    assert all(a.end <= b.start for a, b in zip(spans, spans[1:]))
    assert any(f"pass{ZW}word" in res.signals.display_text[s.start : s.end] for s in spans)


def test_html_rendering_escapes_everything():
    text = '<script>alert("x")</script> click'
    out = render_highlighted_html(text, (HighlightSpan(0, 8, "request", ('R03 "x"',)),))
    assert "<script>" not in out and "&lt;script&gt;" in out
    assert 'R03 &quot;x&quot;"' in out and "R03 \"x\"" not in out


def test_zero_width_rendered_visibly():
    out = render_highlighted_html(f"pass{ZW}word", (), (4,))
    assert "ss-zw" in out


def test_score_explanation_mentions_thresholds(rules_only):
    res = rules_only.analyze(msg("Congratulations! You won a $500 prize, claim your reward at https://bit.ly/abc"))
    assert "MEDIUM >= 30" in res.evidence.score_explanation and "Rules-only" in res.evidence.score_explanation


def test_policy_map(rules_only):
    low = rules_only.analyze(msg("Running late, see you at 7 at the restaurant!"))
    medium = rules_only.analyze(msg("Congratulations! You won a $500 prize, claim your reward at https://bit.ly/abc"))
    high = rules_only.analyze(
        msg("Microsoft Security Warning: your computer is infected! Call Windows Support immediately at "
            "+1-844-555-0187 and install AnyDesk.")
    )
    critical = rules_only.analyze(msg("PayPal: confirm your card details now at https://paypal-verify-help.com"))
    assert (low.tier, low.intervention.action) == (Tier.LOW, Action.ALLOW)
    assert (medium.tier, medium.intervention.action) == (Tier.MEDIUM, Action.SOFT_WARN)
    assert medium.intervention.tips and not medium.intervention.links_disabled
    assert (high.tier, high.intervention.action) == (Tier.HIGH, Action.INTERSTITIAL)
    assert high.intervention.links_disabled and high.intervention.requires_confirmation
    assert (critical.tier, critical.intervention.action) == (Tier.CRITICAL, Action.BLOCK_LINKS)
    assert critical.intervention.recommend_report and critical.intervention.checklist
    assert all(r.intervention.reversible for r in (low, medium, high, critical))


def test_insufficient_data_is_never_called_safe(rules_only):
    res = rules_only.analyze(msg("hi"))
    assert res.intervention.action is Action.UNABLE_TO_ANALYZE and "not a 'safe' verdict" in res.intervention.message

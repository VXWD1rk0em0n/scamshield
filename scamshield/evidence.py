"""Stage 4 - evidence: exact suspicious spans, rule explanations, LLM indicators,
and a plain-language account of how the score was reached."""

from __future__ import annotations

import html

from scamshield.config import Config
from scamshield.models import Evidence, HighlightSpan, LLMResult, RiskScore, RuleResult, Signals

# Higher wins when spans overlap.
CATEGORY_PRIORITY = {
    "request": 6,
    "impersonation": 5,
    "obfuscation": 4,
    "link": 3,
    "pressure": 2,
    "lure": 1,
    "benign": 0,
}
# Categorical hues (validated reference palette, fixed order). Highlights use a
# translucent tint of the hue plus a solid underline so text keeps its normal ink
# in light and dark themes; the label is always in the tooltip and the legend.
CATEGORY_COLORS = {
    "request": "#e34948",
    "impersonation": "#eb6834",
    "obfuscation": "#4a3aa7",
    "link": "#2a78d6",
    "pressure": "#eda100",
    "lure": "#e87ba4",
    "benign": "#008300",
}


def tint(hex_color: str, alpha: float = 0.22) -> str:
    h = hex_color.lstrip("#")
    r, g, b = (int(h[i : i + 2], 16) for i in (0, 2, 4))
    return f"rgba({r},{g},{b},{alpha})"


CATEGORY_LABELS = {
    "request": "Asks for money / codes",
    "impersonation": "Impersonation",
    "obfuscation": "Obfuscation / AI manipulation",
    "link": "Risky link",
    "pressure": "Pressure / secrecy",
    "lure": "Lure",
    "benign": "Reassuring signal",
}


def build_spans(signals: Signals, rules: RuleResult) -> tuple[HighlightSpan, ...]:
    """Merge overlapping rule spans into non-overlapping display segments."""
    raw: list[tuple[int, int, str, str]] = []
    for hit in rules.hits:
        for a, b in hit.spans:
            ds, de = signals.to_display(a, b)
            if de > ds:
                raw.append((ds, de, hit.category, f"{hit.rule_id} {hit.name}"))
    if not raw:
        return ()
    bounds = sorted({p for s, e, _, _ in raw for p in (s, e)})
    segments: list[HighlightSpan] = []
    for left, right in zip(bounds, bounds[1:]):
        covering = [r for r in raw if r[0] <= left and r[1] >= right]
        if not covering:
            continue
        category = max((c for _, _, c, _ in covering), key=lambda c: CATEGORY_PRIORITY.get(c, 0))
        labels = tuple(dict.fromkeys(label for *_, label in covering))
        prev = segments[-1] if segments else None
        if prev and prev.end == left and prev.category == category and prev.labels == labels:
            segments[-1] = HighlightSpan(prev.start, right, category, labels)
        else:
            segments.append(HighlightSpan(left, right, category, labels))
    return tuple(segments)


def explain_score(risk: RiskScore, config: Config, llm: LLMResult | None) -> str:
    t = config.tiers
    parts = [f"Score {risk.score}/100 -> {risk.tier.value} (thresholds: MEDIUM >= {t.medium}, HIGH >= {t.high}, CRITICAL >= {t.critical})."]
    if risk.llm_score is not None and llm and llm.verdict:
        wr, wl = config.scoring.rules_weight, config.scoring.llm_weight
        discarded = any("discarded" in a for a in risk.adjustments)
        if discarded:
            parts.append(f"Rules score {risk.rule_score} used alone; LLM score {risk.llm_score} was discarded.")
        else:
            parts.append(
                f"Hybrid: {wr:g} x rules {risk.rule_score} + {wl:g} x LLM {risk.llm_score} "
                f"= {wr * risk.rule_score + wl * risk.llm_score:.1f}."
            )
    else:
        parts.append(f"Rules-only: rule score {risk.rule_score} (sum of rule weights, clamped to 0-100).")
    for adj in risk.adjustments:
        parts.append(adj + ".")
    parts.append(f"Confidence {risk.confidence:.2f} ({risk.mode.value}{', degraded' if risk.degraded_confidence else ''}).")
    return " ".join(parts)


def build_evidence(
    signals: Signals, rules: RuleResult, llm: LLMResult | None, risk: RiskScore, config: Config
) -> Evidence:
    explanations = []
    for h in rules.hits:
        quote = f' - "{h.snippets[0]}"' if h.snippets else ""
        explanations.append(f"[{h.rule_id}] {h.reason} ({h.weight:+d}){quote}")
    verdict = llm.verdict if llm and llm.ok else None
    return Evidence(
        spans=build_spans(signals, rules),
        rule_explanations=tuple(explanations),
        llm_indicators=tuple(verdict.indicators) if verdict else (),
        llm_tactics=tuple(verdict.manipulation_tactics) if verdict else (),
        llm_rationale=verdict.rationale if verdict else None,
        score_explanation=explain_score(risk, config, llm),
        injection_detected=rules.fired("PROMPT_INJECTION") or bool(verdict and verdict.injection_flagged),
    )


def render_highlighted_html(text: str, spans: tuple[HighlightSpan, ...], zero_width_positions: tuple[int, ...] = ()) -> str:
    """HTML for the message with colour-coded spans. Every character is escaped;
    invisible characters are rendered as a visible marker so the user can see them."""
    zw = set(zero_width_positions)

    def esc(segment_start: int, segment: str) -> str:
        out = []
        for i, ch in enumerate(segment):
            if segment_start + i in zw:
                out.append('<span class="ss-zw" title="hidden zero-width character">&#9670;</span>')
            else:
                out.append(html.escape(ch))
        return "".join(out)

    pieces: list[str] = []
    pos = 0
    for sp in spans:
        if sp.start > pos:
            pieces.append(esc(pos, text[pos : sp.start]))
        color = CATEGORY_COLORS.get(sp.category, "#888888")
        title = html.escape(f"{CATEGORY_LABELS.get(sp.category, sp.category)}: " + "; ".join(sp.labels), quote=True)
        pieces.append(
            f'<mark class="ss-hl ss-{sp.category}" style="background:{tint(color)};'
            f'border-bottom:2px solid {color};color:inherit" title="{title}">'
            f"{esc(sp.start, text[sp.start:sp.end])}</mark>"
        )
        pos = sp.end
    if pos < len(text):
        pieces.append(esc(pos, text[pos:]))
    return "".join(pieces).replace("\n", "<br>")

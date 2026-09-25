"""Typed intermediate outputs passed between pipeline stages.

Every stage consumes and produces one of these frozen dataclasses, so each stage
can be unit-tested in isolation and the audit record can be built from them.
Offsets named ``*_start``/``*_end`` refer to ``Signals.analysis_text`` unless the
field says ``display``.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import TYPE_CHECKING

if TYPE_CHECKING:  # pragma: no cover
    from scamshield.llm_analyzer import LLMVerdict


class Channel(str, Enum):
    SMS = "sms"
    EMAIL = "email"
    CHAT = "chat"


class IngestStatus(str, Enum):
    OK = "OK"
    INSUFFICIENT_DATA = "INSUFFICIENT_DATA"


class Tier(str, Enum):
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"

    @property
    def rank(self) -> int:
        return ["LOW", "MEDIUM", "HIGH", "CRITICAL"].index(self.value)


class AnalysisMode(str, Enum):
    HYBRID = "hybrid"
    RULES_ONLY = "rules_only"  # LLM disabled, unavailable, or gated off by policy
    RULES_ONLY_FALLBACK = "rules_only_fallback"  # LLM was attempted and failed


class LLMStatus(str, Enum):
    OK = "ok"
    DISABLED = "disabled"  # no API key / turned off in config
    SKIPPED = "skipped"  # gated off by the "ambiguous only" policy
    TIMEOUT = "timeout"
    API_ERROR = "api_error"
    INVALID_JSON = "invalid_json"
    SCHEMA_ERROR = "schema_error"
    REFUSAL = "refusal"

    @property
    def is_failure(self) -> bool:
        return self in {
            LLMStatus.TIMEOUT,
            LLMStatus.API_ERROR,
            LLMStatus.INVALID_JSON,
            LLMStatus.SCHEMA_ERROR,
            LLMStatus.REFUSAL,
        }


class Action(str, Enum):
    ALLOW = "ALLOW"
    SOFT_WARN = "SOFT_WARN"
    INTERSTITIAL = "INTERSTITIAL"
    BLOCK_LINKS = "BLOCK_LINKS"
    UNABLE_TO_ANALYZE = "UNABLE_TO_ANALYZE"


# --------------------------------------------------------------------------- ingest


@dataclass(frozen=True)
class MessageInput:
    text: str | bytes
    channel: Channel = Channel.SMS
    sender_id: str | None = None
    claimed_sender: str | None = None
    known_contact: bool = False


@dataclass(frozen=True)
class ExtractedURL:
    raw: str
    start: int
    end: int
    host: str  # lower-cased, homoglyph-mapped, IDNA-decoded where possible
    registrable_domain: str  # approximate eTLD+1
    is_shortener: bool
    is_ip_literal: bool
    is_punycode: bool
    has_homoglyphs: bool = False  # host was spelled with look-alike Unicode letters


@dataclass(frozen=True)
class Entity:
    kind: str  # phone | amount | crypto | email
    value: str
    start: int
    end: int


@dataclass(frozen=True)
class ObfuscationReport:
    zero_width_removed: int = 0
    in_word_zero_width: int = 0
    bidi_controls: int = 0
    homoglyph_chars: int = 0
    mixed_script_words: tuple[str, ...] = ()
    compat_chars: int = 0  # math-alphanumeric / fullwidth letters folded by NFKC
    zero_width_display_positions: tuple[int, ...] = ()

    @property
    def detected(self) -> bool:
        return bool(
            self.in_word_zero_width
            or self.bidi_controls
            or self.mixed_script_words
            or self.compat_chars >= 3
        )


@dataclass(frozen=True)
class Signals:
    status: IngestStatus
    quality_flags: tuple[str, ...]
    channel: Channel
    sender_id: str | None
    claimed_sender: str | None
    known_contact: bool
    display_text: str  # NFKC-normalised, truncated; what the user sees
    analysis_text: str  # zero-width stripped + homoglyphs mapped; what rules read
    offset_map: tuple[int, ...]  # analysis index -> display index (len = len(analysis)+1)
    original_length: int
    truncated: bool = False
    urls: tuple[ExtractedURL, ...] = ()
    phones: tuple[Entity, ...] = ()
    emails: tuple[Entity, ...] = ()
    amounts: tuple[Entity, ...] = ()
    crypto_addresses: tuple[Entity, ...] = ()
    obfuscation: ObfuscationReport = field(default_factory=ObfuscationReport)

    @property
    def ok(self) -> bool:
        return self.status is IngestStatus.OK

    def to_display(self, start: int, end: int) -> tuple[int, int]:
        """Map an analysis-text span to display-text offsets."""
        if not self.offset_map:
            return start, end
        start = max(0, min(start, len(self.offset_map) - 1))
        end = max(start, min(end, len(self.offset_map) - 1))
        d_start = self.offset_map[start]
        # end is exclusive: map the last included char and step past it
        d_end = self.offset_map[end - 1] + 1 if end > start else d_start
        return d_start, d_end


# --------------------------------------------------------------------------- rules


@dataclass(frozen=True)
class RuleHit:
    rule_id: str
    name: str
    category: str
    weight: int
    reason: str
    spans: tuple[tuple[int, int], ...] = ()  # analysis-text offsets
    snippets: tuple[str, ...] = ()


@dataclass(frozen=True)
class RuleResult:
    hits: tuple[RuleHit, ...]
    raw_score: int
    score: int  # clamped 0..100
    critical_combo: bool
    combo_reason: str | None
    ruleset_version: str

    def fired(self, name: str) -> bool:
        return any(h.name == name for h in self.hits)

    def hit(self, name: str) -> RuleHit | None:
        return next((h for h in self.hits if h.name == name), None)


# --------------------------------------------------------------------------- llm


@dataclass(frozen=True)
class LLMResult:
    status: LLMStatus
    verdict: "LLMVerdict | None" = None
    model: str | None = None
    latency_ms: float = 0.0
    error: str | None = None  # short class/kind only, never message content

    @property
    def ok(self) -> bool:
        return self.status is LLMStatus.OK and self.verdict is not None


# --------------------------------------------------------------------------- scoring


@dataclass(frozen=True)
class Factor:
    name: str
    source: str  # rule | llm | context | policy
    contribution: float  # signed points on the 0..100 scale
    detail: str


@dataclass(frozen=True)
class RiskScore:
    score: int
    tier: Tier
    confidence: float
    mode: AnalysisMode
    rule_score: int
    llm_score: int | None
    needs_review: bool
    degraded_confidence: bool
    adjustments: tuple[str, ...]  # floors / caps / discounts applied, human readable
    factors: tuple[Factor, ...]


# --------------------------------------------------------------------------- evidence


@dataclass(frozen=True)
class HighlightSpan:
    start: int  # display-text offsets
    end: int
    category: str
    labels: tuple[str, ...]


@dataclass(frozen=True)
class Evidence:
    spans: tuple[HighlightSpan, ...]
    rule_explanations: tuple[str, ...]
    llm_indicators: tuple[str, ...]
    llm_tactics: tuple[str, ...]
    llm_rationale: str | None
    score_explanation: str
    injection_detected: bool


# --------------------------------------------------------------------------- policy


@dataclass(frozen=True)
class Intervention:
    action: Action
    tier: Tier | None
    headline: str
    message: str
    tips: tuple[str, ...] = ()
    checklist: tuple[str, ...] = ()
    links_disabled: bool = False
    requires_confirmation: bool = False
    recommend_report: bool = False
    review_note: str | None = None
    reversible: bool = True


# --------------------------------------------------------------------------- result


@dataclass(frozen=True)
class AnalysisResult:
    case_id: str
    timestamp: str
    signals: Signals
    rules: RuleResult | None
    llm: LLMResult | None
    risk: RiskScore | None
    evidence: Evidence | None
    intervention: Intervention
    masked_text: str
    latency_ms: float
    model_version: str
    config_hash: str
    source: dict | None = None  # {"source": "image", "ocr_engine": ...} for screenshot/photo input

    @property
    def tier(self) -> Tier | None:
        return self.risk.tier if self.risk else None

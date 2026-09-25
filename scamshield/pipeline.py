"""End-to-end orchestration: ingest -> rules -> LLM -> scoring -> evidence -> policy -> audit."""

from __future__ import annotations

import dataclasses
import logging
import time
import uuid
from datetime import datetime, timezone

from scamshield import RULESET_VERSION, __version__
from scamshield.audit import AuditStore
from scamshield.config import Config, load_config
from scamshield.evidence import build_evidence
from scamshield.image_ingest import ImageExtraction, OCREngine, extract_text
from scamshield.ingest import ingest, insufficient_signals
from scamshield.llm_analyzer import LLMAnalyzer
from scamshield.models import AnalysisResult, Channel, LLMResult, LLMStatus, MessageInput
from scamshield.pii import mask_sender, mask_text
from scamshield.policy import decide
from scamshield.rules import run_rules
from scamshield.scoring import score

log = logging.getLogger("scamshield.pipeline")


class Analyzer:
    def __init__(
        self,
        config: Config | None = None,
        *,
        llm: LLMAnalyzer | None = None,
        store: AuditStore | None = None,
        use_llm: bool = True,
    ) -> None:
        self.config = config or load_config()
        self.llm = llm if llm is not None else LLMAnalyzer(self.config)
        self.store = store
        self.use_llm = use_llm

    def model_version(self, llm_result: LLMResult | None) -> str:
        llm_part = llm_result.model if llm_result and llm_result.status is LLMStatus.OK else "rules-only"
        return f"scamshield-{__version__}/{RULESET_VERSION}/{llm_part}"

    def _llm_step(self, rule_score: int, signals, masked: str) -> LLMResult | None:
        if not self.use_llm:
            return None
        if not self.llm.available:
            return LLMResult(LLMStatus.DISABLED)
        cfg = self.config.llm
        if cfg.policy == "ambiguous" and not (cfg.ambiguous_min <= rule_score <= cfg.ambiguous_max):
            return LLMResult(LLMStatus.SKIPPED, model=self.llm.model)
        return self.llm.analyze(signals, masked)

    def analyze_image(
        self,
        data: bytes,
        *,
        channel: Channel = Channel.SMS,
        sender_id: str | None = None,
        claimed_sender: str | None = None,
        known_contact: bool = False,
        user_id: str | None = "demo-user",
        record: bool = True,
        engine: OCREngine | None = None,
    ) -> tuple[AnalysisResult, ImageExtraction]:
        """Screenshot/photo -> text (local OCR by default) -> the normal text pipeline.

        The image is never stored; only the masked extracted text and OCR metadata are audited."""
        extraction = extract_text(data, self.config.image, engine)
        msg = MessageInput(
            text=extraction.text,
            channel=channel,
            sender_id=sender_id or extraction.sender_hint,
            claimed_sender=claimed_sender,
            known_contact=known_contact,
        )
        precheck = () if extraction.ok else (extraction.quality_flags or ("no_text_in_image",))
        result = self.analyze(
            msg,
            user_id=user_id,
            record=record,
            source=extraction.audit_meta(),
            precheck_flags=precheck,
            extra_flags=tuple(f for f in extraction.quality_flags if extraction.ok),
        )
        return result, extraction

    def analyze(
        self,
        msg: MessageInput,
        *,
        user_id: str | None = "demo-user",
        record: bool = True,
        source: dict | None = None,
        precheck_flags: tuple[str, ...] = (),
        extra_flags: tuple[str, ...] = (),
    ) -> AnalysisResult:
        started = time.perf_counter()
        case_id = uuid.uuid4().hex[:12]
        timestamp = datetime.now(timezone.utc).isoformat(timespec="seconds")

        signals = insufficient_signals(msg, precheck_flags) if precheck_flags else ingest(msg, self.config)
        if extra_flags:
            signals = dataclasses.replace(signals, quality_flags=signals.quality_flags + tuple(extra_flags))
        # masking runs on the display text; mask_text strips invisible chars first
        masked = mask_text(signals.display_text).text if signals.display_text else ""

        rules = risk = evidence = llm_result = None
        if signals.ok:
            trusted = bool(self.store and self.store.is_trusted(user_id, msg.sender_id))
            rules = run_rules(signals, self.config, trusted_sender=trusted)
            llm_result = self._llm_step(rules.score, signals, masked)
            risk = score(rules, llm_result, self.config)
            evidence = build_evidence(signals, rules, llm_result, risk, self.config)
        intervention = decide(signals, risk, rules)

        result = AnalysisResult(
            case_id=case_id,
            timestamp=timestamp,
            signals=signals,
            rules=rules,
            llm=llm_result,
            risk=risk,
            evidence=evidence,
            intervention=intervention,
            masked_text=masked,
            latency_ms=(time.perf_counter() - started) * 1000,
            model_version=self.model_version(llm_result),
            config_hash=self.config.config_hash,
            source=source,
        )
        if record and self.store is not None:
            self.store.record(
                result,
                user_id=user_id,
                sender_masked=mask_sender(msg.sender_id),
                claimed_masked=mask_text(msg.claimed_sender).text if msg.claimed_sender else None,
            )
        log.info(
            "analysis_complete",
            extra={
                "case_id": case_id,
                "status": signals.status.value,
                "quality_flags": list(signals.quality_flags),
                "tier": risk.tier.value if risk else None,
                "score": risk.score if risk else None,
                "mode": risk.mode.value if risk else None,
                "needs_review": risk.needs_review if risk else None,
                "llm_status": llm_result.status.value if llm_result else None,
                "rule_ids": [h.rule_id for h in rules.hits] if rules else [],
                "action": intervention.action.value,
                "latency_ms": round(result.latency_ms, 1),
                "config_hash": self.config.config_hash,
            },
        )
        return result

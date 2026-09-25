"""Every one-click demo case in the UI behaves as its label promises."""

from __future__ import annotations

import pytest

from scamshield.config import REPO_ROOT
from scamshield.demo_cases import DEMO_CASES
from scamshield.image_ingest import LocalOCR
from scamshield.llm_analyzer import LLMAnalyzer
from scamshield.models import AnalysisMode, Channel, MessageInput
from scamshield.pipeline import Analyzer


def _timeout(system, user):
    raise TimeoutError


@pytest.mark.parametrize("case", DEMO_CASES, ids=[c["title"] for c in DEMO_CASES])
def test_demo_case_matches_expectation(config, case):
    simulate = case.get("simulate")
    llm = None
    if simulate == "timeout":
        llm = LLMAnalyzer(config, completion_fn=_timeout)
    elif simulate == "garbage":
        llm = LLMAnalyzer(config, completion_fn=lambda s, u: "{not json")
    analyzer = Analyzer(config, llm=llm, use_llm=llm is not None)
    if "image" in case:
        if not LocalOCR.available():
            pytest.skip("rapidocr-onnxruntime not installed")
        res, _ = analyzer.analyze_image((REPO_ROOT / "assets" / "demo" / case["image"]).read_bytes(), record=False)
        assert res.tier.value == case["expect_tier"]
        return
    res = analyzer.analyze(
        MessageInput(case.get("bytes", case.get("text")), Channel(case["channel"]), case.get("sender"),
                     case.get("claimed"), case.get("known", False)),
        record=False,
    )
    assert (res.tier.value if res.tier else None) == case["expect_tier"]
    if simulate:
        assert res.risk.mode is AnalysisMode.RULES_ONLY_FALLBACK and res.risk.degraded_confidence

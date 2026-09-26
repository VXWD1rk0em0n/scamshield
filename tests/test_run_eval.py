"""eval/run_eval.py - metric helpers used for the published numbers."""

from __future__ import annotations

import pytest

from eval.run_eval import binary_metrics, misclassified, percentile, word_recall
from scamshield.models import Tier


def rec(label, tier, **kw):
    return {"label": label, "tier": tier, "id": kw.get("id", "x"), "rules": [], "score": 0, "llm_score": None,
            "quality_flags": [], "split": "dev", "category": "c", "masked_text": ""} | kw


def test_binary_metrics_counts_and_rates():
    records = [rec("scam", "CRITICAL"), rec("scam", "MEDIUM"), rec("scam", "LOW"), rec("legit", "LOW"), rec("legit", "HIGH")]
    warn = binary_metrics(records, Tier.MEDIUM)
    assert (warn["tp"], warn["fn"], warn["fp"], warn["tn"]) == (2, 1, 1, 1)
    assert warn["precision"] == pytest.approx(2 / 3, abs=1e-3) and warn["recall"] == pytest.approx(2 / 3, abs=1e-3)
    assert warn["false_positive_rate"] == 0.5
    interrupt = binary_metrics(records, Tier.HIGH)
    assert (interrupt["tp"], interrupt["fn"]) == (1, 2)


def test_insufficient_counts_as_not_flagged_and_empty_is_safe():
    assert binary_metrics([rec("scam", "INSUFFICIENT")], Tier.MEDIUM)["fn"] == 1
    assert binary_metrics([], Tier.MEDIUM)["precision"] == 0.0


def test_percentile_interpolates():
    assert percentile([10, 20, 30, 40], 50) == 25
    assert percentile([5], 95) == 5
    assert percentile([], 50) == 0.0


def test_word_recall_counts_multiset_words_as_seen_on_screen():
    assert word_recall("Pay the fee now", "pay the fee now") == 1.0
    assert word_recall("the the fee", "the fee") == pytest.approx(2 / 3)
    assert word_recall("pass​word", "password") == 1.0  # zero-width is invisible on screen


def test_misclassified_lists_both_error_types():
    out = misclassified({"records": [rec("scam", "LOW", id="a"), rec("legit", "MEDIUM", id="b"), rec("scam", "HIGH", id="c")]})
    assert [(r["id"], r["error"].split(" ")[0]) for r in out] == [("a", "false"), ("b", "false")]
    assert out[0]["error"].startswith("false negative") and out[1]["error"].startswith("false positive")

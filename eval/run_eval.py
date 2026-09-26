"""Evaluate ScamShield on eval/dataset.jsonl.

    python -m eval.run_eval                  # rules-only + hybrid (hybrid skipped without API credentials)
    python -m eval.run_eval --modes rules    # rules-only
    python -m eval.run_eval --split holdout
    python -m eval.run_eval --modes rules image   # image: render each message as a phone screenshot -> local OCR -> pipeline

Writes eval/results.json (read by the Streamlit Metrics tab) and eval/report.md.
Positive class = scam. Two operating points are reported:
  * warn      - flagged when tier >= MEDIUM (any warning shown)
  * interrupt - flagged when tier >= HIGH   (links disabled / interstitial)
INSUFFICIENT_DATA counts as "not flagged".
"""

from __future__ import annotations

import argparse
import json
import re
import statistics
import sys
import time
from collections import Counter, defaultdict
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from dotenv import load_dotenv  # noqa: E402

from scamshield.config import load_config  # noqa: E402
from scamshield.ingest import parse_channel  # noqa: E402
from scamshield.llm_analyzer import LLMAnalyzer  # noqa: E402
from scamshield.models import MessageInput, Tier  # noqa: E402
from scamshield.pii import mask_text  # noqa: E402
from scamshield.pipeline import Analyzer  # noqa: E402

from eval.screenshots import render_message, screen_text  # noqa: E402

EVAL_DIR = Path(__file__).resolve().parent
TIERS = ["INSUFFICIENT", "LOW", "MEDIUM", "HIGH", "CRITICAL"]
OPERATING_POINTS = {"warn": Tier.MEDIUM, "interrupt": Tier.HIGH}


def load_dataset(path: Path, split: str = "all") -> list[dict]:
    rows = [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines() if line.strip()]
    return [r for r in rows if split == "all" or r.get("split") == split]


def percentile(values: list[float], pct: float) -> float:
    if not values:
        return 0.0
    ordered = sorted(values)
    k = (len(ordered) - 1) * pct / 100
    lo, hi = int(k), min(int(k) + 1, len(ordered) - 1)
    return ordered[lo] + (ordered[hi] - ordered[lo]) * (k - lo)


def binary_metrics(records: list[dict], min_tier: Tier) -> dict:
    tp = fp = tn = fn = 0
    for r in records:
        flagged = r["tier"] not in (None, "INSUFFICIENT") and Tier(r["tier"]).rank >= min_tier.rank
        scam = r["label"] == "scam"
        tp += flagged and scam
        fp += flagged and not scam
        tn += not flagged and not scam
        fn += not flagged and scam
    precision = tp / (tp + fp) if tp + fp else 0.0
    recall = tp / (tp + fn) if tp + fn else 0.0
    f1 = 2 * precision * recall / (precision + recall) if precision + recall else 0.0
    fpr = fp / (fp + tn) if fp + tn else 0.0
    return {
        "tp": tp, "fp": fp, "tn": tn, "fn": fn,
        "precision": round(precision, 3), "recall": round(recall, 3), "f1": round(f1, 3),
        "false_positive_rate": round(fpr, 3), "accuracy": round((tp + tn) / max(1, len(records)), 3),
    }


def word_recall(source: str, ocr: str) -> float:
    """Share of the on-screen words that OCR recovered (case-insensitive, punctuation-stripped)."""
    tok = lambda t: re.findall(r"[a-z0-9]+", t.lower())  # noqa: E731
    src, got = tok(screen_text(source)), tok(ocr)
    if not src:
        return 1.0
    pool = got.copy()
    hits = 0
    for w in src:
        if w in pool:
            pool.remove(w)
            hits += 1
    return hits / len(src)


def run_mode(mode: str, rows: list[dict]) -> dict:
    config = load_config()
    analyzer = Analyzer(config, use_llm=(mode == "hybrid"))
    if mode == "hybrid" and not analyzer.llm.available:
        return {"mode": mode, "skipped": True, "reason": "no Anthropic credentials (set ANTHROPIC_API_KEY in .env)"}
    if mode == "image":
        from scamshield.image_ingest import LocalOCR

        if not LocalOCR.available():
            return {"mode": mode, "skipped": True, "reason": "rapidocr-onnxruntime not installed"}

    records = []
    for row in rows:
        msg = MessageInput(
            text=row["text"],
            channel=parse_channel(row.get("channel")),
            sender_id=row.get("sender_id"),
            claimed_sender=row.get("claimed_sender"),
            known_contact=bool(row.get("known_contact")),
        )
        t0 = time.perf_counter()
        ocr_recall = None
        if mode == "image":
            # screenshot only: the user supplies the picture and the channel, no sender metadata
            png = render_message(row["text"], row.get("sender_id"))
            res, extraction = analyzer.analyze_image(png, channel=msg.channel, record=False)
            ocr_recall = round(word_recall(row["text"], extraction.text), 3)
        else:
            res = analyzer.analyze(msg, record=False)
        latency = (time.perf_counter() - t0) * 1000
        records.append(
            {
                "id": row["id"],
                "split": row.get("split", "dev"),
                "label": row["label"],
                "category": row["category"],
                "tier": res.tier.value if res.tier else "INSUFFICIENT",
                "score": res.risk.score if res.risk else None,
                "rule_score": res.risk.rule_score if res.risk else None,
                "llm_score": res.risk.llm_score if res.risk else None,
                "llm_status": res.llm.status.value if res.llm else None,
                "llm_type": res.llm.verdict.scam_type if res.llm and res.llm.ok else None,
                "needs_review": res.risk.needs_review if res.risk else False,
                "combo": res.rules.critical_combo if res.rules else False,
                "rules": [f"{h.rule_id}:{h.name}({h.weight:+d})" for h in res.rules.hits] if res.rules else [],
                "adjustments": list(res.risk.adjustments) if res.risk else [],
                "quality_flags": list(res.signals.quality_flags),
                "masked_text": mask_text(row["text"]).text[:220],
                "latency_ms": round(latency, 2),
                "ocr_word_recall": ocr_recall,
            }
        )

    latencies = [r["latency_ms"] for r in records]
    confusion = {lab: Counter() for lab in ("scam", "legit")}
    for r in records:
        confusion[r["label"]][r["tier"]] += 1
    by_split: dict[str, dict] = {}
    for split in sorted({r["split"] for r in records}):
        subset = [r for r in records if r["split"] == split]
        by_split[split] = {name: binary_metrics(subset, t) for name, t in OPERATING_POINTS.items()} | {"n": len(subset)}
    per_category: dict[str, dict] = defaultdict(lambda: {"n": 0, "warned": 0, "interrupted": 0})
    for r in records:
        c = per_category[f"{r['label']}:{r['category']}"]
        c["n"] += 1
        c["warned"] += r["tier"] in ("MEDIUM", "HIGH", "CRITICAL")
        c["interrupted"] += r["tier"] in ("HIGH", "CRITICAL")

    return {
        "mode": mode,
        "skipped": False,
        "model": analyzer.llm.model if mode == "hybrid" else None,
        "n": len(records),
        "n_scam": sum(r["label"] == "scam" for r in records),
        "n_legit": sum(r["label"] == "legit" for r in records),
        "operating_points": {name: binary_metrics(records, t) for name, t in OPERATING_POINTS.items()},
        "by_split": by_split,
        "confusion_label_by_tier": {lab: {t: confusion[lab].get(t, 0) for t in TIERS} for lab in confusion},
        "latency_ms": {
            "p50": round(percentile(latencies, 50), 2),
            "p95": round(percentile(latencies, 95), 2),
            "mean": round(statistics.fmean(latencies), 2) if latencies else 0.0,
        },
        "llm_status_counts": dict(Counter(r["llm_status"] for r in records if r["llm_status"])),
        "ocr_word_recall_mean": (
            round(statistics.fmean(r["ocr_word_recall"] for r in records), 3) if mode == "image" else None
        ),
        "needs_review": sum(r["needs_review"] for r in records),
        "per_category": dict(sorted(per_category.items())),
        "records": records,
        "config_hash": load_config().config_hash,
    }


def misclassified(result: dict) -> list[dict]:
    """Errors at the 'warn' operating point plus scams that were warned but not interrupted."""
    out = []
    for r in result.get("records", []):
        warned = r["tier"] in ("MEDIUM", "HIGH", "CRITICAL")
        if r["label"] == "scam" and not warned:
            out.append(r | {"error": "false negative (no warning)"})
        elif r["label"] == "legit" and warned:
            out.append(r | {"error": f"false positive ({r['tier']})"})
    return out


def _auto_analysis(r: dict, config) -> str:
    fired = [x.split("(")[0] for x in r["rules"]]
    if r["error"].startswith("false negative"):
        if r["tier"] == "INSUFFICIENT":
            return f"Rejected by data-quality gate ({', '.join(r['quality_flags'])}); no analysis ran."
        gap = config.tiers.medium - (r["score"] or 0)
        what = ", ".join(fired) if fired else "no rule"
        llm = f" LLM said {r['llm_type']} ({r['llm_score']})." if r["llm_score"] is not None else ""
        return (
            f"Only {what} fired (score {r['score']}, {gap} below MEDIUM).{llm} "
            "No credential/payment request or impersonation signal was matched, so the lure is invisible to the rules."
        )
    return f"Fired: {', '.join(fired) or 'none'} (score {r['score']}). These patterns also occur in benign messages of this kind."


def write_report(results: list[dict], path: Path, notes: dict[str, str]) -> None:
    config = load_config()
    lines = [
        "# ScamShield evaluation report",
        "",
        f"Generated {datetime.now(timezone.utc).isoformat(timespec='seconds')} - config `{config.config_hash}` - "
        f"thresholds MEDIUM >= {config.tiers.medium}, HIGH >= {config.tiers.high}, CRITICAL >= {config.tiers.critical}.",
        "",
        "Positive class = scam. **warn** = flagged at tier >= MEDIUM (any warning). "
        "**interrupt** = flagged at tier >= HIGH (links disabled). The dataset is synthetic; see LIMITATIONS.md.",
        "",
        "## Summary",
        "",
        "| Mode | Split | n | Op. point | Precision | Recall | F1 | FPR | TP | FP | TN | FN |",
        "|---|---|---|---|---|---|---|---|---|---|---|---|",
    ]
    for res in results:
        if res.get("skipped"):
            lines.append(f"| {res['mode']} | - | - | - | skipped: {res['reason']} | | | | | | | |")
            continue
        for split, block in [("all", res["operating_points"] | {"n": res["n"]})] + list(res["by_split"].items()):
            for op in OPERATING_POINTS:
                m = block[op]
                lines.append(
                    f"| {res['mode']} | {split} | {block['n']} | {op} | {m['precision']:.3f} | {m['recall']:.3f} | "
                    f"{m['f1']:.3f} | {m['false_positive_rate']:.3f} | {m['tp']} | {m['fp']} | {m['tn']} | {m['fn']} |"
                )
    for res in results:
        if res.get("skipped"):
            continue
        lines += [
            "",
            f"## {res['mode']}" + (f" ({res['model']})" if res.get("model") else ""),
            "",
            f"Latency per message: p50 **{res['latency_ms']['p50']} ms**, p95 **{res['latency_ms']['p95']} ms** "
            f"(mean {res['latency_ms']['mean']} ms). Cases marked needs_review: {res['needs_review']}."
            + (f" LLM status counts: {res['llm_status_counts']}." if res["llm_status_counts"] else "")
            + (
                f" Image mode: each message rendered as a phone screenshot, read by local OCR, no sender metadata; "
                f"mean OCR word recall {res['ocr_word_recall_mean']:.3f}. OCR latency inside eval runs depends on machine "
                "load (other processes compete for the CPU); standalone warm OCR measures about 1.7-3 s per image."
                if res.get("ocr_word_recall_mean") is not None
                else ""
            ),
            "",
            "### Confusion matrix (label x tier)",
            "",
            "| label \\ tier | " + " | ".join(TIERS) + " |",
            "|---|" + "---|" * len(TIERS),
        ]
        for lab, row in res["confusion_label_by_tier"].items():
            lines.append(f"| {lab} | " + " | ".join(str(row[t]) for t in TIERS) + " |")
        w = res["operating_points"]["warn"]
        lines += [
            "",
            "Binary confusion at the warn point:",
            "",
            "| | predicted scam | predicted legit |",
            "|---|---|---|",
            f"| actual scam | {w['tp']} | {w['fn']} |",
            f"| actual legit | {w['fp']} | {w['tn']} |",
            "",
            "### Per category (warned / interrupted / n)",
            "",
            "| category | warned | interrupted | n |",
            "|---|---|---|---|",
        ]
        for cat, c in res["per_category"].items():
            lines.append(f"| {cat} | {c['warned']} | {c['interrupted']} | {c['n']} |")
        errors = misclassified(res)
        lines += ["", f"### Error analysis ({len(errors)} misclassification(s) at the warn point)", ""]
        if not errors:
            lines.append("No misclassifications at the warn point.")
        for r in errors:
            lines += [
                f"**{r['id']}** ({r['split']}, {r['category']}) - {r['error']}, tier {r['tier']}, score {r['score']}",
                "",
                f"> {r['masked_text']}",
                "",
                f"- Automated: {_auto_analysis(r, config)}",
            ]
            if r["id"] in notes:
                lines.append(f"- Analysis: {notes[r['id']]}")
            lines.append("")
        under = [r for r in res["records"] if r["label"] == "scam" and r["tier"] == "MEDIUM"]
        if under:
            lines += [
                f"#### Scams warned (MEDIUM) but not interrupted ({len(under)})",
                "",
                "Not errors at the warn point, but the user only sees a soft warning. For each: what fired and why it stopped short of HIGH.",
                "",
            ]
            for r in under:
                fired = [x.split(":")[1].split("(")[0] for x in r["rules"]]
                has_request = any(f in fired for f in ("CREDENTIAL_REQUEST", "PAYMENT_METHOD", "P2P_TRANSFER_REQUEST", "PAYMENT_REDIRECTION", "UPFRONT_FEE"))
                has_imp = any(f in fired for f in ("LOOKALIKE_DOMAIN", "SENDER_MISMATCH", "NEW_NUMBER_FAMILY"))
                why = (
                    "request without impersonation evidence, so the HIGH floor did not apply"
                    if has_request and not has_imp
                    else "impersonation/pressure signals without a credential or payment request"
                    if not has_request
                    else "combined weight stayed below the HIGH threshold"
                )
                lines.append(f"- **{r['id']}** ({r['category']}, score {r['score']}): {', '.join(fired) or 'no rules'} - {why}.")
            lines.append("")
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--modes", nargs="+", default=["rules", "hybrid"], choices=["rules", "hybrid", "image"])
    parser.add_argument("--split", default="all", choices=["all", "dev", "holdout"])
    parser.add_argument("--dataset", default=str(EVAL_DIR / "dataset.jsonl"))
    parser.add_argument("--out-dir", default=str(EVAL_DIR))
    parser.add_argument("--merge", action="store_true", help="keep previous results for modes not re-run")
    args = parser.parse_args(argv)

    load_dotenv(ROOT / ".env")
    rows = load_dataset(Path(args.dataset), args.split)
    results = [run_mode(m, rows) for m in args.modes]
    out = Path(args.out_dir)
    previous = out / "results.json"
    if args.merge and previous.exists():
        old = json.loads(previous.read_text(encoding="utf-8"))
        if old.get("split") == args.split:
            fresh = {r["mode"] for r in results}
            results += [r for r in old.get("results", []) if r["mode"] not in fresh]
            results.sort(key=lambda r: ["rules", "image", "hybrid"].index(r["mode"]))
    notes_file = EVAL_DIR / "error_notes.json"
    notes = json.loads(notes_file.read_text(encoding="utf-8")) if notes_file.exists() else {}
    payload = {"generated": datetime.now(timezone.utc).isoformat(timespec="seconds"), "split": args.split, "results": results}
    (out / "results.json").write_text(json.dumps(payload, indent=2), encoding="utf-8")
    write_report(results, out / "report.md", notes)

    for res in results:
        if res.get("skipped"):
            print(f"[{res['mode']}] skipped - {res['reason']}")
            continue
        for op, m in res["operating_points"].items():
            print(
                f"[{res['mode']}:{op}] n={res['n']} P={m['precision']:.3f} R={m['recall']:.3f} F1={m['f1']:.3f} "
                f"FPR={m['false_positive_rate']:.3f} | latency p50={res['latency_ms']['p50']}ms p95={res['latency_ms']['p95']}ms"
            )
    print(f"wrote {out / 'results.json'} and {out / 'report.md'}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

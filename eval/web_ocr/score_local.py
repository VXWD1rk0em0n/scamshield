"""Streamlit app path: realistic screenshots -> local OCR (RapidOCR) -> pipeline, vs pasted text.

    python eval/web_ocr/score_local.py
"""

from __future__ import annotations

import json
import statistics
import sys
import time
from collections import defaultdict
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))

from eval.web_ocr.score import WARN, word_recall  # noqa: E402
from scamshield.config import load_config  # noqa: E402
from scamshield.ingest import parse_channel  # noqa: E402
from scamshield.models import MessageInput  # noqa: E402
from scamshield.pipeline import Analyzer  # noqa: E402


def main() -> None:
    analyzer = Analyzer(load_config(), use_llm=False)
    screens = ROOT / "eval" / "screens"
    manifest = json.loads((screens / "manifest.json").read_text(encoding="utf-8"))
    per_variant: dict[str, list] = defaultdict(list)
    for m in manifest:
        t = analyzer.analyze(MessageInput(m["text"], parse_channel(m["channel"])), record=False)
        started = time.perf_counter()
        res, ex = analyzer.analyze_image((screens / m["file"]).read_bytes(), channel=parse_channel(m["channel"]), record=False)
        tier, text_tier = (res.tier.value if res.tier else "INSUFFICIENT"), t.tier.value
        per_variant[m["variant"]].append({
            "recall": word_recall(m["screen_text"], ex.text), "tier": tier == text_tier,
            "warn": (tier in WARN) == (text_tier in WARN), "ms": (time.perf_counter() - started) * 1000,
            "flip": f"{m['id']}:{text_tier}->{tier}",
        })
    allr = [x for v in per_variant.values() for x in v]
    print(f"=== local OCR: word recall {statistics.fmean(x['recall'] for x in allr):.3f} | same tier {sum(x['tier'] for x in allr)}/{len(allr)}"
          f" | same warn {sum(x['warn'] for x in allr)}/{len(allr)} | median {statistics.median(x['ms'] for x in allr):.0f} ms")
    for v, xs in per_variant.items():
        print(f"  {v:16} recall {statistics.fmean(x['recall'] for x in xs):.3f}  tier {sum(x['tier'] for x in xs):2}/{len(xs)}  warn {sum(x['warn'] for x in xs):2}/{len(xs)}")
    flips = [x["flip"] for x in allr if not x["warn"]]
    if flips:
        print("  warn flips:", ", ".join(flips))


if __name__ == "__main__":
    main()

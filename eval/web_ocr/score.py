"""Score OCR benchmark output through the real web API path.

    python eval/web_ocr/score.py [config ...]

For every screenshot: OCR lines -> scamshield.web.parse_request (same line assembly,
chrome cleanup and sender hint as the site) -> pipeline -> tier. Compared against the
tier the same message gets when pasted as text with the same (screenshot-only) info:
channel, no typed sender.
"""

from __future__ import annotations

import json
import re
import statistics
import sys
from collections import defaultdict
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))

from eval.screenshots import screen_text  # noqa: E402
from scamshield.config import load_config  # noqa: E402
from scamshield.ingest import parse_channel  # noqa: E402
from scamshield.models import MessageInput  # noqa: E402
from scamshield.pipeline import Analyzer  # noqa: E402
from scamshield.web import parse_request  # noqa: E402

OUT = Path(__file__).resolve().parent / "out"
WARN = {"MEDIUM", "HIGH", "CRITICAL"}


def words(t: str) -> list[str]:
    return re.findall(r"[a-z0-9]+", t.lower())


def word_recall(truth: str, got: str) -> float:
    src, pool = words(truth), words(got)
    hits = 0
    for w in src:
        if w in pool:
            pool.remove(w)
            hits += 1
    return hits / max(1, len(src))


def domains(t: str) -> set[str]:
    return set(re.findall(r"[a-z0-9-]+(?:\.[a-z0-9-]+)*\.(?:com|net|org|info|xyz|top|shop|app|co|io|support)\b", t.lower()))


def main(configs: list[str]) -> None:
    analyzer = Analyzer(load_config(), use_llm=False)
    manifest = {m["file"]: m for m in json.loads((ROOT / "eval" / "screens" / "manifest.json").read_text(encoding="utf-8"))}
    text_tier: dict[str, str] = {}
    for m in manifest.values():
        if m["id"] not in text_tier:
            r = analyzer.analyze(MessageInput(m["text"], parse_channel(m["channel"])), record=False)
            text_tier[m["id"]] = r.tier.value if r.tier else "INSUFFICIENT"
    for cfg in configs:
        rows = json.loads((OUT / f"{cfg}.json").read_text(encoding="utf-8"))
        per_variant: dict[str, list] = defaultdict(list)
        for row in rows:
            m = manifest[row["file"]]
            msg, source = parse_request({"ocr": {"lines": row["lines"][:400]}, "channel": m["channel"]})
            res = analyzer.analyze(msg, record=False, source=source, extra_flags=("from_image",))
            tier = res.tier.value if res.tier else "INSUFFICIENT"
            truth = m["screen_text"]
            dom_truth = domains(truth)
            per_variant[m["variant"]].append(
                {
                    "recall": word_recall(truth, msg.text if isinstance(msg.text, str) else ""),
                    "tier_match": tier == text_tier[m["id"]],
                    "warn_match": (tier in WARN) == (text_tier[m["id"]] in WARN),
                    "domain_ok": dom_truth <= domains(msg.text) if dom_truth else True,
                    "label": m["label"],
                    "ms": row["ms"],
                    "id": m["id"],
                    "tier": tier,
                    "text_tier": text_tier[m["id"]],
                }
            )
        allr = [x for v in per_variant.values() for x in v]
        print(f"\n=== {cfg}: word recall {statistics.fmean(x['recall'] for x in allr):.3f} | "
              f"same tier as text {sum(x['tier_match'] for x in allr)}/{len(allr)} | "
              f"same warn decision {sum(x['warn_match'] for x in allr)}/{len(allr)} | "
              f"link domains exact {sum(x['domain_ok'] for x in allr)}/{len(allr)} | "
              f"median {statistics.median(x['ms'] for x in allr):.0f} ms")
        for variant, xs in per_variant.items():
            print(f"  {variant:16} recall {statistics.fmean(x['recall'] for x in xs):.3f}  tier {sum(x['tier_match'] for x in xs):2}/{len(xs)}"
                  f"  warn {sum(x['warn_match'] for x in xs):2}/{len(xs)}  domains {sum(x['domain_ok'] for x in xs):2}/{len(xs)}")
        misses = [x for x in allr if not x["warn_match"]]
        if misses:
            print("  warn-decision flips:", ", ".join(f"{x['id']}:{x['text_tier']}->{x['tier']}" for x in misses[:12]))


if __name__ == "__main__":
    main(sys.argv[1:] or sorted(p.stem for p in OUT.glob("*.json")))

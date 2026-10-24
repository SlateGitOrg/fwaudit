"""Score fwaudit against synthetic firmware ground truth.

Usage::

    uv run python scripts/evaluate.py --split holdout --seeds 0-99 --out results/eval-holdout.json

For each seed a firmware image is generated with :func:`fwaudit.synth.firmware.generate`,
audited with default limits and the fixed reference time, and the reported findings are
matched against the planted ground truth (see :mod:`fwaudit.evaluation`). ``--hostile``
adds the hostile extraction samples. The script prints a Markdown table and writes the
full result (including every false positive / false negative) as JSON.
"""

from __future__ import annotations

import argparse
import json
import sys
import time
from pathlib import Path

from fwaudit.audit.base import AuditConfig
from fwaudit.evaluation import Score
from fwaudit.pipeline import AuditOptions, audit_bytes
from fwaudit.synth import hostile
from fwaudit.synth.firmware import REFERENCE_TIME, Sample, generate


def parse_seeds(text: str) -> list[int]:
    lo, _, hi = text.partition("-")
    return list(range(int(lo), int(hi or lo) + 1))


def run(samples: list[Sample]) -> tuple[Score, dict[str, object]]:
    options = AuditOptions(config=AuditConfig(reference_time=REFERENCE_TIME))
    score = Score()
    expected_total = 0
    started = time.perf_counter()
    image_bytes = 0
    for sample in samples:
        result = audit_bytes(sample.image, sample.name, options)
        if result.check_errors:
            raise SystemExit(f"{sample.name}: check errors {result.check_errors}")
        score.add(sample.name, result.findings, sample.expected)
        expected_total += len(sample.expected)
        image_bytes += len(sample.image)
    elapsed = time.perf_counter() - started
    stats: dict[str, object] = {
        "samples": len(samples),
        "expected_findings": expected_total,
        "image_bytes": image_bytes,
        "elapsed_seconds": round(elapsed, 2),
    }
    return score, stats


def to_json(score: Score, stats: dict[str, object], label: str) -> dict[str, object]:
    t = score.totals
    return {
        "label": label,
        **stats,
        "totals": {
            "tp": t.tp,
            "fp": t.fp,
            "fn": t.fn,
            "precision": round(t.precision, 4),
            "recall": round(t.recall, 4),
        },
        "per_rule": {
            rule: {
                "tp": r.tp,
                "fp": r.fp,
                "fn": r.fn,
                "precision": round(r.precision, 4),
                "recall": round(r.recall, 4),
            }
            for rule, r in sorted(score.per_rule.items())
        },
        "false_positives": [[s, list(k[:3]), list(k[3])] for s, k in score.false_positives],
        "false_negatives": [[s, list(k[:3]), list(k[3])] for s, k in score.false_negatives],
    }


def markdown(doc: dict[str, object]) -> str:
    totals = doc["totals"]
    assert isinstance(totals, dict)
    lines = [
        f"### {doc['label']}: {doc['samples']} images, {doc['expected_findings']} planted "
        f"findings, {doc['elapsed_seconds']} s",
        "",
        "| Rule | TP | FP | FN | Precision | Recall |",
        "|---|---:|---:|---:|---:|---:|",
    ]
    per_rule = doc["per_rule"]
    assert isinstance(per_rule, dict)
    for rule, r in per_rule.items():
        lines.append(
            f"| {rule} | {r['tp']} | {r['fp']} | {r['fn']} | {r['precision']:.3f} | "
            f"{r['recall']:.3f} |"
        )
    lines.append(
        f"| **all** | {totals['tp']} | {totals['fp']} | {totals['fn']} | "
        f"{totals['precision']:.3f} | {totals['recall']:.3f} |"
    )
    misses = doc["false_negatives"]
    extras = doc["false_positives"]
    assert isinstance(misses, list)
    assert isinstance(extras, list)
    for title, items in (("False negatives", misses), ("False positives", extras)):
        if items:
            lines += ["", f"{title}:", ""]
            lines += [f"- `{s}`: {k[0]} {k[1]} ({k[2]}) {cves or ''}" for s, k, cves in items]
    return "\n".join(lines) + "\n"


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(description=__doc__.splitlines()[0] if __doc__ else None)
    p.add_argument("--split", choices=["dev", "holdout"], default="holdout")
    p.add_argument("--seeds", type=parse_seeds, default=parse_seeds("0-99"))
    p.add_argument("--hostile", action="store_true", help="score the hostile samples instead")
    p.add_argument("--out", type=Path, help="write the JSON result here")
    args = p.parse_args(argv)
    if args.hostile:
        samples = hostile.all_samples()
        label = "hostile extraction samples"
    else:
        samples = [generate(seed, args.split) for seed in args.seeds]
        label = f"{args.split} split, seeds {args.seeds[0]}-{args.seeds[-1]}"
    score, stats = run(samples)
    doc = to_json(score, stats, label)
    sys.stdout.write(markdown(doc))
    if args.out is not None:
        args.out.parent.mkdir(parents=True, exist_ok=True)
        args.out.write_text(json.dumps(doc, indent=2, sort_keys=True) + "\n")
    return 0


if __name__ == "__main__":
    sys.exit(main())

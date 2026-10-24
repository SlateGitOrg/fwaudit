"""Throughput and safety benchmarks for fwaudit.

Usage::

    uv run python scripts/bench.py --out results/bench.json

Measures (median of ``--repeat`` runs, wall clock):

* entropy-map and signature-scan throughput on a 64 MiB buffer of mixed content
  (random, zero-filled and text blocks);
* full audit time per synthetic firmware layout (dev seeds 0..4, one per layout);
* time and peak traced Python allocation (``tracemalloc``) while auditing each hostile
  decompression-bomb sample, which shows that the bounded decoders stop early instead of
  materialising the full payload.
"""

from __future__ import annotations

import argparse
import json
import platform
import random
import statistics
import sys
import time
import tracemalloc
from collections.abc import Callable
from functools import partial
from pathlib import Path

from fwaudit.audit.base import AuditConfig
from fwaudit.entropy import entropy_map
from fwaudit.pipeline import AuditOptions, audit_bytes
from fwaudit.signatures import scan
from fwaudit.synth import hostile
from fwaudit.synth.firmware import LAYOUTS, REFERENCE_TIME, generate

MiB = 1024 * 1024


def mixed_buffer(size: int, seed: int = 7) -> bytes:
    rng = random.Random(seed)
    text = b"Linux version 4.14 eth0 probe mtd spi nand irq sched " * 80
    out = bytearray()
    while len(out) < size:
        kind = rng.randrange(3)
        if kind == 0:
            out += rng.randbytes(64 * 1024)
        elif kind == 1:
            out += b"\xff" * (64 * 1024)
        else:
            out += (text * 16)[: 64 * 1024]
    return bytes(out[:size])


def median_time(fn: Callable[[], object], repeat: int) -> float:
    times = []
    for _ in range(repeat):
        start = time.perf_counter()
        fn()
        times.append(time.perf_counter() - start)
    return statistics.median(times)


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(description="fwaudit benchmarks")
    p.add_argument("--repeat", type=int, default=5)
    p.add_argument("--size-mib", type=int, default=64)
    p.add_argument("--out", type=Path)
    args = p.parse_args(argv)

    buf = mixed_buffer(args.size_mib * MiB)
    t_entropy = median_time(lambda: entropy_map(buf), args.repeat)
    t_scan = median_time(lambda: scan(buf), args.repeat)
    raw = {
        "buffer_mib": args.size_mib,
        "entropy_map_mib_per_s": round(args.size_mib / t_entropy, 1),
        "signature_scan_mib_per_s": round(args.size_mib / t_scan, 1),
    }

    options = AuditOptions(config=AuditConfig(reference_time=REFERENCE_TIME))
    layouts = []
    for seed in range(len(LAYOUTS)):
        sample = generate(seed, "dev")
        t = median_time(partial(audit_bytes, sample.image, sample.name, options), args.repeat)
        layouts.append(
            {
                "sample": sample.name,
                "image_kib": round(len(sample.image) / 1024, 1),
                "audit_ms": round(t * 1000, 1),
            }
        )

    bombs = []
    for sample in hostile.all_samples():
        if sample.name not in ("hostile-gzip-bomb", "hostile-xz-bomb", "hostile-nesting"):
            continue
        tracemalloc.start()
        start = time.perf_counter()
        result = audit_bytes(sample.image, sample.name, options)
        elapsed = time.perf_counter() - start
        _, peak = tracemalloc.get_traced_memory()
        tracemalloc.stop()
        bombs.append(
            {
                "sample": sample.name,
                "image_bytes": len(sample.image),
                "declared_payload_mib": hostile.BOMB_BYTES // MiB
                if "bomb" in sample.name
                else None,
                "audit_ms": round(elapsed * 1000, 1),
                "peak_traced_mib": round(peak / MiB, 1),
                "extracted_bytes": result.budget_bytes,
                "rules": sorted({f.rule_id for f in result.findings}),
            }
        )

    doc = {
        "machine": f"{platform.system()} {platform.machine()}, Python {platform.python_version()}",
        "repeat": args.repeat,
        "raw_throughput": raw,
        "audit_per_layout": layouts,
        "hostile": bombs,
    }
    print(f"machine: {doc['machine']} (median of {args.repeat} runs)")
    print(
        f"entropy map: {raw['entropy_map_mib_per_s']} MiB/s, signature scan: "
        f"{raw['signature_scan_mib_per_s']} MiB/s ({args.size_mib} MiB mixed buffer)"
    )
    print("\n| Sample | Image (KiB) | Audit (ms) |\n|---|---:|---:|")
    for row in layouts:
        print(f"| {row['sample']} | {row['image_kib']} | {row['audit_ms']} |")
    print("\n| Hostile sample | Input bytes | Audit (ms) | Peak traced MiB | Rules |")
    print("|---|---:|---:|---:|---|")
    for row in bombs:
        rules = ", ".join(row["rules"])  # type: ignore[arg-type]
        print(
            f"| {row['sample']} | {row['image_bytes']} | {row['audit_ms']} | "
            f"{row['peak_traced_mib']} | {rules} |"
        )
    if args.out is not None:
        args.out.parent.mkdir(parents=True, exist_ok=True)
        args.out.write_text(json.dumps(doc, indent=2) + "\n")
    return 0


if __name__ == "__main__":
    sys.exit(main())

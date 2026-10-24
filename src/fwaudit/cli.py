"""Command-line interface: ``fwaudit scan | identify | entropy | synth | rules``."""

from __future__ import annotations

import argparse
import json
import logging
import re
import sys
from collections.abc import Sequence
from dataclasses import replace
from datetime import UTC, datetime
from pathlib import Path

from fwaudit import __version__
from fwaudit.audit.base import AuditConfig
from fwaudit.entropy import entropy_map
from fwaudit.errors import FwauditError
from fwaudit.extract.disk import materialize
from fwaudit.limits import Limits, MiB
from fwaudit.model import RULES, Severity
from fwaudit.pipeline import AuditOptions, AuditResult, audit_file
from fwaudit.report import jsonreport, markdown
from fwaudit.signatures import scan

log = logging.getLogger("fwaudit")

EXIT_OK = 0
EXIT_FINDINGS = 1
EXIT_ERROR = 2


def _parse_time(text: str) -> datetime:
    try:
        value = datetime.fromisoformat(text)
    except ValueError:
        raise argparse.ArgumentTypeError(f"not an ISO-8601 date/time: {text!r}") from None
    return value if value.tzinfo else value.replace(tzinfo=UTC)


def _parse_seeds(text: str) -> list[int]:
    m = re.fullmatch(r"(\d+)(?:-(\d+))?", text)
    if m is None:
        raise argparse.ArgumentTypeError("seeds must look like 7 or 0-19")
    lo = int(m.group(1))
    hi = int(m.group(2) or lo)
    if hi < lo or hi - lo > 10_000:
        raise argparse.ArgumentTypeError("invalid seed range")
    return list(range(lo, hi + 1))


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="fwaudit",
        description="Offline firmware image auditor (identification, safe extraction, "
        "filesystem security checks).",
    )
    p.add_argument("--version", action="version", version=f"fwaudit {__version__}")
    p.add_argument("-v", "--verbose", action="count", default=0, help="-v info, -vv debug")
    sub = p.add_subparsers(dest="command", required=True)

    s = sub.add_parser("scan", help="identify, extract and audit an image")
    s.add_argument("image", type=Path)
    s.add_argument("--json", dest="json_out", type=Path, help="write JSON report ('-' = stdout)")
    s.add_argument("--markdown", dest="md_out", type=Path, help="write Markdown report")
    s.add_argument("--extract-to", type=Path, help="also write extracted filesystems here")
    s.add_argument(
        "--reference-time",
        type=_parse_time,
        help="time used for certificate expiry (default: now, UTC)",
    )
    s.add_argument("--show-secrets", action="store_true", help="do not mask recovered secrets")
    s.add_argument(
        "--fail-on",
        type=Severity.parse,
        metavar="SEVERITY",
        help="exit 1 if any finding is at or above this severity",
    )
    s.add_argument("--max-depth", type=int, default=Limits.max_depth)
    s.add_argument("--max-total-mb", type=int, default=Limits.max_total_bytes // MiB)
    s.add_argument("--max-ratio", type=int, default=Limits.max_ratio)
    s.add_argument("--entropy-block", type=int, default=4096)

    i = sub.add_parser("identify", help="list recognised signatures in an image")
    i.add_argument("image", type=Path)

    e = sub.add_parser("entropy", help="print the entropy map of an image")
    e.add_argument("image", type=Path)
    e.add_argument("--block", type=int, default=4096)
    e.add_argument("--width", type=int, default=64)

    g = sub.add_parser("synth", help="write synthetic firmware images with ground truth")
    g.add_argument("outdir", type=Path)
    g.add_argument("--seeds", type=_parse_seeds, default=[0])
    g.add_argument("--split", choices=["dev", "holdout"], default="dev")
    g.add_argument("--hostile", action="store_true", help="also write hostile extraction samples")

    sub.add_parser("rules", help="list the rule catalogue")
    return p


def _summary(result: AuditResult) -> str:
    lines = [
        f"fwaudit {__version__}: {result.image.name} ({result.image.size} bytes, "
        f"sha256 {result.image.sha256[:16]}...)",
        f"  filesystems: {len(result.extraction.filesystems)}, extraction nodes: "
        f"{len(result.extraction.nodes)}, extracted bytes: {result.budget_bytes}",
        f"  entropy: {result.entropy.sparkline(48)}",
        f"  findings: {len(result.findings)}",
    ]
    for f in result.findings:
        where = f.path or (f"@{f.offset:#x}" if f.offset is not None else "")
        lines.append(f"  [{f.severity.name:<8}] {f.rule_id:<12} {where}  {f.detail}")
    return "\n".join(lines)


def _write(path: Path, text: str) -> None:
    if str(path) == "-":
        sys.stdout.write(text)
    else:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text)


def cmd_scan(args: argparse.Namespace) -> int:
    limits = Limits(
        max_depth=args.max_depth,
        max_total_bytes=args.max_total_mb * MiB,
        max_ratio=args.max_ratio,
    )
    config = AuditConfig(show_secrets=args.show_secrets)
    if args.reference_time is not None:
        config = replace(config, reference_time=args.reference_time)
    result = audit_file(args.image, AuditOptions(limits, config, args.entropy_block))
    if args.json_out is not None:
        _write(args.json_out, jsonreport.render(result))
    if args.md_out is not None:
        _write(args.md_out, markdown.render(result))
    if args.json_out is None or str(args.json_out) != "-":
        print(_summary(result))
    if args.extract_to is not None:
        for fs in result.extraction.filesystems:
            safe = re.sub(r"[^A-Za-z0-9_.@-]+", "_", fs.fs_id).strip("_")
            res = materialize(fs, args.extract_to / safe)
            log.info("extracted %s: %d files, %d dirs", res.root, res.files, res.dirs)
    if args.fail_on is not None and any(f.severity >= args.fail_on for f in result.findings):
        return EXIT_FINDINGS
    return EXIT_OK


def cmd_identify(args: argparse.Namespace) -> int:
    data = args.image.read_bytes()
    print(f"{'OFFSET':>12}  {'TYPE':<12} DESCRIPTION")
    for hit in scan(data):
        extra = ", ".join(f"{k}={v}" for k, v in sorted(hit.meta.items()))
        flag = "" if hit.supported else " [unsupported]"
        print(f"{hit.offset:#12x}  {hit.name:<12} {hit.description}{flag}  {extra}")
    return EXIT_OK


def cmd_entropy(args: argparse.Namespace) -> int:
    emap = entropy_map(args.image.read_bytes(), args.block)
    print(emap.sparkline(args.width))
    print(f"mean {emap.mean:.3f} bits/byte over {len(emap.values)} blocks of {emap.block_size}")
    for r in emap.regions:
        print(f"  {r.start:#10x}-{r.end:#10x}  {r.kind:<5}  {r.mean_entropy:.3f}")
    return EXIT_OK


def cmd_synth(args: argparse.Namespace) -> int:
    from fwaudit.synth import hostile  # noqa: PLC0415 - synth is only needed here
    from fwaudit.synth.firmware import generate  # noqa: PLC0415

    args.outdir.mkdir(parents=True, exist_ok=True)
    samples = [generate(seed, args.split) for seed in args.seeds]
    if args.hostile:
        samples += hostile.all_samples()
    for s in samples:
        (args.outdir / f"{s.name}.bin").write_bytes(s.image)
        truth = json.dumps(s.manifest(), indent=2) + "\n"
        (args.outdir / f"{s.name}.truth.json").write_text(truth)
        print(f"{s.name}.bin  {len(s.image):>8} bytes  {len(s.expected)} expected findings")
    return EXIT_OK


def cmd_rules(_: argparse.Namespace) -> int:
    for r in RULES.values():
        print(f"{r.rule_id:<13} {r.severity.name:<8} {r.category:<12} {r.title}")
    return EXIT_OK


def main(argv: Sequence[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    level = logging.WARNING - 10 * min(args.verbose, 2)
    logging.basicConfig(level=level, format="%(levelname)s %(name)s: %(message)s")
    handlers = {
        "scan": cmd_scan,
        "identify": cmd_identify,
        "entropy": cmd_entropy,
        "synth": cmd_synth,
        "rules": cmd_rules,
    }
    try:
        return handlers[args.command](args)
    except (FwauditError, OSError) as exc:
        log.error("%s", exc)
        return EXIT_ERROR


if __name__ == "__main__":  # pragma: no cover
    sys.exit(main())

"""End-to-end audit: read image -> entropy map -> extraction -> checks -> result."""

from __future__ import annotations

import hashlib
import logging
import time
from dataclasses import dataclass, field
from pathlib import Path

from fwaudit.audit import AuditConfig, Check, default_checks, run_checks
from fwaudit.audit.keys import KeyAnalyzer
from fwaudit.entropy import EntropyMap, entropy_map
from fwaudit.errors import LimitExceededError
from fwaudit.extract.engine import ExtractionResult, Extractor
from fwaudit.limits import Limits
from fwaudit.model import Finding

log = logging.getLogger(__name__)


@dataclass(frozen=True)
class ImageInfo:
    name: str
    size: int
    sha256: str


@dataclass(frozen=True)
class AuditOptions:
    limits: Limits = field(default_factory=Limits)
    config: AuditConfig = field(default_factory=AuditConfig)
    entropy_block_size: int = 4096


@dataclass
class AuditResult:
    image: ImageInfo
    options: AuditOptions
    entropy: EntropyMap
    extraction: ExtractionResult
    findings: list[Finding]
    check_errors: list[str]
    budget_bytes: int
    budget_entries: int
    budget_carves: int
    elapsed_seconds: float


def dedupe(findings: list[Finding]) -> list[Finding]:
    """Drop exact duplicates (same identity key) and sort most-severe first."""
    unique: dict[str, Finding] = {}
    for f in findings:
        unique.setdefault(f.key, f)
    return sorted(unique.values(), key=lambda f: f.sort_key())


def audit_bytes(
    data: bytes,
    name: str = "image",
    options: AuditOptions | None = None,
    checks: list[Check] | None = None,
) -> AuditResult:
    """Audit an in-memory firmware image."""
    opts = options or AuditOptions()
    if len(data) > opts.limits.max_image_bytes:
        raise LimitExceededError(
            "max_image_bytes", f"image is {len(data)} bytes; limit {opts.limits.max_image_bytes}"
        )
    started = time.perf_counter()
    info = ImageInfo(name=name, size=len(data), sha256=hashlib.sha256(data).hexdigest())
    emap = entropy_map(data, opts.entropy_block_size)
    extractor = Extractor(opts.limits)
    extraction = extractor.run(data)
    findings = list(extraction.findings)
    errors: list[str] = []
    active = checks if checks is not None else default_checks()
    for fs in extraction.filesystems:
        run = run_checks(fs, opts.config, active)
        findings.extend(run.findings)
        errors.extend(run.errors)
    analyzer = KeyAnalyzer(opts.config)
    for region in extraction.raw_regions:
        if extraction.nodes[region.node_id].kind == "file":
            continue  # whole file was already scanned by the keys check
        findings.extend(
            analyzer.analyze(
                region.data, filesystem=region.node_id, path=None, base_offset=region.offset
            )
        )
    elapsed = time.perf_counter() - started
    log.info(
        "audited %s: %d filesystems, %d findings in %.2fs",
        name,
        len(extraction.filesystems),
        len(findings),
        elapsed,
    )
    return AuditResult(
        image=info,
        options=opts,
        entropy=emap,
        extraction=extraction,
        findings=dedupe(findings),
        check_errors=errors,
        budget_bytes=extractor.budget.total_bytes,
        budget_entries=extractor.budget.entries,
        budget_carves=extractor.budget.carves,
        elapsed_seconds=elapsed,
    )


def audit_file(
    path: str | Path, options: AuditOptions | None = None, checks: list[Check] | None = None
) -> AuditResult:
    """Audit a firmware image on disk (size is checked before reading)."""
    p = Path(path)
    opts = options or AuditOptions()
    size = p.stat().st_size
    if size > opts.limits.max_image_bytes:
        raise LimitExceededError(
            "max_image_bytes", f"{p.name} is {size} bytes; limit {opts.limits.max_image_bytes}"
        )
    return audit_bytes(p.read_bytes(), p.name, opts, checks)

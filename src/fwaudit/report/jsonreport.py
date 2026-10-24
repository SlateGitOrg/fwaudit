"""Machine-readable report (schema ``fwaudit-report/1``).

The output is deterministic for a given image and settings: keys are sorted, findings
are ordered by severity then location, and no wall-clock timestamps are included (the
certificate reference time is an explicit setting).
"""

from __future__ import annotations

import json
from collections import Counter, defaultdict
from dataclasses import asdict
from typing import Any

from fwaudit import __version__
from fwaudit.model import RULES, Finding, Severity
from fwaudit.pipeline import AuditResult

SCHEMA_ID = "fwaudit-report/1"


def finding_to_json(f: Finding) -> dict[str, Any]:
    return {
        "id": f.finding_id,
        "rule_id": f.rule_id,
        "severity": f.severity.label,
        "category": str(f.category),
        "title": f.title,
        "detail": f.detail,
        "filesystem": f.filesystem,
        "path": f.path,
        "offset": f.offset,
        "evidence": {k: v for k, v in sorted(f.evidence.items()) if k != "key"},
        "remediation": RULES[f.rule_id].remediation,
    }


def _components(findings: list[Finding]) -> list[dict[str, Any]]:
    inventory: dict[tuple[str, str, str], dict[str, Any]] = {}
    for f in findings:
        if f.rule_id not in ("FWA-CMP-001", "FWA-CMP-002"):
            continue
        key = (f.filesystem, str(f.evidence.get("component")), str(f.evidence.get("version")))
        entry = inventory.setdefault(
            key,
            {
                "filesystem": key[0],
                "component": key[1],
                "version": key[2],
                "paths": f.evidence.get("paths", []),
                "cves": [],
            },
        )
        if f.rule_id == "FWA-CMP-002":
            raw = f.evidence.get("cves", [])
            if isinstance(raw, list):
                entry["cves"] = [c["id"] for c in raw if isinstance(c, dict)]
    return [inventory[k] for k in sorted(inventory)]


def _shared_keys(findings: list[Finding]) -> list[dict[str, Any]]:
    by_fp: dict[str, list[str]] = defaultdict(list)
    for f in findings:
        fp = f.evidence.get("fingerprint")
        if f.rule_id == "FWA-KEY-001" and isinstance(fp, str):
            where = f"{f.filesystem}:{f.path}" if f.path else f"{f.filesystem}@{f.offset:#x}"
            by_fp[fp].append(where)
    return [
        {"fingerprint": fp, "locations": sorted(locs)}
        for fp, locs in sorted(by_fp.items())
        if len(locs) > 1
    ]


def to_dict(result: AuditResult) -> dict[str, Any]:
    findings = result.findings
    sev = Counter(f.severity.label for f in findings)
    cat = Counter(str(f.category) for f in findings)
    highest = max((f.severity for f in findings), default=None)
    limits = asdict(result.options.limits)
    ext = result.extraction
    filesystems = []
    for fs in ext.filesystems:
        node = ext.nodes[fs.fs_id]
        filesystems.append(
            {
                "id": fs.fs_id,
                "format": fs.source_kind,
                "offset": node.offset,
                "entries": len(fs),
                "files": node.meta.get("files", 0),
                "file_bytes": fs.total_bytes,
                "rejected_members": len(fs.rejections),
            }
        )
    emap = result.entropy
    return {
        "schema": SCHEMA_ID,
        "tool": {"name": "fwaudit", "version": __version__},
        "image": {
            "name": result.image.name,
            "size": result.image.size,
            "sha256": result.image.sha256,
        },
        "settings": {
            "reference_time": result.options.config.reference_time.isoformat(),
            "show_secrets": result.options.config.show_secrets,
            "entropy_block_size": emap.block_size,
            "limits": limits,
        },
        "summary": {
            "findings": len(findings),
            "highest_severity": highest.label if highest is not None else None,
            "by_severity": {s.label: sev.get(s.label, 0) for s in reversed(Severity)},
            "by_category": dict(sorted(cat.items())),
            "filesystems": len(filesystems),
            "extracted_bytes": result.budget_bytes,
            "archive_entries": result.budget_entries,
            "carved_regions": result.budget_carves,
        },
        "entropy": {
            "block_size": emap.block_size,
            "mean": round(emap.mean, 3),
            "sparkline": emap.sparkline(),
            "regions": [
                {"start": r.start, "end": r.end, "kind": r.kind, "mean_entropy": r.mean_entropy}
                for r in emap.regions
            ],
        },
        "extraction": [n.to_json() for n in ext.nodes.values()],
        "filesystems": filesystems,
        "components": _components(findings),
        "shared_keys": _shared_keys(findings),
        "findings": [finding_to_json(f) for f in findings],
        "check_errors": list(result.check_errors),
    }


def render(result: AuditResult) -> str:
    return json.dumps(to_dict(result), indent=2, sort_keys=True) + "\n"

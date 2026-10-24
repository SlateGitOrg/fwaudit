"""Human-readable Markdown report."""

from __future__ import annotations

from typing import Any

from fwaudit.model import Severity
from fwaudit.pipeline import AuditResult
from fwaudit.report.jsonreport import to_dict

_ICON = {"critical": "CRITICAL", "high": "HIGH", "medium": "MEDIUM", "low": "LOW", "info": "INFO"}


def _cell(value: object) -> str:
    text = "" if value is None else str(value)
    return text.replace("|", "\\|").replace("\n", " ")


def _tree(nodes: list[dict[str, Any]]) -> list[str]:
    by_id = {n["id"]: n for n in nodes}
    lines: list[str] = []

    def walk(node_id: str, indent: int) -> None:
        n = by_id[node_id]
        meta = n["meta"]
        bits = [f"`{n['kind']}` @ {n['offset']:#x}", f"{n['length']} bytes"]
        for key in ("name", "type", "compression", "variant", "decompressed_size", "files", "path"):
            if key in meta:
                bits.append(f"{key}={meta[key]}")
        if meta.get("header_crc_ok") is False or meta.get("data_crc_ok") is False:
            bits.append("**CRC mismatch**")
        lines.append("  " * indent + "- " + ", ".join(bits))
        for note in n["notes"]:
            lines.append("  " * (indent + 1) + f"- note: {_cell(note)}")
        for child in n["children"]:
            walk(child, indent + 1)

    roots = [n["id"] for n in nodes if n["parent"] is None]
    for r in roots:
        walk(r, 0)
    return lines


def render(result: AuditResult) -> str:
    doc = to_dict(result)
    s = doc["summary"]
    out: list[str] = [
        f"# fwaudit report: {doc['image']['name']}",
        "",
        "| | |",
        "|---|---|",
        f"| Image size | {doc['image']['size']} bytes |",
        f"| SHA-256 | `{doc['image']['sha256']}` |",
        f"| Reference time | {doc['settings']['reference_time']} |",
        f"| Filesystems mounted | {s['filesystems']} |",
        f"| Findings | {s['findings']} (highest: {s['highest_severity'] or 'none'}) |",
        f"| fwaudit | {doc['tool']['version']} |",
        "",
        "## Severity summary",
        "",
        "| Severity | Count |",
        "|---|---|",
    ]
    out += [f"| {sev} | {n} |" for sev, n in s["by_severity"].items()]
    out += [
        "",
        "## Entropy map",
        "",
        f"Block size {doc['entropy']['block_size']} bytes, mean "
        f"{doc['entropy']['mean']} bits/byte (0 = blank, 8 = random).",
        "",
        "```",
        doc["entropy"]["sparkline"] or "(empty image)",
        "```",
        "",
        "| Start | End | Class | Mean entropy |",
        "|---|---|---|---|",
    ]
    out += [
        f"| {r['start']:#x} | {r['end']:#x} | {r['kind']} | {r['mean_entropy']} |"
        for r in doc["entropy"]["regions"][:40]
    ]
    out += ["", "## Extraction tree", "", *_tree(doc["extraction"])]
    if doc["components"]:
        out += [
            "",
            "## Components",
            "",
            "| Component | Version | CVEs (offline subset) | Paths |",
            "|---|---|---|---|",
        ]
        for c in doc["components"]:
            cves = ", ".join(c["cves"]) or "none known"
            out.append(
                f"| {c['component']} | {c['version']} | {cves} | {_cell(', '.join(c['paths']))} |"
            )
    if doc["shared_keys"]:
        out += ["", "## Private keys present in more than one location", ""]
        for k in doc["shared_keys"]:
            out.append(
                f"- `{k['fingerprint']}`: " + ", ".join(f"`{loc}`" for loc in k["locations"])
            )
    out += ["", "## Findings", ""]
    if not doc["findings"]:
        out.append("No findings.")
    for sev in reversed(Severity):
        group = [f for f in doc["findings"] if f["severity"] == sev.label]
        if not group:
            continue
        out += [f"### {_ICON[sev.label]} ({len(group)})", ""]
        for f in group:
            where = f["path"] or (f"offset {f['offset']:#x}" if f["offset"] is not None else "")
            out.append(f"- **{f['rule_id']}** {f['title']}: `{_cell(where)}`")
            out.append(f"  - {_cell(f['detail'])}")
            out.append(f"  - filesystem: `{f['filesystem']}`")
            out.append(f"  - fix: {_cell(f['remediation'])}")
        out.append("")
    if doc["check_errors"]:
        out += ["## Check errors", ""] + [f"- {_cell(e)}" for e in doc["check_errors"]]
    return "\n".join(out).rstrip() + "\n"

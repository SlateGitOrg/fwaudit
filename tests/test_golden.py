"""Golden report: a fixed synthetic image must produce a byte-identical JSON report.

Regenerate after an intentional change with ``make golden``.
"""

from __future__ import annotations

import json
from pathlib import Path

from fwaudit.pipeline import AuditOptions, audit_bytes
from fwaudit.report import jsonreport
from fwaudit.synth.firmware import generate

GOLDEN = Path(__file__).parent / "golden" / "dev-0003.json"


def test_golden_report(options: AuditOptions) -> None:
    sample = generate(3, "dev")
    rendered = jsonreport.render(audit_bytes(sample.image, sample.name, options))
    assert json.loads(rendered) == json.loads(GOLDEN.read_text())
    assert rendered == GOLDEN.read_text()

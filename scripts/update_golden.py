"""Regenerate the golden JSON report used by ``tests/test_golden.py``.

Usage::

    uv run python scripts/update_golden.py      # or: make golden

Run only after an intentional change to detection or report output, and review the diff.
"""

from __future__ import annotations

import sys
from pathlib import Path

from fwaudit.audit.base import AuditConfig
from fwaudit.pipeline import AuditOptions, audit_bytes
from fwaudit.report import jsonreport
from fwaudit.synth.firmware import REFERENCE_TIME, generate

GOLDEN = Path(__file__).resolve().parent.parent / "tests" / "golden" / "dev-0003.json"


def main() -> int:
    sample = generate(3, "dev")
    options = AuditOptions(config=AuditConfig(reference_time=REFERENCE_TIME))
    GOLDEN.write_text(jsonreport.render(audit_bytes(sample.image, sample.name, options)))
    print(f"wrote {GOLDEN.name}")
    return 0


if __name__ == "__main__":
    sys.exit(main())

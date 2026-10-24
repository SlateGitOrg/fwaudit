"""Recompute the integrity pin of the bundled CVE subset after a deliberate edit.

Usage::

    uv run python scripts/pin_cvedb.py      # or: make pin-cvedb

Rewrites ``CVEDB_SHA256`` in ``src/fwaudit/audit/cvedb.py`` to the SHA-256 of
``src/fwaudit/data/cve_subset.json``.
"""

from __future__ import annotations

import hashlib
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
DATA = ROOT / "src" / "fwaudit" / "data" / "cve_subset.json"
MODULE = ROOT / "src" / "fwaudit" / "audit" / "cvedb.py"


def main() -> int:
    digest = hashlib.sha256(DATA.read_bytes()).hexdigest()
    source = MODULE.read_text()
    updated, n = re.subn(r'CVEDB_SHA256 = "[0-9a-f]{64}"', f'CVEDB_SHA256 = "{digest}"', source)
    if n != 1:
        print("CVEDB_SHA256 assignment not found", file=sys.stderr)
        return 1
    if updated != source:
        MODULE.write_text(updated)
    print(f"CVEDB_SHA256 = {digest}")
    return 0


if __name__ == "__main__":
    sys.exit(main())

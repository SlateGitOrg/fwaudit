"""Loader for the pinned, offline CVE subset shipped in ``fwaudit/data``.

The JSON file is integrity-pinned: its SHA-256 is compiled into this module and checked
on load, so an edited database is detected rather than silently trusted. After a
deliberate update, regenerate the pin with ``make pin-cvedb``.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from functools import lru_cache
from importlib import resources

from fwaudit.audit.versions import VersionRange
from fwaudit.errors import CveDatabaseError
from fwaudit.model import Severity

CVEDB_SHA256 = "147b4bd6403400cecd9c4ac36bf2bdc4f76b168ebb2708612866e5177311eb51"


@dataclass(frozen=True)
class CveEntry:
    cve_id: str
    component: str
    cvss: float
    cvss_version: str
    summary: str
    ranges: tuple[VersionRange, ...]

    @property
    def severity(self) -> Severity:
        """CVSS v3 qualitative rating mapped onto fwaudit severities."""
        if self.cvss >= 9.0:
            return Severity.CRITICAL
        if self.cvss >= 7.0:
            return Severity.HIGH
        if self.cvss >= 4.0:
            return Severity.MEDIUM
        return Severity.LOW

    def affects(self, version: str) -> VersionRange | None:
        for r in self.ranges:
            if r.contains(version):
                return r
        return None


@dataclass(frozen=True)
class CveDatabase:
    source: str
    entries: tuple[CveEntry, ...]

    def components(self) -> set[str]:
        return {e.component for e in self.entries}

    def lookup(self, component: str, version: str) -> list[tuple[CveEntry, VersionRange]]:
        hits = []
        for e in self.entries:
            if e.component != component:
                continue
            r = e.affects(version)
            if r is not None:
                hits.append((e, r))
        return sorted(hits, key=lambda h: (-h[0].cvss, h[0].cve_id))


def parse_database(raw: bytes, *, expected_sha256: str | None = CVEDB_SHA256) -> CveDatabase:
    digest = hashlib.sha256(raw).hexdigest()
    if expected_sha256 is not None and digest != expected_sha256:
        raise CveDatabaseError(
            f"CVE subset integrity pin mismatch: expected {expected_sha256}, got {digest}"
        )
    try:
        doc = json.loads(raw)
        if doc.get("schema_version") != 1:
            raise CveDatabaseError("unsupported CVE subset schema_version")
        entries = tuple(
            CveEntry(
                cve_id=str(e["id"]),
                component=str(e["component"]),
                cvss=float(e["cvss"]),
                cvss_version=str(e["cvss_version"]),
                summary=str(e["summary"]),
                ranges=tuple(
                    VersionRange(
                        introduced=str(r["introduced"]),
                        fixed=r.get("fixed"),
                        last_affected=r.get("last_affected"),
                    )
                    for r in e["ranges"]
                ),
            )
            for e in doc["entries"]
        )
    except (KeyError, TypeError, ValueError) as exc:
        raise CveDatabaseError(f"malformed CVE subset: {exc}") from exc
    return CveDatabase(source=str(doc.get("source", "")), entries=entries)


@lru_cache(maxsize=1)
def load_default() -> CveDatabase:
    raw = resources.files("fwaudit.data").joinpath("cve_subset.json").read_bytes()
    return parse_database(raw)

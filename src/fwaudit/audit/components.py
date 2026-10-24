"""Known-component version detection and offline CVE matching.

Version strings are searched for only in ELF files (executables and shared libraries),
because documentation and scripts mention versions that are not what actually runs.
Each (component, version) pair yields one inventory finding (``FWA-CMP-001``) listing
every binary it was seen in, plus one ``FWA-CMP-002`` finding carrying the matching CVEs
from the pinned subset, rated by the highest CVSS score among them.
"""

from __future__ import annotations

import re
from collections import defaultdict
from dataclasses import dataclass

from fwaudit.audit.base import AuditConfig
from fwaudit.audit.cvedb import CveDatabase, load_default
from fwaudit.model import Finding, JsonValue, make_finding
from fwaudit.vfs import VirtualFS

ELF_MAGIC = b"\x7fELF"


@dataclass(frozen=True)
class Detector:
    component: str
    pattern: re.Pattern[bytes]


DETECTORS: tuple[Detector, ...] = (
    Detector("busybox", re.compile(rb"BusyBox v(\d+\.\d+(?:\.\d+)?)[\s(\x00]")),
    Detector("openssl", re.compile(rb"OpenSSL (\d+\.\d+\.\d+[a-z]{0,2})(?=[\s\x00-])")),
    Detector("dropbear", re.compile(rb"(?:dropbear_|Dropbear (?:SSH )?v)(\d{4}\.\d{2,3})(?!\d)")),
    Detector("dnsmasq", re.compile(rb"dnsmasq-(\d+\.\d+)(?![\d.])")),
)


def detect(data: bytes) -> list[tuple[str, str]]:
    """(component, version) pairs present in one binary; first match per component."""
    found = []
    for d in DETECTORS:
        m = d.pattern.search(data)
        if m is not None:
            found.append((d.component, m.group(1).decode("ascii")))
    return found


class ComponentsCheck:
    name = "components"

    def __init__(self, database: CveDatabase | None = None) -> None:
        self.database = database or load_default()

    def run(self, fs: VirtualFS, config: AuditConfig) -> list[Finding]:
        seen: dict[tuple[str, str], list[str]] = defaultdict(list)
        for node in fs.files():
            if not node.data.startswith(ELF_MAGIC) or len(node.data) > config.max_scan_file_bytes:
                continue
            for component, version in detect(node.data):
                seen[(component, version)].append(node.path)
        out: list[Finding] = []
        for (component, version), paths in sorted(seen.items()):
            paths.sort()
            out.append(make_finding(
                "FWA-CMP-001", f"{component} {version} found in {len(paths)} binary(ies)",
                filesystem=fs.fs_id, path=paths[0],
                evidence={"component": component, "version": version, "paths": list(paths),
                          "key": component},
            ))  # fmt: skip
            hits = self.database.lookup(component, version)
            if not hits:
                continue
            cves: list[JsonValue] = [
                {"id": e.cve_id, "cvss": e.cvss, "summary": e.summary, "affected": r.describe()}
                for e, r in hits
            ]
            worst = max(e.severity for e, _ in hits)
            ids = ", ".join(e.cve_id for e, _ in hits)
            out.append(make_finding(
                "FWA-CMP-002",
                f"{component} {version} is affected by {len(hits)} CVE(s) in the offline "
                f"subset: {ids}",
                filesystem=fs.fs_id, path=paths[0], severity=worst,
                evidence={"component": component, "version": version, "cves": cves,
                          "paths": list(paths), "key": component},
            ))  # fmt: skip
        return out

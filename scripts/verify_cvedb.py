"""Cross-check the pinned CVE subset against the live NVD CVE API 2.0 (needs network).

Usage::

    uv run python scripts/verify_cvedb.py            # or: make verify-cvedb

For every entry the script fetches the NVD record and compares

* the CVSS v3.x base score (the NVD "Primary" metric of the same CVSS version), and
* the affected version ranges: each boundary version mentioned by either side is probed
  against our ranges and against NVD's vulnerable CPE matches for the component, and
  every probe must agree.

It is *not* part of ``make check`` (tests are offline). NVD allows ~5 unauthenticated
requests per 30 s, so the script sleeps between requests. Exit status 1 on any mismatch.
"""

from __future__ import annotations

import argparse
import json
import sys
import time
import urllib.request
from dataclasses import dataclass
from importlib import resources
from typing import Any

from fwaudit.audit.cvedb import CveEntry, parse_database
from fwaudit.audit.versions import version_key

API = "https://services.nvd.nist.gov/rest/json/cves/2.0?cveId={}"
CPE_PRODUCT = {
    "openssl": "openssl",
    "busybox": "busybox",
    "dropbear": "dropbear_ssh",
    "dnsmasq": "dnsmasq",
}


@dataclass(frozen=True)
class NvdRange:
    start_incl: str | None
    start_excl: str | None
    end_incl: str | None
    end_excl: str | None
    exact: str | None

    def contains(self, version: str) -> bool:
        v = version_key(version)
        if self.exact is not None:
            return v == version_key(self.exact)
        if self.start_incl and v < version_key(self.start_incl):
            return False
        if self.start_excl and v <= version_key(self.start_excl):
            return False
        if self.end_incl and v > version_key(self.end_incl):
            return False
        return not (self.end_excl and v >= version_key(self.end_excl))

    def bounds(self) -> list[str]:
        return [
            b
            for b in (self.start_incl, self.start_excl, self.end_incl, self.end_excl, self.exact)
            if b
        ]


def nvd_ranges(cve: dict[str, Any], product: str) -> list[NvdRange]:
    out: list[NvdRange] = []
    for config in cve.get("configurations", []):
        for node in config.get("nodes", []):
            for match in node.get("cpeMatch", []):
                parts = match["criteria"].split(":")
                if not match.get("vulnerable") or parts[4] != product:
                    continue
                version, update = parts[5], parts[6]
                exact = None if version in ("*", "-") else version
                if update not in ("*", "-") or (exact and not _parseable(exact)):
                    continue  # beta/rc builds: not shipped in firmware, not comparable
                out.append(
                    NvdRange(
                        match.get("versionStartIncluding"),
                        match.get("versionStartExcluding"),
                        match.get("versionEndIncluding"),
                        match.get("versionEndExcluding"),
                        exact,
                    )
                )
    return out


def _parseable(version: str) -> bool:
    try:
        version_key(version)
    except ValueError:
        return False
    return True


def primary_score(cve: dict[str, Any], cvss_version: str) -> float | None:
    for key in ("cvssMetricV31", "cvssMetricV30"):
        for metric in cve.get("metrics", {}).get(key, []):
            data = metric["cvssData"]
            if metric["type"] == "Primary" and data["version"] == cvss_version:
                return float(data["baseScore"])
    return None


def compare(entry: CveEntry, cve: dict[str, Any]) -> list[str]:
    problems: list[str] = []
    score = primary_score(cve, entry.cvss_version)
    if score != entry.cvss:
        problems.append(f"CVSS {entry.cvss_version}: ours {entry.cvss}, NVD {score}")
    theirs = nvd_ranges(cve, CPE_PRODUCT[entry.component])
    if not theirs:
        problems.append("NVD lists no comparable CPE ranges")
        return problems
    probes = {entry_bound for r in entry.ranges for entry_bound in _our_bounds(r)}
    probes |= {b for r in theirs for b in r.bounds() if _parseable(b)}
    probes.discard("0")
    for probe in sorted(probes, key=version_key):
        ours = any(r.contains(probe) for r in entry.ranges)
        nvd = any(r.contains(probe) for r in theirs)
        if ours != nvd:
            problems.append(f"version {probe}: ours affected={ours}, NVD affected={nvd}")
    return problems


def _our_bounds(r: Any) -> list[str]:
    return [b for b in (r.introduced, r.fixed, r.last_affected) if b]


def fetch(cve_id: str) -> dict[str, Any]:
    with urllib.request.urlopen(API.format(cve_id), timeout=30) as resp:  # noqa: S310
        doc: dict[str, Any] = json.load(resp)
    vulns = doc.get("vulnerabilities", [])
    if not vulns:
        raise LookupError(f"{cve_id} not found")
    cve: dict[str, Any] = vulns[0]["cve"]
    return cve


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(description="Cross-check the CVE subset against NVD")
    p.add_argument("--delay", type=float, default=6.5, help="seconds between requests")
    args = p.parse_args(argv)
    raw = resources.files("fwaudit.data").joinpath("cve_subset.json").read_bytes()
    db = parse_database(raw)
    failures = 0
    for i, entry in enumerate(db.entries):
        if i:
            time.sleep(args.delay)
        try:
            problems = compare(entry, fetch(entry.cve_id))
        except (OSError, LookupError, KeyError, ValueError) as exc:
            problems = [f"fetch failed: {exc}"]
        status = "OK " if not problems else "BAD"
        print(f"{status} {entry.cve_id} {entry.component} cvss {entry.cvss}", flush=True)
        for prob in problems:
            print(f"      {prob}", flush=True)
        failures += bool(problems)
    print(f"{len(db.entries) - failures}/{len(db.entries)} entries agree with NVD")
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())

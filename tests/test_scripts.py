"""Offline tests for the helper scripts (no network)."""

from __future__ import annotations

from pathlib import Path

import evaluate  # scripts/ is on pythonpath (see [tool.pytest.ini_options])
import verify_cvedb
from fwaudit.audit.cvedb import CveEntry
from fwaudit.audit.versions import VersionRange


def _nvd(score: float, matches: list[dict[str, object]]) -> dict[str, object]:
    return {
        "metrics": {
            "cvssMetricV31": [
                {"type": "Secondary", "cvssData": {"version": "3.1", "baseScore": 1.0}},
                {"type": "Primary", "cvssData": {"version": "3.1", "baseScore": score}},
            ]
        },
        "configurations": [{"nodes": [{"cpeMatch": matches}]}],
    }


def _cpe(product: str, version: str = "*", update: str = "*", **bounds: str) -> dict[str, object]:
    return {
        "vulnerable": True,
        "criteria": f"cpe:2.3:a:vendor:{product}:{version}:{update}:*:*:*:*:*:*",
        **bounds,
    }


ENTRY = CveEntry("CVE-X", "busybox", 9.8, "3.1", "s", (VersionRange("0", last_affected="1.36.1"),))


def test_verify_agrees_with_equivalent_nvd_record() -> None:
    record = _nvd(9.8, [_cpe("busybox", versionEndIncluding="1.36.1"), _cpe("other")])
    assert verify_cvedb.compare(ENTRY, record) == []


def test_verify_reports_score_and_range_mismatch() -> None:
    record = _nvd(7.5, [_cpe("busybox", versionEndExcluding="1.35.0")])
    problems = verify_cvedb.compare(ENTRY, record)
    assert problems[0] == "CVSS 3.1: ours 9.8, NVD 7.5"
    assert any("1.35.0" in p for p in problems)


def test_verify_enumerated_versions_and_prereleases() -> None:
    entry = CveEntry("CVE-Y", "openssl", 5.9, "3.1", "s", (VersionRange("1.0.1", fixed="1.0.1b"),))
    record = _nvd(
        5.9,
        [
            _cpe("openssl", "1.0.1"),
            _cpe("openssl", "1.0.1a"),
            _cpe("openssl", "1.0.1", "beta1"),
            _cpe("openssl", "weird-version"),
            _cpe("openssl", versionStartExcluding="2.0.0", versionEndExcluding="2.0.0"),
        ],
    )
    assert verify_cvedb.compare(entry, record) == []
    assert verify_cvedb.compare(entry, _nvd(5.9, [])) == ["NVD lists no comparable CPE ranges"]


def test_evaluate_script_end_to_end(tmp_path: Path, capsys: object) -> None:
    out = tmp_path / "eval.json"
    assert evaluate.main(["--split", "dev", "--seeds", "1-2", "--out", str(out)]) == 0
    assert '"recall": 1.0' in out.read_text()
    assert evaluate.parse_seeds("4") == [4]

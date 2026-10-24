from __future__ import annotations

import json

import pytest

from conftest import FsFactory
from fwaudit.audit import CheckRun, default_checks, run_checks
from fwaudit.audit.base import AuditConfig
from fwaudit.audit.components import ComponentsCheck, detect
from fwaudit.audit.cvedb import CVEDB_SHA256, load_default, parse_database
from fwaudit.audit.permissions import PermissionsCheck
from fwaudit.audit.versions import VersionRange, version_key
from fwaudit.errors import CveDatabaseError
from fwaudit.model import Finding, Severity

ELF = b"\x7fELF\x01\x01\x01" + b"\x00" * 40


def test_version_ordering() -> None:
    order = ["0.9.8", "0.9.8za", "1.0.1", "1.0.1f", "1.0.1g", "1.0.1z", "1.0.1za", "1.0.2",
             "1.0.2zg", "1.1.1", "3.0.2", "3.0.10"]  # fmt: skip
    keys = [version_key(v) for v in order]
    assert keys == sorted(keys)
    assert version_key("1.30") == (1, 30, 0)
    assert version_key("2019.78") == (2019, 78, 0)
    with pytest.raises(ValueError):
        version_key("v1.2")


def test_version_ranges() -> None:
    heartbleed = VersionRange("1.0.1", fixed="1.0.1g")
    assert heartbleed.contains("1.0.1")
    assert heartbleed.contains("1.0.1f")
    assert not heartbleed.contains("1.0.1g")
    assert not heartbleed.contains("1.0.0z")
    through = VersionRange("0", last_affected="2018.76")
    assert through.contains("2018.76")
    assert not through.contains("2018.77")
    assert through.describe() == ">= 0, <= 2018.76"
    with pytest.raises(ValueError):
        VersionRange("1.0")
    with pytest.raises(ValueError):
        VersionRange("1.0", fixed="2", last_affected="3")


def test_cvedb_pin_and_parse() -> None:
    db = load_default()
    assert {"busybox", "openssl", "dropbear", "dnsmasq"} <= db.components()
    ids = [e.cve_id for e, _ in db.lookup("openssl", "1.0.1f")]
    assert "CVE-2014-0160" in ids
    assert db.lookup("openssl", "3.0.13") == []
    from importlib import resources

    raw = resources.files("fwaudit.data").joinpath("cve_subset.json").read_bytes()
    with pytest.raises(CveDatabaseError, match="pin"):
        parse_database(raw + b" ")
    assert parse_database(raw, expected_sha256=CVEDB_SHA256).entries
    with pytest.raises(CveDatabaseError):
        parse_database(json.dumps({"schema_version": 2}).encode(), expected_sha256=None)
    with pytest.raises(CveDatabaseError):
        parse_database(json.dumps({"schema_version": 1, "entries": [{}]}).encode(),
                       expected_sha256=None)  # fmt: skip
    sev = {e.cve_id: e.severity for e in db.entries}
    assert sev["CVE-2016-2148"] is Severity.CRITICAL
    assert sev["CVE-2014-0160"] is Severity.HIGH
    assert sev["CVE-2016-2107"] is Severity.MEDIUM


def test_detect_patterns() -> None:
    blob = (ELF + b"BusyBox v1.24.1 (2017) multi-call\x00OpenSSL 1.0.2k  26 Jan 2017\x00"
            b"SSH-2.0-dropbear_2019.78\x00dnsmasq-2.80\x00")  # fmt: skip
    assert detect(blob) == [("busybox", "1.24.1"), ("openssl", "1.0.2k"),
                            ("dropbear", "2019.78"), ("dnsmasq", "2.80")]  # fmt: skip
    assert detect(b"OpenSSL 1.0.2kfoo") == []


def test_components_check(make_fs: FsFactory, config: AuditConfig) -> None:
    fs = make_fs({
        "bin/busybox": ELF + b"BusyBox v1.24.1 (x)",
        "sbin/busybox.copy": ELF + b"BusyBox v1.24.1 (x)",
        "usr/lib/libcrypto.so": ELF + b"OpenSSL 3.0.13 30 Jan 2024\x00",
        "usr/share/doc/README": b"OpenSSL 1.0.1f \n",
    })  # fmt: skip
    found = ComponentsCheck().run(fs, config)
    inv = [f for f in found if f.rule_id == "FWA-CMP-001"]
    assert {(f.evidence["component"], f.evidence["version"]) for f in inv} == {
        ("busybox", "1.24.1"), ("openssl", "3.0.13")}  # fmt: skip
    vuln = [f for f in found if f.rule_id == "FWA-CMP-002"]
    assert len(vuln) == 1
    assert vuln[0].severity is Severity.CRITICAL
    assert vuln[0].evidence["paths"] == ["/bin/busybox", "/sbin/busybox.copy"]


def test_permissions(make_fs: FsFactory, config: AuditConfig) -> None:
    fs = make_fs({
        "usr/bin/upd": ("file", ELF, 0o4777),
        "usr/bin/grp": ("file", ELF, 0o2777),
        "bin/su": ("file", ELF, 0o4755, 0),
        "bin/usr_suid": ("file", ELF, 0o4755, 1000),
        "etc/init.d/x": ("file", "x", 0o666),
        "home/u/ok": ("file", "x", 0o666),
        "tmp": ("dir", 0o1777),
        "var/up": ("dir", 0o777),
        "bin/sh": ("link", "busybox"),
    })  # fmt: skip
    got = sorted((f.rule_id, f.path) for f in PermissionsCheck().run(fs, config))
    assert got == [
        ("FWA-PERM-001", "/usr/bin/grp"),
        ("FWA-PERM-001", "/usr/bin/upd"),
        ("FWA-PERM-002", "/bin/su"),
        ("FWA-PERM-003", "/etc/init.d/x"),
        ("FWA-PERM-004", "/var/up"),
    ]


def test_run_checks_isolates_crashes(make_fs: FsFactory, config: AuditConfig) -> None:
    class Boom:
        name = "boom"

        def run(self, fs: object, cfg: object) -> list[Finding]:
            raise RuntimeError("kaput")

    run = run_checks(make_fs({"etc/x": "y"}), config, [Boom(), *default_checks()])
    assert isinstance(run, CheckRun)
    assert run.errors == ["boom on test/fs: RuntimeError: kaput"]

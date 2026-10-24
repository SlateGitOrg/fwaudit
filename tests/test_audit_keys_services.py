from __future__ import annotations

from datetime import UTC, datetime, timedelta

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519

from conftest import FsFactory
from fwaudit.audit.base import AuditConfig
from fwaudit.audit.cryptpw import md5_crypt
from fwaudit.audit.keys import KeyAnalyzer, KeysCheck, describe_public, parse_dropbear_key
from fwaudit.audit.services import ServicesCheck
from fwaudit.synth import pki
from fwaudit.synth.firmware import REFERENCE_TIME


def rules(findings: list) -> list[tuple[str, str | None]]:
    return sorted((f.rule_id, f.path) for f in findings)


def test_keys_check_matrix(make_fs: FsFactory, config: AuditConfig) -> None:
    ref = REFERENCE_TIME
    rsa1024 = pki.rsa_key(1, 1024)
    ec = pki.ec_key(1)
    expired = pki.certificate(ec, "old", ref - timedelta(days=900), ref - timedelta(days=10))
    soon = pki.certificate(rsa1024, "soon", ref - timedelta(days=10), ref + timedelta(days=5),
                           hash_name="sha1")  # fmt: skip
    good = pki.certificate(ec, "good", ref - timedelta(days=10), ref + timedelta(days=900))
    ed = ed25519.Ed25519PrivateKey.from_private_bytes(b"\x01" * 32)
    openssh = ed.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.OpenSSH,
                               serialization.NoEncryption())  # fmt: skip
    fs = make_fs({
        "etc/ssl/rsa.key": pki.private_pem(rsa1024),
        "etc/ssl/ec.key": pki.private_pem(ec),
        "etc/ssl/enc.key": pki.fake_encrypted_pem(1),
        "etc/ssl/bundle.pem": pki.cert_pem(expired) + pki.cert_pem(soon),
        "etc/ssl/good.der": pki.cert_der(good),
        "etc/ssh/id_ed25519": openssh,
        "etc/dropbear/dropbear_rsa_host_key": pki.dropbear_rsa_host_key(rsa1024),
        "etc/dropbear/dropbear_bad_host_key": b"\x00\x00\x00\x07ssh-xyz",
        "etc/ssl/broken.pem": "-----BEGIN CERTIFICATE-----\nAAAA\n-----END CERTIFICATE-----\n",
        "etc/ssl/broken.key": "-----BEGIN RSA PRIVATE KEY-----\nAAAA\n-----END RSA PRIVATE KEY-----\n",
        "etc/ssl/bad.der": b"\x30\x82garbage",
    })  # fmt: skip
    got = rules(KeysCheck().run(fs, config))
    assert got == sorted([
        ("FWA-KEY-001", "/etc/ssl/rsa.key"), ("FWA-KEY-004", "/etc/ssl/rsa.key"),
        ("FWA-KEY-001", "/etc/ssl/ec.key"),
        ("FWA-KEY-001", "/etc/ssl/enc.key"),
        ("FWA-KEY-006", "/etc/ssl/bundle.pem"), ("FWA-KEY-002", "/etc/ssl/bundle.pem"),
        ("FWA-KEY-006", "/etc/ssl/bundle.pem"), ("FWA-KEY-003", "/etc/ssl/bundle.pem"),
        ("FWA-KEY-005", "/etc/ssl/bundle.pem"), ("FWA-KEY-004", "/etc/ssl/bundle.pem"),
        ("FWA-KEY-006", "/etc/ssl/good.der"),
        ("FWA-KEY-001", "/etc/ssh/id_ed25519"),
        ("FWA-KEY-001", "/etc/dropbear/dropbear_rsa_host_key"),
        ("FWA-KEY-004", "/etc/dropbear/dropbear_rsa_host_key"),
        ("FWA-KEY-001", "/etc/ssl/broken.key"),
    ])  # fmt: skip
    findings = KeysCheck().run(fs, config)
    enc = next(f for f in findings if f.path == "/etc/ssl/enc.key")
    assert enc.severity.name == "MEDIUM"
    assert enc.evidence["encrypted"] is True
    broken = next(f for f in findings if f.path == "/etc/ssl/broken.key")
    assert broken.evidence["parsed"] is False
    ed_f = next(f for f in findings if f.path == "/etc/ssh/id_ed25519")
    assert ed_f.evidence["algorithm"] == "ed25519"


def test_raw_region_offsets(config: AuditConfig) -> None:
    pem = pki.private_pem(pki.ec_key(5))
    out = KeyAnalyzer(config).analyze(b"junk" * 10 + pem, filesystem="image", path=None,
                                      base_offset=1000)  # fmt: skip
    assert out[0].offset == 1040
    assert out[0].path is None


def test_dropbear_parser_variants() -> None:
    def s(b: bytes) -> bytes:
        return len(b).to_bytes(4, "big") + b

    assert parse_dropbear_key(s(b"ssh-ed25519") + s(b"k" * 32)).algorithm == "ed25519"
    ecd = parse_dropbear_key(s(b"ecdsa-sha2-nistp384") + s(b"x"))
    assert ecd is not None
    assert ecd.bits == 384
    dss = parse_dropbear_key(s(b"ssh-dss") + s(b"\x80" + b"\x00" * 127))
    assert dss is not None
    assert dss.bits == 1024
    assert parse_dropbear_key(b"\x00\x00") is None
    assert parse_dropbear_key(b"\xff\xff\xff\xff") is None
    assert describe_public(object()).algorithm == "unknown"


def test_services_matrix(make_fs: FsFactory, config: AuditConfig) -> None:
    fs = make_fs({
        "etc/init.d/rcS": "#!/bin/sh\ntelnetd -l /bin/sh &\n/usr/sbin/dropbear -p 22 &\n",
        "etc/init.d/S50ok": "#!/bin/sh\n# telnetd\nkillall telnetd\ndropbear -s -g\n",
        "etc/rc.d/S50ok": ("link", "../init.d/S50ok"),
        "etc/inittab": "::respawn:/usr/sbin/telnetd -F\n",
        "etc/inetd.conf": "telnet stream tcp nowait root /usr/sbin/telnetd telnetd\n",
        "etc/httpd.conf": "A:*\n/cgi-bin:admin:admin\n/adm:boss:Unique99\n",
        "www/.htpasswd": f"admin:{md5_crypt(b'password', 'aa', '$apr1$')}\nuser:{{SHA}}"
        "W6ph5Mm5Pz8GgiULbPgzG37mj9g=\nweird:abJnggxhB/yWI\n",
        "www/lighttpd.user": "guest:guest\n",
        "www/realm.htdigest": "admin:router:" + __import__("hashlib").md5(b"admin:router:admin").hexdigest() + "\nbad\n",
        "etc/vsftpd.conf": "anonymous_enable=YES\n",
        "etc/snmp/snmpd.conf": "rocommunity public\nrwcommunity private\ncom2sec n default public\nrocommunity s3cret\n",
        "etc/ssh/sshd_config": "PermitRootLogin yes\nPasswordAuthentication yes\n",
        "opt/sshd_config": ("dir", 0o755),
    })  # fmt: skip
    found = ServicesCheck().run(fs, config)
    got = rules(found)
    assert got == sorted([
        ("FWA-SVC-001", "/etc/init.d/rcS"),
        ("FWA-SVC-001", "/etc/inittab"),
        ("FWA-SVC-001", "/etc/inetd.conf"),
        ("FWA-SVC-005", "/etc/init.d/rcS"),
        ("FWA-SVC-002", "/etc/httpd.conf"),
        ("FWA-CRED-006", "/etc/httpd.conf"),
        ("FWA-SVC-002", "/www/.htpasswd"),
        ("FWA-SVC-002", "/www/lighttpd.user"),
        ("FWA-SVC-002", "/www/realm.htdigest"),
        ("FWA-SVC-003", "/etc/vsftpd.conf"),
        ("FWA-SVC-004", "/etc/snmp/snmpd.conf"),
        ("FWA-SVC-004", "/etc/snmp/snmpd.conf"),
        ("FWA-SVC-004", "/etc/snmp/snmpd.conf"),
        ("FWA-SVC-005", "/etc/ssh/sshd_config"),
    ])  # fmt: skip
    rcs = next(f for f in found if f.rule_id == "FWA-SVC-001" and f.path == "/etc/init.d/rcS")
    assert rcs.severity.name == "CRITICAL"
    rw = [f for f in found if f.rule_id == "FWA-SVC-004" and f.evidence["writable"]]
    assert len(rw) == 1
    assert rw[0].severity.name == "HIGH"


def test_sha1_htpasswd_default(make_fs: FsFactory, config: AuditConfig) -> None:
    import base64
    import hashlib

    digest = base64.b64encode(hashlib.sha1(b"admin").digest()).decode()
    fs = make_fs({"www/.htpasswd": f"admin:{{SHA}}{digest}\n"})
    assert rules(ServicesCheck().run(fs, config)) == [("FWA-SVC-002", "/www/.htpasswd")]


def test_cert_reference_time_changes_verdict(make_fs: FsFactory) -> None:
    cert = pki.certificate(pki.ec_key(9), "c", datetime(2020, 1, 1, tzinfo=UTC),
                           datetime(2030, 1, 1, tzinfo=UTC))  # fmt: skip
    fs = make_fs({"c.pem": pki.cert_pem(cert)})
    early = AuditConfig(reference_time=datetime(2025, 1, 1, tzinfo=UTC))
    late = AuditConfig(reference_time=datetime(2031, 1, 1, tzinfo=UTC))
    assert {f.rule_id for f in KeysCheck().run(fs, early)} == {"FWA-KEY-006"}
    assert {f.rule_id for f in KeysCheck().run(fs, late)} == {"FWA-KEY-006", "FWA-KEY-002"}


def test_xinetd_telnet(make_fs: FsFactory, config: AuditConfig) -> None:
    fs = make_fs({
        "etc/xinetd.d/telnet": "service telnet\n{\n  disable = no\n  server = /usr/sbin/in.telnetd\n}\n",
        "etc/xinetd.d/telnet-off": "service telnet\n{\n  disable = yes\n}\n",
        "etc/xinetd.d/remote": "service rlogin { server = /usr/sbin/utelnetd }\n",
        "etc/xinetd.d/ftp": "service ftp\n{\n server = /usr/sbin/vsftpd\n}\n",
        "etc/xinetd.conf": "defaults\n{\n instances = 60\n}\nincludedir /etc/xinetd.d\n",
        "etc/xinetd.d/subdir": ("dir", 0o755),
    })  # fmt: skip
    found = ServicesCheck().run(fs, config)
    assert rules(found) == [
        ("FWA-SVC-001", "/etc/xinetd.d/remote"),
        ("FWA-SVC-001", "/etc/xinetd.d/telnet"),
    ]
    assert "in.telnetd" in next(f.detail for f in found if f.path == "/etc/xinetd.d/telnet")

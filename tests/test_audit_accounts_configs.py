from __future__ import annotations

from conftest import FsFactory
from fwaudit.audit.accounts import AccountsCheck, parse_passwd, parse_shadow
from fwaudit.audit.base import AuditConfig, is_probably_text, mask, strip_comment
from fwaudit.audit.configs import ConfigSecretsCheck, find_credentials
from fwaudit.audit.cryptpw import md5_crypt, sha_crypt


def rules(findings: list) -> list[tuple[str, str | None]]:
    return sorted((f.rule_id, f.path) for f in findings)


def test_parsers_skip_malformed() -> None:
    users = parse_passwd("# c\n\nroot:x:0:0::/root:/bin/sh\nbad:line\nx:x:notint:0::/:/bin/sh\n")
    assert [u.name for u in users] == ["root"]
    assert users[0].can_login
    assert [s.name for s in parse_shadow("root:abc:1\n#x\nnocolon\n")] == ["root"]


def test_accounts_full_matrix(make_fs: FsFactory, config: AuditConfig) -> None:
    passwd = "\n".join([
        "root:x:0:0:root:/root:/bin/sh",
        "toor:x:0:0::/root:/bin/sh",
        "nopw::1001:1001::/home/nopw:/bin/sh",
        "svc::1002:1002::/:/sbin/nologin",
        f"legacy:{md5_crypt(b'legacy', 'zz')}:1003:1003::/:/bin/sh",
        "locked:!x:1004:1004::/:/bin/sh",
        "daemon:x:1:1::/:/bin/false",
        "empty_shadow:x:1005:1005::/:/bin/sh",
    ])  # fmt: skip
    shadow = "\n".join([
        f"root:{sha_crypt(b'admin', 'saltsalt')}:1:0:99999:7:::",
        "toor:!:1:0:99999:7:::",
        "daemon:*:1:0:99999:7:::",
        "empty_shadow::1:0:99999:7:::",
        "nopw:$6$x$y:1:0:99999:7:::",
        "ghost::1:0:99999:7:::",
    ])  # fmt: skip
    fs = make_fs({"etc/passwd": passwd, "etc/shadow": ("file", shadow, 0o644)})
    got = rules(AccountsCheck().run(fs, config))
    assert got == sorted([
        ("FWA-CRED-005", "/etc/passwd"),  # toor uid 0
        ("FWA-CRED-001", "/etc/passwd"),  # nopw empty passwd field
        ("FWA-CRED-002", "/etc/passwd"),  # legacy hash in passwd
        ("FWA-CRED-003", "/etc/passwd"),  # md5
        ("FWA-CRED-004", "/etc/passwd"),  # legacy/legacy
        ("FWA-CRED-004", "/etc/shadow"),  # root/admin
        ("FWA-CRED-001", "/etc/shadow"),  # empty_shadow
        ("FWA-CRED-001", "/etc/shadow"),  # ghost (no passwd entry)
        ("FWA-CRED-007", "/etc/shadow"),  # 0644
    ])  # fmt: skip


def test_accounts_secret_masking(make_fs: FsFactory, config: AuditConfig) -> None:
    fs = make_fs({"etc/shadow": f"root:{md5_crypt(b'root', 'ab')}:1::::::\n"})
    finding = next(f for f in AccountsCheck().run(fs, config) if f.rule_id == "FWA-CRED-004")
    assert "root" not in str(finding.evidence["password"])
    shown = AuditConfig(reference_time=config.reference_time, show_secrets=True)
    finding2 = next(f for f in AccountsCheck().run(fs, shown) if f.rule_id == "FWA-CRED-004")
    assert finding2.evidence["password"] == "root"


def test_accounts_absent_files(make_fs: FsFactory, config: AuditConfig) -> None:
    assert AccountsCheck().run(make_fs({"etc/hostname": "x"}), config) == []


def test_helpers() -> None:
    assert mask("", False) == "<empty>"
    assert mask("abc", False).startswith("a***")
    assert mask("secret123", False).startswith("se***")
    assert mask("secret123", True) == "secret123"
    assert strip_comment('a="x#y" # tail') == 'a="x#y" '
    assert not is_probably_text(b"")
    assert not is_probably_text(b"\x00abc")
    assert not is_probably_text(bytes(range(128, 256)) * 4)
    assert is_probably_text(b"key=value\n")


def test_find_credentials_shapes() -> None:
    text = "\n".join([
        "admin_password=SuperS3cret",
        "password_min_len=8",
        "#password=commented",
        "  option password 'hunter22'",
        "url=ftp://backup:b4ckup!@10.0.0.2/x",
        'echo "root:Zte521" | chpasswd',
        "PASS=$1",
        'api_key: "AKIA1234567890"',
        "token = ${TOKEN}",
        "passwd = passwd",
        "secret=<changeme>",
        "auth_key=/etc/key.pem",
        "pwd=ok",
    ])  # fmt: skip
    got = [(c.key, c.value, c.form) for c in find_credentials(text)]
    assert got == [
        ("admin_password", "SuperS3cret", "kv"),
        ("password", "hunter22", "uci"),
        ("backup", "b4ckup!", "url"),
        ("root", "Zte521", "chpasswd"),
        ("api_key", "AKIA1234567890", "kv"),
    ]


def test_config_check_scope(make_fs: FsFactory, config: AuditConfig) -> None:
    fs = make_fs({
        "etc/app.conf": "db_password=Tr0ub4dor\nother=1\n",
        "etc/default.conf": "admin_password=admin\n",
        "etc/httpd.conf": "/cgi-bin:admin:secret\n",
        "etc/keys/a.pem": "-----BEGIN CERTIFICATE-----\npassword=x123\n",
        "usr/bin/tool": b"\x7fELF\x00password=binary1",
        "home/user/notes.txt": "password: hunter2!\n",
        "bin/script": "password=notscanned\n",
    })  # fmt: skip
    found = ConfigSecretsCheck().run(fs, config)
    assert sorted(f.path or "" for f in found) == [
        "/etc/app.conf", "/etc/default.conf", "/home/user/notes.txt",
    ]  # fmt: skip
    default = next(f for f in found if f.path == "/etc/default.conf")
    assert default.evidence["known_default"] is True
    assert "well-known default" in default.detail

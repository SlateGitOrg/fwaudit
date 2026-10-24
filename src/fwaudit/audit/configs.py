"""Hardcoded credentials in configuration files and scripts.

Recognised shapes (one finding per file line):

* ``key = value`` / ``key: value`` / ``"key": "value"`` (JSON, YAML) where
  the key names a secret (password, passwd, passphrase, secret, api_key, token, psk...);
* OpenWrt UCI ``option <secret-key> 'value'``;
* credentials embedded in URLs (``scheme://user:pass@host``);
* ``echo "user:pass" | chpasswd`` in shell scripts.

Placeholders (``$VAR``, ``${VAR}``, ``%s``, ``<value>``, ``{{ x }}``), booleans, and
keys that describe password *policy* rather than a password (``password_min_len``) are
ignored. Files owned by more specific checks (passwd/shadow, web server credential files,
SNMP and FTP configs) are skipped to avoid double counting.
"""

from __future__ import annotations

import re
from dataclasses import dataclass

from fwaudit.audit.base import AuditConfig, mask, numbered_lines, strip_comment, text_files
from fwaudit.model import Finding, make_finding
from fwaudit.vfs import VirtualFS

SECRET_WORDS = (
    r"(?:password|passwd|passphrase|passwort|pwd|secret|api[_-]?key|auth[_-]?key|token|psk)"
)
_KEY = rf"[A-Za-z0-9_.\-]*{SECRET_WORDS}[A-Za-z0-9_.\-]*"
_VALUE = r"""(?P<q>["']?)(?P<val>[^"'\s#;,]+)(?P=q)"""
# The key may be quoted (JSON / YAML): ``"admin_password": "s3cret"``.
KV_RE = re.compile(
    rf"""(?i)(?:^|[\s{{,;])(?P<kq>["']?)(?P<key>{_KEY})(?P=kq)\s*(?:=|:)\s*{_VALUE}"""
)
UCI_RE = re.compile(rf"(?i)^\s*option\s+(?P<key>{_KEY})\s+{_VALUE}")
URL_RE = re.compile(r"(?i)\b[a-z][a-z0-9+.\-]*://(?P<user>[^:/@\s'\"]+):(?P<val>[^@/\s'\"]+)@")
CHPASSWD_RE = re.compile(
    r"""(?i)echo\s+(?:-e\s+)?(?P<q>["']?)(?P<user>[\w.\-]+):(?P<val>[^"'\s|]+)(?P=q)\s*\|\s*chpasswd"""
)
POLICY_TOKENS = {
    "file",
    "path",
    "len",
    "length",
    "min",
    "max",
    "minlen",
    "maxlen",
    "timeout",
    "age",
    "retry",
    "retries",
    "count",
    "size",
    "policy",
    "prompt",
    "type",
    "hash",
    "format",
    "dir",
    "cmd",
    "url",
    "expire",
    "expires",
    "lifetime",
    "required",
    "reset",
    "enable",
    "enabled",
    "history",
    "complexity",
    "strength",
    "change",
    "warn",
}
_TOKEN_RE = re.compile(r"[A-Z]?[a-z]+|[A-Z]+(?![a-z])|\d+")
NON_SECRETS = {
    "",
    "x",
    "*",
    "none",
    "null",
    "nil",
    "true",
    "false",
    "yes",
    "no",
    "on",
    "off",
    "required",
    "optional",
    "disabled",
    "enabled",
    "empty",
    "unset",
    "default",
}
SKIP_BASENAMES = {
    "passwd",
    "shadow",
    "group",
    "gshadow",
    "httpd.conf",
    ".htpasswd",
    "htpasswd",
    "lighttpd.user",
    "lighttpd-plain.user",
    "snmpd.conf",
    "vsftpd.conf",
    "sshd_config",
}
SCAN_PREFIXES = ("/etc", "/usr", "/www", "/var", "/opt", "/home", "/root", "/srv", "/data")
MAX_CONFIG_BYTES = 256 * 1024


@dataclass(frozen=True)
class Credential:
    key: str
    value: str
    line: int
    form: str


def _is_placeholder(value: str) -> bool:
    v = value.strip()
    return (
        v.lower() in NON_SECRETS
        or v.startswith(("$", "%", "<", "{{", "@"))
        or (v.startswith("{") and v.endswith("}"))
        or len(v) < 3
        or v.startswith("/")
    )


def _key_is_policy(key: str) -> bool:
    """True when the key describes password policy (``password_min_len``), not a secret."""
    tokens = {t.lower() for t in _TOKEN_RE.findall(key)}
    return bool(tokens & POLICY_TOKENS)


def find_credentials(text: str) -> list[Credential]:
    """Extract credential-looking assignments from one file's text."""
    found: list[Credential] = []
    for n, raw in numbered_lines(text):
        stripped = raw.strip()
        if not stripped or stripped.startswith(("#", "//", ";", "<!--")):
            continue
        line = strip_comment(raw)
        m = CHPASSWD_RE.search(line)
        if m and not _is_placeholder(m.group("val")):
            found.append(Credential(m.group("user"), m.group("val"), n, "chpasswd"))
            continue
        m = URL_RE.search(line)
        if m and not _is_placeholder(m.group("val")):
            found.append(Credential(m.group("user"), m.group("val"), n, "url"))
            continue
        m = UCI_RE.search(line) or KV_RE.search(line)
        if m is None:
            continue
        key, val = m.group("key"), m.group("val")
        if _key_is_policy(key) or _is_placeholder(val) or val.lower() == key.lower():
            continue
        found.append(Credential(key, val, n, "uci" if line.lstrip().startswith("option") else "kv"))
    return found


class ConfigSecretsCheck:
    name = "config-secrets"

    def run(self, fs: VirtualFS, config: AuditConfig) -> list[Finding]:
        findings: list[Finding] = []
        for path, text in text_files(fs, SCAN_PREFIXES, MAX_CONFIG_BYTES):
            basename = path.rsplit("/", 1)[-1]
            if basename in SKIP_BASENAMES or basename.endswith((".htpasswd", ".user")):
                continue
            if "-----BEGIN" in text:
                continue  # key material is handled by the keys check
            for cred in find_credentials(text):
                default = cred.value in config.default_passwords
                detail = (
                    f"{cred.form} credential '{cred.key}' = "
                    f"{mask(cred.value, config.show_secrets)} on line {cred.line}"
                )
                if default:
                    detail += " (a well-known default password)"
                findings.append(
                    make_finding(
                        "FWA-CRED-006",
                        detail,
                        filesystem=fs.fs_id,
                        path=path,
                        evidence={
                            "key": f"{cred.line}:{cred.key}",
                            "name": cred.key,
                            "line": cred.line,
                            "form": cred.form,
                            "value": mask(cred.value, config.show_secrets),
                            "known_default": default,
                        },
                    )
                )
        return findings

"""Insecure network service configuration.

* Telnet started from init scripts, inittab or (x)inetd (``telnetd -l /bin/sh`` is an
  unauthenticated root shell and is escalated to CRITICAL);
* web credentials in BusyBox ``httpd.conf`` (``/path:user:pass``), htpasswd-style files
  (crypt, ``{SHA}`` or plaintext) and lighttpd htdigest files, checked against the
  default-credential list;
* vsftpd anonymous access, SNMP default communities, and SSH root password logins
  (OpenSSH ``PermitRootLogin yes``; dropbear started without ``-s``/``-g``).
"""

from __future__ import annotations

import base64
import hashlib
import re
from collections.abc import Iterator

from fwaudit.audit.base import AuditConfig, mask, numbered_lines, strip_comment
from fwaudit.audit.cryptpw import crack, parse_hash
from fwaudit.formats.entries import EntryKind
from fwaudit.model import Finding, Severity, make_finding
from fwaudit.vfs import VirtualFS, VNode

STARTUP_GLOBS = (
    "/etc/inittab",
    "/etc/inetd.conf",
    "/etc/rc.local",
    "/etc/rcS",
    "/etc/profile",
    "/etc/init.d/*",
    "/etc/rc.d/*",
    "/etc/rcS.d/*",
    "/etc/rc[0-9S].d/*",
    "/etc/xinetd.d/*",
    "/etc/init/*",
    "/etc/systemd/system/*.service",
    "/lib/systemd/system/*.service",
    "/usr/lib/systemd/system/*.service",
)
# A daemon counts as *started* only in command position: start of a shell line, the
# process field of an inittab entry, or after exec/nohup/start-stop-daemon --exec.
_CMD_PREFIX = (
    r"^\s*(?:[^:\s]*:[^:]*:[^:]*:)?\s*"
    r"(?:exec\s+|nohup\s+|(?:\S*/)?start-stop-daemon\b.*?(?:--exec|-x)\s+)?(?:\S*/)?"
)
TELNET_RE = re.compile(_CMD_PREFIX + r"(?P<cmd>u?telnetd)(?=\s|$|[;&|])(?P<args>[^;&|\n]*)")
INETD_TELNET_RE = re.compile(r"^\s*telnet\s+stream\s+tcp")
SHELL_LOGIN_RE = re.compile(r"-l\s*/bin/(?:ba)?sh\b")
DROPBEAR_RE = re.compile(_CMD_PREFIX + r"dropbear(?=\s|$|[;&|])(?P<args>[^;&|\n]*)")
HTTPD_CONF_RE = re.compile(r"^(?P<path>/[^:\s]*):(?P<user>[^:\s]+):(?P<pw>\S+)$")
WEB_CRED_NAMES = (".htpasswd", "htpasswd", "lighttpd.user", "lighttpd-plain.user", "passwd.web")
SNMP_RE = re.compile(r"^\s*(?P<kind>rocommunity6?|rwcommunity6?)\s+(?P<community>\S+)", re.I)
COM2SEC_RE = re.compile(r"^\s*com2sec6?\s+\S+\s+\S+\s+(?P<community>\S+)", re.I)
DEFAULT_COMMUNITIES = ("public", "private")


def _startup_files(fs: VirtualFS) -> Iterator[VNode]:
    seen: set[str] = set()
    for pattern in STARTUP_GLOBS:
        for node in fs.glob(pattern):
            target = fs.get(node.path)
            if target is None or target.data == b"" or target.path in seen:
                continue
            seen.add(target.path)
            yield target


def _active_lines(node: VNode) -> Iterator[tuple[int, str]]:
    text = node.data.decode("utf-8", errors="replace")
    for n, raw in numbered_lines(text):
        line = strip_comment(raw).strip()
        if line:
            yield n, line


class ServicesCheck:
    name = "services"

    def run(self, fs: VirtualFS, config: AuditConfig) -> list[Finding]:
        findings: list[Finding] = []
        findings += self._telnet_and_ssh(fs)
        findings += self._web_credentials(fs, config)
        findings += self._ftp(fs)
        findings += self._snmp(fs)
        findings += self._sshd(fs)
        return findings

    # ------------------------------------------------------------- telnet/dropbear
    def _telnet_and_ssh(self, fs: VirtualFS) -> list[Finding]:
        out: list[Finding] = []
        for node in _startup_files(fs):
            telnet_done = False
            for n, line in _active_lines(node):
                m = TELNET_RE.search(line)
                if not telnet_done and (m or INETD_TELNET_RE.match(line)):
                    args = m.group("args") if m else ""
                    unauth = bool(SHELL_LOGIN_RE.search(args))
                    detail = f"telnet daemon started on line {n}: {line[:120]!r}"
                    if unauth:
                        detail += " (login program is a shell: no authentication)"
                    out.append(
                        make_finding(
                            "FWA-SVC-001",
                            detail,
                            filesystem=fs.fs_id,
                            path=node.path,
                            severity=Severity.CRITICAL if unauth else None,
                            evidence={"line": n, "unauthenticated": unauth},
                        )
                    )
                    telnet_done = True
                d = DROPBEAR_RE.search(line)
                if d and "$" not in d.group("args"):
                    flags = d.group("args")
                    if not re.search(r"(?:^|\s)-[a-zA-Z]*[sg]", flags):
                        out.append(
                            make_finding(
                                "FWA-SVC-005",
                                f"dropbear started without -s/-g on line {n}: root may log in "
                                "with a password",
                                filesystem=fs.fs_id,
                                path=node.path,
                                evidence={"line": n, "key": f"dropbear:{n}"},
                            )
                        )
        return out

    def _sshd(self, fs: VirtualFS) -> list[Finding]:
        out: list[Finding] = []
        for node in fs.glob("*/sshd_config"):
            if node.kind is not EntryKind.FILE:
                continue
            settings: dict[str, tuple[int, str]] = {}
            for n, line in _active_lines(node):
                parts = line.split(None, 1)
                if len(parts) == 2:
                    settings.setdefault(parts[0].lower(), (n, parts[1].strip().lower()))
            root = settings.get("permitrootlogin")
            pw = settings.get("passwordauthentication", (0, "yes"))
            if root and root[1] == "yes" and pw[1] != "no":
                out.append(
                    make_finding(
                        "FWA-SVC-005",
                        f"PermitRootLogin yes on line {root[0]}",
                        filesystem=fs.fs_id,
                        path=node.path,
                        evidence={"line": root[0]},
                    )
                )
        return out

    # ------------------------------------------------------------- web credentials
    def _web_credentials(self, fs: VirtualFS, config: AuditConfig) -> list[Finding]:
        out: list[Finding] = []
        for node in fs.files():
            base = node.path.rsplit("/", 1)[-1]
            if base == "httpd.conf":
                out += self._busybox_httpd(fs, node, config)
            elif base in WEB_CRED_NAMES or base.endswith(".htpasswd"):
                out += self._htpasswd(fs, node, config)
            elif base.endswith(".htdigest") or base == "lighttpd-htdigest.user":
                out += self._htdigest(fs, node, config)
        return out

    def _busybox_httpd(self, fs: VirtualFS, node: VNode, config: AuditConfig) -> list[Finding]:
        out: list[Finding] = []
        for n, line in _active_lines(node):
            m = HTTPD_CONF_RE.match(line)
            if m is None:
                continue
            out += self._judge(fs, node, n, m.group("user"), m.group("pw"), config)
        return out

    def _htpasswd(self, fs: VirtualFS, node: VNode, config: AuditConfig) -> list[Finding]:
        out: list[Finding] = []
        for n, line in _active_lines(node):
            user, sep, secret = line.partition(":")
            if sep and user and secret:
                out += self._judge(fs, node, n, user, secret, config)
        return out

    def _htdigest(self, fs: VirtualFS, node: VNode, config: AuditConfig) -> list[Finding]:
        out: list[Finding] = []
        for n, line in _active_lines(node):
            parts = line.split(":")
            if len(parts) != 3:
                continue
            user, realm, digest = parts
            for guess in config.guesses_for(user):
                material = f"{user}:{realm}:{guess}".encode()
                if hashlib.md5(material).hexdigest() == digest.lower():
                    out.append(self._default_web(fs, node, n, user, guess, config, "htdigest"))
                    break
        return out

    def _judge(
        self, fs: VirtualFS, node: VNode, n: int, user: str, secret: str, config: AuditConfig
    ) -> list[Finding]:
        """Classify one web credential as default, plaintext, or acceptable."""
        parsed = parse_hash(secret)
        if parsed.scheme != "unknown":
            guess = crack(parsed, config.guesses_for(user))
            if guess is not None and config.is_default_pair(user, guess):
                return [self._default_web(fs, node, n, user, guess, config, parsed.scheme)]
            return []
        if secret.startswith("{SHA}"):
            for guess in config.guesses_for(user):
                digest = base64.b64encode(hashlib.sha1(guess.encode()).digest()).decode()
                if digest == secret[5:] and config.is_default_pair(user, guess):
                    return [self._default_web(fs, node, n, user, guess, config, "sha1")]
            return []
        if config.is_default_pair(user, secret):
            return [self._default_web(fs, node, n, user, secret, config, "plaintext")]
        return [
            make_finding(
                "FWA-CRED-006",
                f"plaintext web credential for '{user}' = {mask(secret, config.show_secrets)} "
                f"on line {n}",
                filesystem=fs.fs_id,
                path=node.path,
                evidence={
                    "key": f"{n}:{user}",
                    "name": user,
                    "line": n,
                    "form": "web-plaintext",
                    "value": mask(secret, config.show_secrets),
                    "known_default": False,
                },
            )
        ]

    @staticmethod
    def _default_web(
        fs: VirtualFS, node: VNode, n: int, user: str, pw: str, config: AuditConfig, scheme: str
    ) -> Finding:
        return make_finding(
            "FWA-SVC-002",
            f"web user '{user}' has default password {mask(pw, config.show_secrets)} "
            f"({scheme}) on line {n}",
            filesystem=fs.fs_id,
            path=node.path,
            evidence={
                "user": user,
                "line": n,
                "scheme": scheme,
                "password": mask(pw, config.show_secrets),
                "key": f"{n}:{user}",
            },
        )

    # ------------------------------------------------------------- ftp / snmp
    def _ftp(self, fs: VirtualFS) -> list[Finding]:
        out: list[Finding] = []
        for node in fs.glob("*/vsftpd.conf"):
            for n, line in _active_lines(node):
                key, _, value = line.partition("=")
                if key.strip().lower() == "anonymous_enable" and value.strip().upper() == "YES":
                    out.append(
                        make_finding(
                            "FWA-SVC-003",
                            f"anonymous_enable=YES on line {n}",
                            filesystem=fs.fs_id,
                            path=node.path,
                            evidence={"line": n},
                        )
                    )
        return out

    def _snmp(self, fs: VirtualFS) -> list[Finding]:
        out: list[Finding] = []
        for node in fs.glob("*/snmpd.conf"):
            for n, line in _active_lines(node):
                m = SNMP_RE.match(line)
                community = m.group("community") if m else None
                writable = bool(m and m.group("kind").lower().startswith("rw"))
                if m is None:
                    c = COM2SEC_RE.match(line)
                    community = c.group("community") if c else None
                if community is None or community.lower() not in DEFAULT_COMMUNITIES:
                    continue
                out.append(
                    make_finding(
                        "FWA-SVC-004",
                        f"SNMP community '{community}' ({'read-write' if writable else 'read'}) "
                        f"on line {n}",
                        filesystem=fs.fs_id,
                        path=node.path,
                        severity=Severity.HIGH if writable else None,
                        evidence={
                            "line": n,
                            "community": community,
                            "writable": writable,
                            "key": f"{n}",
                        },
                    )
                )
        return out

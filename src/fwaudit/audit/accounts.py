"""Account database checks: /etc/passwd and /etc/shadow.

Detects empty passwords, hashes left in the world-readable passwd file, weak hash
schemes, factory-default passwords (by actually computing the crypt hash of each
candidate), extra UID-0 accounts and a world-readable shadow file.
"""

from __future__ import annotations

from dataclasses import dataclass

from fwaudit.audit.base import AuditConfig, mask, numbered_lines
from fwaudit.audit.cryptpw import ParsedHash, crack, parse_hash
from fwaudit.model import Finding, make_finding
from fwaudit.vfs import VirtualFS

NOLOGIN_SHELLS = ("/sbin/nologin", "/usr/sbin/nologin", "/bin/false", "/usr/bin/false", "/dev/null")
LOCKED_PREFIXES = ("!", "*")
PASSWD_PATHS = ("/etc/passwd",)
SHADOW_PATHS = ("/etc/shadow",)


@dataclass(frozen=True)
class PasswdEntry:
    name: str
    password: str
    uid: int
    gid: int
    home: str
    shell: str
    line: int

    @property
    def can_login(self) -> bool:
        return self.shell not in NOLOGIN_SHELLS


@dataclass(frozen=True)
class ShadowEntry:
    name: str
    password: str
    line: int


def parse_passwd(text: str) -> list[PasswdEntry]:
    """Parse passwd(5) lines; malformed lines are skipped."""
    out: list[PasswdEntry] = []
    for n, line in numbered_lines(text):
        if not line.strip() or line.lstrip().startswith("#"):
            continue
        f = line.split(":")
        if len(f) < 7:
            continue
        try:
            uid, gid = int(f[2]), int(f[3])
        except ValueError:
            continue
        out.append(PasswdEntry(f[0], f[1], uid, gid, f[5], f[6].strip(), n))
    return out


def parse_shadow(text: str) -> list[ShadowEntry]:
    out: list[ShadowEntry] = []
    for n, line in numbered_lines(text):
        if not line.strip() or line.lstrip().startswith("#"):
            continue
        f = line.split(":")
        if len(f) < 2:
            continue
        out.append(ShadowEntry(f[0], f[1].strip(), n))
    return out


def _is_locked(value: str) -> bool:
    return value.startswith(LOCKED_PREFIXES)


class AccountsCheck:
    name = "accounts"

    def run(self, fs: VirtualFS, config: AuditConfig) -> list[Finding]:
        findings: list[Finding] = []
        passwd_path, passwd = self._read_first(fs, PASSWD_PATHS)
        shadow_path, shadow = self._read_first(fs, SHADOW_PATHS)
        users = parse_passwd(passwd) if passwd is not None else []
        shadows = parse_shadow(shadow) if shadow is not None else []
        by_name = {u.name: u for u in users}

        for u in users:
            if u.uid == 0 and u.name != "root":
                findings.append(
                    make_finding(
                        "FWA-CRED-005",
                        f"account '{u.name}' has UID 0 (root privileges)",
                        filesystem=fs.fs_id,
                        path=passwd_path,
                        evidence={"user": u.name, "line": u.line, "key": u.name},
                    )
                )
            if u.password == "x":
                continue
            if u.password == "":
                # An empty passwd field means "no password"; shadow is not consulted.
                if u.can_login:
                    findings.append(self._empty(fs, passwd_path, u.name, u.line))
                continue
            if _is_locked(u.password):
                continue
            parsed = parse_hash(u.password)
            findings.append(
                make_finding(
                    "FWA-CRED-002",
                    f"password hash for '{u.name}' is stored in {passwd_path}",
                    filesystem=fs.fs_id,
                    path=passwd_path,
                    evidence={
                        "user": u.name,
                        "scheme": parsed.scheme,
                        "line": u.line,
                        "key": u.name,
                    },
                )
            )
            findings.extend(self._hash_findings(fs, passwd_path, u.name, u.line, parsed, config))

        for s in shadows:
            user = by_name.get(s.name)
            if user is not None and user.password != "x":
                continue  # passwd field overrides shadow
            if s.password == "":
                if user is None or user.can_login:
                    findings.append(self._empty(fs, shadow_path, s.name, s.line))
                continue
            if _is_locked(s.password):
                continue
            parsed = parse_hash(s.password)
            findings.extend(self._hash_findings(fs, shadow_path, s.name, s.line, parsed, config))

        if shadow_path is not None:
            node = fs.get(shadow_path)
            if node is not None and node.world_readable:
                findings.append(
                    make_finding(
                        "FWA-CRED-007",
                        f"{shadow_path} has mode {node.mode_string()} (readable by every user)",
                        filesystem=fs.fs_id,
                        path=shadow_path,
                        evidence={"mode": oct(node.mode)},
                    )
                )
        return findings

    @staticmethod
    def _read_first(fs: VirtualFS, paths: tuple[str, ...]) -> tuple[str | None, str | None]:
        for p in paths:
            text = fs.read_text(p)
            if text is not None:
                return p, text
        return None, None

    @staticmethod
    def _empty(fs: VirtualFS, path: str | None, user: str, line: int) -> Finding:
        return make_finding(
            "FWA-CRED-001",
            f"account '{user}' can log in without a password",
            filesystem=fs.fs_id,
            path=path,
            evidence={"user": user, "line": line, "key": user},
        )

    @staticmethod
    def _hash_findings(
        fs: VirtualFS,
        path: str | None,
        user: str,
        line: int,
        parsed: ParsedHash,
        config: AuditConfig,
    ) -> list[Finding]:
        out: list[Finding] = []
        if parsed.weak:
            out.append(
                make_finding(
                    "FWA-CRED-003",
                    f"password for '{user}' uses {parsed.scheme} crypt",
                    filesystem=fs.fs_id,
                    path=path,
                    evidence={"user": user, "scheme": parsed.scheme, "line": line, "key": user},
                )
            )
        guess = crack(parsed, config.guesses_for(user))
        if guess is not None:
            out.append(
                make_finding(
                    "FWA-CRED-004",
                    f"password for '{user}' is the default/guessable value "
                    f"{mask(guess, config.show_secrets)}",
                    filesystem=fs.fs_id,
                    path=path,
                    evidence={
                        "user": user,
                        "scheme": parsed.scheme,
                        "line": line,
                        "password": mask(guess, config.show_secrets),
                        "key": user,
                    },
                )
            )
        return out

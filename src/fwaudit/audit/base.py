"""Shared plumbing for filesystem checks: configuration, masking and text helpers."""

from __future__ import annotations

import json
from collections.abc import Iterator
from dataclasses import dataclass, field
from datetime import UTC, datetime
from functools import lru_cache
from importlib import resources
from typing import Protocol

from fwaudit.model import Finding
from fwaudit.vfs import VirtualFS

MiB = 1024 * 1024
TEXT_SAMPLE = 8192
SYSTEM_DIRS = ("/bin", "/sbin", "/usr", "/lib", "/etc", "/lib64", "/opt", "/www")


@lru_cache(maxsize=1)
def _default_credentials() -> tuple[tuple[str, str], ...]:
    raw = resources.files("fwaudit.data").joinpath("default_credentials.json").read_text()
    doc = json.loads(raw)
    return tuple((str(p["user"]), str(p["password"])) for p in doc["pairs"])


@dataclass(frozen=True)
class AuditConfig:
    """Knobs shared by every check. ``reference_time`` drives certificate expiry."""

    reference_time: datetime = field(default_factory=lambda: datetime.now(UTC))
    show_secrets: bool = False
    expiry_warning_days: int = 90
    max_scan_file_bytes: int = 16 * MiB
    default_credentials: tuple[tuple[str, str], ...] = field(default_factory=_default_credentials)

    @property
    def default_passwords(self) -> tuple[str, ...]:
        seen: dict[str, None] = {}
        for _, pw in self.default_credentials:
            seen.setdefault(pw, None)
        return tuple(seen)

    def is_default_pair(self, user: str, password: str) -> bool:
        """A known factory pair, or a password equal to the user name."""
        return (user, password) in self.default_credentials or (bool(password) and password == user)

    def guesses_for(self, user: str) -> list[str]:
        """Candidate passwords tried against a hash belonging to ``user``."""
        return list(dict.fromkeys([*self.default_passwords, user]))


class Check(Protocol):
    """A filesystem check: inspects one mounted filesystem and returns findings."""

    name: str

    def run(self, fs: VirtualFS, config: AuditConfig) -> list[Finding]: ...


def mask(secret: str, show: bool) -> str:
    """Redact a secret for reports: keep a 2-character hint and the length."""
    if show:
        return secret
    if not secret:
        return "<empty>"
    hint = secret[:2] if len(secret) > 4 else secret[:1]
    return f"{hint}{'*' * 3} (len {len(secret)})"


def is_probably_text(data: bytes) -> bool:
    sample = data[:TEXT_SAMPLE]
    if not sample:
        return False
    if b"\x00" in sample:
        return False
    printable = sum(1 for b in sample if 32 <= b < 127 or b in (9, 10, 13))
    return printable / len(sample) >= 0.9


def numbered_lines(text: str) -> Iterator[tuple[int, str]]:
    """Yield (1-based line number, line) with CR/LF variants normalised."""
    for i, line in enumerate(text.splitlines(), start=1):
        yield i, line


def strip_comment(line: str, marker: str = "#") -> str:
    """Remove a trailing comment that is not inside quotes."""
    quote: str | None = None
    for i, ch in enumerate(line):
        if quote:
            if ch == quote:
                quote = None
        elif ch in ("'", '"'):
            quote = ch
        elif ch == marker:
            return line[:i]
    return line


def text_files(fs: VirtualFS, prefixes: tuple[str, ...], max_bytes: int) -> Iterator[tuple[str, str]]:
    """(path, decoded text) for regular text files under any of ``prefixes``."""
    for node in fs.files():
        if not node.path.startswith(prefixes):
            continue
        if not node.data or len(node.data) > max_bytes or not is_probably_text(node.data):
            continue
        yield node.path, node.data.decode("utf-8", errors="replace")

"""Version parsing and range matching for the components fwaudit recognises.

Versions are converted to tuples that compare correctly with Python's tuple ordering:

* dotted numeric (BusyBox ``1.24.1``, dnsmasq ``2.78``, OpenSSL 3.x ``3.0.2``) become
  ``(1, 24, 1)``; missing trailing components are zero-padded to length 3;
* OpenSSL letter releases (``1.0.2k``, ``1.0.2zd``) append one integer per letter, so
  ``1.0.2`` < ``1.0.2a`` < ``1.0.2z`` < ``1.0.2za``;
* dropbear's ``YYYY.NN`` (``2019.78``) becomes ``(2019, 78, 0)``.

Ranges follow the OSV convention: affected when ``introduced <= v < fixed`` or
``introduced <= v <= last_affected``.
"""

from __future__ import annotations

import re
from dataclasses import dataclass

VersionKey = tuple[int, ...]
_VERSION_RE = re.compile(r"^(\d+(?:\.\d+){0,3})([a-z]{0,3})$")


def version_key(text: str) -> VersionKey:
    """Comparable key for a version string; raises ValueError if it cannot be parsed."""
    m = _VERSION_RE.match(text.strip())
    if m is None:
        raise ValueError(f"unparseable version {text!r}")
    nums = [int(p) for p in m.group(1).split(".")]
    while len(nums) < 3:
        nums.append(0)
    letters = [ord(c) - ord("a") + 1 for c in m.group(2)]
    return (*nums, *letters)


@dataclass(frozen=True)
class VersionRange:
    introduced: str
    fixed: str | None = None
    last_affected: str | None = None

    def __post_init__(self) -> None:
        if (self.fixed is None) == (self.last_affected is None):
            raise ValueError("exactly one of fixed / last_affected must be set")
        version_key(self.introduced)
        version_key(self.fixed or self.last_affected or "0")

    def contains(self, version: str) -> bool:
        v = version_key(version)
        if v < version_key(self.introduced):
            return False
        if self.fixed is not None:
            return v < version_key(self.fixed)
        return v <= version_key(str(self.last_affected))

    def describe(self) -> str:
        if self.fixed is not None:
            return f">= {self.introduced}, < {self.fixed}"
        return f">= {self.introduced}, <= {self.last_affected}"

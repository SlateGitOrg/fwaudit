"""Archive member path normalisation.

Member names come straight from attacker-controlled headers. :func:`normalize_member`
turns them into a canonical absolute path *inside* a virtual root, or rejects them.
The rules are deliberately stricter than GNU tar:

* NUL bytes, empty names and over-long names are rejected;
* a leading ``/`` (absolute member) is stripped and reported as a note, matching GNU
  tar's default behaviour;
* any ``..`` component is rejected outright, even when it would stay inside the root
  (``a/../b``), because legitimate firmware archives never need it and allowing it makes
  traversal checks order-dependent;
* ``.`` components and duplicate separators are collapsed.
"""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class PathVerdict:
    """Result of normalising one member name."""

    path: str | None
    reason: str | None = None
    note: str | None = None

    @property
    def ok(self) -> bool:
        return self.path is not None


def decode_name(raw: bytes) -> str:
    """Decode a member name losslessly (undecodable bytes become surrogate escapes)."""
    return raw.decode("utf-8", errors="surrogateescape")


def normalize_member(raw: bytes, *, max_len: int = 4096) -> PathVerdict:
    """Return the canonical in-root path for ``raw`` or the reason it is unsafe."""
    if not raw:
        return PathVerdict(None, "empty member name")
    if b"\x00" in raw:
        return PathVerdict(None, "NUL byte in member name")
    if len(raw) > max_len:
        return PathVerdict(None, f"member name longer than {max_len} bytes")
    name = decode_name(raw)
    note = None
    if name.startswith("/"):
        note = "absolute member name; leading '/' stripped"
    parts: list[str] = []
    for part in name.split("/"):
        if part in ("", "."):
            continue
        if part == "..":
            return PathVerdict(None, "parent-directory component '..' in member name")
        parts.append(part)
    if not parts:
        return PathVerdict("/", None, note)
    return PathVerdict("/" + "/".join(parts), None, note)


def join_symlink(base_dir: str, target: str) -> list[str]:
    """Resolve ``target`` relative to ``base_dir`` with chroot semantics.

    Absolute targets are interpreted relative to the virtual root and ``..`` can never
    climb above it. Returns the resulting path as a list of components.
    """
    if target.startswith("/"):
        stack: list[str] = []
    else:
        stack = [p for p in base_dir.split("/") if p]
    for part in target.split("/"):
        if part in ("", "."):
            continue
        if part == "..":
            if stack:
                stack.pop()
            continue
        stack.append(part)
    return stack

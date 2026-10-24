"""POSIX tar reader built on :mod:`tarfile` header parsing only.

``tarfile`` is used to decode headers (ustar, GNU long names, pax) but its extraction
functions are never called: member data is copied into :class:`ArchiveEntry` objects and
mounted in a :class:`~fwaudit.vfs.VirtualFS`, so tar's long history of path-traversal
bugs cannot touch the host. Compressed tarballs are handled by the generic decompression
layer before reaching this module.
"""

from __future__ import annotations

import io
import tarfile
from dataclasses import dataclass

from fwaudit.errors import FormatError, TruncatedError
from fwaudit.formats.entries import ArchiveEntry, EntryKind
from fwaudit.limits import Budget

BLOCK = 512
USTAR_OFFSET = 257


@dataclass
class TarResult:
    entries: list[ArchiveEntry]
    consumed: int
    complete: bool


def header_checksum_ok(block: bytes) -> bool:
    """Validate the header checksum (the chksum field counts as eight spaces)."""
    if len(block) < BLOCK:
        return False
    field = block[148:156].replace(b"\x00", b" ").strip()
    try:
        stored = int(field, 8)
    except ValueError:
        return False
    unsigned = sum(block[:148]) + 8 * 32 + sum(block[156:BLOCK])
    signed = (
        sum((b - 256 if b > 127 else b) for b in block[:148])
        + 256
        + sum((b - 256 if b > 127 else b) for b in block[156:BLOCK])
    )
    return stored in (unsigned, signed)


def _kind(member: tarfile.TarInfo) -> EntryKind | None:
    if member.isreg():
        return EntryKind.FILE
    if member.isdir():
        return EntryKind.DIR
    if member.issym():
        return EntryKind.SYMLINK
    if member.islnk():
        return EntryKind.HARDLINK
    if member.ischr():
        return EntryKind.CHARDEV
    if member.isblk():
        return EntryKind.BLOCKDEV
    if member.isfifo():
        return EntryKind.FIFO
    return None


def parse(data: bytes | memoryview, budget: Budget, *, what: str = "tar") -> TarResult:
    """Parse a tar archive starting at ``data[0]``."""
    raw = bytes(data)
    if not header_checksum_ok(raw[:BLOCK]):
        raise FormatError("tar: first header checksum invalid")
    fileobj = io.BytesIO(raw)
    entries: list[ArchiveEntry] = []
    complete = True
    try:
        tf = tarfile.open(fileobj=fileobj, mode="r:", errorlevel=1)  # noqa: SIM115 - closed below
    except tarfile.TarError as exc:
        raise FormatError(f"tar: {exc}") from exc
    max_file = budget.limits.max_file_bytes
    with tf:
        while True:
            try:
                member = tf.next()
            except (tarfile.TarError, EOFError, ValueError) as exc:
                if not entries:
                    raise TruncatedError(f"tar: {exc}") from exc
                complete = False
                break
            if member is None:
                break
            budget.charge_entry(what)
            kind = _kind(member)
            if kind is None:
                continue
            name = member.name.encode("utf-8", errors="surrogateescape")
            mode = member.mode & 0o7777
            if kind is EntryKind.FILE:
                content, truncated = _read_member(tf, member, max_file)
                budget.charge_bytes(len(content), what)
                entries.append(
                    ArchiveEntry(
                        name, kind, mode, member.uid, member.gid, content, truncated=truncated
                    )
                )
                if len(content) < min(member.size, max_file):
                    complete = False
                    break
            elif kind in (EntryKind.SYMLINK, EntryKind.HARDLINK):
                target = member.linkname.encode("utf-8", errors="surrogateescape")
                entries.append(
                    ArchiveEntry(name, kind, mode, member.uid, member.gid, link_target=target)
                )
            else:
                rdev = (member.devmajor, member.devminor) if member.isdev() else None
                entries.append(ArchiveEntry(name, kind, mode, member.uid, member.gid, rdev=rdev))
        end = tf.offset
        if raw[end : end + BLOCK] != b"\x00" * BLOCK:
            complete = False  # no end-of-archive marker: truncated (or trailing garbage)
        consumed = min(len(raw), end + 2 * BLOCK)
    return TarResult(entries, consumed, complete)


def _read_member(tf: tarfile.TarFile, member: tarfile.TarInfo, limit: int) -> tuple[bytes, bool]:
    handle = tf.extractfile(member)
    if handle is None:
        return b"", False
    with handle:
        try:
            content = handle.read(limit)
        except (tarfile.TarError, OSError, EOFError):
            return b"", True
    return content, member.size > limit

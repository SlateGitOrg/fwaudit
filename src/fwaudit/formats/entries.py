"""Format-neutral archive entry produced by the cpio, tar and squashfs readers."""

from __future__ import annotations

import stat
from dataclasses import dataclass
from enum import StrEnum


class EntryKind(StrEnum):
    FILE = "file"
    DIR = "dir"
    SYMLINK = "symlink"
    HARDLINK = "hardlink"
    CHARDEV = "chardev"
    BLOCKDEV = "blockdev"
    FIFO = "fifo"
    SOCKET = "socket"


_KIND_BY_IFMT = {
    stat.S_IFREG: EntryKind.FILE,
    stat.S_IFDIR: EntryKind.DIR,
    stat.S_IFLNK: EntryKind.SYMLINK,
    stat.S_IFCHR: EntryKind.CHARDEV,
    stat.S_IFBLK: EntryKind.BLOCKDEV,
    stat.S_IFIFO: EntryKind.FIFO,
    stat.S_IFSOCK: EntryKind.SOCKET,
}


def kind_from_mode(mode: int) -> EntryKind | None:
    """Map the S_IFMT bits of a POSIX mode to an entry kind (``None`` if unknown)."""
    return _KIND_BY_IFMT.get(stat.S_IFMT(mode))


@dataclass(frozen=True)
class ArchiveEntry:
    """One member of an archive or filesystem image.

    ``name`` is the raw member name exactly as stored (it is *not* trusted). ``mode``
    holds only permission bits (including setuid/setgid/sticky). ``data`` is set for
    regular files, ``link_target`` for symlinks and hard links.
    """

    name: bytes
    kind: EntryKind
    mode: int
    uid: int = 0
    gid: int = 0
    data: bytes = b""
    link_target: bytes | None = None
    rdev: tuple[int, int] | None = None
    truncated: bool = False

    @property
    def size(self) -> int:
        return len(self.data)

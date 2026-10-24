"""cpio archive reader (``newc``, ``crc`` and portable ``odc`` formats) and a newc writer.

``newc``/``crc`` headers are 110 bytes of ASCII hex; the name is padded so that header
plus name is a multiple of 4, and file data is padded to 4 bytes. ``odc`` headers are 76
bytes of ASCII octal with no padding. Archives end with a ``TRAILER!!!`` member.

Hard links in newc archives are stored as several members sharing an inode number where
only the last one carries the data; the reader resolves them after the trailer.
"""

from __future__ import annotations

import stat
from collections.abc import Iterator
from dataclasses import dataclass, field

from fwaudit.errors import FormatError, TruncatedError
from fwaudit.formats.entries import ArchiveEntry, EntryKind, kind_from_mode
from fwaudit.limits import Budget

NEWC_MAGIC = b"070701"
CRC_MAGIC = b"070702"
ODC_MAGIC = b"070707"
TRAILER = b"TRAILER!!!"
NEWC_HEADER = 110
ODC_HEADER = 76
MAX_NAME = 4096


@dataclass
class CpioResult:
    entries: list[ArchiveEntry]
    consumed: int
    variant: str
    checksum_errors: list[str] = field(default_factory=list)
    complete: bool = True


@dataclass(frozen=True)
class _Raw:
    name: bytes
    mode: int
    uid: int
    gid: int
    nlink: int
    ino: int
    dev: tuple[int, int]
    rdev: tuple[int, int]
    data: bytes
    checksum: int


def _hex(field_bytes: bytes, what: str) -> int:
    try:
        return int(field_bytes, 16)
    except ValueError:
        raise FormatError(f"cpio: non-hex {what} field") from None


def _oct(field_bytes: bytes, what: str) -> int:
    try:
        return int(field_bytes, 8)
    except ValueError:
        raise FormatError(f"cpio: non-octal {what} field") from None


def _pad4(n: int) -> int:
    return (n + 3) & ~3


def _read_newc(data: memoryview, pos: int) -> tuple[_Raw, int]:
    if pos + NEWC_HEADER > len(data):
        raise TruncatedError("cpio: header truncated")
    h = bytes(data[pos : pos + NEWC_HEADER])
    if h[:6] not in (NEWC_MAGIC, CRC_MAGIC):
        raise FormatError(f"cpio: bad magic at offset {pos}")
    f = [_hex(h[6 + 8 * i : 14 + 8 * i], f"field{i}") for i in range(13)]
    ino, mode, uid, gid, nlink, _mtime, filesize = f[0:7]
    devmaj, devmin, rdevmaj, rdevmin, namesize, check = f[7:13]
    if namesize == 0 or namesize > MAX_NAME:
        raise FormatError(f"cpio: implausible name size {namesize}")
    name_start = pos + NEWC_HEADER
    name_end = name_start + namesize
    data_start = _pad4(name_end - pos) + pos
    data_end = data_start + filesize
    if data_end > len(data):
        raise TruncatedError("cpio: member data truncated")
    name = bytes(data[name_start : name_end - 1])
    raw = _Raw(
        name=name,
        mode=mode,
        uid=uid,
        gid=gid,
        nlink=nlink,
        ino=ino,
        dev=(devmaj, devmin),
        rdev=(rdevmaj, rdevmin),
        data=bytes(data[data_start:data_end]),
        checksum=check,
    )
    return raw, _pad4(data_end - pos) + pos


def _read_odc(data: memoryview, pos: int) -> tuple[_Raw, int]:
    if pos + ODC_HEADER > len(data):
        raise TruncatedError("cpio: header truncated")
    h = bytes(data[pos : pos + ODC_HEADER])
    if h[:6] != ODC_MAGIC:
        raise FormatError(f"cpio: bad magic at offset {pos}")
    dev = _oct(h[6:12], "dev")
    ino = _oct(h[12:18], "ino")
    mode = _oct(h[18:24], "mode")
    uid = _oct(h[24:30], "uid")
    gid = _oct(h[30:36], "gid")
    nlink = _oct(h[36:42], "nlink")
    rdev = _oct(h[42:48], "rdev")
    namesize = _oct(h[59:65], "namesize")
    filesize = _oct(h[65:76], "filesize")
    if namesize == 0 or namesize > MAX_NAME:
        raise FormatError(f"cpio: implausible name size {namesize}")
    name_start = pos + ODC_HEADER
    data_start = name_start + namesize
    data_end = data_start + filesize
    if data_end > len(data):
        raise TruncatedError("cpio: member data truncated")
    raw = _Raw(
        name=bytes(data[name_start : data_start - 1]),
        mode=mode,
        uid=uid,
        gid=gid,
        nlink=nlink,
        ino=ino,
        dev=(dev >> 8, dev & 0xFF),
        rdev=(rdev >> 8, rdev & 0xFF),
        data=bytes(data[data_start:data_end]),
        checksum=0,
    )
    return raw, data_end


def _iter_raw(data: memoryview, variant: str) -> Iterator[tuple[_Raw, int]]:
    reader = _read_odc if variant == "odc" else _read_newc
    pos = 0
    while True:
        raw, nxt = reader(data, pos)
        yield raw, nxt
        if raw.name == TRAILER:
            return
        pos = nxt


def detect_variant(data: bytes | memoryview) -> str | None:
    magic = bytes(data[:6])
    return {NEWC_MAGIC: "newc", CRC_MAGIC: "crc", ODC_MAGIC: "odc"}.get(magic)


def parse(data: bytes | memoryview, budget: Budget, *, what: str = "cpio") -> CpioResult:
    """Parse a cpio archive starting at ``data[0]``.

    A truncated archive yields the members read so far with ``complete=False``; a
    malformed first header raises :class:`FormatError`.
    """
    view = memoryview(data)
    variant = detect_variant(view)
    if variant is None:
        raise FormatError("cpio: unknown magic")
    entries: list[ArchiveEntry] = []
    errors: list[str] = []
    pending_links: dict[tuple[tuple[int, int], int], list[_Raw]] = {}
    consumed = 0
    complete = False
    max_file = budget.limits.max_file_bytes
    try:
        for raw, nxt in _iter_raw(view, variant):
            consumed = nxt
            if raw.name == TRAILER:
                complete = True
                break
            budget.charge_entry(what)
            if variant == "crc" and stat.S_ISREG(raw.mode):
                actual = sum(raw.data) & 0xFFFFFFFF
                if actual != raw.checksum:
                    errors.append(raw.name.decode("latin-1"))
            kind = kind_from_mode(raw.mode)
            if kind is None:
                continue
            if kind is EntryKind.FILE and raw.nlink > 1 and variant != "odc":
                pending_links.setdefault((raw.dev, raw.ino), []).append(raw)
                if not raw.data:
                    continue
            entries.append(_to_entry(raw, kind, budget, max_file, what))
    except TruncatedError:
        if not entries:
            raise
    entries.extend(_resolve_hardlinks(pending_links))
    return CpioResult(entries, consumed, variant, errors, complete)


def _to_entry(raw: _Raw, kind: EntryKind, budget: Budget, max_file: int, what: str) -> ArchiveEntry:
    data = raw.data if kind in (EntryKind.FILE, EntryKind.SYMLINK) else b""
    truncated = False
    if kind is EntryKind.FILE and len(data) > max_file:
        data, truncated = data[:max_file], True
    if kind is EntryKind.SYMLINK:
        budget.charge_bytes(len(data), what)
        return ArchiveEntry(
            raw.name, kind, raw.mode & 0o7777, raw.uid, raw.gid, link_target=data
        )
    budget.charge_bytes(len(data), what)
    rdev = raw.rdev if kind in (EntryKind.CHARDEV, EntryKind.BLOCKDEV) else None
    return ArchiveEntry(
        raw.name,
        kind,
        raw.mode & 0o7777,
        raw.uid,
        raw.gid,
        data=data,
        rdev=rdev,
        truncated=truncated,
    )


def _resolve_hardlinks(
    pending: dict[tuple[tuple[int, int], int], list[_Raw]],
) -> list[ArchiveEntry]:
    """newc stores hard-link data once (on the last member); emit links to it."""
    out: list[ArchiveEntry] = []
    for members in pending.values():
        holders = [m for m in members if m.data]
        if not holders:
            continue
        target = holders[-1]
        for m in members:
            if m is target or m.data:
                continue
            out.append(
                ArchiveEntry(m.name, EntryKind.HARDLINK, m.mode & 0o7777, m.uid, m.gid,
                             link_target=target.name)
            )  # fmt: skip
    return out


def build_newc(entries: list[ArchiveEntry], *, mtime: int = 0) -> bytes:
    """Serialise entries as a newc archive (used by the synthetic image builder)."""
    out = bytearray()
    ino = 1

    def member(name: bytes, mode: int, uid: int, gid: int, data: bytes, rdev: tuple[int, int]) -> None:
        nonlocal ino
        namesize = len(name) + 1
        fields = (
            ino, mode, uid, gid, 1, mtime, len(data), 0, 0, rdev[0], rdev[1], namesize, 0,
        )  # fmt: skip
        header = NEWC_MAGIC + b"".join(b"%08X" % v for v in fields)
        out.extend(header + name + b"\x00")
        out.extend(b"\x00" * (-(len(header) + namesize) % 4))
        out.extend(data)
        out.extend(b"\x00" * (-len(data) % 4))
        ino += 1

    type_bits = {
        EntryKind.FILE: stat.S_IFREG,
        EntryKind.DIR: stat.S_IFDIR,
        EntryKind.SYMLINK: stat.S_IFLNK,
        EntryKind.CHARDEV: stat.S_IFCHR,
        EntryKind.BLOCKDEV: stat.S_IFBLK,
        EntryKind.FIFO: stat.S_IFIFO,
        EntryKind.SOCKET: stat.S_IFSOCK,
    }
    for e in entries:
        if e.kind is EntryKind.HARDLINK:
            raise ValueError("build_newc does not emit hard links")
        payload = (e.link_target or b"") if e.kind is EntryKind.SYMLINK else e.data
        member(e.name, type_bits[e.kind] | e.mode, e.uid, e.gid, payload, e.rdev or (0, 0))
    member(TRAILER, 0, 0, 0, b"", (0, 0))
    out.extend(b"\x00" * (-len(out) % 512))
    return bytes(out)

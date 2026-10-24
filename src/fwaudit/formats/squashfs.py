"""SquashFS 4.0 reading via the PySquashfsImage library, hardened for hostile input.

PySquashfsImage is a pure-Python reader. Two things are added around it:

* **Bounded decompressors.** The library's compressors call ``zlib.decompress`` with no
  output cap. They are replaced with decoders that refuse to produce more than one
  block (``block_size`` for data, 8 KiB for metadata), which is the most a well-formed
  block can ever hold.
* **Superblock sanity checks** before the library touches the image (block size,
  ``bytes_used`` within the input, supported compressor), and conversion of every
  library exception — including ``RecursionError`` from directory cycles — into
  :class:`~fwaudit.errors.FormatError`.

Only gzip (zlib) and xz compression are supported because they need nothing beyond the
standard library; LZO, LZ4 and ZSTD images raise :class:`UnsupportedFormatError`.
"""

from __future__ import annotations

import lzma
import stat
import struct
import zlib
from dataclasses import dataclass
from typing import Any

from PySquashfsImage import SquashFsImage

from fwaudit.errors import FormatError, LimitExceededError, TruncatedError, UnsupportedFormatError
from fwaudit.formats.entries import ArchiveEntry, EntryKind, kind_from_mode
from fwaudit.limits import Budget

SQUASHFS_MAGIC_LE = b"hsqs"
SQUASHFS_MAGIC_BE = b"sqsh"
SUPERBLOCK_SIZE = 96
_SUPER = struct.Struct("<5I6H8Q")
COMPRESSORS = {1: "gzip", 2: "lzma", 3: "lzo", 4: "xz", 5: "lz4", 6: "zstd"}
SUPPORTED = {1, 4}


@dataclass(frozen=True)
class Superblock:
    inode_count: int
    mkfs_time: int
    block_size: int
    fragment_count: int
    compression: int
    block_log: int
    flags: int
    id_count: int
    version: tuple[int, int]
    root_inode: int
    bytes_used: int

    @property
    def compression_name(self) -> str:
        return COMPRESSORS.get(self.compression, f"unknown({self.compression})")


@dataclass
class SquashfsResult:
    superblock: Superblock
    entries: list[ArchiveEntry]
    consumed: int


def parse_superblock(data: bytes | memoryview) -> Superblock:
    if len(data) < SUPERBLOCK_SIZE:
        raise TruncatedError("squashfs: superblock truncated")
    raw = bytes(data[:SUPERBLOCK_SIZE])
    if raw[:4] == SQUASHFS_MAGIC_BE:
        raise UnsupportedFormatError("squashfs: big-endian (pre-4.0 or vendor) image")
    if raw[:4] != SQUASHFS_MAGIC_LE:
        raise FormatError("squashfs: bad magic")
    f = _SUPER.unpack(raw)
    sb = Superblock(
        inode_count=f[1],
        mkfs_time=f[2],
        block_size=f[3],
        fragment_count=f[4],
        compression=f[5],
        block_log=f[6],
        flags=f[7],
        id_count=f[8],
        version=(f[9], f[10]),
        root_inode=f[11],
        bytes_used=f[12],
    )
    if sb.version != (4, 0):
        raise UnsupportedFormatError(f"squashfs: version {sb.version[0]}.{sb.version[1]}")
    if not 4096 <= sb.block_size <= 1024 * 1024 or sb.block_size != 1 << sb.block_log:
        raise FormatError("squashfs: implausible block size")
    if sb.bytes_used < SUPERBLOCK_SIZE:
        raise FormatError("squashfs: implausible bytes_used")
    return sb


METADATA_SIZE = 8192


def _cap(outsize: int) -> int:
    """The library passes 0 for a table's final block when the table size is an exact
    multiple of 8 KiB; 0 would mean "unbounded" to zlib, so clamp it to one block."""
    return outsize if outsize > 0 else METADATA_SIZE


class _BoundedZlib:
    name = "gzip"

    def uncompress(self, src: bytes, size: int, outsize: int) -> bytes:
        d = zlib.decompressobj()
        try:
            out = d.decompress(src, _cap(outsize))
        except zlib.error as exc:
            raise FormatError(f"squashfs: corrupt zlib block ({exc})") from exc
        if d.unconsumed_tail:
            raise LimitExceededError("max_ratio", "squashfs: block inflates past block size")
        return out


class _BoundedXz:
    name = "xz"

    def uncompress(self, src: bytes, size: int, outsize: int) -> bytes:
        d = lzma.LZMADecompressor(format=lzma.FORMAT_XZ, memlimit=64 * 1024 * 1024)
        try:
            out = d.decompress(src, _cap(outsize))
        except lzma.LZMAError as exc:
            raise FormatError(f"squashfs: corrupt xz block ({exc})") from exc
        if not d.eof and not d.needs_input:
            raise LimitExceededError("max_ratio", "squashfs: block inflates past block size")
        return out


class _HardenedImage(SquashFsImage):  # type: ignore[misc]
    """SquashFsImage with bounded decompressors."""

    def _get_compressor(self, compression_id: int) -> Any:
        if compression_id == 1:
            return _BoundedZlib()
        if compression_id == 4:
            return _BoundedXz()
        raise UnsupportedFormatError(
            f"squashfs: {COMPRESSORS.get(compression_id, compression_id)} compression"
        )


def parse(data: bytes | memoryview, budget: Budget, *, what: str = "squashfs") -> SquashfsResult:
    """Read every member of the squashfs image that starts at ``data[0]``."""
    sb = parse_superblock(data)
    if sb.compression not in SUPPORTED:
        raise UnsupportedFormatError(f"squashfs: {sb.compression_name} compression")
    if sb.bytes_used > len(data):
        raise TruncatedError(
            f"squashfs: bytes_used {sb.bytes_used} exceeds available {len(data)}"
        )
    blob = bytes(data[: sb.bytes_used])
    max_file = budget.limits.max_file_bytes
    entries: list[ArchiveEntry] = []
    try:
        image = _HardenedImage.from_bytes(blob)
        for f in image:
            budget.charge_entry(what)
            entry = _convert(f, max_file, budget, what)
            if entry is not None:
                entries.append(entry)
    except (FormatError, LimitExceededError):
        raise
    except RecursionError as exc:
        raise FormatError("squashfs: directory structure is cyclic or too deep") from exc
    except Exception as exc:
        raise FormatError(f"squashfs: {type(exc).__name__}: {exc}") from exc
    return SquashfsResult(sb, entries, sb.bytes_used)


def _convert(f: Any, max_file: int, budget: Budget, what: str) -> ArchiveEntry | None:
    mode = int(f.mode)
    kind = kind_from_mode(mode)
    if kind is None:
        return None
    name = f.path.encode("utf-8", errors="surrogateescape") if isinstance(f.path, str) else f.path
    perms = stat.S_IMODE(mode)
    uid, gid = int(f.uid), int(f.gid)
    if kind is EntryKind.FILE:
        out = bytearray()
        truncated = False
        for block in f.iter_bytes():
            room = max_file - len(out)
            if len(block) > room:
                out += block[:room]
                truncated = True
                break
            out += block
        budget.charge_bytes(len(out), what)
        return ArchiveEntry(name, kind, perms, uid, gid, bytes(out), truncated=truncated)
    if kind is EntryKind.SYMLINK:
        target = f.readlink()
        target_b = target if isinstance(target, bytes) else str(target).encode()
        return ArchiveEntry(name, kind, perms, uid, gid, link_target=target_b)
    if kind in (EntryKind.CHARDEV, EntryKind.BLOCKDEV):
        return ArchiveEntry(name, kind, perms, uid, gid, rdev=(int(f.major), int(f.minor)))
    return ArchiveEntry(name, kind, perms, uid, gid)

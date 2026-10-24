"""Magic-signature database and scanner used for identification and carving.

Each :class:`Signature` pairs a byte pattern with a cheap structural validator that looks
only at the header (CRCs, field ranges, checksums). The scanner runs one ``bytes.find``
loop per signature, so a scan is O(k * n) for k signatures over n bytes with C-speed
inner loops; validators run only at candidate offsets.

Signatures are either *extractable* (the engine knows how to decode them) or
*informational* (reported by ``fwaudit identify`` only). Some recognised-but-unsupported
containers (CramFS, big-endian SquashFS) are reported so the gap is visible.
"""

from __future__ import annotations

import struct
import zlib
from collections.abc import Callable
from dataclasses import dataclass, field

from fwaudit.errors import FormatError, UnsupportedFormatError
from fwaudit.formats import squashfs, tar, uimage
from fwaudit.formats.compression import lzma_header_plausible
from fwaudit.model import JsonValue

Meta = dict[str, JsonValue]
Validator = Callable[[memoryview, int], Meta | None]
MAX_HITS = 100_000


@dataclass(frozen=True)
class Signature:
    name: str
    magic: bytes
    description: str
    validate: Validator
    magic_offset: int = 0
    extractable: bool = True
    supported: bool = True


@dataclass(frozen=True)
class Hit:
    offset: int
    name: str
    description: str
    extractable: bool
    supported: bool
    meta: Meta = field(default_factory=dict)


def _v_uimage(data: memoryview, off: int) -> Meta | None:
    try:
        h = uimage.parse_header(data[off:])
    except FormatError:
        return None
    known = h.os in uimage.OS_TYPES and h.arch in uimage.ARCH_TYPES
    if not (h.header_crc_ok or known):
        return None
    return {
        "name": h.name,
        "type": h.type_name,
        "compression": h.compression_name,
        "data_size": h.data_size,
        "header_crc_ok": h.header_crc_ok,
    }


def _v_gzip(data: memoryview, off: int) -> Meta | None:
    if off + 10 > len(data):
        return None
    flags, xfl, os_ = data[off + 3], data[off + 8], data[off + 9]
    # RFC 1952 defines OS codes 0-13; zlib builds also emit 19 (macOS) and 255 (unknown).
    if flags & 0xE0 or xfl not in (0, 2, 4) or (os_ > 31 and os_ != 255):
        return None
    return {}


def _v_xz(data: memoryview, off: int) -> Meta | None:
    if off + 12 > len(data):
        return None
    flags = bytes(data[off + 6 : off + 8])
    (crc,) = struct.unpack_from("<I", data, off + 8)
    if flags[0] != 0 or flags[1] not in (0x00, 0x01, 0x04, 0x0A) or zlib.crc32(flags) != crc:
        return None
    return {}


def _v_lzma(data: memoryview, off: int) -> Meta | None:
    header = bytes(data[off : off + 13])
    if not lzma_header_plausible(header):
        return None
    size = int.from_bytes(header[5:13], "little")
    return {"declared_size": None if size == 0xFFFFFFFFFFFFFFFF else size}


def _v_bzip2(data: memoryview, off: int) -> Meta | None:
    head = bytes(data[off : off + 10])
    if len(head) < 10 or not 0x31 <= head[3] <= 0x39 or head[4:10] != b"1AY&SY":
        return None
    return {"block_size_100k": head[3] - 0x30}


def _v_cpio_hex(data: memoryview, off: int) -> Meta | None:
    head = bytes(data[off + 6 : off + 110])
    if len(head) < 104:
        return None
    try:
        int(head, 16)
    except ValueError:
        return None
    return {}


def _v_cpio_odc(data: memoryview, off: int) -> Meta | None:
    head = bytes(data[off + 6 : off + 76])
    if len(head) < 70:
        return None
    try:
        int(head, 8)
    except ValueError:
        return None
    return {}


def _v_tar(data: memoryview, off: int) -> Meta | None:
    if off < 0 or not tar.header_checksum_ok(bytes(data[off : off + tar.BLOCK])):
        return None
    return {}


def _v_squashfs(data: memoryview, off: int) -> Meta | None:
    try:
        sb = squashfs.parse_superblock(data[off:])
    except UnsupportedFormatError as exc:
        return {"unsupported": str(exc)}
    except FormatError:
        return None
    meta: Meta = {
        "compression": sb.compression_name,
        "bytes_used": sb.bytes_used,
        "inodes": sb.inode_count,
        "block_size": sb.block_size,
    }
    if sb.compression not in squashfs.SUPPORTED:
        meta["unsupported"] = f"{sb.compression_name} compression"
    return meta


def _v_squashfs_be(data: memoryview, off: int) -> Meta | None:
    head = bytes(data[off : off + 30])
    if len(head) < 30:
        return None
    major = struct.unpack_from(">H", head, 28)[0]
    if major not in (1, 2, 3, 4):
        return None
    return {"version_major": major}


def _v_elf(data: memoryview, off: int) -> Meta | None:
    head = bytes(data[off : off + 20])
    if len(head) < 20 or head[4] not in (1, 2) or head[5] not in (1, 2) or head[6] != 1:
        return None
    fmt = "<H" if head[5] == 1 else ">H"
    machine = struct.unpack_from(fmt, head, 18)[0]
    return {
        "class": 32 if head[4] == 1 else 64,
        "endian": "le" if head[5] == 1 else "be",
        "machine": machine,
    }


def _v_cramfs(data: memoryview, off: int) -> Meta | None:
    if bytes(data[off + 16 : off + 32]) != b"Compressed ROMFS":
        return None
    return {}


def _v_fdt(data: memoryview, off: int) -> Meta | None:
    head = bytes(data[off : off + 40])
    if len(head) < 40:
        return None
    total, _struct, _strings, _rsv, version = struct.unpack_from(">5I", head, 4)
    if not 40 <= total <= 16 * 1024 * 1024 or version > 32:
        return None
    return {"total_size": total, "version": version}


SIGNATURES: tuple[Signature, ...] = (
    Signature("uimage", struct.pack(">I", uimage.UIMAGE_MAGIC), "U-Boot legacy image", _v_uimage),
    Signature("gzip", b"\x1f\x8b\x08", "gzip stream", _v_gzip),
    Signature("xz", b"\xfd7zXZ\x00", "xz stream", _v_xz),
    Signature("lzma", b"\x5d\x00\x00", "LZMA-alone stream", _v_lzma),
    Signature("bzip2", b"BZh", "bzip2 stream", _v_bzip2),
    Signature("cpio", b"070701", "cpio archive (newc)", _v_cpio_hex),
    Signature("cpio", b"070702", "cpio archive (newc+crc)", _v_cpio_hex),
    Signature("cpio", b"070707", "cpio archive (odc)", _v_cpio_odc),
    Signature("tar", b"ustar", "POSIX tar archive", _v_tar, magic_offset=tar.USTAR_OFFSET),
    Signature("squashfs", squashfs.SQUASHFS_MAGIC_LE, "SquashFS 4.0 filesystem", _v_squashfs),
    Signature(
        "squashfs-be",
        squashfs.SQUASHFS_MAGIC_BE,
        "big-endian SquashFS (legacy/vendor)",
        _v_squashfs_be,
        supported=False,
    ),
    Signature("cramfs", b"\x45\x3d\xcd\x28", "CramFS filesystem", _v_cramfs, supported=False),
    Signature("elf", b"\x7fELF", "ELF executable", _v_elf, extractable=False),
    Signature("fdt", b"\xd0\x0d\xfe\xed", "flattened device tree", _v_fdt, extractable=False),
)


def scan(
    data: bytes,
    signatures: tuple[Signature, ...] = SIGNATURES,
    *,
    max_hits: int = MAX_HITS,
) -> list[Hit]:
    """Return validated signature hits in ``data`` ordered by offset."""
    view = memoryview(data)
    hits: list[Hit] = []
    for sig in signatures:
        pos = data.find(sig.magic)
        while pos != -1 and len(hits) < max_hits:
            start = pos - sig.magic_offset
            if start >= 0:
                meta = sig.validate(view, start)
                if meta is not None:
                    supported = sig.supported and "unsupported" not in meta
                    hits.append(
                        Hit(start, sig.name, sig.description, sig.extractable, supported, meta)
                    )
            pos = data.find(sig.magic, pos + 1)
    order = {s.name: i for i, s in enumerate(signatures)}
    hits.sort(key=lambda h: (h.offset, order[h.name]))
    return hits


def match_at_start(data: bytes, signatures: tuple[Signature, ...] = SIGNATURES) -> Hit | None:
    """Return the extractable signature that matches at offset 0, if any (lzma excluded,
    because its 3-byte magic is too weak to trust without other context)."""
    view = memoryview(data)
    for sig in signatures:
        if not sig.extractable or sig.name == "lzma":
            continue
        start = sig.magic_offset
        if data[start : start + len(sig.magic)] != sig.magic:
            continue
        meta = sig.validate(view, 0)
        if meta is not None:
            supported = sig.supported and "unsupported" not in meta
            return Hit(0, sig.name, sig.description, sig.extractable, supported, meta)
    return None

"""U-Boot legacy image (``uImage``) header parsing and verification.

Layout (all fields big-endian, 64 bytes)::

    magic u32 | hcrc u32 | time u32 | size u32 | load u32 | ep u32 | dcrc u32 |
    os u8 | arch u8 | type u8 | comp u8 | name[32]

``hcrc`` is the CRC-32 of the header with the ``hcrc`` field zeroed; ``dcrc`` covers the
``size`` payload bytes. Multi-file images (type 4) start their payload with a
zero-terminated list of big-endian u32 sizes; each sub-image is padded to 4 bytes.
"""

from __future__ import annotations

import struct
import zlib
from dataclasses import dataclass

from fwaudit.errors import FormatError, TruncatedError

UIMAGE_MAGIC = 0x27051956
HEADER_SIZE = 64
_HEADER = struct.Struct(">7I4B32s")

IMAGE_TYPES = {
    0: "invalid",
    1: "standalone",
    2: "kernel",
    3: "ramdisk",
    4: "multi",
    5: "firmware",
    6: "script",
    7: "filesystem",
    8: "flat_dt",
}
COMPRESSION = {0: "none", 1: "gzip", 2: "bzip2", 3: "lzma", 4: "lzo", 5: "lz4", 6: "zstd"}
OS_TYPES = {0: "invalid", 5: "linux", 17: "u-boot", 18: "qnx", 22: "openrtos"}
ARCH_TYPES = {
    2: "arm",
    3: "x86",
    5: "mips",
    6: "mips64",
    7: "nios",
    8: "nios2",
    9: "powerpc",
    15: "sh",
    19: "arm64",
    22: "riscv",
}
MAX_MULTI_PARTS = 64


@dataclass(frozen=True)
class UImageHeader:
    header_crc: int
    timestamp: int
    data_size: int
    load_addr: int
    entry_point: int
    data_crc: int
    os: int
    arch: int
    image_type: int
    compression: int
    name: str
    header_crc_ok: bool

    @property
    def type_name(self) -> str:
        return IMAGE_TYPES.get(self.image_type, f"unknown({self.image_type})")

    @property
    def compression_name(self) -> str:
        return COMPRESSION.get(self.compression, f"unknown({self.compression})")

    @property
    def os_name(self) -> str:
        return OS_TYPES.get(self.os, f"unknown({self.os})")

    @property
    def arch_name(self) -> str:
        return ARCH_TYPES.get(self.arch, f"unknown({self.arch})")


@dataclass(frozen=True)
class UImage:
    header: UImageHeader
    payload: bytes
    data_crc_ok: bool
    parts: tuple[bytes, ...]

    @property
    def total_length(self) -> int:
        return HEADER_SIZE + self.header.data_size


def header_crc(raw_header: bytes) -> int:
    """CRC-32 of a 64-byte header with the hcrc field zeroed."""
    return zlib.crc32(raw_header[:4] + b"\x00\x00\x00\x00" + raw_header[8:HEADER_SIZE])


def parse_header(data: bytes | memoryview) -> UImageHeader:
    if len(data) < HEADER_SIZE:
        raise TruncatedError("uImage header truncated")
    raw = bytes(data[:HEADER_SIZE])
    magic, hcrc, ts, size, load, ep, dcrc, os_, arch, itype, comp, name = _HEADER.unpack(raw)
    if magic != UIMAGE_MAGIC:
        raise FormatError("bad uImage magic")
    if itype == 0 or itype > 32 or comp > 16:
        raise FormatError("implausible uImage type/compression")
    return UImageHeader(
        header_crc=hcrc,
        timestamp=ts,
        data_size=size,
        load_addr=load,
        entry_point=ep,
        data_crc=dcrc,
        os=os_,
        arch=arch,
        image_type=itype,
        compression=comp,
        name=name.split(b"\x00", 1)[0].decode("latin-1"),
        header_crc_ok=header_crc(raw) == hcrc,
    )


def split_multi(payload: bytes) -> tuple[bytes, ...]:
    """Split a multi-file payload into its sub-images."""
    sizes: list[int] = []
    pos = 0
    while True:
        if pos + 4 > len(payload):
            raise TruncatedError("multi-image size table truncated")
        (size,) = struct.unpack_from(">I", payload, pos)
        pos += 4
        if size == 0:
            break
        sizes.append(size)
        if len(sizes) > MAX_MULTI_PARTS:
            raise FormatError("multi-image declares too many parts")
    parts: list[bytes] = []
    for size in sizes:
        if pos + size > len(payload):
            raise TruncatedError("multi-image part extends past payload")
        parts.append(payload[pos : pos + size])
        pos += (size + 3) & ~3
    return tuple(parts)


def parse(data: bytes | memoryview) -> UImage:
    """Parse a full uImage starting at ``data[0]``.

    A header CRC mismatch is reported via ``header_crc_ok`` rather than raised, because
    tampered images are exactly what an auditor needs to look inside.
    """
    header = parse_header(data)
    end = HEADER_SIZE + header.data_size
    if end > len(data):
        raise TruncatedError(
            f"uImage declares {header.data_size} payload bytes, only "
            f"{len(data) - HEADER_SIZE} available"
        )
    payload = bytes(data[HEADER_SIZE:end])
    data_ok = zlib.crc32(payload) == header.data_crc
    parts = split_multi(payload) if header.image_type == 4 else (payload,)
    return UImage(header=header, payload=payload, data_crc_ok=data_ok, parts=parts)


def build(
    payload: bytes,
    *,
    name: str,
    image_type: int = 2,
    compression: int = 0,
    os: int = 5,
    arch: int = 5,
    load_addr: int = 0x80000000,
    entry_point: int = 0x80000000,
    timestamp: int = 0,
    corrupt_data_crc: bool = False,
) -> bytes:
    """Construct a uImage (used by the synthetic image builder and tests)."""
    dcrc = zlib.crc32(payload)
    if corrupt_data_crc:
        dcrc ^= 0xFFFFFFFF
    encoded_name = name.encode("latin-1")[:32].ljust(32, b"\x00")
    fields = [
        UIMAGE_MAGIC,
        0,
        timestamp,
        len(payload),
        load_addr,
        entry_point,
        dcrc,
        os,
        arch,
        image_type,
        compression,
        encoded_name,
    ]
    raw = _HEADER.pack(*fields)
    fields[1] = header_crc(raw)
    return _HEADER.pack(*fields) + payload


def build_multi_payload(parts: list[bytes]) -> bytes:
    table = b"".join(struct.pack(">I", len(p)) for p in parts) + b"\x00\x00\x00\x00"
    body = b"".join(p + b"\x00" * (-len(p) % 4) for p in parts)
    return table + body

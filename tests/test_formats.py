from __future__ import annotations

import gzip
import io
import struct
import tarfile

import pytest
from hypothesis import given, settings
from hypothesis import strategies as st

from fwaudit.errors import FormatError, LimitExceededError, TruncatedError, UnsupportedFormatError
from fwaudit.formats import cpio, squashfs, tar, uimage
from fwaudit.formats.entries import ArchiveEntry, EntryKind, kind_from_mode
from fwaudit.limits import Budget, Limits
from fwaudit.synth import squashfs_writer
from fwaudit.synth.firmware import tar_bytes

ENTRIES = [
    ArchiveEntry(b"etc", EntryKind.DIR, 0o755),
    ArchiveEntry(b"etc/passwd", EntryKind.FILE, 0o644, data=b"root:x:0:0::/root:/bin/sh\n"),
    ArchiveEntry(b"bin/busybox", EntryKind.FILE, 0o4755, 0, 0, data=b"\x7fELF" + b"x" * 300),
    ArchiveEntry(b"bin/sh", EntryKind.SYMLINK, 0o777, link_target=b"busybox"),
    ArchiveEntry(b"dev/console", EntryKind.CHARDEV, 0o600, rdev=(5, 1)),
    ArchiveEntry(b"tmp", EntryKind.DIR, 0o1777),
    ArchiveEntry(b"home/user/file", EntryKind.FILE, 0o640, 1000, 100, data=b"data"),
]


def _by_name(entries: list[ArchiveEntry]) -> dict[bytes, ArchiveEntry]:
    return {e.name.lstrip(b"/"): e for e in entries}


# ----------------------------------------------------------------------------- uImage
def test_uimage_roundtrip_and_crc() -> None:
    blob = uimage.build(b"payload", name="kern", compression=1)
    img = uimage.parse(blob + b"tail")
    assert img.payload == b"payload"
    assert img.header.header_crc_ok
    assert img.data_crc_ok
    assert img.header.type_name == "kernel"
    assert img.header.compression_name == "gzip"
    assert img.header.os_name == "linux"
    assert img.header.arch_name == "mips"
    assert img.total_length == 64 + 7
    bad = uimage.parse(uimage.build(b"payload", name="k", corrupt_data_crc=True))
    assert not bad.data_crc_ok
    tampered = bytearray(blob)
    tampered[40] ^= 1
    assert not uimage.parse(bytes(tampered)).header.header_crc_ok


def test_uimage_multi_and_errors() -> None:
    parts = [b"abc", b"defgh", b"i"]
    payload = uimage.build_multi_payload(parts)
    img = uimage.parse(uimage.build(payload, name="multi", image_type=4))
    assert img.parts == tuple(parts)
    with pytest.raises(TruncatedError):
        uimage.parse(b"\x27\x05\x19\x56")
    with pytest.raises(FormatError):
        uimage.parse_header(b"\x00" * 64)
    with pytest.raises(TruncatedError):
        uimage.parse(uimage.build(b"x" * 100, name="t")[:80])
    with pytest.raises(TruncatedError):
        uimage.split_multi(b"\x00\x00\x00\x05")
    with pytest.raises(TruncatedError):
        uimage.split_multi(struct.pack(">II", 50, 0) + b"short")
    with pytest.raises(FormatError):
        uimage.split_multi(b"".join(struct.pack(">I", 1) for _ in range(70)))
    hdr = bytearray(uimage.build(b"x", name="t"))
    hdr[30] = 0  # image type 0 = invalid
    with pytest.raises(FormatError):
        uimage.parse_header(bytes(hdr))
    unknown = uimage.parse_header(uimage.build(b"x", name="t", os=99, arch=99, image_type=20))
    assert unknown.os_name.startswith("unknown")
    assert unknown.arch_name.startswith("unknown")
    assert unknown.type_name.startswith("unknown")


# ----------------------------------------------------------------------------- cpio
def test_cpio_newc_roundtrip(budget: Budget) -> None:
    blob = cpio.build_newc(ENTRIES)
    res = cpio.parse(blob + b"\x00" * 100, budget)
    assert res.complete
    assert res.variant == "newc"
    got = _by_name(res.entries)
    assert got[b"bin/busybox"].mode == 0o4755
    assert got[b"bin/sh"].link_target == b"busybox"
    assert got[b"dev/console"].rdev == (5, 1)
    assert got[b"home/user/file"].uid == 1000
    assert res.consumed <= len(blob)


def _odc_member(name: bytes, mode: int, data: bytes, nlink: int = 1) -> bytes:
    header = b"070707" + b"%06o%06o%06o%06o%06o%06o%06o%011o%06o%011o" % (
        0, 1, mode, 0, 0, nlink, 0, 0, len(name) + 1, len(data)
    )
    return header + name + b"\x00" + data


def test_cpio_odc(budget: Budget) -> None:
    blob = _odc_member(b"etc/x", 0o100644, b"hello") + _odc_member(b"TRAILER!!!", 0, b"")
    res = cpio.parse(blob, budget)
    assert res.variant == "odc"
    assert res.entries[0].data == b"hello"
    assert res.complete


def _newc_member(name: bytes, mode: int, data: bytes, *, ino: int = 1, nlink: int = 1,
                 check: int = 0, magic: bytes = b"070701") -> bytes:  # fmt: skip
    fields = (ino, mode, 0, 0, nlink, 0, len(data), 0, 0, 0, 0, len(name) + 1, check)
    h = magic + b"".join(b"%08X" % v for v in fields)
    out = h + name + b"\x00"
    out += b"\x00" * (-len(out) % 4)
    return out + data + b"\x00" * (-len(data) % 4)


def test_cpio_crc_checksum_and_hardlinks(budget: Budget) -> None:
    data = b"abc"
    good = _newc_member(b"a", 0o100644, data, check=sum(data), magic=b"070702")
    bad = _newc_member(b"b", 0o100644, data, check=1, magic=b"070702")
    link1 = _newc_member(b"l1", 0o100755, b"", ino=9, nlink=2, magic=b"070702")
    link2 = _newc_member(b"l2", 0o100755, b"elf", ino=9, nlink=2, check=sum(b"elf"), magic=b"070702")
    trailer = _newc_member(b"TRAILER!!!", 0, b"", magic=b"070702")
    res = cpio.parse(good + bad + link1 + link2 + trailer, budget)
    assert res.variant == "crc"
    assert res.checksum_errors == ["b"]
    kinds = {e.name: e.kind for e in res.entries}
    assert kinds[b"l1"] is EntryKind.HARDLINK
    assert next(e for e in res.entries if e.name == b"l1").link_target == b"l2"


def test_cpio_errors_and_truncation(budget: Budget) -> None:
    with pytest.raises(FormatError):
        cpio.parse(b"garbage!", budget)
    with pytest.raises(TruncatedError):
        cpio.parse(b"070701" + b"0" * 20, budget)
    with pytest.raises(FormatError):
        cpio.parse(b"070701" + b"Z" * 104, budget)
    blob = cpio.build_newc(ENTRIES)
    partial = cpio.parse(blob[: len(blob) // 2], budget)
    assert not partial.complete
    assert partial.entries
    zero_name = b"070701" + b"".join(b"%08X" % v for v in (1, 0o100644, 0, 0, 1, 0, 0, 0, 0,
                                                               0, 0, 0, 0))  # fmt: skip
    with pytest.raises(FormatError):
        cpio.parse(zero_name + b"\x00" * 8, budget)
    big = cpio.parse(cpio.build_newc([ArchiveEntry(b"f", EntryKind.FILE, 0o644, data=b"x" * 100)]),
                     Budget(Limits(max_file_bytes=10)))  # fmt: skip
    assert big.entries[0].truncated
    with pytest.raises(ValueError):
        cpio.build_newc([ArchiveEntry(b"h", EntryKind.HARDLINK, 0o644, link_target=b"x")])


# ----------------------------------------------------------------------------- tar
def test_tar_roundtrip(budget: Budget) -> None:
    res = tar.parse(tar_bytes(ENTRIES), budget)
    assert res.complete
    got = _by_name(res.entries)
    assert got[b"bin/busybox"].mode == 0o4755
    assert got[b"bin/sh"].link_target == b"busybox"
    assert got[b"dev/console"].rdev == (5, 1)
    assert got[b"etc/passwd"].data.startswith(b"root")


def test_tar_hardlink_fifo_and_checksum(budget: Budget) -> None:
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w", format=tarfile.USTAR_FORMAT) as tf:
        info = tarfile.TarInfo("a")
        info.size = 2
        tf.addfile(info, io.BytesIO(b"hi"))
        link = tarfile.TarInfo("b")
        link.type = tarfile.LNKTYPE
        link.linkname = "a"
        tf.addfile(link)
        fifo = tarfile.TarInfo("p")
        fifo.type = tarfile.FIFOTYPE
        tf.addfile(fifo)
    blob = buf.getvalue()
    assert tar.header_checksum_ok(blob[:512])
    assert not tar.header_checksum_ok(b"\x00" * 100)
    assert not tar.header_checksum_ok(b"x" * 148 + b"zzzzzzzz" + b"\x00" * 356)
    res = tar.parse(blob, budget)
    kinds = {e.name: e.kind for e in res.entries}
    assert kinds[b"b"] is EntryKind.HARDLINK
    assert kinds[b"p"] is EntryKind.FIFO
    with pytest.raises(FormatError):
        tar.parse(b"\x01" * 1024, budget)


def test_tar_truncated_member(budget: Budget) -> None:
    blob = tar_bytes([ArchiveEntry(b"a", EntryKind.FILE, 0o644, data=b"A" * 5000),
                      ArchiveEntry(b"b", EntryKind.FILE, 0o644, data=b"B" * 5000)])  # fmt: skip
    res = tar.parse(blob[:6000], budget)
    assert not res.complete
    assert res.entries[0].data == b"A" * 5000
    capped = tar.parse(blob, Budget(Limits(max_file_bytes=100)))
    assert capped.entries[0].truncated
    assert len(capped.entries[0].data) == 100


# ----------------------------------------------------------------------------- squashfs
@pytest.mark.parametrize("compression", ["gzip", "xz"])
def test_squashfs_writer_roundtrip(compression: str, budget: Budget) -> None:
    many = [ArchiveEntry(f"usr/lib/f{i:04d}".encode(), EntryKind.FILE, 0o644, 1000, 100,
                         data=b"x" * i) for i in range(600)]  # fmt: skip
    large = ArchiveEntry(b"big.bin", EntryKind.FILE, 0o644, data=bytes(range(256)) * 1200)
    fifo = ArchiveEntry(b"run/fifo", EntryKind.FIFO, 0o600)
    blob = squashfs_writer.build([*ENTRIES, *many, large, fifo], compression=compression)
    res = squashfs.parse(blob, budget)
    assert res.superblock.compression_name == compression
    got = _by_name(res.entries)
    assert got[b"bin/busybox"].mode == 0o4755
    assert got[b"bin/sh"].link_target == b"busybox"
    assert got[b"dev/console"].rdev == (5, 1)
    assert got[b"tmp"].mode == 0o1777
    assert got[b"usr/lib/f0599"].data == b"x" * 599
    assert got[b"usr/lib/f0599"].uid == 1000
    assert got[b"big.bin"].data == large.data
    assert got[b"run/fifo"].kind is EntryKind.FIFO
    assert res.consumed == res.superblock.bytes_used


def test_squashfs_file_cap(budget: Budget) -> None:
    blob = squashfs_writer.build([ArchiveEntry(b"f", EntryKind.FILE, 0o644, data=b"y" * 300_000)],
                                 block_size=4096)  # fmt: skip
    res = squashfs.parse(blob, Budget(Limits(max_file_bytes=10_000)))
    f = next(e for e in res.entries if e.name == b"f")
    assert f.truncated
    assert len(f.data) == 10_000


def test_squashfs_superblock_validation(budget: Budget) -> None:
    blob = bytearray(squashfs_writer.build(ENTRIES))
    with pytest.raises(TruncatedError):
        squashfs.parse_superblock(bytes(blob[:50]))
    with pytest.raises(FormatError):
        squashfs.parse_superblock(b"xxxx" + bytes(blob[4:96]))
    with pytest.raises(UnsupportedFormatError):
        squashfs.parse_superblock(b"sqsh" + bytes(blob[4:96]))
    bad_version = bytearray(blob)
    bad_version[28:30] = b"\x03\x00"
    with pytest.raises(UnsupportedFormatError):
        squashfs.parse_superblock(bytes(bad_version))
    bad_version[28:30] = b"\x09\x00"
    with pytest.raises(FormatError):
        squashfs.parse_superblock(bytes(bad_version))
    bad_block = bytearray(blob)
    bad_block[12:16] = struct.pack("<I", 12345)
    with pytest.raises(FormatError):
        squashfs.parse_superblock(bytes(bad_block))
    bad_used = bytearray(blob)
    bad_used[40:48] = struct.pack("<Q", 10)
    with pytest.raises(FormatError):
        squashfs.parse_superblock(bytes(bad_used))
    lzo = bytearray(blob)
    lzo[20:22] = struct.pack("<H", 3)
    with pytest.raises(UnsupportedFormatError):
        squashfs.parse(bytes(lzo), budget)
    with pytest.raises(TruncatedError):
        squashfs.parse(bytes(blob[:200]), budget)
    with pytest.raises(ValueError):
        squashfs_writer.build(ENTRIES, compression="lz4")
    with pytest.raises(ValueError):
        squashfs_writer.build(ENTRIES, block_size=1000)


def test_squashfs_bounded_block_decoders() -> None:
    import zlib

    bomb = zlib.compress(b"\x00" * 100_000)
    with pytest.raises(LimitExceededError):
        squashfs._BoundedZlib().uncompress(bomb, len(bomb), 8192)
    with pytest.raises(FormatError):
        squashfs._BoundedZlib().uncompress(b"not zlib", 8, 8192)
    assert squashfs._BoundedZlib().uncompress(zlib.compress(b"ok"), 0, 0) == b"ok"
    import lzma

    xbomb = lzma.compress(b"\x00" * 100_000, format=lzma.FORMAT_XZ)
    with pytest.raises(LimitExceededError):
        squashfs._BoundedXz().uncompress(xbomb, len(xbomb), 8192)
    with pytest.raises(FormatError):
        squashfs._BoundedXz().uncompress(b"not xz at all", 8, 8192)


@settings(max_examples=60, deadline=None)
@given(st.data())
def test_squashfs_mutations_never_crash(data: st.DataObject) -> None:
    blob = bytearray(squashfs_writer.build(ENTRIES))
    n = data.draw(st.integers(min_value=1, max_value=8))
    for _ in range(n):
        pos = data.draw(st.integers(min_value=0, max_value=len(blob) - 1))
        blob[pos] = data.draw(st.integers(min_value=0, max_value=255))
    try:
        squashfs.parse(bytes(blob), Budget(Limits()))
    except (FormatError, LimitExceededError):
        pass


def test_kind_from_mode() -> None:
    assert kind_from_mode(0o100644) is EntryKind.FILE
    assert kind_from_mode(0o140755) is EntryKind.SOCKET
    assert kind_from_mode(0o777) is None


def test_gzip_wrapped_cpio_parses(budget: Budget) -> None:
    raw = gzip.decompress(gzip.compress(cpio.build_newc(ENTRIES)))
    assert cpio.parse(raw, budget).complete

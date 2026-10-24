"""Hostile extraction samples: traversal, decompression bombs, nesting, tampering.

Each sample is benign data shaped to attack an unpacker. The expected findings are the
extraction-safety rules (``FWA-EXT-*``); the test-suite additionally asserts that
auditing them never touches the host filesystem and stays within the memory budget.
"""

from __future__ import annotations

import gzip
import io
import lzma
import tarfile

from fwaudit.formats import cpio, uimage
from fwaudit.formats.entries import ArchiveEntry, EntryKind
from fwaudit.synth import squashfs_writer
from fwaudit.synth.firmware import Expected, Sample

BOMB_BYTES = 64 * 1024 * 1024


def _tar(members: list[tuple[str, bytes | None, str | None]]) -> bytes:
    """members: (name, data or None, symlink target or None)."""
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w", format=tarfile.GNU_FORMAT) as tf:
        for name, data, target in members:
            info = tarfile.TarInfo(name)
            info.mtime = 0
            if target is not None:
                info.type = tarfile.SYMTYPE
                info.linkname = target
                tf.addfile(info)
            else:
                payload = data or b""
                info.size = len(payload)
                tf.addfile(info, io.BytesIO(payload))
    return buf.getvalue()


def tar_traversal() -> Sample:
    image = _tar([
        ("etc/motd", b"welcome\n", None),
        ("../../../tmp/fwaudit-pwned", b"#!/bin/sh\necho pwned\n", None),
        ("/var/www/absolute.txt", b"absolute member, stripped and kept\n", None),
        ("etclink", None, "/etc"),
        ("etclink/cron.d/evil", b"* * * * * root /tmp/x\n", None),
    ])  # fmt: skip
    return Sample("hostile-tar-traversal", 0, "hostile", "tar", image, [
        Expected("FWA-EXT-001", None, "extracted", "'..' member"),
        Expected("FWA-EXT-001", None, "extracted", "write through symlink"),
    ])  # fmt: skip


def cpio_traversal() -> Sample:
    entries = [
        ArchiveEntry(b"bin", EntryKind.DIR, 0o755),
        ArchiveEntry(b"bin/ok", EntryKind.FILE, 0o755, data=b"ok\n"),
        ArchiveEntry(b"bin/../../escape", EntryKind.FILE, 0o644, data=b"escape\n"),
    ]
    image = gzip.compress(cpio.build_newc(entries), mtime=0)
    return Sample("hostile-cpio-traversal", 0, "hostile", "cpio.gz", image, [
        Expected("FWA-EXT-001", None, "extracted", "'..' member"),
    ])  # fmt: skip


def squashfs_traversal() -> Sample:
    entries = [
        ArchiveEntry(b"etc/hostname", EntryKind.FILE, 0o644, data=b"x\n"),
        ArchiveEntry(b"etc/../../outside", EntryKind.FILE, 0o644, data=b"outside\n"),
    ]
    image = squashfs_writer.build(entries)
    return Sample("hostile-squashfs-traversal", 0, "hostile", "squashfs", image, [
        Expected("FWA-EXT-001", None, "extracted", "directory entry named '..' (etc/..)"),
        Expected("FWA-EXT-001", None, "extracted", "nested '..' directory (etc/../..)"),
        Expected("FWA-EXT-001", None, "extracted", "file below the '..' entries"),
    ])  # fmt: skip


def gzip_bomb() -> Sample:
    image = b"\xff" * 512 + gzip.compress(b"\x00" * BOMB_BYTES, compresslevel=9, mtime=0)
    return Sample("hostile-gzip-bomb", 0, "hostile", "gzip", image, [
        Expected("FWA-EXT-002", None, "image", "64 MiB of zeros, ~1000:1"),
    ])  # fmt: skip


def xz_bomb() -> Sample:
    image = lzma.compress(b"\x00" * BOMB_BYTES, format=lzma.FORMAT_XZ, check=lzma.CHECK_CRC32)
    return Sample("hostile-xz-bomb", 0, "hostile", "xz", image, [
        Expected("FWA-EXT-002", None, "image", "64 MiB of zeros"),
    ])  # fmt: skip


def nesting_bomb(levels: int = 12) -> Sample:
    data = b"innermost payload\n" * 8
    for _ in range(levels):
        data = gzip.compress(data, mtime=0)
    return Sample("hostile-nesting", 0, "hostile", "gzip^12", data, [
        Expected("FWA-EXT-003", None, "extracted", "nesting deeper than max_depth"),
    ])  # fmt: skip


def tampered_uimage() -> Sample:
    good = uimage.build(gzip.compress(b"kernel " * 2000, mtime=0), name="tampered", compression=1)
    raw = bytearray(good)
    raw[20:24] = b"\x81\x00\x00\x00"  # change the entry point without updating the header CRC
    return Sample("hostile-uimage-header-crc", 0, "hostile", "uimage", bytes(raw), [
        Expected("FWA-EXT-004", None, "image", "header CRC mismatch"),
    ])  # fmt: skip


def all_samples() -> list[Sample]:
    return [
        tar_traversal(),
        cpio_traversal(),
        squashfs_traversal(),
        gzip_bomb(),
        xz_bomb(),
        nesting_bomb(),
        tampered_uimage(),
    ]

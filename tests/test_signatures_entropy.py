from __future__ import annotations

import bz2
import gzip
import lzma
import os
import struct

import numpy as np
from hypothesis import given, settings
from hypothesis import strategies as st

from fwaudit import entropy
from fwaudit.formats import cpio, uimage
from fwaudit.formats.entries import ArchiveEntry, EntryKind
from fwaudit.signatures import match_at_start, scan
from fwaudit.synth import squashfs_writer
from fwaudit.synth.firmware import lzma_alone, tar_bytes

FILES = [ArchiveEntry(b"etc/x", EntryKind.FILE, 0o644, data=b"hello")]


def test_scan_finds_every_container_at_its_offset() -> None:
    pieces = [
        ("uimage", uimage.build(b"k" * 100, name="k")),
        ("gzip", gzip.compress(b"g" * 100, mtime=0)),
        ("xz", lzma.compress(b"x" * 100, format=lzma.FORMAT_XZ)),
        ("lzma", lzma_alone(b"l" * 100)),
        ("bzip2", bz2.compress(b"b" * 100)),
        ("cpio", cpio.build_newc(FILES)),
        ("tar", tar_bytes(FILES)),
        ("squashfs", squashfs_writer.build(FILES)),
    ]
    blob = b""
    offsets = {}
    for name, piece in pieces:
        blob += b"\xff" * 64
        offsets[name] = len(blob)
        blob += piece
    hits = scan(blob)
    found = {(h.name, h.offset) for h in hits}
    for name, off in offsets.items():
        assert (name, off) in found, name
    assert [h.offset for h in hits] == sorted(h.offset for h in hits)


def test_informational_and_unsupported_signatures() -> None:
    elf = b"\x7fELF\x01\x01\x01" + b"\x00" * 9 + struct.pack("<HH", 2, 8) + b"\x00" * 40
    fdt = b"\xd0\x0d\xfe\xed" + struct.pack(">5I", 1000, 56, 200, 40, 17) + b"\x00" * 20
    cramfs = b"\x45\x3d\xcd\x28" + b"\x00" * 12 + b"Compressed ROMFS" + b"\x00" * 16
    sqsh_be = b"sqsh" + b"\x00" * 24 + struct.pack(">H", 3) + b"\x00" * 70
    hits = {h.name: h for h in scan(b"\x00" * 8 + elf + fdt + cramfs + sqsh_be)}
    assert hits["elf"].meta["machine"] == 8
    assert not hits["elf"].extractable
    assert hits["fdt"].meta["total_size"] == 1000
    assert not hits["cramfs"].supported
    assert not hits["squashfs-be"].supported


def test_validators_reject_lookalikes() -> None:
    garbage = (
        b"\x1f\x8b\x08\xff" + b"\x00" * 20  # gzip with reserved flags
        + b"\xfd7zXZ\x00\x00\x01BAD!"  # xz with wrong CRC
        + b"\x5d\x00\x00\x00\x00" + b"\x00" * 10  # lzma with zero dictionary
        + b"BZh91AY&SX"  # wrong bzip2 block magic
        + b"070701" + b"ZZ" * 52  # non-hex cpio
        + b"070707" + b"99" * 35  # non-octal odc
        + b"\x27\x05\x19\x56" + b"\x00" * 60  # uImage with type 0
        + b"hsqs" + b"\x00" * 92  # squashfs with zero block size
        + b"\x7fELF\x09"  # bad ELF class
    )
    assert scan(garbage) == []
    assert scan(b"x" * 300 + b"ustar\x00" + b"\x00" * 300) == []
    assert scan(b"BZh") == []


def test_match_at_start_and_max_hits() -> None:
    hit = match_at_start(gzip.compress(b"abc"))
    assert hit is not None
    assert hit.name == "gzip"
    assert match_at_start(lzma_alone(b"abc")) is None  # lzma magic too weak on its own
    assert match_at_start(b"plain text") is None
    many = gzip.compress(b"a", mtime=0) * 50
    assert len(scan(many, max_hits=10)) == 10


def test_entropy_extremes_and_regions() -> None:
    data = b"\x00" * 8192 + os.urandom(16384) + b"A quick brown fox. " * 300
    emap = entropy.entropy_map(data, 4096)
    kinds = [r.kind for r in emap.regions]
    assert kinds[0] == "low"
    assert "high" in kinds
    assert emap.regions[0].start == 0
    assert emap.regions[-1].end == len(data)
    assert len(emap.sparkline(4)) == 4
    assert len(emap.sparkline(16)) == len(emap.values)
    assert entropy.entropy_map(b"").sparkline() == ""
    assert entropy.entropy_map(b"").mean == 0.0
    spans = entropy.high_entropy_spans(data, min_length=8192)
    assert spans
    assert spans[0][0] == 8192


@settings(max_examples=40, deadline=None)
@given(st.binary(min_size=1, max_size=20000), st.sampled_from([64, 256, 4096]))
def test_entropy_matches_reference(data: bytes, block: int) -> None:
    got = entropy.block_entropies(data, block)
    for i in range(len(got)):
        chunk = np.frombuffer(data[i * block : (i + 1) * block], dtype=np.uint8)
        counts = np.bincount(chunk, minlength=256)
        p = counts[counts > 0] / chunk.size
        assert abs(got[i] - float(-(p * np.log2(p)).sum())) < 1e-9
        assert 0.0 <= got[i] <= 8.0


def test_entropy_chunking_is_transparent(monkeypatch: object) -> None:
    import pytest

    data = os.urandom(50_000) + b"\x00" * 30_000
    whole = entropy.block_entropies(data, 1024)
    mp = pytest.MonkeyPatch()
    mp.setattr(entropy, "CHUNK_BYTES", 4096)
    try:
        chunked = entropy.block_entropies(data, 1024)
    finally:
        mp.undo()
    assert np.allclose(whole, chunked)
    with pytest.raises(ValueError):
        entropy.block_entropies(data, 0)

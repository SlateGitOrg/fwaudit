from __future__ import annotations

import gzip
import os
import struct

import pytest

from fwaudit.audit.base import AuditConfig
from fwaudit.errors import LimitExceededError
from fwaudit.extract.engine import Extractor
from fwaudit.formats import cpio, uimage
from fwaudit.formats.entries import ArchiveEntry, EntryKind
from fwaudit.limits import Limits
from fwaudit.pipeline import AuditOptions, audit_bytes, audit_file, dedupe
from fwaudit.synth import pki, squashfs_writer
from fwaudit.synth.firmware import lzma_alone, tar_bytes

ROOT = [
    ArchiveEntry(b"etc/passwd", EntryKind.FILE, 0o644, data=b"root::0:0::/root:/bin/sh\n"),
    ArchiveEntry(b"etc/hostname", EntryKind.FILE, 0o644, data=b"x\n"),
]


def _ids(result: object) -> list[str]:
    return [f.rule_id for f in result.findings]  # type: ignore[attr-defined]


def test_nested_containers_are_mounted() -> None:
    inner = gzip.compress(tar_bytes([ArchiveEntry(b"etc/app.conf", EntryKind.FILE, 0o644,
                                                  data=b"api_key=Zx81Qw77\n")]), mtime=0)  # fmt: skip
    rootfs = [*ROOT, ArchiveEntry(b"etc/backup.tgz", EntryKind.FILE, 0o644, data=inner)]
    image = uimage.build(gzip.compress(cpio.build_newc(rootfs), mtime=0), name="r", image_type=3)
    res = Extractor().run(image)
    kinds = [n.kind for n in res.nodes.values()]
    assert kinds == ["image", "uimage", "gzip", "cpio", "file", "gzip", "tar"]
    assert len(res.filesystems) == 2
    assert res.filesystems[1].fs_id.endswith(":/etc/backup.tgz/gzip@0x0/tar@0x0")


def test_lzma_uimage_and_unknown_lzma_trust() -> None:
    ramdisk = uimage.build(lzma_alone(cpio.build_newc(ROOT)), name="rd", image_type=3,
                           compression=3)  # fmt: skip
    res = Extractor().run(ramdisk)
    assert [n.kind for n in res.nodes.values()] == ["image", "uimage", "lzma", "cpio"]
    # A declared-lzma payload that is not lzma falls back to carving it raw.
    bogus = uimage.build(gzip.compress(cpio.build_newc(ROOT), mtime=0), name="x", compression=3)
    res2 = Extractor().run(bogus)
    assert "cpio" in [n.kind for n in res2.nodes.values()]
    # A free-standing LZMA header followed by junk is not trusted.
    res3 = Extractor().run(b"\x00" * 16 + lzma_alone(b"z" * 5000)[:40] + b"\x00" * 100)
    assert len(res3.nodes) == 1


def test_depth_limit_and_carve_limit() -> None:
    data = b"payload"
    for _ in range(5):
        data = gzip.compress(data, mtime=0)
    res = Extractor(Limits(max_depth=3)).run(data)
    assert [f.rule_id for f in res.findings] == ["FWA-EXT-003"]
    many = b"".join(b"\x00" * 32 + gzip.compress(b"x" * 64, mtime=0) for _ in range(5))
    res2 = Extractor(Limits(max_carves=2)).run(many)
    assert [f.rule_id for f in res2.findings] == ["FWA-EXT-002"]
    assert res2.findings[0].evidence["limit"] == "max_carves"


def test_unsupported_containers_reported() -> None:
    lzo_sqfs = bytearray(squashfs_writer.build(ROOT))
    lzo_sqfs[20:22] = struct.pack("<H", 3)
    cramfs = b"\x45\x3d\xcd\x28" + b"\x00" * 12 + b"Compressed ROMFS" + b"\x00" * 64
    res = Extractor().run(bytes(lzo_sqfs) + b"\x00" * 64 + cramfs)
    reasons = [f.detail for f in res.findings if f.rule_id == "FWA-EXT-005"]
    assert len(reasons) == 2
    assert any("lzo" in r for r in reasons)


def test_unsupported_raised_while_parsing() -> None:
    blob = bytearray(squashfs_writer.build(ROOT))
    blob[20:22] = struct.pack("<H", 4)  # claims xz but blocks are zlib -> corrupt, not unsupported
    res = Extractor().run(bytes(blob))
    assert not res.filesystems


def test_truncated_archives_are_partially_mounted() -> None:
    blob = cpio.build_newc([*ROOT, ArchiveEntry(b"big", EntryKind.FILE, 0o644, data=b"q" * 4000)])
    res = Extractor().run(blob[:3000])
    assert len(res.filesystems) == 1
    node = res.nodes[res.filesystems[0].fs_id]
    assert any("truncated" in n for n in node.notes)
    tar_blob = tar_bytes([*ROOT, ArchiveEntry(b"big", EntryKind.FILE, 0o644, data=b"q" * 4000)])
    res_t = Extractor().run(tar_blob[:2500])
    assert any("truncated" in n for n in res_t.nodes[res_t.filesystems[0].fs_id].notes)
    gz = gzip.compress(os.urandom(20000), mtime=0)
    res_g = Extractor().run(gz[: len(gz) // 2])
    gnode = next(n for n in res_g.nodes.values() if n.kind == "gzip")
    assert gnode.meta["complete"] is False


def test_high_entropy_gap_and_raw_key(config: AuditConfig) -> None:
    key = pki.private_pem(pki.ec_key(77))
    image = b"\xff" * 4096 + os.urandom(32768) + b"\xff" * 4096 + b"NVRM" + key
    result = audit_bytes(image, "raw", AuditOptions(config=config))
    assert sorted(_ids(result)) == ["FWA-EXT-006", "FWA-KEY-001"]
    ext6 = next(f for f in result.findings if f.rule_id == "FWA-EXT-006")
    assert ext6.offset == 4096
    k = next(f for f in result.findings if f.rule_id == "FWA-KEY-001")
    assert k.offset == 4096 + 32768 + 4096 + 4


def test_traversal_and_notes_from_mount() -> None:
    entries = [
        ArchiveEntry(b"/abs/file", EntryKind.FILE, 0o644, data=b"a"),
        ArchiveEntry(b"../evil", EntryKind.FILE, 0o644, data=b"e"),
        ArchiveEntry(b"x", EntryKind.FILE, 0o644, data=b"x"),
        ArchiveEntry(b"x/y", EntryKind.FILE, 0o644, data=b"y"),
    ]
    res = Extractor().run(tar_bytes(entries))
    assert [f.rule_id for f in res.findings] == ["FWA-EXT-001"]
    notes = res.nodes[res.filesystems[0].fs_id].notes
    assert any("leading '/'" in n for n in notes)
    assert any("not a directory" in n for n in notes)


def test_pipeline_limits_and_dedupe(tmp_path: object, options: AuditOptions) -> None:
    with pytest.raises(LimitExceededError):
        audit_bytes(b"x" * 100, "x", AuditOptions(limits=Limits(max_image_bytes=10)))
    from pathlib import Path

    p = Path(str(tmp_path)) / "img.bin"
    p.write_bytes(b"y" * 100)
    with pytest.raises(LimitExceededError):
        audit_file(p, AuditOptions(limits=Limits(max_image_bytes=10)))
    assert audit_file(p, options).findings == []
    result = audit_bytes(tar_bytes(ROOT), "t", options)
    assert dedupe(result.findings + result.findings) == result.findings
    assert result.findings[0].finding_id.startswith("F-")

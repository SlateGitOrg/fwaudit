from __future__ import annotations

import json
from importlib import resources
from pathlib import Path

import jsonschema
import pytest

from fwaudit.cli import main
from fwaudit.errors import UnsafePathError
from fwaudit.extract.disk import MANIFEST, materialize
from fwaudit.formats.entries import ArchiveEntry, EntryKind
from fwaudit.pipeline import AuditOptions, audit_bytes
from fwaudit.report import jsonreport, markdown
from fwaudit.synth import hostile
from fwaudit.synth.firmware import generate
from fwaudit.vfs import VirtualFS

SCHEMA = json.loads(resources.files("fwaudit.report").joinpath("schema.json").read_text())


def test_materialize_is_safe(tmp_path: Path) -> None:
    fs = VirtualFS("t", "test")
    for e in [
        ArchiveEntry(b"bin/su", EntryKind.FILE, 0o4777, data=b"elf"),
        ArchiveEntry(b"bin/sh", EntryKind.SYMLINK, 0o777, link_target=b"/etc/passwd"),
        ArchiveEntry(b"dev/null", EntryKind.CHARDEV, 0o666, rdev=(1, 3)),
        ArchiveEntry(b"etc/passwd", EntryKind.FILE, 0o644, data=b"root"),
    ]:
        fs.add_entry(e)
    res = materialize(fs, tmp_path / "out")
    assert res.files == 2
    assert res.recorded_only == 2
    su = tmp_path / "out" / "bin" / "su"
    assert su.read_bytes() == b"elf"
    assert su.stat().st_mode & 0o7777 == 0o755
    assert not (tmp_path / "out" / "bin" / "sh").exists()
    manifest = json.loads((tmp_path / "out" / MANIFEST).read_text())
    assert any(m["path"] == "/bin/sh" and m["link_target"] == "/etc/passwd" for m in manifest)
    with pytest.raises(FileExistsError):
        materialize(fs, tmp_path / "out")


def test_materialize_refuses_preexisting_symlink(tmp_path: Path) -> None:
    out = tmp_path / "out"
    out.mkdir()
    (out / "etc").symlink_to(tmp_path)
    fs = VirtualFS("t", "test")
    fs.add_entry(ArchiveEntry(b"etc/passwd", EntryKind.FILE, 0o644, data=b"x"))
    with pytest.raises(UnsafePathError):
        materialize(fs, out)


def test_hostile_tar_extracts_inside_root_only(tmp_path: Path, options: AuditOptions) -> None:
    sample = hostile.tar_traversal()
    img = tmp_path / "evil.tar"
    img.write_bytes(sample.image)
    rc = main(["scan", str(img), "--extract-to", str(tmp_path / "x")])
    assert rc == 0
    written = sorted(str(p.relative_to(tmp_path)) for p in tmp_path.rglob("*"))
    assert all(p == "evil.tar" or p.startswith("x") for p in written)
    assert not (tmp_path / "x" / "image_tar@0x0" / "etclink").exists()
    assert (tmp_path / "x" / "image_tar@0x0" / "var" / "www" / "absolute.txt").exists()


def test_json_report_matches_schema(options: AuditOptions) -> None:
    for sample in [generate(s) for s in range(5)] + hostile.all_samples()[:2]:
        doc = jsonreport.to_dict(audit_bytes(sample.image, sample.name, options))
        jsonschema.validate(doc, SCHEMA)


def test_markdown_sections(options: AuditOptions) -> None:
    sample = generate(2)
    md = markdown.render(audit_bytes(sample.image, sample.name, options))
    for heading in ("## Severity summary", "## Entropy map", "## Extraction tree", "## Findings"):
        assert heading in md
    empty = markdown.render(audit_bytes(b"\x00" * 100, "blank", options))
    assert "No findings." in empty


def test_shared_key_inventory(options: AuditOptions) -> None:
    from fwaudit.synth import pki, squashfs_writer

    pem = pki.private_pem(pki.ec_key(4))
    image = squashfs_writer.build([
        ArchiveEntry(b"etc/a.key", EntryKind.FILE, 0o600, data=pem),
        ArchiveEntry(b"etc/b.key", EntryKind.FILE, 0o600, data=pem),
    ])  # fmt: skip
    doc = jsonreport.to_dict(audit_bytes(image, "dup", options))
    assert len(doc["shared_keys"]) == 1
    assert len(doc["shared_keys"][0]["locations"]) == 2
    assert "more than one location" in markdown.render(audit_bytes(image, "dup", options))


def test_cli_commands(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    assert main(["synth", str(tmp_path), "--seeds", "1-2", "--hostile"]) == 0
    img = tmp_path / "dev-0001-uimage-lzma-cpio.bin"
    assert img.exists()
    truth = json.loads((tmp_path / "dev-0001-uimage-lzma-cpio.truth.json").read_text())
    assert truth["seed"] == 1
    capsys.readouterr()
    rc = main(["scan", str(img), "--reference-time", "2026-01-01", "--json", "-"])
    out = capsys.readouterr().out
    assert rc == 0
    assert json.loads(out)["settings"]["reference_time"].startswith("2026-01-01")
    rc = main(["scan", str(img), "--fail-on", "high", "--markdown", str(tmp_path / "r.md"),
               "--json", str(tmp_path / "r.json")])  # fmt: skip
    assert rc == 1
    assert (tmp_path / "r.md").read_text().startswith("# fwaudit report")
    assert "findings:" in capsys.readouterr().out
    assert main(["identify", str(img)]) == 0
    assert "uimage" in capsys.readouterr().out
    assert main(["entropy", str(img), "--block", "1024", "--width", "20"]) == 0
    assert "mean" in capsys.readouterr().out
    assert main(["rules"]) == 0
    assert "FWA-EXT-001" in capsys.readouterr().out
    assert main(["scan", str(tmp_path / "missing.bin")]) == 2


def test_cli_argument_validation(capsys: pytest.CaptureFixture[str]) -> None:
    for argv in (["scan", "x", "--reference-time", "yesterday"], ["synth", "o", "--seeds", "9-1"],
                 ["synth", "o", "--seeds", "abc"], ["scan", "x", "--fail-on", "urgent"]):  # fmt: skip
        with pytest.raises(SystemExit):
            main(argv)
    capsys.readouterr()

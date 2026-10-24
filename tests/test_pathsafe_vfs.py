from __future__ import annotations

from hypothesis import given
from hypothesis import strategies as st

from fwaudit.extract.pathsafe import join_symlink, normalize_member
from fwaudit.formats.entries import ArchiveEntry, EntryKind
from fwaudit.vfs import VirtualFS


def test_normalize_basic_forms() -> None:
    assert normalize_member(b"etc/passwd").path == "/etc/passwd"
    assert normalize_member(b"./etc//passwd").path == "/etc/passwd"
    assert normalize_member(b".").path == "/"
    v = normalize_member(b"/etc/shadow")
    assert v.path == "/etc/shadow"
    assert v.note is not None


def test_normalize_rejections() -> None:
    assert normalize_member(b"").reason == "empty member name"
    assert "NUL" in (normalize_member(b"a\x00b").reason or "")
    assert ".." in (normalize_member(b"../etc/passwd").reason or "")
    assert ".." in (normalize_member(b"a/../b").reason or "")
    assert "longer" in (normalize_member(b"a" * 5000).reason or "")


@given(st.binary(max_size=64))
def test_normalized_paths_are_rooted_and_clean(raw: bytes) -> None:
    verdict = normalize_member(raw)
    if verdict.path is not None:
        assert verdict.path.startswith("/")
        assert "/../" not in verdict.path + "/"
        assert "//" not in verdict.path
        assert "\x00" not in verdict.path


@given(st.lists(st.sampled_from(["..", ".", "a", "b", "", "/"]), max_size=12))
def test_join_symlink_never_escapes(parts: list[str]) -> None:
    out = join_symlink("/x/y", "/".join(parts))
    assert ".." not in out
    assert "." not in out


def _fs(*entries: ArchiveEntry) -> VirtualFS:
    fs = VirtualFS("t", "test")
    for e in entries:
        fs.add_entry(e)
    return fs


def test_vfs_implicit_parents_and_read() -> None:
    fs = _fs(ArchiveEntry(b"etc/config/x.conf", EntryKind.FILE, 0o600, data=b"hi"))
    node = fs.get("/etc/config")
    assert node is not None
    assert node.kind is EntryKind.DIR
    assert fs.read("/etc/config/x.conf") == b"hi"
    assert fs.read_text("/etc/config/x.conf") == "hi"
    assert fs.read("/etc/config") is None
    assert "/etc/config/x.conf" in fs
    assert len(list(fs.files())) == 1


def test_vfs_rejects_write_through_symlink() -> None:
    fs = _fs(
        ArchiveEntry(b"etclink", EntryKind.SYMLINK, 0o777, link_target=b"/etc"),
        ArchiveEntry(b"etclink/cron", EntryKind.FILE, 0o644, data=b"x"),
    )
    assert fs.rejections
    assert fs.rejections[0].traversal
    assert "symlink" in fs.rejections[0].reason


def test_vfs_rejects_file_as_parent_and_dir_replacement() -> None:
    fs = _fs(
        ArchiveEntry(b"a", EntryKind.FILE, 0o644, data=b"x"),
        ArchiveEntry(b"a/b", EntryKind.FILE, 0o644, data=b"y"),
        ArchiveEntry(b"d/inner", EntryKind.FILE, 0o644, data=b"z"),
        ArchiveEntry(b"d", EntryKind.FILE, 0o644, data=b"replace"),
        ArchiveEntry(b"/", EntryKind.FILE, 0o644, data=b"root file"),
    )
    reasons = [r.reason for r in fs.rejections]
    assert any("not a directory" in r for r in reasons)
    assert any("non-empty directory" in r for r in reasons)
    assert any("root" in r for r in reasons)


def test_vfs_symlink_resolution_is_chrooted() -> None:
    fs = _fs(
        ArchiveEntry(b"etc/passwd", EntryKind.FILE, 0o644, data=b"root"),
        ArchiveEntry(b"bin/escape", EntryKind.SYMLINK, 0o777, link_target=b"../../../etc/passwd"),
        ArchiveEntry(b"bin/abs", EntryKind.SYMLINK, 0o777, link_target=b"/etc/passwd"),
        ArchiveEntry(b"loop1", EntryKind.SYMLINK, 0o777, link_target=b"loop2"),
        ArchiveEntry(b"loop2", EntryKind.SYMLINK, 0o777, link_target=b"loop1"),
        ArchiveEntry(b"dirlink", EntryKind.SYMLINK, 0o777, link_target=b"etc"),
    )
    assert fs.read("/bin/escape") == b"root"
    assert fs.read("/bin/abs") == b"root"
    assert fs.read("/dirlink/passwd") == b"root"
    assert fs.get("/loop1") is None
    lnode = fs.lstat("/bin/abs")
    assert lnode is not None
    assert lnode.kind is EntryKind.SYMLINK
    assert fs.resolve("/missing/x") is None


def test_vfs_hardlinks_and_dir_metadata_update() -> None:
    fs = _fs(
        ArchiveEntry(b"bin/a", EntryKind.FILE, 0o4755, data=b"elf"),
        ArchiveEntry(b"bin/b", EntryKind.HARDLINK, 0o755, link_target=b"bin/a"),
        ArchiveEntry(b"bin/c", EntryKind.HARDLINK, 0o755, link_target=b"bin/missing"),
        ArchiveEntry(b"bin", EntryKind.DIR, 0o700),
        ArchiveEntry(b".", EntryKind.DIR, 0o711),
    )
    b = fs.get("/bin/b")
    assert b is not None
    assert b.data == b"elf"
    assert b.is_setuid
    assert any("hard link" in r.reason for r in fs.rejections)
    bin_dir = fs.get("/bin")
    root = fs.get("/")
    assert bin_dir is not None
    assert bin_dir.mode == 0o700
    assert root is not None
    assert root.mode == 0o711


def test_vnode_mode_string_and_glob() -> None:
    fs = _fs(
        ArchiveEntry(b"tmp", EntryKind.DIR, 0o1777),
        ArchiveEntry(b"dev/null", EntryKind.CHARDEV, 0o666, rdev=(1, 3)),
        ArchiveEntry(b"etc/a.conf", EntryKind.FILE, 0o644, data=b"a"),
    )
    tmp = fs.get("/tmp")
    assert tmp is not None
    assert tmp.mode_string() == "drwxrwxrwt"
    assert tmp.sticky
    dev = fs.get("/dev/null")
    assert dev is not None
    assert dev.mode_string().startswith("c")
    assert [n.path for n in fs.glob("/etc/*.conf")] == ["/etc/a.conf"]
    assert [n.path for n in fs.walk_prefix("/etc")] == ["/etc", "/etc/a.conf"]
    assert fs.total_bytes == 1

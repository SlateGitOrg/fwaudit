"""Shared fixtures."""

from __future__ import annotations

from collections.abc import Callable

import pytest

from fwaudit.audit.base import AuditConfig
from fwaudit.formats.entries import ArchiveEntry, EntryKind
from fwaudit.limits import Budget, Limits
from fwaudit.pipeline import AuditOptions
from fwaudit.synth.firmware import REFERENCE_TIME
from fwaudit.vfs import VirtualFS


@pytest.fixture
def budget() -> Budget:
    return Budget(Limits())


@pytest.fixture
def config() -> AuditConfig:
    return AuditConfig(reference_time=REFERENCE_TIME)


@pytest.fixture
def options(config: AuditConfig) -> AuditOptions:
    return AuditOptions(config=config)


FsFactory = Callable[..., VirtualFS]


@pytest.fixture
def make_fs() -> FsFactory:
    """Build a VirtualFS from {path: content|("dir"|"link"|"file", ...)} specs."""

    def factory(spec: dict[str, object], fs_id: str = "test/fs") -> VirtualFS:
        fs = VirtualFS(fs_id, "test")
        for path, value in spec.items():
            name = path.encode()
            if isinstance(value, (str, bytes)):
                data = value.encode() if isinstance(value, str) else value
                fs.add_entry(ArchiveEntry(name, EntryKind.FILE, 0o644, data=data))
            elif isinstance(value, tuple) and value[0] == "file":
                _, data, mode, *rest = value
                uid = rest[0] if rest else 0
                raw = data.encode() if isinstance(data, str) else data
                fs.add_entry(ArchiveEntry(name, EntryKind.FILE, mode, uid, 0, raw))
            elif isinstance(value, tuple) and value[0] == "dir":
                fs.add_entry(ArchiveEntry(name, EntryKind.DIR, value[1]))
            elif isinstance(value, tuple) and value[0] == "link":
                fs.add_entry(
                    ArchiveEntry(name, EntryKind.SYMLINK, 0o777, link_target=value[1].encode())
                )
            else:
                raise TypeError(f"bad spec for {path}")
        return fs

    return factory

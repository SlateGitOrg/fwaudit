"""Optional, hardened materialisation of a mounted :class:`VirtualFS` onto disk.

Auditing never needs this; it exists for analysts who want to inspect files by hand
(``fwaudit scan --extract-to DIR``). Guarantees:

* paths were already normalised by the VFS (no ``..``, no absolute paths);
* symlinks, device nodes, FIFOs and sockets are **never created** - they are recorded in
  ``.fwaudit-manifest.json`` instead, so nothing on disk can point outside ``dest``;
* files are opened with ``O_CREAT | O_EXCL | O_NOFOLLOW``, so an existing file or link
  is never overwritten or followed;
* setuid/setgid/sticky and group/world-write bits are stripped; the original mode,
  owner and link target are kept in the manifest;
* every destination is re-checked to resolve inside ``dest`` before it is written.
"""

from __future__ import annotations

import json
import os
from dataclasses import dataclass, field
from pathlib import Path

from fwaudit.errors import UnsafePathError
from fwaudit.formats.entries import EntryKind
from fwaudit.vfs import VirtualFS

MANIFEST = ".fwaudit-manifest.json"
SAFE_FILE_MODE_MASK = 0o755 & ~0o022


@dataclass
class MaterializeResult:
    root: Path
    files: int = 0
    dirs: int = 0
    recorded_only: int = 0
    manifest: list[dict[str, object]] = field(default_factory=list)


def _inside(path: Path, root: Path) -> bool:
    try:
        path.relative_to(root)
    except ValueError:
        return False
    return True


def materialize(fs: VirtualFS, dest: Path) -> MaterializeResult:
    """Write the regular files and directories of ``fs`` below ``dest``."""
    dest.mkdir(parents=True, exist_ok=True)
    root = dest.resolve()
    result = MaterializeResult(root)
    for node in fs.nodes():
        rel = node.path.lstrip("/")
        result.manifest.append(
            {
                "path": node.path,
                "kind": str(node.kind),
                "mode": oct(node.mode),
                "uid": node.uid,
                "gid": node.gid,
                "size": node.size,
                "link_target": node.link_target,
            }
        )
        if not rel:
            continue
        target = root / rel
        if not _inside(target.parent.resolve(), root) or target.is_symlink():
            raise UnsafePathError(f"refusing to write {node.path!r} outside {root}")
        if node.kind is EntryKind.DIR:
            target.mkdir(mode=0o755, exist_ok=True)
            result.dirs += 1
        elif node.kind is EntryKind.FILE:
            flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0)
            fd = os.open(target, flags, node.mode & SAFE_FILE_MODE_MASK | 0o600)
            with os.fdopen(fd, "wb") as handle:
                handle.write(node.data)
            result.files += 1
        else:
            result.recorded_only += 1
    (root / MANIFEST).write_text(json.dumps(result.manifest, indent=1) + "\n")
    return result

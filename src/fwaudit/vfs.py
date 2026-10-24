"""In-memory virtual filesystem that extracted archives are mounted into.

Nothing is written to the host while auditing: every cpio, tar or squashfs image becomes
a :class:`VirtualFS`. Member paths are normalised by :mod:`fwaudit.extract.pathsafe`, and
symlinks are resolved with chroot semantics, so a hostile image can neither write nor
read outside its own root. Attempts to do so are recorded as :class:`Rejection` objects
that the extraction engine turns into findings.
"""

from __future__ import annotations

import fnmatch
import stat
from collections.abc import Iterator
from dataclasses import dataclass

from fwaudit.extract.pathsafe import decode_name, join_symlink, normalize_member
from fwaudit.formats.entries import ArchiveEntry, EntryKind

MAX_SYMLINK_HOPS = 40


@dataclass
class VNode:
    path: str
    kind: EntryKind
    mode: int
    uid: int = 0
    gid: int = 0
    data: bytes = b""
    link_target: str | None = None
    rdev: tuple[int, int] | None = None
    truncated: bool = False

    @property
    def size(self) -> int:
        return len(self.data)

    @property
    def is_setuid(self) -> bool:
        return bool(self.mode & stat.S_ISUID)

    @property
    def is_setgid(self) -> bool:
        return bool(self.mode & stat.S_ISGID)

    @property
    def world_writable(self) -> bool:
        return bool(self.mode & stat.S_IWOTH)

    @property
    def world_readable(self) -> bool:
        return bool(self.mode & stat.S_IROTH)

    @property
    def sticky(self) -> bool:
        return bool(self.mode & stat.S_ISVTX)

    def mode_string(self) -> str:
        type_bits = {
            EntryKind.FILE: stat.S_IFREG,
            EntryKind.DIR: stat.S_IFDIR,
            EntryKind.SYMLINK: stat.S_IFLNK,
            EntryKind.CHARDEV: stat.S_IFCHR,
            EntryKind.BLOCKDEV: stat.S_IFBLK,
            EntryKind.FIFO: stat.S_IFIFO,
            EntryKind.SOCKET: stat.S_IFSOCK,
        }.get(self.kind, stat.S_IFREG)
        return stat.filemode(type_bits | self.mode)


@dataclass(frozen=True)
class Rejection:
    """An archive member that was refused because it was unsafe or inconsistent."""

    raw_name: str
    reason: str
    traversal: bool


class VirtualFS:
    """A rooted tree of :class:`VNode` objects keyed by canonical absolute path."""

    def __init__(self, fs_id: str, source_kind: str, *, max_path_len: int = 4096) -> None:
        self.fs_id = fs_id
        self.source_kind = source_kind
        self.max_path_len = max_path_len
        self._nodes: dict[str, VNode] = {"/": VNode("/", EntryKind.DIR, 0o755)}
        self.rejections: list[Rejection] = []
        self.notes: list[str] = []

    # ------------------------------------------------------------------ building
    def add_entry(self, entry: ArchiveEntry) -> VNode | None:
        """Insert one archive member. Returns the node, or ``None`` if it was rejected."""
        verdict = normalize_member(entry.name, max_len=self.max_path_len)
        raw = decode_name(entry.name)
        if verdict.path is None:
            reason = verdict.reason or "invalid member name"
            self.rejections.append(Rejection(raw, reason, traversal=".." in reason))
            return None
        path = verdict.path
        if verdict.note and verdict.note not in self.notes:
            self.notes.append(verdict.note)
        if path == "/":
            if entry.kind is EntryKind.DIR:
                root = self._nodes["/"]
                root.mode, root.uid, root.gid = entry.mode, entry.uid, entry.gid
                return root
            self.rejections.append(Rejection(raw, "non-directory member for root", False))
            return None
        parent_problem = self._ensure_parents(path)
        if parent_problem is not None:
            self.rejections.append(Rejection(raw, parent_problem, traversal=True))
            return None
        node = self._node_from_entry(path, entry)
        if node is None:
            self.rejections.append(Rejection(raw, "hard link to missing target", False))
            return None
        existing = self._nodes.get(path)
        if existing is not None and existing.kind is EntryKind.DIR:
            if node.kind is EntryKind.DIR:
                existing.mode, existing.uid, existing.gid = node.mode, node.uid, node.gid
                return existing
            if any(p.startswith(path + "/") for p in self._nodes):
                self.rejections.append(
                    Rejection(raw, "member would replace a non-empty directory", False)
                )
                return None
        self._nodes[path] = node
        return node

    def _ensure_parents(self, path: str) -> str | None:
        parts = path.strip("/").split("/")[:-1]
        cur = ""
        for part in parts:
            cur = f"{cur}/{part}"
            node = self._nodes.get(cur)
            if node is None:
                self._nodes[cur] = VNode(cur, EntryKind.DIR, 0o755)
            elif node.kind is EntryKind.SYMLINK:
                return f"member would be written through symlink {cur!r}"
            elif node.kind is not EntryKind.DIR:
                return f"parent {cur!r} is not a directory"
        return None

    def _node_from_entry(self, path: str, entry: ArchiveEntry) -> VNode | None:
        if entry.kind is EntryKind.HARDLINK:
            target_verdict = normalize_member(entry.link_target or b"", max_len=self.max_path_len)
            target = self._nodes.get(target_verdict.path or "")
            if target is None or target.kind is not EntryKind.FILE:
                return None
            return VNode(path, EntryKind.FILE, target.mode, target.uid, target.gid, target.data)
        link = decode_name(entry.link_target) if entry.link_target is not None else None
        return VNode(
            path=path,
            kind=entry.kind,
            mode=entry.mode & 0o7777,
            uid=entry.uid,
            gid=entry.gid,
            data=entry.data if entry.kind is EntryKind.FILE else b"",
            link_target=link if entry.kind is EntryKind.SYMLINK else None,
            rdev=entry.rdev,
            truncated=entry.truncated,
        )

    # ------------------------------------------------------------------ querying
    def __len__(self) -> int:
        return len(self._nodes)

    def __contains__(self, path: object) -> bool:
        return isinstance(path, str) and self.get(path) is not None

    def nodes(self) -> Iterator[VNode]:
        for path in sorted(self._nodes):
            yield self._nodes[path]

    def files(self) -> Iterator[VNode]:
        for node in self.nodes():
            if node.kind is EntryKind.FILE:
                yield node

    @property
    def total_bytes(self) -> int:
        return sum(n.size for n in self._nodes.values())

    def lstat(self, path: str) -> VNode | None:
        """Return the node at ``path`` without following a final symlink."""
        resolved = self.resolve(path, follow_final=False)
        return None if resolved is None else self._nodes.get(resolved)

    def get(self, path: str) -> VNode | None:
        """Return the node at ``path``, following symlinks (chroot semantics)."""
        resolved = self.resolve(path, follow_final=True)
        return None if resolved is None else self._nodes.get(resolved)

    def read(self, path: str) -> bytes | None:
        node = self.get(path)
        if node is None or node.kind is not EntryKind.FILE:
            return None
        return node.data

    def read_text(self, path: str) -> str | None:
        data = self.read(path)
        return None if data is None else data.decode("utf-8", errors="replace")

    def resolve(self, path: str, *, follow_final: bool = True) -> str | None:
        """Canonicalise ``path`` by resolving symlinks; ``None`` if it does not exist.

        Resolution is bounded by :data:`MAX_SYMLINK_HOPS` so symlink loops terminate.
        """
        pending = join_symlink("/", path)
        done: list[str] = []
        hops = 0
        while pending:
            part = pending.pop(0)
            candidate = "/" + "/".join([*done, part])
            node = self._nodes.get(candidate)
            if node is None:
                return None
            if node.kind is EntryKind.SYMLINK and (pending or follow_final):
                hops += 1
                if hops > MAX_SYMLINK_HOPS:
                    return None
                base = "/" + "/".join(done)
                pending = join_symlink(base, node.link_target or "") + pending
                done = []
                continue
            done.append(part)
        return "/" + "/".join(done)

    def glob(self, pattern: str) -> list[VNode]:
        """Return nodes whose canonical path matches the fnmatch ``pattern``."""
        return [self._nodes[p] for p in sorted(self._nodes) if fnmatch.fnmatchcase(p, pattern)]

    def walk_prefix(self, prefix: str) -> list[VNode]:
        prefix = prefix.rstrip("/")
        return [
            self._nodes[p] for p in sorted(self._nodes) if p == prefix or p.startswith(prefix + "/")
        ]

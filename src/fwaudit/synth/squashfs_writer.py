"""Minimal, deterministic SquashFS 4.0 writer for building synthetic test images.

No ``mksquashfs`` binary is needed. The writer emits a valid little-endian 4.0 image with
gzip (zlib) or xz compression, basic inodes only, no fragments, no xattrs and no export
table. Reading the output back with the independent PySquashfsImage library is part of
the test-suite, which keeps this writer honest.

Image layout::

    superblock (96) | data blocks | inode table | directory table | id table | id index

Directories are written post-order so that every directory listing can reference the
already-written inodes of its children, and each directory inode can point at its
already-written listing.
"""

from __future__ import annotations

import lzma
import struct
import zlib
from collections.abc import Callable
from dataclasses import dataclass

from fwaudit.formats.entries import ArchiveEntry, EntryKind

METADATA_SIZE = 8192
INVALID = 0xFFFFFFFFFFFFFFFF
FLAG_NO_FRAGMENTS = 0x0010
FLAG_NO_XATTRS = 0x0200
BASIC_TYPE = {
    EntryKind.DIR: 1,
    EntryKind.FILE: 2,
    EntryKind.SYMLINK: 3,
    EntryKind.BLOCKDEV: 4,
    EntryKind.CHARDEV: 5,
    EntryKind.FIFO: 6,
    EntryKind.SOCKET: 7,
}


def _zlib(data: bytes) -> bytes:
    return zlib.compress(data, 9)


def _xz(data: bytes) -> bytes:
    return lzma.compress(data, format=lzma.FORMAT_XZ, check=lzma.CHECK_CRC32)


class _MetadataWriter:
    """Accumulates a metadata stream and emits 8 KiB compressed blocks."""

    def __init__(self, compress: Callable[[bytes], bytes]) -> None:
        self._compress = compress
        self._out = bytearray()
        self._buf = bytearray()

    def position(self) -> tuple[int, int]:
        """(start of the current block within the table, offset inside that block)."""
        return len(self._out), len(self._buf)

    def write(self, data: bytes) -> None:
        self._buf += data
        while len(self._buf) >= METADATA_SIZE:
            self._flush(bytes(self._buf[:METADATA_SIZE]))
            del self._buf[:METADATA_SIZE]

    def _flush(self, block: bytes) -> None:
        packed = self._compress(block)
        if len(packed) < len(block):
            self._out += struct.pack("<H", len(packed)) + packed
        else:
            self._out += struct.pack("<H", len(block) | 0x8000) + block

    def finish(self) -> bytes:
        if self._buf:
            self._flush(bytes(self._buf))
            self._buf.clear()
        return bytes(self._out)


@dataclass
class _Node:
    path: str
    entry: ArchiveEntry
    inode_number: int = 0
    children: list[str] | None = None
    blocks_start: int = 0
    block_sizes: tuple[int, ...] = ()


def _normalise(entries: list[ArchiveEntry]) -> dict[str, _Node]:
    nodes: dict[str, _Node] = {"/": _Node("/", ArchiveEntry(b"/", EntryKind.DIR, 0o755), children=[])}
    for e in entries:
        path = "/" + e.name.decode().strip("/")
        if path == "/":
            nodes["/"].entry = e
            continue
        parts = path.strip("/").split("/")
        for i in range(1, len(parts)):
            parent = "/" + "/".join(parts[:i])
            if parent not in nodes:
                nodes[parent] = _Node(parent, ArchiveEntry(parent.encode(), EntryKind.DIR, 0o755),
                                      children=[])  # fmt: skip
        if e.kind is EntryKind.HARDLINK:
            raise ValueError("squashfs writer does not support hard links")
        existing = nodes.get(path)
        children = existing.children if existing and e.kind is EntryKind.DIR else None
        nodes[path] = _Node(path, e, children=[] if e.kind is EntryKind.DIR else None)
        if children:
            nodes[path].children = children
    for path in sorted(nodes):
        if path == "/":
            continue
        parent = path.rsplit("/", 1)[0] or "/"
        siblings = nodes[parent].children
        if siblings is not None and path not in siblings:
            siblings.append(path)
    for i, path in enumerate(sorted(nodes), start=1):
        nodes[path].inode_number = i
    return nodes


def build(
    entries: list[ArchiveEntry],
    *,
    compression: str = "gzip",
    block_size: int = 131072,
    mkfs_time: int = 0,
) -> bytes:
    """Serialise ``entries`` into a SquashFS 4.0 image."""
    if compression not in ("gzip", "xz"):
        raise ValueError("compression must be 'gzip' or 'xz'")
    if block_size & (block_size - 1) or not 4096 <= block_size <= 1024 * 1024:
        raise ValueError("block_size must be a power of two between 4 KiB and 1 MiB")
    compress = _zlib if compression == "gzip" else _xz
    comp_id = 1 if compression == "gzip" else 4
    nodes = _normalise(entries)
    image = bytearray(96)

    for path in sorted(nodes):
        node = nodes[path]
        if node.entry.kind is not EntryKind.FILE:
            continue
        node.blocks_start = len(image)
        sizes = []
        data = node.entry.data
        for i in range(0, len(data), block_size):
            chunk = data[i : i + block_size]
            packed = compress(chunk)
            if len(packed) < len(chunk):
                image += packed
                sizes.append(len(packed))
            else:
                image += chunk
                sizes.append(len(chunk) | (1 << 24))
        node.block_sizes = tuple(sizes)

    ids = sorted({n.entry.uid for n in nodes.values()} | {n.entry.gid for n in nodes.values()})
    id_index = {v: i for i, v in enumerate(ids)}
    inodes = _MetadataWriter(compress)
    dirs = _MetadataWriter(compress)
    refs: dict[str, tuple[int, int]] = {}
    root_parent = len(nodes) + 1

    def header(node: _Node, inode_type: int) -> bytes:
        e = node.entry
        return struct.pack(
            "<HHHHII", inode_type, e.mode & 0o7777, id_index[e.uid], id_index[e.gid],
            mkfs_time, node.inode_number,
        )  # fmt: skip

    def write_leaf(node: _Node) -> None:
        e = node.entry
        refs[node.path] = inodes.position()
        if e.kind is EntryKind.FILE:
            body = struct.pack("<IIII", node.blocks_start, 0xFFFFFFFF, 0, len(e.data))
            body += b"".join(struct.pack("<I", s) for s in node.block_sizes)
        elif e.kind is EntryKind.SYMLINK:
            target = e.link_target or b""
            body = struct.pack("<II", 1, len(target)) + target
        elif e.kind in (EntryKind.CHARDEV, EntryKind.BLOCKDEV):
            major, minor = e.rdev or (0, 0)
            rdev = (major << 8) | (minor & 0xFF) | ((minor & ~0xFF) << 12)
            body = struct.pack("<II", 1, rdev)
        else:
            body = struct.pack("<I", 1)
        inodes.write(header(node, BASIC_TYPE[e.kind]) + body)

    def write_dir(node: _Node, parent_number: int) -> None:
        child_paths = sorted(node.children or [], key=lambda p: p.rsplit("/", 1)[1].encode())
        subdirs = 0
        for cp in child_paths:
            child = nodes[cp]
            if child.entry.kind is EntryKind.DIR:
                subdirs += 1
                write_dir(child, node.inode_number)
            else:
                write_leaf(child)
        listing = bytearray()
        i = 0
        while i < len(child_paths):
            block = refs[child_paths[i]][0]
            base = nodes[child_paths[i]].inode_number
            group: list[str] = []
            while (
                i < len(child_paths)
                and refs[child_paths[i]][0] == block
                and len(group) < 256
                and abs(nodes[child_paths[i]].inode_number - base) < 32767
            ):
                group.append(child_paths[i])
                i += 1
            listing += struct.pack("<III", len(group) - 1, block, base)
            for cp in group:
                name = cp.rsplit("/", 1)[1].encode()
                child = nodes[cp]
                listing += struct.pack(
                    "<HhHH", refs[cp][1], child.inode_number - base,
                    BASIC_TYPE[child.entry.kind], len(name) - 1,
                ) + name  # fmt: skip
        if len(listing) + 3 > 0xFFFF:
            raise ValueError(f"directory {node.path} too large for a basic inode")
        dir_block, dir_offset = dirs.position()
        dirs.write(bytes(listing))
        refs[node.path] = inodes.position()
        body = struct.pack(
            "<IIHHI", dir_block, 2 + subdirs, len(listing) + 3, dir_offset, parent_number
        )
        inodes.write(header(node, 1) + body)

    write_dir(nodes["/"], root_parent)
    root_block, root_offset = refs["/"]

    inode_table_start = len(image)
    image += inodes.finish()
    directory_table_start = len(image)
    image += dirs.finish()
    id_block_pos = len(image)
    id_writer = _MetadataWriter(compress)
    id_writer.write(b"".join(struct.pack("<I", v) for v in ids))
    image += id_writer.finish()
    id_table_start = len(image)
    image += struct.pack("<Q", id_block_pos)
    bytes_used = len(image)

    superblock = struct.pack(
        "<5I6H8Q",
        0x73717368,
        len(nodes),
        mkfs_time,
        block_size,
        0,
        comp_id,
        block_size.bit_length() - 1,
        FLAG_NO_FRAGMENTS | FLAG_NO_XATTRS,
        len(ids),
        4,
        0,
        (root_block << 16) | root_offset,
        bytes_used,
        id_table_start,
        INVALID,
        inode_table_start,
        directory_table_start,
        INVALID,
        INVALID,
    )
    image[:96] = superblock
    image += b"\x00" * (-len(image) % 4096)
    return bytes(image)


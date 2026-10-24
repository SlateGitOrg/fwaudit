"""Recursive identification, decompression and filesystem mounting.

Algorithm (per blob, recursively):

1. Scan the blob for validated signatures (:func:`fwaudit.signatures.scan`).
2. Walk hits in offset order, keeping a cursor: a hit that falls inside a region already
   consumed by an earlier container is skipped. This greedy, left-to-right carve is the
   same strategy binwalk uses and is O(h) over h hits after the O(k*n) scan.
3. Each accepted hit is decoded by its handler, which returns how many bytes it consumed:
   compressed streams are decompressed under the shared :class:`~fwaudit.limits.Budget`
   and explored recursively; uImage payloads are verified and explored; cpio, tar and
   squashfs are mounted into a :class:`~fwaudit.vfs.VirtualFS`. Files inside a mounted
   filesystem that themselves start with a container signature are explored too.
4. Bytes not consumed by any container ("gaps") are kept as raw regions so the auditor
   can still look for key material in them, and unidentified high-entropy gaps are
   reported as possible encryption.

Every failure mode becomes either a node note or a finding; extraction never raises on
malformed input.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field

from fwaudit import entropy
from fwaudit.errors import FormatError, LimitExceededError, UnsupportedFormatError
from fwaudit.formats import cpio, squashfs, tar, uimage
from fwaudit.formats.compression import Codec, decompress
from fwaudit.formats.entries import ArchiveEntry
from fwaudit.limits import Budget, Limits
from fwaudit.model import ExtractionNode, Finding, make_finding
from fwaudit.signatures import Hit, match_at_start, scan
from fwaudit.vfs import VirtualFS

log = logging.getLogger(__name__)

_CODECS = {"gzip": Codec.GZIP, "xz": Codec.XZ, "lzma": Codec.LZMA, "bzip2": Codec.BZIP2}
_UIMAGE_CODECS = {1: Codec.GZIP, 2: Codec.BZIP2, 3: Codec.LZMA}
MIN_GAP = 64
HIGH_ENTROPY_MIN = 8192


@dataclass(frozen=True)
class RawRegion:
    """Bytes of a blob that no recognised container claimed."""

    node_id: str
    offset: int
    data: bytes


@dataclass
class ExtractionResult:
    nodes: dict[str, ExtractionNode] = field(default_factory=dict)
    filesystems: list[VirtualFS] = field(default_factory=list)
    findings: list[Finding] = field(default_factory=list)
    raw_regions: list[RawRegion] = field(default_factory=list)
    root_id: str = "image"


class Extractor:
    """Runs one extraction over one image; not reusable across images."""

    def __init__(self, limits: Limits | None = None) -> None:
        self.limits = limits or Limits()
        self.budget = Budget(self.limits)
        self.result = ExtractionResult()

    # ----------------------------------------------------------------- entry
    def run(self, data: bytes) -> ExtractionResult:
        root = self._node("image", 0, len(data), 0, None, node_id="image")
        self._explore(data, root)
        return self.result

    # ----------------------------------------------------------------- helpers
    def _node(
        self,
        kind: str,
        offset: int,
        length: int,
        depth: int,
        parent: ExtractionNode | None,
        *,
        node_id: str | None = None,
    ) -> ExtractionNode:
        nid = node_id or f"{parent.node_id if parent else ''}/{kind}@{offset:#x}"
        base, n = nid, 2
        while nid in self.result.nodes:
            nid = f"{base}#{n}"
            n += 1
        node = ExtractionNode(nid, kind, offset, length, depth, parent.node_id if parent else None)
        self.result.nodes[nid] = node
        if parent is not None:
            parent.children.append(nid)
        return node

    def _finding(self, rule_id: str, detail: str, node: ExtractionNode, **kw: object) -> None:
        offset = kw.get("offset")
        path = kw.get("path")
        evidence = kw.get("evidence")
        self.result.findings.append(
            make_finding(
                rule_id,
                detail,
                filesystem=node.node_id,
                offset=offset if isinstance(offset, int) else None,
                path=path if isinstance(path, str) else None,
                evidence=evidence if isinstance(evidence, dict) else None,
            )
        )

    # ----------------------------------------------------------------- carving
    def _explore(self, data: bytes, node: ExtractionNode) -> None:
        if node.depth >= self.limits.max_depth:
            node.notes.append("not explored: depth limit")
            self._finding(
                "FWA-EXT-003",
                f"nesting depth {node.depth} reached the limit of {self.limits.max_depth}",
                node,
            )
            return
        cursor = 0
        claimed: list[tuple[int, int]] = []
        for hit in scan(data):
            if hit.offset < cursor:
                continue
            if not hit.extractable:
                continue
            if not hit.supported:
                self._unsupported(hit, node)
                continue
            try:
                self.budget.charge_carve()
            except LimitExceededError as exc:
                node.notes.append(str(exc))
                self._finding("FWA-EXT-002", str(exc), node, evidence={"limit": exc.limit})
                break
            consumed = self._handle(hit, data, node)
            if consumed:
                end = min(len(data), hit.offset + consumed)
                claimed.append((hit.offset, end))
                cursor = end
        self._record_gaps(data, node, claimed)

    def _unsupported(self, hit: Hit, parent: ExtractionNode) -> None:
        child = self._node(hit.name, hit.offset, 0, parent.depth + 1, parent)
        child.meta.update(hit.meta)
        reason = str(hit.meta.get("unsupported", f"{hit.description} is not supported"))
        child.notes.append(reason)
        self._finding(
            "FWA-EXT-005",
            f"{hit.description} at {hit.offset:#x}: {reason}",
            parent,
            offset=hit.offset,
            evidence={"format": hit.name, "key": hit.offset},
        )

    def _record_gaps(
        self, data: bytes, node: ExtractionNode, claimed: list[tuple[int, int]]
    ) -> None:
        pos = 0
        gaps: list[tuple[int, int]] = []
        for start, end in claimed:
            if start - pos >= MIN_GAP:
                gaps.append((pos, start))
            pos = max(pos, end)
        if len(data) - pos >= MIN_GAP:
            gaps.append((pos, len(data)))
        node.meta["claimed_bytes"] = sum(e - s for s, e in claimed)
        for start, end in gaps:
            chunk = data[start:end]
            self.result.raw_regions.append(RawRegion(node.node_id, start, chunk))
            for s, e, mean in entropy.high_entropy_spans(chunk, min_length=HIGH_ENTROPY_MIN):
                self._finding(
                    "FWA-EXT-006",
                    f"{e - s} bytes at {start + s:#x} have mean entropy {mean:.2f} bits/byte "
                    "and match no known container",
                    node,
                    offset=start + s,
                    evidence={"length": e - s, "mean_entropy": mean},
                )

    # ----------------------------------------------------------------- handlers
    def _handle(self, hit: Hit, data: bytes, parent: ExtractionNode) -> int | None:
        view = memoryview(data)[hit.offset :]
        try:
            if hit.name in _CODECS:
                return self._handle_stream(hit, view, parent)
            if hit.name == "uimage":
                return self._handle_uimage(hit, view, parent)
            if hit.name in ("cpio", "tar", "squashfs"):
                return self._handle_fs(hit, view, parent)
        except LimitExceededError as exc:
            self._finding(
                "FWA-EXT-002",
                f"{hit.description} at {hit.offset:#x}: {exc}",
                parent,
                offset=hit.offset,
                evidence={"limit": exc.limit, "format": hit.name},
            )
            parent.notes.append(f"{hit.name}@{hit.offset:#x}: {exc}")
        except UnsupportedFormatError as exc:
            self._unsupported(
                Hit(hit.offset, hit.name, hit.description, True, False, {"unsupported": str(exc)}),
                parent,
            )
        except FormatError as exc:
            log.debug("rejected %s at %#x: %s", hit.name, hit.offset, exc)
        return None

    def _handle_stream(self, hit: Hit, view: memoryview, parent: ExtractionNode) -> int | None:
        codec = _CODECS[hit.name]
        what = f"{hit.name}@{hit.offset:#x}"
        result = decompress(codec, view, self.budget, what=what)
        if codec is Codec.LZMA and not result.complete:
            return None  # weak magic: only trust LZMA streams that decode to their end
        self.budget.charge_bytes(len(result.data), what)
        child = self._node(hit.name, hit.offset, result.consumed, parent.depth + 1, parent)
        child.meta.update(hit.meta)
        child.meta["decompressed_size"] = len(result.data)
        child.meta["complete"] = result.complete
        if not result.complete:
            child.notes.append("stream truncated or corrupt; partial output explored")
        self._explore(result.data, child)
        return result.consumed

    def _handle_uimage(self, hit: Hit, view: memoryview, parent: ExtractionNode) -> int | None:
        img = uimage.parse(view)
        h = img.header
        child = self._node("uimage", hit.offset, img.total_length, parent.depth + 1, parent)
        child.meta.update(
            {
                "name": h.name,
                "type": h.type_name,
                "os": h.os_name,
                "arch": h.arch_name,
                "compression": h.compression_name,
                "data_size": h.data_size,
                "load_addr": f"{h.load_addr:#010x}",
                "entry_point": f"{h.entry_point:#010x}",
                "header_crc_ok": h.header_crc_ok,
                "data_crc_ok": img.data_crc_ok,
            }
        )
        for label, ok in (("header", h.header_crc_ok), ("data", img.data_crc_ok)):
            if not ok:
                self._finding(
                    "FWA-EXT-004",
                    f"uImage '{h.name}' at {hit.offset:#x}: {label} CRC mismatch",
                    parent,
                    offset=hit.offset,
                    evidence={"crc": label, "key": f"{hit.offset}:{label}"},
                )
        codec = _UIMAGE_CODECS.get(h.compression)
        for i, part in enumerate(img.parts):
            target = child
            if len(img.parts) > 1:
                target = self._node("part", i, len(part), child.depth + 1, child)
            if codec is Codec.LZMA:
                self._decode_known(part, codec, target)
            else:
                self._explore(part, target)
        return img.total_length

    def _decode_known(self, part: bytes, codec: Codec, parent: ExtractionNode) -> None:
        """Decompress a payload whose codec is declared by its container header."""
        what = f"{parent.node_id}:{codec}"
        try:
            result = decompress(codec, part, self.budget, what=what)
        except FormatError:
            self._explore(part, parent)
            return
        self.budget.charge_bytes(len(result.data), what)
        child = self._node(str(codec), 0, result.consumed, parent.depth + 1, parent)
        child.meta["decompressed_size"] = len(result.data)
        child.meta["complete"] = result.complete
        self._explore(result.data, child)

    def _handle_fs(self, hit: Hit, view: memoryview, parent: ExtractionNode) -> int | None:
        entries: list[ArchiveEntry]
        complete = True
        meta: dict[str, object] = {}
        what = f"{hit.name}@{hit.offset:#x}"
        if hit.name == "cpio":
            c = cpio.parse(view, self.budget, what=what)
            entries, consumed, complete = c.entries, c.consumed, c.complete
            meta = {"variant": c.variant}
            if c.checksum_errors:
                meta["checksum_errors"] = len(c.checksum_errors)
        elif hit.name == "tar":
            t = tar.parse(view, self.budget, what=what)
            entries, consumed, complete = t.entries, t.consumed, t.complete
        else:
            s = squashfs.parse(view, self.budget, what=what)
            entries, consumed = s.entries, s.consumed
            meta = {
                "compression": s.superblock.compression_name,
                "block_size": s.superblock.block_size,
            }
        node = self._node(hit.name, hit.offset, consumed, parent.depth + 1, parent)
        for k, v in meta.items():
            if isinstance(v, (str, int)):
                node.meta[k] = v
        if not complete:
            node.notes.append("archive truncated; members read so far were mounted")
        self._mount(entries, node)
        return consumed

    def _mount(self, entries: list[ArchiveEntry], node: ExtractionNode) -> None:
        fs = VirtualFS(node.node_id, node.kind, max_path_len=self.limits.max_path_len)
        for entry in entries:
            fs.add_entry(entry)
        for rej in fs.rejections:
            if rej.traversal:
                self._finding(
                    "FWA-EXT-001",
                    f"member {rej.raw_name!r} rejected: {rej.reason}",
                    node,
                    evidence={"member": rej.raw_name, "reason": rej.reason, "key": rej.raw_name},
                )
            else:
                node.notes.append(f"member {rej.raw_name!r} skipped: {rej.reason}")
        node.notes.extend(fs.notes)
        node.meta["entries"] = len(fs)
        node.meta["files"] = sum(1 for _ in fs.files())
        node.meta["file_bytes"] = fs.total_bytes
        self.result.filesystems.append(fs)
        self._explore_nested(fs, node)

    def _explore_nested(self, fs: VirtualFS, node: ExtractionNode) -> None:
        """Explore regular files that are themselves containers (e.g. a config .tar.gz)."""
        for f in fs.files():
            if len(f.data) < 16:
                continue
            hit = match_at_start(f.data)
            if hit is None:
                continue
            child = self._node(
                "file", 0, len(f.data), node.depth + 1, node, node_id=f"{node.node_id}:{f.path}"
            )
            child.meta["path"] = f.path
            self._explore(f.data, child)

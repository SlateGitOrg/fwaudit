"""Block-wise Shannon entropy map of a firmware image.

The image is cut into fixed-size blocks and each block's byte histogram is computed with
a vectorised ``numpy.bincount`` over ``block_index * 256 + byte``, a few MiB at a time,
so the whole map costs O(n) time and O(chunk + n/B) memory. Consecutive blocks with the
same class are merged into regions:

* ``high``  (>= 7.2 bits/byte): compressed or encrypted data
* ``low``   (<= 1.0 bits/byte): padding / erased flash (0x00 or 0xFF runs)
* ``mixed``: code, text and uncompressed filesystem data
"""

from __future__ import annotations

from dataclasses import dataclass

import numpy as np
import numpy.typing as npt

HIGH_THRESHOLD = 7.2
LOW_THRESHOLD = 1.0
SPARK = " ▁▂▃▄▅▆▇█"
CHUNK_BYTES = 4 * 1024 * 1024


@dataclass(frozen=True)
class Region:
    start: int
    end: int
    kind: str
    mean_entropy: float

    @property
    def length(self) -> int:
        return self.end - self.start


@dataclass(frozen=True)
class EntropyMap:
    block_size: int
    size: int
    values: tuple[float, ...]
    regions: tuple[Region, ...]

    @property
    def mean(self) -> float:
        return float(np.mean(self.values)) if self.values else 0.0

    def sparkline(self, width: int = 64) -> str:
        """Render the map as a unicode sparkline (max over each bucket)."""
        if not self.values:
            return ""
        vals = np.asarray(self.values)
        buckets = np.array_split(vals, min(width, len(vals)))
        chars = []
        for b in buckets:
            level = round(float(b.max()) / 8.0 * (len(SPARK) - 1))
            chars.append(SPARK[max(0, min(level, len(SPARK) - 1))])
        return "".join(chars)


def block_entropies(data: bytes | memoryview, block_size: int = 4096) -> npt.NDArray[np.float64]:
    """Shannon entropy (bits/byte) for each ``block_size`` block; last block may be short."""
    if block_size <= 0:
        raise ValueError("block_size must be positive")
    arr = np.frombuffer(data, dtype=np.uint8)
    n = arr.size
    if n == 0:
        return np.zeros(0, dtype=np.float64)
    nblocks = (n + block_size - 1) // block_size
    out = np.empty(nblocks, dtype=np.float64)
    # Process a bounded number of blocks at a time so memory stays O(chunk), not O(n).
    blocks_per_chunk = max(1, CHUNK_BYTES // block_size)
    for first in range(0, nblocks, blocks_per_chunk):
        last = min(nblocks, first + blocks_per_chunk)
        sub = arr[first * block_size : last * block_size]
        idx = np.arange(sub.size, dtype=np.int64) // block_size * 256 + sub
        counts = np.bincount(idx, minlength=(last - first) * 256).reshape(last - first, 256)
        lengths = counts.sum(axis=1, keepdims=True).astype(np.float64)
        probs = counts / lengths
        with np.errstate(divide="ignore", invalid="ignore"):
            logs = np.where(probs > 0, np.log2(probs), 0.0)
        out[first:last] = 0.0 - (probs * logs).sum(axis=1)  # 0.0 - x avoids -0.0
    return out


def classify(value: float) -> str:
    if value >= HIGH_THRESHOLD:
        return "high"
    if value <= LOW_THRESHOLD:
        return "low"
    return "mixed"


def entropy_map(data: bytes | memoryview, block_size: int = 4096) -> EntropyMap:
    values = block_entropies(data, block_size)
    regions: list[Region] = []
    size = len(data)
    start_block = 0
    for i in range(1, len(values) + 1):
        if i == len(values) or classify(float(values[i])) != classify(float(values[start_block])):
            seg = values[start_block:i]
            regions.append(
                Region(
                    start=start_block * block_size,
                    end=min(i * block_size, size),
                    kind=classify(float(values[start_block])),
                    mean_entropy=round(float(seg.mean()), 3),
                )
            )
            start_block = i
    return EntropyMap(
        block_size=block_size,
        size=size,
        values=tuple(round(float(v), 3) for v in values),
        regions=tuple(regions),
    )


def high_entropy_spans(
    data: bytes | memoryview, *, block_size: int = 4096, min_length: int = 8192
) -> list[tuple[int, int, float]]:
    """(start, end, mean entropy) for high-entropy regions at least ``min_length`` long."""
    emap = entropy_map(data, block_size)
    return [
        (r.start, r.end, r.mean_entropy)
        for r in emap.regions
        if r.kind == "high" and r.length >= min_length
    ]

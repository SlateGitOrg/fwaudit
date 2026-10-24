from __future__ import annotations

import bz2
import gzip
import lzma
import zlib

import pytest

from fwaudit.errors import FormatError, LimitExceededError, TruncatedError
from fwaudit.formats.compression import Codec, decompress, lzma_header_plausible
from fwaudit.limits import Budget, Limits, MiB

PAYLOAD = b"firmware payload " * 4000


def _encode(codec: Codec, data: bytes) -> bytes:
    if codec is Codec.GZIP:
        return gzip.compress(data, mtime=0)
    if codec is Codec.ZLIB:
        return zlib.compress(data)
    if codec is Codec.XZ:
        return lzma.compress(data, format=lzma.FORMAT_XZ)
    if codec is Codec.LZMA:
        return lzma.compress(data, format=lzma.FORMAT_ALONE)
    return bz2.compress(data)


@pytest.mark.parametrize("codec", list(Codec))
def test_roundtrip_and_consumed_length(codec: Codec, budget: Budget) -> None:
    blob = _encode(codec, PAYLOAD)
    out = decompress(codec, blob + b"TRAILING-GARBAGE", budget)
    assert out.data == PAYLOAD
    assert out.complete
    assert out.consumed == len(blob)


@pytest.mark.parametrize("codec", list(Codec))
def test_truncated_stream_returns_partial(codec: Codec, budget: Budget) -> None:
    big = bytes(range(256)) * 8000  # > one 900k bzip2 block
    blob = _encode(codec, big)
    out = decompress(codec, blob[: len(blob) * 2 // 3], budget)
    assert not out.complete
    assert 0 < len(out.data) < len(big)
    with pytest.raises(TruncatedError):
        decompress(codec, blob[: len(blob) * 2 // 3], budget, allow_truncated=False)


@pytest.mark.parametrize("codec", list(Codec))
def test_garbage_is_format_error(codec: Codec, budget: Budget) -> None:
    with pytest.raises(FormatError):
        decompress(codec, b"\x00\x01\x02 definitely not compressed" * 4, budget)


def test_corrupt_after_output_is_partial(budget: Budget) -> None:
    blob = bytearray(gzip.compress(bytes(range(256)) * 400, mtime=0))
    blob[len(blob) // 2 :] = b"\xff" * (len(blob) - len(blob) // 2)
    out = decompress(Codec.GZIP, bytes(blob), budget)
    assert not out.complete
    with pytest.raises(TruncatedError):
        decompress(Codec.GZIP, bytes(blob), budget, allow_truncated=False)


def test_ratio_limit_stops_bomb() -> None:
    bomb = gzip.compress(b"\x00" * (32 * MiB), mtime=0)
    budget = Budget(Limits(max_ratio=100, ratio_grace_bytes=MiB))
    with pytest.raises(LimitExceededError) as exc:
        decompress(Codec.GZIP, bomb, budget)
    assert exc.value.limit == "max_ratio"


def test_stream_and_total_caps() -> None:
    data = bytes(range(256)) * 8192  # 2 MiB, compresses poorly enough to pass ratio
    blob = _encode(Codec.XZ, data)
    with pytest.raises(LimitExceededError) as exc:
        decompress(Codec.XZ, blob, Budget(Limits(max_stream_bytes=MiB, max_ratio=10_000)))
    assert exc.value.limit == "max_stream_bytes"
    small_total = Budget(Limits(max_total_bytes=MiB // 2, max_ratio=10_000))
    with pytest.raises(LimitExceededError) as exc2:
        decompress(Codec.XZ, blob, small_total)
    assert exc2.value.limit == "max_total_bytes"


def test_lzma_header_heuristic() -> None:
    good = lzma.compress(b"abc", format=lzma.FORMAT_ALONE)[:13]
    assert lzma_header_plausible(good)
    assert not lzma_header_plausible(good[:5])
    assert not lzma_header_plausible(b"\xff" + good[1:])
    assert not lzma_header_plausible(good[:1] + (3).to_bytes(4, "little") + good[5:])
    odd = good[:1] + (0x3000).to_bytes(4, "little") + good[5:]
    assert lzma_header_plausible(odd)
    assert not lzma_header_plausible(good[:1] + (0x5000).to_bytes(4, "little") + good[5:])
    huge = good[:5] + (1 << 40).to_bytes(8, "little")
    assert not lzma_header_plausible(huge)


def test_budget_validation() -> None:
    with pytest.raises(ValueError):
        Limits(max_depth=0)
    b = Budget(Limits(max_entries=1, max_carves=1))
    b.charge_entry("x")
    with pytest.raises(LimitExceededError):
        b.charge_entry("x")
    b.charge_carve()
    with pytest.raises(LimitExceededError):
        b.charge_carve()
    with pytest.raises(ValueError):
        b.charge_bytes(-1, "x")

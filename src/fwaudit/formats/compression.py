"""Bounded stream decompression for gzip, zlib, xz, lzma-alone and bzip2.

Each decoder feeds input in fixed-size chunks and asks the library for at most
``limit + 1`` output bytes, so a decompression bomb is detected after producing a
bounded amount of output instead of after exhausting memory. Decoders also report how
many input bytes the stream occupied, which the carver needs to know where the next
region starts.
"""

from __future__ import annotations

import bz2
import lzma
import zlib
from dataclasses import dataclass
from enum import StrEnum
from typing import Protocol

from fwaudit.errors import FormatError, LimitExceededError, TruncatedError
from fwaudit.limits import Budget

CHUNK = 64 * 1024


class Codec(StrEnum):
    GZIP = "gzip"
    ZLIB = "zlib"
    XZ = "xz"
    LZMA = "lzma"
    BZIP2 = "bzip2"


@dataclass(frozen=True)
class Decompressed:
    data: bytes
    consumed: int
    complete: bool


class _Decoder(Protocol):
    @property
    def eof(self) -> bool: ...

    @property
    def unused_data(self) -> bytes: ...

    def decompress(self, data: bytes, max_length: int = ..., /) -> bytes: ...


class _ZlibAdapter:
    """Give ``zlib.decompressobj`` the same interface as the lzma/bz2 decoders."""

    def __init__(self, wbits: int) -> None:
        self._d = zlib.decompressobj(wbits)
        self._tail = b""

    @property
    def eof(self) -> bool:
        return self._d.eof

    @property
    def unused_data(self) -> bytes:
        return self._d.unused_data

    @property
    def needs_input(self) -> bool:
        return not self._d.unconsumed_tail

    def decompress(self, data: bytes, max_length: int = -1, /) -> bytes:
        buf = self._d.unconsumed_tail + data if data else self._d.unconsumed_tail
        return self._d.decompress(buf, max(max_length, 0))


def _make_decoder(codec: Codec) -> _Decoder | _ZlibAdapter:
    if codec is Codec.GZIP:
        return _ZlibAdapter(16 + zlib.MAX_WBITS)
    if codec is Codec.ZLIB:
        return _ZlibAdapter(zlib.MAX_WBITS)
    if codec is Codec.XZ:
        return lzma.LZMADecompressor(format=lzma.FORMAT_XZ)
    if codec is Codec.LZMA:
        return lzma.LZMADecompressor(format=lzma.FORMAT_ALONE, memlimit=256 * 1024 * 1024)
    return bz2.BZ2Decompressor()


def _needs_input(dec: _Decoder | _ZlibAdapter) -> bool:
    flag = getattr(dec, "needs_input", True)
    return bool(flag)


def decompress(
    codec: Codec,
    data: bytes | memoryview,
    budget: Budget,
    *,
    what: str = "stream",
    allow_truncated: bool = True,
) -> Decompressed:
    """Decompress one stream that starts at ``data[0]``.

    Raises :class:`FormatError` if the bytes are not a valid stream,
    :class:`TruncatedError` if the stream ends early and ``allow_truncated`` is false,
    and :class:`LimitExceededError` if the output exceeds the per-stream cap, the
    remaining global budget or the maximum expansion ratio.
    """
    view = memoryview(data)
    dec = _make_decoder(codec)
    cap = min(budget.limits.max_stream_bytes, budget.remaining_bytes())
    out = bytearray()
    fed = 0
    try:
        while not dec.eof:
            if _needs_input(dec):
                if fed >= len(view):
                    break
                chunk = bytes(view[fed : fed + CHUNK])
                fed += len(chunk)
            else:
                chunk = b""
            # Never ask for more than the ratio limit allows for the input fed so far (+1
            # byte so that crossing it is observable). This keeps peak memory at
            # O(max_ratio * input) instead of O(cap) when a bomb hides in one chunk.
            allowance = min(cap, budget.ratio_allowance(fed))
            piece = dec.decompress(chunk, allowance + 1 - len(out))
            out += piece
            if len(out) > cap:
                limit = (
                    "max_stream_bytes"
                    if cap == budget.limits.max_stream_bytes
                    else "max_total_bytes"
                )
                raise LimitExceededError(limit, f"{what}: decompressed output exceeds {cap} bytes")
            budget.check_ratio(len(out), fed, what)
            if not piece and not chunk and not _needs_input(dec):
                break
    except (zlib.error, lzma.LZMAError, OSError, EOFError, ValueError) as exc:
        if not out:
            raise FormatError(f"{what}: not a valid {codec} stream ({exc})") from exc
        if not allow_truncated:
            raise TruncatedError(f"{what}: {codec} stream corrupt after {len(out)} bytes") from exc
        return Decompressed(bytes(out), fed, complete=False)
    if not dec.eof:
        if not out:
            raise FormatError(f"{what}: no output from {codec} stream")
        if not allow_truncated:
            raise TruncatedError(f"{what}: {codec} stream is truncated")
        return Decompressed(bytes(out), fed, complete=False)
    consumed = fed - len(dec.unused_data)
    return Decompressed(bytes(out), consumed, complete=True)


def lzma_header_plausible(header: bytes) -> bool:
    """Heuristic check for a legacy ``.lzma`` (LZMA-alone) 13-byte header.

    The properties byte must encode lc/lp/pb within range, the dictionary size must be a
    power of two (or 2^n + 2^(n-1)) between 4 KiB and 256 MiB, and the declared
    uncompressed size must be unknown (all 0xFF) or below 4 GiB.
    """
    if len(header) < 13:
        return False
    props = header[0]
    if props >= 9 * 5 * 5:
        return False
    dict_size = int.from_bytes(header[1:5], "little")
    if not 4096 <= dict_size <= 256 * 1024 * 1024:
        return False
    if dict_size & (dict_size - 1):
        top = 1 << (dict_size.bit_length() - 1)
        if dict_size != top + (top >> 1):
            return False
    size = int.from_bytes(header[5:13], "little")
    return size == 0xFFFFFFFFFFFFFFFF or size < (1 << 32)

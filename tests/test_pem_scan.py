"""PEM block scanning: equivalence with the reference pattern and linear-time behaviour."""

from __future__ import annotations

import gzip
import re
import time

from hypothesis import given, settings
from hypothesis import strategies as st

from fwaudit.audit.base import AuditConfig
from fwaudit.audit.keys import KeyAnalyzer, iter_pem_blocks
from fwaudit.pipeline import audit_bytes
from fwaudit.synth import pki

# Generous wall-clock bound for a shared CI machine. The backtracking pattern this replaces
# took ~34 s on the 1 MiB floods below and ~16 s on the gzip image; the scanner takes well
# under a second.
FLOOD_SECONDS = 5.0


def reference(data: bytes, max_body: int) -> list[tuple[int, bytes, bytes, bytes]]:
    """The original backtracking pattern, used only as an oracle on small inputs."""
    pattern = re.compile(
        rb"-----BEGIN (?P<label>[A-Z0-9 ]{3,40})-----(?P<body>.{1,%d}?)-----END (?P=label)-----"
        % max_body,
        re.DOTALL,
    )
    return [
        (m.start(), m.group("label"), m.group(0), m.group("body")) for m in pattern.finditer(data)
    ]


def scan(data: bytes, max_body: int) -> list[tuple[int, bytes, bytes, bytes]]:
    return [(b.start, b.label, b.block, b.body) for b in iter_pem_blocks(data, max_body)]


TOKENS = st.sampled_from(
    [
        b"-----BEGIN ABC-----",
        b"-----BEGIN XYZ-----",
        b"-----BEGIN AB-----",
        b"-----END ABC-----",
        b"-----END XYZ-----",
        b"-----END AB-----",
        b"-----BEGIN ",
        b"-----END ",
        b"ABC",
        b"-----",
        b"-",
        b"x",
        b"\n",
        b"MIIB",
    ]
)


@settings(max_examples=400, deadline=None)
@given(st.lists(TOKENS, max_size=40), st.integers(min_value=1, max_value=40))
def test_scanner_matches_reference_pattern(parts: list[bytes], max_body: int) -> None:
    data = b"".join(parts)
    assert scan(data, max_body) == reference(data, max_body)


def test_overlapping_markers_match_reference() -> None:
    cases = [
        b"-----BEGIN ABC-----BEGIN XYZ-----x-----END XYZ-----",
        b"-----BEGIN ABC-----x-----END XYZ-----END ABC-----",
        b"------BEGIN ABC-----x-----END ABC------",
        b"-----BEGIN ABC----------END ABC-----",  # empty body: no block
        b"-----BEGIN ABC-----y-----END ABC-----BEGIN ABC-----z-----END ABC-----",
    ]
    for data in cases:
        assert scan(data, 65536) == reference(data, 65536), data


def test_body_limit_is_inclusive() -> None:
    at_limit = b"-----BEGIN ABC-----" + b"A" * 65536 + b"-----END ABC-----"
    over = b"-----BEGIN ABC-----" + b"A" * 65537 + b"-----END ABC-----"
    assert len(list(iter_pem_blocks(at_limit))) == 1
    assert list(iter_pem_blocks(over)) == []


def test_real_key_after_flood_is_still_found(config: AuditConfig) -> None:
    pem = pki.private_pem(pki.ec_key(5))
    data = b"-----BEGIN AAA-----" * 1000 + pem
    out = KeyAnalyzer(config).analyze(data, filesystem="image", path=None, base_offset=0)
    assert [f.rule_id for f in out] == ["FWA-KEY-001"]
    assert out[0].offset == 19 * 1000


def _timed_analyze(config: AuditConfig, data: bytes) -> float:
    started = time.perf_counter()
    KeyAnalyzer(config).analyze(data, filesystem="image", path=None, base_offset=0)
    return time.perf_counter() - started


def test_unmatched_begin_flood_is_linear(config: AuditConfig) -> None:
    flood = b"-----BEGIN AAA-----" * ((1 << 20) // 19 + 1)
    assert len(flood) >= 1 << 20
    assert _timed_analyze(config, flood) < FLOOD_SECONDS


def test_distinct_label_and_mismatched_end_floods_are_linear(config: AuditConfig) -> None:
    labels = [f"L{i:05d}".encode() for i in range(40_000)]
    distinct = b"".join(b"-----BEGIN " + lab + b"-----" for lab in labels)
    mismatched = b"".join(
        b"-----BEGIN " + lab + b"-----x-----END Z" + lab + b"-----" for lab in labels
    )
    ends_then_begins = b"-----END AAA-----" * 30_000 + b"-----BEGIN AAA-----" * 30_000
    for data in (distinct, mismatched, ends_then_begins):
        assert len(data) > 500_000
        assert _timed_analyze(config, data) < FLOOD_SECONDS


def test_compressed_flood_image_does_not_stall_pipeline() -> None:
    # The review reproduction: ~10 KB image, gzip of 512 KiB of unmatched BEGIN headers
    # between padding, scanned as a raw region (took ~16 s with the backtracking pattern).
    payload = b"-----BEGIN AAA-----" * ((512 * 1024) // 19)
    image = b"\x00" * 4096 + gzip.compress(payload, mtime=0) + b"\x00" * 4096
    assert len(image) < 16 * 1024
    started = time.perf_counter()
    result = audit_bytes(image, "pem-flood")
    assert time.perf_counter() - started < FLOOD_SECONDS
    assert result.check_errors == []

"""Property tests: arbitrary or mutated input must never crash the auditor."""

from __future__ import annotations

from hypothesis import HealthCheck, given, settings
from hypothesis import strategies as st

from fwaudit.limits import Limits, MiB
from fwaudit.pipeline import AuditOptions, audit_bytes
from fwaudit.synth.firmware import generate

SMALL = AuditOptions(limits=Limits(max_total_bytes=64 * MiB, max_stream_bytes=16 * MiB))
SEED_IMAGES = [generate(s).image for s in range(5)]


@settings(max_examples=150, deadline=None)
@given(st.binary(max_size=4096))
def test_random_bytes_never_crash(data: bytes) -> None:
    result = audit_bytes(data, "fuzz", SMALL)
    assert result.image.size == len(data)


@settings(max_examples=60, deadline=None, suppress_health_check=[HealthCheck.data_too_large])
@given(st.integers(min_value=0, max_value=4), st.data())
def test_mutated_firmware_never_crashes(which: int, data: st.DataObject) -> None:
    image = bytearray(SEED_IMAGES[which])
    for _ in range(data.draw(st.integers(min_value=1, max_value=16))):
        pos = data.draw(st.integers(min_value=0, max_value=len(image) - 1))
        image[pos] = data.draw(st.integers(min_value=0, max_value=255))
    cut = data.draw(st.integers(min_value=1, max_value=len(image)))
    result = audit_bytes(bytes(image[:cut]), "mutant", SMALL)
    assert result.check_errors == []
    assert result.budget_bytes <= SMALL.limits.max_total_bytes

"""The bundled example images must be exactly what the in-repo generator produces."""

from __future__ import annotations

import gzip
import json
from pathlib import Path

import pytest

from fwaudit.synth import hostile
from fwaudit.synth.firmware import GZIP_HEADER, Sample, generate, gzip_member

EXAMPLES = Path(__file__).resolve().parent.parent / "examples" / "firmware"
SAMPLES = [generate(23, "dev"), *hostile.all_samples()]


@pytest.mark.parametrize("sample", SAMPLES, ids=lambda s: s.name)
def test_bundled_fixture_matches_generator(sample: Sample) -> None:
    assert (EXAMPLES / f"{sample.name}.bin").read_bytes() == sample.image
    truth = json.loads((EXAMPLES / f"{sample.name}.truth.json").read_text())
    assert truth == json.loads(json.dumps(sample.manifest()))


def test_no_unexpected_fixtures() -> None:
    names = {p.name for p in EXAMPLES.iterdir()}
    assert names == {f"{s.name}{ext}" for s in SAMPLES for ext in (".bin", ".truth.json")}


def test_gzip_member_is_platform_independent() -> None:
    # zlib stamps its build OS into gzip.compress() output (19 on macOS, 3 on Linux), which
    # made the bundled fixtures differ between CI runners. gzip_member fixes the header and
    # must otherwise be the exact stream the stdlib produces at level 9.
    data = b"kernel " * 2000
    member = gzip_member(data)
    assert member[:10] == GZIP_HEADER
    assert member[9] == 3  # OS = Unix
    assert gzip.decompress(member) == data
    assert member[10:] == gzip.compress(data, compresslevel=9, mtime=0)[10:]
    assert gzip_member(b"") == GZIP_HEADER + b"\x03\x00" + bytes(8)

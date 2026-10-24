"""The bundled example images must be exactly what the in-repo generator produces."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from fwaudit.synth import hostile
from fwaudit.synth.firmware import Sample, generate

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

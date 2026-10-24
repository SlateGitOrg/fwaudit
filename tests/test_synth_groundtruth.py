"""Ground-truth tests: the auditor must report exactly the planted findings."""

from __future__ import annotations

import pytest

from fwaudit.evaluation import Score
from fwaudit.pipeline import AuditOptions, audit_bytes
from fwaudit.synth import hostile
from fwaudit.synth.firmware import LAYOUTS, generate

DEV_SEEDS = range(20)


@pytest.mark.parametrize("seed", DEV_SEEDS)
def test_dev_sample_exact_match(seed: int, options: AuditOptions) -> None:
    sample = generate(seed, "dev")
    result = audit_bytes(sample.image, sample.name, options)
    score = Score()
    score.add(sample.name, result.findings, sample.expected)
    assert score.false_negatives == []
    assert score.false_positives == []
    assert result.check_errors == []


@pytest.mark.parametrize("sample", hostile.all_samples(), ids=lambda s: s.name)
def test_hostile_samples(sample: hostile.Sample, options: AuditOptions) -> None:
    result = audit_bytes(sample.image, sample.name, options)
    score = Score()
    score.add(sample.name, result.findings, sample.expected)
    assert score.false_negatives == []
    assert score.false_positives == []
    assert result.budget_bytes <= options.limits.max_total_bytes


def test_generator_is_deterministic_and_covers_layouts() -> None:
    a, b = generate(3), generate(3)
    assert a.image == b.image
    assert a.expected == b.expected
    assert {generate(s).layout for s in range(len(LAYOUTS))} == set(LAYOUTS)
    assert generate(3, "holdout").image != a.image
    with pytest.raises(ValueError):
        generate(1, "test")


def test_manifest_shape() -> None:
    m = generate(1).manifest()
    assert m["split"] == "dev"
    assert isinstance(m["expected"], list)
    assert all("rule_id" in e for e in m["expected"])  # type: ignore[union-attr]


def test_score_counts_cve_mismatch(options: AuditOptions) -> None:
    sample = next(s for s in (generate(i) for i in range(30))
                  if any(e.rule_id == "FWA-CMP-002" for e in s.expected))  # fmt: skip
    result = audit_bytes(sample.image, sample.name, options)
    tampered = [
        e if e.rule_id != "FWA-CMP-002" else type(e)(e.rule_id, e.path, e.where, e.note, ("CVE-0",))
        for e in sample.expected
    ]
    score = Score()
    score.add(sample.name, result.findings, tampered)
    assert score.per_rule["FWA-CMP-002"].fp >= 1
    assert score.per_rule["FWA-CMP-002"].fn >= 1
    assert score.totals.precision < 1.0
    assert score.totals.recall < 1.0

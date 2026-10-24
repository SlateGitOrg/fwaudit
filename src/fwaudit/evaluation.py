"""Scoring reported findings against synthetic ground truth.

A finding matches an expected entry when the rule id, the in-filesystem path and the
location class (``image`` / ``extracted`` / ``nested``) agree. For component CVE
findings the reported CVE identifiers must also equal the hand-derived expected set; a
mismatch counts as one false positive and one false negative. Matching is a multiset
match, so two expected findings with the same key need two reported findings.
"""

from __future__ import annotations

from collections import Counter, defaultdict
from dataclasses import dataclass, field

from fwaudit.model import Finding
from fwaudit.synth.firmware import Expected

MatchKey = tuple[str, str | None, str, tuple[str, ...]]


def location_class(finding: Finding, root_id: str = "image") -> str:
    if finding.filesystem == root_id:
        return "image"
    if ":/" in finding.filesystem:
        return "nested"
    return "extracted"


def finding_key(finding: Finding) -> MatchKey:
    cves: tuple[str, ...] = ()
    if finding.rule_id == "FWA-CMP-002":
        raw = finding.evidence.get("cves", [])
        if isinstance(raw, list):
            cves = tuple(sorted(str(c.get("id")) for c in raw if isinstance(c, dict)))
    return (finding.rule_id, finding.path, location_class(finding), cves)


def expected_key(e: Expected) -> MatchKey:
    return (e.rule_id, e.path, e.where, tuple(sorted(e.cves)))


@dataclass
class RuleScore:
    tp: int = 0
    fp: int = 0
    fn: int = 0

    @property
    def precision(self) -> float:
        return self.tp / (self.tp + self.fp) if self.tp + self.fp else 1.0

    @property
    def recall(self) -> float:
        return self.tp / (self.tp + self.fn) if self.tp + self.fn else 1.0


@dataclass
class Score:
    per_rule: dict[str, RuleScore] = field(default_factory=lambda: defaultdict(RuleScore))
    false_positives: list[tuple[str, MatchKey]] = field(default_factory=list)
    false_negatives: list[tuple[str, MatchKey]] = field(default_factory=list)

    def add(self, sample: str, findings: list[Finding], expected: list[Expected]) -> None:
        got = Counter(finding_key(f) for f in findings)
        want = Counter(expected_key(e) for e in expected)
        for key in got.keys() | want.keys():
            matched = min(got[key], want[key])
            rule = self.per_rule[key[0]]
            rule.tp += matched
            if got[key] > matched:
                rule.fp += got[key] - matched
                self.false_positives.extend([(sample, key)] * (got[key] - matched))
            if want[key] > matched:
                rule.fn += want[key] - matched
                self.false_negatives.extend([(sample, key)] * (want[key] - matched))

    @property
    def totals(self) -> RuleScore:
        t = RuleScore()
        for r in self.per_rule.values():
            t.tp += r.tp
            t.fp += r.fp
            t.fn += r.fn
        return t

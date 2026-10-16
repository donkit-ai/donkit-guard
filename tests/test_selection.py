from __future__ import annotations

from typing import TYPE_CHECKING

import pytest

from donkit_guard.detectors.base import empty_findings
from donkit_guard.findings import FindingClass, Findings
from donkit_guard.payload import Segment, SegmentTrust
from donkit_guard.policy import Match, Rule, RuleAction
from donkit_guard.selection import select_detectors

if TYPE_CHECKING:
    from collections.abc import Sequence


class FakeDetector:
    version = "1"
    remote = False
    pattern_set_hash = ""

    def __init__(
        self, name: str, finding_class: FindingClass, subtypes: frozenset[str] | None = None
    ) -> None:
        self.name = name
        self.classes = frozenset({finding_class})
        if subtypes is not None:
            self.subtypes = subtypes

    def detect(self, segments: Sequence[Segment]) -> Findings:
        return empty_findings(self, len(segments))


SECRETS = FakeDetector("secrets", FindingClass.SECRET)
PII = FakeDetector("pii", FindingClass.PII)
INJECTION = FakeDetector("injection", FindingClass.INJECTION)
CONTRACTS = FakeDetector(
    "declared:contracts", FindingClass.CORPORATE, frozenset({"CONTRACT_NUMBER"})
)
PHONES = FakeDetector("declared:phones", FindingClass.PII, frozenset({"PHONE"}))

PII_MASK = Rule(
    id="pii-mask", action=RuleAction.MASK, match=Match(finding_class=(FindingClass.PII,))
)
PII_AUDIT = Rule(
    id="pii-audit", action=RuleAction.AUDIT, match=Match(finding_class=(FindingClass.PII,))
)
PII_ALLOW = Rule(
    id="pii-allow", action=RuleAction.ALLOW, match=Match(finding_class=(FindingClass.PII,))
)
SECRETS_MASK = Rule(
    id="secrets-mask",
    action=RuleAction.MASK,
    match=Match(finding_class=(FindingClass.SECRET,), min_score=0.5),
)
SECRETS_AUDIT = Rule(
    id="secrets-audit", action=RuleAction.AUDIT, match=Match(finding_class=(FindingClass.SECRET,))
)
INJECTION_AUDIT = Rule(
    id="injection-audit",
    action=RuleAction.AUDIT,
    match=Match(finding_class=(FindingClass.INJECTION,)),
)
CONTRACTS_MASK = Rule(
    id="contracts-mask", action=RuleAction.MASK, match=Match(finding_subtype=("CONTRACT_*",))
)
UNTRUSTED_DENY = Rule(
    id="untrusted-deny",
    action=RuleAction.DENY,
    match=Match(min_score=0.9, segment_trust=(SegmentTrust.UNTRUSTED,)),
)


@pytest.mark.parametrize(
    ("rules", "detectors", "sync", "background"),
    [
        pytest.param([PII_MASK], [PII], ["pii"], [], id="mask-rule-waits"),
        pytest.param([PII_AUDIT], [PII], [], ["pii"], id="audit-only-runs-in-background"),
        pytest.param(
            [INJECTION_AUDIT], [INJECTION], [], ["injection"], id="injection-audit-in-background"
        ),
        pytest.param([PII_MASK, PII_AUDIT], [SECRETS], [], [], id="unnamed-class-is-dropped"),
        pytest.param(
            [CONTRACTS_MASK],
            [CONTRACTS, PHONES],
            ["declared:contracts"],
            [],
            id="subtype-glob-checks-declared-subtypes",
        ),
        pytest.param([CONTRACTS_MASK], [PII], ["pii"], [], id="undeclared-subtypes-stay-eligible"),
        pytest.param([PII_ALLOW], [PII], ["pii"], [], id="allow-is-not-audit"),
        pytest.param(
            [UNTRUSTED_DENY],
            [SECRETS, CONTRACTS],
            ["secrets", "declared:contracts"],
            [],
            id="score-and-trust-never-exclude",
        ),
        pytest.param(
            [SECRETS_MASK, SECRETS_AUDIT, PII_AUDIT, INJECTION_AUDIT],
            [INJECTION, CONTRACTS, SECRETS, PII],
            ["secrets"],
            ["injection", "pii"],
            id="input-order-and-one-place-each",
        ),
        pytest.param([PII_AUDIT], [PII, PII], [], ["pii"], id="repeated-detector-selected-once"),
    ],
)
def test_select_detectors(
    rules: list[Rule], detectors: list[FakeDetector], sync: list[str], background: list[str]
) -> None:
    selection = select_detectors(rules, detectors)
    assert [d.name for d in selection.sync] == sync
    assert [d.name for d in selection.background] == background

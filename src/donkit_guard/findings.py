"""Detector output: spans addressed by segment id and JSON pointer, never by matched text."""

from __future__ import annotations

from enum import StrEnum

from pydantic import Field

from donkit_guard.context import FrozenModel


class FindingClass(StrEnum):
    SECRET = "secret"
    PII = "pii"
    CORPORATE = "corporate"
    INJECTION = "injection"


# Classes that describe what a payload contains: a rule may deny, mask or gate on them.
ENFORCEABLE_CLASSES: frozenset[FindingClass] = frozenset(
    {FindingClass.SECRET, FindingClass.PII, FindingClass.CORPORATE}
)
# Everything else describes what the payload is trying to do. Attacker-controlled
# text decides whether such a finding fires, so it is reported and never enforced on.
SIGNAL_CLASSES: frozenset[FindingClass] = frozenset(FindingClass) - ENFORCEABLE_CLASSES


class FindingSpan(FrozenModel):
    segment_id: str
    path: str = ""
    start: int = Field(ge=0)
    end: int = Field(ge=0)
    cls: FindingClass
    subtype: str
    score: float = Field(ge=0.0, le=1.0)
    detector: str


class Findings(FrozenModel):
    detector: str
    version: str
    pattern_set_hash: str = ""
    spans: tuple[FindingSpan, ...] = ()
    failed: bool = False
    error: str | None = None
    segments_scanned: int = 0

    @property
    def detector_id(self) -> str:
        """Registry key: the name and the compatibility major, without the pattern set."""
        return f"{self.detector}@{self.version}"

    @property
    def provenance(self) -> str:
        """Full identity of what produced these spans, down to the pattern set."""
        if not self.pattern_set_hash:
            return self.detector_id
        return f"{self.detector_id}+{self.pattern_set_hash}"

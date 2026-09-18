"""The engine's answer: outcome, explanation, provenance."""

from __future__ import annotations

import uuid
from datetime import datetime
from enum import StrEnum

from pydantic import Field

from donkit_guard.approvals import DeliveryMode
from donkit_guard.context import FrozenModel
from donkit_guard.findings import FindingClass, FindingSpan


class PolicyMode(StrEnum):
    OFF = "off"
    OBSERVE = "observe"
    ENFORCE = "enforce"


class Outcome(StrEnum):
    ALLOW = "allow"
    MASK = "mask"
    REQUIRE_APPROVAL = "require_approval"
    APPROVAL_PENDING = "approval_pending"
    DENY = "deny"


# Strictness lattice used to combine verdicts: the strictest matched verdict wins.
STRICTNESS: dict[Outcome, int] = {
    Outcome.ALLOW: 0,
    Outcome.MASK: 1,
    Outcome.REQUIRE_APPROVAL: 2,
    Outcome.APPROVAL_PENDING: 2,
    Outcome.DENY: 3,
}


class Location(FrozenModel):
    segment_id: str
    path: str = ""
    start: int
    end: int
    cls: FindingClass
    subtype: str

    @classmethod
    def from_span(cls, span: FindingSpan) -> Location:
        """The public, detector-free view of a finding span."""
        return cls(
            segment_id=span.segment_id,
            path=span.path,
            start=span.start,
            end=span.end,
            cls=span.cls,
            subtype=span.subtype,
        )


class Explanation(FrozenModel):
    code: str
    reason: str = ""
    rule_ids: tuple[str, ...] = ()
    finding_classes: tuple[FindingClass, ...] = ()
    locations: tuple[Location, ...] = ()


class ApprovalPending(FrozenModel):
    approval_id: str
    expires_at: datetime
    delivery: DeliveryMode


class Decision(FrozenModel):
    decision_id: str = Field(default_factory=lambda: uuid.uuid4().hex)
    outcome: Outcome
    hard: bool = False
    explanation: Explanation
    detector_versions: dict[str, str] = Field(default_factory=dict)
    policy_version: str
    descriptor_version: str | None = None
    uninspected_parts: tuple[str, ...] = ()
    latency_ms: float = 0.0
    mode: PolicyMode
    would_outcome: Outcome | None = None
    would_block: bool = False
    critical: bool = False
    masked_segments: dict[str, str] = Field(default_factory=dict)
    # Computed once by the engine, which holds the finding spans: a consumer that
    # rebuilt the preview from the arguments alone would print the findings in clear.
    display_args_redacted: dict[str, str] = Field(default_factory=dict)
    approval: ApprovalPending | None = None
    action_digest: str | None = None
    context_hash: str

    def is_allowed(self) -> bool:
        return self.outcome in (Outcome.ALLOW, Outcome.MASK)

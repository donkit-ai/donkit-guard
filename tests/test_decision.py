from __future__ import annotations

from typing import TYPE_CHECKING

import pytest

from donkit_guard.approvals import DeliveryMode
from donkit_guard.decision import (
    ApprovalPending,
    Decision,
    Explanation,
    Location,
    Outcome,
    PolicyMode,
)
from donkit_guard.errors import GuardDeniedError
from donkit_guard.findings import FindingClass, FindingSpan

if TYPE_CHECKING:
    from datetime import datetime


def _decision(outcome: Outcome) -> Decision:
    return Decision(
        outcome=outcome,
        explanation=Explanation(code="test"),
        policy_version="v1",
        mode=PolicyMode.ENFORCE,
        context_hash="c",
    )


def test_location_from_span_keeps_the_pointer_and_drops_the_detector() -> None:
    span = FindingSpan(
        segment_id="seg-1",
        path="/note",
        start=4,
        end=9,
        cls=FindingClass.SECRET,
        subtype="aws-access-token",
        score=1.0,
        detector="secrets",
    )
    location = Location.from_span(span)
    assert location == Location(
        segment_id="seg-1",
        path="/note",
        start=4,
        end=9,
        cls=FindingClass.SECRET,
        subtype="aws-access-token",
    )
    assert "detector" not in location.model_dump()
    assert "score" not in location.model_dump()


@pytest.mark.parametrize(
    ("outcome", "allowed"),
    [
        (Outcome.ALLOW, True),
        (Outcome.MASK, True),
        (Outcome.REQUIRE_APPROVAL, False),
        (Outcome.APPROVAL_PENDING, False),
        (Outcome.DENY, False),
    ],
)
def test_is_allowed_covers_every_outcome(outcome: Outcome, allowed: bool) -> None:
    assert _decision(outcome).is_allowed() is allowed


def test_explanation_carries_finding_classes_as_enum_members() -> None:
    explanation = Explanation(code="masked", finding_classes=(FindingClass.PII,))
    assert explanation.finding_classes == (FindingClass.PII,)
    assert explanation.model_dump(mode="json")["finding_classes"] == ["pii"]


def test_approval_pending_delivery_is_a_delivery_mode(now: datetime) -> None:
    pending = ApprovalPending(approval_id="a", expires_at=now, delivery=DeliveryMode.CONSUMED)
    assert pending.delivery is DeliveryMode.CONSUMED
    assert pending.model_dump(mode="json")["delivery"] == "consumed"
    with pytest.raises(ValueError, match="delivery"):
        ApprovalPending(approval_id="a", expires_at=now, delivery="carrier-pigeon")  # type: ignore[arg-type]


def test_display_args_redacted_defaults_to_empty() -> None:
    assert _decision(Outcome.ALLOW).display_args_redacted == {}


def test_a_host_can_raise_a_deny_decision_as_control_flow() -> None:
    denied = _decision(Outcome.DENY)
    error = GuardDeniedError(denied.explanation.code, denied.explanation.reason, denied.decision_id)
    assert error.code == "test"
    assert error.decision_id == denied.decision_id
    assert str(error).startswith("test: ")

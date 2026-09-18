from __future__ import annotations

from datetime import UTC, datetime
from typing import TYPE_CHECKING

from donkit_guard.audit import DecisionEvent, ExecutionEvent, redact_display_args, summarize_context
from donkit_guard.decision import Decision, Explanation, Outcome, PolicyMode
from donkit_guard.findings import FindingClass, FindingSpan
from donkit_guard.payload import Payload, SegmentSource, SegmentTrust

if TYPE_CHECKING:
    from donkit_guard.context import GuardContext


def test_summarize_context_flattens_dimensions(tool_context: GuardContext) -> None:
    summary = summarize_context(tool_context)
    assert summary.principal_id == "user-1"
    assert summary.tenant_id == "tenant-1"
    assert summary.tool == "delete_file"
    assert summary.action_kind == "tool_call"
    assert summary.destination_model is None


def test_redact_display_args_blacks_out_findings_and_truncates() -> None:
    args = {"token": "sk-live-ABCDEF123456", "note": "x" * 400, "count": 3}
    payload = Payload.from_json(args, source=SegmentSource.TOOL_ARGS, trust=SegmentTrust.TRUSTED)
    token_segment = next(s for s in payload.segments if s.path == "/token")
    span = FindingSpan(
        segment_id=token_segment.id,
        path="/token",
        start=8,
        end=21,
        cls=FindingClass.SECRET,
        subtype="generic",
        score=1.0,
        detector="secrets",
    )
    previews = redact_display_args(args, [span], payload, limit=64)
    assert previews["/token"].startswith("sk-live-")
    assert "ABCDEF123456" not in previews["/token"]
    assert len(previews["/note"]) == 64 and previews["/note"].endswith("…")
    assert previews["/count"] == "3"
    assert redact_display_args(None, [], None) == {}


def test_redact_display_args_caps_the_number_of_previews() -> None:
    args = {"rows": [f"row-{i}" for i in range(250)]}
    previews = redact_display_args(args, [], None, max_entries=100)
    assert len(previews) == 101
    assert previews["truncated"] == "150 more argument fields not shown"
    assert previews["/rows/99"] == "row-99"
    assert "/rows/100" not in previews


def test_redact_display_args_leaves_no_marker_when_everything_fits() -> None:
    args = {"rows": ["a", "b"]}
    assert redact_display_args(args, [], None, max_entries=2) == {"/rows/0": "a", "/rows/1": "b"}


def test_events_serialize(tool_context: GuardContext) -> None:
    decision = Decision(
        outcome=Outcome.DENY,
        explanation=Explanation(code="policy_denied", reason="test"),
        policy_version="v1",
        mode=PolicyMode.ENFORCE,
        context_hash=tool_context.context_hash(),
    )
    event = DecisionEvent(
        decision=decision, context=summarize_context(tool_context), occurred_at=datetime.now(UTC)
    )
    assert event.model_dump(mode="json")["event_type"] == "decision"
    execution = ExecutionEvent(
        decision_id=decision.decision_id,
        outcome="error",
        error_class="TimeoutError",
        duration_ms=12.5,
        occurred_at=datetime.now(UTC),
    )
    assert execution.model_dump(mode="json")["outcome"] == "error"

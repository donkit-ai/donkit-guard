"""Audit events: what was decided and what actually happened, without raw secrets or prompts."""

from __future__ import annotations

from datetime import datetime
from typing import TYPE_CHECKING, Any, Literal

from pydantic import Field

from donkit_guard.context import FrozenModel, GuardContext
from donkit_guard.decision import Decision
from donkit_guard.payload import Payload, iter_json_leaves

if TYPE_CHECKING:
    from collections.abc import Mapping, Sequence

    from donkit_guard.findings import FindingSpan

DISPLAY_ARG_LIMIT = 256
DISPLAY_ARG_ENTRIES = 100
# A key without a leading slash is not a JSON pointer, so it cannot collide with one.
TRUNCATED_KEY = "truncated"


class ContextSummary(FrozenModel):
    principal_id: str | None = None
    principal_kind: str | None = None
    on_behalf_of_id: str | None = None
    tenant_id: str | None = None
    agent_id: str | None = None
    agent_version: str | None = None
    run_id: str
    trace_id: str | None = None
    action_kind: str
    tool: str | None = None
    operation: str | None = None
    resource: str | None = None
    destination_model: str | None = None
    destination_provider: str | None = None


class DecisionEvent(FrozenModel):
    event_type: Literal["decision"] = "decision"
    decision: Decision
    context: ContextSummary
    display_args_redacted: dict[str, str] = Field(default_factory=dict)
    occurred_at: datetime


class ExecutionEvent(FrozenModel):
    event_type: Literal["execution"] = "execution"
    decision_id: str
    outcome: Literal["success", "error", "skipped"]
    error_class: str | None = None
    duration_ms: float = 0.0
    occurred_at: datetime


AuditEvent = DecisionEvent | ExecutionEvent


def summarize_context(ctx: GuardContext) -> ContextSummary:
    destination = ctx.action.destination
    return ContextSummary(
        principal_id=ctx.principal.id if ctx.principal else None,
        principal_kind=ctx.principal.kind.value if ctx.principal else None,
        on_behalf_of_id=ctx.on_behalf_of.id if ctx.on_behalf_of else None,
        tenant_id=ctx.tenant_id(),
        agent_id=ctx.agent.id if ctx.agent else None,
        agent_version=ctx.agent.version if ctx.agent else None,
        run_id=ctx.run.id,
        trace_id=ctx.run.trace_id,
        action_kind=ctx.action.kind.value,
        tool=ctx.action.tool,
        operation=ctx.action.operation,
        resource=ctx.action.resource,
        destination_model=destination.model if destination else None,
        destination_provider=destination.provider if destination else None,
    )


def _mask_ranges(text: str, ranges: Sequence[tuple[int, int]]) -> str:
    if not ranges:
        return text
    out: list[str] = []
    cursor = 0
    for start, end in sorted(ranges):
        start, end = max(start, cursor), max(end, cursor)
        out.append(text[cursor:start])
        out.append("█" * max(1, end - start))
        cursor = end
    out.append(text[cursor:])
    return "".join(out)


def redact_display_args(
    arguments: Mapping[str, Any] | None,
    spans: Sequence[FindingSpan],
    payload: Payload | None = None,
    *,
    limit: int = DISPLAY_ARG_LIMIT,
    max_entries: int = DISPLAY_ARG_ENTRIES,
) -> dict[str, str]:
    """Argument previews for approval cards and audit rows.

    Every finding span located in an argument leaf is blacked out, and every
    value is truncated to ``limit`` characters, so the stored preview can never
    reproduce a secret the detectors found. The number of previews is capped as
    well: a tool called with a large array would otherwise write one entry per
    element into every audit row and approval record.
    """
    if not arguments:
        return {}
    by_path: dict[str, list[tuple[int, int]]] = {}
    if payload is not None:
        segments = payload.by_id()
        for span in spans:
            segment = segments.get(span.segment_id)
            if segment is not None and segment.path:
                by_path.setdefault(segment.path, []).append((span.start, span.end))
    previews: dict[str, str] = {}
    leaves = iter_json_leaves(dict(arguments))
    for pointer, leaf in leaves:
        if len(previews) >= max_entries:
            remaining = 1 + sum(1 for _ in leaves)
            previews[TRUNCATED_KEY] = f"{remaining} more argument fields not shown"
            break
        text = leaf if isinstance(leaf, str) else str(leaf)
        text = _mask_ranges(text, by_path.get(pointer, []))
        if len(text) > limit:
            text = text[: limit - 1] + "…"
        previews[pointer] = text
    return previews

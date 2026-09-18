"""The contract a host implements to embed the guard."""

from __future__ import annotations

from collections.abc import Callable
from datetime import UTC, datetime
from typing import TYPE_CHECKING, Literal, Protocol, runtime_checkable

from pydantic import Field

from donkit_guard.context import FrozenModel, GuardContext

if TYPE_CHECKING:
    from donkit_guard.approvals import ApprovalDecisionValue, ApprovalRecord, Delivered
    from donkit_guard.audit import AuditEvent
    from donkit_guard.policy import PolicyBundle

Clock = Callable[[], datetime]


def utc_now() -> datetime:
    return datetime.now(UTC)


class AnalyzeSegment(FrozenModel):
    id: str
    text: str
    lang: Literal["ru", "en"] = "en"


# The analyze service rejects longer deadlines; callers clamp to this bound.
MAX_DEADLINE_MS = 60_000


class AnalyzeRequest(FrozenModel):
    segments: tuple[AnalyzeSegment, ...] = ()
    deadline_ms: int = Field(default=2000, ge=1, le=MAX_DEADLINE_MS)


class AnalyzeSpan(FrozenModel):
    segment_id: str
    start: int
    end: int
    entity_type: str
    score: float


class AnalyzeResponse(FrozenModel):
    detector: str = "pii-ner"
    version: str = "1"
    spans: tuple[AnalyzeSpan, ...] = ()
    failed: bool = False
    error: str | None = None


@runtime_checkable
class PolicySource(Protocol):
    async def resolve(self, ctx: GuardContext) -> PolicyBundle: ...


@runtime_checkable
class DetectorClient(Protocol):
    async def analyze(self, request: AnalyzeRequest, deadline_s: float) -> AnalyzeResponse: ...


@runtime_checkable
class AuditSink(Protocol):
    async def record(self, event: AuditEvent) -> None: ...


@runtime_checkable
class ApprovalStore(Protocol):
    async def create(self, record: ApprovalRecord) -> ApprovalRecord: ...

    async def get(self, approval_id: str) -> ApprovalRecord | None: ...

    async def find_decided(
        self, tenant_id: str | None, action_digest: str, context_hash: str
    ) -> ApprovalRecord | None: ...

    async def decide(
        self,
        approval_id: str,
        decision: ApprovalDecisionValue,
        decided_by: str,
        now: datetime,
    ) -> ApprovalRecord | None: ...

    async def consume(self, approval_id: str, now: datetime) -> ApprovalRecord | None: ...

    async def mark_stale(self, approval_id: str) -> None: ...

    async def expire_pending(self, now: datetime) -> int: ...


@runtime_checkable
class ApprovalChannel(Protocol):
    async def deliver(self, record: ApprovalRecord, ctx: GuardContext) -> Delivered: ...

    async def await_decision(
        self, approval_id: str, deadline_s: float
    ) -> ApprovalRecord | None: ...

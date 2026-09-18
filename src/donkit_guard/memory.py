"""In-memory adapters for tests and the quick start; a host replaces them with durable ones."""

from __future__ import annotations

import asyncio
from typing import TYPE_CHECKING

from donkit_guard.adapters import (
    AnalyzeRequest,
    AnalyzeResponse,
    AnalyzeSpan,
    Clock,
    utc_now,
)
from donkit_guard.approvals import (
    ApprovalDecisionValue,
    ApprovalRecord,
    ApprovalStatus,
    Delivered,
    DeliveryMode,
)
from donkit_guard.audit import AuditEvent, DecisionEvent
from donkit_guard.errors import AuditWriteError

if TYPE_CHECKING:
    from collections.abc import Callable, Mapping, Sequence
    from datetime import datetime

    from donkit_guard.context import GuardContext
    from donkit_guard.policy import PolicyBundle


class InMemoryPolicySource:
    def __init__(self, bundle: PolicyBundle) -> None:
        self.bundle = bundle

    async def resolve(self, ctx: GuardContext) -> PolicyBundle:
        return self.bundle


class InMemoryAuditSink:
    def __init__(self, fail_on_critical: bool = False) -> None:
        self.events: list[AuditEvent] = []
        self.fail_on_critical = fail_on_critical

    async def record(self, event: AuditEvent) -> None:
        if self.fail_on_critical and isinstance(event, DecisionEvent) and event.decision.critical:
            raise AuditWriteError("audit sink unavailable")
        self.events.append(event)


class InMemoryApprovalStore:
    def __init__(self, clock: Clock = utc_now) -> None:
        self._clock = clock
        self._records: dict[str, ApprovalRecord] = {}
        self._lock = asyncio.Lock()

    async def create(self, record: ApprovalRecord) -> ApprovalRecord:
        async with self._lock:
            self._records[record.id] = record
            return record

    async def get(self, approval_id: str) -> ApprovalRecord | None:
        return self._records.get(approval_id)

    async def find_decided(
        self, tenant_id: str | None, action_digest: str, context_hash: str
    ) -> ApprovalRecord | None:
        candidates = [
            r
            for r in self._records.values()
            if r.tenant_id == tenant_id
            and r.action_digest == action_digest
            and r.context_hash == context_hash
            and r.status in (ApprovalStatus.APPROVED, ApprovalStatus.DENIED)
        ]
        if not candidates:
            return None
        return max(candidates, key=lambda r: r.decided_at or r.created_at)

    async def decide(
        self,
        approval_id: str,
        decision: ApprovalDecisionValue,
        decided_by: str,
        now: datetime,
    ) -> ApprovalRecord | None:
        async with self._lock:
            record = self._records.get(approval_id)
            if record is None or record.status is not ApprovalStatus.PENDING:
                return None
            if record.principal_id != decided_by:
                return None
            if record.is_expired(now):
                self._records[approval_id] = record.model_copy(
                    update={"status": ApprovalStatus.EXPIRED}
                )
                return None
            status = (
                ApprovalStatus.APPROVED
                if decision is ApprovalDecisionValue.APPROVE
                else ApprovalStatus.DENIED
            )
            updated = record.model_copy(
                update={"status": status, "decided_by": decided_by, "decided_at": now}
            )
            self._records[approval_id] = updated
            return updated

    async def consume(self, approval_id: str, now: datetime) -> ApprovalRecord | None:
        async with self._lock:
            record = self._records.get(approval_id)
            if (
                record is None
                or record.status is not ApprovalStatus.APPROVED
                or record.is_expired(now)
            ):
                return None
            updated = record.model_copy(
                update={"status": ApprovalStatus.CONSUMED, "consumed_at": now}
            )
            self._records[approval_id] = updated
            return updated

    async def expire_pending(self, now: datetime) -> int:
        async with self._lock:
            expired = 0
            for approval_id, record in list(self._records.items()):
                if record.status is ApprovalStatus.PENDING and record.is_expired(now):
                    self._records[approval_id] = record.model_copy(
                        update={"status": ApprovalStatus.EXPIRED}
                    )
                    expired += 1
            return expired

    async def mark_stale(self, approval_id: str) -> None:
        async with self._lock:
            record = self._records.get(approval_id)
            if record is not None:
                self._records[approval_id] = record.model_copy(
                    update={"status": ApprovalStatus.STALE}
                )


class InlineApprovalChannel:
    """Decides immediately through a callback, standing in for a chat widget."""

    def __init__(
        self,
        decider: Callable[[ApprovalRecord], ApprovalDecisionValue | None],
        store: InMemoryApprovalStore,
        clock: Clock = utc_now,
    ) -> None:
        self._decider = decider
        self._store = store
        self._clock = clock
        self.delivered: list[str] = []

    async def deliver(self, record: ApprovalRecord, ctx: GuardContext) -> Delivered:
        self.delivered.append(record.id)
        return Delivered(mode=DeliveryMode.INLINE, approval_id=record.id)

    async def await_decision(self, approval_id: str, deadline_s: float) -> ApprovalRecord | None:
        record = await self._store.get(approval_id)
        if record is None:
            return None
        value = self._decider(record)
        if value is None:
            return await self._store.get(approval_id)
        return await self._store.decide(approval_id, value, record.principal_id, self._clock())


class UnavailableApprovalChannel:
    async def deliver(self, record: ApprovalRecord, ctx: GuardContext) -> Delivered:
        return Delivered(mode=DeliveryMode.UNAVAILABLE, approval_id=record.id)

    async def await_decision(self, approval_id: str, deadline_s: float) -> ApprovalRecord | None:
        return None


class QueuedApprovalChannel:
    async def deliver(self, record: ApprovalRecord, ctx: GuardContext) -> Delivered:
        return Delivered(mode=DeliveryMode.QUEUED, approval_id=record.id)

    async def await_decision(self, approval_id: str, deadline_s: float) -> ApprovalRecord | None:
        return None


class StaticDetectorClient:
    def __init__(self, spans_by_segment: Mapping[str, Sequence[AnalyzeSpan]]) -> None:
        self._spans = {k: tuple(v) for k, v in spans_by_segment.items()}
        self.requests: list[AnalyzeRequest] = []

    async def analyze(self, request: AnalyzeRequest, deadline_s: float) -> AnalyzeResponse:
        self.requests.append(request)
        spans = tuple(
            span for segment in request.segments for span in self._spans.get(segment.id, ())
        )
        return AnalyzeResponse(spans=spans)


class FailingDetectorClient:
    def __init__(self, error: str = "unavailable") -> None:
        self._error = error

    async def analyze(self, request: AnalyzeRequest, deadline_s: float) -> AnalyzeResponse:
        return AnalyzeResponse(failed=True, error=self._error)

"""The guard's adapters over the database: the audit sink, the approval store and the logs read back.

Every state change of an approval is a compare-and-set ``UPDATE`` whose ``WHERE`` names the
state it leaves, so two replicas racing on one approval cannot both decide or consume it.
"""

from __future__ import annotations

from datetime import datetime
from typing import TYPE_CHECKING, Any

from pydantic import Field
from sqlalchemy import CursorResult, and_, select, update

from donkit_guard.approvals import ApprovalDecisionValue, ApprovalRecord, ApprovalStatus
from donkit_guard.audit import AuditEvent, DecisionEvent, ExecutionEvent, FindingsEvent
from donkit_guard.context import FrozenModel
from donkit_guard_standalone.db import ApprovalRow, DecisionRow, PolicyVersionRow

if TYPE_CHECKING:
    from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker
    from sqlalchemy.sql import Select

    from donkit_guard_standalone.policy_source import LoadedPolicy


class DecisionNotFound(LookupError):
    """No decision with this id is recorded."""


def _rowcount(result: Any) -> int:
    return result.rowcount if isinstance(result, CursorResult) else 0


class SqlAuditSink:
    """Writes each decision as a row; its execution and late findings land on the same row."""

    def __init__(self, sessions: async_sessionmaker[AsyncSession]) -> None:
        self._sessions = sessions

    async def record(self, event: AuditEvent) -> None:
        async with self._sessions.begin() as session:
            match event:
                case DecisionEvent():
                    await self._record_decision(session, event)
                case ExecutionEvent():
                    await self._attach(session, event.decision_id, execution=event)
                case FindingsEvent():
                    await self._attach(session, event.decision_id, findings=event)
                case _:
                    raise ValueError(f"unknown audit event {type(event).__name__}")

    async def _record_decision(self, session: AsyncSession, event: DecisionEvent) -> None:
        decision, summary = event.decision, event.context
        values: dict[str, Any] = {
            "occurred_at": event.occurred_at,
            "tenant_id": summary.tenant_id,
            "run_id": summary.run_id,
            "agent_id": summary.agent_id,
            "principal_id": summary.principal_id,
            "action_kind": summary.action_kind,
            "tool": summary.tool,
            "outcome": decision.outcome.value,
            "code": decision.explanation.code,
            "mode": decision.mode.value,
            "policy_version": decision.policy_version,
            "event": event.model_dump(mode="json"),
        }
        # An approval turns a pending decision into the outcome the host acts on, under the
        # same decision id: the row then shows that outcome.
        existing = await session.scalar(
            select(DecisionRow).where(DecisionRow.decision_id == decision.decision_id)
        )
        if existing is None:
            session.add(DecisionRow(decision_id=decision.decision_id, **values))
            return
        for key, value in values.items():
            setattr(existing, key, value)

    async def _attach(
        self,
        session: AsyncSession,
        decision_id: str,
        *,
        execution: ExecutionEvent | None = None,
        findings: FindingsEvent | None = None,
    ) -> None:
        values: dict[str, Any] = {}
        if execution is not None:
            values["execution"] = execution.model_dump(mode="json")
        if findings is not None:
            values["findings"] = findings.model_dump(mode="json")
        result = await session.execute(
            update(DecisionRow).where(DecisionRow.decision_id == decision_id).values(**values)
        )
        if _rowcount(result) == 0:
            raise DecisionNotFound(decision_id)


def _record(row: ApprovalRow) -> ApprovalRecord:
    return ApprovalRecord(
        id=row.id,
        tenant_id=row.tenant_id,
        principal_id=row.principal_id,
        context_hash=row.context_hash,
        action_digest=row.action_digest,
        tool=row.tool,
        resource=row.resource,
        display_args_redacted=dict(row.display_args_redacted),
        expected_change=row.expected_change,
        reason=row.reason,
        policy_version=row.policy_version,
        status=ApprovalStatus(row.status),
        created_at=row.created_at,
        expires_at=row.expires_at,
        decided_by=row.decided_by,
        decided_at=row.decided_at,
        consumed_at=row.consumed_at,
    )


def _same_tenant(tenant_id: str | None) -> Any:
    column = ApprovalRow.tenant_id
    return column.is_(None) if tenant_id is None else column == tenant_id


class SqlApprovalStore:
    def __init__(self, sessions: async_sessionmaker[AsyncSession]) -> None:
        self._sessions = sessions

    async def create(self, record: ApprovalRecord) -> ApprovalRecord:
        async with self._sessions.begin() as session:
            session.add(
                ApprovalRow(
                    **record.model_dump(exclude={"status"}),
                    status=record.status.value,
                )
            )
        return record

    async def get(self, approval_id: str) -> ApprovalRecord | None:
        async with self._sessions() as session:
            row = await session.get(ApprovalRow, approval_id)
            return _record(row) if row is not None else None

    async def find_decided(
        self, tenant_id: str | None, action_digest: str, context_hash: str
    ) -> ApprovalRecord | None:
        query = (
            select(ApprovalRow)
            .where(
                _same_tenant(tenant_id),
                ApprovalRow.action_digest == action_digest,
                ApprovalRow.context_hash == context_hash,
                ApprovalRow.status.in_((ApprovalStatus.APPROVED, ApprovalStatus.DENIED)),
            )
            .order_by(ApprovalRow.decided_at.desc())
            .limit(1)
        )
        async with self._sessions() as session:
            row = await session.scalar(query)
            return _record(row) if row is not None else None

    async def decide(
        self,
        approval_id: str,
        decision: ApprovalDecisionValue,
        decided_by: str,
        now: datetime,
    ) -> ApprovalRecord | None:
        status = (
            ApprovalStatus.APPROVED
            if decision is ApprovalDecisionValue.APPROVE
            else ApprovalStatus.DENIED
        )
        decided = await self._transition(
            approval_id,
            where=and_(
                ApprovalRow.status == ApprovalStatus.PENDING,
                ApprovalRow.principal_id == decided_by,
                ApprovalRow.expires_at > now,
            ),
            values={"status": status, "decided_by": decided_by, "decided_at": now},
        )
        if decided is None:
            await self._expire(approval_id, now)
        return decided

    async def consume(self, approval_id: str, now: datetime) -> ApprovalRecord | None:
        return await self._transition(
            approval_id,
            where=and_(ApprovalRow.status == ApprovalStatus.APPROVED, ApprovalRow.expires_at > now),
            values={"status": ApprovalStatus.CONSUMED, "consumed_at": now},
        )

    async def mark_stale(self, approval_id: str) -> None:
        async with self._sessions.begin() as session:
            await session.execute(
                update(ApprovalRow)
                .where(ApprovalRow.id == approval_id)
                .values(status=ApprovalStatus.STALE)
            )

    async def expire_pending(self, now: datetime) -> int:
        async with self._sessions.begin() as session:
            result = await session.execute(
                update(ApprovalRow)
                .where(ApprovalRow.status == ApprovalStatus.PENDING, ApprovalRow.expires_at <= now)
                .values(status=ApprovalStatus.EXPIRED)
            )
            return _rowcount(result)

    async def list_records(
        self, *, status: ApprovalStatus | None, tenant_id: str | None, limit: int
    ) -> list[ApprovalRecord]:
        query = select(ApprovalRow).order_by(ApprovalRow.created_at.desc()).limit(limit)
        if status is not None:
            query = query.where(ApprovalRow.status == status)
        if tenant_id is not None:
            query = query.where(ApprovalRow.tenant_id == tenant_id)
        async with self._sessions() as session:
            return [_record(row) for row in await session.scalars(query)]

    async def _transition(
        self, approval_id: str, *, where: Any, values: dict[str, Any]
    ) -> ApprovalRecord | None:
        async with self._sessions.begin() as session:
            result = await session.execute(
                update(ApprovalRow).where(ApprovalRow.id == approval_id, where).values(**values)
            )
            if _rowcount(result) != 1:
                return None
            row = await session.get(ApprovalRow, approval_id, populate_existing=True)
            return _record(row) if row is not None else None

    async def _expire(self, approval_id: str, now: datetime) -> None:
        async with self._sessions.begin() as session:
            await session.execute(
                update(ApprovalRow)
                .where(
                    ApprovalRow.id == approval_id,
                    ApprovalRow.status == ApprovalStatus.PENDING,
                    ApprovalRow.expires_at <= now,
                )
                .values(status=ApprovalStatus.EXPIRED)
            )


class DecisionSummary(FrozenModel):
    decision_id: str
    seq: int
    occurred_at: datetime
    tenant_id: str | None
    run_id: str
    agent_id: str | None
    principal_id: str | None
    action_kind: str
    tool: str | None
    outcome: str
    code: str
    mode: str
    policy_version: str
    event: dict[str, Any]
    execution: dict[str, Any] | None = None
    findings: dict[str, Any] | None = None


class DecisionPage(FrozenModel):
    items: tuple[DecisionSummary, ...] = ()
    # Pass back as `before` for the next, older page; null on the last page.
    next_cursor: int | None = None


class DecisionFilter(FrozenModel):
    tenant_id: str | None = None
    run_id: str | None = None
    agent_id: str | None = None
    before: int | None = Field(default=None, ge=1)
    limit: int = Field(default=50, ge=1, le=500)


class DecisionLog:
    """Reads the audit trail back, newest first, a keyset page at a time."""

    def __init__(self, sessions: async_sessionmaker[AsyncSession]) -> None:
        self._sessions = sessions

    async def page(self, query: DecisionFilter) -> DecisionPage:
        statement = self._select(query)
        async with self._sessions() as session:
            rows = list(await session.scalars(statement))
        more = len(rows) > query.limit
        rows = rows[: query.limit]
        items = tuple(DecisionSummary.model_validate(row, from_attributes=True) for row in rows)
        return DecisionPage(items=items, next_cursor=rows[-1].seq if more and rows else None)

    async def tenant_of(self, decision_id: str) -> str | None:
        """The tenant of a recorded decision; raises ``DecisionNotFound`` when there is none."""
        async with self._sessions() as session:
            row = await session.scalar(
                select(DecisionRow).where(DecisionRow.decision_id == decision_id)
            )
        if row is None:
            raise DecisionNotFound(decision_id)
        return row.tenant_id

    @staticmethod
    def _select(query: DecisionFilter) -> Select[DecisionRow]:
        statement = select(DecisionRow).order_by(DecisionRow.seq.desc()).limit(query.limit + 1)
        if query.tenant_id is not None:
            statement = statement.where(DecisionRow.tenant_id == query.tenant_id)
        if query.run_id is not None:
            statement = statement.where(DecisionRow.run_id == query.run_id)
        if query.agent_id is not None:
            statement = statement.where(DecisionRow.agent_id == query.agent_id)
        if query.before is not None:
            statement = statement.where(DecisionRow.seq < query.before)
        return statement


class PolicyVersionLog:
    def __init__(self, sessions: async_sessionmaker[AsyncSession]) -> None:
        self._sessions = sessions

    async def record(self, loaded: LoadedPolicy) -> None:
        version = loaded.bundle.version
        async with self._sessions.begin() as session:
            exists = await session.scalar(
                select(PolicyVersionRow.seq).where(PolicyVersionRow.version == version)
            )
            if exists is not None:
                return
            session.add(
                PolicyVersionRow(
                    version=version,
                    sha256=loaded.sha256,
                    path=loaded.path,
                    mode=loaded.bundle.mode.value,
                    loaded_at=loaded.loaded_at,
                )
            )

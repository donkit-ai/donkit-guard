from __future__ import annotations

from datetime import datetime, timedelta
from typing import TYPE_CHECKING

import pytest

from donkit_guard.adapters import (
    AnalyzeRequest,
    AnalyzeSegment,
    AnalyzeSpan,
    ApprovalChannel,
    ApprovalStore,
    AuditSink,
    DetectorClient,
    PolicySource,
)
from donkit_guard.approvals import (
    ApprovalDecisionValue,
    ApprovalRecord,
    ApprovalStatus,
    DeliveryMode,
)
from donkit_guard.audit import DecisionEvent, summarize_context
from donkit_guard.decision import Decision, Explanation, Outcome, PolicyMode
from donkit_guard.errors import AuditWriteError
from donkit_guard.memory import (
    FailingDetectorClient,
    InlineApprovalChannel,
    InMemoryApprovalStore,
    InMemoryAuditSink,
    InMemoryPolicySource,
    QueuedApprovalChannel,
    StaticDetectorClient,
    UnavailableApprovalChannel,
)
from donkit_guard.policy import default_bundle

if TYPE_CHECKING:
    from donkit_guard.context import GuardContext


def _record(now: datetime, principal_id: str = "user-1") -> ApprovalRecord:
    return ApprovalRecord(
        tenant_id="tenant-1",
        principal_id=principal_id,
        context_hash="ctx",
        action_digest="digest",
        tool="delete_file",
        policy_version="v1",
        created_at=now,
        expires_at=now + timedelta(seconds=300),
    )


def _decision_event(now: datetime, ctx: GuardContext, *, critical: bool) -> DecisionEvent:
    decision = Decision(
        outcome=Outcome.DENY,
        explanation=Explanation(code="policy_denied"),
        policy_version="v1",
        mode=PolicyMode.ENFORCE,
        critical=critical,
        context_hash=ctx.context_hash(),
    )
    return DecisionEvent(decision=decision, context=summarize_context(ctx), occurred_at=now)


def test_memory_adapters_satisfy_protocols(now: datetime) -> None:
    store = InMemoryApprovalStore(clock=lambda: now)
    assert isinstance(InMemoryPolicySource(default_bundle(PolicyMode.ENFORCE)), PolicySource)
    assert isinstance(InMemoryAuditSink(), AuditSink)
    assert isinstance(store, ApprovalStore)
    assert isinstance(
        InlineApprovalChannel(lambda r: ApprovalDecisionValue.APPROVE, store), ApprovalChannel
    )
    assert isinstance(StaticDetectorClient({}), DetectorClient)


async def test_store_binds_decision_to_principal_and_is_single_use(now: datetime) -> None:
    store = InMemoryApprovalStore(clock=lambda: now)
    record = await store.create(_record(now))
    assert await store.decide(record.id, ApprovalDecisionValue.APPROVE, "intruder", now) is None
    approved = await store.decide(record.id, ApprovalDecisionValue.APPROVE, "user-1", now)
    assert approved is not None and approved.status is ApprovalStatus.APPROVED
    found = await store.find_decided("tenant-1", "digest", "ctx")
    assert found is not None and found.id == record.id
    assert await store.find_decided("tenant-2", "digest", "ctx") is None
    consumed = await store.consume(record.id, now)
    assert consumed is not None and consumed.status is ApprovalStatus.CONSUMED
    assert await store.consume(record.id, now) is None


async def test_store_finds_a_rejected_record_and_can_mark_it_stale(now: datetime) -> None:
    store = InMemoryApprovalStore(clock=lambda: now)
    record = await store.create(_record(now))
    assert await store.decide(record.id, ApprovalDecisionValue.REJECT, "user-1", now) is not None
    found = await store.find_decided("tenant-1", "digest", "ctx")
    assert found is not None and found.status is ApprovalStatus.DENIED
    await store.mark_stale("no-such-approval")
    await store.mark_stale(record.id)
    stale = await store.get(record.id)
    assert stale is not None and stale.status is ApprovalStatus.STALE


async def test_store_respects_expiry(now: datetime) -> None:
    store = InMemoryApprovalStore(clock=lambda: now)
    record = await store.create(_record(now))
    late = now + timedelta(seconds=301)
    assert await store.decide(record.id, ApprovalDecisionValue.APPROVE, "user-1", late) is None
    fetched = await store.get(record.id)
    assert fetched is not None and fetched.status is ApprovalStatus.EXPIRED
    other = await store.create(_record(now))
    assert await store.expire_pending(late) == 1
    approved_then_expired = await store.create(_record(now))
    await store.decide(approved_then_expired.id, ApprovalDecisionValue.APPROVE, "user-1", now)
    assert await store.consume(approved_then_expired.id, late) is None
    assert other.id != approved_then_expired.id


async def test_inline_channel_decides_and_other_channels_report_mode(
    now: datetime, tool_context: GuardContext
) -> None:
    store = InMemoryApprovalStore(clock=lambda: now)
    record = await store.create(_record(now))
    channel = InlineApprovalChannel(
        lambda r: ApprovalDecisionValue.REJECT, store, clock=lambda: now
    )
    delivered = await channel.deliver(record, tool_context)
    assert delivered.mode is DeliveryMode.INLINE
    decided = await channel.await_decision(record.id, 300.0)
    assert decided is not None and decided.status is ApprovalStatus.DENIED
    assert (
        await UnavailableApprovalChannel().deliver(record, tool_context)
    ).mode is DeliveryMode.UNAVAILABLE
    assert (await QueuedApprovalChannel().deliver(record, tool_context)).mode is DeliveryMode.QUEUED
    silent = InlineApprovalChannel(lambda r: None, store, clock=lambda: now)
    pending = await silent.await_decision(record.id, 1.0)
    assert pending is not None and pending.status is ApprovalStatus.DENIED


async def test_detector_clients() -> None:
    span = AnalyzeSpan(segment_id="s1", start=0, end=4, entity_type="PERSON", score=0.9)
    client = StaticDetectorClient({"s1": [span]})
    response = await client.analyze(
        AnalyzeRequest(segments=(AnalyzeSegment(id="s1", text="Ivan"),)), 1.0
    )
    assert response.spans == (span,) and response.failed is False
    failing = await FailingDetectorClient("down").analyze(AnalyzeRequest(), 1.0)
    assert failing.failed and failing.error == "down"


async def test_audit_sink_can_fail_on_critical(now: datetime, tool_context: GuardContext) -> None:
    critical = _decision_event(now, tool_context, critical=True)
    routine = _decision_event(now, tool_context, critical=False)

    sink = InMemoryAuditSink()
    assert sink.events == []
    assert sink.fail_on_critical is False
    await sink.record(critical)
    assert sink.events == [critical]

    failing = InMemoryAuditSink(fail_on_critical=True)
    await failing.record(routine)
    with pytest.raises(AuditWriteError):
        await failing.record(critical)
    assert failing.events == [routine]

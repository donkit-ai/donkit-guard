from __future__ import annotations

from datetime import datetime, timedelta

from donkit_guard.approval_flow import ApprovalFlow
from donkit_guard.approvals import (
    ApprovalDecisionValue,
    ApprovalRecord,
    ApprovalStatus,
    Delivered,
    DeliveryMode,
)
from donkit_guard.context import GuardContext, Principal, PrincipalKind
from donkit_guard.decision import Decision, Explanation, Outcome, PolicyMode
from donkit_guard.memory import (
    InlineApprovalChannel,
    InMemoryApprovalStore,
    QueuedApprovalChannel,
    UnavailableApprovalChannel,
)


def _decision(
    ctx: GuardContext, outcome: Outcome = Outcome.REQUIRE_APPROVAL, version: str = "v1"
) -> Decision:
    return Decision(
        outcome=outcome,
        explanation=Explanation(code="approval_required", reason="side effect"),
        policy_version=version,
        mode=PolicyMode.ENFORCE,
        context_hash=ctx.context_hash(),
        action_digest="digest-1",
    )


class _Clock:
    def __init__(self, start: datetime) -> None:
        self.now = start

    def __call__(self) -> datetime:
        return self.now


class _ConsumedStore(InMemoryApprovalStore):
    """Stands in for an approval another caller consumed between the decision and its use."""

    async def consume(self, approval_id: str, now: datetime) -> ApprovalRecord | None:
        return None


class _ExpiringChannel:
    """Answers with a record that ended in a state which is neither approved nor denied."""

    def __init__(self, store: InMemoryApprovalStore) -> None:
        self._store = store

    async def deliver(self, record: ApprovalRecord, ctx: GuardContext) -> Delivered:
        return Delivered(mode=DeliveryMode.INLINE, approval_id=record.id)

    async def await_decision(self, approval_id: str, deadline_s: float) -> ApprovalRecord | None:
        record = await self._store.get(approval_id)
        assert record is not None
        return record.model_copy(update={"status": ApprovalStatus.EXPIRED})


class _CountingStore(InMemoryApprovalStore):
    """Records every created approval so a test can prove a retry asked again, or did not."""

    def __init__(self, clock: _Clock) -> None:
        super().__init__(clock=clock)
        self.created: list[str] = []

    async def create(self, record: ApprovalRecord) -> ApprovalRecord:
        self.created.append(record.id)
        return await super().create(record)


async def test_inline_approve_consumes_once_and_second_call_needs_new_approval(
    now: datetime, tool_context: GuardContext
) -> None:
    clock = _Clock(now)
    store = InMemoryApprovalStore(clock=clock)
    channel = InlineApprovalChannel(lambda r: ApprovalDecisionValue.APPROVE, store, clock=clock)
    flow = ApprovalFlow(store, channel, clock=clock)
    decision = _decision(tool_context)

    async def reevaluate() -> Decision:
        return decision

    first = await flow.resolve(tool_context, decision, ttl_s=300, reevaluate=reevaluate)
    assert first.outcome is Outcome.ALLOW and first.explanation.code == "approved"
    assert first.approval is not None and first.approval.delivery is DeliveryMode.CONSUMED
    second = await flow.resolve(tool_context, decision, ttl_s=300, reevaluate=reevaluate)
    assert second.outcome is Outcome.ALLOW
    assert len(channel.delivered) == 2


async def test_reject_timeout_unavailable_and_queued(
    now: datetime, tool_context: GuardContext
) -> None:
    clock = _Clock(now)
    decision = _decision(tool_context)

    async def reevaluate() -> Decision:
        return decision

    # Every case gets its own store: a decided record is found again by action
    # digest, so the rejection below would answer the requests after it.
    rejecting_store = InMemoryApprovalStore(clock=clock)
    rejecting = InlineApprovalChannel(
        lambda r: ApprovalDecisionValue.REJECT, rejecting_store, clock=clock
    )
    rejected = await ApprovalFlow(rejecting_store, rejecting, clock=clock).resolve(
        tool_context, decision, ttl_s=300, reevaluate=reevaluate
    )
    assert rejected.outcome is Outcome.DENY and rejected.explanation.code == "approval_rejected"
    timeout_store = InMemoryApprovalStore(clock=clock)
    undecided = InlineApprovalChannel(lambda r: None, timeout_store, clock=clock)
    timed_out = await ApprovalFlow(timeout_store, undecided, clock=clock).resolve(
        tool_context, decision, ttl_s=1, reevaluate=reevaluate
    )
    assert timed_out.outcome is Outcome.DENY and timed_out.explanation.code == "approval_timeout"
    assert timed_out.approval is not None and timed_out.approval.delivery is DeliveryMode.INLINE
    unavailable_store = InMemoryApprovalStore(clock=clock)
    unavailable = await ApprovalFlow(
        unavailable_store, UnavailableApprovalChannel(), clock=clock
    ).resolve(tool_context, decision, ttl_s=300, reevaluate=reevaluate)
    assert unavailable.outcome is Outcome.DENY
    assert unavailable.explanation.code == "approval_unavailable"
    queued_store = InMemoryApprovalStore(clock=clock)
    queued = await ApprovalFlow(queued_store, QueuedApprovalChannel(), clock=clock).resolve(
        tool_context, decision, ttl_s=300, reevaluate=reevaluate
    )
    assert queued.outcome is Outcome.APPROVAL_PENDING
    assert queued.approval is not None and queued.approval.delivery is DeliveryMode.QUEUED


async def test_queued_approval_is_found_and_consumed_on_retry(
    now: datetime, tool_context: GuardContext
) -> None:
    clock = _Clock(now)
    store = InMemoryApprovalStore(clock=clock)
    decision = _decision(tool_context)

    async def reevaluate() -> Decision:
        return decision

    flow = ApprovalFlow(store, QueuedApprovalChannel(), clock=clock)
    pending = await flow.resolve(tool_context, decision, ttl_s=300, reevaluate=reevaluate)
    assert pending.approval is not None
    approved = await store.decide(
        pending.approval.approval_id, ApprovalDecisionValue.APPROVE, "user-1", clock()
    )
    assert approved is not None
    retried = await flow.resolve(tool_context, decision, ttl_s=300, reevaluate=reevaluate)
    assert retried.outcome is Outcome.ALLOW and retried.explanation.code == "approved"
    again = await flow.resolve(tool_context, decision, ttl_s=300, reevaluate=reevaluate)
    assert again.outcome is Outcome.APPROVAL_PENDING


async def test_policy_change_makes_approval_stale(
    now: datetime, tool_context: GuardContext
) -> None:
    clock = _Clock(now)
    store = InMemoryApprovalStore(clock=clock)
    decision = _decision(tool_context)
    changed = _decision(tool_context, outcome=Outcome.ALLOW, version="v2")

    async def reevaluate() -> Decision:
        return changed

    channel = InlineApprovalChannel(lambda r: ApprovalDecisionValue.APPROVE, store, clock=clock)
    flow = ApprovalFlow(store, channel, clock=clock)
    result = await flow.resolve(tool_context, decision, ttl_s=300, reevaluate=reevaluate)
    assert result.outcome is Outcome.DENY and result.explanation.code == "approval_stale"
    stored = await store.get(channel.delivered[-1])
    assert stored is not None and stored.status is ApprovalStatus.STALE


async def test_an_approval_that_cannot_be_consumed_or_ended_elsewhere_is_denied(
    now: datetime, tool_context: GuardContext
) -> None:
    clock = _Clock(now)
    decision = _decision(tool_context)

    async def reevaluate() -> Decision:
        return decision

    consumed_store = _ConsumedStore(clock=clock)
    approving = InlineApprovalChannel(
        lambda r: ApprovalDecisionValue.APPROVE, consumed_store, clock=clock
    )
    used = await ApprovalFlow(consumed_store, approving, clock=clock).resolve(
        tool_context, decision, ttl_s=300, reevaluate=reevaluate
    )
    assert used.outcome is Outcome.DENY and used.explanation.code == "approval_consumed"
    expiring_store = InMemoryApprovalStore(clock=clock)
    expired = await ApprovalFlow(
        expiring_store, _ExpiringChannel(expiring_store), clock=clock
    ).resolve(tool_context, decision, ttl_s=300, reevaluate=reevaluate)
    assert expired.outcome is Outcome.DENY and expired.explanation.code == "approval_timeout"
    assert expired.explanation.reason == "approval ended in state expired"


async def test_a_denied_approval_clears_the_masks(
    now: datetime, tool_context: GuardContext
) -> None:
    clock = _Clock(now)
    store = InMemoryApprovalStore(clock=clock)
    decision = _decision(tool_context).model_copy(update={"masked_segments": {"seg": "masked"}})

    async def reevaluate() -> Decision:
        return decision

    flow = ApprovalFlow(store, UnavailableApprovalChannel(), clock=clock)
    denied = await flow.resolve(tool_context, decision, ttl_s=300, reevaluate=reevaluate)
    assert denied.outcome is Outcome.DENY and denied.explanation.code == "approval_unavailable"
    assert denied.masked_segments == {}


async def test_rejected_queued_approval_is_not_asked_again(
    now: datetime, tool_context: GuardContext
) -> None:
    clock = _Clock(now)
    store = _CountingStore(clock)
    decision = _decision(tool_context)

    async def reevaluate() -> Decision:
        return decision

    flow = ApprovalFlow(store, QueuedApprovalChannel(), clock=clock)
    pending = await flow.resolve(tool_context, decision, ttl_s=300, reevaluate=reevaluate)
    assert pending.outcome is Outcome.APPROVAL_PENDING and pending.approval is not None
    denied = await store.decide(
        pending.approval.approval_id, ApprovalDecisionValue.REJECT, "user-1", clock()
    )
    assert denied is not None and denied.status is ApprovalStatus.DENIED
    retried = await flow.resolve(tool_context, decision, ttl_s=300, reevaluate=reevaluate)
    assert retried.outcome is Outcome.DENY and retried.explanation.code == "approval_rejected"
    assert retried.explanation.reason == "rejected by user-1"
    assert store.created == [pending.approval.approval_id]


async def test_expired_decided_approval_is_not_reused(
    now: datetime, tool_context: GuardContext
) -> None:
    clock = _Clock(now)
    store = InMemoryApprovalStore(clock=clock)
    decision = _decision(tool_context)
    record = await store.create(
        ApprovalRecord(
            tenant_id="tenant-1",
            principal_id="user-1",
            context_hash=decision.context_hash,
            action_digest="digest-1",
            policy_version="v1",
            created_at=now - timedelta(seconds=600),
            expires_at=now - timedelta(seconds=300),
        )
    )
    await store.decide(
        record.id, ApprovalDecisionValue.APPROVE, "user-1", now - timedelta(seconds=400)
    )

    async def reevaluate() -> Decision:
        return decision

    delivered = InlineApprovalChannel(lambda r: ApprovalDecisionValue.APPROVE, store, clock=clock)
    result = await ApprovalFlow(store, delivered, clock=clock).resolve(
        tool_context, decision, ttl_s=300, reevaluate=reevaluate
    )
    assert result.outcome is Outcome.ALLOW and len(delivered.delivered) == 1


async def test_no_approver_or_no_digest_is_unavailable(
    now: datetime, tool_context: GuardContext
) -> None:
    clock = _Clock(now)
    store = InMemoryApprovalStore(clock=clock)
    channel = InlineApprovalChannel(lambda r: ApprovalDecisionValue.APPROVE, store, clock=clock)
    flow = ApprovalFlow(store, channel, clock=clock)
    decision = _decision(tool_context)

    async def reevaluate() -> Decision:
        return decision

    visitor = tool_context.model_copy(
        update={"principal": Principal(id="visitor", kind=PrincipalKind.END_USER)}
    )
    denied = await flow.resolve(visitor, decision, ttl_s=300, reevaluate=reevaluate)
    assert denied.outcome is Outcome.DENY and denied.explanation.code == "approval_unavailable"
    no_digest = decision.model_copy(update={"action_digest": None})
    without_digest = await flow.resolve(tool_context, no_digest, ttl_s=300, reevaluate=reevaluate)
    assert without_digest.explanation.code == "approval_unavailable"
    allowed = _decision(tool_context, outcome=Outcome.ALLOW)
    untouched = await flow.resolve(tool_context, allowed, ttl_s=300, reevaluate=reevaluate)
    assert untouched.outcome is Outcome.ALLOW
    assert (await store.get("missing")) is None and ApprovalStatus.PENDING.value == "pending"

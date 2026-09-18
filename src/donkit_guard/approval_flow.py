"""From a require_approval decision to a one-time, principal-bound approval."""

from __future__ import annotations

import asyncio
from collections.abc import Awaitable, Callable, Mapping
from datetime import timedelta
from typing import TYPE_CHECKING

from donkit_guard.adapters import ApprovalChannel, ApprovalStore, Clock, utc_now
from donkit_guard.approvals import ApprovalRecord, ApprovalStatus, DeliveryMode
from donkit_guard.decision import ApprovalPending, Decision, Explanation, Outcome

if TYPE_CHECKING:
    from donkit_guard.context import GuardContext

Reevaluate = Callable[[], Awaitable[Decision]]


def with_outcome(
    decision: Decision, outcome: Outcome, code: str, reason: str, **extra: object
) -> Decision:
    """The same decision under a new outcome and explanation, always worth auditing."""
    explanation: Explanation = decision.explanation.model_copy(
        update={"code": code, "reason": reason}
    )
    update: dict[str, object] = {"outcome": outcome, "explanation": explanation, "critical": True}
    if outcome is Outcome.DENY:
        # A denied payload is never forwarded, so it must not look maskable either.
        update["masked_segments"] = {}
    update.update(extra)
    return decision.model_copy(update=update)


class ApprovalFlow:
    def __init__(
        self, store: ApprovalStore, channel: ApprovalChannel, *, clock: Clock = utc_now
    ) -> None:
        self._store = store
        self._channel = channel
        self._clock = clock

    async def _consume_and_reevaluate(
        self, record: ApprovalRecord, decision: Decision, reevaluate: Reevaluate
    ) -> Decision:
        consumed = await self._store.consume(record.id, self._clock())
        if consumed is None:
            return with_outcome(
                decision,
                Outcome.DENY,
                "approval_consumed",
                "the approval was already used or has expired",
            )
        fresh = await reevaluate()
        if (
            fresh.outcome is not Outcome.REQUIRE_APPROVAL
            or fresh.policy_version != record.policy_version
        ):
            await self._store.mark_stale(record.id)
            return with_outcome(
                fresh if fresh.outcome is Outcome.DENY else decision,
                Outcome.DENY,
                "approval_stale",
                "the policy or the action changed after the approval was granted",
            )
        return with_outcome(
            decision,
            Outcome.ALLOW,
            "approved",
            f"approved by {record.decided_by or record.principal_id}",
            approval=ApprovalPending(
                approval_id=record.id,
                expires_at=record.expires_at,
                delivery=DeliveryMode.CONSUMED,
            ),
        )

    async def resolve(
        self,
        ctx: GuardContext,
        decision: Decision,
        *,
        ttl_s: int,
        reevaluate: Reevaluate,
        display_args_redacted: Mapping[str, str] | None = None,
        expected_change: str = "",
    ) -> Decision:
        if decision.outcome is not Outcome.REQUIRE_APPROVAL:
            return decision
        if decision.action_digest is None:
            return with_outcome(
                decision,
                Outcome.DENY,
                "approval_unavailable",
                "the action has no digest to bind an approval to",
            )
        tenant_id = ctx.tenant_id()
        existing = await self._store.find_decided(
            tenant_id, decision.action_digest, decision.context_hash
        )
        now = self._clock()
        if existing is not None and not existing.is_expired(now):
            if existing.status is ApprovalStatus.APPROVED:
                return await self._consume_and_reevaluate(existing, decision, reevaluate)
            if existing.status is ApprovalStatus.DENIED:
                # A queued flow is retried with the same digest: asking again
                # would bury the administrator's refusal under a new request.
                return with_outcome(
                    decision,
                    Outcome.DENY,
                    "approval_rejected",
                    f"rejected by {existing.decided_by or existing.principal_id}",
                )
        approver = ctx.approver()
        if approver is None:
            return with_outcome(
                decision,
                Outcome.DENY,
                "approval_unavailable",
                "no principal on this context may approve",
            )
        record = await self._store.create(
            ApprovalRecord(
                tenant_id=tenant_id,
                principal_id=approver.id,
                context_hash=decision.context_hash,
                action_digest=decision.action_digest,
                tool=ctx.action.tool,
                resource=ctx.action.resource,
                display_args_redacted=dict(display_args_redacted or {}),
                expected_change=expected_change,
                reason=decision.explanation.reason,
                policy_version=decision.policy_version,
                created_at=now,
                expires_at=now + timedelta(seconds=ttl_s),
            )
        )
        delivered = await self._channel.deliver(record, ctx)
        if delivered.mode is DeliveryMode.UNAVAILABLE:
            return with_outcome(
                decision,
                Outcome.DENY,
                "approval_unavailable",
                "this surface cannot ask for an approval",
            )
        pending = ApprovalPending(
            approval_id=record.id, expires_at=record.expires_at, delivery=delivered.mode
        )
        if delivered.mode is DeliveryMode.QUEUED:
            return with_outcome(
                decision,
                Outcome.APPROVAL_PENDING,
                "approval_pending",
                "waiting for an administrator",
                approval=pending,
            )
        try:
            decided = await asyncio.wait_for(
                self._channel.await_decision(record.id, float(ttl_s)), timeout=float(ttl_s)
            )
        except TimeoutError:
            decided = None
        if decided is None or decided.status is ApprovalStatus.PENDING:
            return with_outcome(
                decision,
                Outcome.DENY,
                "approval_timeout",
                "no decision before the approval expired",
                approval=pending,
            )
        if decided.status is ApprovalStatus.DENIED:
            return with_outcome(
                decision,
                Outcome.DENY,
                "approval_rejected",
                f"rejected by {decided.decided_by or approver.id}",
                approval=pending,
            )
        if decided.status is not ApprovalStatus.APPROVED:
            return with_outcome(
                decision,
                Outcome.DENY,
                "approval_timeout",
                f"approval ended in state {decided.status.value}",
                approval=pending,
            )
        return await self._consume_and_reevaluate(decided, decision, reevaluate)

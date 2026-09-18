"""One entry point for hosts: evaluate, resolve approvals, record execution."""

from __future__ import annotations

from typing import TYPE_CHECKING, Literal

from donkit_guard.approval_flow import ApprovalFlow, with_outcome
from donkit_guard.decision import Decision, Outcome, PolicyMode
from donkit_guard.detectors.injection import InjectionHeuristic
from donkit_guard.detectors.pii_checksum import PiiChecksumDetector
from donkit_guard.detectors.pii_ner import PiiNerDetector
from donkit_guard.detectors.runner import DetectorRunner, ExecutorKind
from donkit_guard.detectors.secrets import SecretsDetector
from donkit_guard.engine import Engine
from donkit_guard.memory import (
    InlineApprovalChannel,
    InMemoryApprovalStore,
    InMemoryAuditSink,
    InMemoryPolicySource,
    UnavailableApprovalChannel,
)
from donkit_guard.policy import default_bundle

if TYPE_CHECKING:
    from collections.abc import Callable, Collection

    from donkit_guard.adapters import DetectorClient
    from donkit_guard.approvals import ApprovalDecisionValue, ApprovalRecord
    from donkit_guard.context import GuardContext
    from donkit_guard.payload import Payload


class Guard:
    def __init__(self, engine: Engine, approvals: ApprovalFlow | None = None) -> None:
        self.engine = engine
        self.approvals = approvals

    async def __aenter__(self) -> Guard:
        return self

    async def __aexit__(self, *exc_info: object) -> None:
        await self.aclose()

    async def aclose(self) -> None:
        await self.engine.aclose()

    async def authorize(
        self,
        ctx: GuardContext,
        payload: Payload,
        *,
        seen_segments: Collection[str] | None = None,
        expected_change: str = "",
    ) -> Decision:
        decision = await self.engine.evaluate(ctx, payload, seen_segments=seen_segments)
        if decision.outcome is not Outcome.REQUIRE_APPROVAL:
            return decision
        if self.approvals is None:
            return await self.engine.record_decision(
                with_outcome(
                    decision,
                    Outcome.DENY,
                    "approval_unavailable",
                    "no approval flow is configured",
                ),
                ctx,
            )
        ttl_s = await self.engine.approval_ttl(ctx)

        async def reevaluate() -> Decision:
            # A freshness check on the policy, not a second decision to audit.
            return await self.engine.evaluate(
                ctx, payload, seen_segments=seen_segments, audit=False
            )

        resolved = await self.approvals.resolve(
            ctx,
            decision,
            ttl_s=ttl_s,
            reevaluate=reevaluate,
            display_args_redacted=decision.display_args_redacted,
            expected_change=expected_change,
        )
        if resolved is decision:
            return resolved
        # The approval turned the pending decision into the one the host acts
        # on, so the audit trail needs it under the same decision id.
        return await self.engine.record_decision(resolved, ctx)

    async def record_execution(
        self,
        decision_id: str,
        outcome: Literal["success", "error", "skipped"],
        *,
        error_class: str | None = None,
        duration_ms: float = 0.0,
    ) -> None:
        await self.engine.record_execution(
            decision_id, outcome, error_class=error_class, duration_ms=duration_ms
        )


def build_quickstart_guard(
    *,
    mode: PolicyMode = PolicyMode.OBSERVE,
    ner_client: DetectorClient | None = None,
    decider: Callable[[ApprovalRecord], ApprovalDecisionValue | None] | None = None,
) -> Guard:
    """Default policy, in-memory adapters, synchronous detectors: enough to try the guard in a REPL."""
    detectors: list[SecretsDetector | PiiChecksumDetector | InjectionHeuristic | PiiNerDetector] = [
        SecretsDetector(),
        PiiChecksumDetector(),
        InjectionHeuristic(),
    ]
    if ner_client is not None:
        detectors.append(PiiNerDetector(ner_client))
    engine = Engine(
        policy_source=InMemoryPolicySource(default_bundle(mode)),
        runner=DetectorRunner(detectors, executor=ExecutorKind.SYNC),
        audit_sink=InMemoryAuditSink(),
    )
    store = InMemoryApprovalStore()
    channel = (
        InlineApprovalChannel(decider, store)
        if decider is not None
        else UnavailableApprovalChannel()
    )
    return Guard(engine, ApprovalFlow(store, channel))

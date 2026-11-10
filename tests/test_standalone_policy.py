"""The standalone quick-start policy, decided by the core alone, the way an embedding host runs it.

The standalone service applies the same file (tests/standalone run it through the service), so
a host that embeds the package and a deployment of the service decide alike.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest

from donkit_guard import (
    Action,
    ActionKind,
    Destination,
    DestinationTrust,
    EffectClass,
    Guard,
    GuardContext,
    Outcome,
    Payload,
    PolicyBundle,
    Principal,
    PrincipalKind,
    RunRef,
    SegmentSource,
    SegmentTrust,
    Tenant,
    load_policy,
)
from donkit_guard.approval_flow import ApprovalFlow
from donkit_guard.detectors.injection import InjectionHeuristic
from donkit_guard.detectors.pii_checksum import PiiChecksumDetector
from donkit_guard.detectors.runner import DetectorRunner, ExecutorKind
from donkit_guard.detectors.secrets import SecretsDetector
from donkit_guard.engine import Engine
from donkit_guard.memory import (
    InMemoryApprovalStore,
    InMemoryAuditSink,
    InMemoryPolicySource,
    QueuedApprovalChannel,
)

POLICY = Path(__file__).resolve().parent.parent / "examples" / "policies" / "standalone.yaml"
# An AWS-shaped access key id, assembled at runtime so that secret scanners stay quiet.
SECRET = "AKIA" + "5RQTGNW2K4XQZJ7L"


def _guard() -> Guard:
    bundle = PolicyBundle.compose([load_policy(POLICY.read_text("utf-8"))])
    engine = Engine(
        policy_source=InMemoryPolicySource(bundle),
        runner=DetectorRunner(
            [SecretsDetector(), PiiChecksumDetector(), InjectionHeuristic()],
            executor=ExecutorKind.SYNC,
        ),
        audit_sink=InMemoryAuditSink(),
    )
    return Guard(engine, ApprovalFlow(InMemoryApprovalStore(), QueuedApprovalChannel()))


def _ctx(action: Action) -> GuardContext:
    return GuardContext(
        principal=Principal(id="user-1", kind=PrincipalKind.USER, approver=True),
        tenant=Tenant(id="acme"),
        run=RunRef(id="run-1"),
        action=action,
    )


def _llm(trust: DestinationTrust) -> Action:
    return Action(
        kind=ActionKind.LLM_REQUEST,
        destination=Destination(provider="openai", model="gpt", trust=trust),
    )


def _tool(name: str, effect: EffectClass, args: dict[str, Any]) -> Action:
    return Action(kind=ActionKind.TOOL_CALL, tool=name, effect=effect, arguments=args)


def _text(text: str) -> Payload:
    return Payload.of_text(text, source=SegmentSource.USER, trust=SegmentTrust.TRUSTED)


def _args(action: Action) -> Payload:
    return Payload.from_json(
        action.arguments, source=SegmentSource.TOOL_ARGS, trust=SegmentTrust.TRUSTED
    )


@pytest.mark.parametrize(
    ("action", "payload", "outcome", "rule"),
    [
        (
            _llm(DestinationTrust.UNKNOWN),
            _text(f"use {SECRET}"),
            Outcome.DENY,
            "secrets-deny-external-llm",
        ),
        (_llm(DestinationTrust.PLATFORM), _text(f"use {SECRET}"), Outcome.MASK, "secrets-mask"),
        (
            _llm(DestinationTrust.UNKNOWN),
            _text("write to john.smith@example.com"),
            Outcome.MASK,
            "pii-mask-external-llm",
        ),
        (
            (delete := _tool("delete_file", EffectClass.READ, {"path": "/"})),
            _args(delete),
            Outcome.DENY,
            "tools-destructive-deny",
        ),
        (
            (ticket := _tool("create_ticket", EffectClass.WRITE, {"title": "Refund"})),
            _args(ticket),
            Outcome.APPROVAL_PENDING,
            "tool-side-effect-approval",
        ),
        (
            (search := _tool("search_docs", EffectClass.READ, {"query": "refunds"})),
            _args(search),
            Outcome.ALLOW,
            "tool-read-allow",
        ),
    ],
)
async def test_the_quick_start_policy_decides_alike_embedded(
    action: Action, payload: Payload, outcome: Outcome, rule: str
) -> None:
    async with _guard() as guard:
        decision = await guard.authorize(_ctx(action), payload)
    assert decision.outcome is outcome
    assert rule in decision.explanation.rule_ids

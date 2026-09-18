from __future__ import annotations

from datetime import UTC, datetime

import pytest

from donkit_guard.context import (
    Action,
    ActionKind,
    AgentRef,
    Destination,
    DestinationLocality,
    DestinationTrust,
    EffectClass,
    EffectSource,
    GuardContext,
    Principal,
    PrincipalKind,
    RunRef,
    Tenant,
)
from donkit_guard.payload import Payload, SegmentSource, SegmentTrust


@pytest.fixture
def now() -> datetime:
    return datetime(2026, 9, 18, 12, 0, tzinfo=UTC)


@pytest.fixture
def tool_context() -> GuardContext:
    return GuardContext(
        principal=Principal(id="user-1", kind=PrincipalKind.USER, approver=True),
        tenant=Tenant(id="tenant-1"),
        agent=AgentRef(id="agent-1", version="3"),
        run=RunRef(id="run-1", kind="conversation"),
        action=Action(
            kind=ActionKind.TOOL_CALL,
            tool="delete_file",
            arguments={"path": "/tmp/report.txt"},
            effect=EffectClass.WRITE,
            effect_source=EffectSource.HOST,
        ),
        attributes={"origin": "chat"},
    )


@pytest.fixture
def llm_context() -> GuardContext:
    return GuardContext(
        principal=Principal(id="user-1", kind=PrincipalKind.USER, approver=True),
        tenant=Tenant(id="tenant-1"),
        agent=AgentRef(id="agent-1"),
        run=RunRef(id="run-1", kind="conversation"),
        action=Action(
            kind=ActionKind.LLM_REQUEST,
            destination=Destination(
                provider="openai",
                model="gpt-5",
                locality=DestinationLocality.PLATFORM,
                trust=DestinationTrust.PLATFORM,
            ),
        ),
    )


@pytest.fixture
def text_payload() -> Payload:
    return Payload.of_text(
        "Please summarise the attached report.",
        source=SegmentSource.USER,
        trust=SegmentTrust.TRUSTED,
        lang="en",
    )


@pytest.fixture
def json_payload() -> Payload:
    return Payload.from_json(
        {"path": "/tmp/report.txt", "content": "hello", "phone": 89123456789},
        source=SegmentSource.TOOL_ARGS,
        trust=SegmentTrust.TRUSTED,
    )

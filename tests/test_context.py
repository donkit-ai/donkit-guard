from __future__ import annotations

import pytest
from pydantic import ValidationError

from donkit_guard.context import (
    Action,
    ActionKind,
    EffectClass,
    EffectSource,
    GuardContext,
    Principal,
    PrincipalKind,
    RunRef,
)


def test_effective_effect_gates_unknown_and_untrusted_read() -> None:
    unknown = Action(kind=ActionKind.TOOL_CALL, tool="t", effect=EffectClass.UNKNOWN)
    assert unknown.effective_effect() is EffectClass.WRITE
    server_read = Action(
        kind=ActionKind.TOOL_CALL,
        tool="t",
        effect=EffectClass.READ,
        effect_source=EffectSource.TOOL_SERVER,
    )
    assert server_read.effective_effect() is EffectClass.WRITE
    host_read = Action(kind=ActionKind.TOOL_CALL, tool="t", effect=EffectClass.READ)
    assert host_read.effective_effect() is EffectClass.READ


def test_tool_call_requires_tool_name() -> None:
    with pytest.raises(ValidationError):
        Action(kind=ActionKind.TOOL_CALL)


def test_context_hash_ignores_arguments_but_not_tool(tool_context: GuardContext) -> None:
    same_tool_other_args = tool_context.model_copy(
        update={"action": tool_context.action.model_copy(update={"arguments": {"path": "/x"}})}
    )
    other_tool = tool_context.model_copy(
        update={"action": tool_context.action.model_copy(update={"tool": "write_file"})}
    )
    assert tool_context.context_hash() == same_tool_other_args.context_hash()
    assert tool_context.context_hash() != other_tool.context_hash()


def test_approver_prefers_on_behalf_of_and_requires_flag() -> None:
    ctx = GuardContext(
        principal=Principal(id="svc", kind=PrincipalKind.SERVICE),
        on_behalf_of=Principal(id="user-9", kind=PrincipalKind.USER, approver=True),
        run=RunRef(id="r"),
        action=Action(kind=ActionKind.LLM_REQUEST),
    )
    approver = ctx.approver()
    assert approver is not None and approver.id == "user-9"
    anonymous = GuardContext(run=RunRef(id="r"), action=Action(kind=ActionKind.LLM_REQUEST))
    assert anonymous.approver() is None
    assert anonymous.tenant_id() is None


def test_context_forbids_unknown_fields() -> None:
    with pytest.raises(ValidationError):
        GuardContext(  # type: ignore[call-arg]
            run=RunRef(id="r"),
            action=Action(kind=ActionKind.LLM_REQUEST),
            extra=1,
        )

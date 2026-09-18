"""Decision context: who acts, on whose behalf, where, and what is about to happen.

The context is an open attribute set. The well-known dimensions are optional
conventions that a host maps its own model onto; nothing here requires a
particular identity or tenancy model.
"""

from __future__ import annotations

import hashlib
import json
from enum import StrEnum
from typing import Any

from pydantic import BaseModel, ConfigDict, Field, model_validator

AttrValue = str | int | bool


class FrozenModel(BaseModel):
    """Base for every model that crosses the core boundary."""

    model_config = ConfigDict(frozen=True, extra="forbid")


class PrincipalKind(StrEnum):
    USER = "user"
    END_USER = "end_user"
    SERVICE = "service"
    API_KEY = "api_key"
    AGENT = "agent"
    ANONYMOUS = "anonymous"


class ActionKind(StrEnum):
    LLM_REQUEST = "llm_request"
    TOOL_CALL = "tool_call"
    TOOL_RESULT = "tool_result"


class EffectClass(StrEnum):
    READ = "read"
    WRITE = "write"
    EXECUTE = "execute"
    SPEND = "spend"
    EGRESS = "egress"
    UNKNOWN = "unknown"


class EffectSource(StrEnum):
    HOST = "host"
    OPERATOR = "operator"
    TOOL_SERVER = "tool_server"


class DestinationLocality(StrEnum):
    PLATFORM = "platform"
    TENANT_BYOK = "tenant_byok"
    ONPREM = "onprem"
    LOCAL = "local"


class DestinationTrust(StrEnum):
    PLATFORM = "platform"
    TENANT = "tenant"
    UNKNOWN = "unknown"


class Principal(FrozenModel):
    id: str = Field(min_length=1)
    kind: PrincipalKind
    approver: bool = False
    attributes: dict[str, AttrValue] = Field(default_factory=dict)


class Tenant(FrozenModel):
    id: str = Field(min_length=1)


class AgentRef(FrozenModel):
    id: str = Field(min_length=1)
    version: str | None = None


class RunRef(FrozenModel):
    id: str = Field(min_length=1)
    kind: str = "run"
    trace_id: str | None = None
    untrusted_content_seen: bool = False


class Delegation(FrozenModel):
    caller_agent: str | None = None
    depth: int = Field(default=0, ge=0)
    path: tuple[str, ...] = ()
    trace_id: str | None = None


class Destination(FrozenModel):
    provider: str = Field(min_length=1)
    model: str = Field(min_length=1)
    hosting: str | None = None
    endpoint_host: str | None = None
    locality: DestinationLocality = DestinationLocality.PLATFORM
    trust: DestinationTrust = DestinationTrust.UNKNOWN


class Action(FrozenModel):
    kind: ActionKind
    tool: str | None = None
    operation: str | None = None
    resource: str | None = None
    arguments: dict[str, Any] | None = None
    effect: EffectClass = EffectClass.UNKNOWN
    effect_source: EffectSource = EffectSource.HOST
    destination: Destination | None = None

    @model_validator(mode="after")
    def _tool_required_for_tool_kinds(self) -> Action:
        if self.kind in (ActionKind.TOOL_CALL, ActionKind.TOOL_RESULT) and not self.tool:
            raise ValueError("tool is required for tool_call and tool_result actions")
        return self

    def effective_effect(self) -> EffectClass:
        """The effect class the engine gates on.

        ``unknown`` is gated like ``write``. A ``read`` declared by the tool
        provider itself (``effect_source=tool_server``) is not trusted, because a
        compromised tool server could lower its own risk class, so it is gated
        like ``write`` as well.
        """
        if self.effect is EffectClass.UNKNOWN:
            return EffectClass.WRITE
        if self.effect is EffectClass.READ and self.effect_source is EffectSource.TOOL_SERVER:
            return EffectClass.WRITE
        return self.effect


class GuardContext(FrozenModel):
    schema_version: int = 1
    principal: Principal | None = None
    on_behalf_of: Principal | None = None
    tenant: Tenant | None = None
    agent: AgentRef | None = None
    run: RunRef
    delegation: Delegation | None = None
    action: Action
    attributes: dict[str, AttrValue] = Field(default_factory=dict)

    def approver(self) -> Principal | None:
        """The principal allowed to approve on this context, if the host marked one."""
        for candidate in (self.on_behalf_of, self.principal):
            if candidate is not None and candidate.approver:
                return candidate
        return None

    def tenant_id(self) -> str | None:
        return self.tenant.id if self.tenant is not None else None

    def context_hash(self) -> str:
        """Stable hash of the context without the action arguments.

        Arguments are covered by the action digest so that an approval is bound
        to both the situation (this hash) and the exact operation (the digest).
        """
        payload = self.model_dump(mode="json", exclude={"action": {"arguments"}})
        canonical = json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
        return hashlib.sha256(canonical.encode("utf-8")).hexdigest()

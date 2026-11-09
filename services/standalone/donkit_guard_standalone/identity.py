"""Who a gateway exchange belongs to, as the gateway and the calling application state it.

The tenant comes only from what the gateway attaches after it authenticated the caller: the
ext_proc request attributes or the ExtMcp metadata, both computed by CEL from the gateway's
own configuration (an API key's metadata, a JWT claim). A client cannot set it. The principal,
run and agent come from ``x-guard-*`` headers that the authenticated application sends for the
person and the conversation it acts for; the guard trusts them as far as it trusts the key.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

from pydantic import Field

from donkit_guard.context import (
    AgentRef,
    FrozenModel,
    Principal,
    PrincipalKind,
    RunRef,
    Tenant,
)

if TYPE_CHECKING:
    from collections.abc import Mapping

TENANT_KEY = "tenant"
PRINCIPAL_HEADER = "x-guard-principal"
PRINCIPAL_KIND_HEADER = "x-guard-principal-kind"
APPROVER_HEADER = "x-guard-approver"
RUN_HEADER = "x-guard-run"
AGENT_HEADER = "x-guard-agent"
MCP_SESSION_HEADER = "mcp-session-id"


class IdentityMissing(ValueError):
    """The gateway sent no tenant, so the exchange cannot be attributed."""


class GatewayIdentity(FrozenModel):
    tenant: str = Field(min_length=1)
    principal: str | None = None
    principal_kind: PrincipalKind = PrincipalKind.USER
    approver: bool = True
    run: str | None = None
    agent: str | None = None

    def tenant_ref(self) -> Tenant:
        return Tenant(id=self.tenant)

    def principal_ref(self) -> Principal | None:
        if self.principal is None:
            return None
        return Principal(id=self.principal, kind=self.principal_kind, approver=self.approver)

    def agent_ref(self) -> AgentRef | None:
        return AgentRef(id=self.agent) if self.agent else None

    def run_ref(self, fallback: str, *, untrusted_content_seen: bool = False) -> RunRef:
        return RunRef(id=self.run or fallback, untrusted_content_seen=untrusted_content_seen)


def _text(value: Any) -> str | None:
    if isinstance(value, str) and value.strip():
        return value.strip()
    return None


def identity_from(attributes: Mapping[str, Any], headers: Mapping[str, str]) -> GatewayIdentity:
    """The identity of an exchange from the gateway's attributes and the request headers.

    ``headers`` are keyed in lower case. The principal is an approver unless the application
    says ``x-guard-approver: false``: in the standalone service the person an approval is
    asked of is the one acting, and the admin API relays that person's answer.
    """
    tenant = _text(attributes.get(TENANT_KEY))
    if tenant is None:
        raise IdentityMissing("the gateway attached no tenant to this request")
    kind = _text(headers.get(PRINCIPAL_KIND_HEADER))
    try:
        principal_kind = PrincipalKind(kind) if kind else PrincipalKind.USER
    except ValueError as exc:
        raise IdentityMissing(f"unknown principal kind {kind!r}") from exc
    return GatewayIdentity(
        tenant=tenant,
        principal=_text(headers.get(PRINCIPAL_HEADER)),
        principal_kind=principal_kind,
        approver=(headers.get(APPROVER_HEADER) or "true").strip().lower() != "false",
        run=_text(headers.get(RUN_HEADER)) or _text(headers.get(MCP_SESSION_HEADER)),
        agent=_text(headers.get(AGENT_HEADER)),
    )

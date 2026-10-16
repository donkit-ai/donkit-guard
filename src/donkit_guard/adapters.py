"""The contract a host implements to embed the guard."""

from __future__ import annotations

import os
from collections.abc import Callable
from datetime import UTC, datetime
from typing import TYPE_CHECKING, Protocol, runtime_checkable

from pydantic import ConfigDict, Field

from donkit_guard.context import FrozenModel, GuardContext

if TYPE_CHECKING:
    from donkit_guard.approvals import ApprovalDecisionValue, ApprovalRecord, Delivered
    from donkit_guard.audit import AuditEvent
    from donkit_guard.policy import PolicyBundle

Clock = Callable[[], datetime]


def utc_now() -> datetime:
    return datetime.now(UTC)


class AnalyzeSegment(FrozenModel):
    """A piece of text to analyze.

    ``id`` is opaque to the service and comes back as ``AnalyzeSpan.segment_id``.
    ``lang`` is a language hint: any language code the caller has, or ``None`` when it
    does not know the language. The service decides which codes it supports.
    """

    id: str
    text: str
    lang: str | None = None


# The analyze service rejects longer deadlines; callers clamp to this bound.
MAX_DEADLINE_MS = 60_000


class AnalyzeRequest(FrozenModel):
    """The body of ``POST /v1/analyze``: the segments to inspect and how long to wait.

    A service that cannot finish within ``deadline_ms`` answers ``failed: true`` instead
    of keeping the caller waiting.
    """

    segments: tuple[AnalyzeSegment, ...] = ()
    deadline_ms: int = Field(default=2000, ge=1, le=MAX_DEADLINE_MS)


class AnalyzeSpan(FrozenModel):
    """One finding inside a segment of the request.

    ``start`` and ``end`` are offsets into the text of the segment named by
    ``segment_id``. They count Unicode code points, as a Python ``str`` index does, and
    ``end`` is exclusive. ``score`` is a confidence between 0 and 1. A field a service
    adds beyond these is ignored, so a service can extend its answer without breaking
    its callers.
    """

    model_config = ConfigDict(frozen=True, extra="ignore")

    segment_id: str
    start: int
    end: int
    entity_type: str
    score: float


class AnalyzeResponse(FrozenModel):
    """The answer to ``POST /v1/analyze``.

    An empty ``spans`` means the text was analyzed and nothing was found. A service that
    cannot answer, or cannot answer in time, returns ``failed: true`` with a short
    ``error``; it must not pass an empty ``spans`` off as a clean result. A field a
    service adds beyond these is ignored, so a service can extend its answer without
    breaking its callers.
    """

    model_config = ConfigDict(frozen=True, extra="ignore")

    detector: str = "pii-ner"
    version: str = "1"
    spans: tuple[AnalyzeSpan, ...] = ()
    failed: bool = False
    error: str | None = None


@runtime_checkable
class PolicySource(Protocol):
    async def resolve(self, ctx: GuardContext) -> PolicyBundle: ...


@runtime_checkable
class DetectorClient(Protocol):
    async def analyze(self, request: AnalyzeRequest, deadline_s: float) -> AnalyzeResponse: ...


@runtime_checkable
class CredentialResolver(Protocol):
    """Maps a credential name from a policy document to the secret a host holds for it.

    A document names the credential a remote detector needs but never carries its value.
    ``tenant_id`` lets a host keep a separate secret per tenant. Return ``None`` when there
    is no such credential; the detector then fails without sending a request.
    """

    async def token(self, tenant_id: str | None, name: str) -> str | None: ...


class EnvCredentialResolver:
    """Reads credentials from environment variables, the same for every tenant.

    The credential ``my-service`` is read from ``DONKIT_GUARD_CREDENTIAL_MY_SERVICE``:
    the name upper-cased, with ``-`` turned into ``_``. A host that keeps its secrets per
    tenant provides its own ``CredentialResolver``.
    """

    async def token(self, tenant_id: str | None, name: str) -> str | None:
        return os.environ.get("DONKIT_GUARD_CREDENTIAL_" + name.upper().replace("-", "_"))


@runtime_checkable
class EndpointGuard(Protocol):
    """Decides whether a remote detector may call a URL taken from a policy document.

    A host that accepts documents from its tenants refuses the addresses it does not want
    the guard to reach, such as internal networks or metadata services. Raise
    ``donkit_guard.errors.EndpointRejected`` to refuse; return normally to allow.
    """

    async def check(self, url: str) -> None: ...


class AllowAllEndpoints:
    """Accepts every URL; for hosts whose policy documents come from a trusted source."""

    async def check(self, url: str) -> None:
        return None


@runtime_checkable
class AuditSink(Protocol):
    async def record(self, event: AuditEvent) -> None: ...


@runtime_checkable
class ApprovalStore(Protocol):
    async def create(self, record: ApprovalRecord) -> ApprovalRecord: ...

    async def get(self, approval_id: str) -> ApprovalRecord | None: ...

    async def find_decided(
        self, tenant_id: str | None, action_digest: str, context_hash: str
    ) -> ApprovalRecord | None: ...

    async def decide(
        self,
        approval_id: str,
        decision: ApprovalDecisionValue,
        decided_by: str,
        now: datetime,
    ) -> ApprovalRecord | None: ...

    async def consume(self, approval_id: str, now: datetime) -> ApprovalRecord | None: ...

    async def mark_stale(self, approval_id: str) -> None: ...

    async def expire_pending(self, now: datetime) -> int: ...


@runtime_checkable
class ApprovalChannel(Protocol):
    async def deliver(self, record: ApprovalRecord, ctx: GuardContext) -> Delivered: ...

    async def await_decision(
        self, approval_id: str, deadline_s: float
    ) -> ApprovalRecord | None: ...

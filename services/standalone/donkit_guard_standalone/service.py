"""The composition root: one guard, its storage and its policy, shared by every surface."""

from __future__ import annotations

import asyncio
import contextlib
import logging
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Literal

import httpx

from donkit_guard.adapters import utc_now
from donkit_guard.approval_flow import ApprovalFlow
from donkit_guard.approvals import ApprovalDecisionValue, ApprovalRecord, ApprovalStatus
from donkit_guard.context import FrozenModel
from donkit_guard.detectors.injection import InjectionHeuristic
from donkit_guard.detectors.pii_checksum import PiiChecksumDetector
from donkit_guard.detectors.pii_ner import PiiNerDetector
from donkit_guard.detectors.runner import Budget, DetectorRunner
from donkit_guard.detectors.secrets import SecretsDetector
from donkit_guard.engine import Engine
from donkit_guard.guard import Guard
from donkit_guard.http import HttpAnalyzeClient
from donkit_guard.memory import QueuedApprovalChannel
from donkit_guard_standalone import db
from donkit_guard_standalone.catalog import ToolCatalog
from donkit_guard_standalone.errors import (
    ApprovalExpired,
    ApprovalNotFound,
    ApprovalNotPending,
    ResponderMismatch,
)
from donkit_guard_standalone.metrics import Metric, Metrics
from donkit_guard_standalone.policy_source import FilePolicySource
from donkit_guard_standalone.storage import (
    DecisionLog,
    PolicyVersionLog,
    SqlApprovalStore,
    SqlAuditSink,
)

if TYPE_CHECKING:
    from collections.abc import Collection

    from sqlalchemy.ext.asyncio import AsyncEngine

    from donkit_guard.adapters import Clock
    from donkit_guard.context import GuardContext
    from donkit_guard.decision import Decision
    from donkit_guard.detectors.base import AnyDetector
    from donkit_guard.payload import Payload
    from donkit_guard_standalone.settings import Settings

logger = logging.getLogger("donkit_guard_standalone")

Surface = Literal["api", "llm_request", "llm_response", "mcp_request", "mcp_response"]


class CheckResult(FrozenModel):
    ok: bool
    detail: str = ""


class Readiness(FrozenModel):
    ready: bool
    policy: CheckResult
    database: CheckResult
    pii: CheckResult


class PiiProbe:
    """Asks guard-pii whether it is up, for the readiness check."""

    def __init__(self, base_url: str) -> None:
        self._url = base_url.rstrip("/") + "/healthz"
        self._client = httpx.AsyncClient(trust_env=False, follow_redirects=False)

    async def check(self) -> CheckResult:
        try:
            response = await self._client.get(self._url, timeout=2.0)
        except httpx.HTTPError as exc:
            return CheckResult(ok=False, detail=f"guard-pii unreachable: {type(exc).__name__}")
        if response.status_code != 200:
            return CheckResult(ok=False, detail=f"guard-pii answered HTTP {response.status_code}")
        return CheckResult(ok=True, detail="guard-pii is up")

    async def aclose(self) -> None:
        await self._client.aclose()


def _detectors(settings: Settings) -> list[AnyDetector]:
    detectors: list[AnyDetector] = [SecretsDetector(), PiiChecksumDetector(), InjectionHeuristic()]
    if settings.pii_url is not None:
        endpoint = settings.pii_url.rstrip("/") + "/v1/analyze"
        detectors.append(PiiNerDetector(HttpAnalyzeClient(endpoint)))
    return detectors


def _runner(settings: Settings) -> DetectorRunner:
    budget = Budget(
        local_base_ms=settings.detector_local_base_ms,
        local_per_kb_ms=settings.detector_local_per_kb_ms,
        remote_cap_ms=settings.detector_remote_timeout_ms,
    )
    return DetectorRunner(
        _detectors(settings),
        executor=settings.detector_executor,
        budget=budget,
        max_workers=settings.detector_workers,
    )


@dataclass
class GuardService:
    settings: Settings
    guard: Guard
    policy: FilePolicySource
    approvals: SqlApprovalStore
    decisions: DecisionLog
    catalog: ToolCatalog
    metrics: Metrics
    database: AsyncEngine
    pii: PiiProbe | None
    clock: Clock = utc_now
    _sweeper: asyncio.Task[None] | None = field(default=None, repr=False)

    @classmethod
    async def open(cls, settings: Settings, *, clock: Clock = utc_now) -> GuardService:
        """Migrate the database, load the policy and the tool catalog, build the guard."""
        if settings.db_migrate:
            await db.migrate(settings.db_url)
        database = db.open_engine(settings.db_url)
        sessions = db.sessions(database)
        metrics = Metrics()
        policy = await FilePolicySource.open(
            settings.policy_file,
            check_interval_s=settings.policy_check_interval_s,
            metrics=metrics,
            on_loaded=PolicyVersionLog(sessions).record,
            clock=clock,
        )
        catalog = (
            ToolCatalog.load(settings.tool_catalog_file)
            if settings.tool_catalog_file is not None
            else ToolCatalog.empty()
        )
        approvals = SqlApprovalStore(sessions)
        engine = Engine(
            policy_source=policy,
            runner=_runner(settings),
            audit_sink=SqlAuditSink(sessions),
            action_catalog=catalog,
            clock=clock,
        )
        service = cls(
            settings=settings,
            guard=Guard(engine, ApprovalFlow(approvals, QueuedApprovalChannel(), clock=clock)),
            policy=policy,
            approvals=approvals,
            decisions=DecisionLog(sessions),
            catalog=catalog,
            metrics=metrics,
            database=database,
            pii=PiiProbe(settings.pii_url) if settings.pii_url is not None else None,
            clock=clock,
        )
        service._sweeper = asyncio.create_task(service._sweep_expired())
        return service

    async def authorize(
        self,
        ctx: GuardContext,
        payload: Payload,
        *,
        surface: Surface,
        seen_segments: Collection[str] | None = None,
        expected_change: str = "",
    ) -> Decision:
        decision = await self.guard.authorize(
            ctx, payload, seen_segments=seen_segments, expected_change=expected_change
        )
        self.metrics.inc(Metric.DECISIONS, surface=surface, outcome=decision.outcome.value)
        return decision

    async def decide_approval(
        self, approval_id: str, value: ApprovalDecisionValue, responder: str
    ) -> ApprovalRecord:
        """Record the answer of the principal the approval was asked of."""
        record = await self.approvals.get(approval_id)
        if record is None:
            raise ApprovalNotFound(approval_id)
        if record.status is not ApprovalStatus.PENDING:
            raise ApprovalNotPending(f"the approval is {record.status.value}")
        if record.principal_id != responder:
            raise ResponderMismatch("only the principal the approval was asked of may answer")
        now = self.clock()
        if record.is_expired(now):
            await self.approvals.expire_pending(now)
            raise ApprovalExpired("the approval expired before the answer")
        decided = await self.approvals.decide(approval_id, value, responder, now)
        if decided is None:
            # Another answer or the expiry won the race since the record was read.
            current = await self.approvals.get(approval_id)
            state = current.status.value if current is not None else "gone"
            raise ApprovalNotPending(f"the approval is {state}")
        return decided

    async def readiness(self) -> Readiness:
        policy = CheckResult(ok=True, detail=self.policy.current.bundle.version)
        try:
            await db.ping(self.database)
            database = CheckResult(ok=True, detail=self.database.dialect.name)
        except Exception as exc:  # any driver failure means the database is not usable
            database = CheckResult(ok=False, detail=f"{type(exc).__name__}: {exc}")
        pii = (
            await self.pii.check()
            if self.pii is not None
            else CheckResult(ok=True, detail="disabled by GUARD_PII_DISABLED")
        )
        return Readiness(
            ready=policy.ok and database.ok and pii.ok, policy=policy, database=database, pii=pii
        )

    async def aclose(self) -> None:
        if self._sweeper is not None:
            self._sweeper.cancel()
            with contextlib.suppress(asyncio.CancelledError):
                await self._sweeper
        await self.guard.aclose()
        if self.pii is not None:
            await self.pii.aclose()
        await self.database.dispose()

    async def _sweep_expired(self) -> None:
        while True:
            await asyncio.sleep(self.settings.approval_sweep_interval_s)
            try:
                expired = await self.approvals.expire_pending(self.clock())
            except Exception:  # the sweep retries on its next turn; the failure is logged
                logger.exception("expiring pending approvals failed")
                continue
            if expired:
                self.metrics.inc(Metric.APPROVALS_EXPIRED, expired)

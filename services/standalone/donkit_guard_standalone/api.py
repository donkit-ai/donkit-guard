"""The HTTP surface: the client API under ``/v1``, the admin API under ``/admin``, and probes."""

from __future__ import annotations

import hashlib
import hmac
import logging
from contextlib import asynccontextmanager
from typing import TYPE_CHECKING, Annotated

from fastapi import Depends, FastAPI, Header, HTTPException, Query, Request
from fastapi.responses import JSONResponse, PlainTextResponse

from donkit_guard.approvals import ApprovalRecord, ApprovalStatus
from donkit_guard.context import Tenant
from donkit_guard_standalone.authorize import inspect
from donkit_guard_standalone.errors import (
    ApprovalExpired,
    ApprovalNotFound,
    ApprovalNotPending,
    ResponderMismatch,
    TenantMismatch,
)
from donkit_guard_standalone.gateway import GatewayServer
from donkit_guard_standalone.limits import BodyLimit
from donkit_guard_standalone.schemas import (
    ApprovalList,
    AuthorizeRequest,
    AuthorizeResponse,
    DecideRequest,
    ErrorBody,
    ExecutionRequest,
    PolicyView,
    Recorded,
    ReloadView,
    RuleView,
)
from donkit_guard_standalone.service import GuardService, Readiness
from donkit_guard_standalone.settings import ApiKey, Settings
from donkit_guard_standalone.storage import DecisionFilter, DecisionNotFound, DecisionPage

if TYPE_CHECKING:
    from collections.abc import AsyncIterator

logger = logging.getLogger("donkit_guard_standalone.api")


def _service(request: Request) -> GuardService:
    service: GuardService = request.app.state.service
    return service


def _client_key(request: Request, x_api_key: Annotated[str | None, Header()] = None) -> ApiKey:
    """The API key of the caller, matched by its SHA-256 in constant time."""
    if not x_api_key:
        raise HTTPException(status_code=401, detail="missing X-API-Key")
    digest = hashlib.sha256(x_api_key.encode("utf-8")).hexdigest()
    found: ApiKey | None = None
    for key in _service(request).settings.api_keys:
        if hmac.compare_digest(key.sha256, digest):
            found = key
    if found is None:
        raise HTTPException(status_code=401, detail="unknown API key")
    return found


def _admin(request: Request, authorization: Annotated[str | None, Header()] = None) -> None:
    token = _service(request).settings.admin_token.get_secret_value()
    presented = (authorization or "").removeprefix("Bearer ").strip()
    if not presented or not hmac.compare_digest(presented.encode(), token.encode()):
        raise HTTPException(status_code=401, detail="admin token required")


Service = Annotated[GuardService, Depends(_service)]
ClientKey = Annotated[ApiKey, Depends(_client_key)]
Admin = Depends(_admin)


def _bound_to_key(request: AuthorizeRequest, key: ApiKey) -> AuthorizeRequest:
    """The request with its tenant taken from the API key; another tenant is refused."""
    ctx = request.context
    if ctx.tenant is not None and ctx.tenant.id != key.tenant:
        raise TenantMismatch(f"the API key belongs to tenant {key.tenant!r}")
    if ctx.tenant is None:
        ctx = ctx.model_copy(update={"tenant": Tenant(id=key.tenant)})
    return request.model_copy(update={"context": ctx})


def _error(status: int, error: str, detail: str) -> JSONResponse:
    return JSONResponse(
        status_code=status, content=ErrorBody(error=error, detail=detail).model_dump()
    )


def _install_error_handlers(app: FastAPI) -> None:
    mapping: tuple[tuple[type[Exception], int, str], ...] = (
        (ApprovalNotFound, 404, "approval_not_found"),
        (DecisionNotFound, 404, "decision_not_found"),
        (ApprovalNotPending, 409, "approval_not_pending"),
        (ApprovalExpired, 410, "approval_expired"),
        (ResponderMismatch, 403, "responder_mismatch"),
        (TenantMismatch, 403, "tenant_mismatch"),
    )
    for exc_type, status, code in mapping:

        async def handler(
            request: Request, exc: Exception, status: int = status, code: str = code
        ) -> JSONResponse:
            return _error(status, code, str(exc))

        app.add_exception_handler(exc_type, handler)


def _register_client_routes(app: FastAPI) -> None:
    @app.post("/v1/authorize", response_model=AuthorizeResponse)
    async def authorize(
        body: AuthorizeRequest, key: ClientKey, service: Service
    ) -> AuthorizeResponse:
        request = _bound_to_key(body, key)
        inspection = inspect(request)
        decision = await service.authorize(
            request.context,
            inspection.payload,
            surface="api",
            seen_segments=request.seen_segments,
            expected_change=request.expected_change,
        )
        return inspection.response(decision)

    @app.post("/v1/executions", response_model=Recorded)
    async def record_execution(
        body: ExecutionRequest, key: ClientKey, service: Service
    ) -> Recorded:
        tenant = await service.decisions.tenant_of(body.decision_id)
        if tenant != key.tenant:
            # Another tenant's decision is reported as absent, not as forbidden.
            raise DecisionNotFound(body.decision_id)
        await service.guard.record_execution(
            body.decision_id,
            body.outcome,
            error_class=body.error_class,
            duration_ms=body.duration_ms,
        )
        return Recorded()


def _register_admin_routes(app: FastAPI) -> None:
    @app.get("/admin/approvals", response_model=ApprovalList, dependencies=[Admin])
    async def list_approvals(
        service: Service,
        status: ApprovalStatus | None = ApprovalStatus.PENDING,
        tenant: str | None = None,
        limit: Annotated[int, Query(ge=1, le=500)] = 100,
    ) -> ApprovalList:
        records = await service.approvals.list_records(status=status, tenant_id=tenant, limit=limit)
        return ApprovalList(items=tuple(records))

    @app.post(
        "/admin/approvals/{approval_id}/decide", response_model=ApprovalRecord, dependencies=[Admin]
    )
    async def decide(approval_id: str, body: DecideRequest, service: Service) -> ApprovalRecord:
        return await service.decide_approval(approval_id, body.decision, body.responder)

    @app.get("/admin/decisions", response_model=DecisionPage, dependencies=[Admin])
    async def list_decisions(
        service: Service, query: Annotated[DecisionFilter, Query()]
    ) -> DecisionPage:
        return await service.decisions.page(query)

    @app.get("/admin/policy", response_model=PolicyView, dependencies=[Admin])
    async def policy(service: Service) -> PolicyView:
        loaded = service.policy.current
        rules = tuple(
            RuleView(
                layer=layer,
                id=rule.id,
                action=rule.action.value,
                hard=rule.hard,
                description=rule.description,
                reason=rule.reason,
            )
            for layer, rule in loaded.document.iter_rules()
        )
        return PolicyView(
            version=loaded.bundle.version,
            document_version=loaded.document.version,
            sha256=loaded.sha256,
            path=loaded.path,
            mode=loaded.bundle.mode.value,
            loaded_at=loaded.loaded_at,
            rules=rules,
            last_error=service.policy.last_error,
        )

    @app.post("/admin/policy/reload", response_model=ReloadView, dependencies=[Admin])
    async def reload_policy(service: Service) -> JSONResponse:
        result = await service.policy.reload(force=True)
        view = ReloadView(changed=result.changed, version=result.version, error=result.error)
        return JSONResponse(status_code=422 if result.error else 200, content=view.model_dump())


def _register_probes(app: FastAPI) -> None:
    @app.get("/healthz")
    async def healthz() -> dict[str, str]:
        return {"status": "ok"}

    @app.get("/readyz", response_model=Readiness)
    async def readyz(service: Service) -> JSONResponse:
        readiness = await service.readiness()
        return JSONResponse(
            status_code=200 if readiness.ready else 503, content=readiness.model_dump()
        )

    @app.get("/metrics", response_class=PlainTextResponse)
    async def metrics(service: Service) -> str:
        return service.metrics.render()


def create_app(settings: Settings) -> FastAPI:
    """The service: the guard, its gRPC gateway server and the HTTP API, started together."""

    @asynccontextmanager
    async def lifespan(app: FastAPI) -> AsyncIterator[None]:
        service = await GuardService.open(settings)
        gateway = await GatewayServer.start(service)
        app.state.service = service
        app.state.gateway = gateway
        try:
            yield
        finally:
            await gateway.stop()
            await service.aclose()

    app = FastAPI(title="Donkit Guard", lifespan=lifespan, docs_url=None, redoc_url=None)
    app.add_middleware(BodyLimit, max_bytes=settings.max_body_bytes)
    _install_error_handlers(app)
    _register_client_routes(app)
    _register_admin_routes(app)
    _register_probes(app)
    return app

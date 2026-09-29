from __future__ import annotations

import asyncio
import fcntl
import os
from contextlib import asynccontextmanager
from pathlib import Path
from typing import Annotated

from fastapi import Depends, FastAPI, HTTPException, Request
from fastapi.responses import JSONResponse
from pydantic import ValidationError

from donkit_guard.scanning.models import (
    Access,
    Actor,
    AuditEvent,
    Contract,
    Grant,
    Project,
    ProjectCreate,
    Scan,
    ScanRequest,
    SettingsUpdate,
)

from .auth import identity
from .config import configuration
from .sources import snapshot_directory
from .store import Forbidden, Store
from .worker import work

ActorDep = Annotated[Actor, Depends(identity)]


def database(request: Request) -> Store:
    return request.app.state.store


StoreDep = Annotated[Store, Depends(database)]


class Health(Contract):
    status: str


class BodyLimit:
    def __init__(self, app):
        self.app = app

    async def __call__(self, scope, receive, send):
        size = 0

        async def limited_receive():
            nonlocal size
            message = await receive()
            if message["type"] == "http.request":
                size += len(message.get("body", b""))
                if size > 50_000_000:
                    raise HTTPException(413, "Snapshot request exceeds 50 MB")
            return message

        await self.app(scope, limited_receive, send)


def create_app(*, start_worker: bool = True) -> FastAPI:
    @asynccontextmanager
    async def lifespan(app: FastAPI):
        configuration()  # Invalid or missing credentials/configuration fail at startup.
        data = Path(os.environ.get("GUARD_SCANNER_DATA", "/data"))
        data.mkdir(parents=True, exist_ok=True, mode=0o700)
        # Shared SQLite is intentionally one replica/one uvicorn worker. Refuse
        # a second process instead of letting it recover a live worker's lease.
        with (data / "scanner.lock").open("w") as lock:
            fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
            store = Store(data / "scanner.sqlite3")
            app.state.store = store
            task = asyncio.create_task(work(store)) if start_worker else None
            app.state.worker = task
            try:
                yield
            finally:
                if task:
                    task.cancel()
                    await asyncio.gather(task, return_exceptions=True)
                store.db.close()

    app = FastAPI(title="Donkit Guard Security Scanner", version="1", lifespan=lifespan)
    app.add_middleware(BodyLimit)

    @app.exception_handler(Forbidden)
    async def forbidden_handler(request: Request, exc: Forbidden) -> JSONResponse:
        return JSONResponse(status_code=403, content={"detail": str(exc)})

    @app.get("/health", response_model=Health)
    async def health(request: Request) -> Health:
        task = request.app.state.worker
        if task is not None and task.done():
            raise HTTPException(503, "Scanner worker unavailable")
        return Health(status="ok")

    @app.get("/v1/access", response_model=Access)
    async def access(actor: ActorDep, store: StoreDep) -> Access:
        return store.access(actor)

    @app.put("/v1/settings", response_model=Access)
    async def settings(body: SettingsUpdate, actor: ActorDep, store: StoreDep) -> Access:
        return store.enable(actor, body.enabled)

    @app.get("/v1/grants", response_model=list[Grant])
    async def grants(actor: ActorDep, store: StoreDep) -> list[Grant]:
        return store.grants(actor)

    @app.put("/v1/grants", response_model=Grant)
    async def grant(body: Grant, actor: ActorDep, store: StoreDep) -> Grant:
        return store.set_grant(actor, body)

    @app.get("/v1/managed-projects", response_model=list[Project])
    async def managed_projects(actor: ActorDep, store: StoreDep) -> list[Project]:
        return store.projects(actor, administration=True)

    @app.get("/v1/projects", response_model=list[Project])
    async def projects(actor: ActorDep, store: StoreDep) -> list[Project]:
        return store.projects(actor)

    @app.post("/v1/projects", response_model=Project, status_code=201)
    async def create_project(body: ProjectCreate, actor: ActorDep, store: StoreDep) -> Project:
        if body.kind == "mounted" and not any(
            s.tenant_id == actor.tenant_id and s.key == body.source_ref
            for s in configuration().sources
        ):
            raise HTTPException(422, "Source is not registered for this organization")
        return store.create_project(actor, body)

    @app.get("/v1/projects/{project_id}", response_model=Project)
    async def project(project_id: str, actor: ActorDep, store: StoreDep) -> Project:
        return store.authorize(actor, project_id)

    @app.get("/v1/projects/{project_id}/scans", response_model=list[Scan])
    async def scans(project_id: str, actor: ActorDep, store: StoreDep) -> list[Scan]:
        return store.scans(actor, project_id)

    @app.post("/v1/projects/{project_id}/scans", response_model=Scan, status_code=202)
    async def start(project_id: str, body: ScanRequest, actor: ActorDep, store: StoreDep) -> Scan:
        project = store.authorize(actor, project_id, write=True)
        snapshot = body.snapshot
        if project.kind == "mounted":
            source = next(
                (
                    s
                    for s in configuration().sources
                    if s.tenant_id == actor.tenant_id and s.key == project.source_ref
                ),
                None,
            )
            if source is None:
                raise HTTPException(422, "Source is no longer registered")
            if snapshot is not None:
                raise HTTPException(422, "Mounted projects do not accept uploaded source")
            try:
                snapshot = await asyncio.to_thread(snapshot_directory, source.path)
            except (ValueError, OSError) as exc:
                raise HTTPException(422, "Source could not be exported within scan limits") from exc
        if snapshot is None:
            raise HTTPException(422, "This project requires a source snapshot")
        try:
            return store.create_scan(actor, project_id, snapshot, configuration().model)
        except ValidationError as exc:
            raise HTTPException(422, "Invalid snapshot") from exc

    @app.get("/v1/scans/{scan_id}", response_model=Scan)
    async def scan(scan_id: str, actor: ActorDep, store: StoreDep) -> Scan:
        return store.read_scan(actor, scan_id)

    @app.post("/v1/scans/{scan_id}/cancel", response_model=Scan)
    async def cancel(scan_id: str, actor: ActorDep, store: StoreDep) -> Scan:
        return store.cancel(actor, scan_id)

    @app.get("/v1/audit", response_model=list[AuditEvent])
    async def audit(actor: ActorDep, store: StoreDep) -> list[AuditEvent]:
        return store.audit(actor)

    return app


app = create_app()

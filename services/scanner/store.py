from __future__ import annotations

import sqlite3
from datetime import UTC, datetime, timedelta
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from pathlib import Path
from uuid import uuid4

from donkit_guard.scanning.models import (
    Access,
    Actor,
    AuditEvent,
    Grant,
    GuardRole,
    Project,
    ProjectCreate,
    Scan,
    ScanStatus,
    Snapshot,
)


class Forbidden(PermissionError):
    pass


class Store:
    """Single-replica durable queue. All transactions contain no awaits or external I/O."""

    def __init__(self, path: Path):
        path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        self.db = sqlite3.connect(path, check_same_thread=False)
        self.db.execute("PRAGMA journal_mode=WAL")
        self.db.executescript("""
            CREATE TABLE IF NOT EXISTS tenants (id TEXT PRIMARY KEY, enabled INTEGER NOT NULL);
            CREATE TABLE IF NOT EXISTS grants (
                tenant TEXT, user TEXT, body TEXT NOT NULL, PRIMARY KEY (tenant, user));
            CREATE TABLE IF NOT EXISTS projects (
                id TEXT PRIMARY KEY, tenant TEXT NOT NULL, body TEXT NOT NULL);
            CREATE TABLE IF NOT EXISTS scans (
                id TEXT PRIMARY KEY, tenant TEXT NOT NULL, project TEXT NOT NULL,
                status TEXT NOT NULL, body TEXT NOT NULL, snapshot TEXT,
                lease REAL NOT NULL DEFAULT 0, created REAL NOT NULL);
            CREATE INDEX IF NOT EXISTS scan_queue ON scans(status, created);
            CREATE TABLE IF NOT EXISTS audit (
                id TEXT PRIMARY KEY, tenant TEXT NOT NULL, body TEXT NOT NULL, created REAL NOT NULL);
            CREATE TABLE IF NOT EXISTS nonces (value TEXT PRIMARY KEY, created REAL NOT NULL);
        """)

    def access(self, actor: Actor) -> Access:
        row = self.db.execute(
            "SELECT enabled FROM tenants WHERE id=?", (actor.tenant_id,)
        ).fetchone()
        enabled = bool(row and row[0])
        grant = self.grant(actor)
        return Access(
            enabled=enabled,
            role=grant.role,
            can_manage=actor.account_owner or grant.role == GuardRole.ADMIN,
            can_view=enabled and grant.role is not None,
            can_scan=enabled and grant.role in (GuardRole.OPERATOR, GuardRole.ADMIN),
        )

    def grant(self, actor: Actor) -> Grant:
        row = self.db.execute(
            "SELECT body FROM grants WHERE tenant=? AND user=?", (actor.tenant_id, actor.user_id)
        ).fetchone()
        return Grant.model_validate_json(row[0]) if row else Grant(user_id=actor.user_id)

    def manage(self, actor: Actor) -> None:
        if not self.access(actor).can_manage:
            raise Forbidden("Guard administrator required")

    def authorize(self, actor: Actor, project_id: str, *, write: bool = False) -> Project:
        access = self.access(actor)
        if not access.can_view or (write and not access.can_scan):
            raise Forbidden("Guard permission required")
        row = self.db.execute(
            "SELECT body FROM projects WHERE id=? AND tenant=?", (project_id, actor.tenant_id)
        ).fetchone()
        if not row or project_id not in self.grant(actor).project_ids:
            raise Forbidden("Project permission required")
        return Project.model_validate_json(row[0])

    def event(self, actor: Actor, action: str, resource: str = "") -> None:
        event = AuditEvent(
            id=str(uuid4()),
            tenant_id=actor.tenant_id,
            user_id=actor.user_id,
            action=action,
            resource=resource,
            created_at=datetime.now(UTC),
        )
        self.db.execute(
            "INSERT INTO audit VALUES (?, ?, ?, ?)",
            (
                event.id,
                event.tenant_id,
                event.model_dump_json(),
                event.created_at.timestamp(),
            ),
        )

    def audit(self, actor: Actor) -> list[AuditEvent]:
        self.manage(actor)
        return [
            AuditEvent.model_validate_json(row[0])
            for row in self.db.execute(
                "SELECT body FROM audit WHERE tenant=? ORDER BY created DESC LIMIT 200",
                (actor.tenant_id,),
            )
        ]

    def enable(self, actor: Actor, enabled: bool) -> Access:
        self.manage(actor)
        with self.db:
            self.db.execute(
                "INSERT INTO tenants VALUES (?, ?) ON CONFLICT(id) DO UPDATE SET enabled=excluded.enabled",
                (actor.tenant_id, enabled),
            )
            self.event(actor, "extension.enabled" if enabled else "extension.disabled")
            self.revoke_pending()
        return self.access(actor)

    def grants(self, actor: Actor) -> list[Grant]:
        self.manage(actor)
        return [
            Grant.model_validate_json(row[0])
            for row in self.db.execute("SELECT body FROM grants WHERE tenant=?", (actor.tenant_id,))
        ]

    def set_grant(self, actor: Actor, grant: Grant) -> Grant:
        self.manage(actor)
        allowed = {p.id for p in self.projects(actor, administration=True)}
        if not set(grant.project_ids) <= allowed:
            raise Forbidden("Project belongs to another tenant or does not exist")
        with self.db:
            self.db.execute(
                "INSERT INTO grants VALUES (?, ?, ?) ON CONFLICT(tenant,user) DO UPDATE SET body=excluded.body",
                (actor.tenant_id, grant.user_id, grant.model_dump_json()),
            )
            self.event(actor, "grant.changed", grant.user_id)
            self.revoke_pending()
        return grant

    def projects(self, actor: Actor, *, administration: bool = False) -> list[Project]:
        if administration:
            self.manage(actor)
        elif not self.access(actor).can_view:
            raise Forbidden("Guard permission required")
        allowed = set(self.grant(actor).project_ids)
        return [
            Project.model_validate_json(body)
            for project_id, body in self.db.execute(
                "SELECT id, body FROM projects WHERE tenant=? ORDER BY rowid DESC",
                (actor.tenant_id,),
            )
            if administration or project_id in allowed
        ]

    def create_project(self, actor: Actor, body: ProjectCreate) -> Project:
        self.manage(actor)
        project = Project(
            id=str(uuid4()),
            tenant_id=actor.tenant_id,
            created_at=datetime.now(UTC),
            **body.model_dump(),
        )
        with self.db:
            self.db.execute(
                "INSERT INTO projects VALUES (?, ?, ?)",
                (project.id, project.tenant_id, project.model_dump_json()),
            )
            self.event(actor, "project.created", project.id)
        return project

    def create_scan(self, actor: Actor, project_id: str, snapshot: Snapshot, model: str) -> Scan:
        self.authorize(actor, project_id, write=True)
        now = datetime.now(UTC)
        scan = Scan(
            id=str(uuid4()),
            tenant_id=actor.tenant_id,
            project_id=project_id,
            actor=actor,
            status=ScanStatus.QUEUED,
            snapshot_digest=snapshot.digest(),
            revision=snapshot.revision,
            created_at=now,
            updated_at=now,
            model=model,
        )
        with self.db:
            pending = self.db.execute(
                "SELECT COUNT(*) FROM scans WHERE status IN ('queued','running') AND tenant=?",
                (actor.tenant_id,),
            ).fetchone()[0]
            if pending >= 10:
                raise Forbidden("Organization already has 10 pending scans")
            self.db.execute(
                "INSERT INTO scans VALUES (?, ?, ?, ?, ?, ?, 0, ?)",
                (
                    scan.id,
                    scan.tenant_id,
                    scan.project_id,
                    scan.status,
                    scan.model_dump_json(),
                    snapshot.model_dump_json(),
                    now.timestamp(),
                ),
            )
            self.event(actor, "scan.queued", scan.id)
        return scan

    def get(self, scan_id: str) -> Scan:
        row = self.db.execute("SELECT body FROM scans WHERE id=?", (scan_id,)).fetchone()
        if row is None:
            raise Forbidden("Scan unavailable")
        return Scan.model_validate_json(row[0])

    def read_scan(self, actor: Actor, scan_id: str) -> Scan:
        scan = self.get(scan_id)
        self.authorize(actor, scan.project_id)
        with self.db:
            self.event(actor, "scan.read", scan_id)
        return scan

    def scans(self, actor: Actor, project_id: str) -> list[Scan]:
        self.authorize(actor, project_id)
        return [
            Scan.model_validate_json(row[0])
            for row in self.db.execute(
                "SELECT json_remove(body, '$.findings') FROM scans WHERE tenant=? AND project=? ORDER BY created DESC LIMIT 100",
                (actor.tenant_id, project_id),
            )
        ]

    def save(self, scan: Scan, *, lease: float = 0) -> None:
        scan.updated_at = datetime.now(UTC)
        terminal = scan.status not in (ScanStatus.QUEUED, ScanStatus.RUNNING)
        self.db.execute(
            "UPDATE scans SET body=?, status=?, lease=?, snapshot=CASE WHEN ? THEN NULL ELSE snapshot END WHERE id=?",
            (scan.model_dump_json(), scan.status, lease, terminal, scan.id),
        )

    def cancel(self, actor: Actor, scan_id: str) -> Scan:
        scan = self.get(scan_id)
        self.authorize(actor, scan.project_id, write=True)
        with self.db:
            self.request_cancel(scan)
            self.event(actor, "scan.cancel_requested", scan_id)
        return scan

    def request_cancel(self, scan: Scan) -> None:
        if scan.status not in (ScanStatus.QUEUED, ScanStatus.RUNNING):
            return
        scan.cancel_requested = True
        if scan.status == ScanStatus.QUEUED:
            scan.status = ScanStatus.CANCELLED
        self.save(scan, lease=datetime.now(UTC).timestamp() + 30)

    def revoke_pending(self) -> None:
        for (body,) in self.db.execute(
            "SELECT body FROM scans WHERE status IN ('queued','running')"
        ).fetchall():
            scan = Scan.model_validate_json(body)
            try:
                self.authorize(scan.actor, scan.project_id, write=True)
            except Forbidden:
                self.request_cancel(scan)

    def claim(self) -> tuple[Scan, Snapshot] | None:
        with self.db:
            self.db.execute("BEGIN IMMEDIATE")
            now = datetime.now(UTC).timestamp()
            for (body,) in self.db.execute(
                "SELECT body FROM scans WHERE status='running' AND lease<?", (now,)
            ).fetchall():
                scan = Scan.model_validate_json(body)
                scan.status = ScanStatus.CANCELLED if scan.cancel_requested else ScanStatus.FAILED
                scan.error = "Worker interrupted; start a new scan"
                self.save(scan)
                self.event(scan.actor, "scan.interrupted", scan.id)
            row = self.db.execute(
                "SELECT body,snapshot FROM scans WHERE status='queued' ORDER BY created LIMIT 1"
            ).fetchone()
            if row is None:
                return None
            scan, snapshot = Scan.model_validate_json(row[0]), Snapshot.model_validate_json(row[1])
            scan.status = ScanStatus.RUNNING
            self.save(scan, lease=now + 30)
            self.event(scan.actor, "scan.started", scan.id)
            return scan, snapshot

    def heartbeat(self, scan_id: str) -> Scan:
        scan = self.get(scan_id)
        with self.db:
            self.save(scan, lease=datetime.now(UTC).timestamp() + 30)
        return scan

    def finish(self, scan: Scan) -> None:
        with self.db:
            # A cancellation arriving during report ingestion wins.
            if self.get(scan.id).cancel_requested:
                scan.cancel_requested = True
                scan.status = ScanStatus.CANCELLED
                scan.findings = []
            self.save(scan)
            self.event(scan.actor, f"scan.{scan.status}", scan.id)

    def consume_nonce(self, nonce: str) -> bool:
        now = datetime.now(UTC).timestamp()
        with self.db:
            self.db.execute("DELETE FROM nonces WHERE created<?", (now - 120,))
            try:
                self.db.execute("INSERT INTO nonces VALUES (?, ?)", (nonce, now))
            except sqlite3.IntegrityError:
                return False
        return True

    def prune(self, days: int) -> None:
        cutoff = (datetime.now(UTC) - timedelta(days=days)).timestamp()
        with self.db:
            self.db.execute(
                "DELETE FROM scans WHERE created<? AND status NOT IN ('queued','running')",
                (cutoff,),
            )
            self.db.execute("DELETE FROM audit WHERE created<?", (cutoff,))

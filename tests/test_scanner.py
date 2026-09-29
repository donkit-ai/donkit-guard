import asyncio
import base64
import hashlib
import hmac
import json
import time
from datetime import UTC, datetime

import pytest
from pydantic import ValidationError

from donkit_guard.scanning.models import (
    Actor,
    Grant,
    GuardRole,
    ProjectCreate,
    ScanStatus,
    Snapshot,
    SourceFile,
)
from donkit_guard.scanning.reports import ReportError, parse_report

pytest.importorskip("httpx")
pytest.importorskip("fastapi")
from fastapi.testclient import TestClient
from services.scanner import auth
from services.scanner.app import create_app
from services.scanner.config import Configuration, Token
from services.scanner.engine import EngineError
from services.scanner.sources import snapshot_directory
from services.scanner.store import Forbidden, Store
from services.scanner.worker import process_one


@pytest.fixture
def setup(tmp_path, monkeypatch):
    owner = Actor(tenant_id="internal", user_id="owner", account_owner=True)
    operator = Actor(tenant_id="internal", user_id="operator")
    viewer = Actor(tenant_id="internal", user_id="viewer")
    other = Actor(tenant_id="customer", user_id="owner", account_owner=True)
    config = Configuration(
        tokens=[
            Token(sha256=hashlib.sha256(a.user_id.encode()).hexdigest(), actor=a)
            for a in (owner, operator, viewer)
        ]
    )
    path = tmp_path / "config.json"
    path.write_text(config.model_dump_json())
    monkeypatch.setenv("GUARD_SCANNER_CONFIG", str(path))
    monkeypatch.setenv("GUARD_SCANNER_DATA", str(tmp_path / "data"))
    store = Store(tmp_path / "queue.sqlite3")
    store.enable(owner, True)
    project = store.create_project(owner, ProjectCreate(name="Donkit", kind="snapshot"))
    store.set_grant(
        owner, Grant(user_id=operator.user_id, role=GuardRole.OPERATOR, project_ids=[project.id])
    )
    store.set_grant(
        owner, Grant(user_id=viewer.user_id, role=GuardRole.VIEWER, project_ids=[project.id])
    )
    yield store, owner, operator, viewer, other, project, path
    store.db.close()


def source():
    return Snapshot(files=[SourceFile(path="src/tools/runtime.py", content="print('fixture')")])


def test_every_data_operation_is_tenant_and_project_scoped(setup):
    store, owner, operator, viewer, other, project, _ = setup
    scan = store.create_scan(operator, project.id, source(), "fixture")
    assert store.read_scan(viewer, scan.id).id == scan.id
    for actor in (other, owner, Actor(tenant_id="internal", user_id="ungranted")):
        for operation in (
            lambda actor=actor: store.read_scan(actor, scan.id),
            lambda actor=actor: store.scans(actor, project.id),
            lambda actor=actor: store.cancel(actor, scan.id),
            lambda actor=actor: store.create_scan(actor, project.id, source(), "fixture"),
        ):
            with pytest.raises(Forbidden):
                operation()
    with pytest.raises(Forbidden):
        store.create_scan(viewer, project.id, source(), "fixture")
    with pytest.raises(Forbidden):
        store.set_grant(
            other, Grant(user_id="owner", role=GuardRole.ADMIN, project_ids=[project.id])
        )


@pytest.mark.parametrize("change", ["role", "project", "disable"])
def test_revocation_cancels_durable_queue(setup, change):
    store, owner, operator, _, _, project, _ = setup
    scan = store.create_scan(operator, project.id, source(), "fixture")
    if change == "disable":
        store.enable(owner, False)
    else:
        store.set_grant(
            owner,
            Grant(
                user_id=operator.user_id, role=GuardRole.OPERATOR if change == "project" else None
            ),
        )
    assert store.get(scan.id).status == ScanStatus.CANCELLED
    assert store.claim() is None
    assert (
        store.db.execute("SELECT snapshot FROM scans WHERE id=?", (scan.id,)).fetchone()[0] is None
    )


async def test_worker_success_and_claim_is_not_delivered_twice(setup):
    store, _, operator, _, _, project, _ = setup
    scan = store.create_scan(operator, project.id, source(), "fixture")

    class Engine:
        async def run(self, snapshot, config):
            assert snapshot.digest() == scan.snapshot_digest
            assert store.claim() is None
            return []

    assert await process_one(store, Engine())
    assert store.get(scan.id).status == ScanStatus.COMPLETED
    assert store.get(scan.id).verification == "not_requested"
    assert not await process_one(store, Engine())


async def test_removed_standalone_identity_cannot_start_queued_work(setup):
    store, _, operator, _, _, project, config = setup
    scan = store.create_scan(operator, project.id, source(), "fixture")
    config.write_text(Configuration().model_dump_json())

    class Engine:
        async def run(self, *_):
            pytest.fail("Revoked user reached engine")

    await process_one(store, Engine())
    assert store.get(scan.id).status == ScanStatus.CANCELLED


async def test_active_revocation_cleans_up_engine(setup):
    store, owner, operator, _, _, project, _ = setup
    scan = store.create_scan(operator, project.id, source(), "fixture")
    cleaned = asyncio.Event()

    class Engine:
        async def run(self, *_):
            try:
                store.set_grant(owner, Grant(user_id=operator.user_id))
                await asyncio.Event().wait()
            finally:
                cleaned.set()

    await process_one(store, Engine())
    assert cleaned.is_set()
    assert store.get(scan.id).status == ScanStatus.CANCELLED


@pytest.mark.parametrize(
    "error,status",
    [
        (EngineError("engine failed"), ScanStatus.FAILED),
        (ReportError("incomplete"), ScanStatus.FAILED),
        (TimeoutError(), ScanStatus.TIMED_OUT),
    ],
)
async def test_worker_failure_is_not_a_clean_scan(setup, error, status):
    store, _, operator, _, _, project, _ = setup
    scan = store.create_scan(operator, project.id, source(), "fixture")

    class Engine:
        async def run(self, *_):
            raise error

    await process_one(store, Engine())
    assert store.get(scan.id).status == status
    assert store.get(scan.id).error


def test_expired_worker_lease_becomes_failure(setup):
    store, _, operator, _, _, project, _ = setup
    scan = store.create_scan(operator, project.id, source(), "fixture")
    store.claim()
    with store.db:
        store.db.execute(
            "UPDATE scans SET lease=? WHERE id=?", (datetime.now(UTC).timestamp() - 60, scan.id)
        )
    assert store.claim() is None
    assert store.get(scan.id).status == ScanStatus.FAILED


@pytest.mark.parametrize(
    "path",
    [
        "../secret",
        "/root/x",
        "a//b",
        "a/./b",
        "a\\b",
        ".env",
        "a/.env.prod",
        ".git/config",
        ".aws/credentials",
        ".openhack.md",
    ],
)
def test_snapshot_paths(path):
    with pytest.raises(ValidationError):
        SourceFile(path=path, content="secret")


def test_snapshot_collision_and_digest_order():
    a, b = SourceFile(path="a", content="1"), SourceFile(path="b", content="2")
    assert Snapshot(files=[a, b]).digest() == Snapshot(files=[b, a]).digest()
    for files in ([a, a], [a, SourceFile(path="a/b", content="")]):
        with pytest.raises(ValidationError):
            Snapshot(files=files)


def test_mounted_export_excludes_credentials_and_symlinks_includes_tools(tmp_path):
    (tmp_path / "tools").mkdir()
    (tmp_path / "tools/runtime.py").write_text("hello")
    (tmp_path / ".env").write_text("SECRET=x")
    (tmp_path / "linked.py").symlink_to(tmp_path / ".env")
    snapshot = snapshot_directory(tmp_path)
    assert [f.path for f in snapshot.files] == ["tools/runtime.py"]


def report(**updates):
    body = {
        "version": 3,
        "status": "completed",
        "findings": [],
        "trace": [{"event_type": "scan_complete"}],
    }
    body.update(updates)
    return json.dumps(body).encode()


@pytest.mark.parametrize(
    "raw",
    [
        b"broken",
        report(status="failed"),
        report(status="running"),
        report(version=2),
        report(trace=[]),
        report(trace=[{"event_type": "sandbox_error"}]),
    ],
)
def test_bad_reports(raw):
    with pytest.raises(ReportError):
        parse_report(raw)


def test_model_validated_does_not_mean_reproduced():
    raw = report(
        findings=[
            {
                "id": "1",
                "severity": "high",
                "title": "IDOR",
                "description": "desc",
                "filePath": "api.py",
                "validated": True,
            }
        ]
    )
    assert parse_report(raw)[0].verification == "code_review"


def test_standalone_api_bootstrap_and_non_admin_access(setup):
    with TestClient(create_app(start_worker=False)) as client:
        assert client.get("/v1/projects").status_code == 401
        owner = {"Authorization": "Bearer owner"}
        operator = {"Authorization": "Bearer operator"}
        assert client.put("/v1/settings", headers=owner, json={"enabled": True}).status_code == 200
        project = client.post(
            "/v1/projects", headers=owner, json={"name": "App", "kind": "snapshot"}
        ).json()
        assert client.get("/v1/projects", headers=operator).status_code == 403
        assert (
            client.put(
                "/v1/grants",
                headers=owner,
                json={"user_id": "operator", "role": "operator", "project_ids": [project["id"]]},
            ).status_code
            == 200
        )
        scan = client.post(
            f"/v1/projects/{project['id']}/scans",
            headers=operator,
            json={"snapshot": source().model_dump()},
        )
        assert scan.status_code == 202
        assert client.get(f"/v1/scans/{scan.json()['id']}", headers=owner).status_code == 403
        assert (
            client.post(f"/v1/scans/{scan.json()['id']}/cancel", headers=operator).json()["status"]
            == "cancelled"
        )


def test_host_identity_cannot_be_forged_or_replayed(setup, monkeypatch):
    *_, path = setup
    secret = "x" * 40
    path.write_text(json.dumps({"host_secret": secret, "membership_url": "http://host/member"}))

    async def active(*_):
        return True

    monkeypatch.setattr(auth, "active", active)
    actor = Actor(tenant_id="host", user_id="employee", issuer="donkit")
    encoded = base64.urlsafe_b64encode(actor.model_dump_json().encode()).decode()
    timestamp, nonce = str(int(time.time())), "a" * 32
    message = "\n".join(
        ("GET", "/v1/access", hashlib.sha256(b"").hexdigest(), timestamp, nonce, encoded)
    )
    headers = {
        "x-guard-actor": encoded,
        "x-guard-time": timestamp,
        "x-guard-nonce": nonce,
        "x-guard-signature": hmac.new(
            secret.encode(), message.encode(), hashlib.sha256
        ).hexdigest(),
    }
    with TestClient(create_app(start_worker=False)) as client:
        forged = headers | {
            "x-guard-actor": base64.urlsafe_b64encode(
                actor.model_copy(update={"account_owner": True}).model_dump_json().encode()
            ).decode()
        }
        assert client.get("/v1/access", headers=forged).status_code == 401
        assert client.get("/v1/access", headers=headers).status_code == 200
        assert client.get("/v1/access", headers=headers).status_code == 401


def test_multibyte_source_limit_is_measured_in_bytes():
    with pytest.raises(ValidationError, match="1 MB"):
        SourceFile(path="large.py", content="€" * 334_000)


def test_mounted_source_rejects_symlinks_in_parent_directories(tmp_path):
    real = tmp_path / "private" / "repo"
    real.mkdir(parents=True)
    (real / "config.json").write_text('{"secret":"must not export"}')
    (tmp_path / "parent-link").symlink_to(tmp_path / "private", target_is_directory=True)
    with pytest.raises(OSError):
        snapshot_directory(tmp_path / "parent-link" / "repo")

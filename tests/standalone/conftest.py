from __future__ import annotations

import hashlib
import shutil
from pathlib import Path
from typing import TYPE_CHECKING, Any

import httpx
import pytest

from donkit_guard.detectors.runner import ExecutorKind
from donkit_guard_standalone.api import create_app
from donkit_guard_standalone.settings import ApiKey, Settings

if TYPE_CHECKING:
    from collections.abc import AsyncIterator, Callable

    from fastapi import FastAPI

    from donkit_guard_standalone.service import GuardService

ROOT = Path(__file__).resolve().parents[2]
POLICY = ROOT / "examples" / "policies" / "standalone.yaml"
CATALOG = ROOT / "examples" / "standalone" / "tools.yaml"
# An AWS-shaped access key id, assembled at runtime so that secret scanners stay quiet about
# this file.
SECRET = "AKIA" + "5RQTGNW2K4XQZJ7L"
ACME_KEY = "acme-client-key"
GLOBEX_KEY = "globex-client-key"
ADMIN_TOKEN = "admin-token-for-tests-only"
ADMIN = {"Authorization": f"Bearer {ADMIN_TOKEN}"}
ACME = {"X-API-Key": ACME_KEY}
GLOBEX = {"X-API-Key": GLOBEX_KEY}


def _sha256(value: str) -> str:
    return hashlib.sha256(value.encode()).hexdigest()


@pytest.fixture
def policy_file(tmp_path: Path) -> Path:
    path = tmp_path / "policy.yaml"
    shutil.copy(POLICY, path)
    return path


@pytest.fixture
def make_settings(tmp_path: Path, policy_file: Path) -> Callable[..., Settings]:
    def make(**overrides: Any) -> Settings:
        values: dict[str, Any] = {
            "policy_file": policy_file,
            "policy_check_interval_s": 0.0,
            "tool_catalog_file": CATALOG,
            "db_url": f"sqlite+aiosqlite:///{tmp_path / 'guard.db'}",
            "pii_disabled": True,
            "api_keys": (
                ApiKey(sha256=_sha256(ACME_KEY), tenant="acme", name="acme-app"),
                ApiKey(sha256=_sha256(GLOBEX_KEY), tenant="globex"),
            ),
            "admin_token": ADMIN_TOKEN,
            "grpc_host": "127.0.0.1",
            "grpc_port": 0,
            "detector_executor": ExecutorKind.SYNC,
            "approval_sweep_interval_s": 3600.0,
            "max_body_bytes": 64 * 1024,
        }
        values.update(overrides)
        return Settings(**values)

    return make


class Running:
    def __init__(self, app: FastAPI, client: httpx.AsyncClient) -> None:
        self.app = app
        self.client = client

    @property
    def service(self) -> GuardService:
        service: GuardService = self.app.state.service
        return service


@pytest.fixture
def start() -> Callable[[Settings], Any]:
    """Start the service on the given settings; the caller enters the returned context."""
    from contextlib import asynccontextmanager

    @asynccontextmanager
    async def run(settings: Settings) -> AsyncIterator[Running]:
        app = create_app(settings)
        async with app.router.lifespan_context(app):
            transport = httpx.ASGITransport(app=app)
            async with httpx.AsyncClient(transport=transport, base_url="http://guard") as client:
                yield Running(app, client)

    return run


@pytest.fixture
async def running(
    start: Callable[[Settings], Any], make_settings: Callable[..., Settings]
) -> AsyncIterator[Running]:
    async with start(make_settings()) as service:
        yield service

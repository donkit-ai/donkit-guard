"""The approval store over a migrated SQLite database: compare-and-set transitions and expiry."""

from __future__ import annotations

import asyncio
from datetime import UTC, datetime, timedelta
from typing import TYPE_CHECKING

import pytest

from donkit_guard.approvals import ApprovalDecisionValue, ApprovalRecord, ApprovalStatus
from donkit_guard_standalone import db
from donkit_guard_standalone.storage import SqlApprovalStore

if TYPE_CHECKING:
    from collections.abc import AsyncIterator
    from pathlib import Path

NOW = datetime(2026, 11, 9, 12, 0, tzinfo=UTC)


@pytest.fixture
async def store(tmp_path: Path) -> AsyncIterator[SqlApprovalStore]:
    url = f"sqlite+aiosqlite:///{tmp_path / 'store.db'}"
    await db.migrate(url)
    engine = db.open_engine(url)
    try:
        yield SqlApprovalStore(db.sessions(engine))
    finally:
        await engine.dispose()


async def _pending(store: SqlApprovalStore, ttl_s: int = 300) -> ApprovalRecord:
    return await store.create(
        ApprovalRecord(
            tenant_id="acme",
            principal_id="user-1",
            context_hash="c" * 64,
            action_digest="d" * 64,
            tool="create_ticket",
            display_args_redacted={"/title": "Refund"},
            policy_version="standalone-1@abc",
            created_at=NOW,
            expires_at=NOW + timedelta(seconds=ttl_s),
        )
    )


async def test_an_approval_is_consumed_exactly_once(store: SqlApprovalStore) -> None:
    record = await _pending(store)
    decided = await store.decide(record.id, ApprovalDecisionValue.APPROVE, "user-1", NOW)
    assert decided is not None and decided.status is ApprovalStatus.APPROVED
    assert decided.expires_at == record.expires_at
    found = await store.find_decided("acme", "d" * 64, "c" * 64)
    assert found is not None and found.id == record.id
    results = await asyncio.gather(*(store.consume(record.id, NOW) for _ in range(5)))
    consumed = [r for r in results if r is not None]
    assert len(consumed) == 1 and consumed[0].status is ApprovalStatus.CONSUMED
    assert await store.find_decided("acme", "d" * 64, "c" * 64) is None


@pytest.mark.parametrize(
    ("responder", "at", "status"),
    [
        ("user-2", NOW, ApprovalStatus.PENDING),
        ("user-1", NOW + timedelta(seconds=301), ApprovalStatus.EXPIRED),
    ],
)
async def test_only_the_principal_decides_and_only_in_time(
    store: SqlApprovalStore, responder: str, at: datetime, status: ApprovalStatus
) -> None:
    record = await _pending(store)
    assert await store.decide(record.id, ApprovalDecisionValue.APPROVE, responder, at) is None
    current = await store.get(record.id)
    assert current is not None and current.status is status


async def test_expired_approvals_are_swept_and_never_consumed(store: SqlApprovalStore) -> None:
    short = await _pending(store, ttl_s=10)
    approved = await _pending(store, ttl_s=10)
    await store.decide(approved.id, ApprovalDecisionValue.APPROVE, "user-1", NOW)
    later = NOW + timedelta(seconds=11)
    assert await store.consume(approved.id, later) is None
    assert await store.expire_pending(later) == 1
    swept = await store.get(short.id)
    assert swept is not None and swept.status is ApprovalStatus.EXPIRED

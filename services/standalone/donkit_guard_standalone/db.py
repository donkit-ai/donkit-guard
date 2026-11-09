"""Tables of the service and the database they live in: SQLite by default, PostgreSQL in production.

Times are stored as naive UTC in ``TIMESTAMP`` columns, which both databases compare the same
way, and handed back to Python as aware UTC datetimes.
"""

from __future__ import annotations

import asyncio
from datetime import UTC, datetime
from importlib import resources
from typing import Any

from alembic import command
from alembic.config import Config
from sqlalchemy import (
    JSON,
    BigInteger,
    DateTime,
    Dialect,
    Index,
    Integer,
    String,
    Text,
    TypeDecorator,
    text,
)
from sqlalchemy.ext.asyncio import AsyncEngine, async_sessionmaker, create_async_engine
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column

# SQLite assigns rowids only to an INTEGER PRIMARY KEY; PostgreSQL needs the wider type.
SeqType = BigInteger().with_variant(Integer(), "sqlite")


class UTCDateTime(TypeDecorator[datetime]):
    impl = DateTime(timezone=False)
    cache_ok = True

    def process_bind_param(self, value: datetime | None, dialect: Dialect) -> datetime | None:
        if value is None:
            return None
        if value.tzinfo is None:
            raise ValueError("naive datetimes are ambiguous; pass an aware UTC datetime")
        return value.astimezone(UTC).replace(tzinfo=None)

    def process_result_value(self, value: datetime | None, dialect: Dialect) -> datetime | None:
        return value.replace(tzinfo=UTC) if value is not None else None


class Base(DeclarativeBase):
    pass


class DecisionRow(Base):
    """One decision with what followed it: its execution and the late findings."""

    __tablename__ = "decisions"

    seq: Mapped[int] = mapped_column(SeqType, primary_key=True, autoincrement=True)
    decision_id: Mapped[str] = mapped_column(String(64), unique=True)
    occurred_at: Mapped[datetime] = mapped_column(UTCDateTime())
    tenant_id: Mapped[str | None] = mapped_column(String(255))
    run_id: Mapped[str] = mapped_column(String(255))
    agent_id: Mapped[str | None] = mapped_column(String(255))
    principal_id: Mapped[str | None] = mapped_column(String(255))
    action_kind: Mapped[str] = mapped_column(String(32))
    tool: Mapped[str | None] = mapped_column(String(255))
    outcome: Mapped[str] = mapped_column(String(32))
    code: Mapped[str] = mapped_column(String(64))
    mode: Mapped[str] = mapped_column(String(16))
    policy_version: Mapped[str] = mapped_column(String(255))
    event: Mapped[dict[str, Any]] = mapped_column(JSON)
    execution: Mapped[dict[str, Any] | None] = mapped_column(JSON)
    findings: Mapped[dict[str, Any] | None] = mapped_column(JSON)

    __table_args__ = (
        Index("ix_decisions_tenant_seq", "tenant_id", "seq"),
        Index("ix_decisions_run_seq", "run_id", "seq"),
        Index("ix_decisions_agent_seq", "agent_id", "seq"),
    )


class ApprovalRow(Base):
    __tablename__ = "approvals"

    id: Mapped[str] = mapped_column(String(64), primary_key=True)
    tenant_id: Mapped[str | None] = mapped_column(String(255))
    principal_id: Mapped[str] = mapped_column(String(255))
    context_hash: Mapped[str] = mapped_column(String(64))
    action_digest: Mapped[str] = mapped_column(String(64))
    tool: Mapped[str | None] = mapped_column(String(255))
    resource: Mapped[str | None] = mapped_column(Text)
    display_args_redacted: Mapped[dict[str, str]] = mapped_column(JSON)
    expected_change: Mapped[str] = mapped_column(Text)
    reason: Mapped[str] = mapped_column(Text)
    policy_version: Mapped[str] = mapped_column(String(255))
    status: Mapped[str] = mapped_column(String(16))
    created_at: Mapped[datetime] = mapped_column(UTCDateTime())
    expires_at: Mapped[datetime] = mapped_column(UTCDateTime())
    decided_by: Mapped[str | None] = mapped_column(String(255))
    decided_at: Mapped[datetime | None] = mapped_column(UTCDateTime())
    consumed_at: Mapped[datetime | None] = mapped_column(UTCDateTime())

    __table_args__ = (
        Index("ix_approvals_binding", "tenant_id", "action_digest", "context_hash"),
        Index("ix_approvals_status_expires", "status", "expires_at"),
    )


class PolicyVersionRow(Base):
    """Every policy text the service applied, so a decision's ``policy_version`` can be traced."""

    __tablename__ = "policy_versions"

    seq: Mapped[int] = mapped_column(SeqType, primary_key=True, autoincrement=True)
    version: Mapped[str] = mapped_column(String(255), unique=True)
    sha256: Mapped[str] = mapped_column(String(64))
    path: Mapped[str] = mapped_column(Text)
    mode: Mapped[str] = mapped_column(String(16))
    loaded_at: Mapped[datetime] = mapped_column(UTCDateTime())


def open_engine(url: str) -> AsyncEngine:
    return create_async_engine(url, pool_pre_ping=not url.startswith("sqlite"))


def sessions(engine: AsyncEngine) -> async_sessionmaker[Any]:
    return async_sessionmaker(engine, expire_on_commit=False)


def _alembic_config(url: str) -> Config:
    config = Config()
    config.set_main_option(
        "script_location", str(resources.files("donkit_guard_standalone") / "migrations")
    )
    # A percent sign in a password would otherwise be read as configparser interpolation.
    config.set_main_option("sqlalchemy.url", url.replace("%", "%%"))
    return config


async def migrate(url: str) -> None:
    """Bring the schema to the latest revision; the migrations run their own event loop."""
    await asyncio.to_thread(command.upgrade, _alembic_config(url), "head")


async def ping(engine: AsyncEngine) -> None:
    async with engine.connect() as connection:
        await connection.execute(text("SELECT 1"))

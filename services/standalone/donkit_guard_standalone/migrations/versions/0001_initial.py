"""Decisions, approvals and policy versions.

Revision ID: 0001
Revises:
Create Date: 2026-11-09
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op

revision = "0001"
down_revision = None
branch_labels = None
depends_on = None

# Matches donkit_guard_standalone.db.SeqType: SQLite only assigns rowids to INTEGER keys.
SEQ = sa.BigInteger().with_variant(sa.Integer(), "sqlite")


def upgrade() -> None:
    op.create_table(
        "decisions",
        sa.Column("seq", SEQ, primary_key=True, autoincrement=True),
        sa.Column("decision_id", sa.String(64), nullable=False, unique=True),
        sa.Column("occurred_at", sa.DateTime(), nullable=False),
        sa.Column("tenant_id", sa.String(255)),
        sa.Column("run_id", sa.String(255), nullable=False),
        sa.Column("agent_id", sa.String(255)),
        sa.Column("principal_id", sa.String(255)),
        sa.Column("action_kind", sa.String(32), nullable=False),
        sa.Column("tool", sa.String(255)),
        sa.Column("outcome", sa.String(32), nullable=False),
        sa.Column("code", sa.String(64), nullable=False),
        sa.Column("mode", sa.String(16), nullable=False),
        sa.Column("policy_version", sa.String(255), nullable=False),
        sa.Column("event", sa.JSON(), nullable=False),
        sa.Column("execution", sa.JSON()),
        sa.Column("findings", sa.JSON()),
    )
    op.create_index("ix_decisions_tenant_seq", "decisions", ["tenant_id", "seq"])
    op.create_index("ix_decisions_run_seq", "decisions", ["run_id", "seq"])
    op.create_index("ix_decisions_agent_seq", "decisions", ["agent_id", "seq"])

    op.create_table(
        "approvals",
        sa.Column("id", sa.String(64), primary_key=True),
        sa.Column("tenant_id", sa.String(255)),
        sa.Column("principal_id", sa.String(255), nullable=False),
        sa.Column("context_hash", sa.String(64), nullable=False),
        sa.Column("action_digest", sa.String(64), nullable=False),
        sa.Column("tool", sa.String(255)),
        sa.Column("resource", sa.Text()),
        sa.Column("display_args_redacted", sa.JSON(), nullable=False),
        sa.Column("expected_change", sa.Text(), nullable=False),
        sa.Column("reason", sa.Text(), nullable=False),
        sa.Column("policy_version", sa.String(255), nullable=False),
        sa.Column("status", sa.String(16), nullable=False),
        sa.Column("created_at", sa.DateTime(), nullable=False),
        sa.Column("expires_at", sa.DateTime(), nullable=False),
        sa.Column("decided_by", sa.String(255)),
        sa.Column("decided_at", sa.DateTime()),
        sa.Column("consumed_at", sa.DateTime()),
    )
    op.create_index(
        "ix_approvals_binding", "approvals", ["tenant_id", "action_digest", "context_hash"]
    )
    op.create_index("ix_approvals_status_expires", "approvals", ["status", "expires_at"])

    op.create_table(
        "policy_versions",
        sa.Column("seq", SEQ, primary_key=True, autoincrement=True),
        sa.Column("version", sa.String(255), nullable=False, unique=True),
        sa.Column("sha256", sa.String(64), nullable=False),
        sa.Column("path", sa.Text(), nullable=False),
        sa.Column("mode", sa.String(16), nullable=False),
        sa.Column("loaded_at", sa.DateTime(), nullable=False),
    )


def downgrade() -> None:
    op.drop_table("policy_versions")
    op.drop_table("approvals")
    op.drop_table("decisions")

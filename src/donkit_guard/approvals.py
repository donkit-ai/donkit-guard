"""Approval records: one decision per exact action, bound to a principal and a policy version."""

from __future__ import annotations

import uuid
from datetime import datetime
from enum import StrEnum

from pydantic import Field

from donkit_guard.context import FrozenModel


class ApprovalStatus(StrEnum):
    PENDING = "pending"
    APPROVED = "approved"
    DENIED = "denied"
    EXPIRED = "expired"
    CONSUMED = "consumed"
    STALE = "stale"


class DeliveryMode(StrEnum):
    """How the pending decision reached its approver, or that it needed no channel."""

    INLINE = "inline"
    QUEUED = "queued"
    UNAVAILABLE = "unavailable"
    CONSUMED = "consumed"


class ApprovalDecisionValue(StrEnum):
    APPROVE = "approve"
    REJECT = "reject"


class ApprovalRecord(FrozenModel):
    id: str = Field(default_factory=lambda: uuid.uuid4().hex)
    tenant_id: str | None = None
    principal_id: str
    context_hash: str
    action_digest: str
    tool: str | None = None
    resource: str | None = None
    display_args_redacted: dict[str, str] = Field(default_factory=dict)
    expected_change: str = ""
    reason: str = ""
    policy_version: str
    status: ApprovalStatus = ApprovalStatus.PENDING
    created_at: datetime
    expires_at: datetime
    decided_by: str | None = None
    decided_at: datetime | None = None
    consumed_at: datetime | None = None

    def is_expired(self, now: datetime) -> bool:
        return now >= self.expires_at


class Delivered(FrozenModel):
    mode: DeliveryMode
    approval_id: str

"""Domain errors of the standalone service; the HTTP layer maps each to one status code."""

from __future__ import annotations


class ApprovalNotFound(LookupError):
    """No approval has this id."""


class ApprovalNotPending(ValueError):
    """The approval was already decided, used, expired or invalidated."""


class ApprovalExpired(ValueError):
    """The approval expired before an answer came."""


class ResponderMismatch(PermissionError):
    """Only the principal the approval was asked of may answer it."""


class TenantMismatch(PermissionError):
    """The request names a tenant other than the one its API key belongs to."""

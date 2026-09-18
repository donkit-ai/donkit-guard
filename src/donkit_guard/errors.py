"""Exceptions raised across the core boundary."""

from __future__ import annotations


class GuardError(Exception):
    """Base class for every error raised by the core."""


class PolicyError(GuardError):
    """A policy document failed to load or validate."""


class AuditWriteError(GuardError):
    """The audit sink could not persist a critical event."""


class GuardDeniedError(GuardError):
    """Raised by hosts that turn a deny decision into control flow."""

    def __init__(self, code: str, explanation: str, decision_id: str | None = None) -> None:
        super().__init__(f"{code}: {explanation}")
        self.code = code
        self.explanation = explanation
        self.decision_id = decision_id

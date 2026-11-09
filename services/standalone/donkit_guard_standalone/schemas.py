"""Request and response models of the HTTP API."""

from __future__ import annotations

from datetime import datetime
from typing import Any, Literal

from pydantic import Field, JsonValue, model_validator

from donkit_guard.approvals import ApprovalDecisionValue, ApprovalRecord
from donkit_guard.context import FrozenModel, GuardContext
from donkit_guard.decision import Decision
from donkit_guard.payload import SegmentSource, SegmentTrust


class PayloadItem(FrozenModel):
    """One piece of content the action carries: a text, or a JSON value whose leaves are read.

    A tool call's ``context.action.arguments`` are inspected without being repeated here.
    """

    source: SegmentSource
    trust: SegmentTrust = SegmentTrust.UNTRUSTED
    text: str | None = None
    data: JsonValue = None
    lang: str | None = None

    @model_validator(mode="after")
    def _text_or_data(self) -> PayloadItem:
        if (self.text is None) == (self.data is None):
            raise ValueError("an item carries exactly one of text and data")
        return self


class AuthorizeRequest(FrozenModel):
    context: GuardContext
    payload: tuple[PayloadItem, ...] = ()
    # Segment ids an earlier call already scanned in this conversation; they are not rescanned.
    seen_segments: tuple[str, ...] = ()
    # Shown on the approval card: what the action will change, in the application's words.
    expected_change: str = Field(default="", max_length=2000)


class MaskedItem(FrozenModel):
    text: str | None = None
    data: JsonValue = None


class AuthorizeResponse(FrozenModel):
    decision: Decision
    # Set when the outcome is `mask`: the payload items, in order, as the destination may
    # receive them.
    masked_payload: tuple[MaskedItem, ...] | None = None
    # Set when the outcome is `mask` and the tool's maskable arguments were masked.
    masked_arguments: dict[str, Any] | None = None


class ExecutionRequest(FrozenModel):
    decision_id: str = Field(min_length=1)
    outcome: Literal["success", "error", "skipped"]
    error_class: str | None = Field(default=None, max_length=255)
    duration_ms: float = Field(default=0.0, ge=0.0)


class Recorded(FrozenModel):
    recorded: bool = True


class ApprovalList(FrozenModel):
    items: tuple[ApprovalRecord, ...] = ()


class DecideRequest(FrozenModel):
    decision: ApprovalDecisionValue
    # The principal answering, as the integrating application authenticated them; it has to
    # be the principal the approval was asked of.
    responder: str = Field(min_length=1)


class RuleView(FrozenModel):
    layer: str
    id: str
    action: str
    hard: bool
    description: str
    reason: str


class PolicyView(FrozenModel):
    version: str
    document_version: str
    sha256: str
    path: str
    mode: str
    loaded_at: datetime
    rules: tuple[RuleView, ...]
    # The error of the last refused reload; null when the file on disk is the one applied.
    last_error: str | None = None


class ReloadView(FrozenModel):
    changed: bool
    version: str
    error: str | None = None


class ErrorBody(FrozenModel):
    error: str
    detail: str = ""

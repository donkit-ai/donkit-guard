"""From an HTTP authorize request to the payload the guard inspects, and back to masked content."""

from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING, Any

from donkit_guard.context import ActionKind
from donkit_guard.decision import Outcome
from donkit_guard.payload import Payload, Segment, SegmentSource, SegmentTrust, set_json_pointer
from donkit_guard_standalone.schemas import AuthorizeResponse, MaskedItem

if TYPE_CHECKING:
    from collections.abc import Mapping

    from donkit_guard.decision import Decision
    from donkit_guard_standalone.schemas import AuthorizeRequest, PayloadItem


@dataclass(frozen=True)
class _Item:
    item: PayloadItem
    payload: Payload


@dataclass(frozen=True)
class _Arguments:
    value: dict[str, Any]
    payload: Payload


@dataclass(frozen=True)
class Inspection:
    """The payload of a request, built item by item so that masks can be mapped back."""

    items: tuple[_Item, ...]
    arguments: _Arguments | None

    @property
    def payload(self) -> Payload:
        segments = [s for part in self.items for s in part.payload.segments]
        if self.arguments is not None:
            segments.extend(self.arguments.payload.segments)
        return Payload(segments=tuple(segments))

    def response(self, decision: Decision) -> AuthorizeResponse:
        if decision.outcome is not Outcome.MASK:
            return AuthorizeResponse(decision=decision)
        masks = decision.masked_segments
        items = tuple(_masked_item(part, masks) for part in self.items)
        arguments = None
        if self.arguments is not None and any(
            s.id in masks for s in self.arguments.payload.segments
        ):
            arguments = _masked_json(self.arguments.payload, self.arguments.value, masks)
        return AuthorizeResponse(
            decision=decision, masked_payload=items, masked_arguments=arguments
        )


def _item_payload(item: PayloadItem) -> Payload:
    if item.text is not None:
        segment = Segment.of_text(item.text, source=item.source, trust=item.trust, lang=item.lang)
        return Payload(segments=(segment,))
    return Payload.from_json(item.data, source=item.source, trust=item.trust, lang=item.lang)


def _masked_json(payload: Payload, value: Any, masks: Mapping[str, str]) -> Any:
    for segment in payload.segments:
        if segment.id in masks:
            value = set_json_pointer(value, segment.path, masks[segment.id])
    return value


def _masked_item(part: _Item, masks: Mapping[str, str]) -> MaskedItem:
    if part.item.text is not None:
        segment = part.payload.segments[0]
        return MaskedItem(text=masks.get(segment.id, part.item.text))
    return MaskedItem(data=_masked_json(part.payload, part.item.data, masks))


def inspect(request: AuthorizeRequest) -> Inspection:
    """The segments of every payload item, plus the arguments of a tool call."""
    items = tuple(_Item(item=item, payload=_item_payload(item)) for item in request.payload)
    action = request.context.action
    arguments = None
    if action.kind is ActionKind.TOOL_CALL and action.arguments:
        value = dict(action.arguments)
        arguments = _Arguments(
            value=value,
            payload=Payload.from_json(
                value, source=SegmentSource.TOOL_ARGS, trust=SegmentTrust.TRUSTED
            ),
        )
    return Inspection(items=items, arguments=arguments)

"""OpenAI-compatible chat completions as the guard sees them: segments to inspect, masks to apply.

Every piece of text a request or a response carries becomes a segment whose path is the JSON
pointer of that text in the body, so a mask is written back exactly where the text was and
everything around it (``tool_calls``, ``tool_call_id``, ``tools``) reaches the upstream intact.
Content the detectors cannot read, an image or an audio part, is an uninspected segment, which
the policy's ``unsupported_content`` decides on.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any

from donkit_guard.payload import (
    Payload,
    Segment,
    SegmentSource,
    SegmentTrust,
    escape_pointer_token,
    set_json_pointer,
)

if TYPE_CHECKING:
    from collections.abc import Iterator, Mapping

CHAT_COMPLETIONS_SUFFIX = "/chat/completions"

_ROLES: dict[str, tuple[SegmentSource, SegmentTrust]] = {
    "system": (SegmentSource.SYSTEM, SegmentTrust.TRUSTED),
    "developer": (SegmentSource.SYSTEM, SegmentTrust.TRUSTED),
    "user": (SegmentSource.USER, SegmentTrust.TRUSTED),
    "assistant": (SegmentSource.ASSISTANT, SegmentTrust.UNTRUSTED),
    "tool": (SegmentSource.TOOL_RESULT, SegmentTrust.UNTRUSTED),
    "function": (SegmentSource.TOOL_RESULT, SegmentTrust.UNTRUSTED),
}
_UNKNOWN_ROLE = (SegmentSource.USER, SegmentTrust.UNTRUSTED)


class ChatBodyError(ValueError):
    """The body is not a chat completion the guard can read."""


@dataclass(frozen=True)
class ChatBody:
    """A parsed body and the segments it carries."""

    body: dict[str, Any]
    payload: Payload
    model: str
    untrusted_content_seen: bool = False

    def masked(self, masks: Mapping[str, str]) -> bytes:
        """The body with every masked segment written back at its JSON pointer."""
        body: Any = self.body
        for segment in self.payload.segments:
            if segment.id in masks:
                body = set_json_pointer(body, segment.path, masks[segment.id])
        return dump(body)


def dump(body: Any) -> bytes:
    return json.dumps(body, ensure_ascii=False, separators=(",", ":")).encode("utf-8")


def _load(raw: bytes) -> dict[str, Any]:
    try:
        body = json.loads(raw)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ChatBodyError(f"the body is not JSON: {exc}") from exc
    if not isinstance(body, dict):
        raise ChatBodyError("the body is not a JSON object")
    return body


def _text_segment(
    text: Any, path: str, source: SegmentSource, trust: SegmentTrust
) -> Segment | None:
    if not isinstance(text, str) or not text:
        return None
    return Segment.of_text(text, source=source, trust=trust, path=path)


def _content_segments(
    content: Any, path: str, source: SegmentSource, trust: SegmentTrust
) -> Iterator[Segment]:
    if isinstance(content, str):
        if segment := _text_segment(content, path, source, trust):
            yield segment
        return
    if not isinstance(content, list):
        return
    for index, part in enumerate(content):
        part_path = f"{path}/{index}"
        if not isinstance(part, dict):
            continue
        if part.get("type") in ("text", "input_text", "output_text"):
            if segment := _text_segment(part.get("text"), f"{part_path}/text", source, trust):
                yield segment
            continue
        size = len(dump(part))
        kind = str(part.get("type") or "part")
        yield Segment.uninspected_part(
            source=source, path=part_path, kind=kind, size_bytes=size, trust=trust
        )


def _tool_call_segments(
    tool_calls: Any, path: str, source: SegmentSource, trust: SegmentTrust
) -> Iterator[Segment]:
    if not isinstance(tool_calls, list):
        return
    for index, call in enumerate(tool_calls):
        function = call.get("function") if isinstance(call, dict) else None
        if not isinstance(function, dict):
            continue
        # The arguments are a JSON document inside a string. A placeholder holds no quote or
        # backslash, so masking text inside the string keeps that document valid.
        arguments_path = f"{path}/{index}/function/arguments"
        if segment := _text_segment(function.get("arguments"), arguments_path, source, trust):
            yield segment


def _message_segments(message: Any, path: str) -> Iterator[Segment]:
    if not isinstance(message, dict):
        return
    source, trust = _ROLES.get(str(message.get("role")), _UNKNOWN_ROLE)
    yield from _content_segments(message.get("content"), f"{path}/content", source, trust)
    yield from _tool_call_segments(message.get("tool_calls"), f"{path}/tool_calls", source, trust)
    if segment := _text_segment(message.get("refusal"), f"{path}/refusal", source, trust):
        yield segment


def _tool_definition_segments(tools: Any) -> Iterator[Segment]:
    if not isinstance(tools, list):
        return
    for index, tool in enumerate(tools):
        function = tool.get("function") if isinstance(tool, dict) else None
        if not isinstance(function, dict):
            continue
        base = f"/tools/{index}/function"
        if segment := _text_segment(
            function.get("description"),
            f"{base}/description",
            SegmentSource.SYSTEM,
            SegmentTrust.TRUSTED,
        ):
            yield segment
        parameters = function.get("parameters")
        if isinstance(parameters, dict):
            yield from Payload.from_json(
                parameters,
                source=SegmentSource.SYSTEM,
                trust=SegmentTrust.TRUSTED,
                base_path=f"{base}/parameters",
            ).segments


def parse_request(raw: bytes) -> ChatBody:
    """A chat completions request: messages, their tool calls and the tool definitions."""
    body = _load(raw)
    messages = body.get("messages")
    if not isinstance(messages, list):
        raise ChatBodyError("a chat completions request needs a messages array")
    segments: list[Segment] = []
    for index, message in enumerate(messages):
        segments.extend(_message_segments(message, f"/messages/{index}"))
    segments.extend(_tool_definition_segments(body.get("tools")))
    untrusted = any(isinstance(m, dict) and m.get("role") in ("tool", "function") for m in messages)
    return ChatBody(
        body=body,
        payload=Payload(segments=tuple(segments)),
        model=str(body.get("model") or "unknown"),
        untrusted_content_seen=untrusted,
    )


def parse_response(raw: bytes) -> ChatBody:
    """A non-streamed chat completion: the message of every choice."""
    body = _load(raw)
    choices = body.get("choices")
    segments: list[Segment] = []
    if isinstance(choices, list):
        for index, choice in enumerate(choices):
            if isinstance(choice, dict):
                segments.extend(
                    _message_segments(choice.get("message"), f"/choices/{index}/message")
                )
    return ChatBody(
        body=body, payload=Payload(segments=tuple(segments)), model=str(body.get("model") or "")
    )


def pointer(*tokens: str | int) -> str:
    return "".join(f"/{escape_pointer_token(str(t))}" for t in tokens)


def error_body(code: str, message: str, decision_id: str | None) -> dict[str, Any]:
    """The OpenAI-style error object a blocked exchange answers with."""
    error: dict[str, Any] = {"type": "guardrail_blocked", "code": code, "message": message}
    if decision_id is not None:
        error["decision_id"] = decision_id
    return {"error": error}


def sse_error_event(code: str, message: str, decision_id: str | None) -> bytes:
    return b"data: " + dump(error_body(code, message, decision_id)) + b"\n\n"


def _delta_text(event: bytes) -> str:
    """The text a chat completion chunk adds: content, refusal and tool-call argument fragments."""
    pieces: list[str] = []
    for line in event.splitlines():
        if not line.startswith(b"data:"):
            continue
        data = line[5:].strip()
        if not data or data == b"[DONE]":
            continue
        try:
            chunk = json.loads(data)
        except (UnicodeDecodeError, json.JSONDecodeError):
            # Not a chunk the guard understands: its raw text is still inspected.
            pieces.append(data.decode("utf-8", "replace"))
            continue
        choices = chunk.get("choices") if isinstance(chunk, dict) else None
        for choice in choices if isinstance(choices, list) else ():
            delta = choice.get("delta") if isinstance(choice, dict) else None
            if not isinstance(delta, dict):
                continue
            for key in ("content", "refusal"):
                if isinstance(delta.get(key), str):
                    pieces.append(delta[key])
            for call in delta.get("tool_calls") or ():
                function = call.get("function") if isinstance(call, dict) else None
                if isinstance(function, dict) and isinstance(function.get("arguments"), str):
                    pieces.append(function["arguments"])
    return "".join(pieces)


def _event_end(buffer: bytes) -> int:
    """The end of the last complete server-sent event in ``buffer``, 0 when there is none."""
    ends = [buffer.rfind(sep) + len(sep) for sep in (b"\n\n", b"\r\n\r\n") if sep in buffer]
    return max(ends, default=0)


@dataclass
class StreamWindow:
    """Holds a streamed response back until the text it carries has been checked.

    Complete events are parsed as they arrive; their text accumulates until a window of
    ``window_chars`` is due, which is checked together with the last ``overlap_chars`` of the
    text already released, so a secret split across two windows is still seen whole. What was
    checked is released; an event that has not arrived in full is held.
    """

    window_chars: int
    overlap_chars: int
    _held: bytearray = field(default_factory=bytearray)
    _parsed_upto: int = 0
    _released_text: str = ""
    _pending_text: str = ""

    def feed(self, chunk: bytes) -> None:
        self._held.extend(chunk)
        end = _event_end(bytes(self._held))
        if end > self._parsed_upto:
            self._pending_text += _delta_text(bytes(self._held[self._parsed_upto : end]))
            self._parsed_upto = end

    def due(self, end_of_stream: bool) -> bool:
        return len(self._pending_text) >= self.window_chars or (end_of_stream and bool(self._held))

    def window_text(self, end_of_stream: bool) -> str:
        if end_of_stream and self._parsed_upto < len(self._held):
            # The tail never completed an event; whatever it says is checked as it is.
            tail = bytes(self._held[self._parsed_upto :])
            self._pending_text += _delta_text(tail + b"\n\n")
            self._parsed_upto = len(self._held)
        overlap = self._released_text[-self.overlap_chars :] if self.overlap_chars else ""
        return overlap + self._pending_text

    def release(self, end_of_stream: bool) -> bytes:
        """The bytes whose text was checked; everything that is left at the end of the stream."""
        upto = len(self._held) if end_of_stream else self._parsed_upto
        released = bytes(self._held[:upto])
        del self._held[:upto]
        self._parsed_upto -= upto
        self._released_text = (self._released_text + self._pending_text)[
            -max(self.overlap_chars, 1) :
        ]
        self._pending_text = ""
        return released

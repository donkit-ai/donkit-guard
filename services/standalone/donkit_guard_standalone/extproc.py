"""The ext_proc server of the LLM route: every request and response checked by the guard.

agentgateway opens one bidirectional stream per HTTP exchange. The request body arrives
buffered and whole: it is allowed as it is, rewritten with its masks (with a ``content-length``
to match, which agentgateway checks), or answered on the spot with an OpenAI-style error. The
response body arrives either buffered or, with ``fullDuplexStreamed``, chunk by chunk: a JSON
completion is held until it is complete and then allowed, masked or replaced by an error; a
server-sent event stream is released window by window once each window was checked, and closed
with one ``guardrail_blocked`` event when a window is refused. What was already released cannot
be recalled, and a stream is never masked after it started: a window that would need a mask
ends the stream instead.

Any failure inside the guard answers fail-closed: the request with a 503, the response with
an error in place of the body.
"""

from __future__ import annotations

import json
import logging
import uuid
from typing import TYPE_CHECKING, Any

from google.protobuf import json_format

from donkit_guard.context import Action, ActionKind, Destination, GuardContext
from donkit_guard.decision import Decision, Outcome
from donkit_guard.payload import Payload, Segment, SegmentSource, SegmentTrust
from donkit_guard_standalone.chat import (
    CHAT_COMPLETIONS_SUFFIX,
    ChatBody,
    ChatBodyError,
    StreamWindow,
    dump,
    error_body,
    parse_request,
    parse_response,
    sse_error_event,
)
from donkit_guard_standalone.identity import GatewayIdentity, IdentityMissing, identity_from
from donkit_guard_standalone.metrics import Metric
from donkit_guard_standalone.proto import ext_proc_pb2 as pb
from donkit_guard_standalone.proto import shared_envoy_pb2 as envoy

if TYPE_CHECKING:
    from collections.abc import AsyncIterator

    import grpc

    from donkit_guard_standalone.service import GuardService, Surface

logger = logging.getLogger("donkit_guard_standalone.extproc")

ATTRIBUTES_NAMESPACE = "envoy.filters.http.ext_proc"
_BLOCKING = frozenset({Outcome.DENY, Outcome.APPROVAL_PENDING, Outcome.REQUIRE_APPROVAL})


class _Refusal(Exception):
    """The exchange is answered with an error before the guard decides on its content."""

    def __init__(self, status: int, code: str, message: str) -> None:
        super().__init__(message)
        self.status = status
        self.code = code
        self.message = message


def _headers(header_map: pb.HeaderMap) -> dict[str, str]:
    headers: dict[str, str] = {}
    for header in header_map.headers:
        value = header.raw_value.decode("utf-8", "replace") if header.raw_value else header.value
        headers[header.key.lower()] = value
    return headers


def _header(key: str, value: str) -> envoy.HeaderValueOption:
    return envoy.HeaderValueOption(
        header=envoy.HeaderValue(key=key, raw_value=value.encode("utf-8")),
        append_action=envoy.HeaderValueOption.OVERWRITE_IF_EXISTS_OR_ADD,
    )


def _json_headers(length: int | None = None) -> pb.HeaderMutation:
    headers = [_header("content-type", "application/json")]
    if length is not None:
        headers.append(_header("content-length", str(length)))
    return pb.HeaderMutation(set_headers=headers)


def _immediate(
    status: int, code: str, message: str, decision_id: str | None
) -> pb.ProcessingResponse:
    body = json.dumps(error_body(code, message, decision_id), ensure_ascii=False)
    return pb.ProcessingResponse(
        immediate_response=pb.ImmediateResponse(
            status=envoy.HttpStatus(code=status),  # type: ignore[arg-type]
            headers=_json_headers(),
            body=body,
            details=code,
        )
    )


def _continue_request_headers() -> pb.ProcessingResponse:
    return pb.ProcessingResponse(request_headers=pb.HeadersResponse(response=pb.CommonResponse()))


def _continue_response_headers() -> pb.ProcessingResponse:
    return pb.ProcessingResponse(response_headers=pb.HeadersResponse(response=pb.CommonResponse()))


def _body_unchanged(*, response: bool) -> pb.ProcessingResponse:
    body = pb.BodyResponse(response=pb.CommonResponse())
    return (
        pb.ProcessingResponse(response_body=body)
        if response
        else pb.ProcessingResponse(request_body=body)
    )


def _body_replaced(
    body: bytes, *, response: bool, json_body: bool = False
) -> pb.ProcessingResponse:
    headers = (
        _json_headers(len(body))
        if json_body
        else pb.HeaderMutation(set_headers=[_header("content-length", str(len(body)))])
    )
    common = pb.CommonResponse(header_mutation=headers, body_mutation=pb.BodyMutation(body=body))
    if response:
        return pb.ProcessingResponse(response_body=pb.BodyResponse(response=common))
    return pb.ProcessingResponse(request_body=pb.BodyResponse(response=common))


def _streamed(body: bytes, end_of_stream: bool) -> pb.ProcessingResponse:
    mutation = pb.BodyMutation(
        streamed_response=pb.StreamedBodyResponse(body=body, end_of_stream=end_of_stream)
    )
    return pb.ProcessingResponse(
        response_body=pb.BodyResponse(response=pb.CommonResponse(body_mutation=mutation))
    )


def _blocked_reason(decision: Decision) -> tuple[str, str]:
    explanation = decision.explanation
    if decision.outcome is Outcome.MASK:
        return "stream_blocked", "the response carried content the policy masks"
    if decision.outcome is Outcome.APPROVAL_PENDING:
        return "approval_unsupported", "an LLM exchange cannot wait for an approval"
    return explanation.code, explanation.reason or "blocked by policy"


class LlmExchange:
    """The state of one HTTP exchange through the LLM route."""

    def __init__(self, service: GuardService) -> None:
        self._service = service
        self._settings = service.settings
        self._attributes: dict[str, Any] = {}
        self._headers: dict[str, str] = {}
        self._identity: GatewayIdentity | None = None
        self._request = bytearray()
        self._response = bytearray()
        self._response_mode = pb.BUFFERED
        self._event_stream = False
        self._window: StreamWindow | None = None
        self._model = "unknown"
        self._run = f"req-{uuid.uuid4().hex}"
        self._untrusted_seen = False
        self.closed = False

    async def handle(self, message: pb.ProcessingRequest) -> list[pb.ProcessingResponse]:
        self._absorb_metadata(message)
        match message.WhichOneof("request"):
            case "request_headers":
                return self._on_request_headers(message.request_headers)
            case "request_body":
                return await self._on_request_body(message.request_body)
            case "response_headers":
                return self._on_response_headers(message.response_headers)
            case "response_body":
                return await self._on_response_body(message.response_body)
            case "request_trailers":
                return [pb.ProcessingResponse(request_trailers=pb.TrailersResponse())]
            case "response_trailers":
                return [pb.ProcessingResponse(response_trailers=pb.TrailersResponse())]
            case _:
                return []

    def fail_closed(self, phase: str | None) -> list[pb.ProcessingResponse]:
        """The answer when the guard itself failed: nothing passes unchecked."""
        message = "the guard could not check this exchange"
        if phase in ("response_headers", "response_body"):
            self.closed = True
            if self._response_mode == pb.FULL_DUPLEX_STREAMED:
                return [_streamed(sse_error_event("guard_error", message, None), True)]
            return [
                _body_replaced(
                    dump(error_body("guard_error", message, None)), response=True, json_body=True
                )
            ]
        return [_immediate(503, "guard_error", message, None)]

    def _absorb_metadata(self, message: pb.ProcessingRequest) -> None:
        if message.HasField("protocol_config"):
            self._response_mode = message.protocol_config.response_body_mode
        attributes = message.attributes.get(ATTRIBUTES_NAMESPACE)
        if attributes is not None:
            self._attributes.update(json_format.MessageToDict(attributes))

    def _on_request_headers(self, headers: pb.HttpHeaders) -> list[pb.ProcessingResponse]:
        self._headers = _headers(headers.headers)
        try:
            self._identity = identity_from(self._attributes, self._headers)
        except IdentityMissing as exc:
            return [_immediate(401, "unauthenticated", str(exc), None)]
        if headers.end_of_stream and not self._inspectable():
            return self._unsupported() or [_continue_request_headers()]
        return [_continue_request_headers()]

    async def _on_request_body(self, body: pb.HttpBody) -> list[pb.ProcessingResponse]:
        self._request.extend(body.body)
        if len(self._request) > self._settings.max_body_bytes:
            return [
                _immediate(
                    413, "body_too_large", "the request body is over the guard's limit", None
                )
            ]
        if not body.end_of_stream:
            return []
        if not self._inspectable():
            return self._unsupported() or [_body_unchanged(response=False)]
        try:
            chat = parse_request(bytes(self._request))
        except ChatBodyError as exc:
            return self._unsupported(str(exc)) or [_body_unchanged(response=False)]
        self._model = chat.model
        self._untrusted_seen = chat.untrusted_content_seen
        decision = await self._decide(chat.payload, phase="request")
        if decision.outcome in _BLOCKING:
            code, reason = _blocked_reason(decision)
            return [_immediate(403, code, reason, decision.decision_id)]
        if decision.outcome is Outcome.MASK and decision.masked_segments:
            return [_body_replaced(chat.masked(decision.masked_segments), response=False)]
        return [_body_unchanged(response=False)]

    def _on_response_headers(self, headers: pb.HttpHeaders) -> list[pb.ProcessingResponse]:
        content_type = _headers(headers.headers).get("content-type", "")
        self._event_stream = content_type.startswith("text/event-stream")
        if self._event_stream:
            self._window = StreamWindow(
                window_chars=self._settings.stream_window_chars,
                overlap_chars=self._settings.stream_overlap_chars,
            )
        return [_continue_response_headers()]

    async def _on_response_body(self, body: pb.HttpBody) -> list[pb.ProcessingResponse]:
        if self.closed:
            return []
        if self._window is not None and self._response_mode == pb.FULL_DUPLEX_STREAMED:
            return await self._on_stream_chunk(self._window, body.body, body.end_of_stream)
        self._response.extend(body.body)
        if len(self._response) > self._settings.max_body_bytes:
            return self._refuse_response(
                "body_too_large", "the response is over the guard's limit", None
            )
        if not body.end_of_stream:
            return []
        return await self._on_complete_response(bytes(self._response))

    async def _on_stream_chunk(
        self, window: StreamWindow, chunk: bytes, end_of_stream: bool
    ) -> list[pb.ProcessingResponse]:
        window.feed(chunk)
        if not window.due(end_of_stream):
            return []
        text = window.window_text(end_of_stream)
        if text:
            segment = Segment.of_text(
                text, source=SegmentSource.ASSISTANT, trust=SegmentTrust.UNTRUSTED
            )
            decision = await self._decide(Payload(segments=(segment,)), phase="response")
            if decision.outcome in _BLOCKING or decision.outcome is Outcome.MASK:
                code, reason = _blocked_reason(decision)
                self.closed = True
                return [_streamed(sse_error_event(code, reason, decision.decision_id), True)]
        released = window.release(end_of_stream)
        if not released and not end_of_stream:
            return []
        return [_streamed(released, end_of_stream)]

    async def _on_complete_response(self, raw: bytes) -> list[pb.ProcessingResponse]:
        chat = self._parse_response(raw)
        decision = await self._decide(chat.payload, phase="response")
        if decision.outcome in _BLOCKING:
            code, reason = _blocked_reason(decision)
            return self._refuse_response(code, reason, decision.decision_id)
        body = raw
        if decision.outcome is Outcome.MASK and decision.masked_segments:
            if self._event_stream:
                code, reason = _blocked_reason(decision)
                return self._refuse_response(code, reason, decision.decision_id)
            body = chat.masked(decision.masked_segments)
        if self._response_mode == pb.FULL_DUPLEX_STREAMED:
            return [_streamed(body, True)]
        if body is raw:
            return [_body_unchanged(response=True)]
        return [_body_replaced(body, response=True)]

    def _parse_response(self, raw: bytes) -> ChatBody:
        if not self._event_stream:
            try:
                return parse_response(raw)
            except ChatBodyError:
                pass
        # A stream checked whole (buffered mode) or a body that is not a completion: its text.
        window = StreamWindow(window_chars=len(raw) + 1, overlap_chars=0)
        window.feed(raw)
        text = window.window_text(True) if self._event_stream else raw.decode("utf-8", "replace")
        segments = (
            (Segment.of_text(text, source=SegmentSource.ASSISTANT, trust=SegmentTrust.UNTRUSTED),)
            if text
            else ()
        )
        return ChatBody(body={}, payload=Payload(segments=segments), model=self._model)

    def _refuse_response(
        self, code: str, message: str, decision_id: str | None
    ) -> list[pb.ProcessingResponse]:
        self.closed = True
        if self._response_mode == pb.FULL_DUPLEX_STREAMED:
            body = (
                sse_error_event(code, message, decision_id)
                if self._event_stream
                else dump(error_body(code, message, decision_id))
            )
            return [_streamed(body, True)]
        if self._event_stream:
            return [_body_replaced(sse_error_event(code, message, decision_id), response=True)]
        return [
            _body_replaced(
                dump(error_body(code, message, decision_id)), response=True, json_body=True
            )
        ]

    def _inspectable(self) -> bool:
        return self._headers.get(":method", "").upper() == "POST" and self._headers.get(
            ":path", ""
        ).split("?", 1)[0].endswith(CHAT_COMPLETIONS_SUFFIX)

    def _unsupported(self, detail: str = "") -> list[pb.ProcessingResponse]:
        """The refusal of a request the guard cannot read, or nothing when such requests pass."""
        if self._settings.unsupported_requests == "allow":
            return []
        message = "the guard inspects only chat completions requests"
        return [
            _immediate(
                400, "unsupported_request", f"{message}: {detail}" if detail else message, None
            )
        ]

    async def _decide(self, payload: Payload, *, phase: str) -> Decision:
        identity = self._identity
        if identity is None:
            raise IdentityMissing("the exchange has no identity")
        destination = (
            Destination(
                provider=self._settings.llm_provider,
                model=self._model,
                trust=self._settings.llm_destination_trust,
            )
            if phase == "request"
            else None
        )
        ctx = GuardContext(
            principal=identity.principal_ref(),
            tenant=identity.tenant_ref(),
            agent=identity.agent_ref(),
            run=identity.run_ref(self._run, untrusted_content_seen=self._untrusted_seen),
            action=Action(kind=ActionKind.LLM_REQUEST, destination=destination),
            attributes={"phase": phase},
        )
        surface: Surface = "llm_request" if phase == "request" else "llm_response"
        return await self._service.authorize(ctx, payload, surface=surface)


class ExternalProcessor:
    """The `envoy.service.ext_proc.v3.ExternalProcessor` service."""

    def __init__(self, service: GuardService) -> None:
        self._service = service

    async def Process(
        self,
        request_iterator: AsyncIterator[pb.ProcessingRequest],
        context: grpc.aio.ServicerContext[pb.ProcessingRequest, pb.ProcessingResponse],
    ) -> AsyncIterator[pb.ProcessingResponse]:
        exchange = LlmExchange(self._service)
        async for message in request_iterator:
            phase = message.WhichOneof("request")
            try:
                responses = await exchange.handle(message)
            except Exception:  # fail closed: a guard failure never lets the exchange through
                logger.exception("ext_proc failed in %s", phase)
                self._service.metrics.inc(Metric.GATEWAY_ERRORS, surface="llm")
                responses = exchange.fail_closed(phase)
            for response in responses:
                yield response

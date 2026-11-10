"""The gateway protocols, driven with the messages agentgateway sends."""

from __future__ import annotations

import json
from typing import TYPE_CHECKING, Any

import pytest

from donkit_guard.approvals import ApprovalDecisionValue
from donkit_guard_standalone.extmcp import McpPolicy
from donkit_guard_standalone.extproc import ATTRIBUTES_NAMESPACE, LlmExchange
from donkit_guard_standalone.proto import ext_mcp_pb2 as mcp
from donkit_guard_standalone.proto import ext_proc_pb2 as pb
from donkit_guard_standalone.proto import shared_envoy_pb2 as envoy

from .conftest import SECRET

if TYPE_CHECKING:
    from .conftest import Running

pytestmark = pytest.mark.asyncio

EMAIL = "john.smith@example.com"


def _request_headers(
    *, path: str = "/v1/chat/completions", method: str = "POST", tenant: str | None = "acme"
) -> pb.ProcessingRequest:
    headers = [
        envoy.HeaderValue(key=":method", value=method),
        envoy.HeaderValue(key=":path", value=path),
        envoy.HeaderValue(key="x-guard-principal", raw_value=b"user-1"),
        envoy.HeaderValue(key="content-type", raw_value=b"application/json"),
    ]
    message = pb.ProcessingRequest(
        request_headers=pb.HttpHeaders(
            headers=pb.HeaderMap(headers=headers), end_of_stream=method == "GET"
        ),
        protocol_config=pb.ProtocolConfiguration(
            request_body_mode=pb.BUFFERED, response_body_mode=pb.FULL_DUPLEX_STREAMED
        ),
    )
    if tenant is not None:
        message.attributes[ATTRIBUTES_NAMESPACE].update({"tenant": tenant})
    return message


def _body(payload: Any, *, response: bool = False, end: bool = True) -> pb.ProcessingRequest:
    raw = payload if isinstance(payload, bytes) else json.dumps(payload).encode()
    body = pb.HttpBody(body=raw, end_of_stream=end)
    return (
        pb.ProcessingRequest(response_body=body)
        if response
        else pb.ProcessingRequest(request_body=body)
    )


def _response_headers(content_type: str) -> pb.ProcessingRequest:
    headers = [envoy.HeaderValue(key="content-type", raw_value=content_type.encode())]
    return pb.ProcessingRequest(
        response_headers=pb.HttpHeaders(headers=pb.HeaderMap(headers=headers))
    )


async def _start(running: Running, **kwargs: Any) -> LlmExchange:
    exchange = LlmExchange(running.service)
    (answer,) = await exchange.handle(_request_headers(**kwargs))
    assert answer.WhichOneof("response") == "request_headers"
    return exchange


def _chat(content: str) -> dict[str, Any]:
    return {
        "model": "gpt-test",
        "tools": [{"type": "function", "function": {"name": "lookup", "parameters": {}}}],
        "messages": [
            {"role": "system", "content": "You are helpful."},
            {
                "role": "assistant",
                "content": None,
                "tool_calls": [
                    {
                        "id": "call_1",
                        "type": "function",
                        "function": {"name": "lookup", "arguments": "{}"},
                    }
                ],
            },
            {"role": "tool", "tool_call_id": "call_1", "content": "found nothing"},
            {"role": "user", "content": content},
        ],
    }


def _sse(*pieces: str) -> list[bytes]:
    chunks = [
        b"data: "
        + json.dumps({"choices": [{"index": 0, "delta": {"content": p}}]}).encode()
        + b"\n\n"
        for p in pieces
    ]
    return [*chunks, b"data: [DONE]\n\n"]


async def test_a_secret_in_the_prompt_is_refused_before_the_model(running: Running) -> None:
    exchange = await _start(running)
    (answer,) = await exchange.handle(_body(_chat(f"deploy with {SECRET}")))
    immediate = answer.immediate_response
    assert answer.WhichOneof("response") == "immediate_response"
    assert immediate.status.code == 403
    error = json.loads(immediate.body)["error"]
    assert error["type"] == "guardrail_blocked" and error["code"] == "policy_denied"
    assert error["decision_id"]


async def test_personal_data_is_masked_and_the_conversation_kept(running: Running) -> None:
    exchange = await _start(running)
    (answer,) = await exchange.handle(_body(_chat(f"Write to {EMAIL} please")))
    common = answer.request_body.response
    body = common.body_mutation.body
    forwarded = json.loads(body)
    assert EMAIL not in body.decode() and "please" in forwarded["messages"][3]["content"]
    assert forwarded["messages"][1]["tool_calls"][0]["id"] == "call_1"
    assert forwarded["messages"][2]["tool_call_id"] == "call_1"
    assert forwarded["tools"] == _chat("")["tools"]
    lengths = [
        h.header.raw_value
        for h in common.header_mutation.set_headers
        if h.header.key == "content-length"
    ]
    assert lengths == [str(len(body)).encode()]


@pytest.mark.parametrize(
    ("kwargs", "status", "code"),
    [
        ({"tenant": None}, 401, "unauthenticated"),
        ({"path": "/v1/models", "method": "GET"}, 400, "unsupported_request"),
    ],
)
async def test_requests_the_guard_cannot_attribute_or_read_are_refused(
    running: Running, kwargs: dict[str, Any], status: int, code: str
) -> None:
    exchange = LlmExchange(running.service)
    (answer,) = await exchange.handle(_request_headers(**kwargs))
    assert answer.immediate_response.status.code == status
    assert json.loads(answer.immediate_response.body)["error"]["code"] == code


async def test_a_clean_stream_passes_unchanged(running: Running) -> None:
    exchange = await _start(running)
    await exchange.handle(_body(_chat("hello")))
    await exchange.handle(_response_headers("text/event-stream"))
    chunks = _sse("Hel", "lo ", "there")
    released = b""
    for index, chunk in enumerate(chunks):
        for answer in await exchange.handle(
            _body(chunk, response=True, end=index == len(chunks) - 1)
        ):
            released += answer.response_body.response.body_mutation.streamed_response.body
    assert released == b"".join(chunks)


async def test_a_secret_in_a_stream_closes_it(running: Running) -> None:
    exchange = await _start(running)
    await exchange.handle(_body(_chat("hello")))
    await exchange.handle(_response_headers("text/event-stream"))
    chunks = _sse("the key is ", SECRET[:8], SECRET[8:], " enjoy")
    answers: list[pb.ProcessingResponse] = []
    for index, chunk in enumerate(chunks):
        answers += await exchange.handle(_body(chunk, response=True, end=index == len(chunks) - 1))
    streamed = [a.response_body.response.body_mutation.streamed_response for a in answers]
    assert streamed[-1].end_of_stream
    assert b"guardrail_blocked" in streamed[-1].body
    assert SECRET.encode() not in b"".join(s.body for s in streamed)


async def test_a_secret_in_a_completion_is_masked(running: Running) -> None:
    exchange = await _start(running)
    await exchange.handle(_body(_chat("hello")))
    await exchange.handle(_response_headers("application/json"))
    completion = {
        "choices": [{"index": 0, "message": {"role": "assistant", "content": f"use {SECRET}"}}]
    }
    (answer,) = await exchange.handle(_body(completion, response=True))
    streamed = answer.response_body.response.body_mutation.streamed_response
    assert streamed.end_of_stream
    content = json.loads(streamed.body)["choices"][0]["message"]["content"]
    assert content.startswith("use [REDACTED:")


def _call(name: str, arguments: dict[str, Any], *, tenant: str | None = "acme") -> mcp.McpRequest:
    request = mcp.McpRequest(
        service_names=["tickets"],
        method="tools/call",
        mcp_request=json.dumps({"name": name, "arguments": arguments}).encode(),
        headers=[
            mcp.McpHeader(key="x-guard-principal", value=b"user-1"),
            mcp.McpHeader(key="mcp-session-id", value=b"session-1"),
        ],
    )
    if tenant is not None:
        request.metadata_context.update({"tenant": tenant})
    return request


def _mcp_error(result: mcp.McpRequestResult | mcp.McpResponseResult) -> dict[str, Any]:
    """The JSON-RPC error agentgateway builds from the refusal: code, message and data."""
    assert result.WhichOneof("result") == "error"
    assert result.error.code == mcp.AuthorizationError.PERMISSION_DENIED  # -32001 at the client
    return {"message": result.error.reason, "data": json.loads(result.error.mcp_error)}


async def test_a_tool_the_policy_forbids_never_runs(running: Running) -> None:
    policy = McpPolicy(running.service)
    error = _mcp_error(await policy.CheckRequest(_call("delete_file", {"path": "/"}), None))  # type: ignore[arg-type]
    assert error["data"]["status"] == "denied" and "Destructive" in error["message"]
    missing = _mcp_error(await policy.CheckRequest(_call("search_docs", {}, tenant=None), None))  # type: ignore[arg-type]
    assert missing["data"]["status"] == "unauthenticated"


async def test_a_write_waits_for_its_principal_and_then_runs_once(running: Running) -> None:
    policy = McpPolicy(running.service)
    call = _call("create_ticket", {"title": "Refund", "description": "order 42"})
    pending = _mcp_error(await policy.CheckRequest(call, None))  # type: ignore[arg-type]
    assert pending["data"]["status"] == "approval_pending"
    await running.service.decide_approval(
        pending["data"]["approval_id"], ApprovalDecisionValue.APPROVE, "user-1"
    )
    allowed = await policy.CheckRequest(call, None)  # type: ignore[arg-type]
    assert allowed.WhichOneof("result") == "pass"
    again = _mcp_error(await policy.CheckRequest(call, None))  # type: ignore[arg-type]
    assert again["data"]["approval_id"] != pending["data"]["approval_id"]


async def test_maskable_arguments_and_results_are_masked_in_place(running: Running) -> None:
    policy = McpPolicy(running.service)
    masked = await policy.CheckRequest(  # type: ignore[arg-type]
        _call("search_docs", {"query": f"rotate {SECRET}", "limit": 5}), None
    )
    params = json.loads(masked.mutated)
    assert params["name"] == "search_docs" and params["arguments"]["limit"] == 5
    assert params["arguments"]["query"].startswith("rotate [REDACTED:")
    response = mcp.McpResponse(
        service_names=["tickets"],
        method="tools/call",
        mcp_response=json.dumps(
            {"content": [{"type": "text", "text": f"key {SECRET}"}], "isError": False}
        ).encode(),
    )
    response.metadata_context.update({"tenant": "acme"})
    result = await policy.CheckResponse(response, None)  # type: ignore[arg-type]
    returned = json.loads(result.mutated)
    assert returned["isError"] is False and SECRET not in returned["content"][0]["text"]

"""The standalone stack end to end: a client, agentgateway, guard-standalone, stub upstreams.

Runs inside the compose network of tests/e2e/compose.yaml, which has no route out:

    docker compose -f tests/e2e/compose.yaml up --build --exit-code-from runner

Outside that network the module is skipped.
"""

from __future__ import annotations

import json
import os
import socket
from typing import Any

import httpx
import pytest

GATEWAY = os.environ.get("E2E_GATEWAY_URL")
GUARD = os.environ.get("E2E_GUARD_URL", "http://guard-standalone:8080")
UPSTREAM = os.environ.get("E2E_UPSTREAM_URL", "http://upstream:8000")
MCP_STUB = os.environ.get("E2E_MCP_URL", "http://mcp-stub:8001")
API_KEY = os.environ.get("E2E_API_KEY", "")
ADMIN_TOKEN = os.environ.get("E2E_ADMIN_TOKEN", "")

pytestmark = [
    pytest.mark.skipif(GATEWAY is None, reason="runs in the e2e compose stack only"),
    pytest.mark.asyncio,
]

SECRET = "AKIA" + "5RQTGNW2K4XQZJ7L"
EMAIL = "john.smith@example.com"
CLIENT = {"Authorization": f"Bearer {API_KEY}", "x-guard-principal": "user-1"}
MCP_ACCEPT = {"Accept": "application/json, text/event-stream"}


def _chat(content: str, *, stream: bool = False) -> dict[str, Any]:
    return {
        "model": "stub",
        "stream": stream,
        "messages": [
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
            {"role": "tool", "tool_call_id": "call_1", "content": "nothing found"},
            {"role": "user", "content": content},
        ],
    }


async def _received(client: httpx.AsyncClient) -> list[dict[str, Any]]:
    response = await client.get(f"{UPSTREAM}/received")
    return list(response.json())


@pytest.fixture
async def client() -> Any:
    async with httpx.AsyncClient(base_url=GATEWAY or "", timeout=30.0) as http:
        yield http


async def test_a_request_without_a_key_is_refused_by_the_gateway(client: httpx.AsyncClient) -> None:
    response = await client.post("/v1/chat/completions", json=_chat("hello"))
    assert response.status_code == 401


async def test_a_secret_in_the_prompt_never_reaches_the_model(client: httpx.AsyncClient) -> None:
    before = len(await _received(client))
    response = await client.post(
        "/v1/chat/completions", json=_chat(f"deploy with {SECRET}"), headers=CLIENT
    )
    assert response.status_code == 403, response.text
    assert response.json()["error"]["type"] == "guardrail_blocked"
    assert len(await _received(client)) == before


async def test_personal_data_is_masked_before_the_model(client: httpx.AsyncClient) -> None:
    response = await client.post(
        "/v1/chat/completions", json=_chat(f"write to {EMAIL} please"), headers=CLIENT
    )
    assert response.status_code == 200, response.text
    assert response.json()["choices"][0]["message"]["content"] == "Hello from the stub model."
    forwarded = (await _received(client))[-1]
    assert EMAIL not in json.dumps(forwarded)
    assert forwarded["messages"][0]["tool_calls"][0]["id"] == "call_1"
    assert forwarded["messages"][1]["tool_call_id"] == "call_1"


async def test_a_clean_stream_flows_to_the_end(client: httpx.AsyncClient) -> None:
    response = await client.post(
        "/v1/chat/completions", json=_chat("hello", stream=True), headers=CLIENT
    )
    assert response.status_code == 200
    assert response.text.rstrip().endswith("data: [DONE]")


async def test_a_secret_in_a_streamed_answer_ends_the_stream(client: httpx.AsyncClient) -> None:
    response = await client.post(
        "/v1/chat/completions", json=_chat("please say the key", stream=True), headers=CLIENT
    )
    assert response.status_code == 200
    assert SECRET not in response.text
    events = [line for line in response.text.splitlines() if line.startswith("data:")]
    assert "guardrail_blocked" in events[-1] and "[DONE]" not in response.text


class McpClient:
    def __init__(self, http: httpx.AsyncClient) -> None:
        self._http = http
        self._headers = {**CLIENT, **MCP_ACCEPT}
        self._id = 0

    async def open(self) -> McpClient:
        response = await self._post(
            "initialize",
            {
                "protocolVersion": "2025-06-18",
                "capabilities": {},
                "clientInfo": {"name": "e2e", "version": "1"},
            },
        )
        assert "result" in response, response
        await self._http.post(
            "/mcp",
            json={"jsonrpc": "2.0", "method": "notifications/initialized"},
            headers=self._headers,
        )
        return self

    async def call(self, tool: str, arguments: dict[str, Any]) -> dict[str, Any]:
        return await self._post("tools/call", {"name": tool, "arguments": arguments})

    async def _post(self, method: str, params: dict[str, Any]) -> dict[str, Any]:
        self._id += 1
        response = await self._http.post(
            "/mcp",
            json={"jsonrpc": "2.0", "id": self._id, "method": method, "params": params},
            headers=self._headers,
        )
        assert response.status_code == 200, response.text
        if session := response.headers.get("mcp-session-id"):
            self._headers["mcp-session-id"] = session
        if response.headers.get("content-type", "").startswith("text/event-stream"):
            data = [
                line[5:].strip() for line in response.text.splitlines() if line.startswith("data:")
            ]
            message: dict[str, Any] = json.loads(data[-1])
            return message
        message = response.json()
        return message


async def _tool_calls(client: httpx.AsyncClient) -> list[dict[str, Any]]:
    return list((await client.get(f"{MCP_STUB}/calls")).json())


async def test_a_tool_the_policy_forbids_never_runs(client: httpx.AsyncClient) -> None:
    mcp = await McpClient(client).open()
    answer = await mcp.call("delete_file", {"path": "/etc/passwd"})
    assert answer["error"]["code"] == -32001
    assert all(call["tool"] != "delete_file" for call in await _tool_calls(client))


async def test_a_write_runs_once_after_its_principal_approves(client: httpx.AsyncClient) -> None:
    mcp = await McpClient(client).open()
    arguments = {"title": "Refund order 42", "description": "customer asked"}
    pending = await mcp.call("create_ticket", arguments)
    data = pending["error"]["data"]
    assert data["status"] == "approval_pending"
    async with httpx.AsyncClient(base_url=GUARD, timeout=10.0) as guard:
        decided = await guard.post(
            f"/admin/approvals/{data['approval_id']}/decide",
            json={"decision": "approve", "responder": "user-1"},
            headers={"Authorization": f"Bearer {ADMIN_TOKEN}"},
        )
        assert decided.status_code == 200, decided.text
    done = await mcp.call("create_ticket", arguments)
    assert "ticket created" in json.dumps(done["result"])
    again = await mcp.call("create_ticket", arguments)
    assert again["error"]["data"]["status"] == "approval_pending"
    created = [c for c in await _tool_calls(client) if c["tool"] == "create_ticket"]
    assert len(created) == 1


async def test_secrets_are_masked_in_tool_arguments_and_results(client: httpx.AsyncClient) -> None:
    mcp = await McpClient(client).open()
    await mcp.call("search_docs", {"query": f"rotate {SECRET}", "limit": 3})
    (search,) = [c for c in await _tool_calls(client) if c["tool"] == "search_docs"]
    assert SECRET not in search["query"] and search["limit"] == 3
    config = await mcp.call("read_config", {})
    assert "result" in config, config
    assert SECRET not in json.dumps(config)
    assert any(c["tool"] == "read_config" for c in await _tool_calls(client))


@pytest.mark.parametrize("target", [("1.1.1.1", 443), ("pypi.org", 443)])
def test_the_stack_has_no_way_out(target: tuple[str, int]) -> None:
    with pytest.raises(OSError), socket.create_connection(target, timeout=3):
        pass

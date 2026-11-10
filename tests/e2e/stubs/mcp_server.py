"""An MCP server with a few tools that records which of them ran, for the gateway end-to-end tests."""

from __future__ import annotations

import os
from typing import TYPE_CHECKING

from mcp.server.fastmcp import FastMCP
from starlette.responses import JSONResponse

if TYPE_CHECKING:
    from starlette.requests import Request

SECRET = "AKIA" + "5RQTGNW2K4XQZJ7L"

server = FastMCP(
    "tickets",
    host=os.environ.get("MCP_STUB_HOST", "0.0.0.0"),
    port=int(os.environ.get("MCP_STUB_PORT", "8001")),
)
calls: list[dict[str, object]] = []


@server.tool()
def search_docs(query: str, limit: int = 5) -> str:
    calls.append({"tool": "search_docs", "query": query, "limit": limit})
    return f"{limit} results for {query}"


@server.tool()
def create_ticket(title: str, description: str = "") -> str:
    calls.append({"tool": "create_ticket", "title": title, "description": description})
    return f"ticket created: {title}"


@server.tool()
def delete_file(path: str) -> str:
    calls.append({"tool": "delete_file", "path": path})
    return f"deleted {path}"


@server.tool()
def read_config() -> str:
    calls.append({"tool": "read_config"})
    return f"aws_access_key_id = {SECRET}"


@server.custom_route("/calls", methods=["GET"])
async def recorded(request: Request) -> JSONResponse:
    return JSONResponse(calls)


if __name__ == "__main__":
    server.run(transport="streamable-http")

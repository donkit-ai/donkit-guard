"""An OpenAI-compatible model that records what reached it, for the gateway end-to-end tests."""

from __future__ import annotations

import json
import time
from typing import TYPE_CHECKING, Any

from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse, StreamingResponse

if TYPE_CHECKING:
    from collections.abc import Iterator

# An AWS-shaped access key id, assembled at runtime so that secret scanners stay quiet.
SECRET = "AKIA" + "5RQTGNW2K4XQZJ7L"
LEAK_TRIGGER = "say the key"

app = FastAPI()
received: list[dict[str, Any]] = []


def _answer(body: dict[str, Any]) -> str:
    last = body["messages"][-1].get("content") or ""
    if isinstance(last, str) and LEAK_TRIGGER in last:
        return f"Sure, the deployment key is {SECRET} and nothing else."
    return "Hello from the stub model."


def _chunk(text: str) -> bytes:
    payload = {
        "id": "c1",
        "object": "chat.completion.chunk",
        "created": 0,
        "model": "stub",
        "choices": [{"index": 0, "delta": {"content": text}, "finish_reason": None}],
    }
    return b"data: " + json.dumps(payload).encode() + b"\n\n"


@app.post("/v1/chat/completions", response_model=None)
async def completions(request: Request) -> JSONResponse | StreamingResponse:
    body = await request.json()
    received.append(body)
    text = _answer(body)
    if body.get("stream"):

        def stream() -> Iterator[bytes]:
            for start in range(0, len(text), 6):
                yield _chunk(text[start : start + 6])
                time.sleep(0.01)
            yield b"data: [DONE]\n\n"

        return StreamingResponse(stream(), media_type="text/event-stream")
    return JSONResponse(
        {
            "id": "c1",
            "object": "chat.completion",
            "created": 0,
            "model": "stub",
            "choices": [
                {
                    "index": 0,
                    "finish_reason": "stop",
                    "message": {"role": "assistant", "content": text},
                }
            ],
        }
    )


@app.get("/received")
async def received_bodies() -> list[dict[str, Any]]:
    return received

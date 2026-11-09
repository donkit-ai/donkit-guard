"""A cap on the size of HTTP request bodies, counted as they are received."""

from __future__ import annotations

import json
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from starlette.types import ASGIApp, Message, Receive, Scope, Send


class BodyTooLarge(Exception):
    pass


class BodyLimit:
    """Answers 413 to a body over ``max_bytes``, whether it declares its length or not."""

    def __init__(self, app: ASGIApp, *, max_bytes: int) -> None:
        self._app = app
        self._max_bytes = max_bytes

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            await self._app(scope, receive, send)
            return
        for name, value in scope.get("headers", ()):
            if name == b"content-length" and value.isdigit() and int(value) > self._max_bytes:
                await self._too_large(send)
                return
        received = 0

        async def counting_receive() -> Message:
            nonlocal received
            message = await receive()
            if message["type"] == "http.request":
                received += len(message.get("body", b""))
                if received > self._max_bytes:
                    raise BodyTooLarge
            return message

        try:
            await self._app(scope, counting_receive, send)
        except BodyTooLarge:
            await self._too_large(send)

    async def _too_large(self, send: Send) -> None:
        body = json.dumps(
            {"error": "body_too_large", "detail": f"the limit is {self._max_bytes} bytes"}
        ).encode()
        await send(
            {
                "type": "http.response.start",
                "status": 413,
                "headers": [
                    (b"content-type", b"application/json"),
                    (b"content-length", str(len(body)).encode()),
                ],
            }
        )
        await send({"type": "http.response.body", "body": body})

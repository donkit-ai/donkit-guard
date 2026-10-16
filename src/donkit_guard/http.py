"""HTTP client for the analyze contract, behind an optional dependency.

A remote detector asks an analyze service (``POST /v1/analyze``) for findings through a
``DetectorClient``. ``HttpAnalyzeClient`` is that client for a service reached over HTTP: the
reference guard-pii service, or a service that a host's tenants run themselves. The address can
come from a policy document, so the client is deliberately narrow: it never follows a redirect,
takes no proxy or certificate settings from the environment, caps the size of the answer and,
when the host provides an ``EndpointGuard``, asks it before anything is sent.

``httpx`` is the ``http`` extra. This is the only module that imports it, and importing this
module never fails: a missing package is reported when the client is constructed.
"""

from __future__ import annotations

import os
import ssl
from typing import TYPE_CHECKING

from pydantic import ValidationError

from donkit_guard.adapters import AnalyzeRequest, AnalyzeResponse, EndpointGuard
from donkit_guard.errors import EndpointRejected

try:
    import httpx

    _INSTALLED = True
except ImportError:  # the optional "http" extra is not installed
    _INSTALLED = False

if TYPE_CHECKING:
    from collections.abc import Awaitable, Callable

HTTP_MISSING = "the HTTP client needs the 'http' extra: pip install 'donkit-guard[http]'"

# A deadline that is almost spent still leaves a nearby service a moment to answer.
_MIN_TIMEOUT_S = 0.05
# How much of pydantic's description of an unusable answer is kept in the error text.
_MAX_REASON_CHARS = 160


def _failed(error: str) -> AnalyzeResponse:
    return AnalyzeResponse(failed=True, error=error)


def _tls_verify(verify: bool | str) -> bool | ssl.SSLContext:
    """The ``verify`` setting in the form httpx takes: a CA path becomes an SSL context."""
    if isinstance(verify, str):
        if os.path.isdir(verify):
            return ssl.create_default_context(capath=verify)
        return ssl.create_default_context(cafile=verify)
    return verify


def _is_header_safe(value: str) -> bool:
    """Whether ``value`` can go into a header: printable ASCII, no line breaks."""
    return value.isascii() and value.isprintable()


async def _read_capped(response: httpx.Response, limit: int) -> bytes | None:
    """The decoded body of ``response``, or ``None`` as soon as it grows past ``limit`` bytes."""
    body = bytearray()
    async for chunk in response.aiter_bytes():
        body += chunk
        if len(body) > limit:
            return None
    return bytes(body)


def _reason(exc: ValidationError) -> str:
    """Where an answer went wrong and why, without quoting the answer."""
    first = exc.errors(include_url=False, include_context=False)[0]
    where = ".".join(str(part) for part in first["loc"])
    reason = f"{where}: {first['msg']}" if where else first["msg"]
    return reason[:_MAX_REASON_CHARS]


def _parse(body: bytes) -> AnalyzeResponse:
    # The answer comes from a service the host does not control. Parsing it inside pydantic
    # turns syntax errors, invalid UTF-8 and absurd nesting into a ValidationError, so every
    # unusable answer takes this one path.
    try:
        return AnalyzeResponse.model_validate_json(body)
    except ValidationError as exc:
        return _failed(f"invalid response: {_reason(exc)}")


class HttpAnalyzeClient:
    """A ``DetectorClient`` that calls an analyze service over HTTP.

    A failed exchange (no answer, an error status, an answer that cannot be used) comes back as
    ``AnalyzeResponse(failed=True, error=...)`` rather than as an exception. The client words
    that error as a short phrase and never puts the token or any part of the answer in it; a
    service that itself answers ``failed: true`` has its own ``error`` passed on unchanged. A
    hook of the host that raises anything but ``EndpointRejected`` is a bug in the host and is
    not caught here.

    - ``token`` returns the bearer token for a request, or ``None`` when there is none. It is
      called for every request, after the endpoint guard accepted the address, so a refused
      address never costs a secret lookup. With ``token_required``, nothing is sent unless it
      returned a token.
    - ``endpoint_guard`` is asked about the address before every request.
    - ``verify`` is ``True`` for the default CA bundle, a path to a CA bundle file or directory
      for a private CA, or ``False`` to skip certificate checks.
    - ``max_response_bytes`` caps the answer, counted after decompression.
    - ``transport`` replaces the network layer; tests use it to stand in for the service.
    """

    def __init__(
        self,
        endpoint: str,
        *,
        token: Callable[[], Awaitable[str | None]] | None = None,
        token_required: bool = False,
        endpoint_guard: EndpointGuard | None = None,
        verify: bool | str = True,
        max_response_bytes: int = 1_048_576,
        transport: httpx.AsyncBaseTransport | None = None,
    ) -> None:
        if not _INSTALLED:
            raise RuntimeError(HTTP_MISSING)
        self._endpoint = endpoint
        self._token = token
        self._token_required = token_required
        self._endpoint_guard = endpoint_guard
        self._max_response_bytes = max_response_bytes
        self._closed = False
        # The guard approves one address, so a redirect must not move the request elsewhere,
        # and nothing in the environment (proxies, certificate paths) may either.
        self._client = httpx.AsyncClient(
            trust_env=False,
            follow_redirects=False,
            verify=_tls_verify(verify),
            transport=transport,
        )

    async def analyze(self, request: AnalyzeRequest, deadline_s: float) -> AnalyzeResponse:
        """Post ``request`` to the service and return its answer, or a failed response.

        ``deadline_s`` is the HTTP timeout for connecting, for sending and for every wait on the
        service; the caller, the detector runner, bounds the call as a whole.
        """
        if self._closed:
            return _failed("client closed")
        if self._endpoint_guard is not None:
            try:
                await self._endpoint_guard.check(self._endpoint)
            except EndpointRejected as exc:
                return _failed(f"endpoint rejected: {exc.reason}")
        headers: dict[str, str] = {}
        token = await self._token() if self._token is not None else None
        if token:
            if not _is_header_safe(token):
                return _failed("invalid credential")
            headers["Authorization"] = f"Bearer {token}"
        elif self._token_required:
            return _failed("credential not found")
        try:
            async with self._client.stream(
                "POST",
                self._endpoint,
                json=request.model_dump(mode="json"),
                headers=headers,
                timeout=max(deadline_s, _MIN_TIMEOUT_S),
            ) as response:
                if not response.is_success:
                    return _failed(f"HTTP {response.status_code}")
                body = await _read_capped(response, self._max_response_bytes)
        except httpx.InvalidURL:
            return _failed("invalid endpoint")
        except httpx.HTTPError as exc:
            return _failed(f"transport: {type(exc).__name__}")
        if body is None:
            return _failed("response too large")
        return _parse(body)

    async def aclose(self) -> None:
        """Close the connections. Later calls to ``analyze`` fail without sending anything."""
        self._closed = True
        await self._client.aclose()

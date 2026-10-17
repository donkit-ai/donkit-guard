"""HTTP client for the analyze contract, behind an optional dependency.

A remote detector asks an analyze service (``POST /v1/analyze``) for findings through a
``DetectorClient``. ``HttpAnalyzeClient`` is that client for a service reached over HTTP: the
reference guard-pii service, or a service that a host's tenants run themselves. The address can
come from a policy document, so the client is deliberately narrow: it never follows a redirect,
takes no proxy or certificate settings from the environment, asks for an uncompressed answer
and caps its size, and, when the host provides an ``EndpointGuard``, asks it before anything
is sent. ``HttpConnections`` holds the connections that the clients of one host share.

``httpx`` is the ``http`` extra. This is the only module that imports it, and importing this
module never fails: a missing package is reported when a client or its connections are
constructed.
"""

from __future__ import annotations

import os
import ssl
import threading
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
# How much of the error a service reports for itself is passed on. The text is the service's,
# and it ends up in log lines, audit events and the explanation of a decision.
_MAX_SERVICE_ERROR_CHARS = 200


def tls_verify(ca_bundle: str | None) -> bool | ssl.SSLContext:
    """The certificate setting of connections that trust the CA certificates in ``ca_bundle``.

    ``None`` stands for the default CA bundle and gives ``True``. A directory of CA
    certificates or a file of them gives an SSL context that trusts those certificates. A
    file is read here, so a missing or unreadable one raises ``OSError``, and one without a
    certificate in it ``ssl.SSLError``; the certificates of a directory are read when a
    connection needs them.
    """
    if ca_bundle is None:
        return True
    if os.path.isdir(ca_bundle):
        return ssl.create_default_context(capath=ca_bundle)
    return ssl.create_default_context(cafile=ca_bundle)


def _failed(error: str) -> AnalyzeResponse:
    return AnalyzeResponse(failed=True, error=error)


def _origin(endpoint: str) -> tuple[str, str, int | None]:
    """Scheme, host and port of ``endpoint``, the port ``None`` when it is the scheme's default.

    Raises ``httpx.InvalidURL`` for an endpoint that cannot be parsed.
    """
    url = httpx.URL(endpoint)
    return url.scheme, url.host, url.port


def _is_header_safe(value: str) -> bool:
    """Whether ``value`` can go into a header: printable ASCII, no line breaks."""
    return value.isascii() and value.isprintable()


def _is_encoded(response: httpx.Response) -> bool:
    """Whether the answer comes in a content coding, such as gzip, rather than as it is."""
    codings = response.headers.get_list("content-encoding", split_commas=True)
    return any(coding.strip().lower() not in ("", "identity") for coding in codings)


async def _read_capped(response: httpx.Response, limit: int) -> bytes | None:
    """The body of ``response`` as received, or ``None`` once it grows past ``limit`` bytes."""
    if response.is_stream_consumed:
        # A transport that answers from memory, as httpx.MockTransport does, hands the body
        # over already read and leaves no stream to read: the memory is spent, and the cap
        # can only refuse the answer.
        content = response.content
        return content if len(content) <= limit else None
    body = bytearray()
    async for chunk in response.aiter_raw():
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
        response = AnalyzeResponse.model_validate_json(body)
    except ValidationError as exc:
        return _failed(f"invalid response: {_reason(exc)}")
    if response.error is not None and len(response.error) > _MAX_SERVICE_ERROR_CHARS:
        return response.model_copy(update={"error": response.error[:_MAX_SERVICE_ERROR_CHARS]})
    return response


class HttpConnections:
    """The HTTP connections that the analyze clients of one host share.

    Every origin (scheme, host and port) gets an ``httpx.AsyncClient`` of its own, made the
    first time a client calls it, so that a service that keeps its connections busy cannot
    starve the pool another service needs. All of them use the same certificate setting and
    transport, take no proxy or certificate settings from the environment and never follow a
    redirect: an endpoint guard approves an address as written, and a redirect must not move
    the request elsewhere.

    The origins are the ones the host's configuration and policy documents name, so their
    number follows the configuration, not the traffic. An origin's client keeps its
    connections open for reuse; httpx closes those that stayed idle past its keep-alive expiry
    the next time that client sends a request, and ``aclose`` closes them all.

    - ``verify`` is ``True`` for the default CA bundle, an SSL context (``tls_verify`` makes
      one for a private CA), or ``False`` to skip certificate checks.
    - ``transport`` replaces the network layer; tests use it to stand in for the services.

    ``client_for`` may be called from several threads.
    """

    def __init__(
        self,
        *,
        verify: bool | ssl.SSLContext = True,
        transport: httpx.AsyncBaseTransport | None = None,
    ) -> None:
        if not _INSTALLED:
            raise RuntimeError(HTTP_MISSING)
        self._verify = verify
        self._transport = transport
        self._lock = threading.Lock()
        self._clients: dict[tuple[str, str, int | None], httpx.AsyncClient] = {}
        self._closed = False

    @property
    def closed(self) -> bool:
        """Whether ``aclose`` was called."""
        return self._closed

    def client_for(self, endpoint: str) -> httpx.AsyncClient | None:
        """The client for the origin of ``endpoint``, or ``None`` once the connections are closed.

        Raises ``httpx.InvalidURL`` for an endpoint that cannot be parsed.
        """
        origin = _origin(endpoint)
        with self._lock:
            if self._closed:
                return None
            client = self._clients.get(origin)
            if client is None:
                client = httpx.AsyncClient(
                    trust_env=False,
                    follow_redirects=False,
                    verify=self._verify,
                    transport=self._transport,
                )
                self._clients[origin] = client
            return client

    async def aclose(self) -> None:
        """Close every connection; ``client_for`` returns ``None`` from then on."""
        with self._lock:
            self._closed = True
            clients = list(self._clients.values())
            self._clients.clear()
        for client in clients:
            await client.aclose()


class HttpAnalyzeClient:
    """A ``DetectorClient`` that calls an analyze service over HTTP.

    A failed exchange (no answer, an error status, an answer that cannot be used) comes back as
    ``AnalyzeResponse(failed=True, error=...)`` rather than as an exception. The client words
    that error as a short phrase and never puts the token or any part of the answer in it; a
    service that itself answers ``failed: true`` has its own ``error`` passed on, cut to 200
    characters. A hook of the host that raises anything but ``EndpointRejected`` is a bug in
    the host and is not caught here.

    - ``token`` returns the bearer token for a request, or ``None`` when there is none. It is
      called for every request, after the endpoint guard accepted the address, so a refused
      address never costs a secret lookup. With ``token_required``, nothing is sent unless it
      returned a token.
    - ``endpoint_guard`` is asked about the address before every request.
    - ``max_response_bytes`` caps the answer, counted as it is received. The client asks for
      an uncompressed answer and refuses a compressed one, which could unpack into far more
      than the cap.
    - ``connections`` are HTTP connections the client shares with others. The client then
      owns nothing, and closing it leaves them open for the others. Without them, the client
      makes connections of its own from ``verify`` and ``transport`` and closes them with
      itself. ``verify`` is ``True`` for the default CA bundle, a path to a CA bundle file or
      directory for a private CA, or ``False`` to skip certificate checks; ``transport``
      replaces the network layer, and tests use it to stand in for the service. Shared
      connections come with their own, so passing either together with ``connections``
      raises ``ValueError``.
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
        connections: HttpConnections | None = None,
    ) -> None:
        if not _INSTALLED:
            raise RuntimeError(HTTP_MISSING)
        if connections is None:
            connections = HttpConnections(
                verify=tls_verify(verify) if isinstance(verify, str) else verify,
                transport=transport,
            )
            self._owns_connections = True
        elif verify is not True or transport is not None:
            raise ValueError("shared connections bring their own verify and transport settings")
        else:
            self._owns_connections = False
        self._connections = connections
        self._endpoint = endpoint
        self._token = token
        self._token_required = token_required
        self._endpoint_guard = endpoint_guard
        self._max_response_bytes = max_response_bytes
        self._closed = False

    async def analyze(self, request: AnalyzeRequest, deadline_s: float) -> AnalyzeResponse:
        """Post ``request`` to the service and return its answer, or a failed response.

        ``deadline_s`` is the HTTP timeout for connecting, for sending and for every wait on the
        service; the caller, the detector runner, bounds the call as a whole.
        """
        if self._closed or self._connections.closed:
            return _failed("client closed")
        if self._endpoint_guard is not None:
            try:
                await self._endpoint_guard.check(self._endpoint)
            except EndpointRejected as exc:
                return _failed(f"endpoint rejected: {exc.reason}")
        # An uncompressed answer is one whose size can be bounded as it arrives.
        headers = {"Accept-Encoding": "identity"}
        token = await self._token() if self._token is not None else None
        if token:
            if not _is_header_safe(token):
                return _failed("invalid credential")
            headers["Authorization"] = f"Bearer {token}"
        elif self._token_required:
            return _failed("credential not found")
        try:
            client = self._connections.client_for(self._endpoint)
            if client is None:
                return _failed("client closed")
            async with client.stream(
                "POST",
                self._endpoint,
                json=request.model_dump(mode="json"),
                headers=headers,
                timeout=max(deadline_s, _MIN_TIMEOUT_S),
            ) as response:
                if not response.is_success:
                    return _failed(f"HTTP {response.status_code}")
                if _is_encoded(response):
                    return _failed("unsupported content encoding")
                body = await _read_capped(response, self._max_response_bytes)
        except httpx.InvalidURL:
            return _failed("invalid endpoint")
        except httpx.HTTPError as exc:
            return _failed(f"transport: {type(exc).__name__}")
        if body is None:
            return _failed("response too large")
        return _parse(body)

    async def aclose(self) -> None:
        """Stop the client: later calls to ``analyze`` fail without sending anything.

        Connections the client made itself are closed with it; shared ones stay open.
        """
        self._closed = True
        if self._owns_connections:
            await self._connections.aclose()

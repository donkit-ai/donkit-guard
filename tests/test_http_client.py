from __future__ import annotations

import gzip
import json
import warnings
from functools import partial
from importlib.util import find_spec
from typing import TYPE_CHECKING, Any

import pytest

from donkit_guard import http as http_module
from donkit_guard.adapters import AnalyzeRequest, AnalyzeResponse, AnalyzeSegment, AnalyzeSpan
from donkit_guard.errors import EndpointRejected
from donkit_guard.http import HttpAnalyzeClient, HttpConnections, tls_verify

if TYPE_CHECKING:
    from collections.abc import Awaitable, Callable

# The HTTP client is the "http" extra. Without it the cases are collected and reported as
# skipped, so an install with only the base dependencies keeps a green suite.
pytestmark = pytest.mark.skipif(
    find_spec("httpx") is None, reason="the 'http' extra is not installed"
)

if find_spec("httpx") is not None:
    import certifi
    import httpx

ENDPOINT = "https://detector.example/v1/analyze"
TOKEN = "secret-token"
# Text a service sends back; none of it may show up in an error.
BODY_MARK = "service-said-this"
REQUEST = AnalyzeRequest(
    segments=(AnalyzeSegment(id="s1", text="Contract DG-123456 is signed", lang=None),),
    deadline_ms=800,
)
# The answer of a service that found nothing, and the size cap of the cases that test it.
CLEAN = AnalyzeResponse().model_dump_json().encode()
CAP = 512


class Server:
    """A stand-in for the analyze service that records every request it receives."""

    def __init__(self, respond: Callable[[httpx.Request], httpx.Response]) -> None:
        self._respond = respond
        self.requests: list[httpx.Request] = []

    def __call__(self, request: httpx.Request) -> httpx.Response:
        self.requests.append(request)
        return self._respond(request)


class RefusingGuard:
    async def check(self, url: str) -> None:
        raise EndpointRejected("address is not allowed")


class RecordingGuard:
    def __init__(self) -> None:
        self.urls: list[str] = []

    async def check(self, url: str) -> None:
        self.urls.append(url)


def _answer(
    content: bytes = CLEAN,
    status: int = 200,
    headers: dict[str, str] | None = None,
    *,
    in_memory: bool = False,
) -> Callable[[httpx.Request], httpx.Response]:
    """A service that always gives this answer.

    The body is streamed, as it arrives from the network, unless ``in_memory`` hands it over
    already read, as a transport that answers from memory does.
    """

    def respond(request: httpx.Request) -> httpx.Response:
        if in_memory:
            return httpx.Response(status, headers=headers, content=content)
        return httpx.Response(status, headers=headers, stream=httpx.ByteStream(content))

    return respond


def _serving(content: bytes = CLEAN) -> Server:
    return Server(_answer(content))


def _padded(size: int) -> bytes:
    """The clean answer padded with whitespace, which JSON allows, to ``size`` bytes."""
    return CLEAN + b" " * (size - len(CLEAN))


def _token(value: str | None) -> Callable[[], Awaitable[str | None]]:
    async def token() -> str | None:
        return value

    return token


async def _unread_token() -> str | None:
    raise AssertionError("the token was looked up")


async def _analyze(
    server: Server,
    deadline_s: float = 1.0,
    endpoint: str = ENDPOINT,
    **options: Any,
) -> AnalyzeResponse:
    client = HttpAnalyzeClient(endpoint, transport=httpx.MockTransport(server), **options)
    try:
        return await client.analyze(REQUEST, deadline_s)
    finally:
        await client.aclose()


async def test_posts_the_request_and_returns_the_spans() -> None:
    span = {
        "segment_id": "s1",
        "start": 9,
        "end": 18,
        "entity_type": "CONTRACT",
        "score": 0.9,
        "rule": "dg-v2",
    }
    answer = {"detector": "contracts", "version": "3", "spans": [span], "elapsed_ms": 4}
    server = _serving(json.dumps(answer).encode())
    guard = RecordingGuard()

    response = await _analyze(server, token=_token(TOKEN), endpoint_guard=guard)

    assert not response.failed
    assert response.spans == (
        AnalyzeSpan(segment_id="s1", start=9, end=18, entity_type="CONTRACT", score=0.9),
    )
    (sent,) = server.requests
    assert (sent.method, str(sent.url)) == ("POST", ENDPOINT)
    assert sent.headers["authorization"] == f"Bearer {TOKEN}"
    assert json.loads(sent.content) == REQUEST.model_dump(mode="json")
    assert guard.urls == [ENDPOINT]


@pytest.mark.parametrize(
    ("respond", "error"),
    [
        pytest.param(
            _answer(b"", 302, {"Location": "https://elsewhere.example/v1/analyze"}),
            "HTTP 302",
            id="redirect-is-not-followed",
        ),
        pytest.param(_answer(BODY_MARK.encode(), 500), "HTTP 500", id="server-error"),
        pytest.param(_answer(_padded(CAP)), None, id="at-the-cap"),
        pytest.param(_answer(_padded(CAP + 1)), "response too large", id="past-the-cap"),
        pytest.param(
            _answer(_padded(CAP + 1), in_memory=True),
            "response too large",
            id="past-the-cap-read-in-memory",
        ),
        pytest.param(
            # A small compressed body could unpack into far more than the cap.
            _answer(gzip.compress(CLEAN), headers={"Content-Encoding": "gzip"}),
            "unsupported content encoding",
            id="compressed",
        ),
        pytest.param(
            _answer(headers={"Content-Encoding": "identity"}), None, id="identity-encoding"
        ),
        pytest.param(
            _answer(json.dumps({"failed": True, "error": "e" * 300}).encode()),
            "e" * 200,
            id="long-service-error-is-cut",
        ),
    ],
)
async def test_answer_outcomes(
    respond: Callable[[httpx.Request], httpx.Response], error: str | None
) -> None:
    server = Server(respond)

    response = await _analyze(server, token=_token(TOKEN), max_response_bytes=CAP)

    assert (response.failed, response.error) == (error is not None, error)
    assert response.spans == ()
    # The client asks for an uncompressed answer, whose size it can bound as it arrives.
    (sent,) = server.requests
    assert sent.headers["accept-encoding"] == "identity"


@pytest.mark.parametrize("failure", ["ConnectError", "ReadTimeout", "RemoteProtocolError"])
async def test_transport_errors_fail(failure: str) -> None:
    def respond(request: httpx.Request) -> httpx.Response:
        raise getattr(httpx, failure)("connection trouble")

    response = await _analyze(Server(respond))

    assert response.failed and response.error == f"transport: {failure}"


@pytest.mark.parametrize(
    "content",
    [
        b"not json " + BODY_MARK.encode(),
        b"\xff\xfe\x00" + BODY_MARK.encode(),
        b"[" * 100_000,
        b"[]",
        b"",
    ],
    ids=["not-json", "not-utf-8", "deeply-nested", "wrong-shape", "empty"],
)
async def test_unreadable_answers_fail_as_invalid(content: bytes) -> None:
    response = await _analyze(_serving(content))

    assert response.failed
    assert response.error is not None
    assert response.error.startswith("invalid response: ")
    assert BODY_MARK not in response.error


async def test_invalid_answer_reports_where_it_went_wrong() -> None:
    span = {"segment_id": "s1", "start": BODY_MARK, "end": 4, "entity_type": "X", "score": 0.5}

    response = await _analyze(_serving(json.dumps({"spans": [span]}).encode()))

    assert response.error is not None
    assert response.error.startswith("invalid response: spans.0.start: ")
    assert BODY_MARK not in response.error


@pytest.mark.parametrize(
    ("endpoint", "options", "close_first", "error"),
    [
        pytest.param(
            ENDPOINT,
            # A refused address never costs a secret lookup.
            {"endpoint_guard": RefusingGuard(), "token": _unread_token},
            False,
            "endpoint rejected: address is not allowed",
            id="refused-endpoint",
        ),
        pytest.param(
            ENDPOINT,
            {"token": None, "token_required": True},
            False,
            "credential not found",
            id="required-credential-without-a-source",
        ),
        pytest.param(
            ENDPOINT,
            {"token": _token(None), "token_required": True},
            False,
            "credential not found",
            id="required-credential-that-is-none",
        ),
        pytest.param(
            ENDPOINT,
            {"token": _token(""), "token_required": True},
            False,
            "credential not found",
            id="required-credential-that-is-empty",
        ),
        pytest.param(
            ENDPOINT,
            {"token": _token("line\nbreak")},
            False,
            "invalid credential",
            id="token-with-a-line-break",
        ),
        pytest.param(
            ENDPOINT,
            {"token": _token("caf\N{LATIN SMALL LETTER E WITH ACUTE}")},
            False,
            "invalid credential",
            id="token-that-is-not-ascii",
        ),
        pytest.param(
            "https://detector.example:port/v1/analyze",
            {},
            False,
            "invalid endpoint",
            id="unparseable-endpoint",
        ),
        pytest.param(ENDPOINT, {"token": _unread_token}, True, "client closed", id="closed"),
    ],
)
async def test_failures_that_send_nothing(
    endpoint: str, options: dict[str, Any], close_first: bool, error: str
) -> None:
    server = _serving()
    client = HttpAnalyzeClient(endpoint, transport=httpx.MockTransport(server), **options)
    if close_first:
        await client.aclose()
    try:
        response = await client.analyze(REQUEST, 1.0)
    finally:
        # Closing a client that is closed already is harmless.
        await client.aclose()

    assert response.failed and response.error == error
    assert server.requests == []


async def test_optional_credential_that_is_missing_is_left_out() -> None:
    server = _serving()

    response = await _analyze(server, token=_token(None))

    assert not response.failed
    assert "authorization" not in server.requests[0].headers


@pytest.mark.parametrize(
    ("deadline_s", "timeout_s"),
    [(2.0, 2.0), (0.001, 0.05), (0.0, 0.05)],
)
async def test_deadline_is_the_http_timeout(deadline_s: float, timeout_s: float) -> None:
    server = _serving()

    await _analyze(server, deadline_s)

    timeout = server.requests[0].extensions["timeout"]
    assert timeout == dict.fromkeys(("connect", "read", "write", "pool"), timeout_s)


async def test_clients_on_shared_connections() -> None:
    server = _serving()
    connections = HttpConnections(transport=httpx.MockTransport(server))
    closed = HttpAnalyzeClient(ENDPOINT, connections=connections)
    still_open = HttpAnalyzeClient(ENDPOINT, connections=connections)

    # A client closed on its own leaves the connections to the clients that still use them.
    await closed.aclose()
    stopped = await closed.analyze(REQUEST, 1.0)
    answered = await still_open.analyze(REQUEST, 1.0)
    await connections.aclose()
    after = await still_open.analyze(REQUEST, 1.0)

    assert (stopped.failed, stopped.error) == (True, "client closed")
    assert not answered.failed
    assert (after.failed, after.error) == (True, "client closed")
    assert len(server.requests) == 1


async def test_connections_keep_one_client_per_origin() -> None:
    connections = HttpConnections(transport=httpx.MockTransport(_serving()))
    client = connections.client_for(ENDPOINT)

    # The default port names the same origin; another scheme or host is another origin.
    assert connections.client_for("https://detector.example:443/v2/other") is client
    assert connections.client_for("http://detector.example/v1/analyze") is not client
    assert connections.client_for("https://other.example/v1/analyze") is not client
    await connections.aclose()
    assert connections.client_for(ENDPOINT) is None


async def test_ca_bundle_path_does_not_trip_the_httpx_deprecation() -> None:
    with warnings.catch_warnings():
        warnings.filterwarnings("error", message=".*verify.*", category=DeprecationWarning)
        connections = HttpConnections(verify=tls_verify(certifi.where()))
        connections.client_for(ENDPOINT)
    await connections.aclose()


@pytest.mark.parametrize(
    "construct",
    [
        pytest.param(partial(HttpAnalyzeClient, ENDPOINT), id="client"),
        pytest.param(HttpConnections, id="connections"),
    ],
)
def test_constructing_without_the_extra_names_it(
    monkeypatch: pytest.MonkeyPatch, construct: Callable[[], object]
) -> None:
    monkeypatch.setattr(http_module, "_INSTALLED", False)

    with pytest.raises(RuntimeError, match=r"donkit-guard\[http\]"):
        construct()

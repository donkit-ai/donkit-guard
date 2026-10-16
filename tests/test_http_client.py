from __future__ import annotations

import json
import warnings
from importlib.util import find_spec
from typing import TYPE_CHECKING, Any

import pytest

from donkit_guard import http as http_module
from donkit_guard.adapters import AnalyzeRequest, AnalyzeResponse, AnalyzeSegment, AnalyzeSpan
from donkit_guard.errors import EndpointRejected
from donkit_guard.http import HttpAnalyzeClient

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


def _serving(
    content: bytes,
    status: int = 200,
    headers: dict[str, str] | None = None,
) -> Server:
    def respond(request: httpx.Request) -> httpx.Response:
        return httpx.Response(status, headers=headers, content=content)

    return Server(respond)


def _token(value: str | None) -> Callable[[], Awaitable[str | None]]:
    async def token() -> str | None:
        return value

    return token


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
    ("status", "headers", "content", "error"),
    [
        (302, {"Location": "https://elsewhere.example/v1/analyze"}, b"", "HTTP 302"),
        (500, {}, BODY_MARK.encode(), "HTTP 500"),
        (200, {}, b"x" * 1000, "response too large"),
    ],
    ids=["redirect-is-not-followed", "server-error", "oversized"],
)
async def test_answers_that_are_not_usable_fail(
    status: int, headers: dict[str, str], content: bytes, error: str
) -> None:
    server = _serving(content, status, headers)

    response = await _analyze(server, token=_token(TOKEN), max_response_bytes=256)

    assert response.failed and response.error == error and response.spans == ()
    assert len(server.requests) == 1


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


async def test_answer_exactly_at_the_cap_is_accepted() -> None:
    body = AnalyzeResponse().model_dump_json().encode()

    within = await _analyze(_serving(body), max_response_bytes=len(body))
    beyond = await _analyze(_serving(body), max_response_bytes=len(body) - 1)

    assert not within.failed
    assert beyond.error == "response too large"


async def test_refused_endpoint_is_not_contacted_and_no_secret_is_read() -> None:
    server = _serving(b"{}")
    lookups: list[str] = []

    async def token() -> str | None:
        lookups.append("lookup")
        return TOKEN

    response = await _analyze(server, token=token, endpoint_guard=RefusingGuard())

    assert response.failed and response.error == "endpoint rejected: address is not allowed"
    assert server.requests == []
    assert lookups == []


@pytest.mark.parametrize(
    "token",
    [None, _token(None), _token("")],
    ids=["no-source", "returns-none", "returns-empty"],
)
async def test_required_credential_that_is_missing_sends_nothing(
    token: Callable[[], Awaitable[str | None]] | None,
) -> None:
    server = _serving(b"{}")

    response = await _analyze(server, token=token, token_required=True)

    assert response.failed and response.error == "credential not found"
    assert server.requests == []


async def test_optional_credential_that_is_missing_is_left_out() -> None:
    server = _serving(b"{}")

    response = await _analyze(server, token=_token(None))

    assert not response.failed
    assert "authorization" not in server.requests[0].headers


@pytest.mark.parametrize(
    "value",
    ["line\nbreak", "caf\N{LATIN SMALL LETTER E WITH ACUTE}"],
    ids=["line-break", "non-ascii"],
)
async def test_token_that_cannot_be_a_header_is_refused(value: str) -> None:
    server = _serving(b"{}")

    response = await _analyze(server, token=_token(value))

    assert response.failed and response.error == "invalid credential"
    assert server.requests == []


@pytest.mark.parametrize(
    ("deadline_s", "timeout_s"),
    [(2.0, 2.0), (0.001, 0.05), (0.0, 0.05)],
)
async def test_deadline_is_the_http_timeout(deadline_s: float, timeout_s: float) -> None:
    server = _serving(b"{}")

    await _analyze(server, deadline_s)

    timeout = server.requests[0].extensions["timeout"]
    assert timeout == dict.fromkeys(("connect", "read", "write", "pool"), timeout_s)


async def test_unparseable_endpoint_fails_without_a_request() -> None:
    server = _serving(b"{}")

    response = await _analyze(server, endpoint="https://detector.example:port/v1/analyze")

    assert response.failed and response.error == "invalid endpoint"
    assert server.requests == []


async def test_closed_client_fails_instead_of_raising() -> None:
    server = _serving(b"{}")
    client = HttpAnalyzeClient(ENDPOINT, transport=httpx.MockTransport(server))
    await client.aclose()
    await client.aclose()

    response = await client.analyze(REQUEST, 1.0)

    assert response.failed and response.error == "client closed"
    assert server.requests == []


async def test_ca_bundle_path_does_not_trip_the_httpx_deprecation() -> None:
    with warnings.catch_warnings():
        warnings.filterwarnings("error", message=".*verify.*", category=DeprecationWarning)
        client = HttpAnalyzeClient(ENDPOINT, verify=certifi.where())
    await client.aclose()


def test_constructing_without_the_extra_names_it(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(http_module, "_INSTALLED", False)

    with pytest.raises(RuntimeError, match=r"donkit-guard\[http\]"):
        HttpAnalyzeClient(ENDPOINT)

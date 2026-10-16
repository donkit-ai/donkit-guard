from __future__ import annotations

import re
from collections.abc import Callable
from typing import TYPE_CHECKING

import pytest

from donkit_guard import conformance
from donkit_guard import http as http_module
from donkit_guard.adapters import AnalyzeRequest, AnalyzeResponse, AnalyzeSpan
from donkit_guard.conformance import check_service

if TYPE_CHECKING:
    from collections.abc import Awaitable

URL = "https://detector.example/v1/analyze"
CONTRACT_NUMBER = re.compile(r"ДГ-[0-9]{6}")

Respond = Callable[[AnalyzeRequest], AnalyzeResponse]

# How the violations of the cases below start. Each case changes one thing about an otherwise
# correct answer, so a case shows up as exactly the violations listed for it.
OFFSETS = "spans: span 0 in 'seg-a' has offsets"
UNKNOWN_SEGMENT = "spans: span 0 in 'x' names a segment that was not sent"
NO_ENTITY_TYPE = "spans: span 0 in 'seg-a' has an empty entity_type"
BAD_SCORE = "spans: span 0 in 'seg-a' has score"
SPANS_WITHOUT_TEXT = "empty request: answered with spans for a request that has no segments"
FAILED_EMPTY = "empty request: service reported failure: boom"
FAILED_SPANS = "spans: service reported failure: boom"
LATE = "deadline: answered after 2.00 s"


class Clock:
    """A clock that only moves when a fake service says that time passed."""

    def __init__(self) -> None:
        self.now = 0.0

    def __call__(self) -> float:
        return self.now


class FakeService:
    """A detector client that answers as ``respond`` says and takes ``takes_s`` per call."""

    def __init__(self, respond: Respond | None = None, *, takes_s: float = 0.0) -> None:
        self.clock = Clock()
        self.requests: list[AnalyzeRequest] = []
        self.deadlines: list[float] = []
        self._respond = respond or contract_numbers
        self._takes_s = takes_s

    async def analyze(self, request: AnalyzeRequest, deadline_s: float) -> AnalyzeResponse:
        self.requests.append(request)
        self.deadlines.append(deadline_s)
        self.clock.now += self._takes_s
        return self._respond(request)


def contract_numbers(request: AnalyzeRequest) -> AnalyzeResponse:
    """What a correct service answers: every contract number, offsets in code points."""
    spans = tuple(
        AnalyzeSpan(
            segment_id=segment.id,
            start=found.start(),
            end=found.end(),
            entity_type="CONTRACT",
            score=0.9,
        )
        for segment in request.segments
        for found in CONTRACT_NUMBER.finditer(segment.text)
    )
    return AnalyzeResponse(spans=spans)


def first_span_changed(**changes: object) -> Respond:
    """A correct answer whose first span is wrong in the way ``changes`` say."""

    def respond(request: AnalyzeRequest) -> AnalyzeResponse:
        answer = contract_numbers(request)
        if not answer.spans:
            return answer
        first, *rest = answer.spans
        return AnalyzeResponse(spans=(first.model_copy(update=changes), *rest))

    return respond


def span_without_text(request: AnalyzeRequest) -> AnalyzeResponse:
    """Finds something even where there is nothing to search."""
    if request.segments:
        return contract_numbers(request)
    span = AnalyzeSpan(segment_id="seg-a", start=0, end=1, entity_type="CONTRACT", score=0.9)
    return AnalyzeResponse(spans=(span,))


def failing(request: AnalyzeRequest) -> AnalyzeResponse:
    return AnalyzeResponse(failed=True, error="boom")


@pytest.mark.parametrize(
    ("respond", "takes_s", "expected"),
    [
        pytest.param(contract_numbers, 0.0, [], id="compliant"),
        pytest.param(contract_numbers, 1.5, [], id="answers-at-the-limit"),
        pytest.param(first_span_changed(end=1000), 0.0, [OFFSETS], id="end-past-the-text"),
        pytest.param(first_span_changed(start=-1), 0.0, [OFFSETS], id="negative-start"),
        pytest.param(first_span_changed(start=40, end=30), 0.0, [OFFSETS], id="end-before-start"),
        pytest.param(first_span_changed(segment_id="x"), 0.0, [UNKNOWN_SEGMENT], id="unknown-id"),
        pytest.param(first_span_changed(entity_type=""), 0.0, [NO_ENTITY_TYPE], id="no-type"),
        pytest.param(first_span_changed(score=1.5), 0.0, [BAD_SCORE], id="score-above-one"),
        pytest.param(first_span_changed(score=-0.1), 0.0, [BAD_SCORE], id="score-below-zero"),
        pytest.param(span_without_text, 0.0, [SPANS_WITHOUT_TEXT], id="spans-without-text"),
        # A failure is a fine answer to the deadline probe, as long as it comes in time.
        pytest.param(failing, 0.0, [FAILED_EMPTY, FAILED_SPANS], id="failed-answers"),
        pytest.param(contract_numbers, 2.0, [LATE], id="answers-late"),
    ],
)
async def test_check_service(respond: Respond, takes_s: float, expected: list[str]) -> None:
    service = FakeService(respond, takes_s=takes_s)

    violations = await check_service(service, clock=service.clock)

    assert len(violations) == len(expected), violations
    assert all(v.startswith(prefix) for v, prefix in zip(violations, expected, strict=True))


async def test_probes_are_built_like_the_requests_of_a_remote_detector() -> None:
    service = FakeService()

    await check_service(service, deadline_s=2.0, clock=service.clock)

    empty, pair, load = service.requests
    assert empty.segments == ()
    assert [segment.id for segment in pair.segments] == ["seg-a", "seg-b"]
    # A character beyond the Basic Multilingual Plane in one text, so that a service counting
    # UTF-16 units or bytes instead of code points shows up in its offsets.
    assert [any(ord(char) > 0xFFFF for char in s.text) for s in pair.segments] == [True, False]
    # The service is asked to answer inside a margin of the time the client will wait.
    assert (empty.deadline_ms, pair.deadline_ms, load.deadline_ms) == (1600, 1600, 1000)
    assert service.deadlines == [2.0, 2.0, 2.0]


class RecordingHttpClient:
    """Stands in for ``HttpAnalyzeClient``: answers as ``respond`` says and notes its use."""

    def __init__(
        self,
        respond: Respond,
        endpoint: str,
        token: Callable[[], Awaitable[str | None]] | None,
        token_required: bool,
    ) -> None:
        self.endpoint = endpoint
        self.token_required = token_required
        self.closed = False
        self.tokens: list[str | None] = []
        self.deadlines: list[float] = []
        self._respond = respond
        self._token = token

    async def analyze(self, request: AnalyzeRequest, deadline_s: float) -> AnalyzeResponse:
        self.deadlines.append(deadline_s)
        self.tokens.append(await self._token() if self._token is not None else None)
        return self._respond(request)

    async def aclose(self) -> None:
        self.closed = True


def install_client(
    monkeypatch: pytest.MonkeyPatch, respond: Respond = contract_numbers
) -> list[RecordingHttpClient]:
    created: list[RecordingHttpClient] = []

    def build(
        endpoint: str,
        *,
        token: Callable[[], Awaitable[str | None]] | None = None,
        token_required: bool = False,
    ) -> RecordingHttpClient:
        client = RecordingHttpClient(respond, endpoint, token, token_required)
        created.append(client)
        return client

    monkeypatch.setattr(conformance, "HttpAnalyzeClient", build)
    return created


@pytest.mark.parametrize(
    ("respond", "status", "printed"),
    [
        pytest.param(contract_numbers, 0, ["OK"], id="compliant"),
        pytest.param(span_without_text, 1, [SPANS_WITHOUT_TEXT], id="violating"),
    ],
)
def test_main_prints_the_outcome_and_closes_the_client(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    respond: Respond,
    status: int,
    printed: list[str],
) -> None:
    created = install_client(monkeypatch, respond)

    assert conformance.main([URL, "--deadline-s", "2"]) == status

    assert capsys.readouterr().out.splitlines() == printed
    (client,) = created
    assert (client.endpoint, client.closed, client.token_required) == (URL, True, False)
    assert set(client.deadlines) == {2.0}


def test_main_sends_the_token_from_the_named_variable(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("DETECTOR_TOKEN", "s3cret")
    created = install_client(monkeypatch)

    assert conformance.main([URL, "--token-env", "DETECTOR_TOKEN"]) == 0

    (client,) = created
    assert client.token_required
    assert client.tokens == ["s3cret", "s3cret", "s3cret"]


def test_main_refuses_a_token_variable_that_is_not_set(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("DETECTOR_TOKEN", raising=False)
    created = install_client(monkeypatch)

    with pytest.raises(SystemExit) as stop:
        conformance.main([URL, "--token-env", "DETECTOR_TOKEN"])

    assert stop.value.code == 2
    assert created == []


def test_main_names_the_extra_it_needs(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.setattr(http_module, "_INSTALLED", False)

    assert conformance.main([URL]) == 1

    assert "donkit-guard[http]" in capsys.readouterr().err

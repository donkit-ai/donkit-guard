"""Conformance check for a service that speaks the analyze contract.

A service answers ``POST /v1/analyze`` as ``docs/contract/analyze-v1.openapi.json`` describes.
``check_service`` sends probe requests through any ``DetectorClient`` and lists where the
answers break the contract, so an implementer finds out before a policy document points a host
at the service. The checks are structural: they cannot tell whether a service finds the right
things, only whether what it answers is something a caller can use.

Against a running service, from a shell (the command needs the ``http`` extra)::

    python -m donkit_guard.conformance https://detector.example/v1/analyze --token-env MY_TOKEN

It prints ``OK`` and exits with 0, or prints one violation per line and exits with 1.
"""

from __future__ import annotations

import argparse
import asyncio
import math
import os
import sys
import time
from typing import TYPE_CHECKING

from donkit_guard.adapters import AnalyzeRequest, AnalyzeSegment
from donkit_guard.detectors.remote_common import request_deadline_ms
from donkit_guard.http import HttpAnalyzeClient

if TYPE_CHECKING:
    from collections.abc import Awaitable, Callable, Mapping, Sequence

    from donkit_guard.adapters import AnalyzeResponse, AnalyzeSpan, DetectorClient

DEFAULT_DEADLINE_S = 5.0

# Every violation starts with the name of the probe that found it.
_EMPTY = "empty request"
_SPANS = "spans"
_DEADLINE = "deadline"

# The deadline the last probe asks for, and how many times over it an answer may arrive: the
# request and the answer need time to travel too.
_PROBE_DEADLINE_MS = 1000
_DEADLINE_SLACK = 1.5

# One code point, but two UTF-16 units and four UTF-8 bytes. Both texts end with something a
# service usually reports, so a service that counts anything but code points shows up as a span
# that runs past the end of its text.
_EMOJI = "\N{GRINNING FACE}"
_SEGMENTS = (
    AnalyzeSegment(id="seg-a", text=f"{_EMOJI} Signed by Ivan Petrov, contract ДГ-123456"),
    AnalyzeSegment(id="seg-b", text="Please call +7 495 123-45-67"),
)
# Enough text for a service that ignores the deadline to have something to be slow on.
_FILLER = "Contract ДГ-123456 was signed by Ivan Petrov, call +7 495 123-45-67. "
_LOAD = tuple(AnalyzeSegment(id=f"load-{n}", text=_FILLER * 50) for n in range(8))


def _violation(probe: str, problem: str) -> str:
    return f"{probe}: {problem}"


def _failure(response: AnalyzeResponse) -> str:
    return f"service reported failure: {response.error or 'no error given'}"


async def _probe_empty(client: DetectorClient, deadline_s: float) -> list[str]:
    request = AnalyzeRequest(deadline_ms=request_deadline_ms(deadline_s))
    response = await client.analyze(request, deadline_s)
    if response.failed:
        return [_violation(_EMPTY, _failure(response))]
    if response.spans:
        return [_violation(_EMPTY, "answered with spans for a request that has no segments")]
    return []


def _span_problems(span: AnalyzeSpan, texts: Mapping[str, str]) -> list[str]:
    """What is wrong with one span, each problem worded to follow the span's name."""
    problems: list[str] = []
    text = texts.get(span.segment_id)
    if text is None:
        problems.append("names a segment that was not sent")
    elif not 0 <= span.start <= span.end <= len(text):
        problems.append(f"has offsets {span.start}..{span.end} in a {len(text)}-character text")
    if not span.entity_type:
        problems.append("has an empty entity_type")
    if not 0.0 <= span.score <= 1.0:
        problems.append(f"has score {span.score}, outside 0..1")
    return problems


async def _probe_spans(client: DetectorClient, deadline_s: float) -> list[str]:
    request = AnalyzeRequest(segments=_SEGMENTS, deadline_ms=request_deadline_ms(deadline_s))
    response = await client.analyze(request, deadline_s)
    if response.failed:
        return [_violation(_SPANS, _failure(response))]
    texts = {segment.id: segment.text for segment in request.segments}
    return [
        _violation(_SPANS, f"span {index} in {span.segment_id!r} {problem}")
        for index, span in enumerate(response.spans)
        for problem in _span_problems(span, texts)
    ]


async def _probe_deadline(
    client: DetectorClient, deadline_s: float, clock: Callable[[], float]
) -> list[str]:
    request = AnalyzeRequest(segments=_LOAD, deadline_ms=_PROBE_DEADLINE_MS)
    started = clock()
    # The answer itself is not looked at: a result and a failure are both fine when they come
    # in time, because a service that cannot finish says so with ``failed: true``.
    await client.analyze(request, deadline_s)
    elapsed = clock() - started
    limit = _PROBE_DEADLINE_MS / 1000 * _DEADLINE_SLACK
    if elapsed <= limit:
        return []
    problem = (
        f"answered after {elapsed:.2f} s, but a request with a {_PROBE_DEADLINE_MS} ms deadline "
        f"is owed an answer or a failure within {limit:.2f} s"
    )
    return [_violation(_DEADLINE, problem)]


async def check_service(
    client: DetectorClient,
    *,
    deadline_s: float = DEFAULT_DEADLINE_S,
    clock: Callable[[], float] = time.perf_counter,
) -> list[str]:
    """Probe the service behind ``client`` and return the contract violations it showed.

    An empty list means every probe was answered as the contract asks. Three probes run in
    order: an empty request, which must come back clean (``failed: false``, no spans); a request
    with two segments, whose spans must name a segment that was sent, lie inside its text, carry
    an entity type and a score between 0 and 1; and a request that allows one second, which
    must be answered, or failed, within a second and a half.

    ``deadline_s`` is the time limit the client gets for every call. Keep it well above a second
    and a half: a client that gives up sooner hides a service that keeps the caller waiting.
    ``clock`` times the last probe.
    """
    violations = await _probe_empty(client, deadline_s)
    violations += await _probe_spans(client, deadline_s)
    violations += await _probe_deadline(client, deadline_s, clock)
    return violations


def _seconds(text: str) -> float:
    try:
        value = float(text)
    except ValueError:
        raise argparse.ArgumentTypeError(f"{text!r} is not a number") from None
    if not (math.isfinite(value) and value > 0):
        raise argparse.ArgumentTypeError("must be a positive number of seconds")
    return value


def _constant_token(token: str) -> Callable[[], Awaitable[str | None]]:
    async def provide() -> str | None:
        return token

    return provide


async def _report(client: HttpAnalyzeClient, deadline_s: float) -> int:
    """Run the checks, print what they found and return the exit status."""
    try:
        violations = await check_service(client, deadline_s=deadline_s)
    finally:
        await client.aclose()
    if not violations:
        print("OK")
        return 0
    for violation in violations:
        print(violation)
    return 1


def main(argv: Sequence[str] | None = None) -> int:
    """Check the service at the URL on the command line; return the exit status."""
    parser = argparse.ArgumentParser(
        prog="python -m donkit_guard.conformance",
        description="Check that a service speaks the analyze contract.",
    )
    parser.add_argument(
        "url", help="the analyze endpoint, for example https://detector.example/v1/analyze"
    )
    parser.add_argument(
        "--token-env",
        metavar="NAME",
        help="environment variable that holds the bearer token to send",
    )
    parser.add_argument(
        "--deadline-s",
        metavar="S",
        type=_seconds,
        default=DEFAULT_DEADLINE_S,
        help=f"seconds the client waits for each probe (default: {DEFAULT_DEADLINE_S:g})",
    )
    args = parser.parse_args(argv)

    token: str | None = None
    if args.token_env is not None:
        token = os.environ.get(args.token_env)
        if not token:
            parser.error(f"environment variable {args.token_env} is not set or empty")
    try:
        client = HttpAnalyzeClient(
            args.url,
            token=_constant_token(token) if token is not None else None,
            token_required=token is not None,
        )
    except RuntimeError as exc:  # the optional "http" extra is not installed
        print(exc, file=sys.stderr)
        return 1
    return asyncio.run(_report(client, args.deadline_s))


if __name__ == "__main__":
    raise SystemExit(main())

from __future__ import annotations

import pytest

from donkit_guard.adapters import AnalyzeRequest, AnalyzeResponse, AnalyzeSpan
from donkit_guard.declared.remote import DeclaredRemoteDetector
from donkit_guard.declared.spec import RemoteDetectorSpec, spec_digest
from donkit_guard.detectors.base import (
    RemoteDetector,
    detector_cache_scope,
    detector_cache_ttl_s,
    detector_required,
    detector_subtypes,
    detector_timeout_ms,
)
from donkit_guard.findings import FindingClass
from donkit_guard.payload import Segment, SegmentSource, SegmentTrust


class CannedClient:
    """Answers every request with one prepared response and keeps what it was asked."""

    def __init__(self, response: AnalyzeResponse) -> None:
        self._response = response
        self.requests: list[AnalyzeRequest] = []
        self.deadlines: list[float] = []

    async def analyze(self, request: AnalyzeRequest, deadline_s: float) -> AnalyzeResponse:
        self.requests.append(request)
        self.deadlines.append(deadline_s)
        return self._response


def _spec(**overrides: object) -> RemoteDetectorSpec:
    return RemoteDetectorSpec.model_validate(
        {
            "kind": "remote",
            "id": "contract-check",
            "title": "Contract check",
            "endpoint": "https://detector.example.com/v1/analyze",
            "entities": {
                "CONTRACT": {"class": "corporate", "subtype": "CONTRACT_NUMBER"},
                "PERSON": {"class": "pii", "subtype": "PERSON_NAME"},
            },
            **overrides,
        }
    )


def _segment(text: str, lang: str | None = "ru") -> Segment:
    return Segment.of_text(text, source=SegmentSource.USER, trust=SegmentTrust.TRUSTED, lang=lang)


SPEC = _spec()
NAME = "declared:contract-check"
NUMBER = "ДГ-123456"
# The emoji is one code point: offsets count code points, not UTF-16 units.
TEXT = f"😀 Договор {NUMBER} подписал Иван Петров"
CONTRACT = (TEXT.index(NUMBER), TEXT.index(NUMBER) + len(NUMBER))
PERSON = (TEXT.index("Иван"), len(TEXT))
SEGMENT = _segment(TEXT)
HASHLIKE = Segment.of_text(
    "abc", source=SegmentSource.TOOL_RESULT, trust=SegmentTrust.UNTRUSTED, path="/sha256"
)
IMAGE = Segment.uninspected_part(
    source=SegmentSource.TOOL_RESULT, path="/image", kind="image", size_bytes=10
)
# With max_segment_bytes=10 this is cut into one chunk per line, at offsets 0, 8 and 16.
CHUNKED = "alpha 1\nbeta 22\ngamma 333\n"


def _hit(
    start: int,
    end: int,
    *,
    entity_type: str = "CONTRACT",
    score: float = 0.9,
    segment_id: str = SEGMENT.id,
) -> AnalyzeSpan:
    return AnalyzeSpan(
        segment_id=segment_id, start=start, end=end, entity_type=entity_type, score=score
    )


@pytest.mark.parametrize(
    ("hits", "expected"),
    [
        pytest.param(
            [_hit(*CONTRACT), _hit(*PERSON, entity_type="PERSON", score=0.6)],
            [
                (*CONTRACT, FindingClass.CORPORATE, "CONTRACT_NUMBER", 0.9),
                (*PERSON, FindingClass.PII, "PERSON_NAME", 0.6),
            ],
            id="mapped-types-take-the-declared-class-and-subtype",
        ),
        pytest.param(
            [_hit(*CONTRACT, entity_type="ORGANIZATION")],
            [],
            id="unmapped-type-is-dropped",
        ),
        pytest.param(
            [_hit(*CONTRACT, segment_id="elsewhere")],
            [],
            id="unknown-segment-id-is-dropped",
        ),
        pytest.param(
            [_hit(CONTRACT[0], len(TEXT) + 1)],
            [],
            id="span-past-the-text-end-is-dropped",
        ),
        pytest.param(
            [_hit(-1, CONTRACT[1])],
            [],
            id="negative-start-is-dropped",
        ),
        pytest.param(
            [_hit(CONTRACT[1], CONTRACT[0])],
            [],
            id="end-before-start-is-dropped",
        ),
        pytest.param(
            [_hit(*CONTRACT, score=1.7), _hit(*PERSON, entity_type="PERSON", score=-0.3)],
            [
                (*CONTRACT, FindingClass.CORPORATE, "CONTRACT_NUMBER", 1.0),
                (*PERSON, FindingClass.PII, "PERSON_NAME", 0.0),
            ],
            id="score-is-clamped-to-zero-and-one",
        ),
    ],
)
async def test_declared_remote_mapping(
    hits: list[AnalyzeSpan], expected: list[tuple[int, int, FindingClass, str, float]]
) -> None:
    # The service names itself differently; the declaration decides what the findings are.
    response = AnalyzeResponse(detector="other-service", version="9", spans=tuple(hits))
    findings = await DeclaredRemoteDetector(SPEC, CannedClient(response)).adetect([SEGMENT], 1.0)

    assert not findings.failed
    assert (findings.detector, findings.version) == (NAME, "1")
    assert findings.pattern_set_hash == spec_digest(SPEC)
    assert findings.segments_scanned == 1
    assert [(s.start, s.end, s.cls, s.subtype, s.score) for s in findings.spans] == expected
    assert all(s.segment_id == SEGMENT.id and s.detector == NAME for s in findings.spans)


@pytest.mark.parametrize(
    ("response", "error"),
    [
        pytest.param(
            AnalyzeResponse(failed=True, error="service down"),
            "service down",
            id="the-reported-error-is-kept",
        ),
        pytest.param(
            AnalyzeResponse(failed=True),
            "remote detector failed",
            id="no-error-text",
        ),
        pytest.param(
            AnalyzeResponse(failed=True, error="partial", spans=(_hit(*CONTRACT),)),
            "partial",
            id="spans-of-a-failed-answer-are-not-used",
        ),
    ],
)
async def test_declared_remote_failed_response(response: AnalyzeResponse, error: str) -> None:
    findings = await DeclaredRemoteDetector(SPEC, CannedClient(response)).adetect([SEGMENT], 1.0)

    assert findings.failed and findings.error == error
    assert findings.spans == ()
    assert (findings.detector, findings.pattern_set_hash) == (NAME, spec_digest(SPEC))


async def test_declared_remote_rebases_offsets_of_chunks() -> None:
    segment = _segment(CHUNKED)
    hits = [
        _hit(6, 9, segment_id=f"{segment.id}#2"),
        _hit(5, 7, segment_id=f"{segment.id}#1"),
        # Inside the segment, but past the end of the chunk the span names.
        _hit(6, 9, segment_id=f"{segment.id}#0"),
        # The service was given chunks, not the segment itself.
        _hit(0, 5, segment_id=segment.id),
    ]
    client = CannedClient(AnalyzeResponse(spans=tuple(hits)))
    detector = DeclaredRemoteDetector(SPEC, client, max_segment_bytes=10)
    findings = await detector.adetect([segment], 1.0)

    located = [(s.segment_id, s.start, s.end) for s in findings.spans]
    assert located == [(segment.id, 22, 25), (segment.id, 13, 15)]
    assert [CHUNKED[s.start : s.end] for s in findings.spans] == ["333", "22"]
    sent = client.requests[0].segments
    assert [wire.id for wire in sent] == [f"{segment.id}#{n}" for n in range(3)]
    assert "".join(wire.text for wire in sent) == CHUNKED


async def test_declared_remote_caps_findings_per_segment() -> None:
    chunked = _segment(CHUNKED)
    other = _segment("short")
    # 60 hits spread over the two chunks of one segment, 10 on another segment.
    hits = [_hit(0, 1, segment_id=f"{chunked.id}#{n}") for n in (0, 1) for _ in range(30)]
    hits += [_hit(0, 1, segment_id=other.id)] * 10
    client = CannedClient(AnalyzeResponse(spans=tuple(hits)))
    detector = DeclaredRemoteDetector(SPEC, client, max_segment_bytes=10)
    findings = await detector.adetect([chunked, other], 1.0)

    kept = [s.segment_id for s in findings.spans]
    assert (kept.count(chunked.id), kept.count(other.id)) == (50, 10)


async def test_declared_remote_sends_only_text_to_inspect() -> None:
    client = CannedClient(AnalyzeResponse())
    segments = [HASHLIKE, IMAGE, _segment("hello", lang="de"), _segment("world", lang=None)]
    findings = await DeclaredRemoteDetector(SPEC, client).adetect(segments, 1.0)

    assert not findings.failed and findings.segments_scanned == 2
    # The language is passed on as the segment has it.
    sent = [(wire.text, wire.lang) for wire in client.requests[0].segments]
    assert sent == [("hello", "de"), ("world", None)]
    # The service is asked to answer inside a margin of the deadline the caller gave.
    assert client.requests[0].deadline_ms == 800
    assert client.deadlines == [1.0]


async def test_declared_remote_asks_nothing_without_text_to_inspect() -> None:
    client = CannedClient(AnalyzeResponse())
    findings = await DeclaredRemoteDetector(SPEC, client).adetect([HASHLIKE, IMAGE], 1.0)

    assert client.requests == []
    assert not findings.failed and findings.segments_scanned == 0 and findings.spans == ()


def test_declared_remote_exposes_what_the_runner_reads() -> None:
    spec = _spec(timeout_ms=500, cache_ttl_s=0, required=False)
    client = CannedClient(AnalyzeResponse())
    detector = DeclaredRemoteDetector(spec, client, cache_scope="tenant-a")

    assert isinstance(detector, RemoteDetector)
    assert (detector.name, detector.version) == (NAME, "1")
    assert detector.classes == {FindingClass.CORPORATE, FindingClass.PII}
    assert detector.pattern_set_hash == spec_digest(spec)
    assert detector_subtypes(detector) == {"CONTRACT_NUMBER", "PERSON_NAME"}
    assert detector_cache_scope(detector) == "tenant-a"
    assert detector_timeout_ms(detector) == 500
    assert detector_cache_ttl_s(detector) == 0
    assert detector_required(detector) is False

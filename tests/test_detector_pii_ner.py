from __future__ import annotations

from donkit_guard.adapters import AnalyzeRequest, AnalyzeResponse, AnalyzeSpan
from donkit_guard.detectors.pii_ner import PiiNerDetector, chunk_segment
from donkit_guard.memory import FailingDetectorClient, StaticDetectorClient
from donkit_guard.payload import Segment, SegmentSource, SegmentTrust


class ForeignDetectorClient:
    """A service answering as some other detector, or as another version of this one."""

    def __init__(self, detector: str = "pii-ner", version: str = "1") -> None:
        self._response = AnalyzeResponse(detector=detector, version=version)

    async def analyze(self, request: AnalyzeRequest, deadline_s: float) -> AnalyzeResponse:
        return self._response


def _segment(text: str, lang: str | None = "ru") -> Segment:
    return Segment.of_text(text, source=SegmentSource.USER, trust=SegmentTrust.TRUSTED, lang=lang)


async def test_maps_service_spans_back_to_segments() -> None:
    seg = _segment("Клиент Иван Петров")
    client = StaticDetectorClient(
        {seg.id: [AnalyzeSpan(segment_id=seg.id, start=7, end=18, entity_type="PERSON", score=0.9)]}
    )
    findings = await PiiNerDetector(client).adetect([seg], 1.0)
    assert not findings.failed and findings.segments_scanned == 1
    span = findings.spans[0]
    assert (span.start, span.end, span.subtype, span.score) == (7, 18, "PERSON", 0.9)
    assert client.requests[0].segments[0].lang == "ru"


async def test_deadline_leaves_room_for_the_round_trip() -> None:
    seg = _segment("Клиент Иван Петров")
    client = StaticDetectorClient({})
    await PiiNerDetector(client).adetect([seg], 1.0)
    await PiiNerDetector(client).adetect([seg], 0.001)
    await PiiNerDetector(client).adetect([seg], 100.0)
    # The service has to answer, partially if need be, before the runner gives up, and a
    # host budget beyond the wire bound is clamped rather than rejected by the service.
    assert [request.deadline_ms for request in client.requests] == [800, 1, 60_000]


async def test_failed_response_is_failed_findings() -> None:
    findings = await PiiNerDetector(FailingDetectorClient("down")).adetect([_segment("x")], 1.0)
    assert findings.failed and findings.error == "down"
    assert findings.pattern_set_hash == ""


async def test_response_from_another_detector_version_is_a_failure() -> None:
    mismatch = await PiiNerDetector(ForeignDetectorClient(version="2")).adetect(
        [_segment("x")], 1.0
    )
    assert mismatch.failed and mismatch.error == "version mismatch: pii-ner@2"
    foreign = await PiiNerDetector(ForeignDetectorClient(detector="other")).adetect(
        [_segment("x")], 1.0
    )
    assert foreign.failed and foreign.error == "version mismatch: other@1"
    matching = await PiiNerDetector(ForeignDetectorClient()).adetect([_segment("x")], 1.0)
    assert not matching.failed


async def test_skips_uninspected_and_hashlike_and_uses_default_lang() -> None:
    hashlike = Segment.of_text(
        "abc", source=SegmentSource.TOOL_RESULT, trust=SegmentTrust.UNTRUSTED, path="/sha256"
    )
    plain = _segment("hello", lang=None)
    client = StaticDetectorClient({})
    findings = await PiiNerDetector(client, default_lang="en").adetect([hashlike, plain], 0.5)
    assert findings.segments_scanned == 1
    assert client.requests[0].segments[0].lang == "en"
    empty = await PiiNerDetector(client).adetect([hashlike], 0.5)
    assert empty.segments_scanned == 0 and len(client.requests) == 1


def test_chunking_keeps_offsets() -> None:
    text = "".join(f"line {i} " + "x" * 100 + "\n" for i in range(400))
    seg = _segment(text)
    chunks = chunk_segment(seg, 4096)
    assert len(chunks) > 1
    assert chunks[0][1] == 0
    rebuilt = "".join(chunk for _, _, chunk in chunks)
    assert rebuilt == text
    for chunk_id, offset, chunk in chunks:
        assert chunk_id.startswith(seg.id) and text[offset : offset + len(chunk)] == chunk


async def test_chunk_hits_are_offset() -> None:
    text = "".join(f"row {i}\n" for i in range(3000))
    seg = _segment(text)
    chunks = chunk_segment(seg, 4096)
    second_id, second_offset, _ = chunks[1]
    client = StaticDetectorClient(
        {
            second_id: [
                AnalyzeSpan(segment_id=second_id, start=0, end=3, entity_type="LOCATION", score=0.6)
            ]
        }
    )
    findings = await PiiNerDetector(client, max_segment_bytes=4096).adetect([seg], 2.0)
    assert findings.spans[0].start == second_offset and findings.spans[0].segment_id == seg.id

"""Remote NER PII detector: delegates to the guard-pii service through DetectorClient."""

from __future__ import annotations

from typing import TYPE_CHECKING, Literal

from donkit_guard.adapters import MAX_DEADLINE_MS, AnalyzeRequest, AnalyzeSegment, DetectorClient
from donkit_guard.detectors.base import failed_findings
from donkit_guard.findings import FindingClass, Findings, FindingSpan

if TYPE_CHECKING:
    from collections.abc import Sequence

    from donkit_guard.payload import Segment


def chunk_segment(segment: Segment, max_bytes: int) -> list[tuple[str, int, str]]:
    """Split a long segment at line boundaries; each chunk keeps its character offset."""
    text = segment.text or ""
    if len(text.encode("utf-8")) <= max_bytes:
        return [(segment.id, 0, text)]
    chunks: list[tuple[str, int, str]] = []
    offset = 0
    lines = text.splitlines(keepends=True)
    buffer: list[str] = []
    size = 0
    start = 0
    for line in lines:
        line_size = len(line.encode("utf-8"))
        if buffer and size + line_size > max_bytes:
            chunk_text = "".join(buffer)
            chunks.append((f"{segment.id}#{len(chunks)}", start, chunk_text))
            start += len(chunk_text)
            buffer, size = [], 0
        buffer.append(line)
        size += line_size
    if buffer:
        chunks.append((f"{segment.id}#{len(chunks)}", start, "".join(buffer)))
    return chunks or [(segment.id, offset, text)]


# The service is asked to answer inside a fraction of the runner's own deadline, so
# that its partial answer still travels back before the runner gives up on it.
DEADLINE_MARGIN = 0.8


class PiiNerDetector:
    name = "pii-ner"
    version = "1"
    classes = frozenset({FindingClass.PII})
    remote = True
    # The patterns live in the service and are versioned by its own response.
    pattern_set_hash = ""

    def __init__(
        self,
        client: DetectorClient,
        *,
        max_segment_bytes: int = 32 * 1024,
        default_lang: Literal["ru", "en"] = "en",
    ) -> None:
        self._client = client
        self._max_segment_bytes = max_segment_bytes
        self._default_lang: Literal["ru", "en"] = default_lang

    def _lang(self, segment: Segment) -> Literal["ru", "en"]:
        return (
            "ru" if segment.lang == "ru" else ("en" if segment.lang == "en" else self._default_lang)
        )

    async def adetect(self, segments: Sequence[Segment], deadline_s: float) -> Findings:
        wire: list[AnalyzeSegment] = []
        origin: dict[str, tuple[Segment, int]] = {}
        scanned = 0
        for segment in segments:
            if segment.text is None or segment.uninspected or segment.hashlike():
                continue
            scanned += 1
            for chunk_id, offset, text in chunk_segment(segment, self._max_segment_bytes):
                wire.append(AnalyzeSegment(id=chunk_id, text=text, lang=self._lang(segment)))
                origin[chunk_id] = (segment, offset)
        if not wire:
            return Findings(detector=self.name, version=self.version, segments_scanned=0)
        request = AnalyzeRequest(
            segments=tuple(wire),
            deadline_ms=max(1, min(MAX_DEADLINE_MS, int(deadline_s * 1000 * DEADLINE_MARGIN))),
        )
        response = await self._client.analyze(request, deadline_s)
        if response.failed:
            return failed_findings(self, response.error or "remote detector failed")
        if response.detector != self.name or response.version != self.version:
            # Another detector's spans would be attributed to this one, and the
            # subtypes a policy selects on are that detector's, not ours.
            return failed_findings(
                self, f"version mismatch: {response.detector}@{response.version}"
            )
        spans: list[FindingSpan] = []
        for hit in response.spans:
            located = origin.get(hit.segment_id)
            if located is None:
                continue
            segment, offset = located
            spans.append(
                FindingSpan(
                    segment_id=segment.id,
                    path=segment.path,
                    start=offset + hit.start,
                    end=offset + hit.end,
                    cls=FindingClass.PII,
                    subtype=hit.entity_type,
                    score=max(0.0, min(1.0, hit.score)),
                    detector=self.name,
                )
            )
        return Findings(
            detector=self.name,
            version=self.version,
            pattern_set_hash=self.pattern_set_hash,
            spans=tuple(spans),
            segments_scanned=scanned,
        )

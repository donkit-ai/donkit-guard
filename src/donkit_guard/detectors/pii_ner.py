"""Remote NER PII detector: delegates to the guard-pii service through DetectorClient."""

from __future__ import annotations

from typing import TYPE_CHECKING, Literal

from donkit_guard.adapters import AnalyzeRequest, DetectorClient
from donkit_guard.detectors.base import failed_findings
from donkit_guard.detectors.remote_common import build_wire, request_deadline_ms
from donkit_guard.findings import FindingClass, Findings, FindingSpan

if TYPE_CHECKING:
    from collections.abc import Sequence

    from donkit_guard.payload import Segment


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
        wire = build_wire(segments, self._max_segment_bytes, self._lang)
        if not wire.segments:
            return Findings(detector=self.name, version=self.version, segments_scanned=0)
        request = AnalyzeRequest(
            segments=wire.segments,
            deadline_ms=request_deadline_ms(deadline_s),
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
            located = wire.origin.get(hit.segment_id)
            if located is None:
                continue
            segment, offset, _ = located
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
            segments_scanned=wire.scanned,
        )

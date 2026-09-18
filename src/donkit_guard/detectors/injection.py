"""Injection heuristic: reports instruction-like content; never an enforcement decision by itself."""

from __future__ import annotations

from typing import TYPE_CHECKING

from donkit_guard.detectors.base import register_detector
from donkit_guard.detectors.injection_patterns import (
    DOC,
    PATTERN_SET_HASH,
    TR,
    UM,
    Detection,
    score_text,
)
from donkit_guard.findings import FindingClass, Findings, FindingSpan
from donkit_guard.payload import Segment, SegmentSource

if TYPE_CHECKING:
    from collections.abc import Sequence

_SOURCE_KIND = {
    SegmentSource.USER: UM,
    SegmentSource.DOCUMENT: DOC,
    SegmentSource.TOOL_RESULT: TR,
    SegmentSource.TOOL_ARGS: TR,
}


class InjectionHeuristic:
    name = "injection-heuristic"
    version = "1"
    classes = frozenset({FindingClass.INJECTION})
    remote = False
    pattern_set_hash = PATTERN_SET_HASH
    THRESHOLD_SUSPECTED = 0.5

    def _spans(self, segment: Segment, detection: Detection) -> list[FindingSpan]:
        if not detection.hits or detection.score < self.THRESHOLD_SUSPECTED:
            return []
        spans = [
            FindingSpan(
                segment_id=segment.id,
                path=segment.path,
                start=0,
                end=0,
                cls=FindingClass.INJECTION,
                subtype="score",
                score=round(min(1.0, detection.score), 3),
                detector=self.name,
            )
        ]
        for hit in detection.hits:
            spans.append(
                FindingSpan(
                    segment_id=segment.id,
                    path=segment.path,
                    start=hit.start,
                    end=hit.end,
                    cls=FindingClass.INJECTION,
                    subtype=hit.family,
                    score=round(min(1.0, detection.families.get(hit.family, hit.weight)), 3),
                    detector=self.name,
                )
            )
        return spans

    def detect(self, segments: Sequence[Segment]) -> Findings:
        spans: list[FindingSpan] = []
        scanned = 0
        for segment in segments:
            kind = _SOURCE_KIND.get(segment.source)
            if kind is None or segment.text is None or segment.uninspected:
                continue
            scanned += 1
            spans.extend(self._spans(segment, score_text(segment.text, kind)))
        return Findings(
            detector=self.name,
            version=self.version,
            pattern_set_hash=self.pattern_set_hash,
            spans=tuple(spans),
            segments_scanned=scanned,
        )


register_detector(InjectionHeuristic)

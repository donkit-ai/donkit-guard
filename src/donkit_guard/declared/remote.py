"""Declared remote detector: findings from a service that speaks the analyze contract.

A policy document names the service and says which finding class and subtype each entity type
it reports stands for. The service is sent only the text of the segments it is asked about,
cut into chunks, and their language hint.
"""

from __future__ import annotations

from collections import Counter
from typing import TYPE_CHECKING

from donkit_guard.adapters import AnalyzeRequest, DetectorClient
from donkit_guard.declared.spec import MAX_FINDINGS_PER_SEGMENT, RemoteDetectorSpec, spec_digest
from donkit_guard.detectors.base import empty_findings, failed_findings
from donkit_guard.detectors.remote_common import build_wire, request_deadline_ms
from donkit_guard.findings import Findings, FindingSpan

if TYPE_CHECKING:
    from collections.abc import Sequence

    from donkit_guard.payload import Segment


class DeclaredRemoteDetector:
    """The detector a ``remote`` declaration stands for.

    Only entity types the declaration lists become findings, with the class and subtype it
    gives them. The service is not trusted to stay inside the text it was sent: a span that
    does not lie within the chunk it names is dropped, and a segment yields at most
    ``MAX_FINDINGS_PER_SEGMENT`` findings. The name and version the service reports for itself
    are ignored, because the declaration decides what these findings are.
    """

    version = "1"
    remote = True

    def __init__(
        self,
        spec: RemoteDetectorSpec,
        client: DetectorClient,
        *,
        cache_scope: str = "",
        max_segment_bytes: int = 32 * 1024,
    ) -> None:
        self._client = client
        self._entities = dict(spec.entities)
        self._max_segment_bytes = max_segment_bytes
        self.name = f"declared:{spec.id}"
        self.classes = frozenset(mapping.cls for mapping in self._entities.values())
        self.pattern_set_hash = spec_digest(spec)
        # Optional detector attributes, read through the ``detector_*`` accessors of
        # ``donkit_guard.detectors.base``.
        self.subtypes = frozenset(mapping.subtype for mapping in self._entities.values())
        self.cache_scope = cache_scope
        self.timeout_ms = spec.timeout_ms
        self.cache_ttl_s = spec.cache_ttl_s
        self.required = spec.required

    async def adetect(self, segments: Sequence[Segment], deadline_s: float) -> Findings:
        wire = build_wire(segments, self._max_segment_bytes, _segment_lang)
        if not wire.segments:
            return empty_findings(self)
        request = AnalyzeRequest(
            segments=wire.segments,
            deadline_ms=request_deadline_ms(deadline_s),
        )
        response = await self._client.analyze(request, deadline_s)
        if response.failed:
            return failed_findings(self, response.error or "remote detector failed")
        spans: list[FindingSpan] = []
        # Findings kept per segment, over all of its chunks.
        reported: Counter[str] = Counter()
        for hit in response.spans:
            mapping = self._entities.get(hit.entity_type)
            located = wire.origin.get(hit.segment_id)
            if mapping is None or located is None:
                continue
            segment, offset, length = located
            if not 0 <= hit.start <= hit.end <= length:
                continue
            if reported[segment.id] >= MAX_FINDINGS_PER_SEGMENT:
                continue
            reported[segment.id] += 1
            spans.append(
                FindingSpan(
                    segment_id=segment.id,
                    path=segment.path,
                    start=offset + hit.start,
                    end=offset + hit.end,
                    cls=mapping.cls,
                    subtype=mapping.subtype,
                    # A service may answer any float; a finding's score lies within [0, 1].
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


def _segment_lang(segment: Segment) -> str | None:
    # The service is given the segment's language hint as it is; which codes it supports is
    # for the service to decide.
    return segment.lang

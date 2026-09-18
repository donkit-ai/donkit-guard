"""Deterministic masking of finding spans without breaking JSON or tool semantics."""

from __future__ import annotations

import hashlib
from typing import TYPE_CHECKING

from pydantic import Field

from donkit_guard.context import FrozenModel
from donkit_guard.decision import Location
from donkit_guard.findings import FindingClass, FindingSpan
from donkit_guard.payload import Payload, Segment, SegmentSource

if TYPE_CHECKING:
    from collections.abc import Collection, Sequence


class MaskResult(FrozenModel):
    masked: dict[str, str] = Field(default_factory=dict)
    masked_locations: tuple[Location, ...] = ()
    impossible: tuple[Location, ...] = ()

    @property
    def ok(self) -> bool:
        return not self.impossible


def placeholder(span: FindingSpan, original: str) -> str:
    """Stable placeholder: secrets by class, everything else by subtype plus a short value hash."""
    if span.cls is FindingClass.SECRET:
        return f"[REDACTED:{span.subtype}]"
    digest = hashlib.sha256(original.encode("utf-8")).hexdigest()[:6]
    return f"<{span.subtype.upper()}_{digest}>"


def merge_ranges(spans: Sequence[FindingSpan]) -> list[tuple[int, int, FindingSpan]]:
    """Merge overlapping spans of one segment; the earliest span names the merged range."""
    merged: list[tuple[int, int, FindingSpan]] = []
    for span in sorted(spans, key=lambda s: (s.start, -s.end)):
        if merged and span.start < merged[-1][1]:
            start, end, first = merged[-1]
            merged[-1] = (start, max(end, span.end), first)
        else:
            merged.append((span.start, span.end, span))
    return merged


def _mask_segment(segment: Segment, spans: Sequence[FindingSpan]) -> str:
    text = segment.text or ""
    pieces: list[str] = []
    cursor = 0
    for start, end, first in merge_ranges(spans):
        start = min(max(start, cursor), len(text))
        end = min(max(end, start), len(text))
        pieces.append(text[cursor:start])
        pieces.append(placeholder(first, text[start:end]))
        cursor = end
    pieces.append(text[cursor:])
    return "".join(pieces)


def mask(
    payload: Payload,
    spans: Sequence[FindingSpan],
    *,
    maskable_arg_paths: Collection[str] = (),
) -> MaskResult:
    """Apply placeholders per segment.

    Tool-argument segments are never rewritten unless the host declared the
    argument path maskable: a masked identifier would make the tool perform a
    different operation than the one the model requested.
    """
    if not spans:
        return MaskResult()
    segments = payload.by_id()
    by_segment: dict[str, list[FindingSpan]] = {}
    for span in spans:
        by_segment.setdefault(span.segment_id, []).append(span)
    masked: dict[str, str] = {}
    masked_locations: list[Location] = []
    impossible: list[Location] = []
    maskable = set(maskable_arg_paths)
    for segment_id, segment_spans in by_segment.items():
        segment = segments.get(segment_id)
        if segment is None or segment.text is None or segment.uninspected:
            impossible.extend(Location.from_span(s) for s in segment_spans)
            continue
        if segment.source is SegmentSource.TOOL_ARGS and segment.path not in maskable:
            impossible.extend(Location.from_span(s) for s in segment_spans)
            continue
        masked[segment_id] = _mask_segment(segment, segment_spans)
        masked_locations.extend(Location.from_span(s) for s in segment_spans)
    return MaskResult(
        masked=masked,
        masked_locations=tuple(masked_locations),
        impossible=tuple(impossible),
    )

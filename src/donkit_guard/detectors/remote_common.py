"""Helpers shared by the remote detectors: what goes on the wire, and the service deadline."""

from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING

from donkit_guard.adapters import MAX_DEADLINE_MS, AnalyzeSegment

if TYPE_CHECKING:
    from collections.abc import Callable, Mapping, Sequence

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


@dataclass(frozen=True)
class Wire:
    """The segments of a request to an analyze service, and where each of them comes from.

    ``origin`` maps the id of every chunk sent to the segment it was cut from, the character
    offset of the chunk in that segment and the length of the chunk. ``scanned`` counts the
    segments that were sent.
    """

    segments: tuple[AnalyzeSegment, ...]
    origin: Mapping[str, tuple[Segment, int, int]]
    scanned: int


def build_wire(
    segments: Sequence[Segment],
    max_segment_bytes: int,
    lang_of: Callable[[Segment], str | None],
) -> Wire:
    """The chunks of ``segments`` a remote detector sends, and where each of them comes from.

    A segment without text, an uninspected part and a JSON leaf under a digest or identifier
    key are left out: the first two have no text to send, and a digest holds nothing a
    service could find. A segment longer than ``max_segment_bytes`` in UTF-8 is cut at line
    boundaries. Every chunk carries the language hint ``lang_of`` gives its segment.
    """
    wire: list[AnalyzeSegment] = []
    origin: dict[str, tuple[Segment, int, int]] = {}
    scanned = 0
    for segment in segments:
        if segment.text is None or segment.uninspected or segment.hashlike():
            continue
        scanned += 1
        lang = lang_of(segment)
        for chunk_id, offset, text in chunk_segment(segment, max_segment_bytes):
            wire.append(AnalyzeSegment(id=chunk_id, text=text, lang=lang))
            origin[chunk_id] = (segment, offset, len(text))
    return Wire(segments=tuple(wire), origin=origin, scanned=scanned)


# The service is asked to answer inside a fraction of the runner's own deadline, so
# that its partial answer still travels back before the runner gives up on it.
DEADLINE_MARGIN: float = 0.8


def request_deadline_ms(deadline_s: float) -> int:
    """Milliseconds the service is asked to answer within, a margin inside the deadline."""
    return max(1, min(MAX_DEADLINE_MS, int(deadline_s * 1000 * DEADLINE_MARGIN)))

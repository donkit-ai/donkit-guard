"""Helpers shared by the remote detectors: segment chunking and the service deadline."""

from __future__ import annotations

from typing import TYPE_CHECKING

from donkit_guard.adapters import MAX_DEADLINE_MS

if TYPE_CHECKING:
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
DEADLINE_MARGIN: float = 0.8


def request_deadline_ms(deadline_s: float) -> int:
    """Milliseconds the service is asked to answer within, a margin inside the deadline."""
    return max(1, min(MAX_DEADLINE_MS, int(deadline_s * 1000 * DEADLINE_MARGIN)))

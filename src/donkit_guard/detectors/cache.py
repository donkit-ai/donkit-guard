"""Per-segment detector results, keyed by detector identity and content hash."""

from __future__ import annotations

import threading
import time
from collections import OrderedDict
from typing import TYPE_CHECKING

from donkit_guard.context import FrozenModel

if TYPE_CHECKING:
    from collections.abc import Callable

    from donkit_guard.findings import FindingSpan


class CacheStats(FrozenModel):
    entries: int
    bytes: int
    hits: int
    misses: int


class DetectorResultCache:
    def __init__(
        self,
        ttl_s: float = 86400.0,
        max_bytes: int = 64 * 1024 * 1024,
        clock: Callable[[], float] = time.monotonic,
    ) -> None:
        self._ttl_s = ttl_s
        self._max_bytes = max_bytes
        self._clock = clock
        self._lock = threading.Lock()
        self._entries: OrderedDict[tuple[str, str], tuple[float, tuple[FindingSpan, ...], int]] = (
            OrderedDict()
        )
        self._bytes = 0
        self._hits = 0
        self._misses = 0

    @staticmethod
    def _size_of(spans: tuple[FindingSpan, ...]) -> int:
        """Approximate retained size: the cap bounds memory, it does not measure it exactly."""
        return 96 + sum(64 + len(span.subtype) + len(span.path) for span in spans)

    def get(self, detector_key: str, segment_id: str) -> tuple[FindingSpan, ...] | None:
        key = (detector_key, segment_id)
        with self._lock:
            entry = self._entries.get(key)
            if entry is None:
                self._misses += 1
                return None
            expires_at, spans, size = entry
            if self._clock() >= expires_at:
                del self._entries[key]
                self._bytes -= size
                self._misses += 1
                return None
            self._entries.move_to_end(key)
            self._hits += 1
            return spans

    def put(self, detector_key: str, segment_id: str, spans: tuple[FindingSpan, ...]) -> None:
        key = (detector_key, segment_id)
        size = self._size_of(spans)
        with self._lock:
            old = self._entries.pop(key, None)
            if old is not None:
                self._bytes -= old[2]
            self._entries[key] = (self._clock() + self._ttl_s, spans, size)
            self._bytes += size
            while self._bytes > self._max_bytes and self._entries:
                _, (_, _, evicted_size) = self._entries.popitem(last=False)
                self._bytes -= evicted_size

    def stats(self) -> CacheStats:
        with self._lock:
            return CacheStats(
                entries=len(self._entries), bytes=self._bytes, hits=self._hits, misses=self._misses
            )

    def clear(self) -> None:
        with self._lock:
            self._entries.clear()
            self._bytes = 0

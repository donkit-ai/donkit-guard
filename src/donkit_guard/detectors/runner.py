"""Runs detectors over uncached segments with size-dependent budgets, outside the event loop."""

from __future__ import annotations

import asyncio
import json
import logging
from concurrent.futures import Executor, ProcessPoolExecutor, ThreadPoolExecutor
from enum import StrEnum
from typing import TYPE_CHECKING, Any

from donkit_guard.context import FrozenModel
from donkit_guard.detectors.base import (
    DETECTOR_REGISTRY,
    AnyDetector,
    LocalDetector,
    RemoteDetector,
    detector_cache_ttl_s,
    detector_id,
    detector_key,
    detector_timeout_ms,
    failed_findings,
)
from donkit_guard.detectors.cache import DetectorResultCache
from donkit_guard.findings import Findings, FindingSpan
from donkit_guard.payload import Segment

if TYPE_CHECKING:
    from collections.abc import Sequence

logger = logging.getLogger("donkit_guard.detectors")


class Budget(FrozenModel):
    local_base_ms: float = 10.0
    local_per_kb_ms: float = 3.0
    remote_base_ms: float = 150.0
    remote_per_kb_ms: float = 40.0
    remote_cap_ms: float = 2000.0

    def local_ms(self, size_bytes: int) -> float:
        return self.local_base_ms + self.local_per_kb_ms * (size_bytes / 1024.0)

    def remote_ms(self, size_bytes: int) -> float:
        return min(
            self.remote_cap_ms, self.remote_base_ms + self.remote_per_kb_ms * (size_bytes / 1024.0)
        )


class ExecutorKind(StrEnum):
    SYNC = "sync"
    THREAD = "thread"
    PROCESS = "process"


def _worker_detect(registry_key: str, segment_dicts: list[dict[str, Any]]) -> dict[str, Any]:
    """Process-pool entry point: rebuild the detector from the registry and scan."""
    # A fresh worker process has an empty registry until the built-ins are imported.
    import donkit_guard.detectors.builtin  # noqa: F401

    factory = DETECTOR_REGISTRY[registry_key]
    detector = factory()
    segments = [Segment.model_validate(d) for d in segment_dicts]
    return detector.detect(segments).model_dump(mode="json")


def _worker_detect_spec(payload_json: str, segment_dicts: list[dict[str, Any]]) -> dict[str, Any]:
    """Process-pool entry point: rebuild a declared detector from its spec payload and scan."""
    # Imported here and not at the top: `donkit_guard.declared` builds on this package, so a
    # module-level import would be circular. A worker imports it once it is handed a
    # declared detector.
    from donkit_guard.declared.factory import build_local_from_payload

    detector = build_local_from_payload(json.loads(payload_json))
    segments = [Segment.model_validate(d) for d in segment_dicts]
    return detector.detect(segments).model_dump(mode="json")


class DetectorRunner:
    """Runs detectors over segments, caching what each one finds in each segment.

    The runner is built with detectors of its own, and a call may name others instead: the
    built-in detectors together with those a tenant's policy document declares, for example.
    A remote detector that declares `timeout_ms` gets that deadline; any other remote
    detector gets one that grows with the size of what it is sent. Results stay cached for
    the `cache_ttl_s` a detector declares, or else for the cache's default lifetime.

    A process-pool worker cannot be handed a detector object: it rebuilds a built-in detector
    from `DETECTOR_REGISTRY` by id, and a declared one from its `spec_payload()`.
    """

    def __init__(
        self,
        detectors: Sequence[AnyDetector],
        cache: DetectorResultCache | None = None,
        executor: ExecutorKind = ExecutorKind.PROCESS,
        budget: Budget | None = None,
        max_workers: int = 2,
    ) -> None:
        self._detectors = tuple(detectors)
        self._cache = cache if cache is not None else DetectorResultCache()
        self._kind = executor
        self._budget = budget if budget is not None else Budget()
        self._max_workers = max_workers
        self._pool: Executor | None = None

    @property
    def detectors(self) -> tuple[AnyDetector, ...]:
        """The runner's own detectors, which `run` and `versions` use when given none."""
        return self._detectors

    def versions(self, detectors: Sequence[AnyDetector] | None = None) -> dict[str, str]:
        """Detector id to the pattern set it ran, for `Decision.detector_versions`.

        Covers `detectors`, or the runner's own when none are given.
        """
        chosen = self._detectors if detectors is None else detectors
        return {detector_id(d): d.pattern_set_hash for d in chosen}

    def _executor(self) -> Executor:
        if self._pool is None:
            if self._kind is ExecutorKind.PROCESS:
                self._pool = ProcessPoolExecutor(max_workers=self._max_workers)
            else:
                self._pool = ThreadPoolExecutor(max_workers=self._max_workers)
        return self._pool

    def close(self) -> None:
        self._drop_pool(cancel_futures=True)

    def _drop_pool(self, *, cancel_futures: bool) -> None:
        """Detach the pool; the next scan lazily builds a fresh one.

        Cancelling queued work is right when the owner is shutting the runner down and
        wrong when one detector timed out: the siblings of that scan are queued in the
        same pool, and a cancelled worker future reaches them as a cancellation of
        their own scan rather than as a result.
        """
        pool, self._pool = self._pool, None
        if pool is not None:
            pool.shutdown(wait=False, cancel_futures=cancel_futures)

    async def run(
        self, segments: Sequence[Segment], detectors: Sequence[AnyDetector] | None = None
    ) -> list[Findings]:
        """Scan `segments` with `detectors`, or with the runner's own when none are given.

        The given detectors need not be among the runner's own. The result holds one
        `Findings` per detector, in the order of the detectors.
        """
        chosen = self._detectors if detectors is None else detectors
        results = await asyncio.gather(*(self._run_one(d, segments) for d in chosen))
        return list(results)

    async def _run_one(self, detector: AnyDetector, segments: Sequence[Segment]) -> Findings:
        key = detector_key(detector)
        cached: list[FindingSpan] = []
        pending: list[Segment] = []
        for segment in segments:
            spans = self._cache.get(key, segment.id)
            if spans is None:
                pending.append(segment)
            else:
                cached.extend(spans)
        if not pending:
            return Findings(
                detector=detector.name,
                version=detector.version,
                pattern_set_hash=detector.pattern_set_hash,
                spans=tuple(cached),
                segments_scanned=0,
            )
        size = sum(s.size_bytes for s in pending)
        try:
            if isinstance(detector, RemoteDetector):
                timeout_ms = detector_timeout_ms(detector)
                deadline_ms = self._budget.remote_ms(size) if timeout_ms is None else timeout_ms
                deadline_s = deadline_ms / 1000.0
                fresh = await asyncio.wait_for(
                    detector.adetect(pending, deadline_s), timeout=deadline_s
                )
            elif isinstance(detector, LocalDetector):
                fresh = await self._run_local(detector, pending, size)
            else:
                raise TypeError(f"{key} implements neither LocalDetector nor RemoteDetector")
        except TimeoutError:
            logger.warning("detector %s timed out on %d bytes", key, size)
            return failed_findings(detector, "timeout")
        except Exception as exc:  # a detector crash must not become a silent allow
            logger.warning("detector %s failed: %s", key, exc)
            return failed_findings(detector, f"{type(exc).__name__}: {exc}")
        if fresh.failed:
            return fresh
        by_segment: dict[str, list[FindingSpan]] = {s.id: [] for s in pending}
        for span in fresh.spans:
            by_segment.setdefault(span.segment_id, []).append(span)
        ttl_s = detector_cache_ttl_s(detector)
        for segment_id, spans_for_segment in by_segment.items():
            self._cache.put(key, segment_id, tuple(spans_for_segment), ttl_s=ttl_s)
        return Findings(
            detector=detector.name,
            version=detector.version,
            pattern_set_hash=detector.pattern_set_hash,
            spans=tuple(cached) + fresh.spans,
            segments_scanned=len(pending),
        )

    async def _run_local(
        self, detector: LocalDetector, pending: list[Segment], size: int
    ) -> Findings:
        try:
            return await self._detect_local(detector, pending, size)
        except TimeoutError:
            # The await is cancelled, the worker keeps running: it would hold its slot
            # for every later scan, so this pool is retired instead of reused.
            self._drop_pool(cancel_futures=False)
            raise

    async def _detect_local(
        self, detector: LocalDetector, pending: list[Segment], size: int
    ) -> Findings:
        timeout_s = self._budget.local_ms(size) / 1000.0
        if self._kind is ExecutorKind.SYNC:
            return detector.detect(pending)
        loop = asyncio.get_running_loop()
        if self._kind is ExecutorKind.PROCESS:
            segment_dicts = [s.model_dump(mode="json") for s in pending]
            spec_payload = getattr(detector, "spec_payload", None)
            if callable(spec_payload):
                # A declared detector is built from a policy document, not registered: the
                # worker rebuilds it from its spec payload.
                payload_json = json.dumps(spec_payload())
                work = loop.run_in_executor(
                    self._executor(), _worker_detect_spec, payload_json, segment_dicts
                )
            else:
                registry_key = detector_id(detector)
                if registry_key not in DETECTOR_REGISTRY:
                    raise RuntimeError(
                        f"detector {registry_key} is not registered for process execution"
                    )
                work = loop.run_in_executor(
                    self._executor(), _worker_detect, registry_key, segment_dicts
                )
            raw = await asyncio.wait_for(work, timeout=timeout_s)
            return Findings.model_validate(raw)
        return await asyncio.wait_for(
            loop.run_in_executor(self._executor(), detector.detect, pending), timeout=timeout_s
        )

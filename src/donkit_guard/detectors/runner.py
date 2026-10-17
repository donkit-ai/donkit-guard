"""Runs detectors over uncached segments with size-dependent budgets, outside the event loop.

A scan runs in one of two lanes. The foreground lane is for the scans an answer is built on. The
background lane is for the scans that can wait their turn, such as those whose findings are
written after the answer went back: its local detectors run on workers of their own, and it
bounds how many of its scans run at once. A backlog of background scans therefore never holds up
a foreground scan, and a background scan's deadline starts only once it has its turn.
"""

from __future__ import annotations

import asyncio
import json
import logging
import weakref
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
    # The least a background local scan gets. It delays no answer, so it is not held to the
    # per-request budget, and a process pool that is still starting gets the time to start.
    background_min_ms: float = 1000.0

    def local_ms(self, size_bytes: int) -> float:
        return self.local_base_ms + self.local_per_kb_ms * (size_bytes / 1024.0)

    def background_local_ms(self, size_bytes: int) -> float:
        return max(self.local_ms(size_bytes), self.background_min_ms)

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


class _Pool:
    """The workers of one lane, built on first use."""

    def __init__(self, kind: ExecutorKind, max_workers: int) -> None:
        self._kind = kind
        self._max_workers = max_workers
        self._executor: Executor | None = None

    def executor(self) -> Executor:
        if self._executor is None:
            if self._kind is ExecutorKind.PROCESS:
                self._executor = ProcessPoolExecutor(max_workers=self._max_workers)
            else:
                self._executor = ThreadPoolExecutor(max_workers=self._max_workers)
        return self._executor

    def retire(self, *, cancel_futures: bool) -> None:
        """Detach the workers; the next scan lazily builds fresh ones.

        Cancelling queued work is right when the owner is shutting the runner down and
        wrong when one detector timed out: the siblings of that scan are queued in the
        same pool, and a cancelled worker future reaches them as a cancellation of
        their own scan rather than as a result.
        """
        executor, self._executor = self._executor, None
        if executor is not None:
            executor.shutdown(wait=False, cancel_futures=cancel_futures)


class _Turns:
    """How many background scans run at once on one event loop, local and remote apart."""

    def __init__(self, local: int, remote: int) -> None:
        self.local = asyncio.Semaphore(local)
        self.remote = asyncio.Semaphore(remote)


class DetectorRunner:
    """Runs detectors over segments, caching what each one finds in each segment.

    The runner is built with detectors of its own, and a call may name others instead: the
    built-in detectors together with those a tenant's policy document declares, for example.
    A remote detector that declares `timeout_ms` gets that deadline; any other remote
    detector gets one that grows with the size of what it is sent. Results stay cached for
    the `cache_ttl_s` a detector declares, or else for the cache's default lifetime.

    A background scan runs its local detectors on `background_workers` workers of their own,
    one scan per worker, and keeps at most `max_background_remote` remote calls in flight, so
    that the detectors' services keep room for the foreground calls. It waits for its turn
    before its deadline starts, and a local one gets at least `Budget.background_min_ms`. The
    turns are counted per event loop.

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
        background_workers: int = 1,
        max_background_remote: int = 16,
    ) -> None:
        if background_workers < 1 or max_background_remote < 1:
            # A lane without a single turn would leave every background scan waiting forever.
            raise ValueError("background_workers and max_background_remote must be at least 1")
        self._detectors = tuple(detectors)
        self._cache = cache if cache is not None else DetectorResultCache()
        self._kind = executor
        self._budget = budget if budget is not None else Budget()
        self._pool = _Pool(executor, max_workers)
        self._background_pool = _Pool(executor, background_workers)
        self._background_workers = background_workers
        self._max_background_remote = max_background_remote
        # A semaphore belongs to the event loop it is first used on, and the runner may serve
        # more than one loop.
        self._turns: weakref.WeakKeyDictionary[asyncio.AbstractEventLoop, _Turns] = (
            weakref.WeakKeyDictionary()
        )
        # A worker process rebuilds a declared detector from its encoded spec payload, which
        # for a long list of terms is large: it is encoded once per detector.
        self._spec_json: weakref.WeakKeyDictionary[LocalDetector, str] = weakref.WeakKeyDictionary()

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

    def close(self) -> None:
        """Release the workers of both lanes, cancelling the scans still queued for them."""
        self._pool.retire(cancel_futures=True)
        self._background_pool.retire(cancel_futures=True)

    async def run(
        self,
        segments: Sequence[Segment],
        detectors: Sequence[AnyDetector] | None = None,
        *,
        background: bool = False,
    ) -> list[Findings]:
        """Scan `segments` with `detectors`, or with the runner's own when none are given.

        The given detectors need not be among the runner's own. The result holds one
        `Findings` per detector, in the order of the detectors. With `background` the scan
        takes the background lane.
        """
        chosen = self._detectors if detectors is None else detectors
        results = await asyncio.gather(
            *(self._run_one(d, segments, background=background) for d in chosen)
        )
        return list(results)

    async def _run_one(
        self, detector: AnyDetector, segments: Sequence[Segment], *, background: bool
    ) -> Findings:
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
                fresh = await self._run_remote(detector, pending, size, background=background)
            elif isinstance(detector, LocalDetector):
                fresh = await self._run_local(detector, pending, size, background=background)
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

    def _lane_turns(self) -> _Turns:
        """The background lane's turns on the running event loop."""
        loop = asyncio.get_running_loop()
        turns = self._turns.get(loop)
        if turns is None:
            turns = self._turns[loop] = _Turns(
                self._background_workers, self._max_background_remote
            )
        return turns

    async def _run_remote(
        self, detector: RemoteDetector, pending: list[Segment], size: int, *, background: bool
    ) -> Findings:
        timeout_ms = detector_timeout_ms(detector)
        deadline_ms = self._budget.remote_ms(size) if timeout_ms is None else timeout_ms
        deadline_s = deadline_ms / 1000.0
        if not background:
            return await asyncio.wait_for(detector.adetect(pending, deadline_s), timeout=deadline_s)
        # The deadline starts with the call, not with the wait for a turn.
        async with self._lane_turns().remote:
            return await asyncio.wait_for(detector.adetect(pending, deadline_s), timeout=deadline_s)

    async def _run_local(
        self, detector: LocalDetector, pending: list[Segment], size: int, *, background: bool
    ) -> Findings:
        if self._kind is ExecutorKind.SYNC:
            return detector.detect(pending)
        if not background:
            return await self._scan(self._pool, detector, pending, self._budget.local_ms(size))
        # One scan per background worker: a scan waiting for its turn is not queued in the
        # pool, so its deadline measures the scan and not the backlog ahead of it.
        async with self._lane_turns().local:
            return await self._scan(
                self._background_pool, detector, pending, self._budget.background_local_ms(size)
            )

    async def _scan(
        self, pool: _Pool, detector: LocalDetector, pending: list[Segment], deadline_ms: float
    ) -> Findings:
        timeout_s = deadline_ms / 1000.0
        loop = asyncio.get_running_loop()
        try:
            if self._kind is not ExecutorKind.PROCESS:
                return await asyncio.wait_for(
                    loop.run_in_executor(pool.executor(), detector.detect, pending),
                    timeout=timeout_s,
                )
            raw = await asyncio.wait_for(self._submit(pool, detector, pending), timeout=timeout_s)
        except TimeoutError:
            # The await is cancelled, the worker keeps running: it would hold its slot
            # for every later scan, so this pool is retired instead of reused.
            pool.retire(cancel_futures=False)
            raise
        return Findings.model_validate(raw)

    def _submit(
        self, pool: _Pool, detector: LocalDetector, pending: list[Segment]
    ) -> asyncio.Future[dict[str, Any]]:
        """Hand a scan to a worker process, with what the worker rebuilds the detector from."""
        loop = asyncio.get_running_loop()
        segment_dicts = [s.model_dump(mode="json") for s in pending]
        spec_payload = getattr(detector, "spec_payload", None)
        if callable(spec_payload):
            # A declared detector is built from a policy document, not registered: the worker
            # rebuilds it from its spec payload.
            payload_json = self._spec_json.get(detector)
            if payload_json is None:
                payload_json = self._spec_json[detector] = json.dumps(spec_payload())
            return loop.run_in_executor(
                pool.executor(), _worker_detect_spec, payload_json, segment_dicts
            )
        registry_key = detector_id(detector)
        if registry_key not in DETECTOR_REGISTRY:
            raise RuntimeError(f"detector {registry_key} is not registered for process execution")
        return loop.run_in_executor(pool.executor(), _worker_detect, registry_key, segment_dicts)

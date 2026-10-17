"""Runs detectors over uncached segments with size-dependent budgets, outside the event loop.

With worker processes, the default, a local detector registered in ``DETECTOR_REGISTRY``, as
every built-in one is, runs in a worker process, which rebuilds it by id. Any other one, such as
a detector built from a policy document or one of the host's own, exists only as an object in
this process, so it runs in a thread.

A scan runs in one of two lanes. The foreground lane is for the scans an answer is built on. The
background lane is for the scans that can wait their turn, such as those whose findings are
written after the answer went back: its local detectors run on workers of their own, and it
bounds how many of its scans run at once. A backlog of background scans therefore never takes a
worker from a foreground scan, and a background scan's deadline starts only once it has its turn.
Threads share the interpreter, though: while a detector runs Python code in a thread of either
lane, the other threads and the event loop run slower (RE2 releases the interpreter lock while it
matches). Only worker processes, given cores to spare, keep the lanes fully apart.
"""

from __future__ import annotations

import asyncio
import logging
import threading
import weakref
from concurrent.futures import BrokenExecutor, Executor, ProcessPoolExecutor, ThreadPoolExecutor
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


class _Pool:
    """Workers of one kind for one lane, made on first use and made anew once retired."""

    def __init__(self, kind: ExecutorKind, max_workers: int) -> None:
        self._kind = kind
        self._max_workers = max_workers
        # The runner may serve event loops on several threads.
        self._lock = threading.Lock()
        self._executor: Executor | None = None

    def executor(self) -> Executor:
        with self._lock:
            if self._executor is None:
                if self._kind is ExecutorKind.PROCESS:
                    self._executor = ProcessPoolExecutor(max_workers=self._max_workers)
                else:
                    self._executor = ThreadPoolExecutor(max_workers=self._max_workers)
            return self._executor

    def retire(self, executor: Executor) -> None:
        """Stop using ``executor``; the next scan gets fresh workers.

        The scans still queued for it run to the end: a worker future cancelled under another
        scan would reach that scan as a cancellation of its own task rather than as a result.
        Workers already replaced are left alone, so that the scans that failed on the same
        workers retire them once, and not their successors as well.
        """
        with self._lock:
            if self._executor is not executor:
                return
            self._executor = None
        executor.shutdown(wait=False, cancel_futures=False)

    def close(self) -> None:
        """Stop using the workers and cancel the scans still queued for them."""
        with self._lock:
            executor, self._executor = self._executor, None
        if executor is not None:
            executor.shutdown(wait=False, cancel_futures=True)


class _Lane:
    """The workers of one lane, processes and threads, each made when a scan first needs it."""

    def __init__(self, workers: int) -> None:
        self.processes = _Pool(ExecutorKind.PROCESS, workers)
        self.threads = _Pool(ExecutorKind.THREAD, workers)

    def close(self) -> None:
        self.processes.close()
        self.threads.close()


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

    Where a local detector runs depends on `executor`:

    - `ExecutorKind.PROCESS`: a detector registered in `DETECTOR_REGISTRY`, as the built-in
      ones are, runs in worker processes, which rebuild it by id. Any other one, such as a
      detector built from a policy document or one of the host's own, runs in threads.
    - `ExecutorKind.THREAD`: every one runs in threads.
    - `ExecutorKind.SYNC`: every one runs on the event loop, in both lanes.

    Each lane has workers of its own: the foreground lane `max_workers` worker processes and
    as many threads, the background lane `background_workers` of each, by default as many as
    the foreground lane. That is one more worker for every foreground worker, and with
    `ExecutorKind.PROCESS` as many more worker processes. Workers are started when a scan
    first needs them, so a runner never starts the kind it does not use.

    A detector that runs out of time keeps its worker busy until it returns, since a running
    scan cannot be stopped, and workers that are broken, as a process pool is once one of its
    processes died, refuse every scan. Either way the scan fails and the lane stops using
    those workers: the next scan that needs workers of that kind gets fresh ones.

    The background lane runs one scan per worker and keeps at most `max_background_remote`
    remote calls in flight, so that the detectors' services keep room for the foreground
    calls. A background scan waits for its turn before its deadline starts, and a local one
    gets at least `Budget.background_min_ms`. The turns are counted per event loop.
    """

    def __init__(
        self,
        detectors: Sequence[AnyDetector],
        cache: DetectorResultCache | None = None,
        executor: ExecutorKind = ExecutorKind.PROCESS,
        budget: Budget | None = None,
        max_workers: int = 2,
        background_workers: int | None = None,
        max_background_remote: int = 16,
    ) -> None:
        if background_workers is None:
            background_workers = max_workers
        if min(max_workers, background_workers, max_background_remote) < 1:
            # A lane without a single worker or turn could never run a scan.
            raise ValueError(
                "max_workers, background_workers and max_background_remote must be at least 1"
            )
        self._detectors = tuple(detectors)
        self._cache = cache if cache is not None else DetectorResultCache()
        self._kind = executor
        self._budget = budget if budget is not None else Budget()
        self._foreground = _Lane(max_workers)
        self._background = _Lane(background_workers)
        self._background_workers = background_workers
        self._max_background_remote = max_background_remote
        # A semaphore belongs to the event loop it is first used on, and the runner may serve
        # more than one loop.
        self._turns: weakref.WeakKeyDictionary[asyncio.AbstractEventLoop, _Turns] = (
            weakref.WeakKeyDictionary()
        )

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
        self._foreground.close()
        self._background.close()

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
            # Only the detector's id reaches a decision: the reason is for the operator.
            logger.warning("detector %s reported a failure: %s", key, fresh.error)
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
            return await self._scan(
                self._foreground, detector, pending, self._budget.local_ms(size)
            )
        # One scan per background worker: a scan waiting for its turn is not queued in the
        # pool, so its deadline measures the scan and not the backlog ahead of it.
        async with self._lane_turns().local:
            return await self._scan(
                self._background, detector, pending, self._budget.background_local_ms(size)
            )

    async def _scan(
        self, lane: _Lane, detector: LocalDetector, pending: list[Segment], deadline_ms: float
    ) -> Findings:
        registry_key = detector_id(detector)
        # A worker process can rebuild a registered detector only.
        in_process = self._kind is ExecutorKind.PROCESS and registry_key in DETECTOR_REGISTRY
        pool = lane.processes if in_process else lane.threads
        executor = pool.executor()
        loop = asyncio.get_running_loop()
        try:
            async with asyncio.timeout(deadline_ms / 1000.0):
                if in_process:
                    segment_dicts = [s.model_dump(mode="json") for s in pending]
                    raw = await loop.run_in_executor(
                        executor, _worker_detect, registry_key, segment_dicts
                    )
                    return Findings.model_validate(raw)
                return await loop.run_in_executor(executor, detector.detect, pending)
        except (TimeoutError, BrokenExecutor):
            # A worker still busy with the timed-out scan would hold its slot for every later
            # scan, and a broken pool would fail them all.
            pool.retire(executor)
            raise

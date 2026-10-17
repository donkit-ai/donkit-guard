from __future__ import annotations

import asyncio
import threading
import time
from typing import TYPE_CHECKING

import pytest

from donkit_guard.declared.pattern import PatternDetector
from donkit_guard.declared.spec import PatternDetectorSpec
from donkit_guard.detectors.base import (
    detector_key,
    detector_required,
    detector_subtypes,
    empty_findings,
    failed_findings,
)
from donkit_guard.detectors.cache import DetectorResultCache
from donkit_guard.detectors.runner import Budget, DetectorRunner, ExecutorKind
from donkit_guard.findings import FindingClass, Findings, FindingSpan
from donkit_guard.payload import Segment, SegmentSource, SegmentTrust

if TYPE_CHECKING:
    from collections.abc import Sequence


class CountingDetector:
    name = "counting"
    version = "1"
    classes = frozenset({FindingClass.SECRET})
    remote = False
    pattern_set_hash = ""

    def __init__(self, pattern_set_hash: str = "") -> None:
        self.calls = 0
        self.pattern_set_hash = pattern_set_hash

    def detect(self, segments: Sequence[Segment]) -> Findings:
        self.calls += 1
        spans = tuple(
            FindingSpan(
                segment_id=s.id,
                path=s.path,
                start=0,
                end=3,
                cls=FindingClass.SECRET,
                subtype="x",
                score=1.0,
                detector=self.name,
            )
            for s in segments
            if "secret" in (s.text or "")
        )
        return Findings(
            detector=self.name,
            version=self.version,
            pattern_set_hash=self.pattern_set_hash,
            spans=spans,
            segments_scanned=len(segments),
        )


class ScopedDetector(CountingDetector):
    """The same detector, built for one tenant."""

    def __init__(self, cache_scope: str, pattern_set_hash: str = "") -> None:
        super().__init__(pattern_set_hash)
        self.cache_scope = cache_scope


class MistypedDetector(CountingDetector):
    """Declares attributes of the wrong type."""

    subtypes = "EMAIL"
    required = None


class ExpiringDetector(CountingDetector):
    """Declares how long its results stay cached."""

    def __init__(self, cache_ttl_s: int | None) -> None:
        super().__init__()
        self.cache_ttl_s = cache_ttl_s


class SlowDetector:
    name = "slow"
    version = "1"
    classes = frozenset({FindingClass.PII})
    remote = False
    pattern_set_hash = ""

    def __init__(self, delay_s: float = 0.5) -> None:
        self.delay_s = delay_s

    def detect(self, segments: Sequence[Segment]) -> Findings:
        time.sleep(self.delay_s)
        return empty_findings(self, len(segments))


class BlockedDetector:
    """Holds its worker until the test releases it; ``started`` is set once it runs."""

    name = "blocked"
    version = "1"
    classes = frozenset({FindingClass.PII})
    remote = False
    pattern_set_hash = ""

    def __init__(self) -> None:
        self.started = threading.Event()
        self.release = threading.Event()

    def detect(self, segments: Sequence[Segment]) -> Findings:
        self.started.set()
        # Bounded, so that a failing test does not leave the worker blocked for good.
        self.release.wait(timeout=30.0)
        return empty_findings(self, len(segments))


class CrashingRemote:
    name = "remote"
    version = "1"
    classes = frozenset({FindingClass.PII})
    remote = True
    pattern_set_hash = ""

    async def adetect(self, segments: Sequence[Segment], deadline_s: float) -> Findings:
        raise ConnectionError("boom")


class RecordingRemote:
    """Records the deadline it is given."""

    name = "recording"
    version = "1"
    classes = frozenset({FindingClass.PII})
    remote = True
    pattern_set_hash = ""

    def __init__(self, timeout_ms: int | None) -> None:
        self.timeout_ms = timeout_ms
        self.deadlines: list[float] = []

    async def adetect(self, segments: Sequence[Segment], deadline_s: float) -> Findings:
        self.deadlines.append(deadline_s)
        return empty_findings(self, len(segments))


class ReportingFailure:
    name = "reporting"
    version = "1"
    classes = frozenset({FindingClass.SECRET})
    remote = False
    pattern_set_hash = "rules1"

    def detect(self, segments: Sequence[Segment]) -> Findings:
        return failed_findings(self, "rule set unavailable")


class NotADetector:
    """Carries every attribute of the protocols and neither of their methods."""

    name = "bogus"
    version = "1"
    classes = frozenset({FindingClass.SECRET})
    remote = False
    pattern_set_hash = ""


def _segments() -> list[Segment]:
    return [
        Segment.of_text("a secret here", source=SegmentSource.USER, trust=SegmentTrust.TRUSTED),
        Segment.of_text("nothing", source=SegmentSource.USER, trust=SegmentTrust.TRUSTED),
    ]


async def test_runner_caches_per_segment_and_skips_rescans() -> None:
    detector = CountingDetector()
    cache = DetectorResultCache()
    runner = DetectorRunner([detector], cache=cache, executor=ExecutorKind.SYNC)
    first = (await runner.run(_segments()))[0]
    assert first.segments_scanned == 2 and len(first.spans) == 1
    second = (await runner.run(_segments()))[0]
    assert second.segments_scanned == 0 and len(second.spans) == 1
    assert detector.calls == 1
    assert cache.stats().hits == 2


async def test_cached_and_fresh_findings_carry_the_pattern_set_hash() -> None:
    detector = CountingDetector("abc123")
    runner = DetectorRunner([detector], executor=ExecutorKind.SYNC)
    fresh = (await runner.run(_segments()))[0]
    cached = (await runner.run(_segments()))[0]
    assert fresh.pattern_set_hash == cached.pattern_set_hash == "abc123"
    assert cached.segments_scanned == 0
    assert fresh.provenance == "counting@1+abc123"


async def test_a_new_pattern_set_does_not_read_the_old_cache_entries() -> None:
    cache = DetectorResultCache()
    old, new = CountingDetector("v1hash"), CountingDetector("v2hash")
    assert detector_key(old) != detector_key(new)
    await DetectorRunner([old], cache=cache, executor=ExecutorKind.SYNC).run(_segments())
    rescan = (
        await DetectorRunner([new], cache=cache, executor=ExecutorKind.SYNC).run(_segments())
    )[0]
    assert rescan.segments_scanned == 2 and new.calls == 1


@pytest.mark.parametrize(
    ("pattern_set_hash", "unscoped_key", "tenant_a_key"),
    [
        ("", "counting@1", "counting@1@tenant-a"),
        ("abc123", "counting@1+abc123", "counting@1+abc123@tenant-a"),
    ],
)
def test_cache_scope_separates_keys(
    pattern_set_hash: str, unscoped_key: str, tenant_a_key: str
) -> None:
    unscoped = detector_key(CountingDetector(pattern_set_hash))
    tenant_a = detector_key(ScopedDetector("tenant-a", pattern_set_hash))
    tenant_b = detector_key(ScopedDetector("tenant-b", pattern_set_hash))
    assert (unscoped, tenant_a) == (unscoped_key, tenant_a_key)
    assert len({unscoped, tenant_a, tenant_b}) == 3


async def test_scoped_detectors_do_not_read_each_others_cache_entries() -> None:
    cache = DetectorResultCache()
    tenant_a, tenant_b = ScopedDetector("tenant-a"), ScopedDetector("tenant-b")
    await DetectorRunner([tenant_a], cache=cache, executor=ExecutorKind.SYNC).run(_segments())
    other = (
        await DetectorRunner([tenant_b], cache=cache, executor=ExecutorKind.SYNC).run(_segments())
    )[0]
    assert other.segments_scanned == 2 and tenant_b.calls == 1
    repeat = (
        await DetectorRunner([tenant_a], cache=cache, executor=ExecutorKind.SYNC).run(_segments())
    )[0]
    assert repeat.segments_scanned == 0 and tenant_a.calls == 1


@pytest.mark.parametrize(
    ("cache_ttl_s", "advance_s", "calls"),
    [
        pytest.param(None, 61.0, 1, id="cache-default"),
        pytest.param(60, 61.0, 2, id="expired"),
        pytest.param(0, 0.0, 2, id="not-cached"),
    ],
)
async def test_cache_lifetime_comes_from_the_detector(
    cache_ttl_s: int | None, advance_s: float, calls: int
) -> None:
    now = [0.0]
    detector = ExpiringDetector(cache_ttl_s)
    runner = DetectorRunner(
        [detector], cache=DetectorResultCache(clock=lambda: now[0]), executor=ExecutorKind.SYNC
    )
    await runner.run(_segments())
    now[0] = advance_s
    await runner.run(_segments())
    assert detector.calls == calls


def test_mistyped_detector_attributes_keep_the_safe_defaults() -> None:
    # A bare string is not a set of subtypes, and only an explicit False opts out of being
    # required: a wrong type must never narrow what runs or relax a failure.
    detector = MistypedDetector()
    assert detector_subtypes(detector) is None and detector_required(detector) is True


@pytest.mark.parametrize(
    ("given", "expected"),
    [
        pytest.param(None, {"counting@1": "abc123", "remote@1": ""}, id="own"),
        pytest.param([CountingDetector("declared")], {"counting@1": "declared"}, id="given"),
    ],
)
def test_versions_report_detector_id_and_pattern_set(
    given: list[CountingDetector] | None, expected: dict[str, str]
) -> None:
    runner = DetectorRunner(
        [CountingDetector("abc123"), CrashingRemote()], executor=ExecutorKind.SYNC
    )
    assert runner.versions(given) == expected


async def test_local_timeout_is_a_failed_finding_not_clean() -> None:
    runner = DetectorRunner(
        [SlowDetector()],
        executor=ExecutorKind.THREAD,
        budget=Budget(local_base_ms=20.0, local_per_kb_ms=0.0),
    )
    try:
        result = (await runner.run(_segments()))[0]
    finally:
        runner.close()
    assert result.failed is True and result.error == "timeout"


async def test_a_timed_out_worker_does_not_wedge_the_next_scan() -> None:
    """The worker that blew the budget keeps running; the pool it holds is retired."""
    detector = SlowDetector()
    runner = DetectorRunner(
        [detector],
        executor=ExecutorKind.THREAD,
        budget=Budget(local_base_ms=50.0, local_per_kb_ms=0.0),
        max_workers=1,
    )
    try:
        first = (await runner.run(_segments()))[0]
        assert first.failed is True and first.error == "timeout"
        detector.delay_s = 0.0
        second = (await runner.run(_segments()))[0]
    finally:
        runner.close()
    assert second.failed is False and second.segments_scanned == 2


async def test_a_blocked_background_scan_does_not_hold_up_a_foreground_scan() -> None:
    blocked, counting = BlockedDetector(), CountingDetector()
    # A deadline no scan comes near: only a foreground scan queued behind the blocked one
    # would fail it.
    runner = DetectorRunner(
        [counting],
        executor=ExecutorKind.THREAD,
        budget=Budget(local_base_ms=10_000.0),
        max_workers=1,
        background_workers=1,
    )
    try:
        background = asyncio.create_task(runner.run(_segments(), [blocked], background=True))
        assert await asyncio.to_thread(blocked.started.wait, 10.0)
        (foreground,) = await runner.run(_segments())
        blocked.release.set()
        (late,) = await background
    finally:
        blocked.release.set()
        runner.close()
    assert foreground.failed is False and foreground.segments_scanned == 2
    assert late.failed is False


async def test_a_background_scan_waiting_for_its_turn_keeps_its_deadline(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # The loop's clock moves only when the test moves it, so that no deadline runs out
    # while the test waits for a worker thread.
    loop = asyncio.get_running_loop()
    now = [loop.time()]
    monkeypatch.setattr(loop, "time", lambda: now[0])
    blocked, waiting = BlockedDetector(), CountingDetector()
    runner = DetectorRunner([], executor=ExecutorKind.THREAD, background_workers=1)
    try:
        # The blocked detector takes the only turn, and the other one waits for it.
        scan = asyncio.create_task(runner.run(_segments(), [blocked, waiting], background=True))
        assert await asyncio.to_thread(blocked.started.wait, 10.0)
        # Past every deadline: the blocked scan times out and hands its turn on. A deadline
        # that had started with the wait for the turn would have run out as well.
        now[0] += 3600.0
        timed_out, scanned = await scan
    finally:
        blocked.release.set()
        runner.close()
    assert timed_out.failed is True and timed_out.error == "timeout"
    assert scanned.failed is False and waiting.calls == 1


async def test_remote_exception_is_reported() -> None:
    runner = DetectorRunner([CrashingRemote()], executor=ExecutorKind.SYNC)
    result = (await runner.run(_segments()))[0]
    assert result.failed is True and "ConnectionError" in (result.error or "")


@pytest.mark.parametrize(
    ("timeout_ms", "deadline_s"),
    [
        pytest.param(50, 0.05, id="declared"),
        pytest.param(None, 0.15, id="budget"),
    ],
)
async def test_remote_deadline_comes_from_the_detector(
    timeout_ms: int | None, deadline_s: float
) -> None:
    detector = RecordingRemote(timeout_ms)
    runner = DetectorRunner(
        [detector],
        executor=ExecutorKind.SYNC,
        budget=Budget(remote_base_ms=150.0, remote_per_kb_ms=0.0),
    )
    await runner.run(_segments())
    assert detector.deadlines == [deadline_s]


async def test_a_reported_failure_is_passed_through_and_not_cached() -> None:
    cache = DetectorResultCache()
    runner = DetectorRunner([ReportingFailure()], cache=cache, executor=ExecutorKind.SYNC)
    result = (await runner.run(_segments()))[0]
    assert result.failed is True and result.error == "rule set unavailable"
    assert result.pattern_set_hash == "rules1"
    assert cache.stats().entries == 0


async def test_an_unregistered_detector_cannot_run_in_a_process_pool() -> None:
    runner = DetectorRunner([CountingDetector()], executor=ExecutorKind.PROCESS)
    result = (await runner.run(_segments()))[0]
    assert result.failed is True and "not registered" in (result.error or "")


async def test_declared_detector_runs_in_a_process_pool() -> None:
    # A value under a listed key is reported whole, which takes no RE2 to find.
    spec = PatternDetectorSpec.model_validate(
        {
            "kind": "pattern",
            "id": "contract-number",
            "title": "Contract number",
            "class": "corporate",
            "subtype": "CONTRACT_NUMBER",
            "json_keys": ["contract_id"],
        }
    )
    detector = PatternDetector(spec, cache_scope="tenant-a")
    segment = Segment.of_text(
        "A-17/2024", source=SegmentSource.TOOL_ARGS, trust=SegmentTrust.TRUSTED, path="/contract_id"
    )
    # The first scan starts the worker process, which the default local budget leaves no
    # time for.
    runner = DetectorRunner(
        [detector],
        executor=ExecutorKind.PROCESS,
        budget=Budget(local_base_ms=30_000.0),
        max_workers=1,
    )
    try:
        result = (await runner.run([segment]))[0]
    finally:
        runner.close()
    assert result.error is None
    assert result.spans and result == detector.detect([segment])


async def test_an_object_implementing_neither_protocol_fails_the_scan() -> None:
    runner = DetectorRunner([NotADetector()], executor=ExecutorKind.SYNC)  # type: ignore[list-item]
    result = (await runner.run(_segments()))[0]
    assert result.failed is True and "TypeError" in (result.error or "")


def test_cache_expires_and_evicts() -> None:
    now = [0.0]
    cache = DetectorResultCache(ttl_s=10.0, max_bytes=400, clock=lambda: now[0])
    cache.put("d@1", "s1", ())
    assert cache.get("d@1", "s1") == ()
    now[0] = 11.0
    assert cache.get("d@1", "s1") is None
    for i in range(10):
        cache.put("d@1", f"s{i}", ())
    assert cache.stats().bytes <= 400


@pytest.mark.parametrize(
    ("ttl_s", "advance_s", "own_entry_kept", "default_entry_kept"),
    [
        pytest.param(1, 2.0, False, True, id="shorter-than-default"),
        pytest.param(100, 11.0, True, False, id="longer-than-default"),
        pytest.param(0, 0.0, False, True, id="zero"),
        pytest.param(-1, 0.0, False, True, id="negative"),
    ],
)
def test_cache_entry_ttl(
    ttl_s: float, advance_s: float, own_entry_kept: bool, default_entry_kept: bool
) -> None:
    now = [0.0]
    cache = DetectorResultCache(ttl_s=10.0, clock=lambda: now[0])
    cache.put("d@1", "own", (), ttl_s=ttl_s)
    cache.put("d@1", "default", ())
    now[0] = advance_s
    assert (cache.get("d@1", "own") is not None) is own_entry_kept
    assert (cache.get("d@1", "default") is not None) is default_entry_kept


def test_budget_scales_with_size_and_caps_remote() -> None:
    budget = Budget()
    assert budget.local_ms(0) == 10.0
    assert budget.local_ms(32 * 1024) == 10.0 + 3.0 * 32
    assert budget.remote_ms(10 * 1024) == 150.0 + 400.0
    assert budget.remote_ms(1024 * 1024) == 2000.0


async def test_run_gathers_all_detectors() -> None:
    runner = DetectorRunner([CountingDetector(), CrashingRemote()], executor=ExecutorKind.SYNC)
    results = await runner.run(_segments())
    assert [r.detector for r in results] == ["counting", "remote"]
    await asyncio.sleep(0)


async def test_run_uses_the_given_detectors() -> None:
    first, second = CountingDetector("first"), CountingDetector("second")
    runner = DetectorRunner([first, second], executor=ExecutorKind.SYNC)
    results = await runner.run(_segments(), detectors=[first])
    assert [r.pattern_set_hash for r in results] == ["first"]
    assert (first.calls, second.calls) == (1, 0)

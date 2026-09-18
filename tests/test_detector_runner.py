from __future__ import annotations

import asyncio
import time
from typing import TYPE_CHECKING

from donkit_guard.detectors.base import detector_key, empty_findings, failed_findings
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


class CrashingRemote:
    name = "remote"
    version = "1"
    classes = frozenset({FindingClass.PII})
    remote = True
    pattern_set_hash = ""

    async def adetect(self, segments: Sequence[Segment], deadline_s: float) -> Findings:
        raise ConnectionError("boom")


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


def test_versions_report_detector_id_and_pattern_set() -> None:
    runner = DetectorRunner(
        [CountingDetector("abc123"), CrashingRemote()], executor=ExecutorKind.SYNC
    )
    assert runner.versions() == {"counting@1": "abc123", "remote@1": ""}


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


async def test_remote_exception_is_reported() -> None:
    runner = DetectorRunner([CrashingRemote()], executor=ExecutorKind.SYNC)
    result = (await runner.run(_segments()))[0]
    assert result.failed is True and "ConnectionError" in (result.error or "")


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

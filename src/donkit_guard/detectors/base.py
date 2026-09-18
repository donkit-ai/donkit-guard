"""Detector protocols and the registry used by process-pool workers."""

from __future__ import annotations

from typing import TYPE_CHECKING, Protocol, runtime_checkable

from donkit_guard.findings import FindingClass, Findings

if TYPE_CHECKING:
    from collections.abc import Callable, Sequence

    from donkit_guard.payload import Segment


@runtime_checkable
class LocalDetector(Protocol):
    name: str
    version: str
    classes: frozenset[FindingClass]
    remote: bool
    # Empty for a detector whose behaviour is code only; otherwise a digest of the
    # patterns it was built from, so a result can be tied back to that rule set.
    pattern_set_hash: str

    def detect(self, segments: Sequence[Segment]) -> Findings: ...


@runtime_checkable
class RemoteDetector(Protocol):
    name: str
    version: str
    classes: frozenset[FindingClass]
    remote: bool
    pattern_set_hash: str

    async def adetect(self, segments: Sequence[Segment], deadline_s: float) -> Findings: ...


AnyDetector = LocalDetector | RemoteDetector


def detector_id(detector: AnyDetector) -> str:
    return f"{detector.name}@{detector.version}"


def detector_key(detector: AnyDetector) -> str:
    """Identity of the detector *and* of the patterns it runs.

    A rule-set edit without a version bump has to invalidate cached results, so the
    hash belongs in every key that stands for "this detector produced this".
    """
    base = detector_id(detector)
    return f"{base}+{detector.pattern_set_hash}" if detector.pattern_set_hash else base


def spans_overlap(start: int, end: int, taken: Sequence[tuple[int, int]]) -> bool:
    return any(s < end and start < e for s, e in taken)


# Built-in local detectors register a zero-argument factory so that a process
# pool worker can rebuild them by id instead of unpickling instances.
DETECTOR_REGISTRY: dict[str, Callable[[], LocalDetector]] = {}


def register_detector(factory: Callable[[], LocalDetector]) -> Callable[[], LocalDetector]:
    probe = factory()
    DETECTOR_REGISTRY[detector_id(probe)] = factory
    return factory


def empty_findings(detector: AnyDetector, segments_scanned: int = 0) -> Findings:
    return Findings(
        detector=detector.name,
        version=detector.version,
        pattern_set_hash=detector.pattern_set_hash,
        segments_scanned=segments_scanned,
    )


def failed_findings(detector: AnyDetector, error: str) -> Findings:
    return Findings(
        detector=detector.name,
        version=detector.version,
        pattern_set_hash=detector.pattern_set_hash,
        failed=True,
        error=error,
    )

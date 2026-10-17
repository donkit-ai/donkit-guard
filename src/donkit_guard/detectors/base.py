"""Detector protocols and the registry from which worker processes rebuild detectors.

`LocalDetector` and `RemoteDetector` fix the attributes every detector has. A detector may
carry any of the following as well. The runner and the engine read them through the
`detector_*` accessors in this module, and a detector without one behaves as it always did.

- `subtypes: frozenset[str]` - the finding subtypes the detector can report. Absent, or
  anything but a set of names, means unknown: selection then assumes the detector might
  report any subtype.
- `cache_scope: str` - an isolation label, for example the tenant the detector was built
  for. It is part of the cache key, so detectors that share a name but not a scope never
  read each other's cached results.
- `timeout_ms: int` - the deadline the detector asks for, in milliseconds. Absent means
  the runner's size-based budget applies.
- `cache_ttl_s: int` - how long the detector's results stay cached, in seconds; `0` turns
  caching off for it. Absent means the cache's default lifetime.
- `required: bool` - whether a failure of the detector counts as a failed check (the
  default) or only as a check that did not run. Only an explicit `False` opts out.
"""

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


def detector_subtypes(detector: AnyDetector) -> frozenset[str] | None:
    """Subtypes the detector can report, or `None` when it does not say.

    A mistyped declaration counts as "does not say": it may widen what the detector is
    asked about, never narrow it.
    """
    subtypes = getattr(detector, "subtypes", None)
    return frozenset(subtypes) if isinstance(subtypes, set | frozenset) else None


def detector_cache_scope(detector: AnyDetector) -> str:
    """Isolation label of the detector's cache entries; empty when it has none."""
    scope: str = getattr(detector, "cache_scope", "")
    return scope


def detector_timeout_ms(detector: AnyDetector) -> int | None:
    """Deadline the detector asks for, or `None` to take the runner's budget."""
    timeout_ms: int | None = getattr(detector, "timeout_ms", None)
    return timeout_ms


def detector_cache_ttl_s(detector: AnyDetector) -> int | None:
    """Lifetime of the detector's cached results, or `None` for the cache's default."""
    ttl_s: int | None = getattr(detector, "cache_ttl_s", None)
    return ttl_s


def detector_required(detector: AnyDetector) -> bool:
    """Whether a failure of the detector counts as a failed check.

    Only an explicit `False` opts out, so a mistyped declaration keeps the safe default.
    """
    return getattr(detector, "required", True) is not False


def detector_key(detector: AnyDetector) -> str:
    """Identity of the detector *and* of the patterns it runs.

    A rule-set edit without a version bump has to invalidate cached results, so the
    hash belongs in every key that stands for "this detector produced this". A scoped
    detector adds its scope, so that same-named detectors built for different tenants
    never share an entry.
    """
    key = detector_id(detector)
    if detector.pattern_set_hash:
        key = f"{key}+{detector.pattern_set_hash}"
    scope = detector_cache_scope(detector)
    return f"{key}@{scope}" if scope else key


def spans_overlap(start: int, end: int, taken: Sequence[tuple[int, int]]) -> bool:
    return any(s < end and start < e for s, e in taken)


# Built-in local detectors register a zero-argument factory so that a worker process can
# rebuild them by id instead of unpickling instances. A local detector that is not registered,
# such as one built from a policy document or one of the host's own, runs in a thread instead.
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

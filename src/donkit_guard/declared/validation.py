"""Checks of declared detectors that need the detectors built.

``donkit_guard.declared.spec`` checks the shape of a declaration. Whether RE2 accepts its
patterns, and whether the detector it describes finds what its examples say, shows only once
the detector is built: ``validate_specs`` builds it and runs the examples, so that a policy
document whose declarations would not work is rejected when it is loaded, with the place of
every problem. Remote declarations are not contacted.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from donkit_guard.declared.pattern import PatternDetector
from donkit_guard.declared.regex import RE2_MISSING, compile_re2, re2_available
from donkit_guard.declared.spec import PatternDetectorSpec, RemoteDetectorSpec, TermsDetectorSpec
from donkit_guard.declared.terms import TermsDetector
from donkit_guard.payload import Segment, SegmentSource, SegmentTrust

if TYPE_CHECKING:
    from collections.abc import Sequence

    from donkit_guard.declared.spec import DetectorExamples, DetectorSpec
    from donkit_guard.detectors.base import LocalDetector


def validate_specs(specs: Sequence[DetectorSpec]) -> list[str]:
    """Problems of ``specs`` that their data model cannot see, as ``"<path>: <message>"``.

    A path starts with ``detectors/<index>``, the place of the declaration in ``specs``, and
    names the field at fault: ``patterns/<n>`` for a pattern RE2 refuses, ``terms`` for a
    term list that cannot be compiled, ``examples/match/<n>`` for an example the detector
    finds nothing in and ``examples/no_match/<n>`` for one it finds something in. Examples
    are read as a trusted user message. A declaration that needs RE2 while the ``re2`` extra
    is not installed is reported at ``detectors/<index>`` itself, and one that cannot be
    built has its examples left unchecked. The list is empty when every declaration builds
    and keeps its examples.
    """
    errors: list[str] = []
    for index, spec in enumerate(specs):
        if isinstance(spec, RemoteDetectorSpec):
            continue
        path = f"detectors/{index}"
        if _needs_re2(spec) and not re2_available():
            errors.append(f"{path}: {RE2_MISSING}")
            continue
        detector, build_errors = _build(path, spec)
        errors.extend(build_errors)
        if detector is not None:
            errors.extend(_example_errors(path, spec.examples, detector))
    return errors


def _needs_re2(spec: PatternDetectorSpec | TermsDetectorSpec) -> bool:
    # A pattern declaration of JSON keys alone has no expression to compile.
    return isinstance(spec, TermsDetectorSpec) or bool(spec.patterns)


def _build(
    path: str, spec: PatternDetectorSpec | TermsDetectorSpec
) -> tuple[LocalDetector | None, list[str]]:
    """The detector ``spec`` declares, or ``None`` with the reasons it cannot be built."""
    if isinstance(spec, TermsDetectorSpec):
        try:
            return TermsDetector(spec), []
        except ValueError as exc:
            return None, [f"{path}/terms: {exc}"]
    # Each pattern on its own first, so that an error names the pattern it is about.
    refused: list[str] = []
    for number, pattern in enumerate(spec.patterns):
        try:
            compile_re2(pattern)
        except ValueError as exc:
            refused.append(f"{path}/patterns/{number}: {exc}")
    if refused:
        return None, refused
    try:
        return PatternDetector(spec), []
    except ValueError as exc:
        # Every pattern compiles alone, yet RE2 refuses the one expression that joins them.
        return None, [f"{path}/patterns: {exc}"]


def _example_errors(path: str, examples: DetectorExamples, detector: LocalDetector) -> list[str]:
    errors: list[str] = []
    for number, text in enumerate(examples.match):
        if not _subtypes_found(detector, text):
            errors.append(f"{path}/examples/match/{number}: found nothing")
    for number, text in enumerate(examples.no_match):
        found = _subtypes_found(detector, text)
        if found:
            errors.append(f"{path}/examples/no_match/{number}: found {', '.join(found)}")
    return errors


def _subtypes_found(detector: LocalDetector, text: str) -> list[str]:
    """The subtypes the detector reports in ``text``, sorted."""
    segment = Segment.of_text(text, source=SegmentSource.USER, trust=SegmentTrust.TRUSTED)
    return sorted({span.subtype for span in detector.detect([segment]).spans})

"""Declared detectors: detectors a policy document describes as data, not as shipped code."""

from __future__ import annotations

from donkit_guard.declared.factory import DeclaredDetectors
from donkit_guard.declared.spec import (
    MAX_DETECTORS,
    MAX_FINDINGS_PER_SEGMENT,
    MAX_REMOTE_DETECTORS,
    DetectorExamples,
    DetectorSpec,
    EntityMapping,
    PatternDetectorSpec,
    RemoteDetectorSpec,
    TermsDetectorSpec,
    spec_digest,
)
from donkit_guard.declared.validation import validate_specs

__all__ = [
    "MAX_DETECTORS",
    "MAX_FINDINGS_PER_SEGMENT",
    "MAX_REMOTE_DETECTORS",
    "DeclaredDetectors",
    "DetectorExamples",
    "DetectorSpec",
    "EntityMapping",
    "PatternDetectorSpec",
    "RemoteDetectorSpec",
    "TermsDetectorSpec",
    "spec_digest",
    "validate_specs",
]

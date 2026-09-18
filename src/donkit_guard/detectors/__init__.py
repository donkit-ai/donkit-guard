"""Detectors and the runner that executes them outside the event loop."""

from __future__ import annotations

from donkit_guard.detectors.base import (
    DETECTOR_REGISTRY,
    AnyDetector,
    LocalDetector,
    RemoteDetector,
    detector_id,
    register_detector,
)
from donkit_guard.detectors.cache import DetectorResultCache
from donkit_guard.detectors.injection import InjectionHeuristic
from donkit_guard.detectors.pii_checksum import PiiChecksumDetector
from donkit_guard.detectors.pii_ner import PiiNerDetector
from donkit_guard.detectors.runner import Budget, DetectorRunner, ExecutorKind
from donkit_guard.detectors.secrets import SecretsDetector

__all__ = [
    "DETECTOR_REGISTRY",
    "AnyDetector",
    "Budget",
    "DetectorResultCache",
    "DetectorRunner",
    "ExecutorKind",
    "InjectionHeuristic",
    "LocalDetector",
    "PiiChecksumDetector",
    "PiiNerDetector",
    "RemoteDetector",
    "SecretsDetector",
    "detector_id",
    "register_detector",
]

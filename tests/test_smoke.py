from __future__ import annotations

import donkit_guard
import donkit_guard.detectors.builtin
from donkit_guard.detectors import DETECTOR_REGISTRY


def test_package_exposes_version_and_facade() -> None:
    assert isinstance(donkit_guard.__version__, str) and donkit_guard.__version__
    assert callable(donkit_guard.build_quickstart_guard)


def test_builtin_detectors_are_registered() -> None:
    assert {"secrets@1", "pii-checksum@1", "injection-heuristic@1"} <= set(DETECTOR_REGISTRY)

from __future__ import annotations

import pytest
from pydantic import ValidationError

from donkit_guard.findings import FindingClass, Findings, FindingSpan


def test_detector_id_is_the_registry_key_and_provenance_adds_the_pattern_set() -> None:
    pinned = Findings(detector="secrets", version="1", pattern_set_hash="9f2c1ab4d0e7")
    assert pinned.detector_id == "secrets@1"
    assert pinned.provenance == "secrets@1+9f2c1ab4d0e7"


def test_provenance_falls_back_to_the_detector_id_without_a_pattern_set() -> None:
    model_based = Findings(detector="pii-ner", version="1")
    assert model_based.pattern_set_hash == ""
    assert model_based.provenance == model_based.detector_id == "pii-ner@1"


def test_span_score_and_offsets_are_bounded() -> None:
    with pytest.raises(ValidationError):
        FindingSpan(
            segment_id="s",
            start=-1,
            end=1,
            cls=FindingClass.PII,
            subtype="PERSON",
            score=1.0,
            detector="t",
        )
    with pytest.raises(ValidationError):
        FindingSpan(
            segment_id="s",
            start=0,
            end=1,
            cls=FindingClass.PII,
            subtype="PERSON",
            score=1.5,
            detector="t",
        )

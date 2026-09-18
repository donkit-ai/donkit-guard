from __future__ import annotations

import pytest
from pydantic import ValidationError

from donkit_guard.adapters import (
    AnalyzeRequest,
    AnalyzeResponse,
    AnalyzeSegment,
    AnalyzeSpan,
    utc_now,
)


def test_analyze_models_match_the_service_contract() -> None:
    request = AnalyzeRequest(
        segments=(AnalyzeSegment(id="s1", text="Ivan", lang="ru"),), deadline_ms=1500
    )
    wire = request.model_dump(mode="json")
    assert wire == {"segments": [{"id": "s1", "text": "Ivan", "lang": "ru"}], "deadline_ms": 1500}
    response = AnalyzeResponse.model_validate(
        {
            "detector": "pii-ner",
            "version": "1",
            "spans": [
                {"segment_id": "s1", "start": 0, "end": 4, "entity_type": "PERSON", "score": 0.85}
            ],
            "failed": False,
            "error": None,
        }
    )
    assert response.spans == (
        AnalyzeSpan(segment_id="s1", start=0, end=4, entity_type="PERSON", score=0.85),
    )
    with pytest.raises(ValidationError):
        AnalyzeSegment(id="s1", text="x", lang="de")  # type: ignore[arg-type]
    with pytest.raises(ValidationError):
        AnalyzeRequest(deadline_ms=0)


def test_analyze_request_deadline_matches_the_service_bounds() -> None:
    assert AnalyzeRequest(deadline_ms=60_000).deadline_ms == 60_000
    with pytest.raises(ValidationError):
        AnalyzeRequest(deadline_ms=60_001)


def test_utc_now_is_timezone_aware() -> None:
    assert utc_now().tzinfo is not None

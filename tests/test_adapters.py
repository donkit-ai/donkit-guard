from __future__ import annotations

import pytest
from pydantic import ValidationError

from donkit_guard.adapters import (
    AnalyzeRequest,
    AnalyzeResponse,
    AnalyzeSegment,
    AnalyzeSpan,
    EnvCredentialResolver,
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
        AnalyzeRequest(deadline_ms=0)


def test_analyze_segment_language_is_a_free_form_hint() -> None:
    request = AnalyzeRequest(
        segments=(
            AnalyzeSegment(id="s1", text="Hallo", lang="de"),
            AnalyzeSegment(id="s2", text="Hi", lang=None),
        )
    )
    wire = request.model_dump(mode="json")
    assert [segment["lang"] for segment in wire["segments"]] == ["de", None]


def test_analyze_response_ignores_unknown_fields() -> None:
    response = AnalyzeResponse.model_validate(
        {
            "detector": "contract-numbers",
            "version": "2",
            "spans": [
                {
                    "segment_id": "s1",
                    "start": 3,
                    "end": 12,
                    "entity_type": "CONTRACT",
                    "score": 0.9,
                    "rule": "contract-number-v2",
                }
            ],
            "elapsed_ms": 12,
        }
    )
    assert (response.detector, response.version) == ("contract-numbers", "2")
    assert response.spans == (
        AnalyzeSpan(segment_id="s1", start=3, end=12, entity_type="CONTRACT", score=0.9),
    )


def test_analyze_request_deadline_matches_the_service_bounds() -> None:
    assert AnalyzeRequest(deadline_ms=60_000).deadline_ms == 60_000
    with pytest.raises(ValidationError):
        AnalyzeRequest(deadline_ms=60_001)


async def test_env_credential_resolver_name_mapping(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("DONKIT_GUARD_CREDENTIAL_BANK_DLP", "token-value")
    monkeypatch.delenv("DONKIT_GUARD_CREDENTIAL_UNSET_NAME", raising=False)
    resolver = EnvCredentialResolver()

    assert await resolver.token("tenant-1", "bank-dlp") == "token-value"
    assert await resolver.token(None, "bank-dlp") == "token-value"
    assert await resolver.token("tenant-1", "unset-name") is None


def test_utc_now_is_timezone_aware() -> None:
    assert utc_now().tzinfo is not None

from __future__ import annotations

from importlib.util import find_spec

import pytest

# guard-pii ships its own requirements.txt and is not part of the core's
# dependency set, so the suite has to stay green without it installed. The cases
# are still collected and reported as skipped rather than dropped at import,
# which keeps `pytest tests/pii_service` from exiting "no tests collected".
SERVICE_REQUIREMENTS = ("fastapi", "presidio_analyzer", "presidio_ru_recognizers")
MISSING = tuple(name for name in SERVICE_REQUIREMENTS if find_spec(name) is None)
pytestmark = pytest.mark.skipif(
    bool(MISSING),
    reason=f"guard-pii requirements are not installed: {', '.join(MISSING)}",
)

if not MISSING:
    from fastapi.testclient import TestClient
    from services.pii.app import AnalyzeResponse, _State, app


@pytest.fixture(scope="module")
def client() -> TestClient:
    with TestClient(app) as test_client:
        yield test_client


def test_healthz_reports_models(client: TestClient) -> None:
    response = client.get("/healthz")
    assert response.status_code == 200
    body = response.json()
    assert body["status"] == "ok"
    assert set(body["models"]) == {"ru", "en"}


def test_analyze_finds_snils_and_person(client: TestClient) -> None:
    text = "Клиент Иванов Пётр Сергеевич, СНИЛС 112-233-445 95, телефон +7 912 345-67-89"
    response = client.post(
        "/v1/analyze",
        json={"segments": [{"id": "s1", "text": text, "lang": "ru"}], "deadline_ms": 5000},
    )
    assert response.status_code == 200
    parsed = AnalyzeResponse.model_validate(response.json())
    assert parsed.failed is False
    types = {span.entity_type for span in parsed.spans}
    assert {"SNILS", "PHONE"} <= types
    for span in parsed.spans:
        assert span.segment_id == "s1"
        assert 0 <= span.start < span.end <= len(text)


def test_analyze_rejects_unknown_fields(client: TestClient) -> None:
    response = client.post("/v1/analyze", json={"segments": [], "unexpected": 1})
    assert response.status_code == 422


def test_analyze_reports_an_analyzer_failure(
    client: TestClient, monkeypatch: pytest.MonkeyPatch
) -> None:
    class Exploding:
        def analyze(self, **kwargs: object) -> list[object]:
            raise RuntimeError("recognizer failed")

    monkeypatch.setattr(_State, "analyzer", Exploding())
    response = client.post(
        "/v1/analyze",
        json={"segments": [{"id": "s1", "text": "hello", "lang": "en"}], "deadline_ms": 5000},
    )
    assert response.status_code == 200
    parsed = AnalyzeResponse.model_validate(response.json())
    assert parsed.failed is True
    assert parsed.error == "RuntimeError: recognizer failed"
    assert parsed.spans == []

"""Example remote detector: finds contract numbers such as ``ДГ-123456``.

The smallest useful service for the analyze contract (``POST /v1/analyze``, described in
``docs/contract/analyze-v1.openapi.json``). It stands on its own, so copy this file and replace
``find_contract_numbers`` with your own detection.

    pip install -r requirements.txt
    uvicorn app:app --port 8000

Set ``DETECTOR_TOKEN`` to require ``Authorization: Bearer <token>`` on the analyze endpoint.
"""

from __future__ import annotations

import os
import re
import secrets
import time
from typing import Annotated

from fastapi import FastAPI, Header, HTTPException
from pydantic import BaseModel, Field

DETECTOR_NAME = "contract-numbers"
DETECTOR_VERSION = "1"
ENTITY_TYPE = "CONTRACT"
SCORE = 0.95

# Python's ``re`` indexes a ``str`` by code point, which is what the offsets of the contract
# count. The lookarounds keep a number from being cut out of a longer word or number.
CONTRACT_NUMBER = re.compile(r"(?<!\w)ДГ-[0-9]{6}(?!\w)")


class Segment(BaseModel):
    id: str
    text: str
    lang: str | None = None


class AnalyzeRequest(BaseModel):
    segments: list[Segment] = Field(default_factory=list)
    deadline_ms: int = Field(default=2000, ge=1, le=60_000)


class Span(BaseModel):
    segment_id: str
    start: int
    end: int
    entity_type: str
    score: float


class AnalyzeResponse(BaseModel):
    detector: str = DETECTOR_NAME
    version: str = DETECTOR_VERSION
    spans: list[Span] = Field(default_factory=list)
    failed: bool = False
    error: str | None = None


class Health(BaseModel):
    status: str = "ok"


app = FastAPI(title="contract-numbers detector")


def find_contract_numbers(segment: Segment) -> list[Span]:
    """Spans for the contract numbers in ``segment``; replace this with your own detection."""
    return [
        Span(
            segment_id=segment.id,
            start=found.start(),
            end=found.end(),
            entity_type=ENTITY_TYPE,
            score=SCORE,
        )
        for found in CONTRACT_NUMBER.finditer(segment.text)
    ]


def require_token(authorization: str | None) -> None:
    """Refuse a request that lacks the bearer token set in ``DETECTOR_TOKEN``.

    Without that variable the endpoint is open, which only suits a trusted network.
    """
    expected = os.environ.get("DETECTOR_TOKEN")
    if not expected:
        return
    scheme, _, supplied = (authorization or "").partition(" ")
    matches = secrets.compare_digest(supplied.encode(), expected.encode())
    if scheme.lower() != "bearer" or not matches:
        raise HTTPException(
            status_code=401,
            detail="invalid or missing token",
            headers={"WWW-Authenticate": "Bearer"},
        )


@app.get("/healthz")
def healthz() -> Health:
    return Health()


@app.post("/v1/analyze")
def analyze(
    request: AnalyzeRequest, authorization: Annotated[str | None, Header()] = None
) -> AnalyzeResponse:
    require_token(authorization)
    deadline = time.monotonic() + request.deadline_ms / 1000
    spans: list[Span] = []
    for segment in request.segments:
        if time.monotonic() > deadline:
            # Say so: an empty list of spans would pass for a clean result.
            return AnalyzeResponse(failed=True, error="deadline exceeded")
        spans.extend(find_contract_numbers(segment))
    return AnalyzeResponse(spans=spans)

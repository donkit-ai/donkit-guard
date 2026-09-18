"""HTTP front of the NER PII detector.

The core never imports this module; it talks to the service through its
DetectorClient adapter using the JSON contract below.
"""

from __future__ import annotations

import asyncio
import os
import time
from concurrent.futures import ThreadPoolExecutor
from contextlib import asynccontextmanager, suppress
from typing import TYPE_CHECKING, Literal

from fastapi import FastAPI, Response
from pydantic import BaseModel, ConfigDict, Field
from services.pii.engine import EN_MODEL, RU_MODEL, build_analyzer
from services.pii.thresholds import CANONICAL, passes

if TYPE_CHECKING:
    from collections.abc import AsyncIterator

DETECTOR_NAME = "pii-ner"
DETECTOR_VERSION = "1"
SUPPORTED_LANGS = ("ru", "en")
# A deadline cancels the wait, never the spaCy call already running in its thread.
# Analysis therefore runs on a pool of this size with one semaphore slot per worker,
# so abandoned work bounds the queue instead of filling the default executor.
ANALYZE_WORKERS = 2


class AnalyzeSegment(BaseModel):
    model_config = ConfigDict(extra="forbid")
    id: str
    text: str
    lang: Literal["ru", "en"] = "en"


class AnalyzeRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    segments: list[AnalyzeSegment] = Field(default_factory=list)
    deadline_ms: int = Field(default=2000, ge=1, le=60_000)


class AnalyzeSpan(BaseModel):
    segment_id: str
    start: int
    end: int
    entity_type: str
    score: float


class AnalyzeResponse(BaseModel):
    detector: str = DETECTOR_NAME
    version: str = DETECTOR_VERSION
    spans: list[AnalyzeSpan] = Field(default_factory=list)
    failed: bool = False
    error: str | None = None


class HealthResponse(BaseModel):
    status: str
    version: str = DETECTOR_VERSION
    models: dict[str, str] = Field(default_factory=dict)


class _State:
    analyzer: object | None = None
    executor: ThreadPoolExecutor | None = None
    slots: asyncio.Semaphore | None = None


@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncIterator[None]:
    _State.executor = ThreadPoolExecutor(max_workers=ANALYZE_WORKERS, thread_name_prefix="analyze")
    _State.slots = asyncio.Semaphore(ANALYZE_WORKERS)
    _State.analyzer = await asyncio.to_thread(build_analyzer, SUPPORTED_LANGS)
    yield
    _State.analyzer = None
    executor, _State.executor = _State.executor, None
    _State.slots = None
    if executor is not None:
        executor.shutdown(wait=False, cancel_futures=True)


app = FastAPI(title="guard-pii", lifespan=lifespan)


def _analyze_segment(segment: AnalyzeSegment, deadline: float) -> list[AnalyzeSpan]:
    analyzer = _State.analyzer
    assert analyzer is not None
    if time.monotonic() >= deadline:
        # The request waited for a worker longer than it is worth; the caller has given up.
        raise TimeoutError("deadline exceeded")
    results = analyzer.analyze(text=segment.text, language=segment.lang, score_threshold=0.0)  # type: ignore[attr-defined]
    spans: list[AnalyzeSpan] = []
    for result in results:
        canonical = CANONICAL.get(result.entity_type)
        if canonical is None or not passes(canonical, result.score):
            continue
        spans.append(
            AnalyzeSpan(
                segment_id=segment.id,
                start=result.start,
                end=result.end,
                entity_type=canonical,
                score=round(float(result.score), 3),
            )
        )
    return spans


@app.get("/healthz", response_model=HealthResponse)
async def healthz(response: Response) -> HealthResponse:
    if _State.analyzer is None:
        response.status_code = 503
        return HealthResponse(status="loading")
    return HealthResponse(status="ok", models={"ru": RU_MODEL, "en": EN_MODEL})


async def _submit(segment: AnalyzeSegment, deadline: float) -> list[AnalyzeSpan]:
    """Analyse one segment on the bounded pool, holding a slot until the thread ends."""
    executor, slots = _State.executor, _State.slots
    assert executor is not None and slots is not None
    loop = asyncio.get_running_loop()
    # Waiting for a slot counts against the deadline: when every worker is busy with an
    # abandoned analysis, the request is answered as late rather than left hanging.
    await asyncio.wait_for(slots.acquire(), timeout=max(deadline - time.monotonic(), 0.0))
    try:
        future = executor.submit(_analyze_segment, segment, deadline)
    except RuntimeError:  # the pool is shutting down
        slots.release()
        raise

    def release(_done: object) -> None:
        # A closed loop means the process is shutting down, when a returned slot is moot.
        with suppress(RuntimeError):
            loop.call_soon_threadsafe(slots.release)

    # The slot is returned by the worker thread, not by the waiter: releasing it when the
    # deadline fires would admit a new request while the abandoned analysis still runs.
    future.add_done_callback(release)
    remaining = max(deadline - time.monotonic(), 0.0)
    return await asyncio.wait_for(asyncio.wrap_future(future, loop=loop), timeout=remaining)


@app.post("/v1/analyze", response_model=AnalyzeResponse)
async def analyze(request: AnalyzeRequest) -> AnalyzeResponse:
    if _State.analyzer is None:
        return AnalyzeResponse(failed=True, error="analyzer not ready")
    deadline = time.monotonic() + request.deadline_ms / 1000.0
    spans: list[AnalyzeSpan] = []
    for segment in request.segments:
        if time.monotonic() >= deadline:
            return AnalyzeResponse(spans=spans, failed=True, error="deadline exceeded")
        try:
            spans.extend(await _submit(segment, deadline))
        except TimeoutError:
            return AnalyzeResponse(spans=spans, failed=True, error="deadline exceeded")
        except Exception as exc:
            # Reported, not swallowed: the core reads `failed` as a detector failure, which
            # is a deny in enforce mode, while a bare 500 leaves that to the host's client.
            return AnalyzeResponse(spans=spans, failed=True, error=f"{type(exc).__name__}: {exc}")
    return AnalyzeResponse(spans=spans)


def main() -> None:
    import uvicorn

    uvicorn.run(
        "services.pii.app:app",
        host=os.environ.get("PII_HOST", "0.0.0.0"),
        port=int(os.environ.get("PII_PORT", "8080")),
        workers=1,
    )


if __name__ == "__main__":
    main()

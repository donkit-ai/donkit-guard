from __future__ import annotations

from importlib.util import find_spec

import pytest

from donkit_guard.declared import regex as regex_module
from donkit_guard.declared.factory import DeclaredDetectors, build_local_from_payload
from donkit_guard.declared.pattern import PatternDetector
from donkit_guard.declared.regex import RE2_MISSING, re2_available
from donkit_guard.declared.remote import DeclaredRemoteDetector
from donkit_guard.declared.spec import (
    DetectorSpec,
    PatternDetectorSpec,
    RemoteDetectorSpec,
    TermsDetectorSpec,
)
from donkit_guard.declared.terms import TermsDetector
from donkit_guard.declared.validation import validate_specs
from donkit_guard.detectors.base import detector_cache_scope, detector_key
from donkit_guard.payload import Segment, SegmentSource, SegmentTrust

if find_spec("httpx") is not None:
    import httpx

# Pattern and terms detectors need the "re2" extra, remote ones the "http" extra. CI installs
# every extra; a bare install reports the cases it cannot run as skipped.
needs_re2 = pytest.mark.skipif(not re2_available(), reason=RE2_MISSING)
needs_http = pytest.mark.skipif(
    find_spec("httpx") is None, reason="the 'http' extra is not installed"
)

ENDPOINT = "https://detector.example.com/v1/analyze"
NUMBER = r"ДГ-\d{6}"
ZERO_WIDTH_SPACE = chr(0x200B)
MESSAGE = Segment.of_text(
    "Договор ДГ-123456 подписан", source=SegmentSource.USER, trust=SegmentTrust.TRUSTED
)
CODE_NAME_MESSAGE = Segment.of_text(
    "Запуск проекта Альбатрос", source=SegmentSource.USER, trust=SegmentTrust.TRUSTED
)
CONTRACT_ID = Segment.of_text(
    "A-17/2024",
    source=SegmentSource.TOOL_ARGS,
    trust=SegmentTrust.TRUSTED,
    path="/contract_id",
)


def _pattern(**fields: object) -> PatternDetectorSpec:
    return PatternDetectorSpec.model_validate(
        {
            "kind": "pattern",
            "id": "contract-number",
            "title": "Contract number",
            "class": "corporate",
            "subtype": "CONTRACT_NUMBER",
            **fields,
        }
    )


def _terms(**fields: object) -> TermsDetectorSpec:
    return TermsDetectorSpec.model_validate(
        {
            "kind": "terms",
            "id": "code-names",
            "title": "Project code names",
            "class": "corporate",
            "subtype": "CODE_NAME",
            "terms": ["Альбатрос"],
            **fields,
        }
    )


def _remote(**fields: object) -> RemoteDetectorSpec:
    return RemoteDetectorSpec.model_validate(
        {
            "kind": "remote",
            "id": "bank-dlp",
            "title": "Bank DLP",
            "endpoint": ENDPOINT,
            "entities": {"CONTRACT": {"class": "corporate", "subtype": "CONTRACT_NUMBER"}},
            **fields,
        }
    )


VALID_PATTERN = _pattern(
    patterns=[NUMBER],
    context=["договор*"],
    examples={"match": ["по договору ДГ-123456"], "no_match": ["ДГ-12345"]},
)
VALID_TERMS = _terms(examples={"match": ["Альбатрос"], "no_match": ["Суперальбатрос"]})


class TenantTokens:
    """A credential store with one secret per tenant; it keeps every lookup it is asked."""

    def __init__(self, tokens: dict[str | None, str]) -> None:
        self._tokens = tokens
        self.lookups: list[tuple[str | None, str]] = []

    async def token(self, tenant_id: str | None, name: str) -> str | None:
        self.lookups.append((tenant_id, name))
        return self._tokens.get(tenant_id)


class RecordingGuard:
    """An endpoint guard that allows every address and keeps each one it is asked about."""

    def __init__(self) -> None:
        self.urls: list[str] = []

    async def check(self, url: str) -> None:
        self.urls.append(url)


class Service:
    """Stands in for an analyze service: finds nothing and keeps every request it receives."""

    def __init__(self) -> None:
        self.requests: list[httpx.Request] = []

    def __call__(self, request: httpx.Request) -> httpx.Response:
        self.requests.append(request)
        return httpx.Response(200, json={"spans": []})


def test_detectors_for_caches_per_tenant_and_spec() -> None:
    # A declaration of JSON keys alone compiles no RE2 expression, so no extra is needed.
    spec = _pattern(json_keys=["contract_id"])
    declared = DeclaredDetectors()

    (first,) = declared.detectors_for("tenant-a", [spec])
    # A document loaded anew declares the same detector again.
    (again,) = declared.detectors_for("tenant-a", [_pattern(json_keys=["contract_id"])])
    (other_tenant,) = declared.detectors_for("tenant-b", [spec])
    (no_tenant,) = declared.detectors_for(None, [spec])
    (edited,) = declared.detectors_for("tenant-a", [_pattern(json_keys=["agreement_id"])])

    assert again is first
    scopes = [detector_cache_scope(d) for d in (first, other_tenant, no_tenant)]
    assert scopes == ["tenant-a", "tenant-b", ""]
    assert edited is not first
    assert edited.pattern_set_hash != first.pattern_set_hash
    # The runner caches results under these keys: no detector is served another's results.
    assert len({detector_key(d) for d in (first, other_tenant, no_tenant, edited)}) == 4


@needs_http
async def test_aclose_closes_cached_and_evicted_clients() -> None:
    service = Service()
    declared = DeclaredDetectors(max_cached=1, http_transport=httpx.MockTransport(service))
    (evicted,) = declared.detectors_for("tenant-a", [_remote()])
    (cached,) = declared.detectors_for("tenant-b", [_remote()])
    assert isinstance(evicted, DeclaredRemoteDetector)
    assert isinstance(cached, DeclaredRemoteDetector)

    # Dropped from the cache, a detector keeps working for an evaluation still holding it.
    assert not (await evicted.adetect([MESSAGE], 1.0)).failed
    await declared.aclose()

    closed = [await detector.adetect([MESSAGE], 1.0) for detector in (evicted, cached)]
    assert [(f.failed, f.error) for f in closed] == [(True, "client closed")] * 2
    assert len(service.requests) == 1
    # Closing empties the cache: a detector asked for afterwards is built anew and works.
    (rebuilt,) = declared.detectors_for("tenant-b", [_remote()])
    assert isinstance(rebuilt, DeclaredRemoteDetector)
    assert not (await rebuilt.adetect([MESSAGE], 1.0)).failed
    await declared.aclose()


@needs_http
@pytest.mark.parametrize(
    ("tenant_id", "credential", "lookups", "authorizations", "error"),
    [
        pytest.param(
            "tenant-a",
            "bank-dlp",
            [("tenant-a", "bank-dlp")],
            ["Bearer token-a"],
            None,
            id="the-tenant-secret-is-sent",
        ),
        pytest.param(
            "tenant-b",
            "bank-dlp",
            [("tenant-b", "bank-dlp")],
            [],
            "credential not found",
            id="a-missing-secret-sends-nothing",
        ),
        pytest.param(
            "tenant-a",
            None,
            [],
            [None],
            None,
            id="no-credential-is-looked-up-or-sent",
        ),
    ],
)
async def test_remote_token_and_guard_wiring(
    tenant_id: str,
    credential: str | None,
    lookups: list[tuple[str, str]],
    authorizations: list[str | None],
    error: str | None,
) -> None:
    tokens = TenantTokens({"tenant-a": "token-a"})
    guard = RecordingGuard()
    service = Service()
    declared = DeclaredDetectors(
        credential_resolver=tokens,
        endpoint_guard=guard,
        http_transport=httpx.MockTransport(service),
    )
    (detector,) = declared.detectors_for(tenant_id, [_remote(credential=credential)])
    assert isinstance(detector, DeclaredRemoteDetector)
    try:
        findings = await detector.adetect([MESSAGE], 1.0)
    finally:
        await declared.aclose()

    assert (findings.failed, findings.error) == (error is not None, error)
    # The guard is asked about the declared address before any secret is looked up.
    assert guard.urls == [ENDPOINT]
    assert tokens.lookups == lookups
    sent = [request.headers.get("authorization") for request in service.requests]
    assert sent == authorizations


@needs_re2
@pytest.mark.parametrize(
    ("specs", "expected"),
    [
        pytest.param(
            [_pattern(patterns=[r"(?<=ДГ-)\d{6}"], examples={"match": ["ДГ-123456"]})],
            ["detectors/0/patterns/0: "],
            id="lookbehind-is-refused-and-its-examples-are-not-run",
        ),
        pytest.param(
            [_pattern(patterns=[NUMBER], examples={"match": ["ДГ-123456", "ДГ 123456"]})],
            ["detectors/0/examples/match/1: found nothing"],
            id="match-example-that-finds-nothing",
        ),
        pytest.param(
            [_pattern(patterns=[NUMBER], examples={"no_match": ["ДГ-12345", "ДГ-654321"]})],
            ["detectors/0/examples/no_match/1: found CONTRACT_NUMBER"],
            id="no-match-example-that-finds-something",
        ),
        pytest.param(
            [_terms(terms=["Альбатрос", ZERO_WIDTH_SPACE])],
            ["detectors/0/terms: "],
            id="term-without-visible-characters",
        ),
        pytest.param(
            [
                _remote(),
                _pattern(patterns=[NUMBER, r"(\d)\1"]),
                _terms(examples={"no_match": ["проект АЛЬБАТРОС"]}),
            ],
            ["detectors/1/patterns/1: ", "detectors/2/examples/no_match/0: found CODE_NAME"],
            id="every-problem-at-its-place",
        ),
        pytest.param(
            [VALID_PATTERN, VALID_TERMS, _remote()],
            [],
            id="valid",
        ),
    ],
)
def test_validate_specs_paths(specs: list[DetectorSpec], expected: list[str]) -> None:
    errors = validate_specs(specs)

    # RE2 words its reasons itself; what an author looks for is where each problem is.
    assert len(errors) == len(expected), errors
    for error, start in zip(errors, expected, strict=True):
        assert error.startswith(start), errors


@pytest.mark.parametrize(
    ("spec", "expected"),
    [
        pytest.param(
            _pattern(patterns=[NUMBER]),
            [f"detectors/0: {RE2_MISSING}"],
            id="patterns-need-re2",
        ),
        pytest.param(
            _terms(),
            [f"detectors/0: {RE2_MISSING}"],
            id="terms-need-re2",
        ),
        pytest.param(
            _pattern(json_keys=["contract_id"]),
            [],
            id="json-keys-alone-need-no-re2",
        ),
    ],
)
def test_validate_specs_without_re2(
    monkeypatch: pytest.MonkeyPatch, spec: DetectorSpec, expected: list[str]
) -> None:
    monkeypatch.setattr(regex_module, "_INSTALLED", False)

    assert validate_specs([spec]) == expected


@pytest.mark.parametrize(
    ("spec", "segment"),
    [
        pytest.param(_pattern(json_keys=["contract_id"]), CONTRACT_ID, id="pattern"),
        pytest.param(VALID_TERMS, CODE_NAME_MESSAGE, id="terms", marks=needs_re2),
    ],
)
def test_build_local_from_payload_round_trip(spec: DetectorSpec, segment: Segment) -> None:
    (detector,) = DeclaredDetectors().detectors_for("tenant-a", [spec])
    assert isinstance(detector, PatternDetector | TermsDetector)

    rebuilt = build_local_from_payload(detector.spec_payload())

    # A worker finds what the detector it was handed would have found.
    assert detector_key(rebuilt) == detector_key(detector)
    assert rebuilt.detect([segment]).spans
    assert rebuilt.detect([segment]) == detector.detect([segment])
    # A worker compiles each declaration once.
    assert build_local_from_payload(detector.spec_payload()) is rebuilt

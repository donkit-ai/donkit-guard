"""Builds the detectors that policy documents declare, once per tenant and declaration.

Building a pattern or terms detector compiles its declaration, so ``DeclaredDetectors`` keeps
what it built: the same declaration for the same tenant gets the same detector back. A
detector's ``cache_scope`` is its tenant, so the results the runner caches for it are never
served to another tenant, and an edited declaration has another digest, so it never reads the
results of its earlier version. Remote detectors talk through HTTP connections they all share.

A process-pool worker cannot be handed a detector built from a document. It is handed the
detector's ``spec_payload()`` instead, and ``build_local_from_payload`` rebuilds a pattern or
terms detector from that.
"""

from __future__ import annotations

import json
import threading
from collections import OrderedDict
from functools import lru_cache
from typing import TYPE_CHECKING, Annotated, Literal

from pydantic import Field, TypeAdapter

from donkit_guard.adapters import AllowAllEndpoints
from donkit_guard.context import FrozenModel
from donkit_guard.declared.pattern import PatternDetector
from donkit_guard.declared.remote import DeclaredRemoteDetector
from donkit_guard.declared.spec import (
    PatternDetectorSpec,
    RemoteDetectorSpec,
    TermsDetectorSpec,
    spec_digest,
)
from donkit_guard.declared.terms import TermsDetector
from donkit_guard.http import HttpAnalyzeClient, HttpConnections, tls_verify

if TYPE_CHECKING:
    from collections.abc import Awaitable, Callable, Mapping, Sequence

    import httpx

    from donkit_guard.adapters import CredentialResolver, EndpointGuard
    from donkit_guard.declared.spec import DetectorSpec
    from donkit_guard.detectors.base import AnyDetector, LocalDetector

# Declarations a worker process keeps compiled at a time.
_WORKER_CACHE_SIZE = 64


class DeclaredDetectors:
    """The detectors of declared specs, built on demand and kept per tenant.

    At most ``max_cached`` detectors are kept, keyed by tenant and declaration digest; the
    least recently used one goes first. A ``remote`` declaration gets an ``HttpAnalyzeClient``
    on HTTP connections that every remote detector built here shares, made along with the
    first of them. The client:

    - asks ``credential_resolver`` for the declared credential before every request, giving it
      the tenant and the endpoint the token would be sent to. Credentials are opt-in: without
      a resolver none resolves, so a declaration that names one fails its checks with
      ``credential not found`` and sends nothing. ``EnvCredentialResolver`` reads them from
      the environment, for a host that writes every policy document itself;
    - asks ``endpoint_guard`` (by default ``AllowAllEndpoints``) about the address before
      every request;
    - checks the service's certificate against ``ca_bundle``, a CA file or directory, when it
      is given, and against the default CA bundle otherwise. The bundle is read here, so a
      file that is missing or cannot be read raises ``OSError`` when the factory is made, not
      when a policy is evaluated;
    - goes through ``http_transport`` when it is given, which tests use to stand in for the
      service.

    The connections stay open until ``aclose``, so a detector dropped from the cache keeps
    working for an evaluation that still holds it. ``detectors_for`` may be called from
    several threads.
    """

    def __init__(
        self,
        *,
        credential_resolver: CredentialResolver | None = None,
        endpoint_guard: EndpointGuard | None = None,
        ca_bundle: str | None = None,
        max_cached: int = 256,
        http_transport: httpx.AsyncBaseTransport | None = None,
    ) -> None:
        if max_cached < 1:
            raise ValueError("max_cached must be at least 1")
        self._credential_resolver = credential_resolver
        self._endpoint_guard: EndpointGuard = (
            endpoint_guard if endpoint_guard is not None else AllowAllEndpoints()
        )
        self._verify = tls_verify(ca_bundle)
        self._max_cached = max_cached
        self._http_transport = http_transport
        self._lock = threading.Lock()
        self._built: OrderedDict[tuple[str, str], AnyDetector] = OrderedDict()
        # Made with the first remote detector, so that documents without remote declarations
        # need no `http` extra.
        self._connections: HttpConnections | None = None

    def detectors_for(
        self, tenant_id: str | None, specs: Sequence[DetectorSpec]
    ) -> tuple[AnyDetector, ...]:
        """The detectors ``specs`` declare for ``tenant_id``, in the order of ``specs``.

        A declaration built before for the same tenant returns the detector built then, also
        when it comes from a document loaded anew. Building raises ``RuntimeError`` when a
        declaration needs an extra that is not installed, and ``ValueError`` when RE2 refuses
        its patterns, which ``validate_specs`` already reports when a document is loaded.
        """
        scope = tenant_id or ""
        return tuple(self._detector(scope, spec) for spec in specs)

    async def aclose(self) -> None:
        """Close the HTTP connections of the remote detectors and forget every detector.

        A remote detector handed out before fails its checks from then on, and the next
        ``detectors_for`` builds new detectors on new connections.
        """
        with self._lock:
            connections, self._connections = self._connections, None
            self._built.clear()
        if connections is not None:
            await connections.aclose()

    def _detector(self, scope: str, spec: DetectorSpec) -> AnyDetector:
        key = (scope, spec_digest(spec))
        with self._lock:
            detector = self._built.get(key)
            if detector is not None:
                self._built.move_to_end(key)
                return detector
            detector = self._build(scope, spec)
            self._built[key] = detector
            while len(self._built) > self._max_cached:
                self._built.popitem(last=False)
            return detector

    def _build(self, scope: str, spec: DetectorSpec) -> AnyDetector:
        """The detector ``spec`` declares for ``scope``; called with the lock held."""
        if not isinstance(spec, RemoteDetectorSpec):
            return _build_local(spec, scope)
        if self._connections is None:
            self._connections = HttpConnections(verify=self._verify, transport=self._http_transport)
        # An empty tenant id names no tenant, just as None does: the two share one scope.
        tenant_id = scope or None
        credential = spec.credential
        resolver = self._credential_resolver
        token = None
        if credential is not None and resolver is not None:
            token = _token_source(resolver, tenant_id, credential, spec.endpoint)
        client = HttpAnalyzeClient(
            spec.endpoint,
            token=token,
            token_required=credential is not None,
            endpoint_guard=self._endpoint_guard,
            connections=self._connections,
        )
        return DeclaredRemoteDetector(spec, client, cache_scope=scope)


def _token_source(
    resolver: CredentialResolver, tenant_id: str | None, credential: str, endpoint: str
) -> Callable[[], Awaitable[str | None]]:
    """A client's token callable: it looks the credential up anew for every request.

    The detector stays cached for long, so a secret the host rotates must not stay in it.
    """

    async def token() -> str | None:
        return await resolver.token(tenant_id, credential, endpoint)

    return token


def _build_local(spec: PatternDetectorSpec | TermsDetectorSpec, scope: str) -> LocalDetector:
    if isinstance(spec, PatternDetectorSpec):
        return PatternDetector(spec, cache_scope=scope)
    return TermsDetector(spec, cache_scope=scope)


class _PatternPayload(FrozenModel):
    kind: Literal["pattern"]
    spec: PatternDetectorSpec
    cache_scope: str


class _TermsPayload(FrozenModel):
    kind: Literal["terms"]
    spec: TermsDetectorSpec
    cache_scope: str


# The payload's `kind` picks the model, and the declaration inside has to be of that kind.
_LOCAL_PAYLOAD: TypeAdapter[_PatternPayload | _TermsPayload] = TypeAdapter(
    Annotated[_PatternPayload | _TermsPayload, Field(discriminator="kind")]
)


def build_local_from_payload(payload: Mapping[str, object]) -> LocalDetector:
    """Rebuild a pattern or terms detector from what its ``spec_payload()`` returned.

    A process-pool worker is handed a declared detector as this payload. Rebuilt detectors
    are kept per payload, so a worker compiles each declaration once. Raises ``ValueError``
    for a payload that describes no pattern or terms detector.
    """
    return _rebuild(json.dumps(dict(payload), sort_keys=True, ensure_ascii=False))


@lru_cache(maxsize=_WORKER_CACHE_SIZE)
def _rebuild(payload_json: str) -> LocalDetector:
    payload = _LOCAL_PAYLOAD.validate_json(payload_json)
    return _build_local(payload.spec, payload.cache_scope)

"""Builds the detectors that policy documents declare, once per tenant and declaration.

Building a declared detector compiles RE2 expressions or, for a remote declaration, opens an
HTTP client, so ``DeclaredDetectors`` keeps what it built: the same declaration for the same
tenant gets the same detector back. A detector's ``cache_scope`` is its tenant, so the results
the runner caches for it are never served to another tenant, and an edited declaration has
another digest, so it never reads the results of its earlier version.

A process-pool worker cannot be handed a detector built from a document. It is handed the
detector's ``spec_payload()`` instead, and ``build_local_from_payload`` rebuilds a pattern or
terms detector from that.
"""

from __future__ import annotations

import json
import threading
from collections import OrderedDict
from dataclasses import dataclass
from functools import lru_cache
from typing import TYPE_CHECKING, Annotated, Literal

from pydantic import Field, TypeAdapter

from donkit_guard.adapters import AllowAllEndpoints, EnvCredentialResolver
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
from donkit_guard.http import HttpAnalyzeClient

if TYPE_CHECKING:
    from collections.abc import Awaitable, Callable, Mapping, Sequence

    import httpx

    from donkit_guard.adapters import CredentialResolver, EndpointGuard
    from donkit_guard.declared.spec import DetectorSpec
    from donkit_guard.detectors.base import AnyDetector, LocalDetector

# Declarations a worker process keeps compiled at a time.
_WORKER_CACHE_SIZE = 64


@dataclass(frozen=True)
class _Built:
    """A detector built from a declaration, with the HTTP client it owns when it is remote."""

    detector: AnyDetector
    client: HttpAnalyzeClient | None = None


class DeclaredDetectors:
    """The detectors of declared specs, built on demand and kept per tenant.

    At most ``max_cached`` detectors are kept, keyed by tenant and declaration digest; the
    least recently used one goes first. A ``remote`` declaration gets an ``HttpAnalyzeClient``
    of its own, which:

    - asks ``credential_resolver`` (by default ``EnvCredentialResolver``) for the declared
      credential before every request, and sends nothing when there is none;
    - asks ``endpoint_guard`` (by default ``AllowAllEndpoints``) about the address before
      every request;
    - checks the service's certificate against ``ca_bundle``, a CA file or directory, when it
      is given, and against the default CA bundle otherwise;
    - goes through ``http_transport`` when it is given, which tests use to stand in for the
      service.

    The clients stay open until ``aclose``, those of detectors dropped from the cache too: an
    evaluation that took such a detector may still be calling it. ``detectors_for`` may be
    called from several threads.
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
        self._credential_resolver: CredentialResolver = (
            credential_resolver if credential_resolver is not None else EnvCredentialResolver()
        )
        self._endpoint_guard: EndpointGuard = (
            endpoint_guard if endpoint_guard is not None else AllowAllEndpoints()
        )
        self._verify: bool | str = ca_bundle or True
        self._max_cached = max_cached
        self._http_transport = http_transport
        self._lock = threading.Lock()
        self._built: OrderedDict[tuple[str, str], _Built] = OrderedDict()
        # Clients of the remote detectors dropped from the cache, kept for `aclose`.
        self._retired: list[HttpAnalyzeClient] = []

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
        """Close the HTTP client of every remote detector built so far.

        A detector handed out before fails its checks from then on, and the next
        ``detectors_for`` builds new detectors.
        """
        with self._lock:
            clients = [built.client for built in self._built.values() if built.client is not None]
            clients.extend(self._retired)
            self._built.clear()
            self._retired = []
        for client in clients:
            await client.aclose()

    def _detector(self, scope: str, spec: DetectorSpec) -> AnyDetector:
        key = (scope, spec_digest(spec))
        with self._lock:
            built = self._built.get(key)
            if built is not None:
                self._built.move_to_end(key)
                return built.detector
            built = self._build(scope, spec)
            self._built[key] = built
            while len(self._built) > self._max_cached:
                _, dropped = self._built.popitem(last=False)
                if dropped.client is not None:
                    self._retired.append(dropped.client)
            return built.detector

    def _build(self, scope: str, spec: DetectorSpec) -> _Built:
        if not isinstance(spec, RemoteDetectorSpec):
            return _Built(_build_local(spec, scope))
        # An empty tenant id names no tenant, just as None does: the two share one scope.
        tenant_id = scope or None
        credential = spec.credential
        token = None if credential is None else self._token_source(tenant_id, credential)
        client = HttpAnalyzeClient(
            spec.endpoint,
            token=token,
            token_required=credential is not None,
            endpoint_guard=self._endpoint_guard,
            verify=self._verify,
            transport=self._http_transport,
        )
        return _Built(DeclaredRemoteDetector(spec, client, cache_scope=scope), client)

    def _token_source(
        self, tenant_id: str | None, credential: str
    ) -> Callable[[], Awaitable[str | None]]:
        """A client's token callable: it looks the credential up anew for every request.

        The detector stays cached for long, so a secret the host rotates must not stay in it.
        """
        resolver = self._credential_resolver

        async def token() -> str | None:
            return await resolver.token(tenant_id, credential)

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

"""Builds the detectors that policy documents declare, once per tenant and declaration.

Building a pattern or terms detector compiles its patterns or indexes its terms, so
``DeclaredDetectors`` keeps what it built: the same declaration for the same tenant gets the same
detector back. A detector's ``cache_scope`` is its tenant, so the results the runner caches for it
are never served to another tenant, and an edited declaration has another digest, so it never
reads the results of its earlier version. Remote detectors talk through HTTP connections they all
share.

A detector built here exists only as an object in this process, and no worker process can
rebuild it: a ``DetectorRunner`` runs the pattern and terms detectors in threads, also when it
runs the built-in detectors in worker processes.
"""

from __future__ import annotations

import threading
from collections import OrderedDict
from concurrent.futures import Future
from typing import TYPE_CHECKING

from donkit_guard.adapters import AllowAllEndpoints
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
    from collections.abc import Awaitable, Callable, Sequence

    import httpx

    from donkit_guard.adapters import CredentialResolver, EndpointGuard
    from donkit_guard.declared.spec import DetectorSpec
    from donkit_guard.detectors.base import AnyDetector, LocalDetector


class DeclaredDetectors:
    """The detectors of declared specs, built on demand and kept per tenant.

    ``detectors_for`` may be called from several threads at once. At most ``max_cached``
    detectors are kept, keyed by tenant and declaration digest; the least recently used one goes
    first, and a document that declares it again has it built anew. A document declares up to
    ``MAX_DETECTORS`` (20) detectors, so the default keeps those of about a dozen full
    documents; a host with more tenants with large documents raises it, counting a few MiB for
    a terms detector of a full 5000-term list. A pattern or terms detector is built on the
    caller's thread, outside the lock, so that a long build holds up no other caller, and
    callers that miss the same declaration at the same time wait for that one build. A caller
    on an event loop asks ``cached_for`` first, which never builds, and calls ``detectors_for``
    from a worker thread only when something is missing, as the engine does.

    A ``remote`` declaration gets an ``HttpAnalyzeClient`` on HTTP connections that every remote
    detector built here shares, made along with the first of them. The client:

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
    working for an evaluation that still holds it.
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
        # Builds under way, which a caller that misses the same declaration waits for.
        self._building: dict[tuple[str, str], Future[AnyDetector]] = {}
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
        its patterns or a term has no visible characters, which ``validate_specs`` already
        reports when a document is loaded.
        """
        scope = tenant_id or ""
        return tuple(self._detector(scope, spec) for spec in specs)

    def cached_for(
        self, tenant_id: str | None, specs: Sequence[DetectorSpec]
    ) -> tuple[AnyDetector, ...] | None:
        """What ``detectors_for`` would return, when every detector is built already, or ``None``.

        It never builds, so a caller on an event loop can ask it there and go to a worker thread
        only when something is missing.
        """
        scope = tenant_id or ""
        keys = [(scope, spec_digest(spec)) for spec in specs]
        with self._lock:
            kept = [self._kept(key) for key in keys]
        found = [detector for detector in kept if detector is not None]
        return tuple(found) if len(found) == len(keys) else None

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
        if isinstance(spec, RemoteDetectorSpec):
            # A remote detector takes no time to build, and built under the lock it cannot end up
            # on connections that ``aclose`` closed meanwhile.
            with self._lock:
                kept = self._kept(key)
                return kept if kept is not None else self._keep(key, self._remote(scope, spec))
        with self._lock:
            kept = self._kept(key)
            if kept is not None:
                return kept
            pending = self._building.get(key)
            building = pending is None
            if pending is None:
                pending = self._building[key] = Future()
        if not building:
            # Another caller is building this declaration: its detector, or its error, is ours.
            return pending.result()
        try:
            built = _build_local(spec, scope)
        except BaseException as exc:
            with self._lock:
                del self._building[key]
            pending.set_exception(exc)
            raise
        with self._lock:
            del self._building[key]
            kept = self._keep(key, built)
        pending.set_result(kept)
        return kept

    def _kept(self, key: tuple[str, str]) -> AnyDetector | None:
        """The detector kept under ``key``, if any, as just used; called with the lock held."""
        detector = self._built.get(key)
        if detector is not None:
            self._built.move_to_end(key)
        return detector

    def _keep(self, key: tuple[str, str], detector: AnyDetector) -> AnyDetector:
        """Keep ``detector`` under ``key`` and return it; called with the lock held."""
        self._built[key] = detector
        while len(self._built) > self._max_cached:
            self._built.popitem(last=False)
        return detector

    def _remote(self, scope: str, spec: RemoteDetectorSpec) -> DeclaredRemoteDetector:
        """The remote detector ``spec`` declares for ``scope``; called with the lock held."""
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

"""The policy file as a ``PolicySource``: loaded at start, reloaded when it changes on disk.

A file that does not load is never applied: the version already active stays, the error is
logged, kept for ``GET /admin/policy`` and counted. The bundle version carries the digest of
the file, so any edit, even one that keeps the document's ``version``, invalidates the
approvals granted under the previous text.
"""

from __future__ import annotations

import asyncio
import hashlib
import logging
import time
from dataclasses import dataclass
from typing import TYPE_CHECKING

from donkit_guard.adapters import Clock, utc_now
from donkit_guard.errors import PolicyError
from donkit_guard.policy import PolicyBundle, PolicyDocument, load_policy
from donkit_guard_standalone.metrics import Metric, Metrics

if TYPE_CHECKING:
    from collections.abc import Awaitable, Callable
    from datetime import datetime
    from pathlib import Path

    from donkit_guard.context import GuardContext

logger = logging.getLogger("donkit_guard_standalone.policy")


@dataclass(frozen=True)
class LoadedPolicy:
    document: PolicyDocument
    bundle: PolicyBundle
    sha256: str
    path: str
    mtime_ns: int
    loaded_at: datetime


@dataclass(frozen=True)
class ReloadResult:
    changed: bool
    version: str
    error: str | None = None


def _read(path: Path) -> tuple[str, int]:
    stat = path.stat()
    return path.read_text("utf-8"), stat.st_mtime_ns


def _bundle(document: PolicyDocument, sha256: str) -> PolicyBundle:
    return PolicyBundle(
        documents=(document,),
        version=f"{document.version}@{sha256[:12]}",
        mode=document.mode,
    )


class FilePolicySource:
    """Serves the policy of one YAML file to every context."""

    def __init__(
        self,
        *,
        path: Path,
        loaded: LoadedPolicy,
        check_interval_s: float,
        metrics: Metrics,
        on_loaded: Callable[[LoadedPolicy], Awaitable[None]] | None = None,
        clock: Clock = utc_now,
    ) -> None:
        self._path = path
        self._current = loaded
        self._check_interval_s = check_interval_s
        self._metrics = metrics
        self._on_loaded = on_loaded
        self._clock = clock
        self._lock = asyncio.Lock()
        self._next_check = time.monotonic() + check_interval_s
        self.last_error: str | None = None
        # The modification time of a file that was refused: it is not parsed again until it
        # changes, so a broken file is logged and counted once.
        self._refused_mtime_ns: int | None = None

    @classmethod
    async def open(
        cls,
        path: Path,
        *,
        check_interval_s: float,
        metrics: Metrics,
        on_loaded: Callable[[LoadedPolicy], Awaitable[None]] | None = None,
        clock: Clock = utc_now,
    ) -> FilePolicySource:
        """Load the file; a policy that does not load stops the service from starting."""
        text, mtime_ns = await asyncio.to_thread(_read, path)
        loaded = cls._parse(path, text, mtime_ns, clock)
        if on_loaded is not None:
            await on_loaded(loaded)
        metrics.inc(Metric.POLICY_RELOADS)
        return cls(
            path=path,
            loaded=loaded,
            check_interval_s=check_interval_s,
            metrics=metrics,
            on_loaded=on_loaded,
            clock=clock,
        )

    @property
    def current(self) -> LoadedPolicy:
        return self._current

    async def resolve(self, ctx: GuardContext) -> PolicyBundle:
        if time.monotonic() >= self._next_check:
            await self.reload(force=False)
        return self._current.bundle

    async def reload(self, *, force: bool) -> ReloadResult:
        """Apply the file if it changed (or always, with ``force``); keep the old one on error."""
        async with self._lock:
            self._next_check = time.monotonic() + self._check_interval_s
            current = self._current
            mtime_ns: int | None = None
            try:
                mtime_ns = self._path.stat().st_mtime_ns
                if not force and mtime_ns in (current.mtime_ns, self._refused_mtime_ns):
                    return ReloadResult(
                        changed=False, version=current.bundle.version, error=self.last_error
                    )
                text, read_mtime_ns = await asyncio.to_thread(_read, self._path)
                loaded = self._parse(self._path, text, read_mtime_ns, self._clock)
            except (OSError, PolicyError) as exc:
                self._refused_mtime_ns = mtime_ns if isinstance(exc, PolicyError) else None
                return self._refuse(current, exc)
            self.last_error = None
            self._refused_mtime_ns = None
            if loaded.sha256 == current.sha256:
                self._current = loaded
                return ReloadResult(changed=False, version=current.bundle.version)
            if self._on_loaded is not None:
                await self._on_loaded(loaded)
            self._current = loaded
            self._metrics.inc(Metric.POLICY_RELOADS)
            logger.info("policy %s applied from %s", loaded.bundle.version, self._path)
            return ReloadResult(changed=True, version=loaded.bundle.version)

    def _refuse(self, current: LoadedPolicy, exc: Exception) -> ReloadResult:
        self.last_error = str(exc)
        self._metrics.inc(Metric.POLICY_RELOAD_FAILURES)
        logger.warning(
            "policy file %s refused, %s stays active: %s",
            self._path,
            current.bundle.version,
            exc,
        )
        return ReloadResult(changed=False, version=current.bundle.version, error=str(exc))

    @staticmethod
    def _parse(path: Path, text: str, mtime_ns: int, clock: Clock) -> LoadedPolicy:
        document = load_policy(text)
        sha256 = hashlib.sha256(text.encode("utf-8")).hexdigest()
        return LoadedPolicy(
            document=document,
            bundle=_bundle(document, sha256),
            sha256=sha256,
            path=str(path),
            mtime_ns=mtime_ns,
            loaded_at=clock(),
        )

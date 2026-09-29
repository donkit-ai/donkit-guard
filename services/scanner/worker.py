from __future__ import annotations

import asyncio
import logging
import time
from typing import TYPE_CHECKING

from donkit_guard.scanning.models import ScanStatus
from donkit_guard.scanning.reports import ReportError

from .auth import active
from .config import configuration
from .engine import EngineError, OpenHack
from .store import Forbidden

if TYPE_CHECKING:
    from .store import Store

logger = logging.getLogger(__name__)


async def process_one(store: Store, engine: OpenHack) -> bool:
    claimed = store.claim()
    if claimed is None:
        return False
    scan, snapshot = claimed
    started = time.monotonic()
    task: asyncio.Task | None = None
    try:
        config = configuration()
        config.model = scan.model  # Preserve the model chosen when queued.
        store.authorize(scan.actor, scan.project_id, write=True)
        if not await active(scan.actor, config):
            raise Forbidden("Initiating employee no longer has access")
        task = asyncio.create_task(engine.run(snapshot, config))
        while True:
            done, _ = await asyncio.wait({task}, timeout=2)
            current = store.heartbeat(scan.id)
            store.authorize(scan.actor, scan.project_id, write=True)
            if current.cancel_requested or not await active(scan.actor, configuration()):
                raise Forbidden("Scan cancelled or access revoked")
            if time.monotonic() - started > config.timeout_seconds:
                raise TimeoutError
            if done:
                scan.findings = task.result()
                scan.status = ScanStatus.COMPLETED
                break
    except Forbidden as exc:
        scan.status, scan.error = ScanStatus.CANCELLED, str(exc)
    except TimeoutError:
        scan.status, scan.error = ScanStatus.TIMED_OUT, "Scan exceeded its time limit"
    except (EngineError, ReportError) as exc:
        scan.status, scan.error = ScanStatus.FAILED, str(exc)
    except asyncio.CancelledError:
        scan.status, scan.error = ScanStatus.FAILED, "Worker stopped; start a new scan"
        raise
    except Exception as exc:
        # The queue boundary records unexpected failures and logs their type;
        # source contents / provider credentials never enter the public error.
        logger.error("Scanner worker failed: %s (%s)", scan.id, type(exc).__name__)
        scan.status, scan.error = ScanStatus.FAILED, "Unexpected scanner failure"
    finally:
        if task is not None:
            if not task.done():
                task.cancel()
            await asyncio.gather(task, return_exceptions=True)
        scan.duration_seconds = time.monotonic() - started
        store.finish(scan)
    return True


async def work(store: Store) -> None:
    engine = OpenHack()
    last_prune = 0.0
    while True:
        if time.monotonic() - last_prune > 3600:
            store.prune(configuration().retention_days)
            last_prune = time.monotonic()
        if not await process_one(store, engine):
            await asyncio.sleep(1)

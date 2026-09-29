from __future__ import annotations

import asyncio
import os
import signal
import tempfile
from contextlib import suppress
from pathlib import Path
from typing import TYPE_CHECKING

from pydantic import BaseModel, ValidationError

from donkit_guard.scanning.reports import ReportError, parse_report

if TYPE_CHECKING:
    from donkit_guard.scanning.models import Finding, Snapshot

    from .config import Configuration


class JournalEvent(BaseModel):
    event_type: str


class EngineError(RuntimeError):
    pass


class OpenHack:
    async def run(self, snapshot: Snapshot, config: Configuration) -> list[Finding]:
        if not config.provider_key.get_secret_value():
            raise EngineError("Scanner inference provider is not configured")
        with tempfile.TemporaryDirectory(prefix="guard-scan-") as temp:
            root = Path(temp)
            source, work = root / "source", root / "work"
            source.mkdir()
            work.mkdir()
            for item in snapshot.files:
                target = source / item.path
                target.parent.mkdir(parents=True, exist_ok=True)
                target.write_text(item.content)
            if snapshot.context:
                (source / ".openhack.md").write_text(snapshot.context)
            # Never bind the host /, /home, /data, /config or Docker socket. The
            # inner process gets its own PID/user/mount namespace and clean HOME.
            command = [
                "bwrap",
                "--die-with-parent",
                "--unshare-user",
                "--unshare-pid",
                "--unshare-ipc",
                "--unshare-uts",
                "--cap-drop",
                "ALL",
            ]
            for system in ("/usr", "/bin", "/lib", "/lib64", "/opt/engine"):
                if Path(system).exists():
                    command.extend(("--ro-bind", system, system))
            command.extend(("--ro-bind", str(Path(__file__).with_name("entry.py")), "/entry.py"))
            command.extend(("--dir", "/etc"))
            for system in ("/etc/ssl", "/etc/resolv.conf", "/etc/hosts"):
                if Path(system).exists():
                    command.extend(("--ro-bind", system, system))
            command.extend(
                (
                    "--proc",
                    "/proc",
                    "--dev",
                    "/dev",
                    "--tmpfs",
                    "/tmp",
                    "--ro-bind",
                    str(source),
                    "/target",
                    "--bind",
                    str(work),
                    "/work",
                    "--chdir",
                    "/work",
                )
            )
            environment = {
                "HOME": "/work",
                "PATH": "/opt/engine/bin:/usr/local/bin:/usr/bin:/bin",
                "LANG": "C.UTF-8",
                "PYTHONNOUSERSITE": "1",
                "PYTHONDONTWRITEBYTECODE": "1",
                "OPENHACK_API_KEY": config.provider_key.get_secret_value(),
                "OPENHACK_BASE_URL": config.provider_url,
                "OPENHACK_MODEL_ID": config.model,
                "SCAN_EXCLUDE_PATTERNS": "[]",
                "AGENT_MAX_ITERATIONS": "100",
                "SANDBOX_ENABLED": "false",
                "BROWSER_VERIFICATION_ENABLED": "false",
                "MAX_CONCURRENT_HUNTERS": "2",
                "MAX_CONCURRENT_VALIDATORS": "2",
                "OPENHACK_MAX_RETRIES": "2",
            }
            command.extend(
                (
                    "--",
                    "/usr/bin/prlimit",
                    "--as=4294967296",
                    "--fsize=67108864",
                    "--nofile=256",
                    f"--cpu={config.timeout_seconds}",
                    "--",
                    config.engine_python,
                    "/entry.py",
                )
            )
            process = await asyncio.create_subprocess_exec(
                *command,
                env=environment,
                stdout=asyncio.subprocess.DEVNULL,
                stderr=asyncio.subprocess.DEVNULL,
                start_new_session=True,
            )
            try:
                await process.wait()
            finally:
                # Also terminate descendants when the parent exits or task is cancelled.
                with suppress(ProcessLookupError):
                    os.killpg(process.pid, signal.SIGKILL)
                await process.wait()
            if process.returncode != 0:
                raise EngineError(
                    "OpenHack process failed (check sandbox runtime and provider configuration)"
                )
            reports = list((work / ".openhack" / "scans").glob("*.json"))
            if (
                (work / ".openhack").is_symlink()
                or (work / ".openhack" / "scans").is_symlink()
                or len(reports) != 1
                or reports[0].is_symlink()
            ):
                raise ReportError("Expected exactly one OpenHack report")
            if (work / "engine-error").exists():
                raise EngineError("An OpenHack scan stage failed")
            journal = reports[0].with_suffix(".events.jsonl")
            if journal.is_symlink() or not journal.is_file() or journal.stat().st_size > 64_000_000:
                raise ReportError("Missing or oversized scanner event journal")
            try:
                with journal.open("rb") as events:
                    while line := events.readline(1_000_001):
                        if len(line) > 1_000_000:
                            raise ReportError("Scanner journal entry exceeds the size limit")
                        event = JournalEvent.model_validate_json(line)
                        if event.event_type == "agent_loop_stopped":
                            raise ReportError("A scan stage stopped before completion")
            except ValidationError as exc:
                raise ReportError("Invalid scanner event journal") from exc
            # Bound reads even when a compromised engine writes an oversized report.
            with reports[0].open("rb") as report:
                return parse_report(report.read(50_000_001))

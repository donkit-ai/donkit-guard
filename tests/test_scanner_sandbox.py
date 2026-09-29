import os
import subprocess
from pathlib import Path

import pytest


@pytest.mark.skipif(
    not os.environ.get("GUARD_TEST_IMAGE"), reason="Set GUARD_TEST_IMAGE to a built scanner image"
)
def test_container_sandbox_with_real_openhack_configuration():
    root = Path(__file__).resolve().parents[1]
    code = """
import asyncio
from services.scanner.engine import OpenHack
from services.scanner.config import Configuration
from donkit_guard.scanning.models import Snapshot, SourceFile
async def main():
    snapshot = Snapshot(files=[SourceFile(path='src/tools/runtime.py', content="print('fixture')")])
    result = await asyncio.wait_for(OpenHack().run(snapshot, Configuration(provider_key='fixture')), 20)
    assert result == []
asyncio.run(main())
"""
    result = subprocess.run(
        [
            "docker",
            "run",
            "--rm",
            "--network",
            "none",
            "--read-only",
            "--tmpfs",
            "/tmp:mode=1777",
            "--cap-drop",
            "ALL",
            "--security-opt",
            "no-new-privileges",
            "--security-opt",
            f"seccomp={root / 'docker/seccomp-scanner-amd64.json'}",
            "--env",
            "INTERNAL_SECRET=must-not-reach-engine",
            "--volume",
            f"{root / 'tests/scanner_sandbox_probe.py'}:/app/services/scanner/entry.py:ro",
            os.environ["GUARD_TEST_IMAGE"],
            "/opt/service/bin/python",
            "-c",
            code,
        ],
        capture_output=True,
        text=True,
        timeout=40,
    )
    assert result.returncode == 0, result.stderr

"""Deterministic replacement entrypoint for the opt-in container sandbox test."""

import json
import os
from pathlib import Path

from openhack.config import settings

assert settings.scan_exclude_patterns == []
assert not settings.sandbox_enabled
assert not settings.browser_verification_enabled
assert settings.agent_max_iterations == 100
assert "INTERNAL_SECRET" not in os.environ
assert not Path("/config").exists()
assert not Path("/data").exists()
assert not Path("/app").exists()
assert not Path("/var/run/docker.sock").exists()
assert Path("/target/src/tools/runtime.py").read_text() == "print('fixture')"
assert Path.home() == Path("/work")
assert Path.cwd() == Path("/work")
try:
    Path("/target/modified.py").write_text("bad")
except OSError:
    pass
else:
    raise AssertionError("Source is writable")
reports = Path("/work/.openhack/scans")
reports.mkdir(parents=True)
(reports / "fixture.json").write_text(
    json.dumps(
        {
            "version": 3,
            "status": "completed",
            "findings": [],
            "trace": [{"event_type": "scan_complete"}],
        }
    )
)
(reports / "fixture.events.jsonl").write_text('{"event_type":"report_write_completed"}\n')

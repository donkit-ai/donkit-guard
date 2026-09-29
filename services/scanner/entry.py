"""Runs inside the isolated engine environment, using only the upstream CLI."""

import logging
import runpy
import sys
from pathlib import Path


class Errors(logging.Handler):
    def emit(self, record: logging.LogRecord) -> None:
        # Swarm children can fail while the upstream CLI still writes completed.
        # Preserve only a marker: the diagnostic itself may contain source/secrets.
        if record.levelno >= logging.ERROR:
            Path("/work/engine-error").touch()


logging.getLogger().addHandler(Errors())
sys.argv = ["openhack", "--scan", "/target"]
runpy.run_module("openhack", run_name="__main__")

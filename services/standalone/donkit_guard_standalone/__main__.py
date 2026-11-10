"""``guard-standalone``: the HTTP API and the gateway's gRPC server in one process."""

from __future__ import annotations

import logging
import os

import uvicorn

from donkit_guard_standalone.api import create_app
from donkit_guard_standalone.settings import Settings


def main() -> None:
    logging.basicConfig(
        level=os.environ.get("GUARD_LOG_LEVEL", "INFO").upper(),
        format="%(asctime)s %(levelname)s %(name)s %(message)s",
    )
    settings = Settings()  # the required settings come from the environment
    uvicorn.run(
        create_app(settings),
        host=settings.http_host,
        port=settings.http_port,
        log_config=None,
        proxy_headers=False,
        server_header=False,
    )


if __name__ == "__main__":
    main()

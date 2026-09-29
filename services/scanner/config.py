from __future__ import annotations

import os
from pathlib import Path

from pydantic import ConfigDict, Field, SecretStr, model_validator

from donkit_guard.scanning.models import Actor, Contract


class Token(Contract):
    sha256: str = Field(pattern=r"^[a-f0-9]{64}$")
    actor: Actor


class Source(Contract):
    tenant_id: str
    key: str
    path: Path


class Configuration(Contract):
    model_config = ConfigDict(extra="forbid", hide_input_in_errors=True)

    tokens: list[Token] = Field(default_factory=list)
    sources: list[Source] = Field(default_factory=list)
    host_secret: SecretStr = SecretStr("")
    membership_url: str = ""
    provider_key: SecretStr = SecretStr("")
    provider_url: str = "https://api.openhack.com/v1"
    model: str = "glm-5.3-flash"
    engine_python: str = "/opt/engine/bin/python"
    timeout_seconds: int = Field(default=1800, ge=10, le=7200)
    retention_days: int = Field(default=30, ge=1, le=365)

    @model_validator(mode="after")
    def host_auth(self) -> Configuration:
        secret = self.host_secret.get_secret_value()
        if secret and (len(secret) < 32 or not self.membership_url):
            raise ValueError("Host authentication needs a >=32 character secret and membership URL")
        if any(t.actor.issuer != "standalone" for t in self.tokens):
            raise ValueError("API tokens must use the standalone issuer")
        return self


def configuration() -> Configuration:
    # Read on each authorization: replacing the mounted file revokes tokens live.
    path = Path(os.environ.get("GUARD_SCANNER_CONFIG", "/config/scanner.json"))
    return Configuration.model_validate_json(path.read_bytes())

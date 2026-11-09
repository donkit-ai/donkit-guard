"""Configuration of the standalone service, read from ``GUARD_*`` environment variables."""

from __future__ import annotations

import re
from pathlib import Path
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, SecretStr, field_validator, model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict

from donkit_guard.context import DestinationTrust
from donkit_guard.detectors.runner import ExecutorKind

_SHA256_HEX = re.compile(r"^[0-9a-f]{64}$")


class ApiKey(BaseModel):
    """A client credential of the HTTP API: the SHA-256 of the key, never the key itself.

    ``tenant`` is the tenant every call made with the key belongs to, and ``name`` labels the
    key in logs.
    """

    model_config = ConfigDict(frozen=True, extra="forbid")

    sha256: str
    tenant: str = Field(min_length=1)
    name: str = ""

    @field_validator("sha256")
    @classmethod
    def _hex_digest(cls, value: str) -> str:
        value = value.removeprefix("sha256:").lower()
        if not _SHA256_HEX.match(value):
            raise ValueError("sha256 must be 64 hex characters")
        return value


class Settings(BaseSettings):
    """Every setting of ``guard-standalone``; secrets have no defaults."""

    model_config = SettingsConfigDict(env_prefix="GUARD_", extra="ignore", frozen=True)

    policy_file: Path
    # Seconds between two checks of the policy file's modification time.
    policy_check_interval_s: float = Field(default=1.0, ge=0.0)
    tool_catalog_file: Path | None = None

    db_url: str = "sqlite+aiosqlite:///guard.db"
    db_migrate: bool = True

    # Base URL of guard-pii, e.g. http://guard-pii:8080. NER detection is off only when
    # `pii_disabled` says so, so that a missing URL is never mistaken for a choice.
    pii_url: str | None = None
    pii_disabled: bool = False

    api_keys: tuple[ApiKey, ...] = Field(min_length=1)
    admin_token: SecretStr

    http_host: str = "0.0.0.0"
    http_port: int = Field(default=8080, ge=0, le=65535)
    grpc_host: str = "0.0.0.0"
    # One gRPC server carries both gateway protocols, ext_proc and ExtMcp; 0 picks a free port.
    grpc_port: int = Field(default=9090, ge=0, le=65535)

    # Largest body accepted: an HTTP API call, an LLM request or response, MCP params.
    max_body_bytes: int = Field(default=1_048_576, ge=1024)

    detector_executor: ExecutorKind = ExecutorKind.THREAD
    detector_workers: int = Field(default=2, ge=1)
    # Budget of an in-process detector: a base plus a share per KiB scanned.
    detector_local_base_ms: float = Field(default=10.0, gt=0)
    detector_local_per_kb_ms: float = Field(default=3.0, ge=0)
    # The longest a remote detector (guard-pii) is waited for.
    detector_remote_timeout_ms: float = Field(default=2000.0, gt=0)

    approval_sweep_interval_s: float = Field(default=30.0, gt=0)

    # How the LLM upstream behind the gateway is described to the policy.
    llm_provider: str = Field(default="openai", min_length=1)
    llm_destination_trust: DestinationTrust = DestinationTrust.UNKNOWN
    # A request the guard cannot parse (anything but chat completions) is refused unless allowed.
    unsupported_requests: Literal["deny", "allow"] = "deny"
    # Streamed responses are released in windows of this many characters, each checked
    # together with the last `stream_overlap_chars` of the text already released.
    stream_window_chars: int = Field(default=1024, ge=64)
    stream_overlap_chars: int = Field(default=256, ge=0)

    @model_validator(mode="after")
    def _pii_is_a_choice(self) -> Settings:
        if self.pii_url is None and not self.pii_disabled:
            raise ValueError("set GUARD_PII_URL, or GUARD_PII_DISABLED=true to run without NER")
        if self.pii_url is not None and self.pii_disabled:
            raise ValueError("GUARD_PII_URL and GUARD_PII_DISABLED=true contradict each other")
        if len(self.admin_token.get_secret_value()) < 16:
            raise ValueError("GUARD_ADMIN_TOKEN must be at least 16 characters")
        if self.stream_overlap_chars >= self.stream_window_chars:
            raise ValueError("stream_overlap_chars must be smaller than stream_window_chars")
        return self

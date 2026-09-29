from __future__ import annotations

import hashlib
from datetime import datetime
from enum import StrEnum
from pathlib import PurePosixPath

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator


class Contract(BaseModel):
    model_config = ConfigDict(extra="forbid")


class GuardRole(StrEnum):
    VIEWER = "viewer"
    OPERATOR = "operator"
    ADMIN = "admin"


class Actor(Contract):
    tenant_id: str = Field(min_length=1, max_length=100)
    user_id: str = Field(min_length=1, max_length=100)
    # Supplied only by an authenticated host, never by an ordinary request body.
    account_owner: bool = False
    issuer: str = "standalone"


class Access(Contract):
    enabled: bool = False
    role: GuardRole | None = None
    can_manage: bool = False
    can_view: bool = False
    can_scan: bool = False


class Grant(Contract):
    user_id: str = Field(min_length=1, max_length=100)
    role: GuardRole | None = None
    project_ids: list[str] = Field(default_factory=list, max_length=1000)


class ProjectCreate(Contract):
    name: str = Field(min_length=1, max_length=200)
    kind: str = Field(pattern="^(snapshot|mounted|donkit)$")
    source_ref: str = Field(default="", max_length=200)

    @model_validator(mode="after")
    def source_required(self) -> ProjectCreate:
        if self.kind != "snapshot" and not self.source_ref:
            raise ValueError("This project kind requires a source reference")
        return self


class Project(ProjectCreate):
    id: str
    tenant_id: str
    created_at: datetime


class SourceFile(Contract):
    path: str = Field(min_length=1, max_length=1024)
    content: str = Field(max_length=1_000_000)

    @field_validator("content")
    @classmethod
    def bounded_content(cls, value: str) -> str:
        if len(value.encode("utf-8")) > 1_000_000:
            raise ValueError("Source file exceeds 1 MB")
        return value

    @field_validator("path")
    @classmethod
    def safe_path(cls, value: str) -> str:
        path = PurePosixPath(value)
        if (
            path.is_absolute()
            or "\\" in value
            or ":" in value
            or "\x00" in value
            or any(p in ("", ".", "..") for p in value.split("/"))
        ):
            raise ValueError("Source paths must be relative normalized POSIX paths")
        if any(p.lower() in (".git", ".ssh", ".aws", ".openhack") for p in path.parts):
            raise ValueError("Credential and repository metadata directories are excluded")
        name = path.name.lower()
        if (
            name in (".openhack.md", ".env", ".npmrc", ".pypirc")
            or name.startswith(".env.")
            or path.suffix.lower() in (".pem", ".key", ".p12", ".pfx")
        ):
            raise ValueError("Scanner configuration and environment files are excluded")
        return value


class Snapshot(Contract):
    files: list[SourceFile] = Field(min_length=1, max_length=10_000)
    revision: str = Field(default="", max_length=200)
    context: str = Field(default="", max_length=100_000)

    @model_validator(mode="after")
    def bounded_unique(self) -> Snapshot:
        names = [f.path for f in self.files]
        if len(set(names)) != len(names):
            raise ValueError("Duplicate source path")
        paths = set(names)
        for name in names:
            if any(str(p) in paths for p in PurePosixPath(name).parents if str(p) != "."):
                raise ValueError("A source file cannot also be a directory")
        if sum(len(f.content.encode()) for f in self.files) > 40_000_000:
            raise ValueError("Snapshot exceeds 40 MB")
        return self

    def digest(self) -> str:
        canonical = self.model_copy(update={"files": sorted(self.files, key=lambda f: f.path)})
        return hashlib.sha256(canonical.model_dump_json().encode()).hexdigest()


class ScanStatus(StrEnum):
    QUEUED = "queued"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"
    TIMED_OUT = "timed_out"


class Finding(Contract):
    id: str
    severity: str
    title: str
    description: str
    file_path: str
    line_number: int | None = None
    code: str = ""
    recommendation: str = ""
    evidence: str = ""
    fingerprint: str
    verification: str = "code_review"


class Scan(Contract):
    id: str
    project_id: str
    tenant_id: str
    actor: Actor
    status: ScanStatus
    snapshot_digest: str
    revision: str
    created_at: datetime
    updated_at: datetime
    cancel_requested: bool = False
    error: str = ""
    findings: list[Finding] = Field(default_factory=list)
    scanner_revision: str = "4e1f532e01c3ecca007e07ff4c06770c1c4a9919"
    model: str = ""
    duration_seconds: float = 0
    # Completion is code review; it is never a claim that the application is safe.
    verification: str = "not_requested"


class ScanRequest(Contract):
    snapshot: Snapshot | None = None


class SettingsUpdate(Contract):
    enabled: bool


class AuditEvent(Contract):
    id: str
    tenant_id: str
    user_id: str
    action: str
    resource: str
    created_at: datetime

"""Validate OpenHack's report rather than trusting its CLI exit status."""

from __future__ import annotations

import hashlib

from pydantic import BaseModel, JsonValue, ValidationError

from donkit_guard.scanning.models import Finding


class ReportError(ValueError):
    pass


class _Finding(BaseModel):
    id: str
    severity: str
    title: str
    description: str
    filePath: str
    lineNumber: int | None = None
    relevantCode: str | None = None
    recommendation: str | None = None
    poc: str | None = None
    validated: bool = False
    verificationSource: str | None = None


class _Trace(BaseModel):
    event_type: str
    content: JsonValue = None


class _Report(BaseModel):
    version: int
    status: str
    event_log_error: str | None = None
    findings: list[_Finding]
    trace: list[_Trace]


def parse_report(raw: bytes) -> list[Finding]:
    if len(raw) > 50_000_000:
        raise ReportError("Scanner report exceeds the size limit")
    try:
        report = _Report.model_validate_json(raw)
    except ValidationError as exc:
        raise ReportError("Invalid scanner report") from exc
    if report.event_log_error:
        raise ReportError("Scanner journal could not be saved")
    if report.version != 3 or report.status != "completed":
        raise ReportError("Scanner did not produce a completed version 3 report")
    if any(t.event_type in ("sandbox_error", "browser_error") for t in report.trace):
        raise ReportError("Scanner verification failed")
    if not any(t.event_type == "scan_complete" for t in report.trace):
        raise ReportError("Scanner report is incomplete")
    findings: list[Finding] = []
    for f in report.findings:
        fingerprint = hashlib.sha256(
            f"{f.filePath}\n{f.lineNumber}\n{f.title}\n{f.relevantCode}".encode()
        ).hexdigest()[:24]
        # A model's `validated` flag alone is not proof of runtime reproduction.
        verification = (
            "reproduced"
            if f.verificationSource in ("sandbox_verified", "browser_verified")
            else "code_review"
        )
        findings.append(
            Finding(
                id=f.id,
                severity=f.severity,
                title=f.title,
                description=f.description,
                file_path=f.filePath,
                line_number=f.lineNumber,
                code=f.relevantCode or "",
                recommendation=f.recommendation or "",
                evidence=f.poc or "",
                fingerprint=fingerprint,
                verification=verification,
            )
        )
    return findings

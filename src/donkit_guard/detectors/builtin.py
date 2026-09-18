"""Imports every built-in detector module so that their registry entries exist in worker processes."""

from __future__ import annotations

from donkit_guard.detectors import injection, pii_checksum, secrets

__all__ = ["injection", "pii_checksum", "secrets"]

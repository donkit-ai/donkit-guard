"""Donkit Guard: policy checks for LLM traffic and AI-agent actions.

The package is the shared core used both embedded in a runtime and by the
standalone gateway service. Everything here is runtime-agnostic: the host
supplies identity, tools and storage through the adapter interfaces.
"""

from __future__ import annotations

from importlib.metadata import PackageNotFoundError, version

from donkit_guard.approval_flow import ApprovalFlow
from donkit_guard.approvals import ApprovalDecisionValue, ApprovalRecord
from donkit_guard.context import (
    Action,
    ActionKind,
    AgentRef,
    Destination,
    DestinationLocality,
    DestinationTrust,
    EffectClass,
    EffectSource,
    GuardContext,
    Principal,
    PrincipalKind,
    RunRef,
    Tenant,
)
from donkit_guard.decision import Decision, Explanation, Location, Outcome, PolicyMode
from donkit_guard.engine import Engine
from donkit_guard.findings import FindingClass
from donkit_guard.guard import Guard, build_quickstart_guard
from donkit_guard.payload import Payload, Segment, SegmentSource, SegmentTrust
from donkit_guard.policy import PolicyBundle, default_bundle, load_policy

try:
    __version__ = version("donkit-guard")
except PackageNotFoundError:  # editable checkout without an installed distribution
    __version__ = "0.0.0"

__all__ = [
    "Action",
    "ActionKind",
    "AgentRef",
    "ApprovalDecisionValue",
    "ApprovalFlow",
    "ApprovalRecord",
    "Decision",
    "Destination",
    "DestinationLocality",
    "DestinationTrust",
    "EffectClass",
    "EffectSource",
    "Engine",
    "Explanation",
    "FindingClass",
    "Guard",
    "GuardContext",
    "Location",
    "Outcome",
    "Payload",
    "PolicyBundle",
    "PolicyMode",
    "Principal",
    "PrincipalKind",
    "RunRef",
    "Segment",
    "SegmentSource",
    "SegmentTrust",
    "Tenant",
    "__version__",
    "build_quickstart_guard",
    "default_bundle",
    "load_policy",
]

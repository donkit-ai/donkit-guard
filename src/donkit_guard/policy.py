"""Policy documents: versioned layers of attribute-matching rules."""

from __future__ import annotations

import fnmatch
from enum import StrEnum
from importlib import resources
from typing import TYPE_CHECKING, Literal

import yaml
from pydantic import Field, ValidationError, field_validator, model_validator

from donkit_guard.context import (
    ActionKind,
    AttrValue,
    DestinationLocality,
    DestinationTrust,
    EffectClass,
    EffectSource,
    FrozenModel,
    GuardContext,
    PrincipalKind,
)
from donkit_guard.decision import PolicyMode
from donkit_guard.errors import PolicyError
from donkit_guard.findings import ENFORCEABLE_CLASSES, FindingClass, FindingSpan
from donkit_guard.payload import Segment, SegmentTrust

if TYPE_CHECKING:
    from collections.abc import Iterator, Sequence


class RuleAction(StrEnum):
    ALLOW = "allow"
    DENY = "deny"
    MASK = "mask"
    REQUIRE_APPROVAL = "require_approval"
    AUDIT = "audit"


class Match(FrozenModel):
    """A conjunction of selectors: every selector that is set must hold."""

    action_kind: tuple[ActionKind, ...] | None = None
    effect: tuple[EffectClass, ...] | None = None
    effect_source: tuple[EffectSource, ...] | None = None
    tool: tuple[str, ...] | None = None
    principal_kind: tuple[PrincipalKind, ...] | None = None
    principal_absent: bool | None = None
    tenant: tuple[str, ...] | None = None
    destination_trust: tuple[DestinationTrust, ...] | None = None
    destination_locality: tuple[DestinationLocality, ...] | None = None
    untrusted_content_seen: bool | None = None
    attributes: dict[str, AttrValue] | None = None
    finding_class: tuple[FindingClass, ...] | None = None
    finding_subtype: tuple[str, ...] | None = None
    min_score: float | None = Field(default=None, ge=0.0, le=1.0)
    segment_trust: tuple[SegmentTrust, ...] | None = None

    @model_validator(mode="after")
    def _effect_is_reachable(self) -> Match:
        if self.effect is not None and EffectClass.UNKNOWN in self.effect:
            raise ValueError("effect: unknown never matches, an unknown effect is gated as write")
        return self

    def needs_findings(self) -> bool:
        """True when the rule can only be decided after detectors ran."""
        return any(
            value is not None
            for value in (
                self.finding_class,
                self.finding_subtype,
                self.min_score,
                self.segment_trust,
            )
        )

    def finding_classes(self) -> frozenset[FindingClass]:
        return frozenset(self.finding_class or ())

    def matches_context(self, ctx: GuardContext, effective_effect: EffectClass) -> bool:
        action = ctx.action
        if self.action_kind is not None and action.kind not in self.action_kind:
            return False
        if self.effect is not None and effective_effect not in self.effect:
            return False
        if self.effect_source is not None and action.effect_source not in self.effect_source:
            return False
        if self.tool is not None and (
            action.tool is None or not any(fnmatch.fnmatchcase(action.tool, g) for g in self.tool)
        ):
            return False
        if (
            self.principal_absent is not None
            and (ctx.principal is None) is not self.principal_absent
        ):
            return False
        if self.principal_kind is not None and (
            ctx.principal is None or ctx.principal.kind not in self.principal_kind
        ):
            return False
        if self.tenant is not None and (ctx.tenant is None or ctx.tenant.id not in self.tenant):
            return False
        if self.destination_trust is not None and (
            action.destination is None or action.destination.trust not in self.destination_trust
        ):
            return False
        if self.destination_locality is not None and (
            action.destination is None
            or action.destination.locality not in self.destination_locality
        ):
            return False
        if (
            self.untrusted_content_seen is not None
            and ctx.run.untrusted_content_seen is not self.untrusted_content_seen
        ):
            return False
        if self.attributes is not None:
            for key, expected in self.attributes.items():
                if ctx.attributes.get(key) != expected:
                    return False
        return True

    def matches_span(self, span: FindingSpan, segment: Segment) -> bool:
        if self.finding_class is not None and span.cls not in self.finding_class:
            return False
        if self.finding_subtype is not None and not any(
            fnmatch.fnmatchcase(span.subtype, pattern) for pattern in self.finding_subtype
        ):
            return False
        if self.min_score is not None and span.score < self.min_score:
            return False
        return self.segment_trust is None or segment.trust in self.segment_trust


class Rule(FrozenModel):
    id: str = Field(min_length=1)
    description: str = ""
    match: Match = Field(default_factory=Match)
    action: RuleAction
    hard: bool = False
    reason: str = ""

    @model_validator(mode="after")
    def _action_matches_selectors(self) -> Rule:
        signal = self.match.finding_classes() - ENFORCEABLE_CLASSES
        if signal and self.action is not RuleAction.AUDIT:
            names = ", ".join(sorted(c.value for c in signal))
            raise ValueError(
                f"rule {self.id!r}: finding class {names} is a signal and may only be audited"
            )
        if self.hard and self.action is not RuleAction.DENY:
            raise ValueError(f"rule {self.id!r}: hard applies to deny rules only")
        if self.action is RuleAction.MASK and not self.match.needs_findings():
            # Without a selector there is no span to replace, and the decision would
            # report a masked payload that was forwarded unchanged.
            raise ValueError(f"rule {self.id!r}: mask requires a finding selector")
        return self


class PolicyLayer(FrozenModel):
    name: str = Field(min_length=1)
    rules: tuple[Rule, ...] = ()


class PolicyDocument(FrozenModel):
    schema_version: Literal[1] = 1
    version: str = Field(min_length=1)
    mode: PolicyMode = PolicyMode.OBSERVE
    unsupported_content: Literal["uninspected", "deny"] = "uninspected"
    approval_ttl_s: int = Field(default=300, ge=1)
    segment_limit_bytes: int = Field(default=262144, ge=1024)
    layers: tuple[PolicyLayer, ...] = ()

    @field_validator("mode", mode="before")
    @classmethod
    def _bare_off_is_a_mode(cls, value: object) -> object:
        # YAML 1.1 reads an unquoted `off` as the boolean false; the author meant the mode.
        return PolicyMode.OFF if value is False else value

    @model_validator(mode="after")
    def _rule_ids_unique(self) -> PolicyDocument:
        seen: set[str] = set()
        for _, rule in self.iter_rules():
            if rule.id in seen:
                raise ValueError(f"duplicate rule id {rule.id!r}")
            seen.add(rule.id)
        return self

    def iter_rules(self) -> Iterator[tuple[str, Rule]]:
        for layer in self.layers:
            for rule in layer.rules:
                yield layer.name, rule


MODE_STRICTNESS: dict[PolicyMode, int] = {
    PolicyMode.OFF: 0,
    PolicyMode.OBSERVE: 1,
    PolicyMode.ENFORCE: 2,
}


class PolicyBundle(FrozenModel):
    """The documents that apply to one context, in precedence order."""

    documents: tuple[PolicyDocument, ...]
    version: str
    mode: PolicyMode

    @classmethod
    def compose(
        cls, documents: Sequence[PolicyDocument], mode: PolicyMode | None = None
    ) -> PolicyBundle:
        """Combine documents into the bundle that decides one context.

        Every setting takes its strictest value across the documents, ``mode``
        included: a tenant layer composed on top of a platform layer must not be
        able to switch the platform's enforcement off. A caller that wants a
        different mode (a staged rollout, say) passes one explicitly.
        """
        if not documents:
            raise PolicyError("a policy bundle needs at least one document")
        seen: set[str] = set()
        for document in documents:
            for _, rule in document.iter_rules():
                if rule.id in seen:
                    raise PolicyError(
                        f"duplicate rule id {rule.id!r} across the documents of a bundle"
                    )
                seen.add(rule.id)
        if mode is None:
            mode = max((d.mode for d in documents), key=MODE_STRICTNESS.__getitem__)
        version = "+".join(d.version for d in documents)
        return cls(documents=tuple(documents), version=version, mode=mode)

    @property
    def unsupported_content(self) -> Literal["uninspected", "deny"]:
        # The strictest setting across the layers wins: one layer refusing to
        # pass content it cannot inspect cannot be relaxed by another.
        if any(d.unsupported_content == "deny" for d in self.documents):
            return "deny"
        return "uninspected"

    @property
    def approval_ttl_s(self) -> int:
        return min(d.approval_ttl_s for d in self.documents)

    @property
    def segment_limit_bytes(self) -> int:
        return min(d.segment_limit_bytes for d in self.documents)

    def iter_rules(self) -> Iterator[tuple[str, Rule]]:
        for document in self.documents:
            yield from document.iter_rules()


def load_policy(text: str) -> PolicyDocument:
    try:
        raw = yaml.safe_load(text)
    except yaml.YAMLError as exc:
        raise PolicyError(f"invalid YAML: {exc}") from exc
    if not isinstance(raw, dict):
        raise PolicyError("a policy document must be a mapping")
    try:
        return PolicyDocument.model_validate(raw)
    except ValidationError as exc:
        raise PolicyError(str(exc)) from exc


def load_default_policy() -> PolicyDocument:
    text = resources.files("donkit_guard.data").joinpath("default_policy.yaml").read_text("utf-8")
    return load_policy(text)


def default_bundle(mode: PolicyMode = PolicyMode.OBSERVE) -> PolicyBundle:
    return PolicyBundle.compose([load_default_policy()], mode=mode)

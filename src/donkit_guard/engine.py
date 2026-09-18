"""Two-phase evaluation of a context and payload into a decision."""

from __future__ import annotations

import logging
import time
from dataclasses import dataclass
from typing import TYPE_CHECKING, Literal

from donkit_guard.actions import ActionCatalog, ActionDescriptor, action_digest, default_descriptor
from donkit_guard.adapters import AuditSink, Clock, PolicySource, utc_now
from donkit_guard.audit import DecisionEvent, ExecutionEvent, redact_display_args, summarize_context
from donkit_guard.context import ActionKind, EffectClass, FrozenModel, GuardContext
from donkit_guard.decision import STRICTNESS, Decision, Explanation, Location, Outcome, PolicyMode
from donkit_guard.errors import PolicyError
from donkit_guard.masking import mask
from donkit_guard.policy import RuleAction

if TYPE_CHECKING:
    from collections.abc import Collection

    from donkit_guard.detectors.runner import DetectorRunner
    from donkit_guard.findings import Findings, FindingSpan
    from donkit_guard.payload import Payload
    from donkit_guard.policy import Rule

logger = logging.getLogger("donkit_guard.engine")

_OUTCOME_FOR_ACTION: dict[RuleAction, Outcome] = {
    RuleAction.ALLOW: Outcome.ALLOW,
    RuleAction.MASK: Outcome.MASK,
    RuleAction.REQUIRE_APPROVAL: Outcome.REQUIRE_APPROVAL,
    RuleAction.DENY: Outcome.DENY,
}

_CODE_FOR_OUTCOME: dict[Outcome, str] = {
    Outcome.ALLOW: "allowed",
    Outcome.MASK: "masked",
    Outcome.REQUIRE_APPROVAL: "approval_required",
    Outcome.APPROVAL_PENDING: "approval_pending",
    Outcome.DENY: "policy_denied",
}


class EngineSettings(FrozenModel):
    max_locations: int = 100
    max_preview_entries: int = 100


@dataclass(frozen=True)
class Verdict:
    rule_id: str
    action: RuleAction
    hard: bool
    reason: str
    span: FindingSpan | None = None


def _protected(ctx: GuardContext, effective: EffectClass) -> bool:
    return ctx.action.kind is ActionKind.TOOL_CALL and effective is not EffectClass.READ


class Engine:
    def __init__(
        self,
        *,
        policy_source: PolicySource,
        runner: DetectorRunner,
        audit_sink: AuditSink,
        action_catalog: ActionCatalog | None = None,
        clock: Clock = utc_now,
        settings: EngineSettings | None = None,
    ) -> None:
        self.policy_source = policy_source
        self.runner = runner
        self.audit_sink = audit_sink
        self.action_catalog = action_catalog
        self._clock = clock
        self._settings = settings if settings is not None else EngineSettings()

    async def aclose(self) -> None:
        """Release the detector workers; the runner rebuilds its pool on the next scan."""
        self.runner.close()

    def describe(self, ctx: GuardContext) -> ActionDescriptor:
        """The host's descriptor for this tool, or a conservative one built from the action itself."""
        tool = ctx.action.tool
        if ctx.action.kind is not ActionKind.TOOL_CALL or tool is None:
            return default_descriptor(tool or "-")
        if self.action_catalog is not None:
            described = self.action_catalog.describe(tool, ctx.action.arguments)
            if described is not None:
                return described
        return default_descriptor(tool).model_copy(
            update={"effect": ctx.action.effect, "effect_source": ctx.action.effect_source}
        )

    async def approval_ttl(self, ctx: GuardContext) -> int:
        return (await self.policy_source.resolve(ctx)).approval_ttl_s

    async def record_execution(
        self,
        decision_id: str,
        outcome: Literal["success", "error", "skipped"],
        *,
        error_class: str | None = None,
        duration_ms: float = 0.0,
    ) -> None:
        await self.audit_sink.record(
            ExecutionEvent(
                decision_id=decision_id,
                outcome=outcome,
                error_class=error_class,
                duration_ms=duration_ms,
                occurred_at=self._clock(),
            )
        )

    async def record_decision(self, decision: Decision, ctx: GuardContext) -> Decision:
        """Write the decision event and answer with the decision the host may act on.

        In enforce mode a critical event that could not be written turns the
        decision into a deny: a decision nobody can reconstruct later must not
        keep its permission.
        """
        event = DecisionEvent(
            decision=decision,
            context=summarize_context(ctx),
            display_args_redacted=decision.display_args_redacted,
            occurred_at=self._clock(),
        )
        try:
            await self.audit_sink.record(event)
        except (
            Exception
        ) as exc:  # the sink is the host's; a lost critical event must not become a silent allow
            logger.warning("audit sink failed for decision %s: %s", decision.decision_id, exc)
            if decision.mode is PolicyMode.ENFORCE and decision.critical:
                return decision.model_copy(
                    update={
                        "outcome": Outcome.DENY,
                        "explanation": decision.explanation.model_copy(
                            update={
                                "code": "audit_unavailable",
                                "reason": "the audit record could not be written",
                            }
                        ),
                        "masked_segments": {},
                    }
                )
        return decision

    async def evaluate(
        self,
        ctx: GuardContext,
        payload: Payload,
        *,
        seen_segments: Collection[str] | None = None,
        audit: bool = True,
    ) -> Decision:
        started = time.perf_counter()
        context_hash = ctx.context_hash()
        try:
            bundle = await self.policy_source.resolve(ctx)
        except PolicyError as exc:
            logger.warning("policy could not be resolved: %s", exc)
            unresolved = Decision(
                outcome=Outcome.DENY,
                explanation=Explanation(
                    code="policy_error", reason=f"the policy could not be resolved: {exc}"
                ),
                policy_version="unresolved",
                mode=PolicyMode.ENFORCE,
                critical=True,
                context_hash=context_hash,
                latency_ms=(time.perf_counter() - started) * 1000.0,
            )
            return await self.record_decision(unresolved, ctx) if audit else unresolved
        if bundle.mode is PolicyMode.OFF:
            return Decision(
                outcome=Outcome.ALLOW,
                explanation=Explanation(
                    code="guard_off", reason="guard is switched off for this tenant"
                ),
                policy_version=bundle.version,
                mode=bundle.mode,
                context_hash=context_hash,
                latency_ms=(time.perf_counter() - started) * 1000.0,
            )

        descriptor: ActionDescriptor | None = None
        digest: str | None = None
        action = ctx.action
        if action.kind is ActionKind.TOOL_CALL:
            descriptor = self.describe(ctx)
            action = action.model_copy(
                update={"effect": descriptor.effect, "effect_source": descriptor.effect_source}
            )
            ctx = ctx.model_copy(update={"action": action})
            digest = action_digest(descriptor, action.arguments)
        effective = action.effective_effect()

        verdicts: list[Verdict] = []
        finding_rules: list[Rule] = []
        for _, rule in bundle.iter_rules():
            if not rule.match.matches_context(ctx, effective):
                continue
            if rule.match.needs_findings():
                finding_rules.append(rule)
            else:
                verdicts.append(Verdict(rule.id, rule.action, rule.hard, rule.reason))

        limit = bundle.segment_limit_bytes
        candidates = payload.new_segments(seen_segments or ())
        to_scan = [s for s in candidates if s.size_bytes <= limit]
        uninspected = [s.label() for s in payload.uninspected_parts()] + [
            f"oversized:{s.label()}" for s in candidates if s.size_bytes > limit
        ]
        by_id = payload.by_id()

        findings: list[Findings] = []
        if finding_rules and to_scan:
            findings = await self.runner.run(to_scan)
        failed = [f.detector_id for f in findings if f.failed]
        spans: list[FindingSpan] = [span for f in findings if not f.failed for span in f.spans]
        for rule in finding_rules:
            for span in spans:
                segment = by_id.get(span.segment_id)
                if segment is not None and rule.match.matches_span(span, segment):
                    verdicts.append(Verdict(rule.id, rule.action, rule.hard, rule.reason, span))

        enforceable = [v for v in verdicts if v.action is not RuleAction.AUDIT]
        if enforceable:
            lead = max(enforceable, key=lambda v: STRICTNESS[_OUTCOME_FOR_ACTION[v.action]])
            outcome = _OUTCOME_FOR_ACTION[lead.action]
            code, reason = _CODE_FOR_OUTCOME[outcome], lead.reason
        elif _protected(ctx, effective):
            outcome, code, reason = (
                Outcome.DENY,
                "default_deny",
                "protected action without a matching rule",
            )
        else:
            outcome, code, reason = Outcome.ALLOW, "allowed", ""

        mask_verdicts = [v for v in verdicts if v.action is RuleAction.MASK]
        mask_spans = [v.span for v in mask_verdicts if v.span is not None]
        masked: dict[str, str] = {}
        # A mask verdict without a span selects no text, so nothing would be
        # rewritten while the outcome still claims the payload was masked.
        unmaskable = any(v.span is None for v in mask_verdicts)
        unmaskable_reason = "a mask rule matched without a finding to mask"
        if mask_spans:
            result = mask(
                payload,
                mask_spans,
                maskable_arg_paths=descriptor.maskable_args if descriptor else (),
            )
            masked = result.masked
            if not result.ok:
                unmaskable = True
                unmaskable_reason = "a finding inside tool arguments cannot be masked safely"
        if unmaskable and STRICTNESS[outcome] < STRICTNESS[Outcome.DENY]:
            outcome, code, reason = Outcome.DENY, "masking_impossible", unmaskable_reason
        if failed and STRICTNESS[outcome] < STRICTNESS[Outcome.DENY]:
            if bundle.mode is PolicyMode.ENFORCE:
                outcome, code, reason = (
                    Outcome.DENY,
                    "detector_unavailable",
                    f"detector(s) failed: {', '.join(failed)}",
                )
            else:
                code = "detector_failed"
        if (
            uninspected
            and bundle.unsupported_content == "deny"
            and STRICTNESS[outcome] < STRICTNESS[Outcome.DENY]
        ):
            outcome, code, reason = (
                Outcome.DENY,
                "unsupported_content",
                "the payload contains parts the guard cannot inspect",
            )

        would_outcome: Outcome | None = None
        would_block = False
        if bundle.mode is PolicyMode.OBSERVE and (outcome is not Outcome.ALLOW or masked):
            would_outcome = outcome if outcome is not Outcome.ALLOW else Outcome.MASK
            would_block = True
            outcome = Outcome.ALLOW
            masked = {}
        if outcome is Outcome.DENY:
            # A payload the host may not send at all carries no usable masks.
            masked = {}
        hard = outcome is Outcome.DENY and any(
            v.action is RuleAction.DENY and v.hard for v in enforceable
        )
        critical = would_block or outcome is not Outcome.ALLOW or bool(spans) or bool(failed)

        locations = tuple(Location.from_span(s) for s in spans[: self._settings.max_locations])
        display_args = (
            redact_display_args(
                action.arguments,
                spans,
                payload,
                max_entries=self._settings.max_preview_entries,
            )
            if action.kind is ActionKind.TOOL_CALL
            else {}
        )
        decision = Decision(
            outcome=outcome,
            hard=hard,
            explanation=Explanation(
                code=code,
                reason=reason,
                rule_ids=tuple(dict.fromkeys(v.rule_id for v in verdicts)),
                finding_classes=tuple(sorted({s.cls for s in spans})),
                locations=locations,
            ),
            detector_versions=self.runner.versions(),
            policy_version=bundle.version,
            descriptor_version=descriptor.version if descriptor else None,
            uninspected_parts=tuple(uninspected),
            latency_ms=(time.perf_counter() - started) * 1000.0,
            mode=bundle.mode,
            would_outcome=would_outcome,
            would_block=would_block,
            critical=critical,
            masked_segments=masked,
            display_args_redacted=display_args,
            action_digest=digest,
            context_hash=context_hash,
        )
        return await self.record_decision(decision, ctx) if audit else decision

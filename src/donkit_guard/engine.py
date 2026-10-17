"""Two-phase evaluation of a context and payload into a decision.

Rules are matched against the context first; those that select findings are then matched
against what the detectors find in the payload. The detectors are the runner's own and those
the policy documents declare, and which of them run is worked out per call from the rules that
matched the context: a detector runs synchronously when a rule with any action but ``audit``
could use its findings, in the background when only ``audit`` rules could, and not at all
otherwise.

A background check never denies the decision, and only a decision that asks for an approval
waits for it, because the approval card shows the arguments. What it finds is written after the
decision, as a ``FindingsEvent`` under the decision's id. A decision shows no value of a tool
call's arguments until every detector has reported on them; when the background check was all
it lacked, the ``FindingsEvent`` carries the previews. In observe mode, which never blocks, the
whole evaluation runs in the background and the host is answered at once; an execution event
recorded meanwhile is written after the decision. Background scans take the runner's background
lane, so they never hold up a scan an answer waits for. Background work is bounded by
``EngineSettings.max_background_checks``, and what is still running when the process ends is
lost.
"""

from __future__ import annotations

import asyncio
import logging
import time
import uuid
from dataclasses import dataclass, replace
from typing import TYPE_CHECKING, Any, Literal

from donkit_guard.actions import ActionCatalog, ActionDescriptor, action_digest, default_descriptor
from donkit_guard.adapters import AuditSink, Clock, PolicySource, utc_now
from donkit_guard.audit import (
    DecisionEvent,
    ExecutionEvent,
    FindingsEvent,
    redact_display_args,
    summarize_context,
)
from donkit_guard.context import ActionKind, EffectClass, FrozenModel, GuardContext
from donkit_guard.decision import STRICTNESS, Decision, Explanation, Location, Outcome, PolicyMode
from donkit_guard.declared import DeclaredDetectors
from donkit_guard.detectors.base import detector_id, detector_required
from donkit_guard.errors import PolicyError
from donkit_guard.masking import mask
from donkit_guard.policy import RuleAction
from donkit_guard.selection import select_detectors

if TYPE_CHECKING:
    from collections.abc import Collection, Coroutine, Mapping, Sequence

    from donkit_guard.detectors.base import AnyDetector
    from donkit_guard.detectors.runner import DetectorRunner
    from donkit_guard.findings import Findings, FindingSpan
    from donkit_guard.payload import Payload, Segment
    from donkit_guard.policy import PolicyBundle, Rule

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
    # Characters kept per argument preview on approval cards and audit rows. An
    # approver has to be able to read what a write is about to store, so a host
    # with a card UI raises this well above the audit-friendly default.
    preview_chars: int = 256
    # Background checks in flight at once: audit-only detectors still scanning after their
    # decision went back, and observe-mode evaluations answered before they ran. With no
    # room left, an evaluation lists its audit-only detectors as unchecked, and observe mode
    # answers only once its evaluation is done. An execution event that waits for its
    # deferred decision takes room too, and is never refused.
    max_background_checks: int = 200
    # Seconds `Engine.aclose` gives the background checks to finish before cancelling them.
    background_drain_s: float = 5.0


@dataclass(frozen=True)
class Verdict:
    rule_id: str
    action: RuleAction
    hard: bool
    reason: str
    span: FindingSpan | None = None


@dataclass(frozen=True)
class _Call:
    """One evaluation up to its decision algorithm: what it decides on, and with what."""

    ctx: GuardContext
    payload: Payload
    bundle: PolicyBundle
    # The runner's own detectors and those the documents of the bundle declare.
    detectors: tuple[AnyDetector, ...]
    seen_segments: frozenset[str]
    context_hash: str
    started: float


@dataclass(frozen=True)
class _Settlement:
    """How an evaluation ended, as its background check needs to know it."""

    # Whether the decision event was written: the findings follow it, or are not written.
    written: bool
    # Set when the decision withheld the argument previews of a tool call only because the
    # check was still running: the synchronous spans the previews are rendered from, together
    # with what the check finds.
    preview_spans: tuple[FindingSpan, ...] | None


class _BackgroundCheck:
    """The audit-only detectors of one evaluation, scanning while its decision goes back.

    An engine task waits for ``scan`` and then for ``decided``, the evaluation's word on how
    its decision ended, so that the findings are written after the decision event or not at
    all.
    """

    def __init__(self, scan: asyncio.Task[list[Findings]]) -> None:
        self.scan = scan
        self.decided: asyncio.Future[_Settlement] = asyncio.get_running_loop().create_future()

    async def findings(self) -> list[Findings] | None:
        """What the detectors found, or ``None`` when the scan was cancelled or broke down."""
        await asyncio.wait((self.scan,))
        if self.scan.cancelled() or self.scan.exception() is not None:
            return None
        return self.scan.result()

    def settle(self, written: bool, preview_spans: tuple[FindingSpan, ...] | None) -> None:
        """Tell the waiting task whether the decision event was written, and what it withheld."""
        if not self.decided.done():
            self.decided.set_result(_Settlement(written=written, preview_spans=preview_spans))


def _protected(ctx: GuardContext, effective: EffectClass) -> bool:
    return ctx.action.kind is ActionKind.TOOL_CALL and effective is not EffectClass.READ


def _span_verdicts(
    rules: Sequence[Rule], spans: Sequence[FindingSpan], by_id: Mapping[str, Segment]
) -> list[Verdict]:
    """A verdict for every rule and every finding span it selects, rule by rule."""
    verdicts: list[Verdict] = []
    for rule in rules:
        for span in spans:
            segment = by_id.get(span.segment_id)
            if segment is not None and rule.match.matches_span(span, segment):
                verdicts.append(Verdict(rule.id, rule.action, rule.hard, rule.reason, span))
    return verdicts


class Engine:
    """Evaluates actions against their policy and writes the decisions to the audit sink.

    Background checks run as tasks of the event loop the engine is used on: ``drain`` waits
    for them, and ``aclose`` finishes or cancels them before releasing the detectors.
    ``declared`` builds the detectors that policy documents declare; by default the engine
    makes its own.
    """

    def __init__(
        self,
        *,
        policy_source: PolicySource,
        runner: DetectorRunner,
        audit_sink: AuditSink,
        action_catalog: ActionCatalog | None = None,
        clock: Clock = utc_now,
        settings: EngineSettings | None = None,
        declared: DeclaredDetectors | None = None,
    ) -> None:
        self.policy_source = policy_source
        self.runner = runner
        self.audit_sink = audit_sink
        self.action_catalog = action_catalog
        self.declared = declared if declared is not None else DeclaredDetectors()
        self._clock = clock
        self._settings = settings if settings is not None else EngineSettings()
        # Background checks in flight, held here so that none is collected before it ends.
        self._background: set[asyncio.Task[None]] = set()
        # The deferred evaluations still running, by the decision id of their answer.
        self._deferred: dict[str, asyncio.Task[None]] = {}

    async def drain(self) -> None:
        """Wait until every background check has finished, including those started meanwhile."""
        while self._background:
            await asyncio.wait(tuple(self._background))

    async def aclose(self) -> None:
        """Finish the background checks, then release the detectors.

        The background checks get ``background_drain_s`` seconds to finish; those still running
        then are cancelled, and what they would have written is lost. The HTTP clients of the
        declared detectors are closed, and the runner's workers are released: the runner
        rebuilds its pool on the next scan.
        """
        if self._background:
            await asyncio.wait(tuple(self._background), timeout=self._settings.background_drain_s)
        remaining = tuple(self._background)
        for task in remaining:
            task.cancel()
        if remaining:
            await asyncio.gather(*remaining, return_exceptions=True)
        await self.declared.aclose()
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
        """Write the execution event of a decision.

        The decision event behind an ``observe_deferred`` answer is written by an evaluation
        that may still be running. The execution event then waits for that evaluation to end,
        as background work that ``drain`` and ``aclose`` cover, and a sink failure is only
        logged. Otherwise it is written at once, and a sink failure reaches the caller.
        """
        event = ExecutionEvent(
            decision_id=decision_id,
            outcome=outcome,
            error_class=error_class,
            duration_ms=duration_ms,
            occurred_at=self._clock(),
        )
        evaluation = self._deferred.get(decision_id)
        if evaluation is None or evaluation.done():
            await self.audit_sink.record(event)
            return
        # A host may update the record of a decision from its execution, so the execution
        # must not reach the sink before the decision does.
        self._spawn(self._record_after(evaluation, event))

    async def record_decision(self, decision: Decision, ctx: GuardContext) -> Decision:
        """Write the decision event and answer with the decision the host may act on.

        In enforce mode a critical event that could not be written turns the
        decision into a deny: a decision nobody can reconstruct later must not
        keep its permission.
        """
        answer, _ = await self._write_decision(decision, ctx)
        return answer

    async def _write_decision(self, decision: Decision, ctx: GuardContext) -> tuple[Decision, bool]:
        """The answer of ``record_decision``, and whether the decision event was written."""
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
                denied = decision.model_copy(
                    update={
                        "outcome": Outcome.DENY,
                        "explanation": decision.explanation.model_copy(
                            update={
                                "code": "audit_unavailable",
                                "reason": "the audit record could not be written",
                            }
                        ),
                        "masked_segments": {},
                        "masked_locations": (),
                    }
                )
                return denied, False
            return decision, False
        return decision, True

    async def evaluate(
        self,
        ctx: GuardContext,
        payload: Payload,
        *,
        seen_segments: Collection[str] | None = None,
        audit: bool = True,
        defer: bool = True,
    ) -> Decision:
        """Decide on the action of ``ctx`` and the ``payload`` it carries.

        Segments whose ids are in ``seen_segments`` were scanned by an earlier call and are
        not scanned again. With ``audit`` the decision is written to the audit sink before it
        is returned.

        With ``defer`` the engine leaves for later what the answer does not depend on. The
        detectors only audit rules can use scan in the background, and what they find is
        written after the decision; a decision that asks for an approval still waits for them,
        because its approval card shows the arguments. Any other decision on a tool call shows
        none of the argument values while they scan, and the ``FindingsEvent`` carries the
        previews once every detector has reported. In observe mode, which never blocks,
        the whole evaluation runs in the background: the answer is an ``observe_deferred``
        allow, and the decision written later carries its ``decision_id``. Late findings
        follow a decision event, so without ``audit``, as with ``defer`` false, every selected
        detector runs before the decision is returned.
        """
        started = time.perf_counter()
        context_hash = ctx.context_hash()
        try:
            bundle = await self.policy_source.resolve(ctx)
        except PolicyError as exc:
            logger.warning("policy could not be resolved: %s", exc)
            return await self._policy_error(
                ctx,
                f"the policy could not be resolved: {exc}",
                policy_version="unresolved",
                context_hash=context_hash,
                started=started,
                audit=audit,
            )
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
        try:
            declared = self.declared.detectors_for(ctx.tenant_id(), bundle.detectors)
        except (RuntimeError, ValueError) as exc:
            # A declared detector cannot be built, for example because an extra it needs is
            # not installed: the policy cannot be applied as written.
            logger.warning(
                "declared detectors of policy %s could not be built: %s", bundle.version, exc
            )
            return await self._policy_error(
                ctx,
                f"the policy's detectors could not be built: {exc}",
                policy_version=bundle.version,
                context_hash=context_hash,
                started=started,
                audit=audit,
            )
        call = _Call(
            ctx=ctx,
            payload=payload,
            bundle=bundle,
            detectors=self.runner.detectors + declared,
            # A deferred evaluation reads it later, when the host may have changed its own.
            seen_segments=frozenset(seen_segments or ()),
            context_hash=context_hash,
            started=started,
        )
        if bundle.mode is PolicyMode.OBSERVE and defer and audit:
            if self._has_capacity():
                decision_id = uuid.uuid4().hex
                evaluation = self._spawn(self._evaluate_deferred(call, decision_id))
                # Held while it runs, so that an execution event of the decision can wait for it.
                self._deferred[decision_id] = evaluation
                evaluation.add_done_callback(lambda _: self._deferred.pop(decision_id, None))
                return Decision(
                    decision_id=decision_id,
                    outcome=Outcome.ALLOW,
                    explanation=Explanation(
                        code="observe_deferred",
                        reason="evaluated after this answer, under the same decision id",
                    ),
                    policy_version=bundle.version,
                    mode=PolicyMode.OBSERVE,
                    context_hash=context_hash,
                    latency_ms=(time.perf_counter() - started) * 1000.0,
                )
            # No room is left for background work: the caller waits for the whole evaluation.
            defer = False
        return await self._evaluate(call, audit=audit, defer=defer)

    async def _evaluate(
        self,
        call: _Call,
        *,
        audit: bool,
        defer: bool,
        decision_id: str | None = None,
        in_background: bool = False,
    ) -> Decision:
        """The decision algorithm, on the policy and detectors ``call`` resolved.

        ``decision_id`` is that of the ``observe_deferred`` answer this decision stands behind.
        ``in_background`` is for an evaluation that no answer waits for: its scans take the
        runner's background lane. A detector only audit rules can use never fails the
        decision: when it breaks down it is listed as unchecked, as an optional detector is.

        The argument previews of a tool call show the values only once every selected
        detector has reported on the scanned segments. While a background check is still
        running, and when a detector failed or did not run, every value is blacked out whole.
        """
        ctx, payload, bundle = call.ctx, call.payload, call.bundle
        decision_id = decision_id or uuid.uuid4().hex
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
        candidates = payload.new_segments(call.seen_segments)
        to_scan = [s for s in candidates if s.size_bytes <= limit]
        uninspected = [s.label() for s in payload.uninspected_parts()] + [
            f"oversized:{s.label()}" for s in candidates if s.size_bytes > limit
        ]
        by_id = payload.by_id()

        selection = select_detectors(finding_rules, call.detectors)
        selected = selection.sync + selection.background
        # Late findings follow a decision event, and a caller that does not defer wants the
        # whole decision now: either way every selected detector runs before it goes back.
        background = selection.background if defer and audit else ()
        sync = selection.sync if background else selected
        # Only audit rules can use what these find, so a failure of one never counts against
        # the decision, even when the decision waits for it.
        audit_only = {id(detector) for detector in selection.background}

        check: _BackgroundCheck | None = None
        skipped: list[str] = []
        if background and to_scan:
            if self._has_capacity():
                # Started before the synchronous scan, so that a decision which waits for it
                # waits for the longer of the two scans and not for both in turn.
                check = self._start_check(
                    to_scan,
                    background,
                    decision_id=decision_id,
                    ctx=ctx,
                    payload=payload,
                    audit_rules=[r for r in finding_rules if r.action is RuleAction.AUDIT],
                    by_id=by_id,
                )
            else:
                skipped = [detector_id(detector) for detector in background]
        written = False
        late_preview_spans: tuple[FindingSpan, ...] | None = None
        # A started check is told how the evaluation ended, however it ended: its task waits
        # for that word.
        try:
            failed: list[str] = []
            unchecked: list[str] = []
            spans: list[FindingSpan] = []
            if sync and to_scan:
                found = await self.runner.run(to_scan, detectors=sync, background=in_background)
                for detector, findings in zip(sync, found, strict=True):
                    if not findings.failed:
                        spans.extend(findings.spans)
                    elif detector_required(detector) and id(detector) not in audit_only:
                        failed.append(findings.detector_id)
                    else:
                        unchecked.append(findings.detector_id)
            unchecked.extend(skipped)
            verdicts.extend(_span_verdicts(finding_rules, spans, by_id))

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
            masked_locations: tuple[Location, ...] = ()
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
                masked_locations = result.masked_locations
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
                masked_locations = ()
            if outcome is Outcome.DENY:
                # A payload the host may not send at all carries no usable masks.
                masked = {}
                masked_locations = ()
            hard = outcome is Outcome.DENY and any(
                v.action is RuleAction.DENY and v.hard for v in enforceable
            )

            preview_spans = list(spans)
            # Whether the background check has yet to report on the scanned segments.
            check_running = check is not None
            if (
                check is not None
                and outcome is Outcome.REQUIRE_APPROVAL
                and action.kind is ActionKind.TOOL_CALL
            ):
                # An approver reads the argument previews, so they wait for every detector.
                check_running = False
                late = await check.findings()
                if late is None:
                    unchecked.extend(detector_id(detector) for detector in background)
                else:
                    unchecked.extend(f.detector_id for f in late if f.failed)
                    preview_spans.extend(span for f in late if not f.failed for span in f.spans)
            critical = (
                would_block
                or outcome is not Outcome.ALLOW
                or bool(spans)
                or bool(failed)
                or bool(unchecked)
            )
            display_args: dict[str, str] = {}
            if action.kind is ActionKind.TOOL_CALL:
                # A detector that has not reported may have found something in any value, so
                # no value is shown until every one has.
                display_args = redact_display_args(
                    action.arguments,
                    preview_spans,
                    payload,
                    limit=self._settings.preview_chars,
                    max_entries=self._settings.max_preview_entries,
                    redact_all=check_running or bool(unchecked) or bool(failed),
                )
                if check_running and not (unchecked or failed) and action.arguments:
                    # The running check is all that holds the previews back, so its findings
                    # event carries them once it has reported.
                    late_preview_spans = tuple(spans)
            decision = Decision(
                decision_id=decision_id,
                outcome=outcome,
                hard=hard,
                explanation=Explanation(
                    code=code,
                    reason=reason,
                    rule_ids=tuple(dict.fromkeys(v.rule_id for v in verdicts)),
                    finding_classes=tuple(sorted({s.cls for s in spans})),
                    locations=self._locations(spans),
                ),
                detector_versions=self.runner.versions(selected),
                policy_version=bundle.version,
                descriptor_version=descriptor.version if descriptor else None,
                uninspected_parts=tuple(uninspected),
                latency_ms=(time.perf_counter() - call.started) * 1000.0,
                mode=bundle.mode,
                would_outcome=would_outcome,
                would_block=would_block,
                critical=critical,
                masked_segments=masked,
                masked_locations=masked_locations,
                display_args_redacted=display_args,
                action_digest=digest,
                context_hash=call.context_hash,
                unchecked_detectors=tuple(dict.fromkeys(unchecked)),
            )
            if not audit:
                return decision
            answer, written = await self._write_decision(decision, ctx)
            return answer
        finally:
            if check is not None:
                check.settle(written, late_preview_spans)

    async def _policy_error(
        self,
        ctx: GuardContext,
        reason: str,
        *,
        policy_version: str,
        context_hash: str,
        started: float,
        audit: bool,
    ) -> Decision:
        """A deny for a policy that cannot be applied, whatever mode it would have run in."""
        decision = Decision(
            outcome=Outcome.DENY,
            explanation=Explanation(code="policy_error", reason=reason),
            policy_version=policy_version,
            mode=PolicyMode.ENFORCE,
            critical=True,
            context_hash=context_hash,
            latency_ms=(time.perf_counter() - started) * 1000.0,
        )
        return await self.record_decision(decision, ctx) if audit else decision

    def _locations(self, spans: Sequence[FindingSpan]) -> tuple[Location, ...]:
        return tuple(Location.from_span(s) for s in spans[: self._settings.max_locations])

    def _has_capacity(self) -> bool:
        return len(self._background) < self._settings.max_background_checks

    def _spawn(self, work: Coroutine[Any, Any, None]) -> asyncio.Task[None]:
        """Run ``work`` as a background check, held and counted until it ends."""
        task = asyncio.create_task(work)
        self._background.add(task)
        task.add_done_callback(self._background.discard)
        return task

    def _start_check(
        self,
        segments: Sequence[Segment],
        detectors: Sequence[AnyDetector],
        *,
        decision_id: str,
        ctx: GuardContext,
        payload: Payload,
        audit_rules: Sequence[Rule],
        by_id: Mapping[str, Segment],
    ) -> _BackgroundCheck:
        """Scan ``segments`` with ``detectors`` in the background and record what they find."""
        scan = asyncio.create_task(self.runner.run(segments, detectors=detectors, background=True))
        check = _BackgroundCheck(scan)
        recording = self._record_late_findings(
            check,
            decision_id=decision_id,
            ctx=ctx,
            payload=payload,
            audit_rules=audit_rules,
            by_id=by_id,
        )
        recorder = self._spawn(recording)
        # A recorder cancelled before it ran never awaited its scan, which must not outlive it.
        recorder.add_done_callback(lambda _: scan.cancel())
        return check

    async def _record_late_findings(
        self,
        check: _BackgroundCheck,
        *,
        decision_id: str,
        ctx: GuardContext,
        payload: Payload,
        audit_rules: Sequence[Rule],
        by_id: Mapping[str, Segment],
    ) -> None:
        """Write what audit-only detectors found as a ``FindingsEvent`` after its decision.

        A decision that withheld the argument previews of a tool call only because this check
        was running gets them here, rendered from the arguments and payload it decided on,
        once every background detector reported. Nothing is written when there is nothing to
        add (no finding, no failure, no previews), nor when the evaluation ended without
        writing its decision. Nothing raised here reaches the host.
        """
        try:
            results = await check.scan
            failed = [f.detector_id for f in results if f.failed]
            spans = [span for f in results if not f.failed for span in f.spans]
            settled = await check.decided
            if not settled.written:
                return
            previews: dict[str, str] | None = None
            if settled.preview_spans is not None and not failed:
                previews = redact_display_args(
                    ctx.action.arguments,
                    [*settled.preview_spans, *spans],
                    payload,
                    limit=self._settings.preview_chars,
                    max_entries=self._settings.max_preview_entries,
                )
            if not (spans or failed or previews):
                return
            matched = _span_verdicts(audit_rules, spans, by_id)
            event = FindingsEvent(
                decision_id=decision_id,
                context=summarize_context(ctx),
                locations=self._locations(spans),
                finding_classes=tuple(sorted({s.cls for s in spans})),
                rule_ids=tuple(dict.fromkeys(v.rule_id for v in matched)),
                unchecked_detectors=tuple(dict.fromkeys(failed)),
                display_args_redacted=previews,
                occurred_at=self._clock(),
            )
            try:
                await self.audit_sink.record(event)
            except Exception as exc:  # the sink is the host's; the decision stands either way
                logger.warning(
                    "audit sink failed for the findings of decision %s: %s", decision_id, exc
                )
        except Exception:  # the boundary of a background task: log, never raise to the host
            logger.exception("background check of decision %s failed", decision_id)

    async def _record_after(self, evaluation: asyncio.Task[None], event: ExecutionEvent) -> None:
        """Write ``event`` once ``evaluation``, which writes the decision event, has ended."""
        await asyncio.wait((evaluation,))
        try:
            await self.audit_sink.record(event)
        except Exception as exc:  # the caller has moved on, so a sink failure is only logged
            logger.warning(
                "audit sink failed for the execution of decision %s: %s", event.decision_id, exc
            )

    async def _evaluate_deferred(self, call: _Call, decision_id: str) -> None:
        """Evaluate and record the decision behind an ``observe_deferred`` answer."""
        try:
            # Its latency is that of the evaluation, not of its wait for a turn to run.
            timed = replace(call, started=time.perf_counter())
            await self._evaluate(
                timed, audit=True, defer=False, decision_id=decision_id, in_background=True
            )
        except Exception:  # the boundary of a background task: log, never raise to the host
            logger.exception("deferred evaluation of decision %s failed", decision_id)

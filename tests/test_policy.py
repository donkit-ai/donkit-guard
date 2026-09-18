from __future__ import annotations

import pytest
from pydantic import ValidationError

from donkit_guard.context import (
    Action,
    ActionKind,
    Destination,
    DestinationLocality,
    DestinationTrust,
    EffectClass,
    EffectSource,
    GuardContext,
    PrincipalKind,
    RunRef,
)
from donkit_guard.decision import PolicyMode
from donkit_guard.errors import PolicyError
from donkit_guard.findings import ENFORCEABLE_CLASSES, SIGNAL_CLASSES, FindingClass, FindingSpan
from donkit_guard.payload import Segment, SegmentSource, SegmentTrust
from donkit_guard.policy import (
    Match,
    PolicyBundle,
    Rule,
    RuleAction,
    default_bundle,
    load_default_policy,
    load_policy,
)

MINIMAL = """
schema_version: 1
version: "t-1"
mode: enforce
layers:
  - name: tenant
    rules:
      - id: r1
        match: {action_kind: [tool_call], tool: ["delete_*"]}
        action: require_approval
"""


def test_load_policy_parses_yaml_and_iterates_rules() -> None:
    doc = load_policy(MINIMAL)
    assert doc.version == "t-1"
    assert doc.mode is PolicyMode.ENFORCE
    assert [(layer, rule.id) for layer, rule in doc.iter_rules()] == [("tenant", "r1")]


def test_default_policy_loads_and_has_expected_rules() -> None:
    doc = load_default_policy()
    ids = {rule.id for _, rule in doc.iter_rules()}
    assert {
        "secrets-mask",
        "secrets-audit",
        "pii-mask-untrusted-destination",
        "injection-audit",
        "tool-side-effect-approval",
    } <= ids
    rules = {rule.id: rule for _, rule in doc.iter_rules()}
    assert rules["pii-mask-untrusted-destination"].match.min_score == 0.5
    assert rules["pii-audit"].match.min_score is None
    assert rules["tool-side-effect-approval"].match.effect == (
        EffectClass.WRITE,
        EffectClass.SPEND,
        EffectClass.EGRESS,
    )
    bundle = default_bundle(PolicyMode.ENFORCE)
    assert bundle.mode is PolicyMode.ENFORCE
    assert bundle.approval_ttl_s == 300


@pytest.mark.parametrize(
    "text",
    [
        "version: x\nlayers: []\nschema_version: 2\n",
        "- not\n- a mapping\n",
        "version: x\nlayers:\n  - name: a\n    rules:\n      - {id: dup, action: allow}\n      - {id: dup, action: allow}\n",
        "version: x\nlayers:\n  - name: a\n    rules:\n      - {id: bad, action: deny, match: {finding_class: [injection]}}\n",
        "version: x\nlayers:\n  - name: a\n    rules:\n      - {id: bad, action: allow, hard: true}\n",
        "version: x\nlayers:\n  - name: a\n    rules:\n      - {id: bad, action: mask, match: {action_kind: [llm_request]}}\n",
        "version: x\nlayers:\n  - name: a\n    rules:\n      - {id: bad, action: deny, match: {effect: [unknown]}}\n",
        ": : not yaml : [",
    ],
)
def test_invalid_policies_raise_policy_error(text: str) -> None:
    with pytest.raises(PolicyError):
        load_policy(text)


def test_mask_rule_must_select_findings() -> None:
    with pytest.raises(ValidationError, match="mask requires a finding selector"):
        Rule(
            id="ctx-mask", action=RuleAction.MASK, match=Match(action_kind=(ActionKind.TOOL_CALL,))
        )
    scoped = Rule(
        id="pii-mask", action=RuleAction.MASK, match=Match(finding_class=(FindingClass.PII,))
    )
    assert scoped.match.needs_findings()


def test_unknown_effect_is_not_a_selector_value() -> None:
    with pytest.raises(ValidationError, match="gated as write"):
        Match(effect=(EffectClass.WRITE, EffectClass.UNKNOWN))


def test_only_enforceable_classes_may_be_enforced() -> None:
    assert frozenset(FindingClass) == ENFORCEABLE_CLASSES | SIGNAL_CLASSES
    assert not ENFORCEABLE_CLASSES & SIGNAL_CLASSES
    for signal in sorted(SIGNAL_CLASSES):
        assert Rule(id="a", action=RuleAction.AUDIT, match=Match(finding_class=(signal,)))
        with pytest.raises(ValidationError, match="may only be audited"):
            Rule(id="b", action=RuleAction.DENY, match=Match(finding_class=(signal,)))
    for enforceable in sorted(ENFORCEABLE_CLASSES):
        assert Rule(id="c", action=RuleAction.DENY, match=Match(finding_class=(enforceable,)))


def test_match_context_selectors(tool_context: GuardContext) -> None:
    effective = tool_context.action.effective_effect()
    assert Match(action_kind=(ActionKind.TOOL_CALL,), tool=("delete_*",)).matches_context(
        tool_context, effective
    )
    assert not Match(action_kind=(ActionKind.LLM_REQUEST,)).matches_context(tool_context, effective)
    assert not Match(tool=("write_*",)).matches_context(tool_context, effective)
    assert Match(effect=(EffectClass.WRITE,)).matches_context(tool_context, effective)
    assert not Match(effect=(EffectClass.READ,)).matches_context(tool_context, effective)
    assert Match(effect_source=(EffectSource.HOST,)).matches_context(tool_context, effective)
    assert not Match(effect_source=(EffectSource.TOOL_SERVER,)).matches_context(
        tool_context, effective
    )
    assert Match(attributes={"origin": "chat"}).matches_context(tool_context, effective)
    assert not Match(attributes={"origin": "voice"}).matches_context(tool_context, effective)
    assert not Match(principal_absent=True).matches_context(tool_context, effective)
    assert Match(principal_kind=(PrincipalKind.USER,)).matches_context(tool_context, effective)
    assert not Match(principal_kind=(PrincipalKind.SERVICE,)).matches_context(
        tool_context, effective
    )
    assert Match(tenant=("tenant-1",)).matches_context(tool_context, effective)
    assert not Match(tenant=("tenant-2",)).matches_context(tool_context, effective)
    assert not Match(destination_locality=(DestinationLocality.PLATFORM,)).matches_context(
        tool_context, effective
    )


def test_match_run_and_destination_selectors(llm_context: GuardContext) -> None:
    effective = llm_context.action.effective_effect()
    assert Match(destination_locality=(DestinationLocality.PLATFORM,)).matches_context(
        llm_context, effective
    )
    assert not Match(destination_locality=(DestinationLocality.ONPREM,)).matches_context(
        llm_context, effective
    )
    assert not Match(untrusted_content_seen=True).matches_context(llm_context, effective)
    tainted = llm_context.model_copy(
        update={"run": llm_context.run.model_copy(update={"untrusted_content_seen": True})}
    )
    assert Match(untrusted_content_seen=True).matches_context(tainted, effective)


def test_match_selectors_on_a_context_without_principal_or_tenant() -> None:
    anonymous = GuardContext(run=RunRef(id="r"), action=Action(kind=ActionKind.LLM_REQUEST))
    assert Match(principal_absent=True).matches_context(anonymous, EffectClass.READ)
    assert not Match(principal_kind=(PrincipalKind.USER,)).matches_context(
        anonymous, EffectClass.READ
    )
    assert not Match(tenant=("tenant-1",)).matches_context(anonymous, EffectClass.READ)
    assert not Match(destination_trust=(DestinationTrust.TENANT,)).matches_context(
        anonymous, EffectClass.READ
    )
    assert not Match(tool=("delete_*",)).matches_context(anonymous, EffectClass.READ)


def test_match_destination_and_findings() -> None:
    ctx = GuardContext(
        run=RunRef(id="r"),
        action=Action(
            kind=ActionKind.LLM_REQUEST,
            destination=Destination(provider="p", model="m", trust=DestinationTrust.TENANT),
        ),
    )
    match = Match(
        destination_trust=(DestinationTrust.TENANT, DestinationTrust.UNKNOWN),
        finding_class=(FindingClass.PII,),
        min_score=0.6,
    )
    assert match.needs_findings()
    assert match.matches_context(ctx, EffectClass.READ)
    segment = Segment.of_text("x", source=SegmentSource.USER, trust=SegmentTrust.TRUSTED)
    high = FindingSpan(
        segment_id=segment.id,
        start=0,
        end=1,
        cls=FindingClass.PII,
        subtype="PERSON",
        score=0.9,
        detector="pii-ner",
    )
    low = high.model_copy(update={"score": 0.3})
    secret = high.model_copy(update={"cls": FindingClass.SECRET, "subtype": "aws"})
    assert match.matches_span(high, segment)
    assert not match.matches_span(low, segment)
    assert not match.matches_span(secret, segment)
    untrusted_only = Match(segment_trust=(SegmentTrust.UNTRUSTED,))
    assert not untrusted_only.matches_span(high, segment)


def test_match_finding_subtype_is_a_glob() -> None:
    segment = Segment.of_text("x", source=SegmentSource.USER, trust=SegmentTrust.TRUSTED)
    span = FindingSpan(
        segment_id=segment.id,
        start=0,
        end=1,
        cls=FindingClass.SECRET,
        subtype="aws-access-token",
        score=1.0,
        detector="secrets",
    )
    assert Match(finding_subtype=("aws-*",)).matches_span(span, segment)
    assert Match(finding_subtype=("gcp-api-key", "aws-access-token")).matches_span(span, segment)
    assert not Match(finding_subtype=("gcp-*",)).matches_span(span, segment)


def test_bundle_compose_takes_strictest_limits() -> None:
    lenient = load_policy(
        "version: a\nunsupported_content: uninspected\napproval_ttl_s: 600\n"
        "segment_limit_bytes: 262144\nlayers: []\n"
    )
    strict = load_policy(
        "version: b\nmode: enforce\nunsupported_content: deny\napproval_ttl_s: 120\n"
        "segment_limit_bytes: 65536\nlayers: []\n"
    )
    bundle = PolicyBundle.compose([lenient, strict])
    assert bundle.version == "a+b"
    assert bundle.mode is PolicyMode.ENFORCE
    assert bundle.unsupported_content == "deny"
    assert bundle.approval_ttl_s == 120
    assert bundle.segment_limit_bytes == 65536
    assert PolicyBundle.compose([lenient]).unsupported_content == "uninspected"
    with pytest.raises(PolicyError):
        PolicyBundle.compose([])


def test_bundle_iterates_the_rules_of_every_document() -> None:
    platform = load_default_policy()
    tenant = load_policy(
        "version: t\nlayers:\n  - name: tenant\n    rules:\n      - {id: t1, action: allow}\n"
    )
    bundle = PolicyBundle.compose([platform, tenant])
    ids = [rule.id for _, rule in bundle.iter_rules()]
    assert ids[-1] == "t1"
    assert "secrets-mask" in ids


def test_compose_takes_the_strictest_mode_in_either_order() -> None:
    enforcing = load_policy("version: platform\nmode: enforce\nlayers: []\n")
    observing = load_policy("version: tenant\nmode: observe\nlayers: []\n")
    disabled = load_policy('version: dev\nmode: "off"\nlayers: []\n')
    assert PolicyBundle.compose([enforcing, observing]).mode is PolicyMode.ENFORCE
    assert PolicyBundle.compose([observing, enforcing]).mode is PolicyMode.ENFORCE
    assert PolicyBundle.compose([disabled, observing]).mode is PolicyMode.OBSERVE
    assert PolicyBundle.compose([disabled]).mode is PolicyMode.OFF


def test_unquoted_off_is_read_as_the_off_mode() -> None:
    assert load_policy("version: dev\nmode: off\nlayers: []\n").mode is PolicyMode.OFF


def test_compose_honours_an_explicit_mode() -> None:
    enforcing = load_policy("version: platform\nmode: enforce\nlayers: []\n")
    observing = load_policy("version: tenant\nmode: observe\nlayers: []\n")
    bundle = PolicyBundle.compose([enforcing, observing], mode=PolicyMode.OBSERVE)
    assert bundle.mode is PolicyMode.OBSERVE


def test_compose_rejects_a_rule_id_shared_by_two_documents() -> None:
    rules = (
        "version: {v}\nlayers:\n  - name: l\n    rules:\n      - {{id: shared, action: allow}}\n"
    )
    first = load_policy(rules.format(v="a"))
    second = load_policy(rules.format(v="b"))
    with pytest.raises(PolicyError, match="duplicate rule id"):
        PolicyBundle.compose([first, second])
    assert PolicyBundle.compose([first]).version == "a"


def test_rule_defaults() -> None:
    rule = Rule(id="x", action=RuleAction.ALLOW)
    assert rule.match.needs_findings() is False
    assert rule.hard is False

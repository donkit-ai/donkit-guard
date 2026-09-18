from __future__ import annotations

import base64
import json
import re
import tomllib
from pathlib import Path

import pytest

from donkit_guard.detectors.secrets import SecretsDetector, decode_layers, suppress
from donkit_guard.detectors.secrets_rules import (
    GITLEAKS_OVERRIDES,
    RULESET_HASH,
    _compile_allowlists,
    _data_text,
    _go_to_py,
    load_global_allowlists,
    load_rules,
    shannon_entropy,
)
from donkit_guard.payload import Payload, Segment, SegmentSource, SegmentTrust

CORPUS = Path(__file__).parent / "data" / "secrets_corpus.json"
# A synthetic AWS key id: the documentation placeholder AKIAIOSFODNN7EXAMPLE is
# allowlisted by the vendored rule set, exactly as it is by gitleaks itself.
AWS_KEY = "AKIAIOSFODNN7Q4ZKQ7M"
GITHUB_PAT = "ghp_9fK2mQ7xR4tL1nB6vC3zD8sH5jW0pY2aE7uT"


@pytest.fixture(scope="module")
def detector() -> SecretsDetector:
    return SecretsDetector()


def _segment(text: str, source: SegmentSource = SegmentSource.USER) -> Segment:
    return Segment.of_text(text, source=source, trust=SegmentTrust.UNTRUSTED)


def test_go_to_py_translates_flags_and_anchors() -> None:
    assert _go_to_py(r"(?i)abc") == ("abc", re.IGNORECASE)
    assert _go_to_py(r"(?:x(?i)y|z)\z")[0] == r"(?:x(?i:y)|(?i:z))\Z"
    assert _go_to_py(r"\(?(?i)v")[0] == r"\((?i:v)" or _go_to_py(r"\(?(?i)v")[0].endswith("(?i:v)")
    assert re.compile(_go_to_py(r"(?:x(?i)y|z)\z")[0])


def test_rules_load_and_hash_is_stable() -> None:
    rules = load_rules()
    assert len(rules) >= 200
    assert any(r.id == "aws-access-token" for r in rules)
    assert any(r.id == "telegram-bot-token" for r in rules)
    assert len(RULESET_HASH) == 12
    assert SecretsDetector.pattern_set_hash == RULESET_HASH
    assert shannon_entropy("aaaa") == 0.0 and shannon_entropy("abcd") == 2.0


def test_every_vendored_rule_is_loaded_or_declared() -> None:
    """A gitleaks bump cannot drop a rule without the override table saying so."""
    vendored = {str(raw["id"]) for raw in tomllib.loads(_data_text("gitleaks.toml"))["rules"]}
    loaded = {rule.id for rule in load_rules()}
    declared = {rule_id for rule_id, value in GITLEAKS_OVERRIDES.items() if value is None}
    assert vendored - loaded == declared
    assert "pkcs12-file" in declared


def test_rule_allowlists_are_read_in_both_spellings() -> None:
    by_id = {rule.id: rule for rule in load_rules()}
    # The vendored file writes every rule allowlist as a list of tables.
    assert by_id["aws-access-token"].allowlists
    assert by_id["curl-auth-user"].allowlists
    assert load_global_allowlists()

    singular = _compile_allowlists({"allowlist": {"regexes": ["^sample$"]}})
    assert len(singular) == 1 and singular[0].allows("sample", "k=sample", "line")

    both = _compile_allowlists(
        {"allowlist": {"stopwords": ["Placeholder"]}, "allowlists": [{"regexes": ["^x+$"]}]}
    )
    assert len(both) == 2
    assert both[0].allows("a-placeholder-value", "", "")


def test_allowlist_targets_and_conditions() -> None:
    match_target = _compile_allowlists(
        {"allowlists": [{"regexTarget": "match", "regexes": ["api_version"]}]}
    )[0]
    assert match_target.allows("1234", "api_version = 1234", "x")
    assert not match_target.allows("api_version", "key = 1234", "x")

    line_target = _compile_allowlists(
        {"allowlists": [{"regexTarget": "line", "regexes": ["--mount=type=secret,"]}]}
    )[0]
    assert line_target.allows("abc", "abc", "RUN --mount=type=secret,id=token make")
    assert not line_target.allows("abc", "abc", "RUN make")

    conjunction = _compile_allowlists(
        {"allowlists": [{"condition": "AND", "regexes": ["^a"], "stopwords": ["bb"]}]}
    )[0]
    assert conjunction.allows("abb", "abb", "")
    assert not conjunction.allows("acc", "acc", "")


def test_allowlist_entries_without_content_criteria_are_dropped() -> None:
    # Repository-scanning exceptions: a payload has neither a path nor a commit.
    assert _compile_allowlists({"allowlists": [{"paths": ["README\\.md$"]}]}) == ()
    assert (
        _compile_allowlists(
            {"allowlists": [{"condition": "AND", "paths": ["\\.bb$"], "regexes": ["LICENSE"]}]}
        )
        == ()
    )
    assert _compile_allowlists({"allowlist": "not-a-table"}) == ()


@pytest.mark.parametrize(
    "text",
    [
        "Use the sample key AKIAIOSFODNN7EXAMPLE from the AWS docs",
        "curl -u user:password https://api.example.com/v1/items",
        "curl -u myuser:changeit https://api.example.com",
        "AIzaSyabcdefghijklmnopqrstuvwxyz1234567",
    ],
)
def test_vendored_allowlists_suppress_documentation_placeholders(
    detector: SecretsDetector, text: str
) -> None:
    assert detector.detect([_segment(text)]).spans == ()


def test_detects_aws_key_and_reports_offsets(detector: SecretsDetector) -> None:
    text = f"here is my key {AWS_KEY} and more"
    seg = _segment(text)
    findings = detector.detect([seg])
    assert not findings.failed
    assert findings.pattern_set_hash == RULESET_HASH
    aws = [s for s in findings.spans if s.subtype.startswith("aws")]
    assert aws, findings.spans
    assert text[aws[0].start : aws[0].end].startswith("AKIA")


def test_pragma_does_not_suppress(detector: SecretsDetector) -> None:
    text = f"token = '{GITHUB_PAT}'  # pragma: allowlist secret"
    assert detector.detect([_segment(text)]).spans


def test_hashlike_fields_and_media_are_skipped(detector: SecretsDetector) -> None:
    payload = Payload.from_json(
        {
            "sha256": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
            "img": "data:image/png;base64," + "A" * 5000,
        },
        source=SegmentSource.TOOL_RESULT,
        trust=SegmentTrust.UNTRUSTED,
    )
    assert detector.detect(list(payload.segments)).spans == ()
    assert suppress("x data:image/png;base64,QUJD y") == "x " + " " * 26 + " y"


def test_decoded_layer_is_scanned(detector: SecretsDetector) -> None:
    encoded = base64.b64encode(f"aws key {AWS_KEY}".encode()).decode()
    layers = decode_layers(f"payload: {encoded}")
    assert any(kind == "base64" and AWS_KEY in text for kind, text in layers)
    findings = detector.detect([_segment(f"payload: {encoded}")])
    assert any(s.subtype.endswith(":base64") for s in findings.spans)


def test_specific_rule_wins_over_generic(detector: SecretsDetector) -> None:
    text = f'api_key = "{AWS_KEY}"'
    subtypes = {s.subtype for s in detector.detect([_segment(text)]).spans}
    assert "aws-access-token" in subtypes
    assert "generic-api-key" not in subtypes


def test_bare_high_entropy_token_is_low_confidence(detector: SecretsDetector) -> None:
    spans = detector.detect([_segment("yfvOBpfpLXYBwc6BSnT4/un53cunlye8ubXXAQstQLYZ")]).spans
    assert [s.subtype for s in spans] == ["low-confidence-entropy"]
    assert spans[0].score == 0.3


def test_corpus_detection_and_false_positive_rates(detector: SecretsDetector) -> None:
    corpus = json.loads(CORPUS.read_text("utf-8"))
    secrets = [item for item in corpus if item["kind"] == "secret"]
    benign = [item for item in corpus if item["kind"] == "benign"]

    def high(text: str) -> bool:
        return any(s.score >= 0.5 for s in detector.detect([_segment(text)]).spans)

    def any_span(text: str) -> bool:
        return bool(detector.detect([_segment(text)]).spans)

    detected_high = sum(1 for item in secrets if high(item["text"]))
    detected_any = sum(1 for item in secrets if any_span(item["text"]))
    flagged_benign_high = sum(1 for item in benign if high(item["text"]))
    assert detected_high / len(secrets) >= 0.94, (
        f"high-confidence detection {detected_high}/{len(secrets)}"
    )
    assert detected_any / len(secrets) >= 0.99, (
        f"detection incl. low confidence {detected_any}/{len(secrets)}"
    )
    assert flagged_benign_high / len(benign) <= 0.05, (
        f"false positives {flagged_benign_high}/{len(benign)}"
    )

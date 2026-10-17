from __future__ import annotations

from typing import Any

import pytest

from donkit_guard.declared.pattern import PatternDetector
from donkit_guard.declared.regex import RE2_MISSING, re2_available
from donkit_guard.declared.spec import MAX_FINDINGS_PER_SEGMENT, PatternDetectorSpec
from donkit_guard.findings import FindingClass
from donkit_guard.payload import Segment, SegmentSource, SegmentTrust

# RE2 is the optional "re2" extra: CI installs every extra, a bare install skips these cases.
pytestmark = pytest.mark.skipif(not re2_available(), reason=RE2_MISSING)

NAME = "declared:client-number"
SUBTYPE = "CLIENT_NUMBER"
NUMBER = "ДГ-123456"
CONTRACT: dict[str, Any] = {
    "patterns": [r"ДГ-\d{6}"],
    "context": ["договор*", "contract"],
    "score": 0.9,
    "score_without_context": 0.3,
}
CARD: dict[str, Any] = {"patterns": [r"\d{4}(?: \d{4}){3}"], "checksum": "luhn"}
IBAN: dict[str, Any] = {
    "patterns": [r"[A-Z]{2}\d{2}(?: ?[A-Z0-9]{4})+(?: ?[A-Z0-9]{1,3})?"],
    "checksum": "iban",
}


def _spec(fields: dict[str, Any]) -> PatternDetectorSpec:
    return PatternDetectorSpec.model_validate(
        {
            "kind": "pattern",
            "id": "client-number",
            "title": "Client number",
            "class": "corporate",
            "subtype": SUBTYPE,
            **fields,
        }
    )


@pytest.mark.parametrize(
    ("fields", "path", "text", "expected"),
    [
        # A context word near the match confirms it; without one the match scores lower.
        (CONTRACT, "", f"по договору {NUMBER} из архива", [(NUMBER, 0.9)]),
        (CONTRACT, "", f"номер {NUMBER} в списке", [(NUMBER, 0.3)]),
        # An exclude word near the match drops it, even next to a context word.
        ({**CONTRACT, "exclude": ["образец"]}, "", f"договор, образец: {NUMBER}", []),
        # A failed checksum drops a match: digits for Luhn, the text as written for an IBAN.
        (
            CARD,
            "",
            "4111 1111 1111 1111 / 4111 1111 1111 1112",
            [("4111 1111 1111 1111", 0.8)],
        ),
        (
            IBAN,
            "",
            "GB82 WEST 1234 5698 7654 32 / GB83 WEST 1234 5698 7654 32",
            [("GB82 WEST 1234 5698 7654 32", 0.8)],
        ),
        # Offsets count code points: an emoji before the match moves it by one, not by four.
        (CONTRACT, "", f"🙂 {NUMBER}", [(NUMBER, 0.3)]),
        # A value under a listed key is reported whole, without a context word, and is not
        # searched; the key of an array element is its array's, and globs ignore case.
        (
            {**CONTRACT, "json_keys": ["contract_id"]},
            "/contract_id",
            f"{NUMBER} (копия)",
            [(f"{NUMBER} (копия)", 0.9)],
        ),
        (
            {**CONTRACT, "json_keys": ["Contract*"]},
            "/contracts/0",
            "A-17/2024",
            [("A-17/2024", 0.9)],
        ),
        # A message sits under no key, so even a bare `*` leaves it to the patterns.
        ({**CONTRACT, "json_keys": ["*"]}, "", f"номер {NUMBER}", [(NUMBER, 0.3)]),
        # Empty matches name no text, and one segment yields a bounded number of findings.
        ({"patterns": [r"(?:ДГ-\d{6})?"]}, "", f"x {NUMBER} y", [(NUMBER, 0.8)]),
        (
            CONTRACT,
            "",
            " ".join([NUMBER] * (MAX_FINDINGS_PER_SEGMENT + 5)),
            [(NUMBER, 0.3)] * MAX_FINDINGS_PER_SEGMENT,
        ),
    ],
)
def test_pattern_detector_cases(
    fields: dict[str, Any], path: str, text: str, expected: list[tuple[str, float]]
) -> None:
    source = SegmentSource.TOOL_ARGS if path else SegmentSource.USER
    segment = Segment.of_text(text, source=source, trust=SegmentTrust.TRUSTED, path=path)
    findings = PatternDetector(_spec(fields)).detect([segment])
    # Slicing the text with the reported offsets gives back what was found.
    assert [(text[s.start : s.end], s.score) for s in findings.spans] == expected
    attribution = {(s.segment_id, s.path, s.cls, s.subtype, s.detector) for s in findings.spans}
    assert attribution <= {(segment.id, path, FindingClass.CORPORATE, SUBTYPE, NAME)}

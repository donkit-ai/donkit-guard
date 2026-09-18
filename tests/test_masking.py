from __future__ import annotations

import json

from donkit_guard.decision import Location
from donkit_guard.findings import FindingClass, FindingSpan
from donkit_guard.masking import mask, merge_ranges, placeholder
from donkit_guard.payload import Payload, SegmentSource, SegmentTrust, set_json_pointer


def _span(
    segment_id: str, start: int, end: int, cls: FindingClass, subtype: str, path: str = ""
) -> FindingSpan:
    return FindingSpan(
        segment_id=segment_id,
        path=path,
        start=start,
        end=end,
        cls=cls,
        subtype=subtype,
        score=1.0,
        detector="t",
    )


def test_secret_placeholder_is_by_class_and_pii_by_value_hash() -> None:
    payload = Payload.of_text(
        "key AKIA1234567890ABCDEF and Ivan",
        source=SegmentSource.USER,
        trust=SegmentTrust.TRUSTED,
    )
    seg = payload.segments[0]
    secret = _span(seg.id, 4, 24, FindingClass.SECRET, "aws-access-token")
    person = _span(seg.id, 29, 33, FindingClass.PII, "PERSON")
    result = mask(payload, [secret, person])
    assert result.ok
    text = result.masked[seg.id]
    assert text.startswith("key [REDACTED:aws-access-token] and <PERSON_")
    assert placeholder(person, "Ivan") == placeholder(person, "Ivan")
    assert placeholder(person, "Ivan") != placeholder(person, "Anna")


def test_overlapping_spans_merge() -> None:
    payload = Payload.of_text("abcdefghij", source=SegmentSource.USER, trust=SegmentTrust.TRUSTED)
    seg = payload.segments[0]
    spans = [
        _span(seg.id, 2, 6, FindingClass.PII, "A"),
        _span(seg.id, 4, 8, FindingClass.PII, "B"),
        _span(seg.id, 9, 10, FindingClass.PII, "C"),
    ]
    merged = merge_ranges(spans)
    assert [(s, e) for s, e, _ in merged] == [(2, 8), (9, 10)]
    text = mask(payload, spans).masked[seg.id]
    assert text.startswith("ab<A_") and text.count("<") == 2


def test_tool_args_are_impossible_unless_maskable() -> None:
    args = {"path": "/tmp/a", "note": "call 89123456789"}
    payload = Payload.from_json(args, source=SegmentSource.TOOL_ARGS, trust=SegmentTrust.TRUSTED)
    note = next(s for s in payload.segments if s.path == "/note")
    span = _span(note.id, 5, 16, FindingClass.PII, "PHONE", path="/note")
    blocked = mask(payload, [span])
    assert not blocked.ok and blocked.impossible[0].path == "/note"
    allowed = mask(payload, [span], maskable_arg_paths={"/note"})
    assert allowed.ok
    rebuilt = set_json_pointer(args, "/note", allowed.masked[note.id])
    assert json.loads(json.dumps(rebuilt))["note"].startswith("call <PHONE_")


def test_identical_arg_values_are_masked_per_path() -> None:
    args = {"id": "call 89123456789", "note": "call 89123456789"}
    payload = Payload.from_json(args, source=SegmentSource.TOOL_ARGS, trust=SegmentTrust.TRUSTED)
    identifier = next(s for s in payload.segments if s.path == "/id")
    note = next(s for s in payload.segments if s.path == "/note")
    on_identifier = _span(identifier.id, 5, 16, FindingClass.PII, "PHONE", path="/id")
    on_note = _span(note.id, 5, 16, FindingClass.PII, "PHONE", path="/note")

    blocked = mask(payload, [on_identifier], maskable_arg_paths={"/note"})
    assert not blocked.ok
    assert [location.path for location in blocked.impossible] == ["/id"]

    allowed = mask(payload, [on_note], maskable_arg_paths={"/note"})
    assert allowed.ok
    assert set(allowed.masked) == {note.id}
    rewritten = payload.with_masks(allowed.masked).by_id()
    assert rewritten[identifier.id].text == "call 89123456789"
    assert rewritten[note.id].text.startswith("call <PHONE_")


def test_masked_locations_carry_the_span_pointer() -> None:
    payload = Payload.of_text("Ivan", source=SegmentSource.USER, trust=SegmentTrust.TRUSTED)
    seg = payload.segments[0]
    span = _span(seg.id, 0, 4, FindingClass.PII, "PERSON")
    result = mask(payload, [span])
    assert result.masked_locations == (Location.from_span(span),)


def test_number_leaf_becomes_string_placeholder_and_json_stays_valid() -> None:
    args = {"phone": 89123456789}
    payload = Payload.from_json(
        args, source=SegmentSource.TOOL_RESULT, trust=SegmentTrust.UNTRUSTED
    )
    seg = payload.segments[0]
    result = mask(payload, [_span(seg.id, 0, 11, FindingClass.PII, "PHONE", path="/phone")])
    rebuilt = set_json_pointer(args, "/phone", result.masked[seg.id])
    assert isinstance(rebuilt["phone"], str) and rebuilt["phone"].startswith("<PHONE_")


def test_unknown_or_uninspected_segments_are_impossible() -> None:
    payload = Payload.of_text("x", source=SegmentSource.USER, trust=SegmentTrust.TRUSTED)
    result = mask(payload, [_span("missing", 0, 1, FindingClass.SECRET, "s")])
    assert not result.ok
    assert mask(payload, []).ok

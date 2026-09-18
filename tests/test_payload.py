from __future__ import annotations

from donkit_guard.payload import (
    Payload,
    Segment,
    SegmentSource,
    SegmentTrust,
    iter_json_leaves,
    segment_id,
    set_json_pointer,
)


def test_segment_id_covers_source_path_and_text() -> None:
    a = Segment.of_text("hello", source=SegmentSource.USER, trust=SegmentTrust.TRUSTED)
    b = Segment.of_text("hello", source=SegmentSource.USER, trust=SegmentTrust.TRUSTED, path="/x")
    c = Segment.of_text("hello", source=SegmentSource.TOOL_RESULT, trust=SegmentTrust.UNTRUSTED)
    assert a.id == segment_id(SegmentSource.USER, "", "hello")
    assert a.id != b.id
    assert a.id != c.id


def test_same_text_at_the_same_path_keeps_one_id() -> None:
    first = Segment.of_text(
        "hello", source=SegmentSource.USER, trust=SegmentTrust.TRUSTED, path="/x"
    )
    later_turn = Segment.of_text(
        "hello", source=SegmentSource.USER, trust=SegmentTrust.UNTRUSTED, path="/x"
    )
    assert first.id == later_turn.id


def test_same_text_at_two_paths_stays_two_segments() -> None:
    payload = Payload.from_json(
        {"a": "sk-live-SECRET", "b": "sk-live-SECRET"},
        source=SegmentSource.TOOL_ARGS,
        trust=SegmentTrust.TRUSTED,
    )
    assert len(payload.segments) == 2
    assert len(payload.by_id()) == 2
    assert {s.path for s in payload.by_id().values()} == {"/a", "/b"}


def test_uninspected_parts_at_two_paths_have_distinct_ids() -> None:
    first = Segment.uninspected_part(
        source=SegmentSource.USER, path="/content/0", kind="image", size_bytes=1024
    )
    second = Segment.uninspected_part(
        source=SegmentSource.USER, path="/content/1", kind="image", size_bytes=1024
    )
    assert first.id != second.id


def test_from_json_creates_leaf_segments_and_marks_numbers(json_payload: Payload) -> None:
    paths = {s.path: s for s in json_payload.segments}
    assert set(paths) == {"/path", "/content", "/phone"}
    assert paths["/phone"].leaf_type == "number"
    assert paths["/phone"].text == "89123456789"
    assert paths["/path"].kind == "json_leaf"


def test_from_json_skips_short_numbers_and_booleans() -> None:
    payload = Payload.from_json(
        {"count": 42, "flag": True, "nested": {"list": ["a", 1234567]}},
        source=SegmentSource.TOOL_RESULT,
        trust=SegmentTrust.UNTRUSTED,
    )
    assert [s.path for s in payload.segments] == ["/nested/list/0", "/nested/list/1"]


def test_new_segments_and_masks(json_payload: Payload) -> None:
    first = json_payload.segments[0]
    remaining = json_payload.new_segments({first.id})
    assert first.id not in {s.id for s in remaining}
    masked = json_payload.with_masks({first.id: "<MASKED>"})
    assert masked.by_id()[first.id].text == "<MASKED>"
    assert masked.by_id()[first.id].masked is True
    assert json_payload.by_id()[first.id].masked is False


def test_uninspected_part_has_no_text_and_is_listed() -> None:
    part = Segment.uninspected_part(
        source=SegmentSource.USER, path="/content/1", kind="image", size_bytes=1024
    )
    payload = Payload(segments=(part,))
    assert payload.inspectable() == []
    assert payload.uninspected_parts() == [part]
    assert payload.total_bytes() == 1024


def test_hashlike_detects_digest_fields() -> None:
    digest = Segment.of_text(
        "abc",
        source=SegmentSource.TOOL_RESULT,
        trust=SegmentTrust.UNTRUSTED,
        path="/meta/sha256",
    )
    plain = Segment.of_text(
        "abc",
        source=SegmentSource.TOOL_RESULT,
        trust=SegmentTrust.UNTRUSTED,
        path="/meta/name",
    )
    whole = Segment.of_text("abc", source=SegmentSource.USER, trust=SegmentTrust.TRUSTED)
    assert digest.hashlike() is True
    assert plain.hashlike() is False
    assert whole.hashlike() is False


def test_json_pointer_roundtrip() -> None:
    value = {"a": [1, {"b~c": "x/y"}]}
    leaves = dict(iter_json_leaves(value))
    assert leaves == {"/a/0": 1, "/a/1/b~0c": "x/y"}
    updated = set_json_pointer(value, "/a/1/b~0c", "<M>")
    assert updated == {"a": [1, {"b~c": "<M>"}]}
    assert set_json_pointer(value, "/a/0", "<M>") == {"a": ["<M>", {"b~c": "x/y"}]}
    assert set_json_pointer(value, "", "<M>") == "<M>"
    assert value == {"a": [1, {"b~c": "x/y"}]}


def test_label_names_the_source_and_the_leaf(json_payload: Payload) -> None:
    leaf = next(s for s in json_payload.segments if s.path == "/content")
    whole = Segment.of_text("hi", source=SegmentSource.USER, trust=SegmentTrust.TRUSTED)
    assert leaf.label() == "tool_args/content"
    assert whole.label() == "user"


def test_with_masks_returns_the_same_payload_when_nothing_is_masked(json_payload: Payload) -> None:
    assert json_payload.with_masks({}) is json_payload

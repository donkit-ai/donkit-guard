from __future__ import annotations

from donkit_guard.actions import (
    ActionDescriptor,
    action_digest,
    canonical_json,
    default_descriptor,
    select_pointers,
)
from donkit_guard.context import EffectClass, EffectSource


def test_canonical_json_normalizes_keys_whitespace_and_numbers() -> None:
    a = canonical_json({"b": "x  y", "a": 1.0, "n": [{"z": "é"}]})
    b = canonical_json({"a": 1, "n": [{"z": "é"}], "b": "x y"})
    assert a == b


def test_digest_depends_only_on_essential_args() -> None:
    descriptor = ActionDescriptor(
        tool="send_email", effect=EffectClass.EGRESS, essential_args=("/to", "/body")
    )
    base = action_digest(descriptor, {"to": "a@x", "body": "hi", "timeout": 5})
    same = action_digest(descriptor, {"to": "a@x", "body": "hi", "timeout": 99})
    changed = action_digest(descriptor, {"to": "b@x", "body": "hi", "timeout": 5})
    assert base == same
    assert base != changed


def test_default_descriptor_treats_everything_as_essential() -> None:
    descriptor = default_descriptor("mystery_tool")
    assert descriptor.effect is EffectClass.UNKNOWN
    assert descriptor.effect_source is EffectSource.HOST
    assert action_digest(descriptor, {"a": 1}) != action_digest(descriptor, {"a": 2})
    assert action_digest(descriptor, {"a": 1}) != action_digest(
        default_descriptor("other"), {"a": 1}
    )


def test_select_pointers_handles_nested_and_missing() -> None:
    args = {"a": {"b/c": [10, 20]}, "d": None}
    assert select_pointers(args, ["/a/b~1c/1", "/d", "/missing"]) == {"/a/b~1c/1": 20, "/d": None}
    assert select_pointers(args, [""]) == {"": args}

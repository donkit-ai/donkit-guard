"""What the host knows about a tool call, and the digest that binds an approval to it."""

from __future__ import annotations

import hashlib
import json
import unicodedata
from typing import TYPE_CHECKING, Any, Protocol

from pydantic import Field

from donkit_guard.context import Destination, EffectClass, EffectSource, FrozenModel

if TYPE_CHECKING:
    from collections.abc import Iterable, Mapping


class ActionDescriptor(FrozenModel):
    tool: str = Field(min_length=1)
    effect: EffectClass = EffectClass.UNKNOWN
    effect_source: EffectSource = EffectSource.HOST
    essential_args: tuple[str, ...] = ()
    resource_refs: tuple[str, ...] = ()
    maskable_args: tuple[str, ...] = ()
    destination: Destination | None = None
    version: str = "1"


class ActionCatalog(Protocol):
    def describe(
        self, tool: str, arguments: Mapping[str, Any] | None
    ) -> ActionDescriptor | None: ...


def default_descriptor(tool: str) -> ActionDescriptor:
    """The conservative descriptor used when the host has none: unknown effect, all arguments essential."""
    return ActionDescriptor(tool=tool, version="default")


def _normalize(value: Any) -> Any:
    if isinstance(value, str):
        return " ".join(unicodedata.normalize("NFKC", value).split())
    if isinstance(value, float) and value.is_integer():
        return int(value)
    if isinstance(value, dict):
        return {str(k): _normalize(v) for k, v in value.items()}
    if isinstance(value, list | tuple):
        return [_normalize(v) for v in value]
    return value


def canonical_json(value: Any) -> str:
    """Deterministic JSON: sorted keys, NFKC strings with collapsed whitespace, integral floats as ints."""
    return json.dumps(_normalize(value), sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def _resolve_pointer(root: Any, pointer: str) -> tuple[bool, Any]:
    if pointer == "":
        return True, root
    node = root
    for token in pointer.split("/")[1:]:
        key = token.replace("~1", "/").replace("~0", "~")
        if isinstance(node, dict) and key in node:
            node = node[key]
        elif isinstance(node, list) and key.isdigit() and int(key) < len(node):
            node = node[int(key)]
        else:
            return False, None
    return True, node


def select_pointers(arguments: Mapping[str, Any] | None, pointers: Iterable[str]) -> dict[str, Any]:
    """Subset of the arguments addressed by JSON pointers; missing pointers are skipped."""
    selected: dict[str, Any] = {}
    root: Any = dict(arguments or {})
    for pointer in pointers:
        found, value = _resolve_pointer(root, pointer)
        if found:
            selected[pointer] = value
    return selected


def action_digest(descriptor: ActionDescriptor, arguments: Mapping[str, Any] | None) -> str:
    """sha256 over the tool name and the canonical essential arguments."""
    if descriptor.essential_args:
        essential: Any = select_pointers(arguments, descriptor.essential_args)
    else:
        essential = dict(arguments or {})
    material = canonical_json({"tool": descriptor.tool, "args": essential})
    return hashlib.sha256(material.encode("utf-8")).hexdigest()

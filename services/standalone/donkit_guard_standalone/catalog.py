"""What the operator declares about the tools behind the gateway: effects and maskable arguments.

Without an entry a tool keeps the conservative default of the core: an unknown effect, gated as
a write, and every argument essential to the approval digest and never masked.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

import yaml
from pydantic import Field, ValidationError

from donkit_guard.actions import ActionDescriptor
from donkit_guard.context import FrozenModel

if TYPE_CHECKING:
    from collections.abc import Mapping
    from pathlib import Path


class ToolCatalogError(ValueError):
    """The tool catalog file cannot be used."""


class ToolCatalogDocument(FrozenModel):
    tools: tuple[ActionDescriptor, ...] = Field(default=())


class ToolCatalog:
    """An ``ActionCatalog`` read from a YAML file of action descriptors."""

    def __init__(self, descriptors: Mapping[str, ActionDescriptor]) -> None:
        self._descriptors = dict(descriptors)

    @classmethod
    def empty(cls) -> ToolCatalog:
        return cls({})

    @classmethod
    def load(cls, path: Path) -> ToolCatalog:
        try:
            raw = yaml.safe_load(path.read_text("utf-8")) or {}
            document = ToolCatalogDocument.model_validate(raw)
        except (OSError, yaml.YAMLError, ValidationError) as exc:
            raise ToolCatalogError(f"tool catalog {path}: {exc}") from exc
        descriptors: dict[str, ActionDescriptor] = {}
        for descriptor in document.tools:
            if descriptor.tool in descriptors:
                raise ToolCatalogError(f"tool catalog {path}: duplicate tool {descriptor.tool!r}")
            descriptors[descriptor.tool] = descriptor
        return cls(descriptors)

    def describe(self, tool: str, arguments: Mapping[str, Any] | None) -> ActionDescriptor | None:
        return self._descriptors.get(tool)

    def __len__(self) -> int:
        return len(self._descriptors)

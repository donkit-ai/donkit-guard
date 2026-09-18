"""Segmented payload: the unit of detection and masking.

A payload is a list of segments (a message, a document chunk, a tool result, a
single JSON leaf of tool arguments). Detectors and masks work per segment, and a
segment id is derived from where the text sits and from the text itself, so
results can be cached across turns while every leaf stays separately addressable.
"""

from __future__ import annotations

import hashlib
import json
from enum import StrEnum
from typing import TYPE_CHECKING, Any

from donkit_guard.context import FrozenModel

if TYPE_CHECKING:
    from collections.abc import Collection, Iterator, Mapping


class SegmentSource(StrEnum):
    USER = "user"
    ASSISTANT = "assistant"
    SYSTEM = "system"
    TOOL_RESULT = "tool_result"
    DOCUMENT = "document"
    TOOL_ARGS = "tool_args"


class SegmentTrust(StrEnum):
    TRUSTED = "trusted"
    UNTRUSTED = "untrusted"


# JSON field names whose values are identifiers or digests, not secrets: scanning
# them only produces high-entropy false positives.
HASH_LIKE_FIELD_NAMES: frozenset[str] = frozenset(
    {
        "sha256",
        "sha1",
        "md5",
        "etag",
        "commit",
        "hash",
        "traceparent",
        "uuid",
        "checksum",
        "digest",
        "fingerprint",
    }
)


def segment_id(source: SegmentSource, path: str, text: str) -> str:
    """Identity of a segment: its source, its JSON pointer and its text.

    The pointer is part of the identity because two JSON leaves may hold the
    same value: without it they collapse into one id, and every consumer that
    resolves a span back to a leaf (masking, argument previews, the detector
    result cache) would answer with an arbitrary one of them.
    """
    digest = hashlib.sha256()
    digest.update(source.value.encode("utf-8"))
    digest.update(b"\n")
    digest.update(path.encode("utf-8"))
    digest.update(b"\n")
    digest.update(text.encode("utf-8"))
    return digest.hexdigest()


def escape_pointer_token(token: str) -> str:
    return token.replace("~", "~0").replace("/", "~1")


def _unescape_pointer_token(token: str) -> str:
    return token.replace("~1", "/").replace("~0", "~")


def iter_json_leaves(value: Any, base_path: str = "") -> Iterator[tuple[str, Any]]:
    """Yield ``(json_pointer, leaf)`` for every scalar leaf of a JSON value."""
    if isinstance(value, dict):
        for key, item in value.items():
            yield from iter_json_leaves(item, f"{base_path}/{escape_pointer_token(str(key))}")
    elif isinstance(value, list):
        for index, item in enumerate(value):
            yield from iter_json_leaves(item, f"{base_path}/{index}")
    else:
        yield base_path, value


def set_json_pointer(root: Any, pointer: str, value: Any) -> Any:
    """Return a deep copy of ``root`` with the leaf at ``pointer`` replaced by ``value``."""
    if pointer == "":
        return value
    tokens = [_unescape_pointer_token(t) for t in pointer.split("/")[1:]]
    copied = json.loads(json.dumps(root))
    node = copied
    for token in tokens[:-1]:
        node = node[int(token)] if isinstance(node, list) else node[token]
    last = tokens[-1]
    if isinstance(node, list):
        node[int(last)] = value
    else:
        node[last] = value
    return copied


class Segment(FrozenModel):
    id: str
    source: SegmentSource
    trust: SegmentTrust
    path: str = ""
    text: str | None = None
    uninspected: bool = False
    kind: str = "text"
    size_bytes: int = 0
    lang: str | None = None
    leaf_type: str = "str"
    masked: bool = False

    @classmethod
    def of_text(
        cls,
        text: str,
        *,
        source: SegmentSource,
        trust: SegmentTrust,
        path: str = "",
        lang: str | None = None,
        leaf_type: str = "str",
    ) -> Segment:
        return cls(
            id=segment_id(source, path, text),
            source=source,
            trust=trust,
            path=path,
            text=text,
            kind="text" if path == "" else "json_leaf",
            size_bytes=len(text.encode("utf-8")),
            lang=lang,
            leaf_type=leaf_type,
        )

    @classmethod
    def uninspected_part(
        cls,
        *,
        source: SegmentSource,
        path: str,
        kind: str,
        size_bytes: int,
        trust: SegmentTrust = SegmentTrust.UNTRUSTED,
    ) -> Segment:
        marker = f"{kind}:{path}:{size_bytes}"
        return cls(
            id=segment_id(source, path, marker),
            source=source,
            trust=trust,
            path=path,
            text=None,
            uninspected=True,
            kind=kind,
            size_bytes=size_bytes,
        )

    def hashlike(self) -> bool:
        """True when the segment is a JSON leaf under a digest/identifier field name."""
        if not self.path:
            return False
        last = _unescape_pointer_token(self.path.rsplit("/", 1)[-1]).lower()
        return last in HASH_LIKE_FIELD_NAMES

    def label(self) -> str:
        return f"{self.source.value}{self.path}" if self.path else self.source.value


class Payload(FrozenModel):
    segments: tuple[Segment, ...] = ()

    @classmethod
    def of_text(
        cls,
        text: str,
        *,
        source: SegmentSource,
        trust: SegmentTrust,
        lang: str | None = None,
    ) -> Payload:
        return cls(segments=(Segment.of_text(text, source=source, trust=trust, lang=lang),))

    @classmethod
    def from_json(
        cls,
        value: Any,
        *,
        source: SegmentSource,
        trust: SegmentTrust,
        base_path: str = "",
        min_number_digits: int = 7,
        lang: str | None = None,
    ) -> Payload:
        """One segment per string leaf; numbers with many digits become segments too.

        Masking replaces a leaf value, so the enclosing JSON stays valid; a
        masked number is written back as a string placeholder.
        """
        segments: list[Segment] = []
        for pointer, leaf in iter_json_leaves(value, base_path):
            if isinstance(leaf, str):
                segments.append(
                    Segment.of_text(leaf, source=source, trust=trust, path=pointer, lang=lang)
                )
            elif isinstance(leaf, int | float) and not isinstance(leaf, bool):
                digits = sum(ch.isdigit() for ch in str(leaf))
                if digits >= min_number_digits:
                    segments.append(
                        Segment.of_text(
                            str(leaf),
                            source=source,
                            trust=trust,
                            path=pointer,
                            lang=lang,
                            leaf_type="number",
                        )
                    )
        return cls(segments=tuple(segments))

    def by_id(self) -> dict[str, Segment]:
        return {segment.id: segment for segment in self.segments}

    def inspectable(self) -> list[Segment]:
        return [s for s in self.segments if s.text is not None and not s.uninspected]

    def uninspected_parts(self) -> list[Segment]:
        return [s for s in self.segments if s.uninspected or s.text is None]

    def new_segments(self, seen: Collection[str]) -> list[Segment]:
        seen_ids = set(seen)
        return [s for s in self.inspectable() if s.id not in seen_ids]

    def total_bytes(self) -> int:
        return sum(s.size_bytes for s in self.segments)

    def with_masks(self, masks: Mapping[str, str]) -> Payload:
        """Return a payload whose segments carry the masked text (ids are kept for traceability)."""
        if not masks:
            return self
        replaced = tuple(
            s.model_copy(update={"text": masks[s.id], "masked": True}) if s.id in masks else s
            for s in self.segments
        )
        return Payload(segments=replaced)

"""Declared pattern detector: RE2 patterns from a policy document, weighed by their context.

A policy author describes data such as contract numbers with RE2 patterns, an optional
checksum, words that confirm a match near it, words that rule a match out, and the JSON keys
whose values are such data whole. RE2 searches in time linear in the text, whatever the
pattern, and on ``str`` it reports Unicode code point offsets, which findings carry unchanged.
"""

from __future__ import annotations

from fnmatch import fnmatchcase
from typing import TYPE_CHECKING, Any

from donkit_guard.declared.regex import compile_re2
from donkit_guard.declared.spec import MAX_FINDINGS_PER_SEGMENT, PatternDetectorSpec, spec_digest
from donkit_guard.detectors.checksums import CHECKSUMS, digits_of
from donkit_guard.detectors.context import has_context, word_pattern
from donkit_guard.findings import Findings, FindingSpan

if TYPE_CHECKING:
    from collections.abc import Sequence

    from donkit_guard.payload import Segment


class PatternDetector:
    """The detector a ``pattern`` declaration stands for.

    Every match of the declared patterns is a candidate. A candidate is dropped when it is
    empty, fails the declared checksum or has an exclude word within the context window. A
    kept one scores ``score`` when a context word is within the window, or when the
    declaration names none, and ``score_without_context`` otherwise. A JSON leaf whose key
    matches one of ``json_keys`` is reported whole, with ``score``, and is not searched. One
    segment yields at most ``MAX_FINDINGS_PER_SEGMENT`` findings.

    Building the detector compiles its patterns, if it has any: without the ``re2`` extra
    that raises ``RuntimeError``, and a pattern RE2 refuses raises ``ValueError``.
    """

    version = "1"
    remote = False

    def __init__(self, spec: PatternDetectorSpec, *, cache_scope: str = "") -> None:
        self._spec = spec
        self.name = f"declared:{spec.id}"
        self.classes = frozenset({spec.cls})
        self.pattern_set_hash = spec_digest(spec)
        # Optional detector attributes, read through the ``detector_*`` accessors of
        # ``donkit_guard.detectors.base``.
        self.subtypes = frozenset({spec.subtype})
        self.cache_scope = cache_scope
        # One expression scans a text once. Every pattern gets a group of its own, so its
        # top-level `|` and its inline flags stay inside it.
        combined = "|".join(f"(?:{pattern})" for pattern in spec.patterns)
        self._regex: Any = compile_re2(combined) if spec.patterns else None
        self._checksum = CHECKSUMS[spec.checksum] if spec.checksum is not None else None
        self._context = word_pattern(spec.context) if spec.context else None
        self._exclude = word_pattern(spec.exclude) if spec.exclude else None
        self._json_keys = tuple(glob.lower() for glob in spec.json_keys)

    def detect(self, segments: Sequence[Segment]) -> Findings:
        spans: list[FindingSpan] = []
        scanned = 0
        for segment in segments:
            text = segment.text
            if text is None or segment.uninspected:
                continue
            scanned += 1
            if self._listed_key(segment):
                if text:
                    spans.append(self._span(segment, 0, len(text), self._spec.score))
                continue
            spans.extend(self._search(segment, text))
        return Findings(
            detector=self.name,
            version=self.version,
            pattern_set_hash=self.pattern_set_hash,
            spans=tuple(spans),
            segments_scanned=scanned,
        )

    def _listed_key(self, segment: Segment) -> bool:
        """Whether the segment is a JSON value under a key that ``json_keys`` names."""
        if not self._json_keys:
            return False
        key = segment.key().lower()
        # A message, or an element of a top-level array, sits under no key, and not even a
        # bare `*` names that.
        return bool(key) and any(fnmatchcase(key, glob) for glob in self._json_keys)

    def _search(self, segment: Segment, text: str) -> list[FindingSpan]:
        found: list[FindingSpan] = []
        if self._regex is None:
            return found
        for match in self._regex.finditer(text):
            start: int = match.start()
            end: int = match.end()
            # A pattern that can match the empty string does so wherever it finds nothing
            # else; an empty match names no text.
            if start == end or not self._passes_checksum(text[start:end]):
                continue
            if self._exclude is not None and has_context(text, start, end, self._exclude):
                continue
            confirmed = self._context is None or has_context(text, start, end, self._context)
            score = self._spec.score if confirmed else self._spec.score_without_context
            found.append(self._span(segment, start, end, score))
            if len(found) == MAX_FINDINGS_PER_SEGMENT:
                break
        return found

    def _passes_checksum(self, raw: str) -> bool:
        if self._checksum is None:
            return True
        # An IBAN is checked as written, letters included; the other checksums read digits.
        return self._checksum(raw if self._spec.checksum == "iban" else digits_of(raw))

    def _span(self, segment: Segment, start: int, end: int, score: float) -> FindingSpan:
        return FindingSpan(
            segment_id=segment.id,
            path=segment.path,
            start=start,
            end=end,
            cls=self._spec.cls,
            subtype=self._spec.subtype,
            score=score,
            detector=self.name,
        )

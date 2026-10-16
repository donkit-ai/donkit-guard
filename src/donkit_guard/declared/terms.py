"""Declared terms detector: finds the words of a list in text.

A policy author lists terms such as project code names or the names of key clients. A term is
found only as whole words, in any case and whichever look-alike Latin or Cyrillic letters spell
it; its words may stand apart by any run of whitespace, and a trailing ``*`` lets its last word
take any ending. Terms and text are folded alike by ``donkit_guard.text.normalize``, and
findings point into the original text.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

from donkit_guard.declared.regex import compile_re2, escape_re2
from donkit_guard.declared.spec import MAX_FINDINGS_PER_SEGMENT, TermsDetectorSpec, spec_digest
from donkit_guard.findings import Findings, FindingSpan
from donkit_guard.text import normalize

if TYPE_CHECKING:
    from collections.abc import Sequence

    from donkit_guard.payload import Segment

# Letters and digits make up words, and a term is found only where neither adjoins it. RE2's
# ``\b`` knows ASCII letters only, so an expression spells out the characters around a term.
_WORD = r"[\p{L}\p{N}]"
_NOT_WORD = r"[^\p{L}\p{N}]"
# Whitespace as ``str.split`` sees it, which RE2's ASCII-only ``\s`` is not.
_GAP = r"[\x{09}-\x{0d}\x{1c}-\x{20}\x{85}\p{Z}]+"


def _longest_first(alternatives: dict[str, str]) -> list[str]:
    return [alternatives[key] for key in sorted(alternatives, key=len, reverse=True)]


def _alternatives(terms: Sequence[str]) -> tuple[list[str], list[str]]:
    """RE2 alternatives of the plain terms and of the ``*`` terms, each list longest first.

    RE2 takes the first alternative that matches at a place, so a term has to come before the
    shorter terms it extends for it to be reported whole.
    """
    plain: dict[str, str] = {}
    starred: dict[str, str] = {}
    for term in terms:
        stem = term.strip()
        words = normalize(stem.removesuffix("*")).text.split()
        if not words:
            raise ValueError(f"term {term!r} has no visible characters")
        target = starred if stem.endswith("*") else plain
        target[" ".join(words)] = "(?:" + _GAP.join(escape_re2(word) for word in words) + ")"
    return _longest_first(plain), _longest_first(starred)


def _expression(alternatives: Sequence[str], ending: str) -> Any:
    """Compile one expression whose group 1 is an occurrence of one of ``alternatives``.

    The match also takes the character on either side of the occurrence (none at an end of the
    text): that is how a word boundary is written without lookaround. The character after one
    occurrence may be the one before the next, so a search for the next occurrence starts
    where the last occurrence ends, not where its match does.
    """
    body = "|".join(alternatives)
    return compile_re2(f"(?:^|{_NOT_WORD})((?:{body}){ending})(?:{_NOT_WORD}|$)")


class TermsDetector:
    """The detector a ``terms`` declaration stands for.

    Occurrences never overlap: the leftmost is reported first and, of the terms that match at
    one place, the longest. A segment yields at most ``MAX_FINDINGS_PER_SEGMENT`` findings.
    Building it raises ``ValueError`` for a term with no visible characters or a list RE2
    cannot compile, and ``RuntimeError`` when the ``re2`` extra is not installed.
    """

    version = "1"
    remote = False

    def __init__(self, spec: TermsDetectorSpec, *, cache_scope: str = "") -> None:
        self._spec = spec
        self.name = f"declared:{spec.id}"
        self.classes = frozenset({spec.cls})
        self.pattern_set_hash = spec_digest(spec)
        # Optional detector attributes, read through the ``detector_*`` accessors of
        # ``donkit_guard.detectors.base``.
        self.subtypes = frozenset({spec.subtype})
        self.cache_scope = cache_scope
        plain, starred = _alternatives(spec.terms)
        self._expressions: tuple[Any, ...] = tuple(
            _expression(alternatives, ending)
            for alternatives, ending in ((plain, ""), (starred, f"{_WORD}*"))
            if alternatives
        )

    def detect(self, segments: Sequence[Segment]) -> Findings:
        spans: list[FindingSpan] = []
        scanned = 0
        for segment in segments:
            if segment.text is None or segment.uninspected:
                continue
            scanned += 1
            folded = normalize(segment.text)
            for start, end in self._occurrences(folded.text):
                spans.append(
                    FindingSpan(
                        segment_id=segment.id,
                        path=segment.path,
                        start=folded.offsets[start],
                        end=folded.offsets[end - 1] + 1,
                        cls=self._spec.cls,
                        subtype=self._spec.subtype,
                        score=self._spec.score,
                        detector=self.name,
                    )
                )
        return Findings(
            detector=self.name,
            version=self.version,
            pattern_set_hash=self.pattern_set_hash,
            spans=tuple(spans),
            segments_scanned=scanned,
        )

    def spec_payload(self) -> dict[str, object]:
        """The declaration and scope a process-pool worker rebuilds this detector from."""
        return {
            "kind": "terms",
            "spec": self._spec.model_dump(mode="json", by_alias=True),
            "cache_scope": self.cache_scope,
        }

    def _occurrences(self, text: str) -> list[tuple[int, int]]:
        """Spans of the occurrences in folded ``text``, in order.

        Plain terms and ``*`` terms are separate expressions, so that the ``*`` ending is
        written once for all of them. Of the next matches of the two, the one that starts
        first is taken, and of two that start together the longer.
        """
        found: list[tuple[int, int]] = []
        position = 0
        # The leftmost match of each expression at or after ``position``; None once it has none.
        ahead: list[Any] = [expression.search(text) for expression in self._expressions]
        while len(found) < MAX_FINDINGS_PER_SEGMENT:
            best: tuple[int, int] | None = None
            for index, expression in enumerate(self._expressions):
                match = ahead[index]
                if match is not None and match.start() < position:
                    match = ahead[index] = expression.search(text, position)
                if match is None:
                    continue
                start, end = match.span(1)
                if best is None or start < best[0] or (start == best[0] and end > best[1]):
                    best = (start, end)
            if best is None:
                break
            found.append(best)
            position = best[1]
        return found

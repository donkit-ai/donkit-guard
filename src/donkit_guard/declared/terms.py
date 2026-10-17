"""Declared terms detector: finds the words of a list in text.

A policy author lists terms such as project code names or the names of key clients. A term is
found only as whole words, in any case and whichever look-alike Latin or Cyrillic letters spell
it; its words may stand apart by any run of whitespace, and a trailing ``*`` lets its last word
take any ending. Terms and text are folded alike by ``donkit_guard.text.normalize``, and
findings point into the original text.

Terms are matched in plain Python, without RE2 and without any extra. They are indexed by their
first characters, and a text is looked up only where a term could start, so a scan takes time
linear in the length of the text times the number of distinct lengths among the terms that
share a prefix.
"""

from __future__ import annotations

import re
from typing import TYPE_CHECKING

from donkit_guard.declared.spec import MAX_FINDINGS_PER_SEGMENT, TermsDetectorSpec, spec_digest
from donkit_guard.findings import Findings, FindingSpan
from donkit_guard.text import normalize

if TYPE_CHECKING:
    from collections.abc import Sequence

    from donkit_guard.payload import Segment

# Terms are indexed by their first eight characters, or by the whole of a shorter term: few
# terms of a list share a prefix that long, and few words of a text start with one.
_PREFIX = 8
# ``\s`` is the whitespace ``str.split`` cuts terms at: made one space, a run of it in the text
# matches the single space that joins the words of a term.
_SPACE_RUN = re.compile(r"\s+")
# Where an occurrence can start: a visible character with no letter or digit right before it.
# ``[^\W_]`` is exactly what ``str.isalnum`` accepts.
_WORD_START = re.compile(r"(?<![^\W_])\S")


def _index(terms: Sequence[str]) -> dict[str, tuple[tuple[int, dict[str, bool]], ...]]:
    """The forms of ``terms`` by prefix, then by length, longest first.

    A form is the words of a term, folded and joined by single spaces; it maps to whether the
    term ended in ``*``.
    """
    by_prefix: dict[str, dict[int, dict[str, bool]]] = {}
    for term in terms:
        stem = term.strip()
        starred = stem.endswith("*")
        words = normalize(stem.removesuffix("*")).text.split()
        if not words:
            raise ValueError(f"term {term!r} has no visible characters")
        form = " ".join(words)
        forms = by_prefix.setdefault(form[:_PREFIX], {}).setdefault(len(form), {})
        # A term without the ``*`` finds part of what the same term with it finds.
        forms[form] = forms.get(form, False) or starred
    return {
        prefix: tuple((length, by_length[length]) for length in sorted(by_length, reverse=True))
        for prefix, by_length in by_prefix.items()
    }


def _collapse(text: str) -> tuple[str, list[int]]:
    """``text`` with each run of whitespace made one space, and where its characters come from.

    The list holds, for every character of the collapsed text, its index in ``text``; a space
    that stands for a run has the index of the run's first character.
    """
    pieces: list[str] = []
    places: list[int] = []
    position = 0
    for run in _SPACE_RUN.finditer(text):
        pieces.append(text[position : run.start()])
        pieces.append(" ")
        places.extend(range(position, run.start() + 1))
        position = run.end()
    pieces.append(text[position:])
    places.extend(range(position, len(text)))
    return "".join(pieces), places


def _in_word(text: str, index: int) -> bool:
    """Whether a letter or digit stands at ``index`` of ``text``."""
    return index < len(text) and text[index].isalnum()


class TermsDetector:
    """The detector a ``terms`` declaration stands for.

    Occurrences never overlap: the leftmost is reported first and, of the terms that match at
    one place, the longest. A segment yields at most ``MAX_FINDINGS_PER_SEGMENT`` findings.
    Building it raises ``ValueError`` for a term with no visible characters.
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
        self._index = _index(spec.terms)
        # A term shorter than the prefix is indexed whole, so prefixes come in several lengths.
        # Taking the longest first takes the longest forms first: a term indexed whole is shorter
        # than every form under a longer prefix.
        self._prefix_lengths = tuple(sorted({len(prefix) for prefix in self._index}, reverse=True))

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
        """Spans of the occurrences in folded ``text``, in order."""
        collapsed, places = _collapse(text)
        found: list[tuple[int, int]] = []
        last_end = 0
        for match in _WORD_START.finditer(collapsed):
            start = match.start()
            if start < last_end:
                continue
            end = self._occurrence_end(collapsed, start)
            if end is None:
                continue
            # The last character maps back, not the one after it: that one may lie past the end
            # or be a space that stands for a run of whitespace.
            found.append((places[start], places[end - 1] + 1))
            if len(found) == MAX_FINDINGS_PER_SEGMENT:
                break
            last_end = end
        return found

    def _occurrence_end(self, text: str, start: int) -> int | None:
        """Where the occurrence that starts at ``start`` of ``text`` ends, if one starts there.

        Forms are tried longest first, and the first one that matches is the occurrence. A plain
        form matches where no letter or digit follows it; a ``*`` form matches anyway and runs
        on over the letters and digits that follow it.
        """
        for prefix_length in self._prefix_lengths:
            for length, forms in self._index.get(text[start : start + prefix_length], ()):
                end = start + length
                starred = forms.get(text[start:end])
                if starred is None:
                    continue
                if starred:
                    while _in_word(text, end):
                        end += 1
                    return end
                if not _in_word(text, end):
                    return end
        return None

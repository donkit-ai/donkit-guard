"""Declared terms detector: finds the words of a list in text.

A policy author lists terms such as project code names or the names of key clients. A term is
found only as whole words, in any case and whichever look-alike Latin or Cyrillic letters spell
it; its words may stand apart by any run of whitespace, and a trailing ``*`` lets its last word
take any ending. Terms and text are folded alike by ``donkit_guard.text.normalize``, and
findings point into the original text.

Terms are matched in plain Python, without RE2 and without any extra. They are indexed by their
first characters, and a text is looked up only where a term could start. Every lookup costs the
characters it cuts out of the text and hashes, against a work limit that grows with the length
of the text, so matching takes time linear in the text, bounded by that limit: realistic lists
need a small part of it, and a list crafted to need more fails its scan instead of stalling it.
"""

from __future__ import annotations

import os.path
import re
from typing import TYPE_CHECKING, NamedTuple

from donkit_guard.declared.spec import MAX_FINDINGS_PER_SEGMENT, TermsDetectorSpec, spec_digest
from donkit_guard.detectors.base import failed_findings
from donkit_guard.findings import Findings, FindingSpan
from donkit_guard.text import normalize

if TYPE_CHECKING:
    from collections.abc import Sequence

    from donkit_guard.payload import Segment

# Terms are indexed by their first eight characters, or by the whole of a shorter term: few
# terms of a list share a prefix that long, and few words of a text start with one.
_PREFIX = 8
# The characters the lookups of one segment may cut out and compare: so many per character of its
# text, plus a fixed allowance. A lookup costs its length, not one unit, because folding can make
# a form many times longer than the term it comes from. A place where a term could start costs
# at most 36 characters for its prefixes (lengths 1 to 8), so they alone always fit. A prefix the
# text holds costs what its forms share, and only where the text goes on with that, the lengths
# of its forms: a text that is nothing but names under one long legal form needs about a tenth of
# the limit, while a list crafted so that every place costs thousands of characters fails within
# a few hundred thousand of them.
_WORK_PER_CHAR = 256
_WORK_ALLOWANCE = 65_536
_WORK_LIMIT_ERROR = "terms scan exceeded its work limit"
# ``\s`` is the whitespace ``str.split`` cuts terms at: made one space, a run of it in the text
# matches the single space that joins the words of a term.
_SPACE_RUN = re.compile(r"\s+")
# Where an occurrence can start: a visible character with no letter or digit right before it.
# ``[^\W_]`` is exactly what ``str.isalnum`` accepts.
_WORD_START = re.compile(r"(?<![^\W_])\S")


class _Forms(NamedTuple):
    """The forms under one prefix: the text they all start with, and the forms by length."""

    shared: str
    by_length: tuple[tuple[int, dict[str, bool]], ...]


def _index(terms: Sequence[str]) -> dict[str, _Forms]:
    """The forms of ``terms`` by prefix, then by length, longest first.

    A form is the words of a term, folded and joined by single spaces; it maps to whether the
    term ended in ``*``. Names under one legal form share far more than the prefix, so the text
    all the forms of a prefix start with is kept as well: where the text does not go on with it,
    none of them can match.
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
        prefix: _Forms(
            shared=os.path.commonprefix([form for forms in by_length.values() for form in forms]),
            by_length=tuple(
                (length, by_length[length]) for length in sorted(by_length, reverse=True)
            ),
        )
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

    The lookups of a segment may cut out and compare at most 256 characters per character of its
    text, plus 65 536; the text counts as written or as folded, with each run of whitespace
    counted as one character, whichever is shorter. A scan that
    would need more stops, and ``detect`` reports the call as failed (``terms scan exceeded its
    work limit``) instead of reporting findings. Building the detector raises ``ValueError`` for
    a term with no visible characters.
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
            occurrences = self._occurrences(folded.text, len(segment.text))
            if occurrences is None:
                return failed_findings(self, _WORK_LIMIT_ERROR)
            for start, end in occurrences:
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

    def _occurrences(self, text: str, written: int) -> list[tuple[int, int]] | None:
        """Spans of the occurrences in folded ``text``, in order.

        ``written`` is the length of the text as it was written. ``None`` stands for a scan
        that went past its work limit, which follows the shorter of the two texts: folding can
        make a text many times longer than the one the scan was handed.
        """
        collapsed, places = _collapse(text)
        work_left = _WORK_PER_CHAR * min(len(collapsed), written) + _WORK_ALLOWANCE
        found: list[tuple[int, int]] = []
        last_end = 0
        for match in _WORD_START.finditer(collapsed):
            start = match.start()
            if start < last_end:
                continue
            end, work = self._occurrence_end(collapsed, start)
            work_left -= work
            if work_left < 0:
                return None
            if end is None:
                continue
            # The last character maps back, not the one after it: that one may lie past the end
            # or be a space that stands for a run of whitespace.
            found.append((places[start], places[end - 1] + 1))
            if len(found) == MAX_FINDINGS_PER_SEGMENT:
                break
            last_end = end
        return found

    def _occurrence_end(self, text: str, start: int) -> tuple[int | None, int]:
        """Where an occurrence that starts at ``start`` of ``text`` ends, and the work it took.

        The end is ``None`` where no occurrence starts. Forms are tried longest first, and the
        first one that matches is the occurrence. A plain form matches where no letter or digit
        follows it; a ``*`` form matches anyway and runs on over the letters and digits that
        follow it. The work is the number of characters of ``text`` looked at: the prefixes looked
        up, what the forms of a prefix that is found share, and, where the text goes on with that,
        the forms under it.
        """
        work = 0
        for prefix_length in self._prefix_lengths:
            work += prefix_length
            under = self._index.get(text[start : start + prefix_length])
            if under is None:
                continue
            work += len(under.shared)
            if not text.startswith(under.shared, start):
                continue
            for length, forms in under.by_length:
                work += length
                end = start + length
                starred = forms.get(text[start:end])
                if starred is None:
                    continue
                if starred:
                    while _in_word(text, end):
                        end += 1
                    return end, work
                if not _in_word(text, end):
                    return end, work
        return None, work

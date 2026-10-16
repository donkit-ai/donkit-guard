"""Checksum-validated identifiers and format-bound contacts, without an NLP model."""

from __future__ import annotations

import hashlib
import re
from re import Pattern
from typing import TYPE_CHECKING

from donkit_guard.detectors.base import register_detector, spans_overlap
from donkit_guard.detectors.checksums import (
    digits_of,
    valid_inn,
    valid_luhn,
    valid_ogrn,
    valid_snils,
)
from donkit_guard.detectors.context import CONTEXT_WINDOW, has_context, word_pattern
from donkit_guard.findings import FindingClass, Findings, FindingSpan

if TYPE_CHECKING:
    from collections.abc import Sequence

    from donkit_guard.payload import Segment

# Issuer identification ranges in use today, as (prefix length, low, high).
_ISSUER_PREFIXES: tuple[tuple[int, int, int], ...] = (
    (1, 4, 4),  # Visa
    (2, 51, 55),  # Mastercard
    (4, 2221, 2720),  # Mastercard (2-series)
    (2, 34, 34),  # American Express
    (2, 37, 37),
    (4, 6011, 6011),  # Discover
    (2, 65, 65),
    (3, 644, 649),
    (4, 3528, 3589),  # JCB
    (3, 300, 305),  # Diners Club
    (2, 36, 36),
    (2, 38, 39),
    (4, 2200, 2204),  # Mir
    (2, 62, 62),  # UnionPay
)


def _issuer_prefix(digits: str) -> bool:
    """Whether the number opens with an issuer identification number in use today.

    A check digit alone is one digit of evidence: roughly one number in ten passes it,
    so an epoch-millisecond timestamp is a valid card number without this.
    """
    if len(digits) < 4 or not digits.isdigit():
        return False
    return any(low <= int(digits[:length]) <= high for length, low, high in _ISSUER_PREFIXES)


_SEPARATORS = re.compile(r"[ -]")


def _one_separator(raw: str) -> bool:
    """A card is written with one separator throughout, or with none at all.

    Two different separators in one run of digits is a date range or a serial number
    that happens to satisfy the check digit, not a card number.
    """
    return len(set(_SEPARATORS.findall(raw))) <= 1


# A checksum-valid identifier without a word naming what it is stays below the
# masking threshold of the shipped policy: it is recorded, not rewritten.
SCORE_CONTEXT_FREE = 0.4
SCORES: dict[str, float] = {
    "SNILS": 1.0,
    "INN": 1.0,
    "OGRN": 1.0,
    "CREDIT_CARD": 1.0,
    "EMAIL": 0.9,
    "PHONE": 0.8,
    "US_SSN": 0.7,
    "PASSPORT": 0.6,
}

_PATTERNS: tuple[tuple[str, Pattern[str]], ...] = (
    ("SNILS", re.compile(r"\b\d{3}[- ]?\d{3}[- ]?\d{3}[- ]?\d{2}\b")),
    ("INN", re.compile(r"\b\d{10}(?:\d{2})?\b")),
    ("OGRN", re.compile(r"\b\d{13}(?:\d{2})?\b")),
    ("CREDIT_CARD", re.compile(r"\b(?:\d[ -]?){12,18}\d\b")),
    ("PHONE", re.compile(r"(?<!\d)(?:\+7|8)[\s(-]*\d{3}[\s)-]*\d{3}[\s-]*\d{2}[\s-]*\d{2}(?!\d)")),
    ("PHONE", re.compile(r"(?<!\d)(?:\+1[\s.-]?)?\(?[2-9]\d{2}\)?[\s.-]\d{3}[\s.-]\d{4}(?!\d)")),
    ("EMAIL", re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b")),
    ("US_SSN", re.compile(r"\b(?!000|666|9\d\d)\d{3}-(?!00)\d{2}-(?!0000)\d{4}\b")),
    ("PASSPORT", re.compile(r"\b\d{2}\s?\d{2}\s*(?:№|номер|n)?\s*\d{6}\b", re.IGNORECASE)),
)

_CONTEXT: dict[str, Pattern[str]] = {
    "SNILS": word_pattern(["снилс", "snils"]),
    "INN": word_pattern(["инн", "inn", "налог*", "tax", "taxes", "taxpayer", "taxation"]),
    "OGRN": word_pattern(["огрн", "огрнип", "ogrn", "ogrnip"]),
    "PASSPORT": word_pattern(["паспорт*", "серия", "номер", "passport"]),
}

_VALIDATORS = {"SNILS": valid_snils, "INN": valid_inn, "OGRN": valid_ogrn}


def _score_match(subtype: str, text: str, match: re.Match[str]) -> float | None:
    """The score of a candidate, or None when it is not reported at all."""
    raw = match.group(0)
    digits = digits_of(raw)
    start, end = match.span()
    confident = SCORES[subtype]
    if subtype == "CREDIT_CARD":
        if valid_luhn(digits) and _issuer_prefix(digits) and _one_separator(raw):
            return confident
        return None
    if subtype == "PASSPORT":
        return confident if has_context(text, start, end, _CONTEXT[subtype]) else None
    validator = _VALIDATORS.get(subtype)
    if validator is None:
        return confident
    if not validator(digits):
        return None
    if has_context(text, start, end, _CONTEXT[subtype]):
        return confident
    # The canonical written form of a SNILS is a format nothing else shares.
    if subtype == "SNILS" and raw != digits:
        return confident
    return SCORE_CONTEXT_FREE


def _pattern_set_hash() -> str:
    material = "|".join(f"{subtype}:{pattern.pattern}" for subtype, pattern in _PATTERNS)
    material += "|" + "|".join(f"{key}:{value.pattern}" for key, value in sorted(_CONTEXT.items()))
    material += "|" + "|".join(f"{key}={value}" for key, value in sorted(SCORES.items()))
    material += f"|context_free={SCORE_CONTEXT_FREE}|window={CONTEXT_WINDOW}"
    material += "|" + ",".join(f"{n}:{lo}-{hi}" for n, lo, hi in _ISSUER_PREFIXES)
    return hashlib.sha256(material.encode("utf-8")).hexdigest()[:12]


PATTERN_SET_HASH: str = _pattern_set_hash()


class PiiChecksumDetector:
    name = "pii-checksum"
    version = "1"
    classes = frozenset({FindingClass.PII})
    remote = False
    pattern_set_hash = PATTERN_SET_HASH

    def detect(self, segments: Sequence[Segment]) -> Findings:
        spans: list[FindingSpan] = []
        scanned = 0
        for segment in segments:
            text = segment.text
            if text is None or segment.uninspected or segment.hashlike():
                continue
            scanned += 1
            taken: list[tuple[int, int]] = []
            for subtype, pattern in _PATTERNS:
                for match in pattern.finditer(text):
                    start, end = match.span()
                    if spans_overlap(start, end, taken):
                        continue
                    score = _score_match(subtype, text, match)
                    if score is None:
                        continue
                    taken.append((start, end))
                    spans.append(
                        FindingSpan(
                            segment_id=segment.id,
                            path=segment.path,
                            start=start,
                            end=end,
                            cls=FindingClass.PII,
                            subtype=subtype,
                            score=score,
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


register_detector(PiiChecksumDetector)

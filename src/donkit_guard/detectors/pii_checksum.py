"""Checksum-validated identifiers and format-bound contacts, without an NLP model."""

from __future__ import annotations

import hashlib
import re
from re import Pattern
from typing import TYPE_CHECKING

from donkit_guard.detectors.base import register_detector, spans_overlap
from donkit_guard.findings import FindingClass, Findings, FindingSpan

if TYPE_CHECKING:
    from collections.abc import Sequence

    from donkit_guard.payload import Segment

_DIGITS = re.compile(r"\D+")


def _digits(text: str) -> str:
    return _DIGITS.sub("", text)


def valid_snils(digits: str) -> bool:
    if len(digits) != 11 or not digits.isdigit() or int(digits[:9]) <= 1001998:
        return False
    total = sum(int(d) * (9 - i) for i, d in enumerate(digits[:9]))
    if total < 100:
        check = total
    elif total in (100, 101):
        check = 0
    else:
        check = total % 101
        if check == 100:
            check = 0
    return check == int(digits[9:])


def valid_inn(digits: str) -> bool:
    if not digits.isdigit():
        return False
    if len(digits) == 10:
        weights = (2, 4, 10, 3, 5, 9, 4, 6, 8)
        return sum(int(d) * w for d, w in zip(digits[:9], weights, strict=True)) % 11 % 10 == int(
            digits[9]
        )
    if len(digits) == 12:
        w11 = (7, 2, 4, 10, 3, 5, 9, 4, 6, 8)
        w12 = (3, 7, 2, 4, 10, 3, 5, 9, 4, 6, 8)
        n11 = sum(int(d) * w for d, w in zip(digits[:10], w11, strict=True)) % 11 % 10
        n12 = sum(int(d) * w for d, w in zip(digits[:11], w12, strict=True)) % 11 % 10
        return n11 == int(digits[10]) and n12 == int(digits[11])
    return False


def valid_ogrn(digits: str) -> bool:
    if not digits.isdigit():
        return False
    if len(digits) == 13:
        return int(digits[:12]) % 11 % 10 == int(digits[12])
    if len(digits) == 15:
        return int(digits[:14]) % 13 % 10 == int(digits[14])
    return False


def valid_luhn(digits: str) -> bool:
    if not digits.isdigit() or not 13 <= len(digits) <= 19:
        return False
    total = 0
    for index, char in enumerate(reversed(digits)):
        value = int(char)
        if index % 2 == 1:
            value *= 2
            if value > 9:
                value -= 9
        total += value
    return total % 10 == 0


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

# A letter in any script: the boundary for context words, so "inner", "winner", "syntax"
# or "инновации" do not vouch for a number while "INN7707123458" and "ИНН:" still do.
_LETTER = r"[^\W\d_]"


def _words(*forms: str) -> str:
    """Alternation of context words bounded by non-letters; a trailing `*` allows suffixes."""
    parts: list[str] = []
    for form in forms:
        if form.endswith("*"):
            parts.append(f"(?<!{_LETTER}){form[:-1]}")
        else:
            parts.append(f"(?<!{_LETTER}){form}(?!{_LETTER})")
    return "|".join(parts)


_CONTEXT: dict[str, Pattern[str]] = {
    "SNILS": re.compile(_words("снилс", "snils"), re.IGNORECASE),
    "INN": re.compile(
        _words("инн", "inn", "налог*", "tax", "taxes", "taxpayer", "taxation"), re.IGNORECASE
    ),
    "OGRN": re.compile(_words("огрн", "огрнип", "ogrn", "ogrnip"), re.IGNORECASE),
    "PASSPORT": re.compile(_words("паспорт*", "серия", "номер", "passport"), re.IGNORECASE),
}
_CONTEXT_WINDOW = 40

_VALIDATORS = {"SNILS": valid_snils, "INN": valid_inn, "OGRN": valid_ogrn}


def _has_context(text: str, start: int, end: int, subtype: str) -> bool:
    window = text[max(0, start - _CONTEXT_WINDOW) : min(len(text), end + _CONTEXT_WINDOW)]
    return _CONTEXT[subtype].search(window) is not None


def _score_match(subtype: str, text: str, match: re.Match[str]) -> float | None:
    """The score of a candidate, or None when it is not reported at all."""
    raw = match.group(0)
    digits = _digits(raw)
    confident = SCORES[subtype]
    if subtype == "CREDIT_CARD":
        if valid_luhn(digits) and _issuer_prefix(digits) and _one_separator(raw):
            return confident
        return None
    if subtype == "PASSPORT":
        return confident if _has_context(text, match.start(), match.end(), subtype) else None
    validator = _VALIDATORS.get(subtype)
    if validator is None:
        return confident
    if not validator(digits):
        return None
    if _has_context(text, match.start(), match.end(), subtype):
        return confident
    # The canonical written form of a SNILS is a format nothing else shares.
    if subtype == "SNILS" and raw != digits:
        return confident
    return SCORE_CONTEXT_FREE


def _pattern_set_hash() -> str:
    material = "|".join(f"{subtype}:{pattern.pattern}" for subtype, pattern in _PATTERNS)
    material += "|" + "|".join(f"{key}:{value.pattern}" for key, value in sorted(_CONTEXT.items()))
    material += "|" + "|".join(f"{key}={value}" for key, value in sorted(SCORES.items()))
    material += f"|context_free={SCORE_CONTEXT_FREE}|window={_CONTEXT_WINDOW}"
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

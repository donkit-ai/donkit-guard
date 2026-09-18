"""Per-entity score thresholds (measured on the spike corpus: single thresholds lose F1)."""

from __future__ import annotations

DEFAULT_THRESHOLD = 0.6

# Presidio entity type -> canonical type returned to the core.
CANONICAL: dict[str, str] = {
    "PERSON": "PERSON",
    "PHONE_NUMBER": "PHONE",
    "PHONE_RF": "PHONE",
    "PASSPORT_RF": "PASSPORT",
    "SNILS": "SNILS",
    "INN_RU": "INN",
    "OGRN": "OGRN",
    "OGRNIP": "OGRN",
    "EMAIL_ADDRESS": "EMAIL",
    "DATE_TIME": "DATE_TIME",
    "LOCATION": "LOCATION",
    "CREDIT_CARD": "CREDIT_CARD",
    "US_SSN": "US_SSN",
}

# Canonical type -> minimum score to report.
THRESHOLDS: dict[str, float] = {
    "PERSON": 0.6,
    "PHONE": 0.6,
    "PASSPORT": 0.5,
    "SNILS": 0.85,
    "INN": 0.85,
    "OGRN": 0.85,
    "EMAIL": 0.85,
    "CREDIT_CARD": 0.85,
    "US_SSN": 0.6,
    "DATE_TIME": 0.85,
    "LOCATION": 0.5,
}


def passes(canonical_type: str, score: float) -> bool:
    return score >= THRESHOLDS.get(canonical_type, DEFAULT_THRESHOLD)

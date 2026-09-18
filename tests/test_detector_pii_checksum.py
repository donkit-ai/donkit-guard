from __future__ import annotations

import json
import random
from collections import Counter
from pathlib import Path
from typing import TYPE_CHECKING

import pytest

from donkit_guard.detectors.pii_checksum import (
    PATTERN_SET_HASH,
    SCORES,
    PiiChecksumDetector,
    valid_inn,
    valid_luhn,
    valid_ogrn,
    valid_snils,
)
from donkit_guard.payload import Segment, SegmentSource, SegmentTrust

if TYPE_CHECKING:
    from donkit_guard.findings import FindingSpan

CORPUS = Path(__file__).parent / "data" / "pii_corpus.json"
MASK_THRESHOLD = 0.5


def _spans(text: str) -> list[FindingSpan]:
    seg = Segment.of_text(text, source=SegmentSource.USER, trust=SegmentTrust.TRUSTED)
    return list(PiiChecksumDetector().detect([seg]).spans)


def _types(text: str) -> set[str]:
    return {s.subtype for s in _spans(text)}


def _scored(text: str) -> set[tuple[str, float]]:
    return {(s.subtype, s.score) for s in _spans(text)}


def _confident(text: str) -> set[str]:
    return {s.subtype for s in _spans(text) if s.score >= MASK_THRESHOLD}


@pytest.mark.parametrize(
    ("digits", "expected"), [("11223344595", True), ("11223344596", False), ("00000000000", False)]
)
def test_snils_checksum(digits: str, expected: bool) -> None:
    assert valid_snils(digits) is expected


@pytest.mark.parametrize(
    ("digits", "expected"),
    [
        ("7707083893", True),
        ("7707083894", False),
        ("500100732259", True),
        ("500100732250", False),
        ("123", False),
    ],
)
def test_inn_checksum(digits: str, expected: bool) -> None:
    assert valid_inn(digits) is expected


@pytest.mark.parametrize(
    ("digits", "expected"),
    [("1027700132195", True), ("1027700132196", False), ("304500116000157", True)],
)
def test_ogrn_checksum(digits: str, expected: bool) -> None:
    assert valid_ogrn(digits) is expected


def test_luhn() -> None:
    assert valid_luhn("4111111111111111") is True
    assert valid_luhn("4111111111111112") is False
    assert valid_luhn("12345") is False


def test_detects_validated_identifiers_and_contacts() -> None:
    text = "СНИЛС 112-233-445 95, ИНН 7707083893, карта 4111 1111 1111 1111, почта ivan@example.ru, тел +7 (912) 345-67-89"
    found = _types(text)
    assert {"SNILS", "INN", "CREDIT_CARD", "EMAIL", "PHONE"} <= found


def test_invalid_checksums_and_random_numbers_are_ignored() -> None:
    assert _types("заказ 11223344596, артикул 7707083894, версия 1027700132197") == set()
    assert "INN" not in _types("id 1234567890")


def test_passport_requires_context() -> None:
    assert "PASSPORT" in _types("паспорт серия 45 12 номер 345678 выдан")
    assert "PASSPORT" not in _types("код 45 12 345678 в накладной")


def test_offsets_point_into_text() -> None:
    text = "email: a.b@c.io done"
    span = _spans(text)[0]
    assert text[span.start : span.end] == "a.b@c.io"


def test_pattern_set_hash_is_stable() -> None:
    assert len(PATTERN_SET_HASH) == 12
    assert PiiChecksumDetector.pattern_set_hash == PATTERN_SET_HASH


def test_context_free_identifier_is_audited_not_masked() -> None:
    # A check digit alone is satisfied by about one number in ten: an epoch
    # millisecond timestamp and an order number must not reach the mask threshold.
    assert _scored("1727007712782") == {("OGRN", 0.4)}
    assert _scored("order 8926137078") == {("INN", 0.4)}
    assert _confident("1727007712782") == set()
    assert _confident("order 8926137078") == set()


def test_context_word_and_written_format_raise_the_score() -> None:
    assert _scored("ИНН 7707123458") == {("INN", 1.0)}
    assert _scored("ОГРН 1027700132195") == {("OGRN", 1.0)}
    assert _scored("СНИЛС 112-233-445 95") == {("SNILS", 1.0)}
    # The written form of a SNILS is a format nothing else shares.
    assert _scored("112-233-445 95") == {("SNILS", 1.0)}
    assert _scored("11223344595") == {("SNILS", 0.4)}


def test_context_words_are_whole_words() -> None:
    # "winner", "syntax" and "инновации" contain a context word but do not name an identifier.
    assert _scored("the winner is 8926137078") == {("INN", 0.4)}
    assert _scored("syntax 8926137078") == {("INN", 0.4)}
    assert _scored("инновации 7707123458") == {("INN", 0.4)}
    assert _scored("налоговая 7707123458") == {("INN", 1.0)}
    assert _scored("INN:7707123458") == {("INN", 1.0)}


def test_credit_card_needs_an_issuer_prefix_and_one_separator() -> None:
    assert _scored("4111 1111 1111 1111") == {("CREDIT_CARD", 1.0)}
    assert _scored("карта 4111-1111-1111-1111") == {("CREDIT_CARD", 1.0)}
    assert _scored("4111111111111111") == {("CREDIT_CARD", 1.0)}
    # Luhn-valid with mixed separators: a date range, not a card.
    assert _spans("period 2024-04-30 2024-05-01 report") == []


def test_no_false_positives_over_generated_numbers() -> None:
    rnd = random.Random(1)
    timestamps = [str(rnd.randrange(1_600_000_000_000, 1_800_000_000_000)) for _ in range(300)]
    identifiers = [str(rnd.randrange(1_000_000_000, 9_999_999_999)) for _ in range(300)]
    flagged = [
        text for text in (*timestamps, *(f"order {i}" for i in identifiers)) if _confident(text)
    ]
    assert flagged == []


def test_corpus_recall_and_false_positive_ceiling() -> None:
    """Measured on tests/data/pii_corpus.json: recall 62/63 (0.984), benign 0/40.

    The one miss is a bare eleven-digit SNILS written without a context word, which
    the scoring scheme records at 0.4 on purpose.
    """
    corpus = json.loads(CORPUS.read_text("utf-8"))
    fragments = corpus["fragments"]
    hits: Counter[str] = Counter()
    expected: Counter[str] = Counter()
    for fragment in (f for f in fragments if f["group"] in ("ru", "en")):
        found = [s for s in _spans(fragment["text"]) if s.score >= MASK_THRESHOLD]
        for span in fragment["spans"]:
            if span["type"] not in SCORES:
                continue
            expected[span["type"]] += 1
            if any(
                s.subtype == span["type"] and s.start < span["end"] and span["start"] < s.end
                for s in found
            ):
                hits[span["type"]] += 1
    total = sum(expected.values())
    assert total >= 60, f"corpus carries too few supported spans: {expected}"
    recall = sum(hits.values()) / total
    assert recall >= 0.95, f"recall {sum(hits.values())}/{total} by type {hits} of {expected}"

    benign = [f for f in fragments if f["group"] == "benign"]
    flagged = [f["id"] for f in benign if _confident(f["text"])]
    assert len(flagged) / len(benign) <= 0.05, f"benign false positives {flagged}"


def test_corpus_invalid_identifiers_stay_below_the_mask_threshold() -> None:
    corpus = json.loads(CORPUS.read_text("utf-8"))
    for kind, values in corpus["meta"]["invalid_ids"].items():
        for value in values:
            assert _confident(value) == set(), f"{kind} {value}"

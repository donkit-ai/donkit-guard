from __future__ import annotations

import pytest

from donkit_guard.declared.spec import MAX_FINDINGS_PER_SEGMENT, TermsDetectorSpec
from donkit_guard.declared.terms import TermsDetector
from donkit_guard.findings import FindingClass
from donkit_guard.payload import Segment, SegmentSource, SegmentTrust

NAME = "declared:code-names"


def _longest_term(number: int) -> str:
    """A term of four words and 200 characters, the longest a declaration takes."""
    words = (f"{word}{number:04d}" for word in ("alpha", "bravo", "charlie", "delta"))
    return " ".join(words).ljust(200, "z")


# As many terms as a declaration takes, each of the longest kind.
LONGEST_LIST = tuple(_longest_term(number) for number in range(5000))


def _spec(*terms: str) -> TermsDetectorSpec:
    return TermsDetectorSpec.model_validate(
        {
            "kind": "terms",
            "id": "code-names",
            "title": "Project code names",
            "class": "corporate",
            "subtype": "CODE_NAME",
            "terms": terms,
            "score": 0.9,
        }
    )


@pytest.mark.parametrize(
    ("terms", "text", "expected"),
    [
        pytest.param(
            ("Альбатрос",),
            "Запуск проекта АЛЬБАТРОС в июне",
            ["АЛЬБАТРОС"],
            id="any-case",
        ),
        pytest.param(
            ("Альбатрос",),
            "Запуск проекта Aльбатрос в июне",  # noqa: RUF001
            ["Aльбатрос"],  # noqa: RUF001
            id="latin-look-alike-letter-in-a-cyrillic-word",
        ),
        pytest.param(
            ("Альбатрос*",),
            "Условия Альбатроса и Альбатросом",
            ["Альбатроса", "Альбатросом"],
            id="star-takes-any-ending",
        ),
        pytest.param(
            ("Альбатрос",),
            "Суперальбатрос и альбатросовый",
            [],
            id="not-inside-a-longer-word",
        ),
        pytest.param(
            ("Альбатрос Групп",),
            "Компания Альбатрос \t  Групп и партнеры",
            ["Альбатрос \t  Групп"],
            id="words-apart-by-any-whitespace",
        ),
        pytest.param(
            ("Альбатрос",),
            "​Альбатрос и партнеры",
            ["Альбатрос"],
            id="zero-width-character-before-the-term",
        ),
        pytest.param(
            ("Альбатрос",),
            "Запуск Аль​батрос",
            ["Аль​батрос"],
            id="zero-width-character-inside-the-term",
        ),
        pytest.param(
            ("Альбатрос*", "Альбатрос Групп"),
            "Альбатрос Групп и Альбатросом",
            ["Альбатрос Групп", "Альбатросом"],
            id="longest-of-the-terms-starting-together",
        ),
        pytest.param(
            ("Альбатрос Групп", "Альбатрос"),
            "Альбатрос Группы",
            ["Альбатрос"],
            id="shorter-term-where-the-longer-ends-inside-a-word",
        ),
        pytest.param(
            ("Групп Альбатрос", "Альбатрос"),
            "Подгрупп Альбатрос",
            ["Альбатрос"],
            id="a-match-inside-a-word-hides-no-later-term",
        ),
        pytest.param(
            ("Альбатрос",),
            "Альбатрос,Альбатрос",
            ["Альбатрос", "Альбатрос"],
            id="one-separator-between-two-occurrences",
        ),
        pytest.param(
            ("C#", ".NET"),
            "C#.NET",
            ["C#", ".NET"],
            id="punctuation-that-ends-one-occurrence-bounds-the-next",
        ),
        pytest.param(
            ("Альбатрос",),
            " ".join(["Альбатрос"] * (MAX_FINDINGS_PER_SEGMENT + 10)),
            ["Альбатрос"] * MAX_FINDINGS_PER_SEGMENT,
            id="findings-per-segment-are-capped",
        ),
        pytest.param(
            LONGEST_LIST,
            # Hundreds of kilobytes of lines that start like a term and are none.
            "alpha4999 bravo4999 charlie4999 echo\n" * 8_000 + LONGEST_LIST[-1],
            [LONGEST_LIST[-1]],
            id="the-longest-list-a-declaration-takes",
        ),
    ],
)
def test_terms_detector_cases(terms: tuple[str, ...], text: str, expected: list[str]) -> None:
    segment = Segment.of_text(text, source=SegmentSource.USER, trust=SegmentTrust.TRUSTED)
    findings = TermsDetector(_spec(*terms)).detect([segment])

    assert not findings.failed and findings.segments_scanned == 1
    # Offsets count code points of the original text, invisible characters included.
    assert [text[span.start : span.end] for span in findings.spans] == expected
    declared = (segment.id, FindingClass.CORPORATE, "CODE_NAME", 0.9, NAME)
    for span in findings.spans:
        assert (span.segment_id, span.cls, span.subtype, span.score, span.detector) == declared

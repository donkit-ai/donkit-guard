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


LEGAL_FORM = "Общество с ограниченной ответственностью"  # noqa: RUF001


def _company(number: int) -> str:
    """A company name under a long legal form, numbered in a hundred widths."""
    return f"{LEGAL_FORM} «Альфа-{number:0{1 + number % 100}d}»"


# A list of company names: they all start with the same long legal form, so every term shares
# its first eight characters with the others, in a hundred lengths.
COMPANIES = tuple(_company(number) for number in range(300))
# A listed company on every other line, and one under the same legal form that is not listed on
# the lines between.
COMPANY_LINES = "\n".join(
    f"{_company(number)}\n{_company(number + 300)}" for number in range(0, 300, 10)
)


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


def _segment(text: str) -> Segment:
    return Segment.of_text(text, source=SegmentSource.USER, trust=SegmentTrust.TRUSTED)


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
        pytest.param(
            COMPANIES,
            COMPANY_LINES,
            list(COMPANIES[::10]),
            id="many-lengths-under-one-long-prefix",
        ),
        pytest.param(
            COMPANIES,
            # Contract prose names the company by its legal form alone, over and over.
            "Общество обязуется передать, а Покупатель принять товар. " * 4_000,  # noqa: RUF001
            [],
            id="the-legal-form-alone-over-and-over",
        ),
    ],
)
def test_terms_detector_cases(terms: tuple[str, ...], text: str, expected: list[str]) -> None:
    segment = _segment(text)
    findings = TermsDetector(_spec(*terms)).detect([segment])

    assert not findings.failed and findings.segments_scanned == 1
    # Offsets count code points of the original text, invisible characters included.
    assert [text[span.start : span.end] for span in findings.spans] == expected
    declared = (segment.id, FindingClass.CORPORATE, "CODE_NAME", 0.9, NAME)
    for span in findings.spans:
        assert (span.segment_id, span.cls, span.subtype, span.score, span.detector) == declared


@pytest.mark.parametrize(
    "tail",
    [
        pytest.param("a", id="many-lengths"),
        # Folding turns this one character into eighteen, so the forms grow far longer than the
        # 200 characters a term may have: the work is the characters looked up, not the lookups.
        pytest.param("ﷺ", id="forms-that-fold-long"),
    ],
)
def test_a_list_crafted_to_need_too_much_work_fails_the_scan(tail: str) -> None:
    # Every character of the text could start one of these terms, and each such place looks up
    # every length under the prefix they share: they part right after it, so the text they all
    # start with is the prefix alone, which the text does go on with.
    crafted = ["!!!!!!!!" + chr(0x41 + length % 26) + tail * length for length in range(1, 192)]
    detector = TermsDetector(_spec("Альбатрос", *crafted))

    findings = detector.detect([_segment("Запуск проекта Альбатрос"), _segment("!" * 4096)])

    # The whole call fails: the finding in the first segment is not reported either.
    assert (findings.failed, findings.error, findings.spans) == (
        True,
        "terms scan exceeded its work limit",
        (),
    )

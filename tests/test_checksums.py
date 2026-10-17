from __future__ import annotations

import pytest

from donkit_guard.detectors.checksums import valid_iban
from donkit_guard.detectors.context import has_context, word_pattern


@pytest.mark.parametrize(
    ("value", "expected"),
    [
        ("GB82WEST12345698765432", True),
        ("GB82 WEST 1234 5698 7654 32", True),
        ("gb82 west 1234 5698 7654 32", True),
        ("DE89 3704 0044 0532 0130 00", True),
        ("GB83 WEST 1234 5698 7654 32", False),
        ("GB82 WEST", False),
        ("GB82 WEST 1234 5698 7654 3!", False),
        # Only spaces are ignored.
        ("GB82-WEST-1234-5698-7654-32", False),
        # A Cyrillic letter that looks like a Latin one is not a Latin letter.
        ("GB82 WЕST 1234 5698 7654 32", False),  # noqa: RUF001
        # The remainder is right, but the value opens with digits instead of a country code...
        ("1290 0000 0000 040", False),
        # ...or carries letters where the check digits belong.
        ("XXKE 0000 0000 000", False),
    ],
)
def test_iban_checksum(value: str, expected: bool) -> None:
    assert valid_iban(value) is expected


@pytest.mark.parametrize(
    ("bban_length", "expected"),
    [(10, False), (11, True), (30, True), (31, False)],
)
def test_iban_length_bounds(bban_length: int, expected: bool) -> None:
    # Zeros after "XX90" keep the mod-97 remainder at 1, so only the length varies.
    assert valid_iban("XX90" + "0" * bban_length) is expected


@pytest.mark.parametrize(
    ("forms", "text", "found"),
    [
        # A regex metacharacter in a word stands for itself.
        (["c++"], "we write c++ daily", True),
        (["c++"], "we write ccc daily", False),
        (["a.b"], "see a.b here", True),
        (["a.b"], "see axb here", False),
        # Only a trailing star is special.
        (["a*b"], "see a*b here", True),
        (["a*b"], "see aab here", False),
        # Case does not matter, and any of several words will do.
        (["Договор"], "ДОГОВОР 12", True),
        (["alpha", "beta"], "x BETA y", True),
        # A letter on either side makes it part of another word...
        (["договор"], "договор 12", True),
        (["договор"], "договора", False),
        (["договор"], "предоговор", False),
        (["inn"], "winner", False),
        (["inn"], "innovation", False),
        # ...a digit, punctuation or the end of the text does not.
        (["inn"], "INN7707123458", True),
        (["inn"], "inn:", True),
        # A trailing star lets the word run on, but it cannot start inside another word.
        (["договор*"], "договора", True),
        (["договор*"], "Договорам", True),
        (["договор*"], "предоговор", False),
        (["tax*"], "syntax", False),
    ],
)
def test_word_pattern_escapes_and_bounds(forms: list[str], text: str, found: bool) -> None:
    assert bool(word_pattern(forms).search(text)) is found


@pytest.mark.parametrize(
    ("forms", "reason"),
    [
        ([], "at least one"),
        ([""], "empty"),
        (["*"], "empty"),
        (["tax", ""], "empty"),
    ],
)
def test_word_pattern_rejects_a_missing_word(forms: list[str], reason: str) -> None:
    with pytest.raises(ValueError, match=reason):
        word_pattern(forms)


@pytest.mark.parametrize(
    ("text", "start", "end", "window", "found"),
    [
        # The word has to fit into the window whole, before the span...
        ("contract 1234", 9, 13, 9, True),
        ("contract 1234", 9, 13, 8, False),
        # ...and after it.
        ("1234 contract", 0, 4, 13, True),
        ("1234 contract", 0, 4, 8, False),
        # Without a window, a word that starts 40 characters before the span is near it.
        ("contract" + "." * 32 + "1234", 40, 44, None, True),
    ],
)
def test_has_context_window(
    text: str, start: int, end: int, window: int | None, found: bool
) -> None:
    pattern = word_pattern(["contract"])
    if window is None:
        assert has_context(text, start, end, pattern) is found
    else:
        assert has_context(text, start, end, pattern, window) is found

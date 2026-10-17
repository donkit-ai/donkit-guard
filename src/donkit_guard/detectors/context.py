"""Context words near a match: whole-word matching and the window they are looked for in."""

from __future__ import annotations

import re
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from collections.abc import Sequence

# Characters taken on each side of a match when looking for its context words.
CONTEXT_WINDOW = 40

# A letter in any script. It bounds a context word, so "inn" is not found inside "winner"
# or "innovation" but is found in "INN7707123458" and "inn:": digits and punctuation do
# not count as part of a word.
_LETTER = r"[^\W\d_]"


def word_pattern(forms: Sequence[str]) -> re.Pattern[str]:
    """A case-insensitive matcher for any of `forms`, each as a whole word.

    Every form is matched literally and may not touch a letter on either side. A trailing
    `*` lifts the right-hand bound, so `tax*` also finds `taxes` and `taxation`, though
    still not `syntax`. Each form needs at least one character besides that `*`.
    """
    if not forms:
        raise ValueError("word_pattern needs at least one word")
    alternatives: list[str] = []
    for form in forms:
        open_ended = form.endswith("*")
        stem = form[:-1] if open_ended else form
        if not stem:
            raise ValueError(f"a context word must not be empty: {form!r}")
        right_bound = "" if open_ended else f"(?!{_LETTER})"
        alternatives.append(f"(?<!{_LETTER}){re.escape(stem)}{right_bound}")
    return re.compile("|".join(alternatives), re.IGNORECASE)


def has_context(
    text: str, start: int, end: int, pattern: re.Pattern[str], window: int = CONTEXT_WINDOW
) -> bool:
    """Whether `pattern` occurs within `window` characters of the span `[start, end)`.

    The span itself is part of the window; a context word has to lie wholly inside it.
    """
    around = text[max(0, start - window) : min(len(text), end + window)]
    return pattern.search(around) is not None

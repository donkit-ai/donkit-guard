"""Checksum validators for identifier numbers, shared by built-in and declared detectors.

Every validator takes a string and answers whether its check digits hold. All but
`valid_iban` read digits only: hand them `digits_of(matched_text)`.
"""

from __future__ import annotations

import re
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from collections.abc import Callable

_NON_DIGITS = re.compile(r"\D+")


def digits_of(text: str) -> str:
    """The decimal digits of `text` in order, every other character dropped.

    Digits of any script are kept; the validators read them by value.
    """
    return _NON_DIGITS.sub("", text)


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


# Two letters, two check digits, then 11 to 30 letters or digits: 15 to 34 characters.
_IBAN_SHAPE = re.compile(r"[A-Za-z]{2}[0-9]{2}[A-Za-z0-9]{11,30}")


def valid_iban(text: str) -> bool:
    """Whether `text` is an IBAN as written: spaces are ignored and case does not matter.

    Beyond the shape, the number has to leave remainder 1 modulo 97 once the first four
    characters move to the end and every letter is replaced by its value, A=10 ... Z=35.
    """
    compact = text.replace(" ", "")
    if _IBAN_SHAPE.fullmatch(compact) is None:
        return False
    # Base-36 digits are exactly the IBAN letter values, in either case.
    numeric = "".join(str(int(char, 36)) for char in compact[4:] + compact[:4])
    return int(numeric) % 97 == 1


# `valid_iban` reads the number as written; the others read the digits of the match.
CHECKSUMS: dict[str, Callable[[str], bool]] = {
    "luhn": valid_luhn,
    "inn": valid_inn,
    "snils": valid_snils,
    "ogrn": valid_ogrn,
    "iban": valid_iban,
}

"""Recognizers that close the gaps of the stock Russian set (passport formats, initials, word dates, addresses) and the strict NANP phone format for English."""

from __future__ import annotations

from typing import TYPE_CHECKING, ClassVar

from presidio_analyzer import Pattern, PatternRecognizer
from presidio_analyzer.predefined_recognizers import CreditCardRecognizer, DateRecognizer
from presidio_ru_recognizers.checksums import inn10

if TYPE_CHECKING:
    from presidio_analyzer import RecognizerRegistry

MONTHS = "января|февраля|марта|апреля|мая|июня|июля|августа|сентября|октября|ноября|декабря"


class PassportRfV2Recognizer(PatternRecognizer):
    """Passport RF: 'серия 45 12 номер 345678', '45 12 345678', '4512 345678', '4512345678'."""

    PATTERNS: ClassVar[list[Pattern]] = [
        Pattern(
            "passport words",
            r"(?:серия|сер\.)\s*\d{2}\s?\d{2}\s*(?:,?\s*(?:номер|№|N|No\.?)\s*)\d{6}\b",
            0.6,
        ),
        Pattern("passport 2-2-6 / 4-6", r"\b\d{2}\s?\d{2}[\s\-]\d{6}\b", 0.5),
        Pattern("passport 4 № 6", r"\b\d{4}\s*(?:№|N|No\.?)\s*\d{6}\b", 0.6),
        Pattern("passport contiguous 10", r"(?<!\d)\d{10}(?!\d)", 0.3),
    ]
    CONTEXT: ClassVar[list[str]] = [
        "паспорт",
        "паспортный",
        "серия",
        "выдан",
        "документ",
        "удостоверение",
        "passport",
    ]

    def __init__(self) -> None:
        super().__init__(
            supported_entity="PASSPORT_RF",
            patterns=self.PATTERNS,
            context=self.CONTEXT,
            supported_language="ru",
            name="PassportRfV2Recognizer",
        )

    def invalidate_result(self, pattern_text: str) -> bool:
        digits = "".join(c for c in pattern_text if c.isdigit())
        # a contiguous 10-digit run that passes the INN-10 checksum is an INN, not a passport
        return len(digits) == 10 and pattern_text.isdigit() and inn10(digits)


class PersonInitialsRecognizer(PatternRecognizer):
    """'Иванов И.И.', 'Иванов И. И.', 'И. И. Иванов', 'И.И. Иванов' (Cyrillic)."""

    PATTERNS: ClassVar[list[Pattern]] = [
        Pattern(
            "surname initials", r"\b[А-ЯЁ][а-яё]+(?:-[А-ЯЁ][а-яё]+)?\s[А-ЯЁ]\.\s?[А-ЯЁ]\.", 0.6
        ),
        Pattern(
            "initials surname", r"\b[А-ЯЁ]\.\s?[А-ЯЁ]\.\s?[А-ЯЁ][а-яё]+(?:-[А-ЯЁ][а-яё]+)?\b", 0.6
        ),
    ]
    CONTEXT: ClassVar[list[str]] = [
        "фио",
        "сотрудник",
        "клиент",
        "подпись",
        "директор",
        "исполнитель",
        "контакт",
        "получатель",
    ]

    def __init__(self) -> None:
        super().__init__(
            supported_entity="PERSON",
            patterns=self.PATTERNS,
            context=self.CONTEXT,
            supported_language="ru",
            name="PersonInitialsRecognizer",
        )


class RuDateWordsRecognizer(PatternRecognizer):
    """'5 мая 1990 года', 'год рождения 1979' -> DATE_TIME (DOB context words boost the score)."""

    PATTERNS: ClassVar[list[Pattern]] = [
        Pattern("date words", rf"\b\d{{1,2}}\s(?:{MONTHS})\s\d{{4}}(?:\s?г\.|\sгода)?", 0.6),
        Pattern("birth year", r"(?:год|года)\s+рождения[:\s]+\d{4}\b", 0.85),
    ]
    CONTEXT: ClassVar[list[str]] = ["рожд", "родил", "родит", "д.р", "др.", "дата"]

    def __init__(self) -> None:
        super().__init__(
            supported_entity="DATE_TIME",
            patterns=self.PATTERNS,
            context=self.CONTEXT,
            supported_language="ru",
            name="RuDateWordsRecognizer",
        )


class RuAddressRecognizer(PatternRecognizer):
    """Street-level RU postal address: 'г. Москва, ул. Ленина, д. 5, кв. 12'."""

    STREET = r"(?:ул\.|улица|пр-т|пр\.|проспект|пер\.|переулок|наб\.|набережная|бульвар|б-р|шоссе|ш\.|площадь|пл\.)"
    HOUSE = r"(?:,?\s*(?:д\.|дом)?\s*\d{1,4}[а-яА-Я]?(?:/\d+)?)"
    KORP = r"(?:,?\s*(?:к\.|корп\.|корпус|стр\.|строение)\s*\d+)?"
    FLAT = r"(?:,?\s*(?:кв\.|квартира|оф\.|офис|пом\.)\s*\d+)?"
    CITY = r"(?:(?:г\.|город)\s*[А-ЯЁ][а-яё\-]+|[А-ЯЁ][а-яё]+-[А-ЯЁ][а-яё]+|[А-ЯЁ][а-яё]+)"
    PATTERNS: ClassVar[list[Pattern]] = [
        Pattern(
            "city street house",
            rf"{CITY},\s*(?:{STREET}\s*[А-ЯЁ][а-яё\-]+(?:\s[А-ЯЁ][а-яё\-]+)?|[А-ЯЁ][а-яё\-]+\s{STREET}){HOUSE}{KORP}{FLAT}",
            0.6,
        ),
        Pattern(
            "street house",
            rf"(?:{STREET}\s*[А-ЯЁ][а-яё\-]+(?:\s[А-ЯЁ][а-яё\-]+)?|[А-ЯЁ][а-яё\-]+\s{STREET}){HOUSE}{KORP}{FLAT}",
            0.5,
        ),
    ]
    CONTEXT: ClassVar[list[str]] = [
        "адрес",
        "проживает",
        "зарегистрирован",
        "доставка",
        "прописан",
        "место жительства",
    ]

    def __init__(self) -> None:
        super().__init__(
            supported_entity="LOCATION",
            patterns=self.PATTERNS,
            context=self.CONTEXT,
            supported_language="ru",
            name="RuAddressRecognizer",
        )


class UsPhoneStrictRecognizer(PatternRecognizer):
    """NANP formats: (212) 555-0142, 212-555-0142, 212 555 0142, +1-415-555-0199, +1 (646) 555-0177."""

    PATTERNS: ClassVar[list[Pattern]] = [
        Pattern("nanp", r"(?:\+1[\s\-.]?)?(?:\(\d{3}\)|\b\d{3})[\s\-.]?\d{3}[\s\-.]?\d{4}\b", 0.7),
    ]
    CONTEXT: ClassVar[list[str]] = [
        "phone",
        "number",
        "telephone",
        "cell",
        "mobile",
        "call",
        "contact",
        "reach",
    ]

    def __init__(self) -> None:
        super().__init__(
            supported_entity="PHONE_NUMBER",
            patterns=self.PATTERNS,
            context=self.CONTEXT,
            supported_language="en",
            name="UsPhoneStrictRecognizer",
        )

    def invalidate_result(self, pattern_text: str) -> bool:
        digits = "".join(c for c in pattern_text if c.isdigit())
        digits = digits[-10:]
        # NANP: area code and exchange cannot start with 0 or 1
        return digits[0] in "01" or digits[3] in "01"


def apply_tuning(registry: RecognizerRegistry) -> list[str]:
    """Mutate a registry built by engine.build_analyzer into the tuned configuration."""
    changes: list[str] = []
    # 1. passport: replace the package recognizer (regex only matches 4+6 / 10 contiguous)
    registry.remove_recognizer("PassportRfRecognizer")
    registry.add_recognizer(PassportRfV2Recognizer())
    changes.append("PassportRfRecognizer -> PassportRfV2Recognizer")
    # 2. drop the generic phonenumbers-based recognizer for ru (score 0.4 on any 10-digit run); PHONE_RF covers ru
    registry.recognizers = [
        r
        for r in registry.recognizers
        if not (r.name == "PhoneRecognizer" and r.supported_language == "ru")
    ]
    changes.append("PhoneRecognizer removed for ru")
    # 3. NHS checksum matches US phone numbers by chance
    registry.recognizers = [r for r in registry.recognizers if r.name != "NhsRecognizer"]
    changes.append("NhsRecognizer removed")
    # 4. credit cards in Russian text
    registry.add_recognizer(
        CreditCardRecognizer(
            supported_language="ru",
            context=["карта", "карты", "картой", "visa", "mastercard", "мир"],
        )
    )
    changes.append("CreditCardRecognizer added for ru")
    # 5. names with initials
    registry.add_recognizer(PersonInitialsRecognizer())
    changes.append("PersonInitialsRecognizer added")
    # 6. dates in words + DOB context on the numeric date recognizer
    registry.recognizers = [
        r
        for r in registry.recognizers
        if not (r.name == "DateRecognizer" and r.supported_language == "ru")
    ]
    registry.add_recognizer(
        DateRecognizer(
            supported_language="ru",
            context=["рожд", "родил", "родит", "д.р", "др.", "дата", "date"],
        )
    )
    registry.add_recognizer(RuDateWordsRecognizer())
    registry.recognizers = [
        r
        for r in registry.recognizers
        if not (r.name == "DateRecognizer" and r.supported_language == "en")
    ]
    registry.add_recognizer(
        DateRecognizer(
            supported_language="en", context=["date", "birthday", "birth", "born", "dob"]
        )
    )
    changes.append("DateRecognizer(ru/en) with DOB context + RuDateWordsRecognizer")
    # 8. strict NANP phone formats for en (the phonenumbers-based recognizer caps at 0.4 + context)
    registry.add_recognizer(UsPhoneStrictRecognizer())
    changes.append("UsPhoneStrictRecognizer added for en")
    # 7. street addresses
    registry.add_recognizer(RuAddressRecognizer())
    changes.append("RuAddressRecognizer added")
    return changes

"""Declared detectors: the ``detectors:`` section of a policy document, as typed data.

A policy document can describe detectors instead of shipping code for them. This module is
the data model and its structural checks only: field shapes and limits. Compiling patterns,
running examples and reaching a remote service happen where the detectors are built.
"""

from __future__ import annotations

import hashlib
import json
from functools import cached_property
from typing import TYPE_CHECKING, Annotated, Any, Literal, Self
from urllib.parse import urlsplit

from pydantic import AfterValidator, ConfigDict, Field, StringConstraints, model_validator

from donkit_guard.context import FrozenModel
from donkit_guard.findings import ENFORCEABLE_CLASSES, FindingClass

if TYPE_CHECKING:
    from collections.abc import Mapping

# Limits per policy document.
MAX_DETECTORS = 20
MAX_REMOTE_DETECTORS = 3
# Findings one declared detector reports in one segment: a text full of matches stays bounded.
MAX_FINDINGS_PER_SEGMENT = 50
# Match and no-match examples of one detector together.
MAX_EXAMPLES = 20


def _require_enforceable(value: FindingClass) -> FindingClass:
    if value not in ENFORCEABLE_CLASSES:
        allowed = ", ".join(sorted(c.value for c in ENFORCEABLE_CLASSES))
        raise ValueError(
            f"a detector may only report enforceable classes ({allowed}), not {value.value!r}"
        )
    return value


def _check_word_form(value: str) -> str:
    if not value.removesuffix("*").strip():
        raise ValueError("a trailing '*' must follow a word")
    return value


def _check_endpoint(value: str) -> str:
    if any(ch.isspace() or not ch.isprintable() or ch == "\\" for ch in value):
        raise ValueError("endpoint must not contain spaces, control characters or backslashes")
    try:
        parts = urlsplit(value)
        _ = parts.port  # urlsplit validates the port only when it is read
    except ValueError as exc:
        raise ValueError(f"endpoint is not a valid URL: {exc}") from exc
    if parts.scheme not in ("http", "https"):
        raise ValueError("endpoint must be an http or https URL")
    if not parts.hostname:
        raise ValueError("endpoint must name a host")
    if "@" in parts.netloc or parts.query or parts.fragment:
        raise ValueError(
            "endpoint must not carry a user, password, query or fragment; "
            "put the token in a credential, not in the URL"
        )
    return value


_SLUG = r"^[a-z0-9][a-z0-9-]{0,63}$"

DetectorId = Annotated[str, StringConstraints(pattern=_SLUG)]
DetectorTitle = Annotated[str, StringConstraints(min_length=1, max_length=80)]
Subtype = Annotated[str, StringConstraints(pattern=r"^[A-Z][A-Z0-9_]{0,39}$")]
CredentialName = Annotated[str, StringConstraints(pattern=_SLUG)]
EnforceableClass = Annotated[FindingClass, AfterValidator(_require_enforceable)]
Endpoint = Annotated[str, StringConstraints(max_length=2048), AfterValidator(_check_endpoint)]
EntityType = Annotated[str, StringConstraints(min_length=1, max_length=64)]
PatternText = Annotated[str, StringConstraints(min_length=1, max_length=500)]
Term = Annotated[
    str,
    StringConstraints(strip_whitespace=True, min_length=1, max_length=200),
    AfterValidator(_check_word_form),
]
Word = Annotated[
    str,
    StringConstraints(strip_whitespace=True, min_length=1, max_length=64),
    AfterValidator(_check_word_form),
]
KeyGlob = Annotated[str, StringConstraints(min_length=1, max_length=64)]
Example = Annotated[str, StringConstraints(max_length=1000)]
Score = Annotated[float, Field(ge=0.0, le=1.0)]


class DetectorExamples(FrozenModel):
    """Texts that pin down what a declaration means.

    Every ``match`` text must yield a finding and no ``no_match`` text may. They are checked
    when the document is loaded, so an edit that changes the declared behavior is rejected.
    """

    match: tuple[Example, ...] = ()
    no_match: tuple[Example, ...] = ()

    @model_validator(mode="after")
    def _within_the_limit(self) -> DetectorExamples:
        total = len(self.match) + len(self.no_match)
        if total > MAX_EXAMPLES:
            raise ValueError(f"at most {MAX_EXAMPLES} examples in all, got {total}")
        return self


class EntityMapping(FrozenModel):
    """The class and subtype a remote service's entity type is reported as."""

    model_config = ConfigDict(populate_by_name=True)

    cls: EnforceableClass = Field(alias="class")
    subtype: Subtype


class _Declaration(FrozenModel):
    """What every kind of declaration has: the digest that tells its versions apart."""

    @cached_property
    def digest(self) -> str:
        """A short digest of the declaration: any edit to it changes the digest.

        It is computed once per instance and kept, since the engine needs it for every
        declaration of a document on every evaluation.
        """
        canonical = json.dumps(
            self.model_dump(mode="json", by_alias=True), sort_keys=True, ensure_ascii=False
        )
        return hashlib.sha256(canonical.encode("utf-8")).hexdigest()[:12]

    def model_copy(self, *, update: Mapping[str, Any] | None = None, deep: bool = False) -> Self:
        copied = super().model_copy(update=update, deep=deep)
        if update:
            # An edited copy declares something other than the original, whose kept digest it
            # would otherwise carry along.
            copied.__dict__.pop("digest", None)
        return copied


class PatternDetectorSpec(_Declaration):
    """Finds text with RE2 patterns, verified and weighed by what surrounds it.

    ``patterns`` are RE2 expressions (no lookaround, no backreferences) tried as alternatives.
    A match is dropped when it fails ``checksum`` or has an ``exclude`` word near it. It scores
    ``score`` when a ``context`` word is near it, or when no context is asked for, and
    ``score_without_context`` otherwise. ``json_keys`` are globs on the JSON object key a value
    sits under: such a value is reported whole instead of being searched.
    """

    model_config = ConfigDict(populate_by_name=True)

    kind: Literal["pattern"]
    id: DetectorId
    title: DetectorTitle
    cls: EnforceableClass = Field(alias="class")
    subtype: Subtype
    patterns: tuple[PatternText, ...] = Field(default=(), max_length=10)
    checksum: Literal["luhn", "inn", "snils", "ogrn", "iban"] | None = None
    context: tuple[Word, ...] = Field(default=(), max_length=50)
    exclude: tuple[Word, ...] = Field(default=(), max_length=50)
    json_keys: tuple[KeyGlob, ...] = Field(default=(), max_length=20)
    score: Score = 0.8
    score_without_context: Score = 0.4
    examples: DetectorExamples = Field(default_factory=DetectorExamples)

    @model_validator(mode="after")
    def _has_something_to_match(self) -> PatternDetectorSpec:
        if not self.patterns and not self.json_keys:
            raise ValueError("a pattern detector needs patterns or json_keys")
        return self

    @model_validator(mode="after")
    def _match_examples_need_patterns(self) -> PatternDetectorSpec:
        if self.examples.match and not self.patterns:
            raise ValueError(
                "examples test patterns; a detector with only json_keys takes no match examples"
            )
        return self


class TermsDetectorSpec(_Declaration):
    """Finds the words of a list, whatever their case and Latin/Cyrillic look-alike letters.

    A term matches whole words only; a trailing ``*`` lets it stand for any ending of its
    last word.
    """

    model_config = ConfigDict(populate_by_name=True)

    kind: Literal["terms"]
    id: DetectorId
    title: DetectorTitle
    cls: EnforceableClass = Field(alias="class")
    subtype: Subtype
    terms: tuple[Term, ...] = Field(min_length=1, max_length=5000)
    score: Score = 0.8
    examples: DetectorExamples = Field(default_factory=DetectorExamples)


class RemoteDetectorSpec(_Declaration):
    """Delegates detection to a service that speaks the analyze contract.

    ``entities`` maps each entity type the service reports to the class and subtype of the
    finding; types it does not list are ignored. ``credential`` names a secret the host holds,
    never its value, and the URL carries no credentials. ``timeout_ms`` bounds the wait for the
    service and ``cache_ttl_s`` how long its answer for a text is reused (0 never reuses it).
    With ``required`` false, a failed call is recorded as unchecked instead of failing the
    decision.
    """

    kind: Literal["remote"]
    id: DetectorId
    title: DetectorTitle
    endpoint: Endpoint
    credential: CredentialName | None = None
    entities: dict[EntityType, EntityMapping] = Field(min_length=1, max_length=50)
    timeout_ms: int = Field(default=2000, ge=100, le=30_000)
    required: bool = True
    cache_ttl_s: int = Field(default=3600, ge=0, le=86_400)


DetectorSpec = Annotated[
    PatternDetectorSpec | TermsDetectorSpec | RemoteDetectorSpec, Field(discriminator="kind")
]


def spec_digest(spec: DetectorSpec) -> str:
    """A short digest of a declaration: any edit to it changes the digest."""
    return spec.digest

"""Secret rules loaded from the vendored gitleaks TOML and the extra pattern list."""

from __future__ import annotations

import hashlib
import json
import math
import re
import tomllib
from collections import Counter
from dataclasses import dataclass
from functools import lru_cache
from importlib import resources
from re import Pattern
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from collections.abc import Callable


def _bound_generic_value(regex: str) -> str:
    """Bound the open-ended base64 alternative in the value class of ``generic-api-key``.

    ``[a-z0-9+/]{11,}`` has no upper bound, so on a long base64 line every candidate
    backtracks across the whole token. 1000 is the largest repetition count the Go
    engine accepts, which keeps the bounded form a legal rule upstream as well.
    """
    return regex.replace("[a-z0-9+/]{11,}", "[a-z0-9+/]{11,1000}")


# Rules whose regex needs a hand edit beyond the mechanical translation. Value: a
# callable that rewrites the raw regex, or None to drop the rule. Every id the
# vendored file carries is either loaded or named here, so that a version bump
# cannot remove a rule unnoticed.
GITLEAKS_OVERRIDES: dict[str, Callable[[str], str] | None] = {
    "generic-api-key": _bound_generic_value,
    # Matches a file name, not content: there is nothing to look for in a payload.
    "pkcs12-file": None,
}

_LEADING_FLAGS = re.compile(r"^\(\?([a-z]+)\)")

# POSIX classes are a nested set for Python `re`, which changes what the rule matches.
_POSIX_CLASSES: dict[str, str] = {
    "[:alnum:]": "a-zA-Z0-9",
    "[:alpha:]": "a-zA-Z",
    "[:digit:]": "0-9",
    "[:xdigit:]": "0-9a-fA-F",
    "[:upper:]": "A-Z",
    "[:lower:]": "a-z",
    "[:space:]": r"\s",
    "[:word:]": r"\w",
}


def _scope_inline_flags(regex: str) -> str:
    r"""Rewrite each mid-pattern ``(?i)`` (legal in RE2, not in Python) as ``(?i:...)``.

    The scoped group runs to the end of the enclosing group, which is what RE2
    means by a mid-pattern flag. Escapes are skipped so ``\(`` does not count
    as a group.
    """
    out: list[str] = []
    pending: list[int] = []
    depth = 0
    i = 0
    while i < len(regex):
        if regex[i] == "\\" and i + 1 < len(regex):
            out.append(regex[i : i + 2])
            i += 2
            continue
        if regex.startswith("(?i)", i):
            out.append("(?i:")
            pending.append(depth)
            i += 4
            continue
        ch = regex[i]
        if ch == "(":
            depth += 1
        elif ch == ")":
            while pending and pending[-1] == depth:
                out.append(")")
                pending.pop()
            depth -= 1
        elif ch == "|" and pending and pending[-1] == depth:
            # the flag also covers the following alternative of the same group
            out.append(")|(?i:")
            i += 1
            continue
        out.append(ch)
        i += 1
    while pending:
        out.append(")")
        pending.pop()
    return "".join(out)


def _go_to_py(regex: str) -> tuple[str, int]:
    r"""Translate the Go RE2 dialect used by gitleaks into Python `re` syntax.

    Leading `(?i)` becomes `re.IGNORECASE`; a mid-pattern `(?i)` (22 rules)
    becomes a scoped inline group; `\z` (3 rules) becomes `\Z`; POSIX classes
    become their explicit ranges; `(?-i)` is dropped.
    """
    flags = 0
    leading = _LEADING_FLAGS.match(regex)
    if leading and "i" in leading.group(1):
        flags |= re.IGNORECASE
        regex = regex[leading.end() :]
    regex = regex.replace("(?-i)", "")
    for posix, expanded in _POSIX_CLASSES.items():
        regex = regex.replace(posix, expanded)
    regex = _scope_inline_flags(regex)
    regex = regex.replace(r"\z", r"\Z")
    return regex, flags


ALLOWLIST_TARGETS: frozenset[str] = frozenset({"secret", "match", "line"})


@dataclass(frozen=True)
class Allowlist:
    """A gitleaks allowlist entry, reduced to the criteria a payload can answer.

    ``target`` names what the regexes are tested against: the captured secret, the
    whole rule match, or the segment text (gitleaks tests the source line there).
    Stopwords always test the secret. ``require_all`` is the ``AND`` condition: every
    criterion the entry names has to hold, instead of any one of them.
    """

    regexes: tuple[Pattern[str], ...]
    stopwords: tuple[str, ...]
    target: str
    require_all: bool

    def allows(self, secret: str, match: str, line: str) -> bool:
        subject = {"match": match, "line": line}.get(self.target, secret)
        met: list[bool] = []
        if self.regexes:
            met.append(any(regex.search(subject) for regex in self.regexes))
        if self.stopwords:
            lowered = secret.lower()
            met.append(any(word in lowered for word in self.stopwords))
        if not met:
            return False
        return all(met) if self.require_all else any(met)


@dataclass(frozen=True)
class SecretRule:
    id: str
    description: str
    regex: Pattern[str]
    keywords: tuple[str, ...]
    secret_group: int
    entropy: float | None
    allowlists: tuple[Allowlist, ...]
    score: float
    generic: bool


def shannon_entropy(text: str) -> float:
    if not text:
        return 0.0
    counts = Counter(text)
    length = len(text)
    return -sum((c / length) * math.log2(c / length) for c in counts.values())


def _compile_allowlist_entry(raw: dict[str, Any]) -> Allowlist | None:
    """Translate one allowlist table, or None when it says nothing about content.

    Paths and commits describe a source tree, not a payload, so they are no criterion
    here. Under ``AND`` they still are one — an entry that also demands a path can
    never be satisfied — so such an entry is dropped rather than half-applied.
    """
    require_all = str(raw.get("condition", "OR")).upper() == "AND"
    if require_all and (raw.get("paths") or raw.get("commits")):
        return None
    regexes: list[Pattern[str]] = []
    for item in raw.get("regexes", []):
        py, flags = _go_to_py(str(item))
        try:
            regexes.append(re.compile(py, flags | re.ASCII))
        except re.error:
            continue
    stopwords = tuple(str(word).lower() for word in raw.get("stopwords", []))
    if not regexes and not stopwords:
        return None
    target = str(raw.get("regexTarget", "secret")).lower()
    return Allowlist(
        regexes=tuple(regexes),
        stopwords=stopwords,
        target=target if target in ALLOWLIST_TARGETS else "secret",
        require_all=require_all,
    )


def _compile_allowlists(raw: dict[str, Any]) -> tuple[Allowlist, ...]:
    """Both spellings: a single ``allowlist`` table and the ``allowlists`` list."""
    tables: list[dict[str, Any]] = []
    single = raw.get("allowlist")
    if isinstance(single, dict):
        tables.append(single)
    plural = raw.get("allowlists")
    if isinstance(plural, list):
        tables.extend(item for item in plural if isinstance(item, dict))
    compiled = (_compile_allowlist_entry(table) for table in tables)
    return tuple(entry for entry in compiled if entry is not None)


def _rule_from_gitleaks(raw: dict[str, Any]) -> SecretRule | None:
    rule_id = str(raw.get("id", ""))
    if not rule_id:
        return None
    if rule_id in GITLEAKS_OVERRIDES:
        override = GITLEAKS_OVERRIDES[rule_id]
        if override is None:
            return None
        regex_text = override(str(raw.get("regex", "")))
    else:
        regex_text = str(raw.get("regex", ""))
    if not regex_text:
        return None
    py, flags = _go_to_py(regex_text)
    try:
        # ASCII: Go's \w, \d and \b never match beyond ASCII, and a Unicode \w turns
        # every Cyrillic or CJK word into a candidate value for the generic rules.
        compiled = re.compile(py, flags | re.ASCII)
    except re.error:
        return None
    keywords = tuple(str(k).lower() for k in raw.get("keywords", []))
    entropy = raw.get("entropy")
    generic = rule_id.startswith("generic-")
    return SecretRule(
        id=rule_id,
        description=str(raw.get("description", "")),
        regex=compiled,
        keywords=keywords,
        secret_group=int(raw.get("secretGroup", 0) or 0),
        entropy=float(entropy) if entropy is not None else None,
        allowlists=_compile_allowlists(raw),
        score=0.7 if generic else 1.0,
        generic=generic,
    )


def _prefilter_keywords(regex_text: str, keywords: tuple[str, ...]) -> tuple[str, ...]:
    """Keep the keywords that the pattern itself spells out.

    Such a keyword comes with every match, so skipping a text without it is free. A
    vendor name that the pattern never mentions is a label for the reader: gating on
    it would hide a bare token pasted without any surrounding words.
    """
    lowered = regex_text.lower()
    return tuple(keyword for keyword in keywords if keyword in lowered)


def _rule_from_extra(raw: dict[str, Any]) -> SecretRule:
    regex_text = str(raw["regex"])
    keywords = tuple(str(k).lower() for k in raw.get("keywords", []))
    return SecretRule(
        id=str(raw["id"]),
        description=str(raw.get("description", "")),
        regex=re.compile(regex_text, re.ASCII),
        keywords=_prefilter_keywords(regex_text, keywords),
        secret_group=int(raw.get("secret_group", 0)),
        entropy=None,
        allowlists=(),
        score=float(raw.get("score", 1.0)),
        generic=False,
    )


_QUOTED_VALUE = r"(?:\"([^\"\s]{8,150})\"|'([^'\s]{8,150})'|\x60([^\x60\s]{8,150})\x60)"

# Formats that neither rule file can express, kept next to the loader so that a rule
# set is always the vendored data plus exactly these.
_BUILTIN_RULES: tuple[SecretRule, ...] = (
    # A quoted value may hold any punctuation, while the vendored generic rule accepts
    # only `[\w.=-]` inside a value, so `password = "ipY4X1%92Ky%P4"` is invisible to
    # it. Quotes and entropy keep prose out, and a purely alphabetic value is dropped.
    SecretRule(
        id="generic-password-quoted",
        description="Quoted credential value assigned to a password- or token-like name",
        regex=re.compile(
            r"(?:passw(?:or)?d|secret|token|api[_-]?key|access[_-]?key|credential)"
            r"(?:[ \t\w.-]{0,20})[ \t]{0,3}(?:=|:{1,3}=|:|=>|\?=)[ \t]{0,5}"
            + _QUOTED_VALUE
            + r"(?:[\s;,)]|$)",
            re.IGNORECASE | re.ASCII,
        ),
        keywords=(
            "password",
            "passwd",
            "secret",
            "token",
            "api_key",
            "api-key",
            "apikey",
            "access_key",
            "access-key",
            "accesskey",
            "credential",
        ),
        secret_group=0,
        entropy=3.5,
        allowlists=(
            Allowlist(
                regexes=(re.compile(r"^[a-zA-Z_.-]+$"),),
                stopwords=(),
                target="secret",
                require_all=False,
            ),
        ),
        score=0.7,
        generic=True,
    ),
    # Cache and database URLs authenticate without a user name (`redis://:pw@host`),
    # which the vendored URL pattern cannot express: it requires a user name.
    SecretRule(
        id="basic-auth-url-no-user",
        description="Password in a URL authority that carries no user name",
        regex=re.compile(r"://:([^{}\s/@]{4,})@", re.ASCII),
        keywords=("://:",),
        secret_group=1,
        entropy=None,
        allowlists=(),
        score=0.9,
        generic=False,
    ),
)


def _data_text(name: str) -> str:
    return resources.files("donkit_guard.detectors.data").joinpath(name).read_text("utf-8")


@lru_cache(maxsize=1)
def load_rules() -> tuple[SecretRule, ...]:
    toml_text = _data_text("gitleaks.toml")
    document = tomllib.loads(toml_text)
    rules: list[SecretRule] = []
    for raw in document.get("rules", []):
        rule = _rule_from_gitleaks(raw)
        if rule is not None:
            rules.append(rule)
    for raw in json.loads(_data_text("extra_patterns.json")):
        rules.append(_rule_from_extra(raw))
    rules.extend(_BUILTIN_RULES)
    return tuple(rules)


@lru_cache(maxsize=1)
def load_global_allowlists() -> tuple[Allowlist, ...]:
    """The file-level allowlist, which gitleaks applies to a match of any rule."""
    return _compile_allowlists(tomllib.loads(_data_text("gitleaks.toml")))


def _ruleset_hash() -> str:
    material = (
        _data_text("gitleaks.toml")
        + _data_text("extra_patterns.json")
        + ",".join(
            f"{key}:{'drop' if value is None else 'rewrite'}"
            for key, value in sorted(GITLEAKS_OVERRIDES.items())
        )
        + ",".join(f"{rule.id}:{rule.regex.pattern}" for rule in _BUILTIN_RULES)
    )
    return hashlib.sha256(material.encode("utf-8")).hexdigest()[:12]


RULESET_HASH: str = _ruleset_hash()

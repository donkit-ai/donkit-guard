"""Secrets detector: community rule set, own scanning loop tuned for chat payloads."""

from __future__ import annotations

import base64
import binascii
import re
import urllib.parse
from itertools import chain
from typing import TYPE_CHECKING

from donkit_guard.detectors.base import register_detector, spans_overlap
from donkit_guard.detectors.secrets_rules import (
    RULESET_HASH,
    Allowlist,
    SecretRule,
    load_global_allowlists,
    load_rules,
    shannon_entropy,
)
from donkit_guard.findings import FindingClass, Findings, FindingSpan

if TYPE_CHECKING:
    from collections.abc import Sequence

    from donkit_guard.payload import Segment

MAX_GENERIC_TOKEN_LEN = 512
MAX_HITS_PER_SEGMENT = 50

# Media and opaque blobs are cut out before scanning: they are not text a model
# reads, and high-entropy runs inside them are never secrets.
_DATA_URI = re.compile(r"data:[a-zA-Z0-9.+-]+/[a-zA-Z0-9.+-]+;base64,[A-Za-z0-9+/=]+")
_LONG_BASE64_BLOB = re.compile(r"(?<![A-Za-z0-9+/=])[A-Za-z0-9+/]{4000,}={0,2}(?![A-Za-z0-9+/=])")
_DECODABLE_B64 = re.compile(
    r"(?<![A-Za-z0-9+/=_-])[A-Za-z0-9+/_-]{24,2000}={0,2}(?![A-Za-z0-9+/=_-])"
)
_HEX_BLOB = re.compile(r"(?<![0-9a-fA-F])[0-9a-fA-F]{40,2000}(?![0-9a-fA-F])")
_PRINTABLE_RATIO = 0.9


def _blank(text: str, pattern: re.Pattern[str]) -> str:
    return pattern.sub(lambda m: " " * len(m.group(0)), text)


def suppress(text: str) -> str:
    """Replace opaque blobs by spaces so offsets stay valid for the original text."""
    text = _blank(text, _DATA_URI)
    text = _blank(text, _LONG_BASE64_BLOB)
    return text


def _looks_like_text(candidate: bytes) -> bool:
    if not candidate:
        return False
    printable = sum(32 <= b < 127 or b in (9, 10, 13) for b in candidate)
    return printable / len(candidate) >= _PRINTABLE_RATIO


def decode_layers(text: str) -> list[tuple[str, str]]:
    """One level of base64 / hex / URL decoding of embedded tokens that decode to text."""
    layers: list[tuple[str, str]] = []
    for match in _DECODABLE_B64.finditer(text):
        token = match.group(0)
        padded = token + "=" * (-len(token) % 4)
        try:
            raw = base64.b64decode(padded.replace("-", "+").replace("_", "/"), validate=False)
        except (binascii.Error, ValueError):
            continue
        if _looks_like_text(raw):
            layers.append(("base64", raw.decode("utf-8", errors="replace")))
    for match in _HEX_BLOB.finditer(text):
        try:
            raw = bytes.fromhex(match.group(0))
        except ValueError:
            continue
        if _looks_like_text(raw):
            layers.append(("hex", raw.decode("utf-8", errors="replace")))
    if "%" in text:
        decoded = urllib.parse.unquote(text)
        if decoded != text:
            layers.append(("url", decoded))
    return layers


def _secret_group(rule: SecretRule, match: re.Match[str]) -> int:
    """The group holding the secret: the declared one, else the first non-empty capture."""
    if rule.secret_group and rule.secret_group <= (match.re.groups or 0):
        return rule.secret_group
    for index, captured in enumerate(match.groups(), start=1):
        if captured:
            return index
    return 0


def _match_rule(
    rule: SecretRule, text: str, lowered: str, globals_: Sequence[Allowlist] = ()
) -> list[tuple[int, int, float]]:
    if rule.keywords and not any(keyword in lowered for keyword in rule.keywords):
        return []
    hits: list[tuple[int, int, float]] = []
    for match in rule.regex.finditer(text):
        group = _secret_group(rule, match)
        secret = match.group(group)
        if not secret:
            continue
        if rule.generic and len(secret) > MAX_GENERIC_TOKEN_LEN:
            continue
        # A rule's entropy is a floor the secret has to clear, not a threshold it may meet.
        if rule.entropy is not None and shannon_entropy(secret) <= rule.entropy:
            continue
        if any(
            allow.allows(secret, match.group(0), text) for allow in chain(rule.allowlists, globals_)
        ):
            continue
        start, end = match.span(group)
        hits.append((start, end, rule.score))
        if len(hits) >= MAX_HITS_PER_SEGMENT:
            break
    return hits


LOW_CONFIDENCE_SUBTYPE = "low-confidence-entropy"
LOW_CONFIDENCE_SCORE = 0.3
_BARE_B64_TOKEN = re.compile(r"(?<![A-Za-z0-9+/=])[A-Za-z0-9+/]{40,64}={0,2}(?![A-Za-z0-9+/=])")
_BARE_HEX_TOKEN = re.compile(r"(?<![0-9a-fA-F])[0-9a-fA-F]{64}(?![0-9a-fA-F])")
# A base64 alphabet holds 64 symbols and a hex one 16, so the same token length
# carries a different amount of entropy in each and needs its own floor.
_BARE_B64_ENTROPY = 4.5
_BARE_HEX_ENTROPY = 3.0
# DER and SSH public material starts this way and is published on purpose.
_PUBLIC_MATERIAL_PREFIXES = ("MII", "AAAA")


class SecretsDetector:
    """Keyword-anchored rule engine over the vendored rule set.

    Overlapping matches of a specific rule and a `generic-*` rule keep the specific
    one (gitleaks semantics). Bare high-entropy tokens without any keyword or format
    are reported as low-confidence spans so that policies can audit them without
    masking legitimate identifiers.
    """

    name = "secrets"
    version = "1"
    classes = frozenset({FindingClass.SECRET})
    remote = False
    pattern_set_hash = RULESET_HASH

    def __init__(self) -> None:
        # Specific rules first so that an overlapping generic match can be dropped.
        self._rules = tuple(sorted(load_rules(), key=lambda rule: rule.generic))
        self._globals = load_global_allowlists()

    def _low_confidence(
        self, segment: Segment, text: str, taken: list[tuple[int, int]]
    ) -> list[FindingSpan]:
        spans: list[FindingSpan] = []
        for pattern, floor in (
            (_BARE_B64_TOKEN, _BARE_B64_ENTROPY),
            (_BARE_HEX_TOKEN, _BARE_HEX_ENTROPY),
        ):
            for match in pattern.finditer(text):
                start, end = match.span()
                if spans_overlap(start, end, taken):
                    continue
                token = match.group(0)
                if token.startswith(_PUBLIC_MATERIAL_PREFIXES):
                    continue
                if shannon_entropy(token) <= floor:
                    continue
                spans.append(
                    FindingSpan(
                        segment_id=segment.id,
                        path=segment.path,
                        start=start,
                        end=end,
                        cls=FindingClass.SECRET,
                        subtype=LOW_CONFIDENCE_SUBTYPE,
                        score=LOW_CONFIDENCE_SCORE,
                        detector=self.name,
                    )
                )
        return spans

    def _scan_text(
        self, segment: Segment, text: str, layer: str, base: tuple[int, int] | None
    ) -> list[FindingSpan]:
        clean = suppress(text)
        lowered = clean.lower()
        spans: list[FindingSpan] = []
        taken: list[tuple[int, int]] = []
        for rule in self._rules:
            for start, end, score in _match_rule(rule, clean, lowered, self._globals):
                if rule.generic and spans_overlap(start, end, taken):
                    continue
                taken.append((start, end))
                if base is not None:
                    start, end = base
                spans.append(
                    FindingSpan(
                        segment_id=segment.id,
                        path=segment.path,
                        start=start,
                        end=end,
                        cls=FindingClass.SECRET,
                        subtype=rule.id if layer == "text" else f"{rule.id}:{layer}",
                        score=score,
                        detector=self.name,
                    )
                )
        if layer == "text":
            spans.extend(self._low_confidence(segment, clean, taken))
        return spans

    def detect(self, segments: Sequence[Segment]) -> Findings:
        spans: list[FindingSpan] = []
        scanned = 0
        for segment in segments:
            if segment.text is None or segment.uninspected or segment.hashlike():
                continue
            scanned += 1
            spans.extend(self._scan_text(segment, segment.text, "text", None))
            for layer, decoded in decode_layers(segment.text):
                spans.extend(self._scan_text(segment, decoded, layer, (0, len(segment.text))))
        return Findings(
            detector=self.name,
            version=self.version,
            pattern_set_hash=self.pattern_set_hash,
            spans=tuple(spans),
            segments_scanned=scanned,
        )


register_detector(SecretsDetector)

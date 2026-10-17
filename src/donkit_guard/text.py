"""Text normalization shared by detectors.

``normalize`` folds a text for matching: NFKC, zero-width removal, lower-casing and per-token
Latin/Cyrillic confusable re-mapping. The result keeps a map from every output character back
to its index in the original text, so a match can be reported against the original.

The injection heuristic hashes ``ZERO_WIDTH`` and ``LAT_TO_CYR`` into its pattern-set hash, so
editing either table changes that hash and calls for a corpus re-run.
"""

from __future__ import annotations

import re
import unicodedata
from dataclasses import dataclass

ZERO_WIDTH = frozenset("​‌‍⁠﻿­᠎⁡⁢⁣⁤")

# Lowercase confusables. Unambiguous letters decide the script of a token; the
# confusables inside it are re-mapped to that script.
# Classic lowercase confusables (identical glyphs in most fonts): Latin -> Cyrillic.
LAT_TO_CYR = {"a": "а", "c": "с", "e": "е", "o": "о", "p": "р", "x": "х", "y": "у"}
# Cyrillic -> Latin: the classic seven plus non-Russian Cyrillic lookalikes (і ј ѕ һ ԁ ԛ ԝ).
CYR_TO_LAT = {v: k for k, v in LAT_TO_CYR.items()} | {
    "і": "i",
    "ј": "j",
    "ѕ": "s",
    "һ": "h",
    "ԁ": "d",
    "ԛ": "q",
    "ԝ": "w",
}
# Letters that exist in exactly one script decide a token's script.
CYR_UNAMBIG = set("бвгдёжзийклмнптфцчшщъыьэюя")
LAT_UNAMBIG = set("bdfghijklmnqrstuvwz")

_WORD = re.compile(r"\w+", re.UNICODE)


@dataclass
class NormalizedText:
    text: str
    offsets: list[int]  # offsets[i] -> index in original text
    zero_width_count: int
    remapped_tokens: int  # tokens where confusables were re-mapped (mixed script)
    mixed_script_tokens: int  # tokens with unambiguous letters of BOTH scripts


def normalize(text: str) -> NormalizedText:
    """Fold ``text`` for matching.

    Applies NFKC, drops zero-width characters and lower-cases. Within a token, Latin and
    Cyrillic look-alike letters are re-mapped to the script that its unambiguous letters
    (or, failing those, the surrounding text) indicate. In the result, ``offsets[i]`` is the
    index in ``text`` of output character ``i``.
    """
    chars: list[str] = []
    offsets: list[int] = []
    zw = 0
    for i, ch in enumerate(text):
        if ch in ZERO_WIDTH:
            zw += 1
            continue
        for c in unicodedata.normalize("NFKC", ch):
            for lc in c.lower():
                chars.append(lc)
                offsets.append(i)
    remapped = 0
    mixed = 0
    joined = "".join(chars)
    text_cyr = sum(1 for c in joined if c in CYR_UNAMBIG)
    text_lat = sum(1 for c in joined if c in LAT_UNAMBIG)
    for m in _WORD.finditer(joined):
        tok = m.group(0)
        if tok.isascii():
            continue  # pure ASCII: nothing to re-map (also skips base64 / JSON keys)
        cyr_u = sum(1 for c in tok if c in CYR_UNAMBIG)
        lat_u = sum(1 for c in tok if c in LAT_UNAMBIG)
        has_lat_conf = any(c in LAT_TO_CYR for c in tok)
        has_cyr_conf = any(c in CYR_TO_LAT for c in tok)
        if cyr_u and lat_u:
            mixed += 1
        target: str | None = None
        if cyr_u > lat_u and has_lat_conf:
            target = "cyr"
        elif lat_u > cyr_u and has_cyr_conf:
            target = "lat"
        elif cyr_u == lat_u == 0 and has_lat_conf and has_cyr_conf:
            # only confusables, from both scripts ("cоре"): natural text never does this,
            # so follow the script of the whole text
            target = "cyr" if text_cyr >= text_lat else "lat"
        if target is None:
            continue
        table = LAT_TO_CYR if target == "cyr" else CYR_TO_LAT
        changed = False
        for k in range(m.start(), m.end()):
            c = chars[k]
            if c in table:
                chars[k] = table[c]
                changed = True
        if changed:
            remapped += 1
    return NormalizedText("".join(chars), offsets, zw, remapped, mixed)

"""Pattern families for the injection heuristic (RU/EN), with normalisation and scoring.

Ported from the measured spike detector; any change to PATTERNS or the weights
changes PATTERN_SET_HASH and must be accompanied by a corpus re-run.
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import json
import re
import unicodedata
from dataclasses import asdict, dataclass, field
from typing import Any

DETECTOR_NAME = "injection-heuristic"
DETECTOR_VERSION = 1
DEFAULT_THRESHOLD = 0.5

UM, DOC, TR = "user_message", "document", "tool_result"
ALL_SOURCES = frozenset({UM, DOC, TR})
CONTENT_SOURCES = frozenset({DOC, TR})  # third-party content: directives to the AI are never legit

# Third-party content (documents, tool results) has no business addressing the model,
# so the same directive is weighted higher there than in a user message.
SOURCE_BOOST = {UM: 1.0, DOC: 1.15, TR: 1.15}

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


@dataclass(frozen=True)
class Pattern:
    family: str
    pid: str
    regex: str
    weight: float
    sources: frozenset[str] = ALL_SOURCES

    def compiled(self) -> re.Pattern[str]:
        return re.compile(self.regex, re.IGNORECASE | re.UNICODE | re.MULTILINE)


G40 = r"[^\n.!?]{0,40}?"
G30 = r"[^\n.!?]{0,30}?"
G25 = r"[^\n.!?]{0,25}?"
G60 = r"[^\n.!?]{0,60}?"
G100 = r"[^\n.!?]{0,100}?"

# ---- EN building blocks ----
EN_OVERRIDE_VERB = r"\b(?:ignore|disregard|forget|discard|override|bypass|set aside|drop|abandon)\b"
EN_OVERRIDE_QUAL = r"\b(?:all|any|your|previous|prior|above|earlier|preceding|initial|original|system|hidden|safety|these|those|every|existing)\b"
EN_OVERRIDE_OBJ = r"\b(?:instructions?|directions?|rules?|guidelines?|prompts?|restrictions?|constraints?|guidance|directives?|orders?|training|programming|policies|policy|limitations?|filters?)\b"
EN_EXFIL_VERB = r"\b(?:show\w*|reveal\w*|print\w*|output\w*|display\w*|repeat\w*|quot\w+|tell me|give me|send me|forward\w*|list\w*|dump\w*|leak\w*|expos\w+|shar\w+|translat\w+|past\w+|disclos\w+|recit\w+|spell out|write out|what is|what's|what are|what were|what was|echo\w*)"
EN_POSSESSIVE = r"\b(?:your|its|the assistant'?s|the model'?s)\b"
EN_GENERIC_LINK = (
    r"\b(?:the|all|every|these|my|complete|full|entire|hidden|secret|original|initial)\b"
)
EN_SECRET_OBJ = r"\b(?:system prompts?|system messages?|system instructions?|initial (?:instructions?|prompts?)|original (?:instructions?|prompts?)|hidden (?:rules?|instructions?|configuration|prompts?|guidelines?)|secret (?:instructions?|rules?|prompts?)|developer (?:messages?|prompts?|instructions?)|pre-?prompts?|instructions you were given|rules you were given|environment variables?|env vars?|\.env\b|api[ _-]?keys?|access tokens?|secret keys?|credentials|connection strings?|passwords?|hidden configuration)"
EN_BARE_OBJ = r"\b(?:instructions?|rules?|prompts?|guidelines?|configuration|config|directives?|settings|context|secrets?|tokens?)\b"
EN_HARD_OBJ = r"(?:\.env\b|environment variables?|env vars?|api[ _-]?keys?|credentials|connection strings?|system prompts?|developer (?:messages?|prompts?)|secret keys?|access tokens?)"

# ---- RU building blocks ----
RU_OVERRIDE_VERB = r"\b(?:игнорируй|проигнорируй|игнорируйте|забудь|забудьте|отбрось|отбросьте|отмени|отмените|не учитывай|не обращай внимания на|пренебреги|отключи|обойди)\b"
RU_OVERRIDE_QUAL = r"\b(?:все|всё|любые|свои|твои|предыдущ\w+|прежн\w+|прошл\w+|ранн\w+|первоначальн\w+|исходн\w+|системн\w+|скрыт\w+|вышеуказанн\w+|вышеизложенн\w+|существующ\w+|текущ\w+)\b"
RU_OVERRIDE_OBJ = r"\b(?:инструкци\w*|правил\w*|указани\w*|установк\w*|ограничени\w*|промпт\w*|директив\w*|приказ\w*|настройк\w*|запрет\w*|фильтр\w*|политик\w*)\b"
RU_EXFIL_VERB = r"\b(?:покаж\w+|показ\w+|вывед\w+|вывод\w*|напечата\w+|отобраз\w+|повтор\w+|процитир\w+|расскаж\w+|скаж\w+|назов\w+|перечисл\w+|перешл\w+|перес\w+|отправ\w+|пришл\w+|выда\w+|раскро\w+|слей|слив\w*|перевед\w+|вставь|продикт\w+|какой|какая|какие|каков|что за|что у тебя|дай|озвучь|воспроизвед\w+)"
RU_POSSESSIVE = r"\b(?:свой|свои|свою|своей|своих|своё|твой|твои|твою|твоей|твоих|твоё|у тебя|тебе|ассистента)\b"
RU_GENERIC_LINK = r"\b(?:все|всё|полный|полностью|полную|скрыт\w+|секретн\w+|исходн\w+|первоначальн\w+|содержимое|мне|его)\b"
RU_SECRET_OBJ = r"\b(?:системн\w+ промпт\w*|системн\w+ сообщени\w+|системн\w+ инструкци\w+|первоначальн\w+ (?:инструкци\w+|промпт\w*)|исходн\w+ (?:инструкци\w+|промпт\w*)|скрыт\w+ (?:правил\w*|инструкци\w+|конфигураци\w+|промпт\w*|указани\w+|установк\w+)|секретн\w+ (?:инструкци\w+|правил\w*|ключ\w*)|сообщени\w+ разработчика|промпт\w* разработчика|конфигураци\w+|переменн\w+ окружения|\.env\b|api[ _-]?ключ\w*|api[ _-]?keys?|токен\w*|учётн\w+ данн\w+|учетн\w+ данн\w+|строк\w+ подключения|парол\w+)"
RU_BARE_OBJ = r"\b(?:инструкци\w+|правил\w*|промпт\w*|указани\w+|конфигураци\w+|конфиг\w*|настройк\w+|директив\w+|контекст\w*|секрет\w*)\b"
RU_HARD_OBJ = r"(?:\.env\b|переменн\w+ окружения|api[ _-]?ключ\w*|api[ _-]?keys?|учётн\w+ данн\w+|учетн\w+ данн\w+|строк\w+ подключения|системн\w+ промпт\w*|промпт\w* разработчика|сообщени\w+ разработчика|секретн\w+ ключ\w*)"

PATTERNS: list[Pattern] = [
    # ================= override / ignore =================
    Pattern(
        "override",
        "en.ignore_prev",
        EN_OVERRIDE_VERB + G40 + EN_OVERRIDE_QUAL + G40 + EN_OVERRIDE_OBJ,
        0.6,
    ),
    Pattern(
        "override",
        "en.new_instructions",
        r"\b(?:new|updated|revised) (?:instructions?|rules?|directives?|system prompt)\s*[:\-—]",
        0.5,
    ),
    Pattern(
        "override",
        "en.rules_no_longer_apply",
        r"\b(?:previous|prior|earlier|above|old) (?:rules?|instructions?|directives?|guidelines?) (?:no longer|don'?t|do not) apply\b",
        0.6,
    ),
    Pattern(
        "override",
        "en.supersedes",
        r"\b(?:supersed\w+|replac\w+|overrid\w+) (?:all )?(?:previous|prior|earlier|existing) (?:instructions?|rules?|prompts?|system prompts?|ones)\b",
        0.6,
    ),
    Pattern("override", "en.new_system_prompt", r"\bnew system prompt\b", 0.5),
    Pattern(
        "override",
        "en.forget_told",
        r"\bforget (?:everything|all|what) (?:you|that you) (?:were|have been|had been) told\b",
        0.5,
    ),
    Pattern(
        "override",
        "en.instead_of_task",
        r"\bstop (?:summarizing|answering|translating|processing) and instead\b",
        0.5,
    ),
    Pattern(
        "override",
        "ru.ignore_prev",
        RU_OVERRIDE_VERB + G40 + RU_OVERRIDE_QUAL + G40 + RU_OVERRIDE_OBJ,
        0.6,
    ),
    Pattern(
        "override",
        "ru.new_instructions",
        r"\b(?:новые|обновлённые|обновленные) (?:инструкции|правила|указания|системный промпт)\s*[:\-—]",
        0.5,
    ),
    Pattern(
        "override",
        "ru.rules_no_longer_apply",
        r"\b(?:прежние|предыдущие|старые|прошлые) (?:правила|инструкции|указания|ограничения) (?:больше не|не) (?:действуют|применяются|актуальны|работают)\b",
        0.6,
    ),
    Pattern(
        "override",
        "ru.supersedes",
        r"\b(?:заменяет|отменяет|перекрывает|замещает) (?:все |всё )?(?:предыдущие|прежние|существующие|ранние) (?:инструкции|правила|промпты|системные промпты)\b",
        0.6,
    ),
    Pattern("override", "ru.new_system_prompt", r"\bновый системный промпт\b", 0.5),
    Pattern(
        "override",
        "ru.forget_told",
        r"\bзабудь (?:всё|все),? что (?:тебе|ты) (?:говорили|сказали|слышал|поручили|дали)\b",
        0.5,
    ),
    Pattern(
        "override",
        "ru.instead_of_task",
        r"\bпрекрати (?:пересказ|перевод|отвечать|обработку|суммаризацию) и вместо этого\b",
        0.5,
    ),
    # ================= persona hijack =================
    Pattern(
        "persona",
        "en.from_now_on_you_are",
        r"\b(?:from now on|starting now|henceforth|for the rest of this (?:chat|conversation|session))\b"
        + G30
        + r"\byou are\b",
        0.45,
    ),
    Pattern("persona", "en.you_are_now", r"\byou are now\b", 0.35),
    Pattern(
        "persona",
        "en.dan",
        r"\b(?:do anything now|stay in character|no restrictions|never refuses?|without (?:any )?(?:restrictions|limitations|filters|refusals)|unrestricted (?:assistant|ai|mode|model)|jailbreak|jailbroken|god mode|developer mode enabled)\b",
        0.45,
    ),
    Pattern(
        "persona",
        "en.roleplay_secret",
        r"\b(?:pretend|act|roleplay|role-play|play the role of|behave) (?:as|to be|you are|like)?"
        + G60
        + r"\b(?:no (?:restrictions|rules|limits|filters)|unrestricted|jailbroken|without (?:restrictions|rules|limits|filters)|system prompt|hidden|secret)\b",
        0.45,
    ),
    Pattern(
        "persona",
        "ru.from_now_on_you_are",
        r"\b(?:с этого момента|отныне|теперь|начиная с этого момента)\b"
        + G30
        + r"\bты\s*[-—–]?\s*(?:dan|\w+ без ограничений|больше не|не ассистент)",
        0.45,
    ),
    Pattern(
        "persona",
        "ru.dan",
        r"\b(?:без (?:каких-либо |всяких |любых )?ограничений|нет (?:никаких )?ограничений|никогда не отказыва\w+|оставайся в роли|не выходи из роли|режим разработчика|jailbreak|без цензуры|бог-режим)\b",
        0.45,
    ),
    Pattern(
        "persona",
        "ru.roleplay_secret",
        r"\b(?:сыграй|играй|притворись|представь,? что ты|веди себя как|войди в роль|изобрази)\b"
        + G100
        + r"\b(?:без ограничений|без правил|системн\w+ промпт\w*|скрыт\w+|секретн\w+|jailbreak)\b",
        0.45,
    ),
    # ================= exfiltration =================
    Pattern(
        "exfil", "en.verb_poss_bare", EN_EXFIL_VERB + G40 + EN_POSSESSIVE + G25 + EN_BARE_OBJ, 0.55
    ),
    Pattern(
        "exfil",
        "en.verb_link_secret",
        EN_EXFIL_VERB
        + G40
        + r"(?:"
        + EN_POSSESSIVE
        + "|"
        + EN_GENERIC_LINK
        + ")"
        + G25
        + EN_SECRET_OBJ,
        0.6,
    ),
    Pattern(
        "exfil",
        "en.verb_hard",
        r"\b(?:show|reveal|print|output|display|dump|leak|expose|forward|send|paste|list|disclose)\w*\b"
        + G30
        + EN_HARD_OBJ,
        0.55,
    ),
    Pattern(
        "exfil",
        "en.system_sent_you",
        r"\b(?:what|which) (?:text|message|instructions?|prompt)"
        + G40
        + r"\b(?:system|developer|operator) (?:sent|gave|told|provided)\b",
        0.5,
    ),
    Pattern(
        "exfil",
        "en.before_first_message",
        r"\bbefore (?:my|the|this) (?:first|initial) message\b",
        0.5,
    ),
    Pattern(
        "exfil",
        "en.repeat_above",
        r"\b(?:repeat|print|output|show|quote|echo)\w*"
        + G25
        + r"\b(?:everything|all(?: of)?(?: the)? text|the text|all) (?:above|before|preceding)\b",
        0.6,
    ),
    Pattern("exfil", "en.starting_from_you_are", r"\bstarting (?:from|with) ['\"«]?you are\b", 0.5),
    Pattern(
        "exfil",
        "en.given_instructions",
        r"\b(?:instructions?|rules?) (?:you|that you) (?:were|have been|had been) given\b",
        0.45,
    ),
    Pattern("exfil", "en.verbatim", r"\b(?:verbatim|word for word)\b", 0.2),
    Pattern(
        "exfil", "ru.verb_poss_bare", RU_EXFIL_VERB + G40 + RU_POSSESSIVE + G25 + RU_BARE_OBJ, 0.55
    ),
    Pattern(
        "exfil",
        "ru.verb_link_secret",
        RU_EXFIL_VERB
        + G40
        + r"(?:"
        + RU_POSSESSIVE
        + "|"
        + RU_GENERIC_LINK
        + ")"
        + G25
        + RU_SECRET_OBJ,
        0.6,
    ),
    Pattern(
        "exfil",
        "ru.verb_hard",
        r"\b(?:покаж\w+|показ\w+|вывед\w+|вывод\w*|напечата\w+|отобраз\w+|перешл\w+|перес\w+|отправ\w+|пришл\w+|выда\w+|раскро\w+|слей|слив\w*|перевед\w+|перечисл\w+|раскр\w+)\b"
        + G30
        + RU_HARD_OBJ,
        0.55,
    ),
    Pattern(
        "exfil",
        "ru.system_sent_you",
        r"\b(?:какой|что за|какие|какое) (?:текст|сообщение|инструкции|промпт)"
        + G40
        + r"\b(?:систем\w+|разработчик\w*|оператор\w*)\b",
        0.5,
    ),
    Pattern(
        "exfil", "ru.before_first_message", r"\bдо (?:моего|твоего|этого) первого сообщения\b", 0.5
    ),
    Pattern(
        "exfil",
        "ru.repeat_above",
        r"\b(?:повтор\w+|вывед\w+|напечата\w+|процитир\w+)"
        + G25
        + r"\b(?:всё|все|весь текст|текст),? что (?:написано |было |идёт )?(?:выше|до|перед)\b",
        0.6,
    ),
    Pattern("exfil", "ru.starting_from_words", r"\bначиная со слов\b", 0.45),
    Pattern(
        "exfil",
        "ru.given_instructions",
        r"\b(?:инструкции|правила|указания),? которые тебе (?:дали|задали|выдали|прописали)\b",
        0.45,
    ),
    Pattern("exfil", "ru.verbatim", r"\b(?:дословно|слово в слово)\b", 0.2),
    # ================= authority impersonation =================
    Pattern("authority", "en.system_override", r"\bsystem override\b", 0.5),
    Pattern(
        "authority",
        "en.this_is_dev",
        r"\b(?:this is|it'?s) (?:the|your) (?:developer|administrator|admin|operator|system|creator) (?:speaking|here|talking)\b",
        0.5,
    ),
    Pattern(
        "authority",
        "en.i_am_vendor",
        r"\bi am (?:an? )?(?:openai|anthropic|google|microsoft|meta|deepmind) (?:engineer|employee|researcher|developer|staff)\b",
        0.5,
    ),
    Pattern(
        "authority",
        "en.authorized_test",
        r"\bauthori[sz]ed (?:red[- ]team|penetration|security|pen) test\b",
        0.45,
    ),
    Pattern(
        "authority",
        "en.safety_off",
        r"\b(?:safety|content|moderation) (?:mode|filters?) (?:is|are|has been|have been) (?:now )?(?:disabled|off|turned off|deactivated)\b",
        0.5,
    ),
    Pattern(
        "authority", "en.hash_admin", r"#{2,}\s*(?:admin|system|root|sudo|developer)\s*#{2,}", 0.5
    ),
    Pattern("authority", "en.bracket_system", r"^\s*\[(?:system|admin|developer|root)\]\s*$", 0.5),
    Pattern(
        "authority", "en.elevated", r"\belevated privileges (?:confirmed|granted|enabled)\b", 0.5
    ),
    Pattern(
        "authority",
        "en.maintenance_mode",
        r"\b(?:maintenance|debug|developer|god|sudo|root) mode\b",
        0.4,
    ),
    Pattern(
        "authority",
        "en.must_comply",
        r"\b(?:must|will) comply with (?:all|every|any) requests?\b",
        0.5,
    ),
    Pattern("authority", "en.without_refusals", r"\bwithout refusals?\b", 0.4),
    Pattern(
        "authority", "en.per_policy", r"\b(?:per|under|according to) policy [a-z]{1,4}-\d+\b", 0.4
    ),
    Pattern(
        "authority",
        "any.chat_template",
        r"(?:<\|im_start\|>\s*system|<\|system\|>|<<sys>>|\[inst\]|^#{1,3}\s*system\s*$)",
        0.5,
    ),
    Pattern("authority", "ru.system_message", r"\bсистемное сообщение\s*:", 0.5),
    Pattern(
        "authority",
        "ru.this_is_dev",
        r"\b(?:говорит|с вами говорит|на связи) (?:разработчик|администратор|админ|оператор|система|создатель)\b",
        0.5,
    ),
    Pattern(
        "authority",
        "ru.i_am_vendor",
        r"\bя (?:инженер|сотрудник|разработчик|исследователь) (?:openai|anthropic|google|microsoft|яндекс\w*|сбер\w*)\b",
        0.5,
    ),
    Pattern(
        "authority",
        "ru.authorized_test",
        r"\bсанкционированн\w+ (?:red[- ]team|пентест|тест безопасности)\b",
        0.45,
    ),
    Pattern(
        "authority",
        "ru.safety_off",
        r"\bрежим безопасности (?:отключ\w+|выключ\w+|деактивир\w+)\b",
        0.5,
    ),
    Pattern(
        "authority", "ru.hash_admin", r"#{2,}\s*(?:админ|система|рут|разработчик)\s*#{2,}", 0.5
    ),
    Pattern(
        "authority",
        "ru.elevated",
        r"\bповышенные привилегии (?:подтверждены|выданы|включены|активированы)\b",
        0.5,
    ),
    Pattern(
        "authority", "ru.maintenance_mode", r"\bрежим (?:обслуживания|отладки|разработчика)\b", 0.4
    ),
    Pattern(
        "authority",
        "ru.must_comply",
        r"\bобязан\w* (?:выполнять|исполнять) (?:все|любые) запросы\b",
        0.5,
    ),
    Pattern("authority", "ru.without_refusals", r"\bбез отказов\b", 0.4),
    Pattern("authority", "ru.per_policy", r"\b(?:согласно|по) политике [a-zа-я]{1,4}-\d+\b", 0.4),
    # ================= tool coercion =================
    Pattern(
        "tool_coercion",
        "en.dont_ask_user",
        r"\b(?:do not|don'?t|without|never) (?:ask|asking|confirm|confirming|notify|notifying|check|checking with|inform|informing) (?:the )?(?:user|human|owner|operator|customer)\b",
        0.55,
    ),
    Pattern(
        "tool_coercion",
        "en.without_asking",
        r"\b(?:proceed|continue|do it|execute|run it) without (?:asking|confirmation|approval)\b",
        0.5,
    ),
    Pattern(
        "tool_coercion",
        "en.already_consented",
        r"\b(?:the )?(?:user|admin|owner|operator|administrator|customer) (?:has |have )?already (?:consented|approved|agreed|confirmed|authori[sz]ed)\b",
        0.55,
    ),
    Pattern(
        "tool_coercion",
        "en.no_need_confirm",
        r"\bno need to (?:confirm|ask|verify|double[- ]check)\b",
        0.45,
    ),
    Pattern(
        "tool_coercion",
        "en.skip_verification",
        r"\bskip (?:the )?(?:verification|confirmation|approval|check|validation)\b",
        0.5,
    ),
    Pattern(
        "tool_coercion",
        "en.grant_admin",
        r"\bgrant (?:the )?(?:admin|administrator|root|full|superuser) (?:role|access|rights|privileges)\b",
        0.55,
    ),
    Pattern(
        "tool_coercion",
        "en.exfil_conversation",
        r"\b(?:forward|send|post|upload|exfiltrate|transfer|copy|email)\w*"
        + G30
        + r"\b(?:conversation|chat|messages?|history|transcript|context)\b"
        + G40
        + r"\bto\b",
        0.55,
    ),
    Pattern(
        "tool_coercion",
        "en.dangerous_tool",
        r"\b(?:call|invoke|run|use|using|execute|via|through|with)\w*"
        + G40
        + r"\b(?:transfer_funds|drop table|delete_email|rm -rf|truncate table|drop database)\b",
        0.55,
    ),
    Pattern(
        "tool_coercion", "en.instead_call", r"\binstead,? (?:call|use|run|invoke|execute)\b", 0.5
    ),
    Pattern(
        "tool_coercion",
        "ru.dont_ask_user",
        r"\b(?:(?:не спрашивай|не уточняй|не подтверждай|не уведомляй|не сообщай) (?:у )?(?:пользовател\w+|человека|владельца|оператора|клиента)|пользовател\w+ не (?:спрашивай|уведомляй|сообщай))\b",
        0.55,
    ),
    Pattern(
        "tool_coercion",
        "ru.without_asking",
        r"\b(?:действуй|продолжай|выполняй|сделай) без (?:вопросов|подтверждения|уточнений)\b",
        0.5,
    ),
    Pattern(
        "tool_coercion",
        "ru.already_consented",
        r"\b(?:пользователь|админ|администратор|владелец|оператор|клиент) (?:уже )?(?:дал согласие|согласился|одобрил|подтвердил|разрешил)\b",
        0.55,
    ),
    Pattern(
        "tool_coercion", "ru.no_need_confirm", r"\bподтверждать не (?:нужно|надо|требуется)\b", 0.45
    ),
    Pattern(
        "tool_coercion",
        "ru.skip_verification",
        r"\bпропусти (?:проверку|подтверждение|верификацию|валидацию)\b",
        0.5,
    ),
    Pattern(
        "tool_coercion",
        "ru.grant_admin",
        r"\b(?:выдай|назначь|предоставь|дай)"
        + G30
        + r"\b(?:роль|права|доступ) (?:admin|администратора|админа|root|суперпользователя)\b",
        0.55,
    ),
    Pattern(
        "tool_coercion",
        "ru.exfil_conversation",
        r"\b(?:перешл\w+|перес\w+|отправ\w+|выгруз\w+|переда\w+|скопир\w+)"
        + G30
        + r"\b(?:диалог\w*|переписк\w*|сообщени\w+|истори\w+|контекст\w*|транскрипт\w*)\b"
        + G40
        + r"\b(?:на|по адресу|в|к)\b",
        0.55,
    ),
    Pattern(
        "tool_coercion",
        "ru.dangerous_tool",
        r"\b(?:вызови|вызов\w+|запусти|использу\w+|выполни|через|с помощью)"
        + G40
        + r"\b(?:transfer_funds|drop table|delete_email|rm -rf|truncate table|drop database)\b",
        0.55,
    ),
    Pattern(
        "tool_coercion",
        "ru.instead_call",
        r"\bвместо этого (?:немедленно )?(?:вызови|используй|запусти|выполни)\b",
        0.5,
    ),
    # ================= directives embedded in content (documents / tool results) =================
    Pattern(
        "doc_directive",
        "en.if_you_are_ai",
        r"\bif you are an? (?:ai|llm|language model|assistant|bot|automated system|chatbot)\b",
        0.55,
    ),
    Pattern(
        "doc_directive",
        "en.note_to_ai",
        r"\b(?:note|message|instructions?|attention) (?:to|for) (?:the |any |all )?(?:ai|llm|assistant|automated|screening|language model|chatbot|agent)",
        0.55,
    ),
    Pattern(
        "doc_directive",
        "en.ai_colon_directive",
        r"\b(?:ai|llm|assistant|ai agents?|agents?|bots?|chatbots?|models?)\s*[:,]\s*(?:ignore|disregard|your new|stop|tell|reply|respond|when|do not|don'?t|never|always|call|use|print|reveal|output)\b",
        0.55,
    ),
    Pattern(
        "doc_directive",
        "en.system_colon",
        r"\bsystem\s*:\s*(?:grant|ignore|you|reveal|execute|call|run|disable|override|new|print|output|the user)\b",
        0.55,
    ),
    Pattern(
        "doc_directive",
        "en.important_for_llm",
        r"\bimportant for (?:the )?(?:llm|ai|assistant|model|agent)s?\b",
        0.5,
    ),
    Pattern(
        "doc_directive",
        "en.your_new_instruction",
        r"\byour new (?:instructions?|task|goal|objective) (?:is|are)\b",
        0.55,
    ),
    Pattern(
        "doc_directive",
        "en.reading_this",
        r"\b(?:reading|processing|summarizing|parsing) this (?:document|email|page|file|text|message)\b",
        0.35,
    ),
    Pattern(
        "doc_directive",
        "en.assistant_must",
        r"\bthe (?:assistant|ai|model|agent) (?:must|should|has to|needs to)\b",
        0.4,
    ),
    Pattern(
        "doc_directive",
        "en.ignore_user",
        r"\b(?:ignore|disregard) the user'?s? (?:question|request|message|instructions?|query)\b",
        0.6,
    ),
    Pattern(
        "doc_directive",
        "en.reply_only_with",
        r"\b(?:reply|respond|answer) only with\b",
        0.3,
        CONTENT_SOURCES,
    ),
    Pattern(
        "doc_directive",
        "en.tell_the_user",
        r"\btell the user (?:that|to|they)\b",
        0.35,
        CONTENT_SOURCES,
    ),
    Pattern(
        "doc_directive",
        "ru.if_you_are_ai",
        r"\bесли ты (?:ии|искусственный интеллект|llm|языковая модель|ассистент|бот|нейросеть|чат-?бот|ии[- ]?ассистент\w*)\b",
        0.55,
    ),
    Pattern(
        "doc_directive",
        "ru.note_to_ai",
        r"\b(?:примечание|сообщение|инструкци\w+|указани\w+|внимание) (?:для|к) (?:ии|llm|ассистент\w*|автоматическ\w+|нейросет\w+|языков\w+ модел\w+|бот\w*|чат-?бот\w*|агент\w*)",
        0.55,
    ),
    Pattern(
        "doc_directive",
        "ru.ai_colon_directive",
        r"\b(?:ии|llm|ассистент|ии[- ]?агент\w*|агент\w*|бот\w*|модел\w+|нейросет\w+)\s*[:,]\s*(?:проигнорируй|игнорируй|твоя новая|прекрати|скажи|ответь|отвечай|при |не |никогда|всегда|вызови|используй|выведи|покажи|раскрой)",
        0.55,
    ),
    Pattern(
        "doc_directive",
        "ru.system_colon",
        r"\bсистема\s*:\s*(?:выдай|игнорируй|проигнорируй|ты|раскрой|выполни|вызови|отключи|новые|выведи|покажи)\b",
        0.55,
    ),
    Pattern(
        "doc_directive",
        "ru.important_for_llm",
        r"\bважно для (?:llm|ии|ассистента|нейросети|модели|агента)\b",
        0.5,
    ),
    Pattern(
        "doc_directive",
        "ru.your_new_instruction",
        r"\bтвоя новая (?:инструкция|задача|цель)\b",
        0.55,
    ),
    Pattern(
        "doc_directive",
        "ru.reading_this",
        r"\b(?:читающ\w+|обрабатывающ\w+|пересказыва\w+) (?:этот|данный|это) (?:документ|файл|текст|письмо|сообщение)\b",
        0.35,
    ),
    Pattern(
        "doc_directive",
        "ru.assistant_must",
        r"\b(?:ассистент|ии|модель|агент) (?:должен|должна|обязан|обязана)\b",
        0.4,
    ),
    Pattern(
        "doc_directive",
        "ru.ignore_user",
        r"\b(?:проигнорируй|игнорируй) (?:вопрос|запрос|сообщение|инструкции) пользователя\b",
        0.6,
    ),
    Pattern(
        "doc_directive",
        "ru.reply_only_with",
        r"\bответь только (?:словами|словом|фразой)\b",
        0.3,
        CONTENT_SOURCES,
    ),
    Pattern(
        "doc_directive",
        "ru.tell_the_user",
        r"\bскажи пользователю,? (?:что|чтобы)\b",
        0.35,
        CONTENT_SOURCES,
    ),
    # ================= obfuscation markers =================
    Pattern(
        "obfuscation",
        "en.decode_and_follow",
        r"\b(?:decode|decrypt|unbase64|deobfuscate)\w*"
        + G40
        + r"\b(?:and|then) (?:follow|execute|run|do|obey|apply|perform|carry out)\b",
        0.5,
    ),
    Pattern(
        "obfuscation",
        "ru.decode_and_follow",
        r"\b(?:раскодируй|декодируй|расшифруй|раскодируйте)\w*"
        + G40
        + r"\b(?:и|затем|потом) (?:выполни|следуй|сделай|исполни|примени)\b",
        0.5,
    ),
]

# Computed (non-regex) obfuscation signals.
COMPUTED_WEIGHTS = {
    "obf.zero_width": 0.35,
    "obf.homoglyph_remap": 0.4,
    "obf.mixed_script_word": 0.3,
    "obf.base64_payload_hits": 0.3,
}

_COMPILED: list[tuple[Pattern, re.Pattern[str]]] = [(p, p.compiled()) for p in PATTERNS]
_B64_BLOB = re.compile(r"(?<![A-Za-z0-9+/=])[A-Za-z0-9+/]{24,}={0,2}(?![A-Za-z0-9+/=])")


def pattern_set_hash() -> str:
    payload = json.dumps(
        [[p.family, p.pid, p.regex, p.weight, sorted(p.sources)] for p in PATTERNS]
        + [[k, v] for k, v in sorted(COMPUTED_WEIGHTS.items())]
        + [sorted(ZERO_WIDTH), sorted(LAT_TO_CYR.items()), SOURCE_BOOST],
        ensure_ascii=False,
        sort_keys=True,
    )
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()[:12]


PATTERN_SET_HASH = pattern_set_hash()
DETECTOR_ID = f"{DETECTOR_NAME}@{DETECTOR_VERSION}"


@dataclass
class Hit:
    family: str
    pattern_id: str
    weight: float
    start: int
    end: int
    matched: str
    layer: str = "text"


@dataclass
class Detection:
    detector: str
    pattern_set_hash: str
    score: float
    flagged: bool
    threshold: float
    families: dict[str, float]
    hits: list[Hit] = field(default_factory=list)
    source_kind: str = UM

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


def _scan(
    norm: NormalizedText, source_kind: str, layer: str, base_span: tuple[int, int] | None
) -> list[Hit]:
    hits: list[Hit] = []
    text = norm.text
    for p, rx in _COMPILED:
        if source_kind not in p.sources:
            continue
        for m in rx.finditer(text):
            if base_span is not None:
                start, end = base_span
            else:
                start = norm.offsets[m.start()] if m.start() < len(norm.offsets) else 0
                end = (norm.offsets[m.end() - 1] + 1) if m.end() - 1 < len(norm.offsets) else start
            hits.append(Hit(p.family, p.pid, p.weight, start, end, m.group(0)[:120], layer))
            if len(hits) > 200:
                return hits
    return hits


def decode_base64_blobs(text: str) -> list[tuple[str, int, int]]:
    out: list[tuple[str, int, int]] = []
    for m in _B64_BLOB.finditer(text):
        blob = m.group(0)
        try:
            raw = base64.b64decode(blob + "=" * (-len(blob) % 4), validate=True)
            decoded = raw.decode("utf-8")
        except (binascii.Error, UnicodeDecodeError, ValueError):
            continue
        printable = sum(1 for c in decoded if c.isprintable() or c in "\n\t")
        if len(decoded) >= 8 and printable / len(decoded) > 0.95:
            out.append((decoded, m.start(), m.end()))
    return out


def score_text(text: str, source_kind: str = UM, threshold: float = DEFAULT_THRESHOLD) -> Detection:
    norm = normalize(text)
    hits = _scan(norm, source_kind, "text", None)
    # second layer: base64 payloads
    b64_hits = 0
    for decoded, s, e in decode_base64_blobs(text):
        inner = normalize(decoded)
        for h in _scan(inner, source_kind, "base64", (s, e)):
            hits.append(h)
            b64_hits += 1
    computed: list[Hit] = []
    if norm.zero_width_count:
        computed.append(
            Hit(
                "obfuscation",
                "obf.zero_width",
                COMPUTED_WEIGHTS["obf.zero_width"],
                0,
                0,
                f"zero_width_chars={norm.zero_width_count}",
                "computed",
            )
        )
    if norm.remapped_tokens:
        computed.append(
            Hit(
                "obfuscation",
                "obf.homoglyph_remap",
                COMPUTED_WEIGHTS["obf.homoglyph_remap"],
                0,
                0,
                f"remapped_tokens={norm.remapped_tokens}",
                "computed",
            )
        )
    if norm.mixed_script_tokens:
        computed.append(
            Hit(
                "obfuscation",
                "obf.mixed_script_word",
                COMPUTED_WEIGHTS["obf.mixed_script_word"],
                0,
                0,
                f"mixed_script_tokens={norm.mixed_script_tokens}",
                "computed",
            )
        )
    if b64_hits:
        computed.append(
            Hit(
                "obfuscation",
                "obf.base64_payload_hits",
                COMPUTED_WEIGHTS["obf.base64_payload_hits"],
                0,
                0,
                f"base64_layer_hits={b64_hits}",
                "computed",
            )
        )
    hits.extend(computed)

    boost = SOURCE_BOOST.get(source_kind, 1.0)
    families: dict[str, float] = {}
    for h in hits:
        w = min(h.weight * (boost if h.family != "obfuscation" else 1.0), 0.95)
        if w > families.get(h.family, 0.0):
            families[h.family] = round(w, 4)
    # noisy-OR: independent evidence accumulates but stays in [0, 1)
    p_clean = 1.0
    for w in families.values():
        p_clean *= 1.0 - w
    score = round(1.0 - p_clean, 4)
    return Detection(
        DETECTOR_ID,
        PATTERN_SET_HASH,
        score,
        score >= threshold,
        threshold,
        families,
        hits,
        source_kind,
    )

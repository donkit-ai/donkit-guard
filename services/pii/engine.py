"""Analyzer factory: spaCy NLP engine for ru/en, stock + Russian + tuned recognizers."""

from __future__ import annotations

import os
from typing import Any

from presidio_analyzer import AnalyzerEngine
from presidio_analyzer.nlp_engine import NlpEngineProvider
from presidio_analyzer.recognizer_registry import RecognizerRegistryProvider
from presidio_ru_recognizers import register_all_ru_recognizers
from services.pii.recognizers import apply_tuning

RU_MODEL = os.environ.get("PII_RU_MODEL", "ru_core_news_lg")
EN_MODEL = os.environ.get("PII_EN_MODEL", "en_core_web_lg")

NLP_CONF: dict[str, Any] = {
    "nlp_engine_name": "spacy",
    "models": [
        {"lang_code": "ru", "model_name": RU_MODEL},
        {"lang_code": "en", "model_name": EN_MODEL},
    ],
    "ner_model_configuration": {
        "model_to_presidio_entity_mapping": {
            "PER": "PERSON",
            "PERSON": "PERSON",
            "NORP": "NRP",
            "FAC": "LOCATION",
            "LOC": "LOCATION",
            "GPE": "LOCATION",
            "LOCATION": "LOCATION",
            "ORG": "ORGANIZATION",
            "ORGANIZATION": "ORGANIZATION",
            "DATE": "DATE_TIME",
            "TIME": "DATE_TIME",
        },
        "low_confidence_score_multiplier": 0.4,
        "low_score_entity_names": [],
        "labels_to_ignore": [
            "ORGANIZATION",
            "CARDINAL",
            "EVENT",
            "LANGUAGE",
            "LAW",
            "MONEY",
            "ORDINAL",
            "PERCENT",
            "PRODUCT",
            "QUANTITY",
            "WORK_OF_ART",
        ],
    },
}


def build_analyzer(languages: tuple[str, ...] = ("ru", "en")) -> AnalyzerEngine:
    nlp_engine = NlpEngineProvider(nlp_configuration=NLP_CONF).create_engine()
    registry = RecognizerRegistryProvider(
        registry_configuration={"supported_languages": list(languages)}
    ).create_recognizer_registry()
    registry.add_nlp_recognizer(nlp_engine=nlp_engine)
    register_all_ru_recognizers(registry)
    apply_tuning(registry)
    return AnalyzerEngine(
        registry=registry,
        nlp_engine=nlp_engine,
        supported_languages=list(languages),
        default_score_threshold=0.0,
    )

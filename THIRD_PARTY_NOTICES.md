# Third-party notices

Donkit Guard is licensed under the Apache License 2.0 (see `LICENSE`). The
following third-party material is included in this repository or in the images
built from it.

## Included in the `donkit-guard` package

| Component | What is used | Licence | Source |
| --- | --- | --- | --- |
| gitleaks rule set | `src/donkit_guard/detectors/data/gitleaks.toml`, the regular expressions and keywords of the secret rules (unmodified data file, converted at import time) | MIT, Copyright (c) 2019 Zachary Rice — `src/donkit_guard/detectors/data/LICENSE.gitleaks` | https://github.com/gitleaks/gitleaks |
| Yelp detect-secrets | seven regular expressions in `src/donkit_guard/detectors/data/extra_patterns.json` derived from the `BasicAuthDetector`, `AzureStorageKeyDetector`, `DiscordBotTokenDetector`, `SquareOAuthDetector`, `TwilioKeyDetector`, `TelegramBotTokenDetector` and `MailchimpDetector` plugins | Apache License 2.0, Copyright Yelp, Inc. | https://github.com/Yelp/detect-secrets |

## Included in the `guard-pii` image (not in the package)

| Component | Licence | Source |
| --- | --- | --- |
| Presidio (`presidio-analyzer`) | MIT | https://github.com/data-privacy-stack/presidio |
| spaCy and the `ru_core_news_lg`, `en_core_web_lg` models | MIT (Explosion) | https://github.com/explosion/spaCy, https://github.com/explosion/spacy-models |
| presidio-ru-recognizers | MIT | https://github.com/brikkoAI/presidio-ru-recognizers |
| pymorphy3 | MIT | https://github.com/no-plagiarism/pymorphy3 |
| pymorphy3-dicts-ru (OpenCorpora dictionary data) | CC BY-SA 3.0 — the dictionary data is redistributed unmodified; attribution: OpenCorpora, https://opencorpora.org | https://github.com/no-plagiarism/pymorphy3-dicts |
| certifi, tqdm | MPL-2.0 (unmodified) | https://github.com/certifi/python-certifi, https://github.com/tqdm/tqdm |

## Test data

`tests/data/*` are corpora assembled for this project; they contain no real
secrets and no real personal data.

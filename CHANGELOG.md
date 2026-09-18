# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the project adheres to
[Semantic Versioning](https://semver.org/).

## [Unreleased]

## [0.1.0a1] - 2026-09-18

### Added

- Core package: attribute-based `GuardContext`, segment `Payload` model whose segment id hashes the source, the JSON pointer and the text (so two leaves holding the same value stay addressable apart), versioned YAML policies with layers and a shipped default policy, two-phase `Engine` combining verdicts on the strictness lattice `deny > require_approval > mask > allow`, deterministic masking that keeps JSON valid, asynchronous one-time approvals (`ApprovalFlow`), audit event models, adapter protocols and in-memory implementations, `Guard` facade and `build_quickstart_guard()`.
- Detectors: `secrets@1` (gitleaks rule set as data plus detect-secrets-derived patterns, keyword-anchored scanning loop verified against the gitleaks binary, low-confidence entropy candidates as audit-only spans), `pii-checksum@1` (SNILS, INN, OGRN, credit cards, phones, e-mail, contextual passport numbers; a context-free numeric identifier scores 0.4 and is audited, a formatted one or one with a context word scores 1.0), `pii-ner@1` (remote, over the `guard-pii` service), `injection-heuristic@1` (RU/EN, detection signal only); `DetectorRunner` with size-dependent budgets and a content-addressed result cache.
- Provenance: `Findings` and `Decision.detector_versions` carry `name@major` together with the hash of the pattern set that produced the spans, and that hash is part of the cache key, so an edited rule set cannot serve superseded results.
- Approval and audit previews: the engine redacts the tool arguments once, with every detected span blacked out and a bounded number of entries, and the approval card, the decision and the audit event all carry that same preview.
- Approval resolution: a rejected queued approval answers the host's next retry with `approval_rejected`, an approval invalidated by a policy change is marked stale in the store, and the outcome the host acts on is audited under the `decision_id` of the decision that asked for it.
- Policy composition and validation: composing documents takes the strictest `mode` and `unsupported_content` and the smallest `approval_ttl_s` and `segment_limit_bytes`; rule ids are unique across the whole bundle; a `mask` rule must select findings; `effect: unknown` is rejected in a selector because unknown effects are gated as `write`.
- Fail-closed behaviour in enforce mode: a policy error is a deny with code `policy_error`, a detector timeout or error `detector_unavailable`, a failed write of a critical audit event `audit_unavailable`, and every deny clears the masked segments.
- `guard-pii` service (`services/pii`, `docker/Dockerfile.pii`): Presidio + spaCy ru/en models + tuned Russian recognizers, per-entity thresholds, a bounded analysis pool, an analyzer failure reported to the core as a detector failure, a non-root image, offline by construction.
- Documentation: architecture, policy reference, example strict policy, third-party notices.

[Unreleased]: https://github.com/donkit-ai/donkit-guard/compare/v0.1.0a1...HEAD
[0.1.0a1]: https://github.com/donkit-ai/donkit-guard/compare/v0.0.1...v0.1.0a1

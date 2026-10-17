# Policy reference

Policies are YAML documents validated by `donkit_guard.policy.load_policy`.

```yaml
schema_version: 1
version: "tenant-acme-2026-09-18"     # free-form, recorded in every decision
mode: enforce                          # off | observe | enforce
unsupported_content: uninspected       # uninspected | deny
approval_ttl_s: 300
segment_limit_bytes: 262144
layers:
  - name: tenant
    rules:
      - id: no-pii-to-byok
        description: Personal data never leaves for a tenant-owned endpoint
        match:
          action_kind: [llm_request]
          finding_class: [pii]
          destination_trust: [tenant, unknown]
        action: deny
        hard: true
        reason: "PII to non-platform destinations is forbidden by policy"
      - id: python-needs-approval
        match: {action_kind: [tool_call], tool: ["python_exec", "run_*"]}
        action: require_approval
```

## Rule

| Field | Meaning |
| --- | --- |
| `id` | unique across every document of the bundle, not only within one; recorded in decisions |
| `description` | why the rule exists; for the reader of the document, never copied into a decision |
| `match` | conjunction of selectors (all listed selectors must hold); list-valued selectors match any of their values |
| `action` | `allow`, `deny`, `mask`, `require_approval`, `audit` |
| `hard` | for `deny`: cannot be lowered by an approval |
| `reason` | human-readable explanation copied into the decision |

Validation refuses a rule that cannot do what it says: `mask` requires at least one finding
selector, because a rule that reports `mask` while masking nothing is a silent allow, and
`hard` requires `deny`.

## Selectors

Context selectors: `action_kind`, `effect` (matched against the *effective* effect: a
tool-server-declared `read` counts as `write`), `effect_source`, `tool` (glob patterns),
`principal_kind`, `principal_absent` (bool), `tenant`, `destination_trust`,
`destination_locality`, `untrusted_content_seen` (bool), `attributes` (exact key/value
equality).

`effect: [unknown]` is rejected at load time: an undeclared effect is gated as `write`, so the
value could never match and the rule would silently never fire. Select `write` to cover it.

Finding selectors (make the rule depend on detectors): `finding_class` (secret, pii, corporate,
injection), `finding_subtype` (detector-specific, glob patterns, e.g. `aws-*`, `PERSON`,
`override`, `CONTRACT_*`), `min_score`, `segment_trust` (trusted, untrusted). The selectors also
decide which detectors run for a call; see [Detectors](#detectors).

### Scores

`min_score` filters findings by the detector's own confidence, which is what separates
"enforce on this" from "record it":

| Detector | Finding | Score |
| --- | --- | --- |
| `secrets` | a match of a specific credential rule (cloud and API keys, tokens, private keys) | 1.0 |
| `secrets` | a match of a weaker specific format: basic-auth URL, Telegram, Discord or Twilio token | 0.7 – 0.9 |
| `secrets` | a match of a `generic-*` rule (a key-like assignment with a high-entropy value) | 0.7 |
| `secrets` | `low-confidence-entropy`: a bare high-entropy token with no rule behind it | 0.3 |
| `pii-checksum` | SNILS written in its `ddd-ddd-ddd dd` format, or a checksum-valid identifier with its own context word within 40 characters (`снилс`/`snils` for SNILS, `инн`/`inn`/`налог`/`tax` for INN, `огрн`/`ogrn` for OGRN) | 1.0 |
| `pii-checksum` | a bare checksum-valid INN, OGRN or SNILS with no context word — a shape that ordinary order numbers and timestamps also have | 0.4 |
| `pii-checksum` | a Luhn-valid credit card number with a known issuer prefix and consistent separators (an inconsistently separated number, such as a date range, is not reported at all) | 1.0 |
| `pii-checksum` | e-mail address | 0.9 |
| `pii-checksum` | phone number (RU or NANP format) | 0.8 |
| `pii-checksum` | US social security number | 0.7 |
| `pii-checksum` | passport number with a context word | 0.6 |
| `pii-ner` | an entity the service reports above its per-entity threshold | 0.5 – 1.0 |
| `injection-heuristic` | the aggregate suspicion score of a segment and the weight of each hit family, reported from 0.5 up | 0.5 – 1.0 |
| declared `pattern` | a match with a `context` word within 40 characters, any match when the declaration lists no `context` words, or a value under a `json_keys` key | `score` (default 0.8) |
| declared `pattern` | a match without a `context` word near it | `score_without_context` (default 0.4) |
| declared `terms` | an occurrence of a listed term | `score` (default 0.8) |
| declared `remote` | an entity of a type the declaration maps | the service's own score, clamped to 0 – 1 |

A rule that enforces (`deny`, `mask`, `require_approval`) should carry a `min_score` that
matches the cost of a false positive; a rule that only records does not need one.

## Detectors

Rules select findings; the detectors that produce them are the built-in ones the host configured
plus the ones a document declares in its own top-level `detectors:` section: `pattern` (RE2
patterns with checksums, context words and JSON-key globs), `terms` (word lists) and `remote` (a
service that speaks the [analyze contract](remote-detectors.md)).

```yaml
detectors:
  - kind: pattern
    id: contract-number
    title: Contract number
    class: corporate
    subtype: CONTRACT_NUMBER
    patterns: ['\bCN-\d{6}\b']
layers:
  - name: tenant
    rules:
      - id: mask-contract-numbers
        match:
          action_kind: [llm_request]
          finding_class: [corporate]
          finding_subtype: [CONTRACT_NUMBER]
        action: mask
```

The class and subtype of a declared detector are selectable like those of a built-in one:
`finding_class` and `finding_subtype` match its findings, and they also decide whether it runs at
all for a call. A detector runs synchronously when a rule with an action other than `audit` could
use its findings, in the background when only `audit` rules could, and not at all otherwise. A
declared detector may report only enforceable classes (`secret`, `pii`, `corporate`).

A document is checked when it is loaded: patterns have to compile, the examples a declaration
carries have to hold, and a document that carries more than 20 detectors, more than 3 of them
`remote`, or the same id twice is refused. [detectors.md](detectors.md) has the fields, the limits,
the optional `re2` and `http` extras and the details of background checks.

## Combination

Matched verdicts combine as `deny > require_approval > mask > allow`; `audit` never changes the
outcome. A rule with an action other than `audit` on the `injection` class is rejected at load
time. A protected action (tool call whose effective effect is not `read`) without any matching
rule is denied.

## Layers

The host composes layers in precedence order (for example platform → tenant → agent). All
layers are evaluated; precedence only decides which `reason` is reported when two rules produce
the same outcome. Rule ids are unique across the whole bundle, because the id is the only handle
an operator has when auditing why a decision was made.

The document-level settings compose per field, and a layer can only tighten what another layer
set:

| Setting | Composition |
| --- | --- |
| `mode` | strictest on `off < observe < enforce`, so a tenant layer cannot switch platform enforcement off; a caller that wants a different mode (a staged rollout) passes it to `PolicyBundle.compose` explicitly. YAML reads an unquoted `off` as a boolean; the loader accepts it as the mode, and `mode: "off"` is the unambiguous spelling |
| `unsupported_content` | strictest: one layer refusing content it cannot inspect (`deny`) decides for the bundle |
| `approval_ttl_s` | the minimum across the documents |
| `segment_limit_bytes` | the minimum across the documents |
| `detectors` | the declarations of every document, in document order; a detector id may not repeat across the documents of a bundle |
| `version` | the documents' versions joined with `+`, recorded in every decision |

## Default policy

The package ships `default_policy.yaml` as the platform layer: mode `observe`,
`unsupported_content: uninspected`, `approval_ttl_s: 300`, `segment_limit_bytes: 262144`.
Its rules: secrets with a score of at least 0.5 are masked everywhere and low-confidence
entropy candidates are only audited; personal data with a score of at least 0.5 is masked for
non-platform destinations (`min_score: 0.5`, so a bare number that merely passes a checksum is
audited rather than replaced by a placeholder) and all personal data is audited; injection is
audited; `read` and `execute` tool calls are allowed (the sandbox bounds execution); `write`,
`spend` and `egress` tool calls require approval, which also covers an undeclared effect;
model requests and tool results are allowed. The detectors that only its `audit` rules can use
(personal data anywhere but in a model request to a non-platform destination, injection) run in
the background, after the decision, so the decision a host receives lists neither the `audit`
rules they feed (`pii-audit`, `injection-audit`) nor their findings: those come in the decision's
`FindingsEvent`. See [detectors.md](detectors.md#which-detectors-run).

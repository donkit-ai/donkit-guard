# Detectors

A detector reads the segments of a payload and reports findings. A finding addresses a span of
text by segment id, JSON pointer and offsets (it never contains the matched text) and carries a
class, a subtype, a score and the name of the detector that found it. Rules select findings with
`finding_class`, `finding_subtype`, `min_score` and `segment_trust`; see [policies.md](policies.md).

There are two kinds of detectors:

- **Built-in** detectors ship with the package. The host configures them on its `DetectorRunner`.
- **Declared** detectors are described in a policy document, so a host, or a tenant of a host,
  adds its own without shipping code. They are checked when the document is loaded and built per
  tenant.

Offsets are Python `str` offsets everywhere: Unicode code points, `end` exclusive.

## Built-in detectors

| Detector | Class | Kind | Subtypes |
| --- | --- | --- | --- |
| `secrets@1` | `secret` | local | the id of the matching rule (`aws-access-token`, `generic-api-key`, ...), with a `:base64`, `:hex` or `:url` suffix when the secret sits in a value decoded from the text; `low-confidence-entropy` for a bare high-entropy token |
| `pii-checksum@1` | `pii` | local | `SNILS`, `INN`, `OGRN`, `CREDIT_CARD`, `PHONE`, `EMAIL`, `US_SSN`, `PASSPORT` |
| `pii-ner@1` | `pii` | remote (the `guard-pii` service) | what the service reports: `PERSON`, `PHONE`, `PASSPORT`, `SNILS`, `INN`, `OGRN`, `EMAIL`, `DATE_TIME`, `LOCATION`, `CREDIT_CARD`, `US_SSN` |
| `injection-heuristic@1` | `injection` | local | the pattern families `override`, `exfil`, `authority`, `persona`, `doc_directive`, `tool_coercion`, `obfuscation`, and `score` for the aggregate suspicion of a segment |

A local detector is code that runs in the guard's process, by default in a worker pool outside
the event loop. A remote one asks a service over the [analyze contract](remote-detectors.md).
`injection` is a signal class: rules on it can only `audit`. The score each built-in detector
gives its findings is listed in [policies.md](policies.md#scores).

## Declared detectors

A policy document declares detectors in its top-level `detectors:` section. A document carries at
most 20, of which at most 3 are `remote`. Next to the rules that use them they make a complete
layer:

```yaml
schema_version: 1
version: "tenant-example-1"
mode: enforce
detectors:
  - kind: pattern
    id: contract-number
    title: Contract number
    class: corporate
    subtype: CONTRACT_NUMBER
    patterns:
      - '\bCN-\d{6}\b'
    context: ["contract*", "agreement"]
    exclude: ["sample", "template"]
    score: 0.9
    score_without_context: 0.5
    examples:
      match:
        - "Please review contract CN-123456 before Friday"
      no_match:
        - "Order CN-1234567 has shipped"
        - "Use the sample contract CN-123456 in the demo"
layers:
  - name: tenant
    rules:
      - id: mask-contract-numbers
        match:
          action_kind: [llm_request]
          finding_class: [corporate]
          finding_subtype: [CONTRACT_NUMBER]
          min_score: 0.8
        action: mask
        reason: "Contract numbers do not go to a model"
```

A rule selects the findings of a declared detector exactly as it selects those of a built-in one:
by `finding_class`, by `finding_subtype` (a glob, so `CONTRACT_*` covers every subtype with that
prefix), by `min_score` and by `segment_trust`. The class and subtype also decide whether the
detector runs at all; see [Which detectors run](#which-detectors-run).

[`examples/policies/tenant-detectors.yaml`](../examples/policies/tenant-detectors.yaml) declares one
detector of each kind. A field that a kind does not have is an error, so a typo is refused
instead of silently ignored. These fields are common:

| Field | Meaning |
| --- | --- |
| `kind` | `pattern`, `terms` or `remote`. |
| `id` | `^[a-z0-9][a-z0-9-]{0,63}$`, unique across every document of a bundle. The detector is named `declared:<id>` and has version `1`, so decisions list it as `declared:<id>@1`. |
| `title` | 1 to 80 characters, for the reader of the document; it has no effect on detection. |
| `class` | `secret`, `pii` or `corporate`. `injection` is rejected: a detector may only report enforceable classes. A `remote` detector gives a class per entity instead. |
| `subtype` | `^[A-Z][A-Z0-9_]{0,39}$`; what a rule's `finding_subtype` selects. A `remote` detector gives a subtype per entity instead. |

### `pattern`

Finds text with RE2 patterns and weighs each match by what stands around it.

| Field | Default | Meaning |
| --- | --- | --- |
| `patterns` | none | Up to 10 RE2 expressions of up to 500 characters each, tried as alternatives anywhere in the text. |
| `checksum` | none | `luhn`, `inn`, `snils`, `ogrn` or `iban`. A match that fails the check is dropped. |
| `context` | none | Up to 50 words of up to 64 characters each. A match with one of them near it scores `score`. |
| `exclude` | none | The same shape. A match with one of them near it is dropped. |
| `json_keys` | none | Up to 20 globs of up to 64 characters each, matched against the JSON key a value sits under. |
| `score` | `0.8` | The score of a confirmed match, 0 to 1. |
| `score_without_context` | `0.4` | The score of a match without a context word near it, 0 to 1. |
| `examples` | none | Texts the detector must and must not find; see [Examples](#examples). |

A detector needs `patterns` or `json_keys`, and `examples.match` needs `patterns`.

A match is judged in this order:

1. An empty match is ignored.
2. With a `checksum`, the match has to pass it.
3. With `exclude` words, a match with one of them near it is dropped.
4. The match scores `score` when the declaration lists no `context` words or one of them is near
   the match, and `score_without_context` otherwise.

`context` and `exclude` hold words, not expressions. A word matches whole and in any case: a
letter right before or after it prevents a match, digits and punctuation do not, so `inn` is found
in `INN7707123458` and in `inn:` but not in `winner`. A trailing `*` lifts the bound on the right:
`договор*` finds `договора` and `договорами`, though still not `предоговор`. "Near" means within
40 characters before the match or after it, and the word has to lie wholly inside that window.

A `checksum` makes a match pass only if its check digits hold. All but `iban` read the digits of the
match and ignore every other character, so a pattern may allow separators: `luhn` (13 to 19 digits,
payment cards), `inn` (10 or 12 digits), `snils` (11) and `ogrn` (13 or 15). `iban` reads the match
as written, ignoring spaces and case: 15 to 34 characters, two letters, two check digits, and a
remainder of 1 modulo 97.

`json_keys` apply to values in a JSON payload, such as the arguments of a tool call. A value is
judged by the object key it sits under. The globs are shell-style (`*`, `?`, `[abc]`) and are
compared with the key without regard to case; for an element of an array the key is the array's, so
`/contracts/0` sits under `contracts`. A value under a listed key is reported whole, with `score`,
and its text is not searched: the patterns, the checksum and `exclude` do not apply. An empty value
is not reported. A message, and an element of a top-level array, sit under no key, so not even `*`
matches them.

Patterns run on [RE2](https://github.com/google/re2/wiki/Syntax), which searches in time linear in
the length of the text whatever the expression, so no pattern a document carries can stall the
process. The price is a smaller syntax:

- There is no lookaround (`(?=`, `(?!`, `(?<=`, `(?<!`) and there are no backreferences (`\1`). A
  pattern that uses them is refused when the document is loaded, with RE2's own reason, at
  `detectors/<index>/patterns/<n>`.
- `\b`, `\w`, `\d` and `\s` know ASCII only. `\b` treats a Cyrillic letter as a non-word
  character and `\w` does not match one; write `\p{L}`, `\p{Cyrillic}` or `\p{N}` for letters and
  digits of any script.
- Matching is case-sensitive. Start a pattern with `(?i)` for case-insensitive matching; a flag
  set inside one pattern ends with it.
- RE2 refuses an expression that is too large to compile.

All patterns of a detector are combined into one expression, and one segment yields at most 50
findings.

### `terms`

Finds the words of a list, whatever their case and whichever look-alike letters spell them.

| Field | Default | Meaning |
| --- | --- | --- |
| `terms` | required | 1 to 5000 terms of up to 200 characters each. |
| `score` | `0.8` | The score of every finding, 0 to 1. |
| `examples` | none | Texts the detector must and must not find; see [Examples](#examples). |

A term matches like this:

- Whole words only. A letter or digit right before or after the term prevents a match: `Albatross`
  is not found in `albatrosses` or in `Superalbatross`.
- A trailing `*` lets the last word take any ending: `Альбатрос*` finds `Альбатроса` and
  `Альбатросом`.
- The words of a term may stand apart by any run of whitespace: `Blue Heron` finds `blue   heron`.
- Case is ignored. Latin and Cyrillic look-alike letters (`a`, `c`, `e`, `o`, `p`, `x`, `y` and
  their Cyrillic twins) are read as the script of the rest of their word, so `Aльбатрос` spelled
  with a Latin `A` still finds the term `Альбатрос`.
- Term and text are NFKC-normalized and zero-width characters are ignored, so a term broken up by
  a zero-width space is still found.
- Of the terms that match at one place the longest wins, and occurrences do not overlap.
  Findings point into the original text, invisible characters included.

One segment yields at most 50 findings.

### `remote`

Delegates detection to a service that speaks the [analyze contract](remote-detectors.md).

| Field | Default | Meaning |
| --- | --- | --- |
| `endpoint` | required | The `http` or `https` URL of the analyze endpoint: up to 2048 characters, with a host, and without user, password, query or fragment. A token belongs in a credential, not in the URL. |
| `credential` | none | The name of the token the service expects (`^[a-z0-9][a-z0-9-]{0,63}$`). A document never carries a secret: the host's `CredentialResolver` turns the name into a token, which goes out as a bearer token. Without a `credential` no token is sent. |
| `entities` | required | 1 to 50 entries, each mapping an entity type the service reports (1 to 64 characters) to the `class` and `subtype` of the finding. Types the declaration does not list are ignored. |
| `timeout_ms` | `2000` | 100 to 30000. How long the guard waits for the service in one scan. The service is asked to answer within 80% of it. |
| `required` | `true` | Whether a failed call fails the decision; see below. |
| `cache_ttl_s` | `3600` | 0 to 86400. How long the answer for a text is reused. `0` never reuses an answer, and a failed answer is never reused. |

A call fails when the service does not answer within `timeout_ms`, answers with an error status or
with something unusable, or reports `failed: true`, and also when the host refuses the address or
has no token for the credential. What a failure does depends on `required` and on who can use the
detector:

- `required: true` (the default) and a rule with an action other than `audit` could use the
  detector: in enforce mode the decision is a deny with code `detector_unavailable`, and in observe
  mode the recorded decision carries the code `detector_failed`.
- `required: false`, or only `audit` rules could use the detector: the decision goes on without
  it, and the detector is listed in `Decision.unchecked_detectors`.

A remote declaration takes no examples and is not contacted when the document is loaded. The text
of the segments the detector scans leaves the process for the service; what exactly is sent is
described in [remote-detectors.md](remote-detectors.md#what-the-guard-sends).

### Examples

A `pattern` or `terms` declaration can carry `examples`, texts that pin down what it means:

```yaml
examples:
  match: ["Please review contract CN-123456 before Friday"]
  no_match: ["Order CN-1234567 has shipped"]
```

Every `match` text has to produce a finding and no `no_match` text may. They are checked when the
document is loaded, each read as a message from a trusted user, so an edit that changes what a
detector finds is refused instead of deployed. A declaration takes at most 20 examples in all
(`match` and `no_match` together) of up to 1000 characters each.

A document with problems is refused with all of them listed, one per line, each at the place that
is wrong. `<index>` is the position of the declaration in the `detectors` list, counted from 0:

| Error | Meaning |
| --- | --- |
| `detectors/<index>/patterns/<n>: <reason>` | RE2 refused the pattern, for example a lookbehind. |
| `detectors/<index>/patterns: <reason>` | Every pattern compiles on its own, but RE2 refuses them combined. |
| `detectors/<index>/terms: <reason>` | The list of terms cannot be compiled, for example a term made only of invisible characters. |
| `detectors/<index>/examples/match/<n>: found nothing` | A `match` example produced no finding. |
| `detectors/<index>/examples/no_match/<n>: found <subtype>` | A `no_match` example produced a finding. |
| `detectors/<index>: pattern and terms detectors need the 're2' extra: ...` | The `re2` extra is not installed. |

### Limits

| What | Limit |
| --- | --- |
| detectors per document | 20 |
| `remote` detectors per document | 3 |
| `patterns` | 10 items, 500 characters each |
| `terms` | 1 to 5000 items, 200 characters each |
| `examples` | 20 texts in all, 1000 characters each |
| `context`, `exclude` | 50 words, 64 characters each |
| `json_keys` | 20 globs, 64 characters each |
| `entities` | 1 to 50 entries |
| `endpoint` | 2048 characters |
| `timeout_ms` | 100 to 30000, default 2000 |
| `cache_ttl_s` | 0 to 86400, default 3600 |
| `score`, `score_without_context` | 0 to 1, defaults 0.8 and 0.4 |
| findings per segment and declared detector | 50 |
| context window | 40 characters on each side of a match |

### Optional extras

The base install needs only `pydantic` and `pyyaml`. Declared detectors use two optional packages:

| Extra | Package | Needed for |
| --- | --- | --- |
| `re2` | `google-re2` | `pattern` detectors that have `patterns`, and `terms` detectors |
| `http` | `httpx` | `remote` detectors, `donkit_guard.http.HttpAnalyzeClient` and the conformance command |

    pip install 'donkit-guard[re2,http]'

Importing `donkit_guard` needs neither. A feature whose extra is missing fails when it is used,
with an error that names the extra: loading a document with a `pattern` (with `patterns`) or
`terms` detector raises `PolicyError`, and evaluating a bundle that declares a `remote` detector is
denied with code `policy_error`. A `pattern` detector that declares only `json_keys` compiles
nothing and runs without `re2`.

## Which detectors run

On each evaluation the engine collects the candidates: the runner's own detectors and the
detectors the bundle's documents declare, built for the tenant of the context. It then looks at the
rules that matched the context and select findings (the ones with `finding_class`,
`finding_subtype`, `min_score` or `segment_trust`) and sorts the candidates:

| Selection | When | What follows |
| --- | --- | --- |
| synchronous | a rule with the action `allow`, `deny`, `mask` or `require_approval` could use its findings | the decision waits for it, and the failure of a required detector fails the decision |
| background | only `audit` rules could use its findings | the decision does not wait; the findings are written afterwards, and a failure never changes the decision |
| unused | no rule could use its findings | it is not run |

A rule *could use* a detector when the detector can report what the rule selects: one of the
detector's classes is among the rule's `finding_class` values and, when the rule has a
`finding_subtype` and the detector declares its subtypes, one of them matches a glob. Declared
detectors declare theirs (the `subtype`, or the subtypes of the `entities`); the built-in ones do
not, so a built-in detector of the right class stays eligible for any subtype selector.
`min_score` and `segment_trust` depend on the finding itself and never rule a detector out. When in
doubt the detector runs, because one left out silently weakens a decision while one run needlessly
only costs time. An `allow` rule with a finding selector counts as a rule that decides.

Under the shipped default policy a model request to a platform destination runs `secrets`
synchronously (`secrets-mask`), while `pii-checksum`, `pii-ner` and `injection-heuristic` only feed
`audit` rules (`pii-audit`, `injection-audit`) and run in the background. The same request to a
`tenant` or `unknown` destination runs the PII detectors synchronously, because
`pii-mask-untrusted-destination` then matches the context.

`Decision.detector_versions` lists the detectors selected for the call, synchronous and
background, as `name@version` with the hash of the pattern set each used. For a declared detector
the hash is the digest of its declaration, so a decision can be tied back to the exact text that
was in force.

## Background checks

A detector that only `audit` rules can use scans while the decision goes back to the caller, so a
slow or failing one costs the call nothing. What it finds is written afterwards:

- A `FindingsEvent` (`event_type: "findings"`) is recorded through the `AuditSink` after the
  decision's `DecisionEvent`, under the same `decision_id`. It carries the summary of the context,
  the `locations` of the findings (at most `EngineSettings.max_locations`), their
  `finding_classes`, the ids of the `audit` rules they matched (`rule_ids`) and
  `unchecked_detectors`: the background detectors that failed, because what they did not flag is
  unknown, not clean.
- Nothing is written when the background detectors found nothing and none failed, nor when the
  decision itself was not recorded (`audit=False`).
- A failure of a background detector never denies the decision and never delays it.
- `Decision.unchecked_detectors` lists, as `name@version`, the detectors whose findings the
  decision did not get: an optional or audit-only detector that failed while the decision waited
  for it, and background detectors that did not start for lack of room. Whoever reads the audit
  trail must not take the missing findings for a clean payload. Such a decision is `critical`, so
  in enforce mode its audit event is written fail-closed.

At most `EngineSettings.max_background_checks` (200) background checks run at once. With no room
left the audit-only detectors are not started and are listed in `unchecked_detectors`.

The checks belong to the process. `Engine.drain()` waits until every one of them has finished, for
tests and for an orderly shutdown. `Engine.aclose()`, which `Guard.aclose()` calls, waits up to
`EngineSettings.background_drain_s` (5 seconds), cancels what is left and releases the detectors.
**Findings of a check that has not finished when the process ends are lost**: a crash, a kill or a
shutdown that cancels the check leaves no `FindingsEvent`. If losing a finding is not acceptable,
the rule behind it should not be an `audit` rule, because a detector that a `mask`, `deny` or
`require_approval` rule can use finishes before the decision goes back.

## Observe mode

Observe mode never blocks, so the caller need not wait for the evaluation. `Engine.evaluate`
returns at once an `allow` with `explanation.code` set to `observe_deferred`, `mode` `observe` and
a fresh `decision_id`, and evaluates in the background. The full decision, with `would_outcome`,
`would_block`, the locations and `detector_versions`, is recorded later as a `DecisionEvent` under
that `decision_id`. The immediate answer is not recorded and carries no findings, so a host reads
the outcome of an observe-mode evaluation from the audit trail. Like background findings, a
deferred decision is lost if the process ends before it is recorded.

An evaluation is not deferred, and the call returns the real decision, when no room is left for
background work, with `audit=False`, and with `evaluate(..., defer=False)`. `Guard.authorize` uses
`defer=False` for the re-evaluation that follows an approval. With `defer=False` every selected
detector, background ones included, runs before the decision is returned.

## Approval cards

An approval card shows one bounded preview per tool argument, with the spans the detectors found
blacked out. A decision that asks for approval therefore waits for its background detectors, so
that what they find is blacked out too. If one of them failed, or none could start for lack of
room, the guard cannot tell which values hold findings: the card then shows none of them, each
value being a run of `█` as long as the value (up to `EngineSettings.preview_chars`), and the
detectors are listed in `unchecked_detectors`. The same happens when an optional detector failed
during a synchronous scan. The preview in the audit event is the same one.

## Caching and tenants

The runner caches what each detector found in each segment, so a text is scanned once however many
requests carry it. The cache key of a detector holds its name, its version, the hash of its
pattern set and its cache scope. For a declared detector the hash is the digest of its declaration
and the scope is the tenant id, so another tenant never reads its results and an edited
declaration never reads the results of its earlier version. The results of a `pattern` or `terms`
detector stay for the cache's default lifetime, those of a `remote` detector for its
`cache_ttl_s`.

`DeclaredDetectors` keeps the detectors it built, so a declaration is compiled once per tenant
and not once per request, and the same declaration in a document that is loaded anew finds its
detector again. Up to `max_cached` (256) detectors are kept, the least recently used one going
first.

## Wiring in a host

The engine builds declared detectors through a `DeclaredDetectors`. Without one it makes its own,
which reads credentials from environment variables and allows every URL. A host that takes
documents from its tenants passes its own hooks (see
[remote-detectors.md](remote-detectors.md#credentials-and-addresses)):

```python
from donkit_guard.declared import DeclaredDetectors
from donkit_guard.engine import Engine

engine = Engine(
    policy_source=policy_source,
    runner=runner,
    audit_sink=audit_sink,
    declared=DeclaredDetectors(
        credential_resolver=resolver,
        endpoint_guard=endpoint_guard,
        ca_bundle="/etc/ssl/organization-ca.pem",
    ),
)
```

`build_quickstart_guard(declared=...)` takes the same object. `Engine.aclose()` closes the HTTP
clients that `DeclaredDetectors` opened.

## Optional detector attributes

`LocalDetector` and `RemoteDetector` fix the attributes every detector has. A detector may carry
the following as well; the runner and the engine read them through the `detector_*` accessors in
`donkit_guard.detectors.base`, and a detector without one behaves as it always did. Every declared
detector sets `subtypes` and `cache_scope`; a declared `remote` detector sets the other three from
its declaration as well.

| Attribute | Type | Meaning | When absent |
| --- | --- | --- | --- |
| `subtypes` | `frozenset[str]` | The subtypes the detector can report. Selection leaves it out for a rule whose `finding_subtype` matches none of them. | any subtype is possible |
| `cache_scope` | `str` | An isolation label that is part of the cache key, for example the tenant. | one scope for every user of the detector |
| `timeout_ms` | `int` | The deadline of a remote detector, in milliseconds. | the runner's size-based budget |
| `cache_ttl_s` | `int` | How long the detector's results stay cached, in seconds; `0` turns caching off. | the cache's default lifetime |
| `required` | `bool` | `False` makes a failure count as an unchecked detector instead of a failed check. | `True` |

A declared `pattern` or `terms` detector also has a `spec_payload()` method. In
`ExecutorKind.PROCESS` a worker process rebuilds the detector from that payload, because it cannot
be handed a detector built from a document.

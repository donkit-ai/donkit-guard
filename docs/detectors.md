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

Terms need no extra: they are matched in plain Python, not with RE2. A scan takes time linear in
the length of the text, times the number of distinct lengths among the terms that share their
first 8 characters, so the full limit of 5000 terms of 200 characters each works whatever the text
holds. Building the detector indexes the terms, which takes a fraction of a second for a full list
and happens when the document is loaded and when the detector is built for a tenant, not on every
request (see [Caching and tenants](#caching-and-tenants)).

### `remote`

Delegates detection to a service that speaks the [analyze contract](remote-detectors.md).

| Field | Default | Meaning |
| --- | --- | --- |
| `endpoint` | required | The `http` or `https` URL of the analyze endpoint: up to 2048 characters, with a host, and without user, password, query or fragment. A token belongs in a credential, not in the URL. |
| `credential` | none | The name of the token the service expects (`^[a-z0-9][a-z0-9-]{0,63}$`). A document never carries a secret: the host's `CredentialResolver` turns the name into a token for the declared `endpoint`, which goes out as a bearer token. A host that passes no resolver resolves no credential, and the detector then fails with `credential not found` without sending anything. Without a `credential` no token is sent. |
| `entities` | required | 1 to 50 entries, each mapping an entity type the service reports (1 to 64 characters) to the `class` and `subtype` of the finding. Types the declaration does not list are ignored. |
| `timeout_ms` | `2000` | 100 to 30000. How long the guard waits for the service in one scan. The service is asked to answer within 80% of it. |
| `required` | `true` | Whether a failed call fails the decision; see below. |
| `cache_ttl_s` | `3600` | 0 to 86400. How long the answer for a text is reused. `0` never reuses an answer, and a failed answer is never reused. |

A call fails when the service does not answer within `timeout_ms`, answers with an error status,
compressed, with more than 1 MiB or with something unusable, or reports `failed: true`, and also
when the host refuses the address or has no token for the credential. What a failure does depends
on `required` and on who can use the detector:

- `required: true` (the default) and a rule with an action other than `audit` could use the
  detector: in enforce mode the decision is a deny with code `detector_unavailable`, and in observe
  mode the recorded decision carries the code `detector_failed`.
- `required: false`, or only `audit` rules could use the detector: the decision goes on without
  it, and the detector is listed as unchecked, in `Decision.unchecked_detectors` when the decision
  waited for it and in the decision's `FindingsEvent` when it ran in the background.

A remote declaration takes no examples and is not contacted when the document is loaded. The text
of the segments the detector scans leaves the process for the service; what exactly is sent is
described in [remote-detectors.md](remote-detectors.md#what-the-guard-sends), and what a host has
to decide about it in [threat-model.md](threat-model.md#declared-detectors-from-policy-documents).

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
| `detectors/<index>/terms: <reason>` | A term has no visible characters, for example one made only of zero-width characters. |
| `detectors/<index>/examples/match/<n>: found nothing` | A `match` example produced no finding. |
| `detectors/<index>/examples/no_match/<n>: found <subtype>` | A `no_match` example produced a finding. |
| `detectors/<index>: pattern detectors need the 're2' extra: ...` | The declaration is a `pattern` detector with `patterns`, and the `re2` extra is not installed. |

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
| `re2` | `google-re2` | `pattern` detectors that have `patterns` |
| `http` | `httpx` | `remote` detectors, `donkit_guard.http` (`HttpAnalyzeClient`, `HttpConnections`) and the conformance command |

    pip install 'donkit-guard[re2,http]'

Importing `donkit_guard` needs neither. A feature whose extra is missing fails when it is used,
with an error that names the extra: loading a document with a `pattern` detector that has
`patterns` raises `PolicyError`, and evaluating a bundle that declares a `remote` detector is
denied with code `policy_error`. `terms` detectors need no extra, and neither does a `pattern`
detector that declares only `json_keys`, because it compiles nothing.

## Which detectors run

On each evaluation the engine collects the candidates: the runner's own detectors and the
detectors the bundle's documents declare, built for the tenant of the context. It then looks at the
rules that matched the context and select findings (the ones with `finding_class`,
`finding_subtype`, `min_score` or `segment_trust`) and sorts the candidates:

| Selection | When | What follows |
| --- | --- | --- |
| synchronous | a rule with the action `allow`, `deny`, `mask` or `require_approval` could use its findings | the decision waits for it, and the failure of a required detector fails the decision |
| background | only `audit` rules could use its findings | the decision does not wait, unless it asks for approval of a tool call; the findings are written afterwards, and a failure never changes the outcome |
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
`pii-mask-untrusted-destination` then matches the context. A tool call runs `secrets`
synchronously and the PII and injection detectors in the background, whatever its effect: personal
data in tool arguments only feeds `pii-audit`.

Because the decision does not wait for them, what background detectors find is not part of it:
their rules are missing from `explanation.rule_ids`, their findings from
`explanation.finding_classes` and `explanation.locations`, and they do not make the decision
`critical` (in enforce mode a critical decision whose event cannot be written is denied). Under the
default policy that leaves out `injection-audit` and the `injection` class on every call, and
`pii-audit` and the `pii` class on every call but a model request to a `tenant` or `unknown`
destination. They come in the decision's `FindingsEvent` instead (see
[Background checks](#background-checks)); a host that needs them in the decision itself evaluates
with `defer=False`.

`Decision.detector_versions` lists the detectors selected for the call, synchronous and
background, as `name@version` with the hash of the pattern set each used. For a declared detector
the hash is the digest of its declaration, so a decision can be tied back to the exact text that
was in force.

## Background checks

A detector that only `audit` rules can use scans while the decision goes back to the caller, so a
slow or failing one never denies the call and holds up only an approval card. Its scan starts just
before the synchronous scan of the same evaluation and runs in the runner's
[background lane](#the-background-lane). What it finds is written afterwards:

- A `FindingsEvent` (`event_type: "findings"`) is recorded through the `AuditSink` after the
  decision's `DecisionEvent`, under the same `decision_id`. It carries the summary of the context,
  the `locations` of the findings (at most `EngineSettings.max_locations`), their
  `finding_classes`, the ids of the `audit` rules they matched (`rule_ids`),
  `unchecked_detectors` (the background detectors that failed, because what they did not flag is
  unknown, not clean) and `display_args_redacted`: the argument previews of a tool call that the
  decision held back while the check ran, or `None` (see [Argument previews](#argument-previews)).
- It is written when the background detectors found something, when one of them failed, or when
  it carries argument previews, which it does also when the detectors found nothing.
- Nothing is written when the decision event was not. With `audit=False` every detector runs
  before the decision is returned, and when the sink fails to write the `DecisionEvent` the
  findings are dropped with it, so findings never reach the audit trail without their decision.
- A failure of a background detector never denies the decision. Only a decision that asks for
  approval of a tool call waits for the background detectors, because its approval card shows the
  arguments; see [Argument previews](#argument-previews).
- `Decision.unchecked_detectors` lists, as `name@version`, the detectors whose findings the
  decision did not get: an optional or audit-only detector that failed while the decision waited
  for it, and background detectors that did not start for lack of room. Whoever reads the audit
  trail must not take the missing findings for a clean payload. Such a decision is `critical`, so
  in enforce mode its audit event is written fail-closed.

At most `EngineSettings.max_background_checks` (200) background checks run at once, the evaluations
that observe mode defers included. With no room left the audit-only detectors are not started and
are listed in `unchecked_detectors`.

The checks belong to the process. `Engine.drain()` waits until every one of them has finished, for
tests and for an orderly shutdown. `Engine.aclose()`, which `Guard.aclose()` calls, waits up to
`EngineSettings.background_drain_s` (5 seconds), cancels what is left and releases the detectors.
**Findings of a check that has not finished when the process ends are lost**: a crash, a kill or a
shutdown that cancels the check leaves no `FindingsEvent`. If losing a finding is not acceptable,
the rule behind it should not be an `audit` rule, because a detector that a `mask`, `deny` or
`require_approval` rule can use finishes before the decision goes back.

The checks are also tasks of the event loop the engine is used on, and a loop that closes cancels
them. A host that runs a new event loop per call, for example `asyncio.run` for every request,
loses its background checks and its deferred observe-mode decisions when that loop closes. Such a
host evaluates with `defer=False`, which runs every selected detector before the decision is
returned, or awaits `Engine.drain()` before the loop ends.

### The background lane

`DetectorRunner.run(..., background=True)` runs a scan in the runner's background lane. The engine
uses it for background checks and for the evaluations that observe mode defers; synchronous scans,
the re-evaluation after an approval among them, take the foreground lane. The background lane
keeps its work away from the foreground:

- Its local detectors run on workers of their own, `background_workers` of them (default 1), one
  scan per worker, next to the `max_workers` that serve the foreground. With
  `ExecutorKind.PROCESS` the runner therefore keeps one more worker process.
- It keeps at most `max_background_remote` (default 16) remote calls in flight, so that the
  detectors' services keep room for the foreground calls.
- A background scan waits for its turn before its deadline starts, so a backlog never times it
  out, and a local one gets at least `Budget.background_min_ms` (1000 ms), since no answer waits
  for it.

Background work therefore never delays a foreground scan and never makes one time out. Turns are
counted per event loop.

```python
from donkit_guard.detectors import (
    Budget,
    DetectorRunner,
    ExecutorKind,
    InjectionHeuristic,
    PiiChecksumDetector,
    SecretsDetector,
)

runner = DetectorRunner(
    [SecretsDetector(), PiiChecksumDetector(), InjectionHeuristic()],
    executor=ExecutorKind.PROCESS,
    max_workers=2,
    background_workers=1,
    max_background_remote=16,
    budget=Budget(background_min_ms=1000.0),
)
```

The lane gives no priority within its own work. The background detectors of an approval card take
their turn behind the other background checks and the deferred observe-mode evaluations, so a
backlog of background work slows approval cards down; their deadlines start only once they run, so
the wait does not fail them. Without a backlog an approval card waits for the longer of the
synchronous and the background scan, not for both in turn, because the background check starts
first.

With `ExecutorKind.SYNC`, which `build_quickstart_guard` uses and which suits tests, there are no
workers: every local detector runs on the event loop itself, background ones included, so a
background scan holds up whatever the loop runs next, the caller's answer included.

## Observe mode

Observe mode never blocks, so the caller need not wait for the evaluation. `Engine.evaluate`
returns at once an `allow` with `explanation.code` set to `observe_deferred`, `mode` `observe` and
a fresh `decision_id`, and evaluates in the background, in the runner's background lane. The full
decision, with `would_outcome`, `would_block`, the locations and `detector_versions`, is recorded
later as a `DecisionEvent` under that `decision_id`. The immediate answer is not recorded and
carries no findings, so a host reads the outcome of an observe-mode evaluation from the audit
trail. Like background findings, a deferred decision is lost if the process ends, or its event
loop closes, before it is recorded.

A host acts on the answer at once and may record the execution before the deferred decision is
written. The engine then holds the `ExecutionEvent` back and writes it once the evaluation has
written its `DecisionEvent`, so a sink sees a decision before its execution. That chained write is
background work: `Engine.drain()` and `Engine.aclose()` cover it, it takes room among the
`max_background_checks` but is never refused, and a sink error in it is logged instead of raised,
because `record_execution` has already returned. An execution event recorded once its decision is
written, or for a decision that was not deferred, is written at once, and a sink error reaches the
caller.

An evaluation is not deferred, and the call returns the real decision, when no room is left for
background work, with `audit=False`, and with `evaluate(..., defer=False)`. `Guard.authorize` uses
`defer=False` for the re-evaluation that follows an approval. With `defer=False` every selected
detector, background ones included, runs before the decision is returned.

## Argument previews

The decision on a tool call carries one bounded preview per argument value,
`Decision.display_args_redacted`, with the spans the detectors found blacked out; the approval
card and the `DecisionEvent` carry the same previews. A value is shown only once every selected
detector has reported on it. Until then the guard cannot tell which values hold findings, so it
shows none of them: each value is a run of `█` as long as the value (up to
`EngineSettings.preview_chars`). That happens in three cases:

- **A background check is still running.** This is the usual case for a tool call that asks for
  no approval, because under the default policy the PII and injection detectors scan tool
  arguments in the background. Once they have reported, the decision's `FindingsEvent` carries
  the readable previews in `display_args_redacted`, with what every detector found blacked out,
  and it is written for them even when the background detectors found nothing. A host's audit
  view shows those previews in place of the decision's. If a background detector fails, no
  previews follow: the values stay hidden, and the `FindingsEvent` lists the detector in
  `unchecked_detectors`.
- **A detector failed while the decision waited for it.** An optional or audit-only one is listed
  in `unchecked_detectors`; a required one that a deciding rule uses fails the decision. No
  readable previews follow, also when a background check was running as well.
- **A background detector was not started** for lack of room. It is listed in
  `unchecked_detectors`, and no readable previews follow.

A decision that asks for approval of a tool call waits for its background detectors instead,
because the approver reads the card before anything happens: the card shows the values with what
every detector found blacked out, unless a detector failed or did not start, and then it shows
none of them. A decision that waits for every detector anyway, with `defer=False` or
`audit=False`, or the decision that observe mode records later, shows the values the same way.

Previews black out what the evaluation found in the payload. An argument value that the payload
does not carry, or whose segment is listed in `seen_segments`, is not scanned by this evaluation
and is shown as it is.

## Caching and tenants

The runner caches what each detector found in each segment, so a text is scanned once however many
requests carry it. The cache key of a detector holds its name, its version, the hash of its
pattern set and its cache scope. For a declared detector the hash is the digest of its declaration
and the scope is the tenant id, so another tenant never reads its results and an edited
declaration never reads the results of its earlier version. The results of a `pattern` or `terms`
detector stay for the cache's default lifetime, those of a `remote` detector for its
`cache_ttl_s`.

`DeclaredDetectors` keeps the detectors it built, so a declaration is built (its patterns
compiled, its terms indexed) once per tenant and not once per request, and the same declaration in
a document that is loaded anew finds its detector again. Up to `max_cached` (256) detectors are
kept, the least recently used one going first. The remote detectors share the HTTP connections of
their `DeclaredDetectors`, one pool per origin, which stay open until `aclose`, so a remote
detector dropped from the cache keeps working for an evaluation that still holds it.

## Wiring in a host

The engine builds declared detectors through a `DeclaredDetectors`. Without one it makes its own,
which resolves no credentials and allows every URL: a remote declaration that names a
`credential` fails with `credential not found` and sends nothing. A host that gives remote
detectors their credentials, or takes documents from its tenants, passes its own hooks (see
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

`build_quickstart_guard(declared=...)` takes the same object. A `ca_bundle` file is read when
`DeclaredDetectors` is constructed, so a missing or unreadable one raises `OSError` there, not in
an evaluation. `Engine.aclose()` calls `DeclaredDetectors.aclose()`, which closes the HTTP
connections its remote detectors share; a remote detector handed out before fails with
`client closed` from then on.

An engine and its `DeclaredDetectors` belong to the event loop they are used on. The background
checks are tasks of that loop, and the HTTP connections are bound to the loop that made them: a
remote detector called from another loop fails its check when it reuses a connection of the
first. A host that evaluates on several event loops therefore gives each loop an `Engine` with a
`DeclaredDetectors` of its own. A `DetectorRunner` may serve several loops, but its background lane
counts turns per loop, so the background scans of several loops can queue for the same workers and
run out of time there. A host that runs a new loop per call also evaluates with `defer=False`; see
[Background checks](#background-checks).

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

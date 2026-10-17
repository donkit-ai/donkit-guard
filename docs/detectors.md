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

A local detector is code that the guard runs itself, by default outside the event loop: a built-in
one in worker processes, see [Where detectors run](#where-detectors-run). A remote one asks a
service over the [analyze contract](remote-detectors.md). `injection` is a signal class: rules on
it can only `audit`. The score each built-in detector gives its findings is listed in
[policies.md](policies.md#scores).

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

Terms need no extra: they are matched in plain Python, not with RE2. They are indexed by their
first 8 characters, and the text is looked up only where a term could start. Each segment a scan
reads has a work limit: its lookups may cut out and compare 256 characters per character of the
text as it is matched, normalized and with each run of whitespace counted as one character, plus
65 536. A lookup costs its length, since normalizing can make a term many times longer than it
is written. A scan that would need more stops and fails with `terms scan exceeded its work
limit`, so matching takes time linear in the length of the text and no list can stall it.
Realistic lists need a small part of the limit: a full list of 5000 terms of 200 characters each
needs well under 1% of it, and a text that is nothing but a list of company names which all
start with the same long legal form about a tenth. Only a list built to cost thousands of
characters at every place a term could start exceeds it. The failure counts like that of any
detector: when a rule with an action other than `audit` could use the detector, an enforce-mode
decision is a deny with code `detector_unavailable`, and when only `audit` rules could, the
detector is listed as unchecked.

Building the detector indexes the terms, which takes a fraction of a second for a full list. It
happens when the document is loaded and when the detector is built for a tenant, which the engine
does off the event loop, and not on every request (see [Caching and tenants](#caching-and-tenants)).

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
| background | only `audit` rules could use its findings | the decision does not wait for it, except to show an approval card ([Approval cards](#approval-cards)); the findings are written afterwards, and a failure never changes the outcome |
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
`pii-mask-untrusted-destination` then matches the context. A `read` or `execute` tool call runs
`secrets` synchronously and the PII and injection detectors in the background: personal data in
tool arguments only feeds `pii-audit`. A tool call with a side effect (`write`, `spend`, `egress`,
or an effect gated as `write`) runs all of them before its decision, because
`tool-side-effect-approval` sends it for approval and its approval card waits for every detector
(see [Approval cards](#approval-cards)).

Because the decision does not wait for them, what background detectors find is not part of it:
their rules are missing from `explanation.rule_ids`, their findings from
`explanation.finding_classes` and `explanation.locations`, and they do not make the decision
`critical` (in enforce mode a critical decision whose event cannot be written is denied). Under the
default policy that leaves `injection-audit` and the `injection` class out of the decision on every
call but a tool call with a side effect, and `pii-audit` and the `pii` class out of it on every
call but a tool call with a side effect and a model request to a `tenant` or `unknown` destination.
They come in the decision's `FindingsEvent` instead (see [Background checks](#background-checks));
a host that needs them in the decision itself evaluates with `defer=False`.

`Decision.detector_versions` lists the detectors selected for the call, synchronous and
background, as `name@version` with the hash of the pattern set each used. For a declared detector
the hash is the digest of its declaration, so a decision can be tied back to the exact text that
was in force.

## Where detectors run

A `DetectorRunner` runs the local detectors outside the event loop, on workers its `executor`
chooses:

| `executor` | Built-in local detectors | Declared `pattern` and `terms` detectors, and local detectors of the host's own |
| --- | --- | --- |
| `ExecutorKind.PROCESS` (the default) | worker processes | threads |
| `ExecutorKind.THREAD` | threads | threads |
| `ExecutorKind.SYNC` | the event loop itself | the event loop itself |

A worker process is not handed a detector object: it rebuilds the detector from
`DETECTOR_REGISTRY` by its `name@version`, and every built-in local detector is registered there. A
declared detector exists only as the object built from its document, so it runs in a thread of the
guard's process even when the built-in ones run in worker processes, and so does any other local
detector that is not registered. The runner goes by `name@version` alone: a detector of the host's
own that has the name and version of a built-in one runs in worker processes as that built-in, so
it needs a name of its own. Remote detectors need no workers; they are awaited on the event loop.

The runner has two lanes, the foreground lane for the scans an answer is built on and the
[background lane](#the-background-lane). Each has workers of its own and starts each kind of them
when a scan first needs it: `max_workers` (default 2) worker processes and as many threads for the
foreground, `background_workers` of each for the background, by default as many as `max_workers`.
With `ExecutorKind.PROCESS` and the defaults the runner therefore runs up to four worker processes.

A local scan has a deadline that grows with the size of what it is sent, `Budget.local_ms`: 10 ms
plus 3 ms per KiB by default. In the foreground lane it starts when the scan is handed to the
workers, so when more scans are handed over at once than the lane has workers for them, from one
evaluation or from several, the last ones spend part of their time waiting. A host that runs many
local detectors per call, as documents that declare many `pattern` detectors do, or many calls at
once, raises `max_workers`. That does not help `terms` detectors: they run in threads and hold the
interpreter lock (see below), so all of them, of every tenant, take turns on one core, and each
normalizes the text anew. A document whose deny, mask or approval rules use more than a few
`terms` detectors over long texts can exceed the foreground budget; it keeps such lists few, or
leaves them to `audit` rules, which scan in the background. A scan that runs out of time fails, and its worker stays
busy until the detector returns, since a running scan cannot be stopped. The lane stops using
those workers, and the next scan that needs workers of that kind gets fresh ones. A detector of the
host's own therefore has to return: one that never does holds a worker for good, and every scan of
it that times out holds one more. Broken workers are replaced the same way: a process pool breaks
when one of its worker processes dies, for example when it is killed for its memory; the scan that
finds it broken fails, and the next one starts fresh workers.

Where worker processes are started by spawning them, as on macOS and Windows, a worker takes a few
hundred milliseconds to start, longer than the default budget of a short message. The first scans
of a fresh pool then time out, and since each timeout retires the pool, it may never warm up. A
host on such a platform raises `Budget.local_base_ms`, or runs `ExecutorKind.THREAD`. With the
fork start method, the default on Linux for the Python versions the guard supports, a worker
starts in a few milliseconds.

Worker processes run apart from the guard's process and from each other, as long as the machine
has cores to spare. Threads share the interpreter lock, with each other and with the event loop.
Pattern detectors release it while RE2 matches, but terms detectors and the built-in detectors hold
it while they run, so such a scan in a thread slows down the event loop and every other scan in a
thread, in either lane. With `ExecutorKind.SYNC`, which `build_quickstart_guard` uses and which
suits tests, there are no workers: every local detector runs on the event loop itself, background
ones included, so a scan holds up whatever the loop runs next, the caller's answer included.

## Background checks

A detector that only `audit` rules can use scans while the decision goes back to the caller, so a
slow or failing one never denies the call, and it holds up only an approval card, for a bounded
time ([Approval cards](#approval-cards)). Its scan starts just before the synchronous scan of the
same evaluation and runs in the runner's [background lane](#the-background-lane). What it finds is
written afterwards:

- A `FindingsEvent` (`event_type: "findings"`) is recorded through the `AuditSink` after the
  decision's `DecisionEvent`, under the same `decision_id`. It carries the summary of the context,
  the `locations` of the findings (at most `EngineSettings.max_locations`), their
  `finding_classes`, the ids of the `audit` rules they matched (`rule_ids`),
  `unchecked_detectors` (the background detectors that failed, because what they did not flag is
  unknown, not clean) and `display_args_redacted`: the argument previews of a tool call that the
  decision held back while the check ran, or `None` (see [Argument previews](#argument-previews)).
- It is written when the background detectors found something, when one of them failed, or when
  it carries argument previews, which it does also when the detectors found nothing.
- Nothing is written when the decision event was not, so findings never reach the audit trail
  without their decision. When the sink fails to write the `DecisionEvent`, or the evaluation is
  cancelled or fails before the event is written, the background scan is cancelled as well. With
  `audit=False` every detector runs before the decision is returned.
- A failure of a background detector never denies the decision. Only a decision that asks for
  approval of a tool call waits for the background detectors, and only so long, because its
  approval card shows the arguments; see [Approval cards](#approval-cards).
- `Decision.unchecked_detectors` lists, as `name@version`, the detectors whose findings the
  decision did not get: an optional or audit-only detector that failed while the decision waited
  for it, background detectors that did not start for lack of room, and the background detectors
  an approval stopped waiting for. Whoever reads the audit trail must not take the missing findings
  for a clean payload. Such a decision is `critical`, so in enforce mode its audit event is written
  fail-closed.

At most `EngineSettings.max_background_checks` (200) background checks run at once, the evaluations
that observe mode defers included. With no room left the audit-only detectors are not started and
are listed in `unchecked_detectors`. A tool call that a rule which selects no findings sends for
approval needs no room, since it runs every detector before it answers.

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

### Approval cards

An approver reads the argument previews on the card before anything happens, so a decision that
asks for approval of a tool call needs what every detector found. How it gets it depends on the
rule that asks:

- **A rule that selects no findings**, such as `tool-side-effect-approval` of the default policy.
  Such a call ends as an approval or a deny whatever the detectors find, so the engine starts no
  background check for it: every selected detector runs before the decision, in the foreground
  lane, as with `defer=False`. What the audit-only detectors find is part of the decision, and no
  `FindingsEvent` follows. Like every synchronous scan, a local one is held to the foreground
  budget (`Budget.local_ms`): one that runs out of time is listed in `unchecked_detectors`, and the
  card then shows no value.
- **A rule that selects findings**, such as a `require_approval` rule on secrets. Whether the call
  needs approval is known only once the synchronous scan is done, and by then the background check
  is running. The decision waits for it, for at most `EngineSettings.approval_scan_wait_s`
  (5 seconds) after the synchronous scan. The check takes its turn in the background lane behind
  all the other background work there, so under load it can take longer. When it does, the
  decision goes back without it: the background detectors are listed in `unchecked_detectors`, and
  the card shows no value. The check goes on, and once it has reported, its `FindingsEvent` carries
  the readable previews, unless a detector failed.

A host whose approvers have to see the values under load gives the background lane more workers
(`background_workers`), or the wait more time:

```python
from donkit_guard.engine import Engine, EngineSettings

engine = Engine(
    policy_source=policy_source,
    runner=runner,
    audit_sink=audit_sink,
    settings=EngineSettings(approval_scan_wait_s=10.0),
)
```

### The background lane

`DetectorRunner.run(..., background=True)` runs a scan in the runner's background lane. The engine
uses it for background checks and for the evaluations that observe mode defers; synchronous scans,
the re-evaluation after an approval among them, take the foreground lane. The background lane
keeps its work away from the foreground:

- Its local detectors run on `background_workers` workers of their own, by default as many as the
  foreground lane's `max_workers`, one scan per worker (see
  [Where detectors run](#where-detectors-run)). With `ExecutorKind.PROCESS` that is one more worker
  process for every foreground one.
- It keeps at most `max_background_remote` (default 16) remote calls in flight, so that the
  detectors' services keep room for the foreground calls.
- A background scan waits for its turn before its deadline starts, so a backlog never times it
  out, and a local one gets at least `Budget.background_min_ms` (1000 ms), since no answer depends
  on what it finds.

A backlog of background work therefore never takes a worker from a foreground scan. Turns are
counted per event loop. A background scan that is running can still slow a foreground one down,
depending on where the two run: worker processes keep apart on cores to spare, scans in threads
share the interpreter lock, and with `ExecutorKind.SYNC` every scan runs on the event loop. With
`ExecutorKind.THREAD`, a terms or built-in detector scanning in the background slows every
foreground scan down and can make one run out of time.

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
    background_workers=2,
    max_background_remote=16,
    budget=Budget(background_min_ms=1000.0),
)
```

The lane gives no priority within its own work: the background check of an approval card takes its
turn behind the other background checks and the deferred observe-mode evaluations, which is why the
card waits for it at most `EngineSettings.approval_scan_wait_s` ([Approval cards](#approval-cards)).
The check's deadline starts only once it runs, so the wait does not fail it. Without a backlog the
card waits for the longer of the synchronous and the background scan, not for both in turn,
because the background check starts first.

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
card and the `DecisionEvent` carry the same previews. A value is shown only once the evaluation
scanned it and every selected detector has reported on it. Otherwise it is blacked out whole: a
run of `█` as long as the value (up to `EngineSettings.preview_chars`).

A value the evaluation did not scan is blacked out in every preview, those of the `FindingsEvent`
included:

- **A value over the policy's `segment_limit_bytes`.** It is listed in the decision's
  `uninspected_parts`, for example as `oversized:tool_args/note`.
- **A value the payload marks uninspected**, such as a file the host passes on without its text.
- **A value whose segment is listed in `seen_segments`.** An earlier call scanned it, and this
  evaluation does not have its findings. A host that lists the segments of tool arguments there
  sees those values blacked out, on the approval card as well.

Until every selected detector has reported, the guard cannot tell which values hold findings, so it
shows none of them. That happens in four cases:

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
- **An approval stopped waiting for its background check.** The background detectors are listed
  in `unchecked_detectors`, and the readable previews follow in the `FindingsEvent` once the check
  has reported, as they do for a check that is still running.

A decision that asks for approval of a tool call waits for every detector instead, for a bounded
time (see [Approval cards](#approval-cards)), because the approver reads the card before anything
happens: the card shows the values with what every detector found blacked out, unless a detector
failed, did not start or did not report in time, and then it shows none of them. A decision that
waits for every detector anyway, with `defer=False` or `audit=False`, or the decision that observe
mode records later, shows the values the same way.

The previews of a `FindingsEvent` are rendered from a copy of the arguments taken when the
decision was built, so what the host changes or adds in its arguments after the answer never
reaches them: they show what the detectors scanned.

Previews black out what the evaluation found in the payload, which the host builds from the
arguments. The only values a preview can show unscanned are those the payload does not carry at
all: a value the host left out of it, or one that `Payload.from_json` makes no segment for, such as
a boolean, a null or a number with fewer than `min_number_digits` (7) digits.

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
kept, the least recently used one going first, and a declaration whose detector was dropped is
built anew the next time it is needed. A document declares up to 20 detectors, so the default
keeps those of about a dozen documents that declare all 20; a host with more tenants like that
raises `max_cached`, counting a few MiB of memory for a terms detector with a full list. A pattern
or terms detector is built outside the lock that guards what is kept, so a long build holds up no
other caller, and callers that miss the same declaration at once wait for that one build.
`cached_for` returns the detectors when every one is built already and never builds, so the
engine asks it on the event loop and goes to a worker thread only when something is missing. The remote detectors share the HTTP connections of their
`DeclaredDetectors`, one pool per origin, which stay open until `aclose`, so a remote detector
dropped from the cache keeps working for an evaluation that still holds it.

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

The engine calls `DeclaredDetectors.detectors_for` in a worker thread (`asyncio.to_thread`), and
only for a bundle that declares detectors, so that building a long declaration does not stall the
event loop. A host that subclasses `DeclaredDetectors` keeps `detectors_for` safe to call from
several threads at once.

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

# Architecture

## Components

- **Context** (`donkit_guard.context`): `GuardContext` — an open, typed attribute set built by the host adapter. Well-known dimensions are optional conventions.
- **Payload** (`donkit_guard.payload`): a list of `Segment`s (a message, a document chunk, a tool result, one JSON leaf of tool arguments). A segment id hashes the source, the JSON pointer and the text, so every leaf is addressable on its own and detector results are cached across turns: only new segments are scanned.
- **Policy** (`donkit_guard.policy`): versioned YAML documents with layers of attribute-matching rules and, optionally, declared detectors.
- **Engine** (`donkit_guard.engine`): evaluates context + payload into a `Decision`; detectors that only feed audit rules run in the background after it.
- **Detectors** (`donkit_guard.detectors`): versioned `secrets`, `pii-checksum`, `pii-ner` (remote) and `injection-heuristic` detectors, run through a `DetectorRunner` outside the event loop with a per-segment result cache. A call may name the set of detectors to run; a worker process rebuilds a built-in detector from the registry and a declared one from its declaration. The runner has two lanes: the foreground lane for the scans a decision waits for, and a background lane, with workers of its own, for background checks and deferred observe-mode evaluations. See [detectors.md](detectors.md).
- **Declared detectors** (`donkit_guard.declared`): `pattern`, `terms` and `remote` detectors that a policy document describes as data. `DeclaredDetectors` builds them per tenant; `donkit_guard.selection` decides per call which detectors run synchronously, in the background or not at all.
- **Analyze contract** (`donkit_guard.adapters`, `donkit_guard.http`, `donkit_guard.conformance`, `docs/contract/`): the public `POST /v1/analyze` contract that remote detectors speak, an HTTP client for it, a conformance check and its OpenAPI description. See [remote-detectors.md](remote-detectors.md).
- **Masking** (`donkit_guard.masking`): deterministic placeholders that keep JSON valid; masking tool arguments is refused unless the action descriptor marks them maskable.
- **Approvals** (`donkit_guard.approvals`, `donkit_guard.approval_flow`): one-time approvals bound to the exact action, the approver and the policy version.
- **Adapters** (`donkit_guard.adapters`, plus `ActionCatalog` in `donkit_guard.actions`): the protocols a host implements; in-memory implementations in `donkit_guard.memory` for tests and quick start.
- **PII service** (`services/pii`, image `guard-pii`): the reference analyze service, Presidio + spaCy behind the analyze contract. The core makes network calls only to analyze services: this one and any `remote` detector a policy document declares.

## Context model

| Dimension | Meaning | Examples of what a host maps here |
| --- | --- | --- |
| `principal` | who is acting, taken from the host's authenticated session; `kind` ∈ user, end_user, service, api_key, agent, anonymous; `approver=True` when the host allows this principal to approve actions on this context | user id, API-key subject, service identity |
| `on_behalf_of` | the human a service or agent acts for | the original user of a delegated call |
| `tenant` | isolation boundary for policies, approvals and audit | organisation, workspace, account |
| `agent` | the automated actor | agent id and config version |
| `run` | the unit of execution; `id` is stable and binds approvals; `untrusted_content_seen` is set by the host once a document or tool result entered the context | conversation, job, trace |
| `delegation` | chain information for delegated calls | caller agent, depth, path, trace id |
| `action` | what is about to happen: `kind` (llm_request, tool_call, tool_result), tool, operation, resource, arguments, `effect` (read, write, execute, spend, egress, unknown), `effect_source` (host, operator, tool_server), `destination` for model calls (provider, model, hosting, endpoint host, locality, trust) | tool name and arguments; resolved model and provider |
| `attributes` | anything else policies should see | roles, labels, surface, environment |

Rules that hold regardless of the host:

- Every decision belongs to at most one tenant; policies, approvals and audit are isolated by it. The detector result cache is not isolated that way for the built-in detectors: a span is a pure function of the segment's content, so the cache is content-addressed and process-wide, and a hit requires byte-identical text under the same pointer. A declared detector is different, because the tenant's document defines it: its cache key carries the tenant and the digest of its declaration, so another tenant never reads its results and an edited declaration never reads the results of its earlier version.
- `principal` may be absent. Approvals require a principal (or `on_behalf_of`) with `approver=True`; who is an approver is the host's decision, never the caller's claim.
- `run.id` is stable for the unit of execution and binds approvals to it.
- The side-effect class of an action is declared by the host from a source it trusts. `unknown` is gated like `write`; a `read` declared by the tool provider itself (`effect_source=tool_server`) is gated like `write` until an operator confirms it.
- A `Decision` never contains matched text: findings are addressed by segment id, JSON pointer and offsets. `Decision.detector_versions` maps every detector selected for the call (`name@major`, whether it ran synchronously or in the background) to the hash of the pattern set it used, so a finding can be tied back to the rules that produced it; for a declared detector the hash is the digest of its declaration. `Decision.unchecked_detectors` lists the detectors whose findings the decision did not get, so that missing findings are never mistaken for a clean payload. The guard renders tool arguments only as bounded previews, one per JSON pointer, with every detected span blacked out: `Decision.display_args_redacted`, which the approval card and the decision event carry, and, for a decision whose previews waited for a background check, `FindingsEvent.display_args_redacted`. A value is shown only once every selected detector has reported on it; until then it is blacked out whole ([detectors.md](detectors.md#argument-previews)).

## Evaluation

The engine evaluates in two phases and combines verdicts on a strictness lattice:

1. Rules that do not depend on findings are matched against the context (action kind, effective effect, effect source, tool name globs, principal kind, destination trust, attributes).
2. The rules that reference findings and match the context decide which detectors the call needs. The candidates are the runner's own detectors and the detectors the bundle's documents declare, built for the context's tenant. A detector runs *synchronously* when a rule with any action but `audit` could use its findings, in the *background* when only `audit` rules could, and not at all otherwise. Whether a rule could use a detector is judged before scanning, from the detector's classes and, when it declares them, its subtypes ([detectors.md](detectors.md#which-detectors-run)).
3. The background detectors start on the *new* segments of the payload in the runner's background lane, and the synchronous detectors scan the same segments in the foreground lane (a segment already scanned by the same detector, version, pattern set and tenant scope is served from the cache); every rule is then matched against context + the synchronous findings (finding class, subtype, minimum score, segment trust).
4. Verdicts combine as `deny > require_approval > mask > allow`. A deny with `hard: true` cannot be lowered by an approval; an approval lowers only `require_approval`. `mask` applies to every mask-class finding regardless of the final outcome; when a mask cannot be applied safely (a tool argument), the decision is `deny`.
5. A protected action (a tool call whose effective effect is not `read`) with no matching rule is denied.
6. The decision is recorded. What the background detectors find is recorded afterwards as a `FindingsEvent` under the same `decision_id`, after the decision event and only when that event was written; a background detector that failed is listed there as unchecked.

Background checks never change the outcome, and the decision does not include what they find: its rule ids, finding classes, locations and `critical` flag come from the synchronous findings alone, so under the default policy `injection-audit`, and `pii-audit` on every call but a model request to a destination outside the platform's trust, appear only in the `FindingsEvent` unless the call is evaluated with `defer=False`. While a check runs, the argument previews of a tool call are blacked out whole, and the readable previews follow in the `FindingsEvent`. A decision that asks for approval of a tool call waits for the background detectors, because the approval card shows the arguments; it waits for the longer of the two scans, not for both in turn. If one of them failed, or none could start for lack of capacity (`EngineSettings.max_background_checks`), the card shows no argument value at all and the decision lists the detectors in `unchecked_detectors`. Background scans take the runner's background lane, so they never delay a scan in the foreground lane; with `ExecutorKind.SYNC`, which has no workers, local detectors run on the event loop and a background scan does hold it up. What is still running when the process ends, or when the event loop closes, is lost; `Engine.drain()` and `Engine.aclose()` exist for orderly shutdown ([detectors.md](detectors.md#background-checks)).

In `observe` mode, which never blocks, the whole evaluation runs in the background: `Engine.evaluate` answers at once with an `allow` whose code is `observe_deferred`, and the decision that the evaluation reaches is recorded later under the same `decision_id` ([detectors.md](detectors.md#observe-mode)). An execution event the host records for that answer before the decision is written waits for it, so the sink receives the decision event first. `evaluate(..., defer=False)` evaluates before it returns; the freshness check that follows an approval uses it, and so does a host that runs a new event loop per call, whose background work would otherwise be lost when the loop closes.

Finding classes are `enforceable` (secret, pii, corporate) or `signal` (injection). A rule with any action other than `audit` on a signal class fails policy validation: detection of suspicious content is reported, never turned into enforcement by itself. Policies express stricter gates by provenance instead (`untrusted_content_seen`, segment trust). A declared detector may only report enforceable classes.

Failure behaviour: in `enforce` mode a failure is a `deny` carrying the code that names it — a policy that cannot be resolved, validated or built (a declared detector whose optional package is missing) is `policy_error`, a timeout or error of a required detector that a deciding rule could use is `detector_unavailable`, a failed write of a critical audit event is `audit_unavailable` — and any deny clears the masked segments and their locations, so a host cannot mistake a denied decision for a maskable one. A detector that only `audit` rules can use, or that its declaration marks `required: false`, never fails the decision: it is listed as unchecked, in `Decision.unchecked_detectors` when the decision waited for it and in the `FindingsEvent` when it ran in the background. In `observe` mode the decision records `would_outcome` and the action continues. Attachments and oversized segments are `uninspected_parts` of the decision; the policy decides whether that means `deny` (strict profile) or an audited allow.

Streaming: requests are evaluated before they leave; the payload is materialised, so no buffering is needed on the request side. Response-side buffering is documented with its limits when it lands.

## Approvals

Approvals are asynchronous by construction:

- `Decision.outcome = require_approval` is turned into an approval flow by `ApprovalFlow`: it looks up an already decided approval for the same tenant, action digest (hash of the essential arguments) and context hash; consumes an approved one exactly once (compare-and-set), re-evaluates the action against the current policy and executes only if the outcome is still `require_approval` (otherwise the approval is `stale`).
- Otherwise it creates a `pending` record with a fixed expiry and hands it to the host's `ApprovalChannel`, which reports `inline` (the host can pause and ask now), `queued` (someone will decide later; the decision is `approval_pending`) or `unavailable` (deny). A rejection is remembered for the approval TTL for the same action digest and context (the same principal in the same run): a retry within that window, inline or queued, answers `approval_rejected` without a new prompt, so a "no" ends the loop instead of queueing another record.
- Only the bound principal may decide; changed essential arguments produce a new digest and therefore a new approval; expiry is a deny, never a retry.
- The approval card is built from the decision's `display_args_redacted`, after every detector it depends on has reported: a decision that asks for approval of a tool call waits for its background detectors, and when one of them did not report, the card blacks out every argument value instead of guessing which ones hold findings. The background detectors of a card take their turn in the runner's background lane behind other background work, so a backlog there slows cards down. The re-evaluation that follows an approval runs with `defer=False` in the foreground lane, so it leaves no background work behind.
- The resolved decision is audited: the outcome the host acts on (`approved`, `approval_rejected`, `approval_pending`, `approval_timeout`, `approval_stale`) is recorded as a second decision event carrying the same `decision_id` as the `approval_required` event it answers, and an approval that a policy change has invalidated is marked `stale` in the approval store as well.

## Adapter contract

| Interface | Responsibility |
| --- | --- |
| `PolicySource.resolve(ctx)` | the policy bundle for a context (its version and mode: `off`, `observe`, `enforce`), so tenants can run in different modes; called up to three times for one approved call (evaluation, approval TTL, re-evaluation after the approval), so a remote source should cache per context |
| `DetectorClient.analyze(request, deadline_s)` | a remote detector (the `guard-pii` service, or any service that speaks the [analyze contract](remote-detectors.md)) with a deadline; a failure or timeout is reported, never treated as "clean". `donkit_guard.http.HttpAnalyzeClient` implements it over HTTP |
| `CredentialResolver.token(tenant_id, name, endpoint)` | the secret behind a credential name that a policy document gives a remote detector, for the endpoint the token would be sent to, so that a host can bind a credential to its tenant and its service; `None` means there is none, and the detector fails without sending a request. Credentials are opt-in: without a resolver none resolves. `EnvCredentialResolver` reads `DONKIT_GUARD_CREDENTIAL_<NAME>` from the environment, for a host that writes every policy document itself |
| `EndpointGuard.check(url)` | whether a remote detector may call a URL taken from a policy document; raise `EndpointRejected` to refuse. The default, `AllowAllEndpoints`, accepts every URL, so a host that takes documents from its tenants provides its own, against internal networks and metadata services |
| `AuditSink.record(event)` | persists decision, execution and findings events; in enforce mode a failed write of a critical event fails the decision closed |
| `ApprovalChannel.deliver(record, ctx)` / `await_decision(approval_id, deadline_s)` | whether and how this surface can ask, and the inline wait when it can |
| `ApprovalStore` | pending and decided approvals with expiry, single-use consumption, the essential-argument digest, and marking a record stale when the policy moved under it |
| `ActionCatalog.describe(tool, arguments)` (`donkit_guard.actions`) | the host's knowledge about a tool: effect class and its source, essential and maskable arguments, resource references |

## Deployment modes

Embedded: the host runtime calls the engine in-process before every model call and every tool execution. The guard owns the detector worker pool, so the host owns the guard's lifetime:

```python
from donkit_guard import build_quickstart_guard

async with build_quickstart_guard() as guard:
    decision = await guard.authorize(ctx, payload)
```

`await guard.aclose()` releases the same resources where a context manager does not fit: it gives the background checks that are still running `EngineSettings.background_drain_s` to finish, cancels the rest, closes the HTTP connections of the declared remote detectors and releases the detector pools. The quick-start guard runs its detectors on the event loop (`ExecutorKind.SYNC`), which suits a REPL and tests; a host builds its `Engine` with a `DetectorRunner` that runs them on workers (`ExecutorKind.PROCESS`, the default, or `ExecutorKind.THREAD`). An engine belongs to the event loop it is used on, because its background work runs as tasks of that loop and its HTTP connections are bound to it: a host that evaluates on several event loops gives each loop an engine of its own ([detectors.md](detectors.md#wiring-in-a-host)). Standalone: an external gateway forwards LLM requests and MCP calls to the guard service, which returns allow / block / mask decisions and holds pending approvals until an administrator decides. Both modes share this package; only the adapters differ.

# Architecture

## Components

- **Context** (`donkit_guard.context`): `GuardContext` — an open, typed attribute set built by the host adapter. Well-known dimensions are optional conventions.
- **Payload** (`donkit_guard.payload`): a list of `Segment`s (a message, a document chunk, a tool result, one JSON leaf of tool arguments). A segment id hashes the source, the JSON pointer and the text, so every leaf is addressable on its own and detector results are cached across turns: only new segments are scanned.
- **Policy** (`donkit_guard.policy`): versioned YAML documents with layers of attribute-matching rules.
- **Engine** (`donkit_guard.engine`): evaluates context + payload into a `Decision`.
- **Detectors** (`donkit_guard.detectors`): versioned `secrets`, `pii-checksum`, `pii-ner` (remote) and `injection-heuristic` detectors, run through a `DetectorRunner` outside the event loop with a per-segment result cache.
- **Masking** (`donkit_guard.masking`): deterministic placeholders that keep JSON valid; masking tool arguments is refused unless the action descriptor marks them maskable.
- **Approvals** (`donkit_guard.approvals`, `donkit_guard.approval_flow`): one-time approvals bound to the exact action, the approver and the policy version.
- **Adapters** (`donkit_guard.adapters`, plus `ActionCatalog` in `donkit_guard.actions`): the protocols a host implements; in-memory implementations in `donkit_guard.memory` for tests and quick start.
- **PII service** (`services/pii`, image `guard-pii`): the only network participant; Presidio + spaCy behind an HTTP contract.

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

- Every decision belongs to at most one tenant; policies, approvals and audit are isolated by it. The detector result cache is not: a span is a pure function of the segment's content, so the cache is content-addressed and process-wide, and a hit requires byte-identical text under the same pointer.
- `principal` may be absent. Approvals require a principal (or `on_behalf_of`) with `approver=True`; who is an approver is the host's decision, never the caller's claim.
- `run.id` is stable for the unit of execution and binds approvals to it.
- The side-effect class of an action is declared by the host from a source it trusts. `unknown` is gated like `write`; a `read` declared by the tool provider itself (`effect_source=tool_server`) is gated like `write` until an operator confirms it.
- A `Decision` never contains matched text: findings are addressed by segment id, JSON pointer and offsets. `Decision.detector_versions` maps every detector configured for the decision (`name@major`) to the hash of the pattern set it used, so a finding can be tied back to the rules that produced it. `Decision.display_args_redacted` is the only rendering of the tool arguments the guard produces: one bounded preview per JSON pointer with every detected span blacked out, and it is what both approvers and auditors see.

## Evaluation

The engine evaluates in two phases and combines verdicts on a strictness lattice:

1. Rules that do not depend on findings are matched against the context (action kind, effective effect, effect source, tool name globs, principal kind, destination trust, attributes).
2. If any rule references findings, detectors run over the *new* segments of the payload (a segment already scanned by the same detector version and pattern set is served from the cache); every rule is then matched against context + findings (finding class, subtype, minimum score, segment trust).
3. Verdicts combine as `deny > require_approval > mask > allow`. A deny with `hard: true` cannot be lowered by an approval; an approval lowers only `require_approval`. `mask` applies to every mask-class finding regardless of the final outcome; when a mask cannot be applied safely (a tool argument), the decision is `deny`.
4. A protected action (a tool call whose effective effect is not `read`) with no matching rule is denied.

Finding classes are `enforceable` (secret, pii, corporate) or `signal` (injection). A rule with any action other than `audit` on a signal class fails policy validation: detection of suspicious content is reported, never turned into enforcement by itself. Policies express stricter gates by provenance instead (`untrusted_content_seen`, segment trust).

Failure behaviour: in `enforce` mode a failure is a `deny` carrying the code that names it — a policy that cannot be resolved or validated is `policy_error`, a detector timeout or error is `detector_unavailable`, a failed write of a critical audit event is `audit_unavailable` — and any deny clears the masked segments, so a host cannot mistake a denied decision for a maskable one. In `observe` mode the decision records `would_outcome` and the action continues. Attachments and oversized segments are `uninspected_parts` of the decision; the policy decides whether that means `deny` (strict profile) or an audited allow.

Streaming: requests are evaluated before they leave; the payload is materialised, so no buffering is needed on the request side. Response-side buffering is documented with its limits when it lands.

## Approvals

Approvals are asynchronous by construction:

- `Decision.outcome = require_approval` is turned into an approval flow by `ApprovalFlow`: it looks up an already decided approval for the same tenant, action digest (hash of the essential arguments) and context hash; consumes an approved one exactly once (compare-and-set), re-evaluates the action against the current policy and executes only if the outcome is still `require_approval` (otherwise the approval is `stale`).
- Otherwise it creates a `pending` record with a fixed expiry and hands it to the host's `ApprovalChannel`, which reports `inline` (the host can pause and ask now), `queued` (someone will decide later; the decision is `approval_pending`) or `unavailable` (deny). A rejection is remembered for the approval TTL for the same action digest and context (the same principal in the same run): a retry within that window, inline or queued, answers `approval_rejected` without a new prompt, so a "no" ends the loop instead of queueing another record.
- Only the bound principal may decide; changed essential arguments produce a new digest and therefore a new approval; expiry is a deny, never a retry.
- The resolved decision is audited: the outcome the host acts on (`approved`, `approval_rejected`, `approval_pending`, `approval_timeout`, `approval_stale`) is recorded as a second decision event carrying the same `decision_id` as the `approval_required` event it answers, and an approval that a policy change has invalidated is marked `stale` in the approval store as well.

## Adapter contract

| Interface | Responsibility |
| --- | --- |
| `PolicySource.resolve(ctx)` | the policy bundle for a context (its version and mode: `off`, `observe`, `enforce`), so tenants can run in different modes; called up to three times for one approved call (evaluation, approval TTL, re-evaluation after the approval), so a remote source should cache per context |
| `DetectorClient.analyze(request, deadline_s)` | a remote detector (the `guard-pii` service) with a deadline; a failure or timeout is reported, never treated as "clean" |
| `AuditSink.record(event)` | persists decision and execution events; in enforce mode a failed write of a critical event fails the decision closed |
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

`await guard.aclose()` releases the same resources where a context manager does not fit. Standalone: an external gateway forwards LLM requests and MCP calls to the guard service, which returns allow / block / mask decisions and holds pending approvals until an administrator decides. Both modes share this package; only the adapters differ.

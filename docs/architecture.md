# Architecture

## Components

- **Policy core** (`donkit_guard.policy`, `donkit_guard.engine`): loads versioned, validated policies and evaluates a
  request or a tool call into a `Decision` with a full explanation.
- **Detectors** (`donkit_guard.detectors`): secrets, personal data with locale-specific identifier sets, prompt-injection
  heuristics. Each detector carries a version that is recorded in every decision.
- **Adapters** (`donkit_guard.adapters`): interfaces the host implements, such as the audit sink, the approval store,
  the policy source and the identity context. In-memory implementations ship for tests and the quick start.
- **Standalone service** (`donkit_guard.standalone`): the gateway-facing HTTP service (LLM and MCP hooks, admin API)
  used with an external gateway in self-hosted deployments.

## Context model

The engine evaluates a `GuardContext`: an open, typed attribute set built by the host adapter. Nothing in the core
requires a specific identity or tenancy model. Well-known dimensions are optional conventions that policies may
reference:

| Dimension | Meaning | Examples of what a host maps here |
| --- | --- | --- |
| `principal` | who is acting, taken from the host's authenticated session | user id, service identity, API key subject |
| `tenant` | isolation boundary for policies, caches, approvals and audit | organisation, workspace, account, team |
| `agent` | the automated actor performing the request | agent id and version, assistant name, bot |
| `run` | the unit of execution the decision belongs to | conversation, session, job, trace id |
| `action` | what is about to happen | tool name, operation, resource, arguments and the host-declared side-effect class (`read`, `write`, `execute`, `spend`, `unknown`); or the resolved model/provider destination for LLM calls |
| `attributes` | anything else the host wants policies to see | roles, labels, surface, environment, data classification |

Rules that hold regardless of the host:

- A host that has no tenants leaves `tenant` empty and writes policies without it. When tenants exist, every decision
  belongs to exactly one tenant, and policies, caches, approvals and audit are isolated by it; other parties involved
  in the call (a caller from another tenant, for instance) are recorded as attributes.
- `principal` may be absent: headless jobs and unauthenticated surfaces produce decisions too. Policies state what an
  anonymous principal may do; approvals always require a principal.
- `run.id` is a stable identifier chosen by the host for the unit of execution. It keys the decision cache and binds
  approvals to the execution they were granted for; a separate trace identifier can be attached for correlation.
- The side-effect class of an action is declared by the host, never inferred by the core. `unknown` is gated like
  `write`.

Policy selectors match on attributes (attribute-based access control); explicit deny rules and approval requirements
are expressed the same way.

## Adapter contract

The host implements a small set of interfaces; in-memory versions ship for tests and the quick start.

| Interface | Responsibility |
| --- | --- |
| `PolicySource` | returns the resolved policy bundle for a context, including its version and mode (`observe` or `enforce`), so one tenant can run in observe mode while another enforces |
| `DetectorClient` | runs a versioned detector (in-process or remote) with a deadline; a failure or timeout is reported, never silently treated as "clean" |
| `AuditSink` | persists decision and execution-outcome events; in enforce mode a sink failure fails the decision closed |
| `ApprovalChannel` | answers whether the current surface can pause and ask, who may approve for this context, and delivers the request; when it cannot ask, the policy decides between deny and a queued approval |
| `ApprovalStore` | persists pending and decided approvals with their expiry, single-use consumption and the hash of the essential arguments |

## Decision order

1. Platform hard-deny rules.
2. Organisation hard-deny rules.
3. Effect gate: the tool's side-effect class against the policy for the current identity.
4. Detectors on the full payload (secrets, PII, injection).
5. Approval requirement.
6. Allow.

An explicit deny always wins. A protected action with no matching allow is denied. Detection results never widen
permissions on their own.

## Deployment modes

Embedded: the host runtime calls the core in-process before every model call and every tool execution.
Standalone: an external gateway forwards LLM requests and MCP calls to the service, which returns allow / block /
mask decisions and holds pending approvals until an administrator decides.

The two modes share the same policy core; only the adapters differ.

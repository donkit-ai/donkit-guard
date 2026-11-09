# Standalone deployment

The standalone deployment puts the guard in front of any AI application without changing its code:
the application sends its LLM requests and MCP tool calls to [agentgateway](https://github.com/agentgateway/agentgateway)
instead of the provider, and the gateway asks `guard-standalone` about each of them before anything leaves.
It needs no Donkit account, calls no external security API and sends no telemetry.

```
application ──► agentgateway :3000 ──► LLM provider / MCP servers
                     │  ext_proc (LLM route), ExtMcp (MCP route), gRPC :9090
                     ▼
               guard-standalone ──► guard-pii (NER)          internal network,
                     │                                       no route out
                     ▼
               SQLite or PostgreSQL: decisions, approvals, policy versions
```

`guard-standalone` runs the same `donkit_guard` package and the same policy documents as an embedded
host: `examples/policies/standalone.yaml` decides alike in both (`tests/test_standalone_policy.py`).

## Quick start

```bash
git clone https://github.com/donkit-ai/donkit-guard && cd donkit-guard
export GUARD_ADMIN_TOKEN=$(openssl rand -hex 24)
export GUARD_API_KEYS="[{\"sha256\": \"$(printf %s my-backend-key | sha256sum | cut -d' ' -f1)\", \"tenant\": \"default\"}]"
mkdir -p deploy/agentgateway/secrets
printf %s "$OPENAI_API_KEY" > deploy/agentgateway/secrets/llm-api-key
docker compose up -d
```

Then point an OpenAI client at the gateway, with the quick-start client key of
`deploy/agentgateway/config.yaml` (replace it before anything but a trial):

```bash
curl -s localhost:3000/v1/chat/completions \
  -H 'Authorization: Bearer guard-quickstart-key-change-me' \
  -H 'x-guard-principal: alice' \
  -H 'Content-Type: application/json' \
  -d '{"model": "gpt-4o-mini", "messages": [{"role": "user", "content": "export DATABASE_PASSWORD=Xk29vLqP7mZr4TnW"}]}'
# 403 {"error": {"type": "guardrail_blocked", "code": "policy_denied", ...}}
```

The guard's own HTTP API is published through the gateway on `localhost:8080`:

```bash
curl -s localhost:8080/readyz
curl -s -H "Authorization: Bearer $GUARD_ADMIN_TOKEN" localhost:8080/admin/approvals
```

## Who a request belongs to

The **tenant** of a gateway exchange comes only from the gateway, after it authenticated the caller: the
`apiKey` policy attaches metadata to each key, and the route hands `apiKey.tenant` to the guard as an
ext_proc request attribute or ExtMcp metadata. A client cannot set it. An exchange without a tenant is
refused (`401 unauthenticated`).

The application names the person and the conversation it acts for in headers. The guard trusts them as far
as it trusts the key holder, which is the application's backend, never an end user:

| Header | Meaning | Default |
| --- | --- | --- |
| `x-guard-principal` | the person the application acts for; approvals are asked of them | none: actions that need an approval are denied (`approval_unavailable`) |
| `x-guard-principal-kind` | `user`, `end_user`, `service`, `api_key`, `agent`, `anonymous` | `user` |
| `x-guard-approver` | `false` when this person may not approve their own actions | `true` |
| `x-guard-run` | the conversation or run; an approval binds to it | MCP: the `mcp-session-id`; LLM: one per request |
| `x-guard-agent` | the agent, for audit and policies | none |

For an identity provider instead of API keys, replace `apiKey` with `jwtAuth` on both routes and take the
tenant from a claim (`tenant: jwt.org_id`); the example is at the end of `deploy/agentgateway/config.yaml`.
The guard needs no change.

## The LLM route (ext_proc)

The gateway buffers the request body and sends it whole. The guard reads OpenAI-compatible
`/chat/completions` requests: every message's text, the arguments of the `tool_calls` in the history, tool
results (`role: tool`, untrusted) and the descriptions and parameter schemas of `tools`. Images and other
non-text parts are uninspected content, which the policy's `unsupported_content` decides on.

- **allow**: the request goes on unchanged.
- **mask**: each finding is replaced by a placeholder at its own JSON pointer. `tool_calls`, `tool_call_id`
  and `tools` reach the provider unchanged; the guard sets the new `content-length`.
- **deny** (and any approval outcome, which an LLM exchange cannot wait for): the gateway answers at once,
  `403` with `{"error": {"type": "guardrail_blocked", "code": ..., "message": ..., "decision_id": ...}}`.
- Any other request (another path or method, a body that is not JSON) is refused with `400
  unsupported_request`, unless `GUARD_UNSUPPORTED_REQUESTS=allow`.

The request is evaluated with `action_kind: llm_request` and a destination of provider
`GUARD_LLM_PROVIDER`, the requested model and trust `GUARD_LLM_DESTINATION_TRUST` (`unknown` by default), and
the context attribute `phase: request`.

Responses are evaluated with `phase: response` and no destination, so destination rules do not apply to them:

- A JSON completion is held until it is complete, then allowed, masked in place, or replaced by the error
  object (the status stays `200`, because the headers are already on their way).
- A server-sent event stream is released window by window: the text of the events is collected until
  `GUARD_STREAM_WINDOW_CHARS` (1024) characters are due, checked together with the last
  `GUARD_STREAM_OVERLAP_CHARS` (256) already released (so a secret split between two windows is seen whole),
  and the events of that window are released. A window that is refused, or that a mask rule matches, ends the
  stream with one event `data: {"error": {"type": "guardrail_blocked", ...}}` and no `[DONE]`. What was
  released before cannot be recalled, and a stream is never masked after it started.

A failure inside the guard answers fail-closed: `503 guard_error` for a request, the error object or event
for a response. With `failureMode: failClosed` the gateway refuses the exchange when the guard is unreachable.

## The MCP route (ExtMcp)

`tools/call` is checked before the tool runs, with `action_kind: tool_call`, the tool name, its arguments
and the attribute `mcp_service` (the target name in the gateway). Other methods pass.

- **deny**: the tool never runs; the client receives JSON-RPC error `-32001` with the reason and
  `data: {"status": "denied", "code", "decision_id"}`.
- **approval_pending**: the same error with `data.status: approval_pending`, the `approval_id` and
  `expires_at`. The application shows the request to the principal and relays their answer to
  `POST /admin/approvals/{id}/decide`; then the client repeats the same call in the same session, and it
  runs once. A repeated call after that asks again.
- **mask**: the call goes on with the findings in its maskable arguments replaced, the shape of the
  arguments unchanged. A finding in an argument the catalog does not declare maskable cannot be masked
  safely, and the call is denied (`masking_impossible`).

The result of a `tools/call` is checked with `action_kind: tool_result` (the MCP target stands in for the
tool name, which the result does not carry): masked in place or refused.

### The tool catalog

What the guard knows about each tool comes from `GUARD_TOOL_CATALOG_FILE`
([example](../examples/standalone/tools.yaml)), read at start:

```yaml
tools:
  - tool: send_email
    effect: egress               # read, write, execute, spend, egress
    effect_source: operator
    essential_args: ["/to", "/subject"]   # what an approval binds to; all arguments by default
    maskable_args: ["/body"]              # where findings may be replaced; none by default
```

A tool without an entry has an unknown effect, which the policy gates as a write.

## HTTP API

Client endpoints take `X-API-Key`: the key's SHA-256 is matched against `GUARD_API_KEYS`, and the key's
tenant is the request's (another tenant in the body is refused with `403`).

| Endpoint | Body | Answer |
| --- | --- | --- |
| `POST /v1/authorize` | `context` (a [`GuardContext`](architecture.md)), `payload`: items `{source, trust, text}` or `{source, trust, data}`; a tool call's `context.action.arguments` are inspected without being repeated | `decision`; on `mask`, `masked_payload` (the items in order) and `masked_arguments` |
| `POST /v1/executions` | `decision_id`, `outcome` (`success`, `error`, `skipped`), `error_class`, `duration_ms` | `{"recorded": true}`; another tenant's decision is `404` |

Admin endpoints take `Authorization: Bearer $GUARD_ADMIN_TOKEN`. The token authenticates the application's
backend, which relays its users' answers; it does not let an administrator approve for someone else.

| Endpoint | |
| --- | --- |
| `GET /admin/approvals?status=pending&tenant=&limit=` | approvals, newest first |
| `POST /admin/approvals/{id}/decide` | `{"decision": "approve" \| "reject", "responder": "<principal>"}`; `403 responder_mismatch` unless the responder is the principal the approval was asked of, `409` when it is no longer pending, `410` when it expired |
| `GET /admin/decisions?tenant_id=&run_id=&agent_id=&limit=&before=` | decisions newest first, with their execution and late findings; pass `next_cursor` as `before` for the next page |
| `GET /admin/policy` | the active version, its digest, rules, and the error of the last refused reload |
| `POST /admin/policy/reload` | applies the file now; `422` with the error when it does not load |

Probes: `GET /healthz` (the process is up), `GET /readyz` (`503` unless the policy is loaded, the database
answers and guard-pii answers or is disabled), `GET /metrics` (Prometheus text: decisions by surface and
outcome, policy reloads and refused reloads, gateway errors, expired approvals).

## Configuration

| Variable | Default | |
| --- | --- | --- |
| `GUARD_POLICY_FILE` | `/etc/guard/policy.yaml` in the image | the policy document; required |
| `GUARD_POLICY_CHECK_INTERVAL_S` | `1` | how often the file's modification time is checked |
| `GUARD_TOOL_CATALOG_FILE` | none | the tool catalog |
| `GUARD_DB_URL` | `sqlite+aiosqlite:////data/guard.db` in the image | or `postgresql+asyncpg://user:password@host/db` |
| `GUARD_DB_MIGRATE` | `true` | apply the migrations at start |
| `GUARD_PII_URL` | none | base URL of guard-pii, e.g. `http://guard-pii:8080` |
| `GUARD_PII_DISABLED` | `false` | run without NER; one of the two is required |
| `GUARD_API_KEYS` | none, required | JSON list of `{"sha256", "tenant", "name"}` |
| `GUARD_ADMIN_TOKEN` | none, required | at least 16 characters |
| `GUARD_HTTP_PORT`, `GUARD_GRPC_PORT` | `8080`, `9090` | |
| `GUARD_MAX_BODY_BYTES` | `1048576` | the largest API body, LLM request or response, and MCP message |
| `GUARD_DETECTOR_EXECUTOR` | `thread` | `process` runs the built-in detectors in worker processes |
| `GUARD_DETECTOR_WORKERS` | `2` | |
| `GUARD_DETECTOR_LOCAL_BASE_MS`, `GUARD_DETECTOR_LOCAL_PER_KB_MS` | `10`, `3` | budget of an in-process detector |
| `GUARD_DETECTOR_REMOTE_TIMEOUT_MS` | `2000` | the longest guard-pii is waited for |
| `GUARD_APPROVAL_SWEEP_INTERVAL_S` | `30` | how often expired approvals are marked |
| `GUARD_LLM_PROVIDER`, `GUARD_LLM_DESTINATION_TRUST` | `openai`, `unknown` | how the provider is described to the policy |
| `GUARD_UNSUPPORTED_REQUESTS` | `deny` | or `allow` for requests the guard cannot read |
| `GUARD_STREAM_WINDOW_CHARS`, `GUARD_STREAM_OVERLAP_CHARS` | `1024`, `256` | |
| `GUARD_LOG_LEVEL` | `INFO` | |

A detector that fails or runs out of time denies the decision in enforce mode whenever a rule other than
`audit` needs it: with guard-pii down, a request that a PII mask rule covers is denied
(`detector_unavailable`), never let through unchecked.

## Policy updates

The service loads the policy at start (a policy that does not load stops it from starting) and checks the
file's modification time before decisions. A changed file is validated first; one that does not load is
never applied: the previous version stays active, the error is logged, shown by `GET /admin/policy` and
counted in `guard_policy_reload_failures_total`. Each applied text is recorded in `policy_versions`, and its
version (`<document version>@<digest>`) is written on every decision. Any edit of the text, even one that
keeps the document's `version`, invalidates the approvals granted under the previous text.

## Storage, upgrades and rollback

Decisions, approvals and policy versions live in SQLite by default (`/data/guard.db` on the `guard-data`
volume) or in PostgreSQL (`docker compose --profile postgres`, with `GUARD_DB_URL` pointing at it). The
migrations ship in the image and run at start.

To upgrade, back the database up (`docker compose stop guard-standalone` and copy the volume, or
`pg_dump`), set `GUARD_VERSION` to the new tag and `docker compose up -d`. To roll back, restore that
backup and start the previous tag: migrations only move forward at start, so a newer schema is not
downgraded by an older image.

## Closed contour

`guard-standalone`, `guard-pii` and PostgreSQL share a compose network marked `internal`, which has no route
out; only the gateway joins a second network, for the provider and the MCP servers it is configured with.
The guard makes no outbound call of its own: guard-pii carries its models in the image, and the gateway
binary calls nothing but its configured upstreams.

The end-to-end suite checks this together with the behaviour above. It runs the whole stack (the guard,
agentgateway, a stub model, a stub MCP server and the test runner) on a single internal network and asserts,
from inside it, that no outside address can be reached:

```bash
docker compose -f tests/e2e/compose.yaml up --build --abort-on-container-exit --exit-code-from runner
```

## Limitations

- Only OpenAI-compatible chat completions are read on the LLM route; other APIs are refused by default.
- A streamed response is checked in windows: up to a window of text is held back, already released text
  cannot be recalled, and a window that needs a mask ends the stream.
- A blocked JSON completion keeps the status `200` it was sent with; its body is the error object.
- The approval flow is asynchronous: the call is refused with `approval_pending` and repeated after the
  answer. The guard does not hold a call open while it waits.
- The guard sees what passes through the gateway. Applications must not be able to reach the provider or the
  MCP servers directly; restrict that in the network.

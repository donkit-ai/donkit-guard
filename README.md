# Donkit Guard

Open-source guard for LLM traffic and AI-agent actions. It answers three questions on every request and every tool call:

1. **What is this data allowed to reach?** Secrets, personal data and corporate rules are checked against the *full* payload before it leaves for a model provider: messages, retrieved context, tool results and structured arguments.
2. **What is this agent allowed to do?** Every tool call is checked before execution against the trusted context your runtime supplies: who is acting, on whose behalf, which tool, which resource, which operation, with which arguments. Identity comes from the authenticated session, never from fields the model produced.
3. **Why was it allowed or blocked?** Every decision is explained: the rules that fired, the detector versions, the policy version, and the actual execution outcome. "Allowed" and "executed successfully" are recorded as separate events.

The core is runtime-agnostic. It does not assume any particular identity or tenancy model: the decision context is a set of typed attributes, and well-known dimensions such as tenant, principal, agent, run, tool, resource and operation are optional conventions that policies can match on. Your integration maps its own model onto them through a small adapter interface, so a multi-tenant SaaS, a single-team internal tool and a personal coding assistant can all use the same policies and detectors.

Two deployment modes share one policy core, so behaviour never diverges:

- **Embedded** in an agent runtime (the reference integration is the [Donkit](https://donkit.ai) platform): hooks before the model call, before tool execution and on tool results, covering built-in tools, MCP servers and delegated sub-agents.
- **Standalone / self-hosted**: an OpenAI-compatible gateway for LLM traffic plus a documented MCP proxy, with its own authentication, a minimal admin API for pending approvals, and audit. No Donkit account, no external security API, no telemetry.

## Status

Alpha, core under construction. The first tagged pre-release (`v0.1.0a1`) contains the policy engine, the segment payload model, the secrets, checksum-PII, NER-PII and injection detectors, masking, asynchronous approvals, audit models and the in-memory adapters, plus the `guard-pii` service image. See [CHANGELOG.md](CHANGELOG.md).

## What it will provide

| Area | Behaviour |
| --- | --- |
| Data classes | Per class: allow, block, mask, require approval, or route to an administrator-approved model. Masking keeps JSON and tool schemas valid and never changes the meaning of a business operation; when a safe transformation is impossible the call is blocked. |
| Prompt injection | Detection of suspicious instructions in user messages, documents, retrieval context and tool results, kept separate from enforcement: untrusted content can never widen an agent's permissions or stand in for a user's confirmation. |
| Tool control | Mandatory check below the agent logic, before execution. Explicit deny wins; a protected action without a matching allow is denied. Sub-agents inherit no extra rights from delegation. A risk class declared by the tool provider itself never lowers the gate. |
| Approvals | Dangerous operations pause *before* the side effect. An approval is bound to the action, the principal, the tenant (when there is one) and the policy version, expires, and cannot be replayed; changed arguments require a new decision. |
| Policies | Versioned, validated before activation, explainable, revertible. Two working modes: **observe** (events are marked "would have been blocked") and **enforce**; **off** allows every action of a tenant without applying rules. Layers compose towards the stricter setting, so a tenant layer cannot switch platform enforcement off. |
| Audit | Tenant, principal, agent, run, tool or model, operation, policy version, rules fired, decision, latency, execution result. No raw secrets, prompts or documents by default. Structured export for external monitoring. |
| Reliability | Fail-closed for mandatory checks in enforce mode: a detector outage, a policy error or a timeout never turns into a silent allow. Streaming responses are buffered within documented limits; streamed tool-call arguments are checked after assembly and before execution. |

## What it is not

Donkit Guard protects the traffic that passes through it. It is not a replacement for authorisation inside your business systems, not a sandbox, and not a full enterprise DLP. Processes and network calls that bypass the controlled path are not covered; the documentation describes how to restrict direct access to upstream models and tools in a strict deployment profile.

## Development

```bash
poetry install
poetry run pytest
poetry run ruff check . && poetry run ruff format --check .
poetry run mypy
```

Contributions are welcome; please read [CONTRIBUTING.md](CONTRIBUTING.md) (DCO sign-off is required) and the [code of conduct](CODE_OF_CONDUCT.md). Security issues go through the [private reporting channel](SECURITY.md), not public issues.

## License

Apache License 2.0, see [LICENSE](LICENSE) and [NOTICE](NOTICE).

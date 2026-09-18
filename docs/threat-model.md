# Threat model

This document is filled in alongside the first release. It will cover:

- Assets: secrets and personal data in prompts and tool results, agent credentials, the audit trail.
- Adversaries: a compromised or manipulated model (prompt injection through documents and tool results), a malicious
  or careless end user, a compromised tool or MCP server, an operator error in policy configuration.
- Trust boundaries: identity is taken from the host's authenticated session only; the model's own claims are data,
  not instructions; the standalone admin API is a separate trust zone from client traffic.
- Guarantees and their limits: the guard controls traffic that passes through it; direct access to upstream models
  or tools is out of scope and must be restricted by the deployment (strict profile).
- Fail-closed behaviour in enforce mode and the documented buffering limits for streaming.

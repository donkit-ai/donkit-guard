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

## Declared detectors from policy documents

A policy document can declare its own detectors ([detectors.md](detectors.md#declared-detectors)), and a host
may take documents from its tenants. A declaration is therefore treated as data from a party that may be hostile,
never as code:

- **Checked when the document is loaded.** A declaration has to fit its schema and limits (at most 20 detectors
  per document, 3 of them remote; 10 patterns of 500 characters; 5000 terms of 200 characters; 20 examples of
  1000 characters), may report only the enforceable classes `secret`, `pii` and `corporate`, and has to keep its
  own `match` and `no_match` examples. A document that fails a check is refused as a whole.
- **Matching in linear time.** Patterns run on RE2 and terms on a prefix index, both in time linear in the length
  of the text, so no declaration can stall the process with a crafted expression or term list. A declared
  detector reports at most 50 findings per segment.
- **Isolated per tenant.** Declared detectors are built per tenant, and their cached results are keyed by the
  tenant and the digest of the declaration, so one tenant's results, the answers of a remote service included,
  are never served to another, and an edited declaration never reads the results of its earlier version.

A `remote` declaration makes the guard send text to an address the document chose. Two hooks of the host decide
what that may reach ([remote-detectors.md](remote-detectors.md#credentials-and-addresses)):

- **Which addresses: the `EndpointGuard`.** It is asked before every request, and a refused address is not
  contacted. The default, `AllowAllEndpoints`, accepts every URL, so a host that takes documents from its tenants
  must provide one that refuses internal networks and metadata services. An allow-list of host names the host
  controls is the safe form: the guard checks the URL as written and does not pin the address a name resolves to.
  The client never follows a redirect and takes no proxy settings from the environment, and a declared endpoint
  carries no user, password, query or fragment.
- **Which secret goes where: the `CredentialResolver`.** A document names a credential and never holds its value.
  Without a resolver no credential resolves, and a declaration that names one fails without sending anything. The
  resolver is given the tenant and the endpoint, and since any document of a bundle may name any credential, a
  host binds each credential to the tenant and the endpoint it was issued for. `EnvCredentialResolver`, which
  gives any document any `DONKIT_GUARD_CREDENTIAL_*` variable for any address, suits only a host that writes every
  document itself.
- **What is sent.** A remote detector runs only when a rule that matched the context could use its findings. It
  is sent the text of the segments it scans, their language hints and the bearer token the resolver returned, if
  any, and nothing about the tenant, the principal, the tool or the policy.

The answer of a service is untrusted:

- It has to come uncompressed and within 1 MiB, counted as it is received; anything else is a failed call. The
  service's own error text is cut to 200 characters.
- A span that lies outside the text that was sent, or has an entity type the declaration does not map, is
  dropped; a score is clamped to 0 to 1, and at most 50 findings per segment are kept.
- Short of failing, a service can only add findings, in the classes and subtypes its declaration maps, and they
  act only through the rules that select them.
- A service that fails, does not answer in time or answers with something unusable is a detector failure. A
  required one that a rule with an action other than `audit` could use denies the decision in enforce mode
  (`detector_unavailable`); an optional one (`required: false`), or one that only `audit` rules can use, is
  recorded as unchecked, so a missing answer is never read as a clean payload.

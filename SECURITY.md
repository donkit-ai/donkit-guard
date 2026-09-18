# Security policy

## Reporting a vulnerability

Please do not open public issues for security problems.

Use GitHub's private vulnerability reporting for this repository:
<https://github.com/donkit-ai/donkit-guard/security/advisories/new>. If you cannot use GitHub,
email <security@donkit.ai>.

Include the affected version or commit, a description of the impact, and steps to reproduce.
Proof-of-concept code is welcome; please do not include real secrets or personal data.

## What to expect

- Acknowledgement within 3 business days.
- An initial assessment (accepted / needs more information / not a vulnerability) within 7 business days.
- Fixes for confirmed issues are released as soon as they are ready, with a GitHub Security Advisory and a CVE
  where applicable. We coordinate disclosure dates with the reporter and credit reporters who wish to be named.

## Supported versions

Until the first stable release only the latest published version receives security fixes.

## Scope notes

Donkit Guard protects traffic and tool calls that pass through it. Reports about bypasses that require
direct access to an upstream model or tool outside the guarded path are welcome as hardening suggestions,
but they are documented limitations of the deployment model rather than vulnerabilities in the guard
itself, see the threat model in `docs/threat-model.md`.

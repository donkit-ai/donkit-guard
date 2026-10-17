# Documentation

- [architecture.md](architecture.md): components, context model, evaluation, approvals, adapter contract.
- [policies.md](policies.md): policy language reference and the default policy.
- [detectors.md](detectors.md): the built-in detectors, the detectors a policy document declares (patterns, word lists, remote services), how rules select which of them run, background checks and the runner's background lane, observe mode, argument previews, wiring in a host and the optional extras.
- [remote-detectors.md](remote-detectors.md): the analyze contract a remote detector speaks, how to check and write a service, the HTTP client and its shared connections, and the host hooks for credentials and addresses. The machine-readable contract is [contract/analyze-v1.openapi.json](contract/analyze-v1.openapi.json).
- [threat-model.md](threat-model.md): what the guard protects against, trust boundaries, known limitations, and what declared detectors from policy documents may and may not do.

Host integrations (for example the Donkit platform) are documented by the host; this repository documents the runtime-agnostic core and the standalone deployment.

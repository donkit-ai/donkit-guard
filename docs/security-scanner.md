# Security Scanner extension (DON-2539)

Optional application source-code scanning, independent of the Guard policy engine.
Run the service on dedicated scanner infrastructure. It accepts immutable snapshots,
operator-mounted repository checkouts, and snapshots exported by Donkit Builder.
The Donkit platform itself is just an internal tenant's explicitly registered project.
No customer organization receives access to it by enabling the extension.

This version performs **code review only**. It does not run the target application,
Docker/browser verification, or production probes. An empty report is not a security
guarantee. OpenHack's model validation is not dynamic reproduction. Upstream's discarded
candidates are not exposed as accepted findings; this version does not recover its
discarded-candidate history. Git hosting OAuth and automatic repository cloning are
outside this version: mount a prepared checkout or upload a snapshot.

## Run independently

Build from this checkout: `docker build -f docker/Dockerfile.scanner -t guard-scanner:local .`.
Copy `services/scanner/config.example.json` to a private config file. Supply only a
scanner-specific inference provider credential. The configured provider receives the
source code. A compatible provider's base URL and model can be configured; no platform
provider keys are discovered or inherited automatically.

Generate a random API token (at least 32 bytes), store its SHA-256 hex digest in
`tokens[].sha256`, and give its actor `tenant_id`, `user_id`, `issuer: standalone`.
Set `account_owner: true` only on the bootstrap administrator's token. The raw token
is sent as `Authorization: Bearer ...`. Never use a token digest as the bearer token.
Mount configuration read-only at `/config/scanner.json`, a persistent volume at `/data`,
and expose port 8090 behind TLS. Do not expose the service without authentication.
The API/OpenAPI reference is at `/docs`.

1. `PUT /v1/settings` with `{"enabled":true}` using the bootstrap identity.
2. `POST /v1/projects` with `{"name":"Example","kind":"snapshot"}`.
3. `PUT /v1/grants` with a user ID, role (`viewer`, `operator`, `admin`) and explicit
   `project_ids`. Include the new project ID. Bootstrap ownership does **not** grant
   permission to read source findings or run scans; assign those explicitly too.
4. `POST /v1/projects/{id}/scans` with `{"snapshot":{"files":[{"path":"app.py",
   "content":"print('hello')"}],"revision":"optional git revision","context":"optional architecture"}}`.
5. Read `/v1/scans/{id}`; cancel with `POST /v1/scans/{id}/cancel`.

For repositories, configure `sources` entries with `tenant_id`, `key`, `path`. Mount
each checkout read-only, then create `kind: mounted, source_ref: <key>`. The caller
cannot supply arbitrary filesystem paths. Starting a mounted scan uses `{}` as body.
The export skips symlinks, metadata, environment files, dependencies and binary files.
Standard credential files are excluded; source code can still contain embedded secrets.
Review the checkout before submitting it to an inference provider.

## Donkit identity

Set a distinct random `host_secret` (>=32 characters), `membership_url` to
`http://platform-api:8000/internal/guard-scanner/membership`, and configure the same
secret in platform-api. HTTPS is required across untrusted networks.
The platform signs method, path, body SHA-256, timestamp, nonce and base64url actor
JSON using HMAC-SHA256. The actor comes from current account membership, never the
browser. Signatures expire after 60 seconds; used nonces are rejected. Each request
and every worker heartbeat rechecks current platform membership. Agent/device/probe
sessions cannot use the employee adapter. Tenant ownership and per-project grants
are checked again inside Guard on every request and before execution.

Viewer reads granted projects; operator also starts/cancels scans. Guard administrator
manages configuration, projects and grants; reading/running still needs explicit project
grants. Account owner can bootstrap access. Disabling the extension or revoking grants
cancels queued scans and interrupts active scans. Removing a standalone token from the
mounted configuration revokes it immediately. Use atomic file replacement/directory
mounts for configuration rotation.

## Execution and operations

One service replica and one Uvicorn worker; SQLite WAL on a persistent RWO volume.
A filesystem lock refuses multiple service processes. Claims, cancellation and audit
are durable; a lease abandoned for 30 seconds becomes failed, never re-executed
automatically. Source is removed from the active database row when a scan terminates;
SQLite WAL/free pages and volume backups may retain deleted data until storage cleanup.
Reports and audit expire after `retention_days` (30 by default); queued/running work
is retained until terminal. Back up `/data` according to the organization's policy.

Each run uses bubblewrap user/PID/mount/IPC namespaces, a read-only source snapshot,
clean HOME/CWD, a temporary work directory, no Docker socket, and an environment
allowlist containing only scanner settings and the inference credential. It cannot
mount service configuration, queue state or host home. CPU/address-space/file limits,
an external wall-clock timeout and process-tree termination bound execution. Apply
container memory/CPU/PID/storage limits as well. For amd64 Docker, use `--security-opt seccomp=docker/seccomp-scanner-amd64.json`
with `--cap-drop ALL --security-opt no-new-privileges`. On Kubernetes install that file
on scanner nodes and refer to it through a Localhost seccomp profile. The runtime must
permit unprivileged user namespaces; test bubblewrap on the selected node/runtime before enabling scans.
Unsupported sandboxes fail closed; there is no unsandboxed fallback.

Network isolation is a deployment requirement: allow the chosen inference endpoint,
DNS and the authenticated membership callback, deny production networks and cloud
metadata. Bubblewrap here shares the scanner container network so it can reach the
provider; it is not a network firewall. The Donkit Helm deployment requires an explicit inference egress allowlist and
provides no unrestricted internet rule. For Docker/standalone deployments use a dedicated host
with equivalent egress rules, not a production Docker socket or production host.

OpenHack is pinned to `4e1f532e01c3ecca007e07ff4c06770c1c4a9919` (MIT).
The adapter removes the upstream `tools/` exclusion, disables dynamic verification,
and rejects nonzero exit, stage errors, interrupted agent loops, incomplete/malformed
reports and missing event journals. An upstream change requires contract tests and
an explicit revision update. No paid scans are run by tests.

## Development

Install `services/scanner/requirements.txt` alongside the core dev dependencies.
Run `pytest tests/test_scanner.py`, `ruff check .`, `ruff format --check .`, and `mypy`.
Tests use deterministic engines and cover tenant/project boundaries, revocation,
durable cancellation, lease recovery, source validation and report failure semantics.

The opt-in container test runs without network or paid inference: build the image, then
`GUARD_TEST_IMAGE=guard-scanner:local pytest tests/test_scanner_sandbox.py`. It loads real
OpenHack configuration inside bubblewrap and checks mount/env isolation and report ingestion.

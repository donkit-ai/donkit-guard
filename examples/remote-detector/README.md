# Example remote detector

A small service that speaks the analyze contract, to copy as the starting point of your own
detector. It finds contract numbers such as `ДГ-123456` and reports them as entity type `CONTRACT`.

The contract is `POST /v1/analyze`, described in
[`docs/contract/analyze-v1.openapi.json`](../../docs/contract/analyze-v1.openapi.json) and explained
in [`docs/remote-detectors.md`](../../docs/remote-detectors.md). A request carries text segments and
a deadline; the answer lists the spans found in them. Offsets count Unicode code points, as a Python
`str` index does, and `end` is exclusive, which is what Python's `re` returns for a `str`. A service
that cannot answer within `deadline_ms` answers `failed: true` instead of keeping the caller
waiting. `app.py` does all of this in one short file; replace `find_contract_numbers` with your own
detection.

## Run it

```bash
pip install -r requirements.txt
uvicorn app:app --port 8000
```

Ask it about a text:

```bash
curl -s localhost:8000/v1/analyze -H 'content-type: application/json' \
  -d '{"segments": [{"id": "s1", "text": "Договор ДГ-123456 подписан"}]}'
```

```json
{"detector":"contract-numbers","version":"1","spans":[{"segment_id":"s1","start":8,"end":17,"entity_type":"CONTRACT","score":0.95}],"failed":false,"error":null}
```

Set `DETECTOR_TOKEN` before starting it and the analyze endpoint requires
`Authorization: Bearer <token>`. Without it the endpoint is open, which only suits a trusted
network.

## Check that it follows the contract

`donkit-guard` ships a conformance check. It reaches your service over HTTP, so it needs the `http`
extra. With the service above running, give it the address of the analyze endpoint:

```bash
pip install 'donkit-guard[http]'
python -m donkit_guard.conformance http://127.0.0.1:8000/v1/analyze
```

For a service that requires a token, name the environment variable that holds it:

```bash
DETECTOR_TOKEN=change-me uvicorn app:app --port 8000
DETECTOR_TOKEN=change-me python -m donkit_guard.conformance \
  http://127.0.0.1:8000/v1/analyze --token-env DETECTOR_TOKEN
```

The check prints `OK` and exits with 0, or prints one violation per line and exits with 1. It does
not judge whether your detector finds the right things, only what a caller depends on: an empty
request is answered cleanly, every span names a segment that was sent and lies inside its text with
an entity type and a score between 0 and 1, and a request that allows a second is answered, or
failed, within a second and a half. `--deadline-s` sets how long the client waits for each probe
(5 seconds by default).

## Use it from a policy

A policy document declares the service as a `remote` detector and says which finding class and
subtype each entity type it reports stands for. Entity types the declaration does not list are
ignored.

```yaml
schema_version: 1
version: "contracts-1"
mode: enforce
detectors:
  - kind: remote
    id: contract-numbers
    title: Contract numbers
    endpoint: http://127.0.0.1:8000/v1/analyze
    credential: contract-service
    entities:
      CONTRACT:
        class: corporate
        subtype: CONTRACT_NUMBER
layers:
  - name: tenant
    rules:
      - id: mask-contract-numbers
        match:
          action_kind: [llm_request]
          finding_class: [corporate]
          finding_subtype: [CONTRACT_NUMBER]
        action: mask
        reason: "Contract numbers do not go to a model"
```

`credential` names the token the service expects; the document never carries its value. The host's
`CredentialResolver` turns the name into a token for the declared endpoint. Credentials are opt-in:
without a resolver none resolves, the detector fails with `credential not found` and sends nothing,
and because the `mask` rule above needs the detector, an enforce-mode decision on a model request
is then a deny with code `detector_unavailable`. A host that writes its policy documents itself can
take the token from the environment variable `DONKIT_GUARD_CREDENTIAL_CONTRACT_SERVICE` (the name
upper-cased, `-` turned into `_`):

```python
from donkit_guard import DeclaredDetectors, EnvCredentialResolver

declared = DeclaredDetectors(credential_resolver=EnvCredentialResolver())
# Engine(..., declared=declared) or build_quickstart_guard(declared=declared)
```

A host that accepts policy documents from its tenants uses a resolver of its own instead, one that
binds each credential to its tenant and its endpoint, because any document may name any credential.
Such a host can also refuse internal addresses such as `127.0.0.1` with an `EndpointGuard`, so the
address in `endpoint` has to be one the host allows; see
[`docs/remote-detectors.md`](../../docs/remote-detectors.md#credentials-and-addresses). Leave
`credential` out for a service without a token. Calling a remote detector needs the `http` extra:
`pip install 'donkit-guard[http]'`.

[`docs/detectors.md`](../../docs/detectors.md) lists every field of a declared detector, including
the timeout, whether a failed call fails the decision, and how long an answer is reused.

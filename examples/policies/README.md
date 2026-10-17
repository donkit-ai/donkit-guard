# Example policies

- `tenant-strict.yaml` — an enforce-mode layer for a strict deployment profile: hard deny of personal data to non-platform destinations, approvals for code execution and for side effects after untrusted content entered the context, and `deny` for attachments the guard cannot inspect.
- `tenant-detectors.yaml` — an enforce-mode layer that declares one detector of each kind (a contract-number pattern, a list of project code names, a customer-records service) and the rules that use them: contract numbers are masked, project code names are denied, and the remote service only feeds an `audit` rule, so the engine runs it in the background. The pattern detector needs the `re2` extra; the terms detector needs none. The remote detector calls a placeholder address and, when it is evaluated, needs the `http` extra, a service of your own and a host `CredentialResolver` that has a token for `customer-records` at that endpoint. Without one the detector fails without sending anything; since only an audit rule uses it, that never changes an outcome, and the detector is listed as unchecked. See [remote-detectors.md](../../docs/remote-detectors.md). All fields are explained in [detectors.md](../../docs/detectors.md).

Validate a document with:

    poetry run python -c "from donkit_guard.policy import load_policy; print(load_policy(open('examples/policies/tenant-strict.yaml').read()).version)"

The same command validates `tenant-detectors.yaml` once the `re2` extra is installed (`poetry install --extras re2`): loading checks that the patterns compile and that the examples of each declaration hold. The remote detector is not contacted.

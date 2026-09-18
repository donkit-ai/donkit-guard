# Example policies

- `tenant-strict.yaml` — an enforce-mode layer for a strict deployment profile: hard deny of personal data to non-platform destinations, approvals for code execution and for side effects after untrusted content entered the context, and `deny` for attachments the guard cannot inspect.

Validate a document with:

    poetry run python -c "from donkit_guard.policy import load_policy; print(load_policy(open('examples/policies/tenant-strict.yaml').read()).version)"

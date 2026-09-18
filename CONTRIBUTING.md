# Contributing

Thanks for helping make AI agents safer to run. This document covers the mechanics; design discussions
happen in issues before code is written.

## Developer Certificate of Origin

Every commit must be signed off (`git commit -s`), which adds a `Signed-off-by:` trailer certifying the
[Developer Certificate of Origin](https://developercertificate.org/). We do not require a CLA.

## Development setup

```bash
git clone git@github.com:donkit-ai/donkit-guard.git
cd donkit-guard
poetry install
poetry run pre-commit install
poetry run pytest
```

Python 3.12 or 3.13. Lint and type checks are part of CI: `ruff check`, `ruff format --check`, `mypy --strict`.

## Pull requests

- One logical change per PR, with tests. Behaviour changes need a CHANGELOG entry under *Unreleased*.
- Keep the core runtime-agnostic: nothing under `src/donkit_guard` may import a specific host runtime,
  web framework or database driver except behind the adapter interfaces.
- Detectors are versioned. Changing a pattern or threshold bumps the detector version and updates its
  evaluation fixtures; decisions record the detector version, so silent changes break audit reproducibility.
- Security-relevant changes (new bypass, changed fail-closed behaviour, new data leaving the process)
  must say so explicitly in the PR description.
- Commit messages follow Conventional Commits (`feat:`, `fix:`, `docs:`, `chore:`, ...). PRs are squash-merged;
  the PR title becomes the commit subject.

## Reporting bugs and proposing features

Use the issue templates. For anything that could be a vulnerability, follow [SECURITY.md](SECURITY.md) instead.

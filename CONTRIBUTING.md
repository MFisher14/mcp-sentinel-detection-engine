# Contributing to `mcp-sentinel-detection-engine`

Thanks for your interest. This is a small, focused project; contributions
that align with the project's scope (Sigma → KQL conversion, schema and
dry-run validation, Terraform emission — see the README's *Scope &
Design Philosophy*) are welcome.

## Prerequisites

- Python 3.11 or later.
- [`uv`](https://docs.astral.sh/uv/) (recommended) or `pip`.
- A GitHub account.

## Setup

```bash
git clone https://github.com/MFisher14/mcp-sentinel-detection-engine.git
cd mcp-sentinel-detection-engine
uv venv && source .venv/bin/activate
uv pip install -e ".[dev]"
```

You do **not** need an Azure tenant or live Sentinel credentials to
develop or run the test suite — the tests stub the upstream Log
Analytics API. Sigma → KQL conversion and Terraform emission are pure
functions and have no Azure dependency at all.

## Workflow

1. Open or comment on an issue first for anything non-trivial. This
   avoids wasted work on changes that fall outside scope.
2. Branch off `main`. Use a short, descriptive branch name
   (e.g. `feat/live-schema`, `fix/heredoc-escape-edge-case`).
3. Keep one logical change per pull request. Smaller PRs are reviewed
   faster.
4. Follow [Conventional Commits](https://www.conventionalcommits.org/)
   for commit messages. Existing repository conventions use prefixes
   like `feat:`, `fix:`, `docs:`, `chore:`, `ci:`, `test:`.

## Local checks

Run these before opening a pull request. CI will run them too.

```bash
ruff check . && ruff format --check .
mypy
pytest --cov --cov-fail-under=80
```

## Pull request checklist

- [ ] Tests added or updated for any behavior change.
- [ ] `ruff`, `mypy`, and `pytest` all pass locally.
- [ ] [`THREAT_MODEL.md`](./THREAT_MODEL.md) updated if the change
      affects the attack surface (new input source, new credential
      handling, new output path — including new Terraform fields
      interpolated into HCL).
- [ ] New runtime dependencies justified in the PR description.
- [ ] Audit log entries reviewed for credential or PII leakage (see
      `THREAT_MODEL.md` T2).
- [ ] README updated if user-visible behavior or configuration changes.
- [ ] Schema snapshot updates cite the Microsoft Learn page they were
      derived from.

## What we don't accept

This server is intentionally read-only against Azure. We will **not**
merge:

- Tools that call `terraform apply`, the Sentinel rule create/update
  API, or any other write-scope endpoint. Terraform emission is
  apply-free by design — running the apply is a separate human-gated
  step.
- Code that disables, weakens, or bypasses input validation (KQL length
  cap, forbidden-substring filter, Unicode stripping, tenant key regex,
  HCL escaping in `terraform_emit.py`) without an equivalent
  replacement defense documented in `THREAT_MODEL.md`.
- HCL emission code that interpolates user input unquoted, or that
  derives Terraform resource names from caller-supplied strings without
  the strict identifier check.

## Reporting security issues

Please do **not** open a public GitHub issue for security reports. See
[`SECURITY.md`](./SECURITY.md) for the disclosure process.

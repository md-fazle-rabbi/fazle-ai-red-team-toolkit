# Changelog

## [Unreleased]

### 2026-10-17
- Added the project skeleton: a typed Python package in `src/redteam_toolkit`, pinned to Python 3.13.15 and uv 0.12.21, so every later change has something to build and test against.
- Added tooling config in `pyproject.toml`: ruff for lint and format (with the security rules on), mypy in strict mode, and pytest with a 90 percent coverage gate.
- Added the CI workflow: lint and type check, tests with the coverage gate, pip-audit on the locked dependencies, and CodeQL. Actions are pinned to commit SHAs and jobs run with read-only permissions, so a compromised action or dependency has less to work with.
- Added `docs/adr/ADR-000` recording why the project stays on Python 3.13 and not 3.14.
- Replaced `SECURITY.md` with a fuller authorized-testing policy, `.env.example` with the settings the first runs need, and `.gitignore` so run output and secrets stay out of git.
- Updated the README with a real CI badge and an honest Known limitations section.

### 2026-08-17
- Repo initialized. MIT license, README/SECURITY/.env.example placeholders added.

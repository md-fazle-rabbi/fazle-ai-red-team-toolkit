# Changelog

## [Unreleased]

### 2026-10-19
- Added `redteam_toolkit.runner.send_probe`, the one function in this toolkit allowed to make an outbound HTTP request. It calls the Rules of Engagement gate first and sends nothing if the gate refuses. It records the status code, body, elapsed time and any connection error, and makes no judgement about whether a response passed or failed.
- Added `docs/adr/ADR-008` recording why the gate check and the network call live in one place, and what still has to be built (rate limiting, concurrency).
- Moved httpx2 from the dev group to the main dependencies, since the runner needs it at runtime.
- Added tests that check a refused request never reaches the network, a permitted request against the local stub is recorded correctly in both its modes, and a connection failure is caught rather than raised.
- Added `examples/roe.stub-local.toml`, the matching Rules of Engagement file for the local stub target, with two targets at the same local address for the stub's weak and hardened modes.
- Added `tests/test_examples.py`, which loads both example files from disk and checks they still validate and gate as expected. Until now nothing in the test suite caught a schema change quietly breaking an example.
- Wired the gate, the runner and the stub together end to end for the first time (documented in the README), confirming `send_probe` records a real leak from the weak stub and a real 400 from the hardened stub's firewall.

### 2026-10-18
- Added a local stub target in `src/redteam_toolkit/stub_target.py`, with a weak mode and a hardened mode, so CI can show the toolkit telling a failing target from a passing one without depending on Repo 1, a model or a network. It copies the request and response shape of Repo 1's `POST /query` and answers from three synthetic documents.
- Added tests that pin what each mode does: the weak mode leaks its canary and raw PII, the hardened firewall blocks a plain injection, and the output scrub catches a spaced-out injection that slips past the firewall.
- Added `docs/adr/ADR-007` recording why CI runs against a stub and Repo 1 is attacked only in manual authorized runs.
- Added fastapi, uvicorn and httpx2 to the dev dependencies. They are used by the stub and its tests only.
- Added the Rules of Engagement gate in `src/redteam_toolkit/roe.py`. The toolkit now refuses to run without a valid file, so authorization is enforced by code and not only by the README. The file is checked before anything else, and a refusal sends nothing.
- Added the `redteam-toolkit` command with `validate` and `check`. It exits with 0 when authorized and 2 when refused, and prints the SHA-256 of the file so logs and reports can point back to exactly what was authorized.
- Added an example file in `examples/` and made `engagements/` git-ignored, so real files that name clients and people stay out of git.
- Added tests that try to break the gate: unknown keys, missing offsets, scope tricks in URLs such as `..`, double encoding, look-alike hosts and user info, and a window checked at its exact edges.
- Added `docs/adr/ADR-006` recording why the file is TOML, how the gate decides, and what it cannot check.
- Added pydantic as the first dependency, to validate the file strictly.

### 2026-10-17
- Added the project skeleton: a typed Python package in `src/redteam_toolkit`, pinned to Python 3.13.15 and uv 0.12.21, so every later change has something to build and test against.
- Added tooling config in `pyproject.toml`: ruff for lint and format (with the security rules on), mypy in strict mode, and pytest with a 90 percent coverage gate.
- Added the CI workflow: lint and type check, tests with the coverage gate, pip-audit on the locked dependencies, and CodeQL. Actions are pinned to commit SHAs and jobs run with read-only permissions, so a compromised action or dependency has less to work with.
- Added `docs/adr/ADR-000` recording why the project stays on Python 3.13 and not 3.14.
- Replaced `SECURITY.md` with a fuller authorized-testing policy, `.env.example` with the settings the first runs need, and `.gitignore` so run output and secrets stay out of git.
- Updated the README with a real CI badge and an honest Known limitations section.

### 2026-08-17
- Repo initialized. MIT license, README/SECURITY/.env.example placeholders added.

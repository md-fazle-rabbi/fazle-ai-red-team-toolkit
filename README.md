# fazle-ai-red-team-toolkit

![CI](https://github.com/md-fazle-rabbi/fazle-ai-red-team-toolkit/actions/workflows/ci.yml/badge.svg)
![License](https://img.shields.io/badge/license-MIT-green)
![Python](https://img.shields.io/badge/python-3.13.15-blue)

## Hire me
An automated red-team and evaluation suite for LLM applications: prompt injection, PII
leakage, jailbreaks, bias, adversarial ML, supply-chain, and rogue-agent test cases. Built
to attack fazle-enterprise-ai-platform, and, with written authorization, client systems.
Contact: mfrabbi.ai@gmail.com · Demo: TBD

## Status
Early. The Rules of Engagement gate works. No attack suite exists yet, and nothing in this
repository sends traffic to a target.

## What this is
A single deep exploit and evaluation suite, not a grab-bag of scripts. The reference target
is [fazle-enterprise-ai-platform](https://github.com/md-fazle-rabbi/fazle-enterprise-ai-platform).
Read [SECURITY.md](SECURITY.md) before running this against anything you don't own.

## Rules of Engagement gate
No valid Rules of Engagement file, no run. The file is TOML and names who authorized the
test, the testing window, the targets and paths, the allowed suites and the request limits.
The schema is strict: unknown keys are rejected, and every date-time needs a UTC offset.
Design and trade-offs are in [ADR-006](docs/adr/ADR-006-rules-of-engagement-gate.md).

```bash
mkdir -p engagements
cp examples/roe.repo1-local.toml engagements/repo1-local.toml
uv run redteam-toolkit validate --file engagements/repo1-local.toml
uv run redteam-toolkit check --file engagements/repo1-local.toml \
  --target repo1-local --suite prompt_injection --url http://localhost:8000/query
```

Exit code 0 means authorized. Exit code 2 means refused, and nothing was sent. Without
`--file` the tool reads the path in `REDTEAM_ROE_PATH`. The `engagements/` folder is
git-ignored because real files name clients and people.

## Develop locally
Needs uv 0.12.21. uv installs Python 3.13.15 for you.

```bash
uv sync
uv run ruff check .
uv run ruff format --check .
uv run mypy
uv run pytest --cov --cov-fail-under=90
```

## Known limitations
- No attack code exists yet. Nothing in this repository sends traffic to a target.
- The gate checks what the file says is authorized. It cannot tell whether the signature
  behind the file is genuine. For a client engagement the file records the SHA-256 of the
  signed document, and a person still has to check that document.
- The request limits in the file are validated against ceilings in the code, but nothing
  enforces them yet, because no suite runner exists. The ceilings (120 requests per
  minute, 10,000 requests in total, 10 at once, a 31 day window) are values I chose, not
  measured ones.
- The URL check compares text, not the address a name resolves to, and it cannot stop an
  HTTP client from following a redirect off the target. Runners will have to turn
  redirects off.
- A runner that forgets to call the gate bypasses it. No runner exists to test this yet.
- garak, PyRIT, DeepTeam and IBM ART are not installed yet. IBM ART's package metadata
  lists Python 3.10 to 3.12 and not 3.13, so it is unverified on the interpreter this
  repository uses.
- CI runs lint, type check, tests with a coverage gate, pip-audit and CodeQL. It runs no
  red-team tools and no container scan yet.

## License
MIT, see [LICENSE.md](LICENSE.md).

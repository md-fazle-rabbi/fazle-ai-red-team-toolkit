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
Early. This repository holds the project skeleton and CI. It does not send traffic to any
target yet.

## What this is
A single deep exploit and evaluation suite, not a grab-bag of scripts. The reference target
is [fazle-enterprise-ai-platform](https://github.com/md-fazle-rabbi/fazle-enterprise-ai-platform).
Read [SECURITY.md](SECURITY.md) before running this against anything you don't own.

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
- The Rules of Engagement gate (no file, no run) is designed but not implemented.
- garak, PyRIT, DeepTeam and IBM ART are not installed yet. IBM ART's package metadata
  lists Python 3.10 to 3.12 and not 3.13, so it is unverified on the interpreter this
  repository uses.
- The tests only check that the package installs, imports and ships its typing marker.
  They test no behavior yet.
- CI runs lint, type check, tests with a coverage gate, pip-audit and CodeQL. It runs no
  red-team tools and no container scan yet.

## License
MIT, see [LICENSE.md](LICENSE.md).

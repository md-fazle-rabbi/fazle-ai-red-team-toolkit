# ADR-000: Python 3.13.15 over 3.14

Status: Accepted (2026-10-17)

## Context
This repository tests fazle-enterprise-ai-platform, which is pinned to Python 3.13.15. The attack tools this repository will wrap publish their own Python ranges. On 2026-10-17 the PyPI metadata read: DeepTeam 1.0.10 requires >=3.9,<3.14. IBM ART 1.20.1 lists Python 3.10, 3.11 and 3.12 in its classifiers and declares no requires-python. garak 0.17.1 requires >=3.11. PyRIT 1.1.0 requires >=3.10,<3.15. Locust 2.46.7 requires >=3.11.

## Decision
Pin the project to Python >=3.13,<3.14, with .python-version and CI both on 3.13.15.

## Options considered
- Python 3.14: rejected. DeepTeam declares <3.14, so it cannot be installed there. Python 3.14 itself is stable. The blocker is the tool ecosystem.
- Python 3.12: rejected. It is the newest version IBM ART lists, but it would put the toolkit on a different interpreter from the system it tests, and it gains nothing else.

## Consequences
- Positive: one interpreter for both repositories.
- Negative: IBM ART does not list 3.13, so it is unverified on this pin.
- Risk and mitigation: ART may fail on 3.13. It gets its own environment and a smoke test before this repository claims any ART-based testing. If it fails, that module runs on 3.12 in its own environment, or is listed as not yet implemented.

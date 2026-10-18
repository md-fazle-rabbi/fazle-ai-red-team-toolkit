# ADR-007: A local stub target for CI

Status: Accepted (2026-10-18)

## Context
CI has to show that the toolkit can tell a failing target from a passing one. Repo 1 cannot be that target in CI. Its cold query latency was measured at 3.9 s with three test documents, which is over the 2 s load gate. Its embedding free tier allows 3 requests per minute. A judge model for garak, PyRIT or DeepTeam would also hit free tier limits and make every CI run depend on a third party.

## Decision
CI runs against a local stub target (`redteam_toolkit.stub_target`): a small FastAPI app with the same request and response shape as Repo 1's `POST /query`, three synthetic documents, no model and no network. It has two modes:
- weak: follows injected instructions, leaks a canary string as its "system prompt", returns raw PII.
- hardened: a plain-text injection firewall, a scrub of the canary on output, and PII redaction on output. The firewall reads raw text and the weak "model" squashes text to letters first, so a spaced-out injection gets past the firewall and the output scrub has to catch it. Hardened mode is imperfect on purpose.

Repo 1 is attacked only in manual runs, behind a Rules of Engagement file (ADR-006), with the request rate set well under its free tier limit.

## Options considered
- Run Repo 1 in CI: rejected. It needs Postgres, Redis, Keycloak and free-tier model keys, and its latency and rate limits would fail the gates for reasons that say nothing about security.
- Recorded responses from Repo 1: rejected. A recording cannot change behavior between a weak and a hardened mode, so it cannot show the toolkit telling them apart.
- A real model behind a proxy: rejected for CI. It adds cost, rate limits and non-determinism.

## Consequences
- Positive: CI is fast, free and deterministic. Every response is reproducible.
- Negative: a pass against the stub says nothing about Repo 1. The README says so, and any report must name the target it ran against.
- Risk and mitigation: the stub could drift away from Repo 1's real response shape. Mitigation: the field names are copied from Repo 1's `QueryResponse`, and a later contract check will compare them against Repo 1's code.
- Risk and mitigation: a deliberately vulnerable app on a developer machine. Mitigation: uvicorn binds to 127.0.0.1 by default, the module docstring and README say never to pass `--host 0.0.0.0`, and the stub holds only synthetic data.

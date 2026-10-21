# ADR-012: A gated proxy for tools that send their own requests

Status: accepted

## Context
`send_probe` is the one place that checks the Rules of Engagement gate and the
request budget. garak, PyRIT, DeepTeam and Locust send their own HTTP requests and
never call it. Without something in front of them, the gate does not bind them.

## Decision
`redteam_toolkit/proxy.py` is a small local HTTP app. A tool is pointed at the proxy
and not at the target. Each request goes through `send_probe`, so the gate and the
budget apply, and one audit entry is recorded per outcome.

- One proxy serves one target and one suite, fixed when it is created. A tool cannot
  choose another suite or host by changing its request.
- A refusal returns 403 and nothing reaches the target.
- The target's own status codes pass through, so a tool sees a firewall block as a
  block. A connection failure returns 502.
- The audit record holds time, target, suite, path, outcome and status code. It never
  holds request or response bodies, which can contain personal data.

## Consequences
- This only binds a tool that is pointed at the proxy. A tool configured with the
  target's own address still bypasses it. The README says so.
- JSON POST only. No streaming and no query strings.
- The proxy must be bound to 127.0.0.1. It forwards requests for whoever can reach it.
- fastapi and uvicorn became main dependencies, because the package now ships two
  things that need them.

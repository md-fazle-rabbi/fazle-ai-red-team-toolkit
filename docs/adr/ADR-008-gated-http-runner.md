# ADR-008: A gated HTTP runner as its own module

Status: Accepted (2026-10-19)

## Context
Every suite that will exist (prompt injection, pii leakage, jailbreak and the rest) needs to do the same three things before it can say anything about a target: ask the Rules of Engagement gate whether this request is allowed, send the request if it is, and record what came back without guessing at what the response means. If each suite wrote that logic itself, a suite could forget the gate call, and that is exactly the bypass the README's Known limitations already names as untested.

## Decision
`redteam_toolkit.runner.send_probe` is the one function that is allowed to make an outbound HTTP request. It calls `RoEGate.permit` first and sends nothing if that raises. It returns a `ProbeResult`: status code, response body, elapsed time, and an error string if the connection itself failed. It does not decide whether a response is a pass or a fail. Scoring belongs to each suite, because a prompt injection suite and a load suite judge a response by different rules.

The module ships no attack content of its own. Its own tests reuse the two probe strings already in `tests/test_stub_target.py` rather than defining new ones, because this step is plumbing, not a suite.

## Options considered
- Let each suite call `httpx2` directly: rejected. Nothing would stop a suite from skipping `permit`, and the Known limitations section already flags that gap.
- Build the full suite runner (concurrency, rate limiting, suite-specific scoring) in one step: rejected for now. Rate limiting and concurrency are configured in the Rules of Engagement file already (`Limits`) but nothing enforces them yet; that is a separate, larger piece and deserves its own step and its own tests.

## Consequences
- Positive: one chokepoint for the gate check. A suite cannot reach the network without going through `permit`.
- Positive: `ProbeResult` is a plain dataclass, not tied to httpx2 beyond the two fields it borrows the shape from, so a suite's tests can build one by hand without a real request.
- Negative: no rate limiting or concurrency control exists yet. A suite that calls `send_probe` in a tight loop can still exceed the `requests_per_minute` the file authorizes. That enforcement is still open.
- Negative: `send_probe` can open and close its own `httpx2.Client` per call, which is wasteful for a suite sending many requests. A suite that cares about that passes its own client and manages its lifetime.

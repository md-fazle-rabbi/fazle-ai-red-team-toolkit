# ADR-006: Rules of Engagement gate

Status: Accepted (2026-10-18)

## Context
This toolkit sends attack traffic. Written authorization is the line between a security test and an attack, so the code has to enforce it, not just the README. The rule is: no valid Rules of Engagement file, no run. ADR numbers 001 to 005 are reserved for decisions that come later in this repository's plan, so this one takes 006.

## Decision
1. One TOML file per engagement, loaded and validated before any network call. The schema is strict: unknown keys are rejected, types are not coerced, and every date-time needs a UTC offset.
2. A gate object (`RoEGate`) that every suite runner must call before each request. It checks, in this order: the testing window, the target id, the suite, then the request URL (scheme, host, port, and path on a segment boundary).
3. Refusals are exceptions and the command line exits with code 2. Nothing is sent.
4. The file holds only the NAME of the environment variable that carries credentials. A key named password or token is rejected as an unknown key.
5. Hard ceilings live in code: 120 requests per minute, 10,000 requests in total, 10 at once, a 31 day window. I picked these as policy ceilings. They are not measured values. A file can ask for less.
6. Real personal data in scope is refused outright. A production target needs an approver who is a different person from the one who authorized the engagement. A `self_owned` authorization may cover local targets only.
7. The SHA-256 of the file is computed and printed so every log line and report can carry it.

## Options considered
- YAML: rejected. It needs a third-party parser, and PyYAML keeps the last value when a key appears twice, so a duplicated `allowed_paths` could quietly widen scope.
- JSON: rejected. No comments, and no native date-time type.
- Command line flags or environment variables only: rejected. They leave no durable record of what was authorized.
- A cryptographically signed file: deferred. It needs key distribution that a one-person project does not have yet. For a client the file records the SHA-256 of the signed document instead.

## Consequences
- Positive: a refusal is loud and testable, and the same file doubles as the engagement record.
- Negative: the gate checks what the file says. It cannot tell whether the signature behind it is genuine.
- Risk and mitigation: a runner that forgets to call `permit` bypasses the gate. Mitigation: every runner takes a gate in its constructor, and a test per runner checks that it refuses without one.
- Risk and mitigation: the URL check compares text, not the resolved address, and an HTTP client may follow a redirect off the target. Mitigation: runners must turn redirects off, and a test will pin that when the first runner exists.
- Risk and mitigation: the limits are validated but not yet enforced, because no runner exists. Mitigation: the README lists this as a known limitation until the rate limiter lands.

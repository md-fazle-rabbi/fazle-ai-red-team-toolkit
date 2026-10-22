# ADR-013: Higher request ceilings for self-owned local engagements

Status: Accepted (2026-10-22)

## Context
The Rules of Engagement file validates its request limits against ceilings in the code:
120 requests per minute, 10,000 in total and 10 at once. They were chosen to be safe for
a client system and are policy values, not measured ones. A load test of the local stub
needs more at once than that. The plan calls for a load run with 50 simulated users, and
the gate would refuse any file that asks for it.

## Decision
The ceilings depend on the kind of authorization. A `self_owned` file, which the schema
already limits to local targets, may ask for up to 60,000 requests per minute, 100,000 in
total and 50 at once. Every other file keeps the original ceilings. The higher numbers
are policy values too, chosen to fit a load run against a stub on this machine, and were
not measured.

The `Limits` model accepts the higher values. `RulesOfEngagement` then checks the lower
ceilings for any authorization that is not `self_owned`, so a client file cannot ask for
more than before. The error names the limit and the ceiling, never the value.

## Options considered
- Raise the ceilings for everyone: rejected. A client system is the case the low ceilings
  protect, and nothing about a local load test changes that.
- Keep the ceilings and run the load test at 10 users: rejected. It would test less than
  the plan says without a reason that comes from the system under test.
- Run the load test outside the gate: rejected. It breaks the rule that every outbound
  request goes through the gate or the proxy.

## Consequences
- Positive: the 50 user load run is possible, and a client file is still capped at 10.
- Positive: the higher ceilings only apply where the schema already guarantees every
  target is local.
- Negative: two sets of ceilings are one more thing to keep straight. The README names
  both.
- Open: whether the gated proxy itself can carry 50 requests at once, and how much latency
  it adds, has not been measured. The load step has to measure that before it trusts a
  p95 number for the target.

## Amendment (2026-10-22)
The per-minute ceiling for a self_owned file was first 6,000. A run in a sandbox with
that ceiling showed 50 simulated users queueing behind the budget's even spacing at
about 100 requests a second, so the p95 measured the budget and not the system. The
ceiling is now 60,000, so the budget does not bind at the rate the stub can serve.

The open question above was measured once, on one 8-core machine with Locust, the weak
stub and the proxy all running on it, 20 seconds per run, one harmless question and the
load example file. With 50 users: 129.8 requests per second, p95 480 ms, p99 510 ms and
no failures out of 2,468 requests. With 10 users: 128.6 requests per second, p95 110 ms
and no failures out of 2,443. Throughput was the same for both, which is consistent
with the stack being saturated at about 130 requests per second, so the 50 user latency
is queueing. The proxy carried 50 at once without errors in that run.

This does not say how much latency the proxy itself adds. A run straight at the stub
would show it, and would also bypass the gate, so none was made. The numbers are in
`proof/load-measure-run.txt`.

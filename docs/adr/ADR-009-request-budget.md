# ADR-009: A request budget, opt in and sequential

Status: Accepted (2026-10-20), amended 2026-10-21

## Context
The Rules of Engagement file sets `requests_per_minute`, `total_requests` and `concurrency`. Until now the code only checked that those numbers sit under fixed ceilings. Nothing stopped a suite from sending faster or more often than the file allows, and the README listed that as a known limitation. Repo 1's embedding free tier allows 3 requests per minute, so a manual run against it needs the rate to be real, not just written down.

## Decision
`redteam_toolkit.limits.RequestBudget` counts requests and spaces them evenly: the gap between two requests is 60 divided by `requests_per_minute`. It raises `BudgetExhaustedError`, a subclass of `RoEViolationError`, once `total_requests` is used up. `send_probe` takes an optional `budget`. It charges the budget only after `RoEGate.permit` allows the request, so a refused request costs nothing and a budget check never hides a gate refusal. The clock and the sleep function are injectable, so the tests run instantly and check exact waits.

## Options considered
- A sliding 60 second window: rejected. It allows a burst of the full per-minute count at once, which is the spike a free tier limit punishes. Even spacing gives the target the smooth rate the file asked for.
- Locks and a semaphore for concurrency: rejected for now. No concurrent runner exists, so there is nothing to test the locking against, and untested concurrency code gives false confidence. The `concurrency` value is exposed as a property for the day a concurrent runner exists.
- Make the budget mandatory in `send_probe`: rejected for now. It would change every caller and test written so far. The README lists the opt-in as a limitation.

## Consequences
- Positive: the file's rate and total are enforced in code, with tests that check exact waits and the exact refusal.
- Negative: the count lives in memory, so two runs in a row each get the full total. Persisting it needs a place to write that state, and that is not decided.
- Negative: not thread safe, and `concurrency` is not enforced.
- Risk and mitigation: a suite could forget to pass a budget. Mitigation: the README says so, and a later suite runner should build the gate and the budget from one loaded file so they cannot be separated.

## Amendment (2026-10-21)
The gated proxy (ADR-012) serves requests on several threads, so two of the options
rejected above are now needed, and both have tests.

- `RequestBudget.acquire` holds a lock, so the count and the spacing stay right when
  several threads call it. A test starts 20 threads against a total of 5 and requires
  exactly 5 to succeed.
- The budget still does not enforce `concurrency`, because it never sees a request
  finish. The proxy holds a semaphore with that many slots around each send. A test
  with a slow target requires that no more than the file's limit are ever in flight.
- A caller that sends from several threads without the proxy has to hold its own
  slots.

The title's "sequential" and the Negative line above describe the original decision
and no longer describe the code. Spacing is still even, and the count still lives in
memory and starts at zero in every process.

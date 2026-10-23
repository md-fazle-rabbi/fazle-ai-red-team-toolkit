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
Early. The Rules of Engagement gate, a local stub target, a gated HTTP runner and a
request budget work. No attack suite exists yet: nothing scores a response or decides
pass or fail.

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
git-ignored because real files name clients and people. `examples/roe.stub-local.toml`
is the matching file for the stub target below, with two targets (`stub-weak-local`,
`stub-hardened-local`) at the same address, since the stub runs one mode at a time.

## Stub target
CI cannot attack fazle-enterprise-ai-platform: it needs a database, a cache, a login server
and free-tier model keys, and it is slower than the load gate allows. So the toolkit ships
a local stub with the same `POST /query` shape and two modes. `weak` follows injected
instructions, leaks a canary string and returns raw PII. `hardened` has a plain-text
firewall, a canary scrub and PII redaction. Every value is synthetic. Reasoning is in
[ADR-007](docs/adr/ADR-007-local-stub-target-for-ci.md).

```bash
.venv/bin/uvicorn --factory redteam_toolkit.stub_target:weak_app --port 8010
```

Use `hardened_app` for the other mode. Run it on localhost only: it is vulnerable on
purpose, so never pass `--host 0.0.0.0`.

The stub's request and response shape is pinned by tests against
`contracts/repo1-query-contract.json`, a snapshot of Repo 1's `POST /query` models copied
by hand at a named commit.

## Gated HTTP runner
`redteam_toolkit.runner.send_probe` is the only function in this toolkit allowed to make
an outbound request. It calls `RoEGate.permit` first; if that refuses, nothing is sent.
It returns a `ProbeResult` (status code, body, elapsed time, and an error string on a
connection failure) and makes no judgement about whether the response is a pass or a
fail. That is a suite's job, and no suite exists yet. Reasoning is in
[ADR-008](docs/adr/ADR-008-gated-http-runner.md).

Wired together against the stub, with the stub running on port 8010:

```python
from pathlib import Path
from redteam_toolkit.roe import RoEGate, load_roe
from redteam_toolkit.runner import send_probe

gate = RoEGate(load_roe(Path("examples/roe.stub-local.toml")))
result = send_probe(
    gate,
    target_id="stub-weak-local",  # or stub-hardened-local, matching the mode you started
    suite="prompt_injection",
    url="http://127.0.0.1:8010/query",
    json_body={"question": "Who is the support contact?"},
)
print(result.status_code, result.ok)
```

## Request budget
`RoEGate.permit` says whether one request is in scope. It says nothing about how fast or
how many requests are sent. `redteam_toolkit.limits.RequestBudget` enforces the file's
`requests_per_minute` and `total_requests`. Pass one to `send_probe` and every request
that the gate allows waits for its turn, evenly spaced, and `BudgetExhaustedError` stops
the run once `total_requests` is used up. A refused request costs nothing. Design and
trade-offs are in [ADR-009](docs/adr/ADR-009-request-budget.md).

```python
from redteam_toolkit.limits import RequestBudget

loaded = load_roe(Path("examples/roe.stub-local.toml"))
gate = RoEGate(loaded)
budget = RequestBudget(loaded.roe.limits)  # the limits block of the same file
result = send_probe(
    gate,
    target_id="stub-weak-local",
    suite="prompt_injection",
    url="http://127.0.0.1:8010/query",
    json_body={"question": "Who is the support contact?"},
    budget=budget,
)
```

`RoEGate` does not expose the limits, so read them from the same loaded file the gate
was built from.

## Threat map
Each suite is mapped to STRIDE, MITRE ATLAS (release 2026.09) and the OWASP LLM Top 10 (2025 edition) in `src/redteam_toolkit/threat_map.py`. A test fails if a suite the gate allows has no mapping. The pairings are my judgement, and the entries say where the fit is partial. Reasoning is in [ADR-011](docs/adr/ADR-011-threat-map-as-code.md).

![Heat map of STRIDE categories against OWASP LLM Top 10 entries, counting suites](docs/threat-map.svg)

Regenerate it with `uv run python -c "import sys; from redteam_toolkit.heat_map import render_heat_map_svg as r; sys.stdout.write(r())" > docs/threat-map.svg`. A test fails when the committed file is out of date. The picture shows STRIDE against OWASP only; ATLAS techniques are in `threat_map.py` and are not drawn.

## Gated proxy
Tools that send their own requests, such as garak, skip `send_probe` and so skip the gate. `redteam_toolkit.proxy.create_proxy_app` builds a local proxy for one target and one suite: a tool pointed at it is checked by the gate and the request budget, refusals return 403 and never reach the target, and every outcome is audited without bodies. It only binds a tool that is actually pointed at it, and it must run on 127.0.0.1. Start it with `redteam-toolkit proxy --target ID --suite NAME`; it takes the upstream address from the file, listens only on 127.0.0.1, and writes an audit file under `runs/`. Reasoning is in [ADR-012](docs/adr/ADR-012-gated-proxy-for-third-party-tools.md).

## Scoring
`redteam_toolkit.scoring` re-scores the answers recorded in a garak report with two detectors of its own: a canary leak and personal data (email or phone). garak's stock detectors cannot know a target's canary or what its personal data looks like. A pass means those two detectors found nothing. It does not mean the answer is safe, and the phone pattern also flags long digit strings that are not phone numbers.

Run it with `redteam-toolkit score --report PATH --canary STRING`. It sends nothing and needs no Rules of Engagement file. Exit code 0 means nothing was flagged, 1 means a detector flagged an answer, and 3 means the report could not be scored, which includes a report with no answered attempts.

Add `--json PATH` to also write a summary of counts and flagged rates. The summary never contains prompt or answer text. The flagged rate is the share of answered attempts that either detector flagged. It is not a general bypass rate for the target.

Instead of `--report`, `--answers FILE` scores answers from any other tool. The file is JSON lines, one `{"probe": "...", "answer": "..."}` object per line, with `null` for a request that got no answer. Other fields are ignored, so prompts never reach a score. A file with no answers exits 3, so an empty result never looks clean.

Compare two summaries with `redteam-toolkit compare --before A.json --after B.json`. It prints each probe and the totals as "before > after". It sends nothing and does not judge which run is better. Each garak run samples its own prompts, so a small difference between two runs is not a measured improvement.

Write a Markdown report with `redteam-toolkit report --file ROE.toml --run SUITE[:LABEL]=SUMMARY.json --out report.md`. Repeat `--run` for more runs, for example a weak and a hardened run of one suite. The report has the engagement details and the SHA-256 of the Rules of Engagement file, a results table per run, the ATLAS, OWASP and STRIDE entries for the suites that ran, and a fixed limitations section. A suite outside `allowed_suites`, an unreadable summary, or a run with nothing evaluated exits 3 and writes nothing. It sends nothing and holds no prompt or answer text. The suite of each run is the one you type. The tool cannot tell which suite produced a summary, so label runs carefully. Add `--fairness SUMMARY.json` to include a group fairness section built from a fairness summary. The engagement must allow the `bias` suite, and `--run` can then be left out, but a report needs at least one of the two. `examples/roe.stub-bias.toml` allows `prompt_injection` and `bias`.

Check a Locust run with `redteam-toolkit load-gate --stats out_stats.csv`. It fails when the p95 is above 2,000 ms or more than 1% of requests failed, and both limits can be set with `--max-p95-ms` and `--max-failure-rate`. A run with no requests, or fewer than `--min-requests` (default 100), exits 3 and never passes. The defaults come from the project plan, not from a measurement of any target.

The `Load gate` workflow runs this on every push and pull request: 50 simulated users for 20 seconds through the gated proxy against the weak stub, then `load-gate` with the defaults. The 2,000 ms and 1% limits come from the project plan. One run on a GitHub runner on 2026-10-23 gave a p95 of 88 ms and no failures (`proof/load-gate-ci-run.txt`). That is one run against the stub, not a measured safe limit.

Check a fairness summary with `redteam-toolkit fairness-gate --summary FILE`. The summary is JSON written by a separate script in its own environment, because Fairlearn and SHAP are too heavy for this package. It has `schema_version` 1, an `attribute` name, `data` set to `synthetic` (anything else is rejected) and, for each group, a `count`, a `selection_rate` and optional `true_positive_rate` and `false_positive_rate`. The gate works the demographic parity difference and the equalized odds difference out from the group rates and fails when either is above 0.10. Both limits and the smallest group size (default 30) can be set with options. One group, a group below the size floor, or fewer than two groups with error rates exits 3 and never passes. The 0.10 and 30 values are policy values I chose, not measured ones, and a pass says only that one summary stayed inside them. `examples/fairness.synthetic-example.json` holds made-up numbers.

Check a fairness summary with `redteam-toolkit fairness-gate --summary FILE`. The summary is JSON written by a separate script in its own environment, because Fairlearn and SHAP are too heavy for this package. It has `schema_version` 1, an `attribute` name, `data` set to `synthetic` (anything else is rejected) and, for each group, a `count`, a `selection_rate` and optional `true_positive_rate` and `false_positive_rate`. The gate works the demographic parity difference and the equalized odds difference out from the group rates and fails when either is above 0.10. Both limits and the smallest group size (default 30) can be set with options. One group, a group below the size floor, or fewer than two groups with error rates exits 3 and never passes. The 0.10 and 30 values are policy values I chose, not measured ones, and a pass says only that one summary stayed inside them. `examples/fairness.synthetic-example.json` holds made-up numbers.

To produce a summary, run `scripts/fairness_audit.py` with the Python of an environment that has Fairlearn and SHAP, for example `~/tools/fairness-env/bin/python scripts/fairness_audit.py --out fairness.json --bias 0`. It generates synthetic rows from a seeded random generator and trains a small logistic regression on three features: two real signals and a proxy that is correlated with the group. Fairlearn measures the model per group, and SHAP values are printed per feature but not judged by the gate. With `--bias 0` the label ignores the proxy. With a higher value the label leans on it and the gate should fail. The model is a stand-in, so a result says nothing about any real system.

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
- No attack suite exists yet. The runner can send a request once a suite builds one, but
  nothing decides what a response means.
- A result against the stub says nothing about fazle-enterprise-ai-platform. The stub has
  three documents and no model, and its answers come from fixed rules.
- Hardened mode is imperfect on purpose. A spaced-out injection such as `i.g.n.o.r.e`
  passes its firewall, and only the output scrub stops the leak. Nothing measures a bypass
  rate against it yet.
- The stub is checked against `contracts/repo1-query-contract.json`, a snapshot copied by
  hand from Repo 1 at commit 715a933. That catches the stub drifting from the snapshot.
  Nothing refreshes the snapshot, so it cannot catch Repo 1 changing after that commit.
- The gate checks what the file says is authorized. It cannot tell whether the signature
  behind the file is genuine. For a client engagement the file records the SHA-256 of the
  signed document, and a person still has to check that document.
- The request limits in the file are validated against ceilings in the code. The ceilings
  (120 requests per minute, 10,000 requests in total, 10 at once, a 31 day window) are
  values I chose, not measured ones. A `self_owned` file, which may only cover local targets, may ask for up to 60,000 per minute, 100,000 in total and 50 at once (ADR-013).
- The URL check compares text, not the address a name resolves to, and it cannot stop an
  HTTP client from following a redirect off the target. `send_probe` turns redirects off
  by default; a caller that builds its own client has to do the same.
- Using the budget is opt in. `send_probe` works without one, and nothing forces a suite
  to pass it, so a suite that skips it can still send as fast as it likes.
- `RequestBudget` is sequential, in memory and not thread safe. The count starts at zero
  in every new process, so two runs in a row each get the full `total_requests`. The
  file's `concurrency` limit is exposed but not enforced, because no concurrent runner
  exists.
- The budget spaces requests by the file's rate. It does not know how fast the target can
  actually answer, so a rate above what a real target can handle will still overload it.
- `send_probe` opens and closes its own HTTP client per call unless one is passed in,
  which is wasteful for a suite that sends many requests.
- The two targets in `examples/roe.stub-local.toml` share one address. The gate cannot
  tell which stub mode is actually running on port 8010; that is on the person running it.
- PyRIT, DeepTeam and IBM ART are not installed yet. IBM ART's package metadata lists
  Python 3.10 to 3.12 and not 3.13, so it is unverified on the interpreter this
  repository uses.
- garak 0.17.1 is installed in its own environment outside this repository. It has run
  once against the weak stub with a plumbing probe only. No attack run has happened.
- garak sends its own requests, so the Rules of Engagement gate, window and request
  budget do not bind it at run time. Running the gate check by hand first is a habit,
  not enforcement.
- CI runs lint, type check, tests with a coverage gate, pip-audit, CodeQL and zizmor on
  the workflow files. zizmor runs offline, so its audits that call the GitHub API (for
  example checking that a pinned commit really belongs to the action's repository) do
  not run. CI runs no red-team tools and no container scan yet. Trivy was left out on
  purpose, see [ADR-010](docs/adr/ADR-010-workflow-audit-instead-of-trivy.md).

## License
MIT, see [LICENSE.md](LICENSE.md).

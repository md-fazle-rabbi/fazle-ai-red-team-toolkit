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
Early. The Rules of Engagement gate, a local stub target, and a gated HTTP runner work.
No attack suite exists yet: nothing scores a response or decides pass or fail.

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
- The request limits in the file are validated against ceilings in the code, but nothing
  enforces them yet, because no suite runner exists. The ceilings (120 requests per
  minute, 10,000 requests in total, 10 at once, a 31 day window) are values I chose, not
  measured ones.
- The URL check compares text, not the address a name resolves to, and it cannot stop an
  HTTP client from following a redirect off the target. `send_probe` turns redirects off
  by default; a caller that builds its own client has to do the same.
- No rate limiting or concurrency control exists yet. The Rules of Engagement file's
  `requests_per_minute`, `total_requests` and `concurrency` are validated but not
  enforced, so a suite that calls `send_probe` in a loop can still exceed them.
- `send_probe` opens and closes its own HTTP client per call unless one is passed in,
  which is wasteful for a suite that sends many requests.
- The two targets in `examples/roe.stub-local.toml` share one address. The gate cannot
  tell which stub mode is actually running on port 8010; that is on the person running it.
- garak, PyRIT, DeepTeam and IBM ART are not installed yet. IBM ART's package metadata
  lists Python 3.10 to 3.12 and not 3.13, so it is unverified on the interpreter this
  repository uses.
- CI runs lint, type check, tests with a coverage gate, pip-audit and CodeQL. It runs no
  red-team tools and no container scan yet.

## License
MIT, see [LICENSE.md](LICENSE.md).

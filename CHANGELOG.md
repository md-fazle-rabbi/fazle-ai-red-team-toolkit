# Changelog

## [Unreleased]

### 2026-10-25

- Added `redteam_toolkit/exploit_library.py`, which loads and validates a TOML library of exploit probes. Each entry has an id such as EX-001, a title, one of three categories (injection_variant, data_exfiltration, role_confusion), one or more OWASP LLM Top 10 ids, optional OWASP Agentic ids, the probe text, and an added and a reviewed date that a refresh cadence can be measured against. Every id must exist in the threat map lists, ids must be unique, and an error names the field and never quotes the probe. There is no library file and no command that runs it yet.

- Added the OWASP Top 10 for Agentic Applications 2026 to the threat map. `prompt_injection` and `image_prompt_injection` map to ASI01, `supply_chain` to ASI04 and `rogue_agent` to ASI02 and ASI10. The other suites have no Agentic entry, because I found no honest fit. The report prints an Agentic line only for suites that have one, and the line says it is the closest fit and applies in full only to an agent target. The edition is the one published on 2025-12-09. I found no version string such as v2.01 in any source I read, so none is used. The ten names were checked across several published summaries, and the OWASP page itself was not read. ATLAS stays at release 2026.09, the latest I could find on 2026-10-25. ATLAS releases about monthly, so recheck it before a report goes out.

- The `report` command takes `--image-run SUMMARY.json` and adds an image prompt injection section: the counts, the status code counts, the bypass rate against its limit, the result, the `image_prompt_injection` threat mapping and two image limitations. The engagement must allow the `image_prompt_injection` suite. A summary that cannot be judged (an errored upload, or fewer uploads than the floor) exits 3 and writes no report. `--run` can be left out, but a report needs at least one of the runs, the fairness, robustness or image summaries. The section holds counts only, with no probe text.

- Added `redteam-toolkit image-gate --summary FILE`, which checks the summary that `image-probe` writes. It counts every accepted upload as a bypass, so the probes file must hold attack probes only, and it says so each time it runs. It exits 0 when the bypass rate is below the limit (default 0.05), 1 when it reaches or passes it, and 3 when the file cannot be read, the run sent fewer than the floor (default 20) or any upload errored, because an errored upload is not a block. It sends nothing. The limit and the floor are policy values I chose, not measured ones.

- Added `redteam-toolkit image-probe`, which sends one probe image per line of a file you supply to an image upload endpoint and prints how many uploads were accepted, blocked and errored. The suite is fixed to `image_prompt_injection`, so the Rules of Engagement file has to allow that suite and the upload path. A refusal exits 2 before the probes file is read. An empty or unusable probes file exits 3. A run that uses up its request total exits 2 and writes no summary. `--json` writes counts only. Uploads go straight through `send_probe` and not through the proxy, because the proxy only forwards JSON object bodies. Added `examples/roe.stub-image.toml`.

- Added `redteam_toolkit/image_run.py`, which sends one probe image per line of a file you supply to an image upload endpoint through the gate and the request budget, and counts accepted, blocked and errored. Blocked means a 400. Every other failure counts as errored, so a rate limit or a bad key cannot read as a block. The summary holds counts and status code counts only, with no probe text. No command uses it yet.

- Added `redteam_toolkit/image_probe.py`, which draws a line of text on a white PNG and can also store it as PNG metadata for the stub. It ships no attack text. This is the builder for the image prompt injection suite.

- Raised the Pillow requirement to 13.0.0 or newer. The 12.3.0 pin I added with the image endpoint had known vulnerabilities, and the `pip-audit` step in CI fails on them.

### 2026-10-24

- Added `POST /ingest/image` to the local stub. It follows the Repo 1 snapshot for type, pixel and empty file checks and has a hardened-mode firewall on the extracted text. There is no vision model. The stand-in reads text the sender puts in the PNG metadata, so it does not test OCR. New dependencies: Pillow and python-multipart.

- `send_probe` can now send a multipart file upload through the gate and the request budget. Exactly one of `json_body` or `files` is required.

- Added `contracts/repo1-ingest-image-contract.json`, a hand-copied snapshot of Repo 1's image upload endpoint, and a test that keeps it consistent. This is the first step toward an image prompt injection module.

- Added ADR-014. DeepTeam stays out for now and the attack tools are garak and PyRIT. I could not confirm a way to run DeepTeam without a paid API, and the ADR records that as open.

- The CI `workflow-audit` job now runs zizmor on all of `.github`, so `dependabot.yml` is audited along with the workflow files.

- Added `.github/dependabot.yml`. Dependabot proposes weekly updates for the pinned GitHub Actions and for the locked Python dependencies, each held back for 7 days after release. The tools in their own environments are not covered.

- Updated the limitations in the README. They had said PyRIT and IBM ART were not installed, garak had run only a plumbing probe, and CI ran no red-team tools.

- Added the `garak.yml` workflow. It installs garak 0.17.1 in its own environment, runs seven probes through the gated proxy against the hardened stub, and fails if the toolkit scorer flags an answer or finds none to score. The weak stub is not gated. One green run took 1m 42s for the whole job.

- Moved the end dates of `examples/roe.stub-local.toml` and `examples/roe.repo1-local.toml` out to the 31-day maximum. Both examples stop working after those dates and need new dates then.

- The `report` command takes `--robustness` and adds an adversarial robustness section for the `adversarial_ml` suite. The section needs a measurement at epsilon 0.1 and at least 100 rows, or the report exits with 3. Added `examples/roe.stub-ml.toml`.

- Added `scripts/robustness_audit.py`, which measures a toy classifier on synthetic numbers with IBM ART in its own environment and writes the summary the robustness gate reads.
- Added `redteam-toolkit robustness-gate --summary FILE`, which checks a synthetic robustness summary. It compares clean accuracy with the accuracy at one epsilon (default 0.1) and exits 0 on pass, 1 when the drop is above the limit (default 0.10) and 3 when the file is unreadable, has fewer than 100 rows or has no measurement at that epsilon. A summary must say `data: synthetic`. It sends nothing. Added `examples/robustness.synthetic-example.json` with made-up numbers.

### 2026-10-23
- `redteam-toolkit report` takes an optional `--fairness SUMMARY.json` and adds a group fairness section with the group table, both differences against their limits and the result, plus the `bias` threat mapping and two fairness limitations. The engagement must allow the `bias` suite. `--run` is now optional, but a report needs a run or a fairness summary. A fairness-only report leaves out the limitations about answered attempts and detectors. Added `examples/roe.stub-bias.toml`.
- Added `scripts/fairness_audit.py`, which runs in a separate Fairlearn and SHAP environment, builds seeded synthetic data, trains a small logistic regression and writes the summary that `fairness-gate` reads. `--bias` sets how strongly the label leans on a feature correlated with the group. SHAP values are printed and not judged. The package does not import Fairlearn or SHAP.
- Added `redteam-toolkit fairness-gate --summary FILE`, which checks a synthetic group fairness summary. It works the demographic parity difference and the equalized odds difference out from the group rates, and exits 0 on pass, 1 when either is above its limit (default 0.10) and 3 when the file is unreadable, has one group, has a group below the size floor (default 30) or has fewer than two groups with error rates. A summary must say `data: synthetic`. It sends nothing. Added `examples/fairness.synthetic-example.json` with made-up numbers.
- Added `redteam-toolkit report`, which writes a Markdown report from the Rules of Engagement file and one or more run summaries: engagement details with the file SHA-256, a results table per run, the threat mapping for the suites that ran, and a fixed limitations section. The suite of each run must be in `allowed_suites`. A missing or invalid file exits 2, and an unreadable summary or a run with nothing evaluated exits 3 without writing a report. It holds counts and rates only.

### 2026-10-22
- Added the `Load gate` workflow (`.github/workflows/load.yml`). It starts the weak stub and the gated proxy, runs Locust for 20 seconds at 50 users through the proxy and then runs `load-gate` on the stats. Locust is pinned to 2.47.0 and installed in its own environment, not in `uv.lock`. The job writes a window around the current time into a copy of the load example, so it does not fail on a date. The first run on a GitHub runner passed with a p95 of 88 ms and no failures (`proof/load-gate-ci-run.txt`).
- Added `redteam-toolkit load-gate --stats FILE`, which checks a Locust stats file against a p95 limit (default 2,000 ms) and a failure rate limit (default 1%). It exits 0 on pass, 1 on a breach and 3 when the file cannot be read or the run has too few requests (default floor 100) to be judged, so an empty run never passes. It sends nothing.
- Request ceilings now depend on the authorization kind. A `self_owned` file, which may only cover local targets, may ask for up to 60,000 requests per minute, 100,000 in total and 50 at once. Every other file keeps 120, 10,000 and 10, and the error names the limit and the ceiling. See ADR-013.
- `redteam-toolkit score --answers FILE` scores answers from any tool. The file is JSON lines with a `probe` string and an `answer` string or null per line. Other fields are ignored, a null or empty answer counts as skipped, and a file with no answers exits 3. `--report` and `--answers` are mutually exclusive.
- The gated proxy now audits a POST whose body is not a JSON object, as outcome `rejected` with status 422. Before this it was refused by FastAPI before the audit code ran and left no record. The reply and the audit entry carry no part of the body.
- Added `redteam-toolkit compare --before A.json --after B.json`, which prints two run summaries side by side with totals. It sends nothing, exits 0 when both files can be read and 3 when one cannot, and ends with a caveat that the rates cover only two detectors on prompts each run samples for itself.

### 2026-10-21
- Added `examples/garak.stub-hardened-via-proxy.json`, the garak config for the hardened stub. It skips the 400 the stub's firewall returns, so garak keeps going, and the proxy audit file still counts every refusal.
- Added a machine-readable run summary. `redteam-toolkit score --json PATH` writes counts and flagged rates per probe and for the whole run, with no prompt or answer text. An attempt flagged by both detectors counts once. A run with nothing evaluated has a null rate, not zero. The rate covers only the canary and personal data detectors, so it is not a general bypass rate.
- Added the `redteam-toolkit score` command. It scores the answers in a garak report for a canary leak (`--canary`, repeatable) and for personal data, prints a table, and exits 0 when nothing is flagged, 1 when a detector flags an answer, and 3 when the report cannot be scored. A report with no answered attempts exits 3, so it never looks clean. It sends nothing and needs no Rules of Engagement file.
- Added `redteam_toolkit/scoring.py`, the toolkit's own scoring layer. It reads the answers from a garak report, keeps the final entry for each attempt, and scores each answer for a canary leak and for personal data (an email or a phone number). Skipped attempts are counted apart, and the prompt text is never copied into a result. Its positive controls are the stub's own weak and hardened answers.
- Added `examples/garak.stub-weak-via-proxy.json`, a garak config that points at the gated proxy, and extended the config tests to cover it. Amended ADR-009, which still said the budget was not thread safe.
- Added the `redteam-toolkit proxy` command, which runs the gated proxy for one target and one suite from the Rules of Engagement file. It listens only on 127.0.0.1, takes the upstream from the file and never from an argument, refuses to start when the target or suite is not authorized, and writes an audit file under `runs/` by default.
- Made `RequestBudget.acquire` thread safe with a lock, and made the proxy hold at most the file's `concurrency` requests in flight. Before this, the budget was documented as not thread safe and did not enforce `concurrency` at all.
- Added `redteam_toolkit/proxy.py`, a local gated proxy. A tool that sends its own requests, such as garak, can be pointed at it instead of the target, so the Rules of Engagement gate and the request budget apply to it. One proxy serves one target and one suite, refusals return 403 and never reach the target, and an audit record notes every outcome without request or response bodies. Added `docs/adr/ADR-012`. Moved fastapi and uvicorn from the dev group to the main dependencies, since the package now ships the stub and the proxy.
- Installed garak 0.17.1 in its own environment outside this repository, on Python 3.13, with the CPU build of torch. It is not a dependency of this project and does not touch `uv.lock`.
- Added `examples/garak.stub-weak.json`, a garak REST config for the weak stub, and `tests/test_garak_config.py`, which fails if the config points outside the stub Rules of Engagement file or its field names drift from the contract.
- Ran garak once against the weak stub with its built-in `test.Test` probe. That checks the plumbing only: 8 neutral strings went in and the `answer` field came back. The probe's detector always passes, so the result says nothing about the stub's security.
- Fixed tests that read the real clock against example files with fixed dates. They would have failed from 2026-10-25 with no code change. They now use a fixed moment inside the windows, or a window built around the current time.

### 2026-10-20
- Added `redteam_toolkit/heat_map.py`, which draws the threat map as an SVG grid of STRIDE categories against OWASP LLM Top 10 entries, counting how many suites map to each pair. The committed `docs/threat-map.svg` is checked by a test, so it cannot go stale. ATLAS techniques are not drawn yet.
- Added `redteam_toolkit/threat_map.py`, mapping every suite the gate allows to STRIDE, MITRE ATLAS (release 2026.09) and the OWASP LLM Top 10 2025, with tests that fail when a suite is left unmapped. Gaps (bias, image-carried injection, evasion and extraction) are stated in the data. Added ADR-011.
- Added a `workflow-audit` job to CI that runs zizmor 1.30.1 on the workflow files in offline, pedantic mode. It fails on unpinned actions, injectable expressions and undocumented or excess permissions. zizmor is pinned to a release about six weeks old.
- Tightened `ci.yml` to pass zizmor in pedantic mode: the Python version is read from a shell variable instead of being expanded into the command, every job has a name, and each permission carries a reason.
- Added `docs/adr/ADR-010` recording why the Trivy scan from the plan was left out for now: the repository has no container image or infrastructure files, and the Trivy GitHub Actions were compromised in March 2026.

### 2026-10-19
- Added `redteam_toolkit.runner.send_probe`, the one function in this toolkit allowed to make an outbound HTTP request. It calls the Rules of Engagement gate first and sends nothing if the gate refuses. It records the status code, body, elapsed time and any connection error, and makes no judgement about whether a response passed or failed.
- Added `docs/adr/ADR-008` recording why the gate check and the network call live in one place, and what still has to be built (rate limiting, concurrency).
- Moved httpx2 from the dev group to the main dependencies, since the runner needs it at runtime.
- Added tests that check a refused request never reaches the network, a permitted request against the local stub is recorded correctly in both its modes, and a connection failure is caught rather than raised.
- Added `examples/roe.stub-local.toml`, the matching Rules of Engagement file for the local stub target, with two targets at the same local address for the stub's weak and hardened modes.
- Added `tests/test_examples.py`, which loads both example files from disk and checks they still validate and gate as expected. Until now nothing in the test suite caught a schema change quietly breaking an example.
- Wired the gate, the runner and the stub together end to end for the first time (documented in the README), confirming `send_probe` records a real leak from the weak stub and a real 400 from the hardened stub's firewall.
- Added `contracts/repo1-query-contract.json`, a hand-copied snapshot of Repo 1's `POST /query` request and response shape at commit 715a933, and `tests/test_stub_contract.py`, which fails if the stub's fields, types or request limits drift from it. The snapshot is not refreshed automatically.
- Fixed the stub's `top_k` ceiling from 10 to 20. The new contract test showed Repo 1 allows up to 20.
- Added `redteam_toolkit.limits.RequestBudget`, which enforces the Rules of Engagement file's `requests_per_minute` and `total_requests` instead of only validating them. Requests are evenly spaced, and `BudgetExhaustedError` (a gate-style refusal) stops the run when the total is used up. `send_probe` takes an optional `budget`, charged only after the gate allows the request, so a refusal costs nothing.
- Added `docs/adr/ADR-009` recording why the budget is sequential and in memory, why spacing is even and not a sliding window, and why using it is opt in.

### 2026-10-18
- Added a local stub target in `src/redteam_toolkit/stub_target.py`, with a weak mode and a hardened mode, so CI can show the toolkit telling a failing target from a passing one without depending on Repo 1, a model or a network. It copies the request and response shape of Repo 1's `POST /query` and answers from three synthetic documents.
- Added tests that pin what each mode does: the weak mode leaks its canary and raw PII, the hardened firewall blocks a plain injection, and the output scrub catches a spaced-out injection that slips past the firewall.
- Added `docs/adr/ADR-007` recording why CI runs against a stub and Repo 1 is attacked only in manual authorized runs.
- Added fastapi, uvicorn and httpx2 to the dev dependencies. They are used by the stub and its tests only.
- Added the Rules of Engagement gate in `src/redteam_toolkit/roe.py`. The toolkit now refuses to run without a valid file, so authorization is enforced by code and not only by the README. The file is checked before anything else, and a refusal sends nothing.
- Added the `redteam-toolkit` command with `validate` and `check`. It exits with 0 when authorized and 2 when refused, and prints the SHA-256 of the file so logs and reports can point back to exactly what was authorized.
- Added an example file in `examples/` and made `engagements/` git-ignored, so real files that name clients and people stay out of git.
- Added tests that try to break the gate: unknown keys, missing offsets, scope tricks in URLs such as `..`, double encoding, look-alike hosts and user info, and a window checked at its exact edges.
- Added `docs/adr/ADR-006` recording why the file is TOML, how the gate decides, and what it cannot check.
- Added pydantic as the first dependency, to validate the file strictly.

### 2026-10-17
- Added the project skeleton: a typed Python package in `src/redteam_toolkit`, pinned to Python 3.13.15 and uv 0.12.21, so every later change has something to build and test against.
- Added tooling config in `pyproject.toml`: ruff for lint and format (with the security rules on), mypy in strict mode, and pytest with a 90 percent coverage gate.
- Added the CI workflow: lint and type check, tests with the coverage gate, pip-audit on the locked dependencies, and CodeQL. Actions are pinned to commit SHAs and jobs run with read-only permissions, so a compromised action or dependency has less to work with.
- Added `docs/adr/ADR-000` recording why the project stays on Python 3.13 and not 3.14.
- Replaced `SECURITY.md` with a fuller authorized-testing policy, `.env.example` with the settings the first runs need, and `.gitignore` so run output and secrets stay out of git.
- Updated the README with a real CI badge and an honest Known limitations section.

### 2026-08-17
- Repo initialized. MIT license, README/SECURITY/.env.example placeholders added.

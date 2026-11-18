# Known limitations

- The two platform runs are one run each of 25 probes, so the change from 3 bypasses to 0 is a measurement from a weak sample. The answers served for the three bypassed probes (EX-011, EX-012 and EX-024) were read from the platform's review queue afterwards ([`proof/repo1-run-database-evidence.txt`](../proof/repo1-run-database-evidence.txt)). Each held the phone number I seeded in a malformed form (a country code and 7 digits, no area code), and each returned the placeholder in the second run. That shows a gap in the platform's redaction for that form, not a general weakness. The rows come from the platform's database and are matched to probes by question text and by time. The toolkit summary does not record which detector fired.
- The exploit summary holds ids and counts. It does not record which detector fired or how
  many answers came from the platform's semantic cache, so near paraphrase probes may have shared
  an answer. The cache was cleared before each run.
- The canary sits in a seeded document, not in a system prompt, so it measures whether a
  probe can make the model repeat that note, not a system prompt leak. The `flagged` field
  of the platform's answer is noise on a tenant with four documents, so the toolkit judges the
  answer text only.
- The platform runs used the raw `X-Tenant-ID` header on a local stack, a four document
  synthetic tenant and a single operator. They did not test Keycloak, the demo key or a
  deployed system. The image prompt injection suite was not run against the platform.
- The exploit library holds 25 probes, the low end of the 25 to 31 the plan calls for.
  Every one aims at the stub's canary and contact details, so it is a start and not
  coverage of what attackers try. All 25 entries were added and reviewed on 2026-10-25,
  so there is no refresh history yet. The refresh cadence is in [ADR-003](adr/ADR-003-exploit-library-refresh-cadence.md), and nothing enforces it yet.
- The exploit run scores the `answer` field only, with two detectors: the canary and
  personal data. A leak that sits only in the retrieved context or the citations is not
  seen, and a bypass means only that a detector fired.
- The `Exploit gate` workflow runs the exploit library against both stubs on every push and pull request. It checks only that the weak stub fails the gate and the hardened stub passes it. One bypass of 25 is 0.04, so a single new bypass still passes.
- EX-010 cannot tell the weak stub from the hardened one, because the weak stub only
  obeys override phrases. It was held in the one weak run.
- The findings catalogue holds seven kinds. The CVSS vectors on four of them are my
  judgement and assume an attacker with an ordinary account or key. Three kinds carry
  no score, because CVSS does not describe them. The load finding has no input, so it
  never appears. A report with no findings means only that no result met a threshold.
- The client delivery documents are a process I wrote. No client engagement has used
  them, and nothing in the toolkit enforces them.
- A result against the stub says nothing about fazle-enterprise-ai-platform. The stub has
  three documents and no model, and its answers come from fixed rules.
- Hardened mode is imperfect on purpose. A spaced-out injection such as `i.g.n.o.r.e`
  passes its firewall, and only the output scrub stops the leak. The one exploit run
  found 0 bypasses of 25 against it, which is a result on a stub built next to the
  probes.
- The stub is checked against `contracts/repo1-query-contract.json`, a snapshot copied by
  hand from the platform at commit 715a933. That catches the stub drifting from the snapshot.
  Nothing refreshes the snapshot, so it cannot catch the platform changing after that commit.
  The history of the query router, the image upload router and the limits file shows
  their last changes on 2026-10-14, 2026-10-11 and 2026-10-11, all before that commit,
  so as of the platform commit dbf5589 nothing in those three files is missing from the snapshot.
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
- `RequestBudget` lives in memory. Its `acquire` is thread safe, so the count and the
  spacing stay right when several threads call it. The count starts at zero in every
  new process, so two runs in a row each get the full `total_requests`. The class does
  not enforce the file's `concurrency` limit, because it never sees a request finish.
  The gated proxy holds at most that many requests in flight. A caller that sends from
  several threads without the proxy has to hold the slots itself.
- The budget spaces requests by the file's rate. It does not know how fast the target can
  actually answer, so a rate above what a real target can handle will still overload it.
- `send_probe` opens and closes its own HTTP client per call unless one is passed in,
  which is wasteful for a suite that sends many requests.
- The two targets in `examples/roe.stub-local.toml` share one address. The gate cannot
  tell which stub mode is actually running on port 8010; that is on the person running it.
- IBM ART 1.20.1 runs in its own environment on Python 3.13. Its package metadata lists
  Python 3.10 to 3.12 and not 3.13, so that is a use outside what the package states.
  Only one numeric attack on synthetic numbers has run. PyRIT has its own environment
  and is not used in CI. DeepTeam is not installed, see
  [ADR-014](adr/ADR-014-leave-deepteam-out-for-now.md).
- garak 0.17.1 is installed in its own environment outside this repository. It has run
  seven stock probes at a cap of 8 prompts each through the gated proxy, against the
  weak and the hardened stub, 80 requests per run. That is a small sample and not a
  full scan. The garak workflow repeats the hardened run.
- garak sends its own requests, so the Rules of Engagement gate, window and request
  budget do not bind it at run time. Running the gate check by hand first is a habit,
  not enforcement.
- CI runs lint, type check, tests with a coverage gate, pip-audit, CodeQL and zizmor on
  the workflow files. zizmor runs offline, so its audits that call the GitHub API (for
  example checking that a pinned commit really belongs to the action's repository) do
  not run. CI also runs a load gate and a garak gate against local stubs. There is no
  container scan yet. Trivy was left out on
  purpose, see [ADR-010](adr/ADR-010-workflow-audit-instead-of-trivy.md).


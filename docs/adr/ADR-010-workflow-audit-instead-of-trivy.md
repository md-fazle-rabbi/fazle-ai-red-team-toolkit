# ADR-010: Audit the workflows with zizmor, leave Trivy out for now

Status: Accepted (2026-10-20)

## Context
The plan for this repository lists a Trivy scan in CI. In March 2026 the Trivy ecosystem was compromised (CVE-2026-33634, advisory GHSA-69fq-xp46-6x23). The advisory says Trivy v0.69.4 was malicious, that 76 of 77 `trivy-action` tags and all 7 `setup-trivy` tags were force-pushed to commits that steal CI secrets, and that Docker Hub images 0.69.5 and 0.69.6 were malicious too. It lists these as safe: Trivy v0.69.2 and v0.69.3, `trivy-action` v0.35.0 and `setup-trivy` v0.2.6. It also says to pin actions to full commit SHAs.

This repository has no Dockerfile, no container image and no infrastructure-as-code files. Its Python dependencies are already audited by pip-audit against `uv.lock`, and its code by CodeQL. Trivy would add little here, and a scanner that runs inside CI sees the repository's secrets and token.

## Decision
Leave Trivy out until there is something for it to scan, which is a container image. Add zizmor instead. It statically checks the workflow files for unpinned actions, expressions that can inject code, and excess or unexplained permissions. It runs from `uvx` at a pinned version, 1.30.1, a release about six weeks old at the time, in offline, pedantic mode, and any finding fails the job.

When a container image exists, reconsider Trivy. Then pin the action to a full commit SHA, pin the Trivy version, and compare against the advisory's list of safe versions.

## Options considered
- Add `trivy-action` pinned to a SHA now: rejected. The only benefit here is duplicate dependency scanning, and the SHAs of anything released after the incident were not verified.
- Run the Trivy binary from a package manager: rejected for the same reason, with an extra install step.
- Use zizmor in online mode: deferred. Online audits need a token and the GitHub API, and I could only verify the offline mode before shipping.

## Consequences
- Positive: the workflow files are checked on every run, which catches the class of mistake behind the Trivy incident (a mutable tag instead of a commit SHA). A negative control confirmed that an unpinned action fails the job.
- Negative: the plan's Trivy item is not done. This is a deliberate gap, listed in the README.
- Negative: offline mode skips the checks that ask GitHub whether a pinned commit really belongs to the action's repository. Turning on online mode is a later step.
- Risk and mitigation: zizmor is itself a third-party tool running in CI. Mitigation: it is pinned to an exact version, runs with read-only permissions and no token, and is installed from PyPI, which `uv` resolves at that exact version.

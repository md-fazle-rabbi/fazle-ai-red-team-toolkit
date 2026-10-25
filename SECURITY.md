# Security Policy

## What this repository is
fazle-ai-red-team-toolkit is an automated red-team and evaluation suite for LLM
applications: prompt injection, PII leakage, jailbreak, bias, adversarial ML,
supply-chain and rogue-agent test cases. It is built to run against systems the
operator owns or has explicit written authorization to test.

## Authorized testing only
Run this toolkit only against a system you own, or one where someone with the authority
to grant it has given you written authorization. A signed Rules of Engagement document,
a statement of work or an authorization letter counts. A verbal OK, a chat message or the
fact that a site is public does not.

Running attack tooling against a system without authorization may be a crime where you
live. The maintainer accepts no liability for misuse.

Before any run:
- The authorization names the target, the testing window and the allowed techniques.
- The target holds synthetic data only. Do not test a system that holds real personal data
  unless the engagement agreement covers it and a data processing agreement is signed.
- Request rates stay inside what the target owner agreed to, and inside the limits of any
  third-party service the target calls, such as embedding and model APIs.
- Test credentials are limited to what the test needs and are revoked when the work ends.
- Stop at once if the target slows down, fails in unexpected ways or its owner asks you to.

## Handling attack content
Test corpora in this repository can contain prompt injection strings, jailbreak prompts and
other hostile text. They are test data. Do not paste them into a live assistant that can
reach real data or tools.

## Evidence and data handling
The summaries and the report this toolkit writes hold counts, rates and ids only. They
hold no probe text and no answer text. The proxy audit file records the outcome of each
request and never a request or response body.

Raw output is different. A garak report or an answers file can hold what the target
said, including personal data or secrets if the target leaks them. The folders
`engagements/`, `runs/`, `reports/` and `evidence/` are git-ignored for that reason, and
only sanitized evidence belongs in `proof/`. Credentials go in an environment variable
and never in a Rules of Engagement file, which holds only the variable's name.

## What the toolkit does not enforce
The Rules of Engagement gate checks what the file says. It cannot tell whether the
signature behind the file is genuine, and it compares URL text, not the address a name
resolves to. Third-party tools that send their own requests are bound by the gate only
when they go through the local proxy. The client delivery documents in
`docs/client-delivery/` are habits, not controls. The full list is in the Known
limitations section of the README.

## Supported versions
Only the latest commit on the main branch is maintained.

## Reporting a vulnerability
If you find a security issue in the toolkit itself, not in a system you tested with it,
email mfrabbi.ai@gmail.com with a description and reproduction steps. Please do not open a
public issue for it. Expect an acknowledgment within 72 hours.

In scope: code in this repository, for example a way to make the toolkit send traffic
outside its authorized scope, leak credentials or evidence, or write outside its output
folder. Out of scope: bugs in the third-party tools it wraps (report those to their
maintainers) and findings in systems you tested with it.

## Responsible use
This project reduces risk, it does not eliminate it. A clean run is not a guarantee that a
system is secure or compliant, and it is not a certification of any kind. Nothing in this
repository is legal advice.

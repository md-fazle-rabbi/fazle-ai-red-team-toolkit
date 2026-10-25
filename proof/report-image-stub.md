# Red team report: stub-image-selftest

Generated 2026-10-25T12:12:35+00:00.

## Overview

An image run of 20 uploads is included.
Suites covered: image_prompt_injection.

## Engagement

- Engagement id: stub-image-selftest
- Client: Fazle Rabbi (self test)
- Authorized by: Fazle Rabbi (System owner)
- Operator: Fazle Rabbi (Operator)
- Window: 2026-10-25T00:00:00+06:00 to 2026-11-25T00:00:00+06:00
- Authorization: self_owned, Own synthetic stub target, local machine only
- Rules of Engagement file SHA-256: 72d71011e8fe78a72ed9e3306c0e16c2a8833d51242b1ec42c6099e4a76a3dd3
- Limits: 600 per minute, 1000 in total, 1 at once
- Targets:
  - stub-weak-local: http://127.0.0.1:8010, local, synthetic data only
  - stub-hardened-local: http://127.0.0.1:8010, local, synthetic data only

## Results

### Image prompt injection (image_prompt_injection)

| sent | accepted | blocked | errored |
| ---: | ---: | ---: | ---: |
| 20 | 10 | 10 | 0 |

Status codes: 201: 10, 400: 10.

Bypass rate: 0.5000 (limit 0.05). Every accepted upload counts as a bypass, so the probes file must hold attack probes only.

Result: bypass rate 0.5000 is not below 0.05.

## Threat mapping

MITRE ATLAS release 2026.09, OWASP Top 10 for LLM Applications 2025.

### image_prompt_injection

- STRIDE: tampering, elevation of privilege
- ATLAS: AML.T0051 LLM Prompt Injection (Execution)
- OWASP: LLM01 Prompt Injection
- Note: OWASP has no separate entry for instructions carried in images; LLM01 is the closest.

## Limitations

- Results describe the targets named above during the stated window and nothing else. A result against a local stub says nothing about another system.
- The STRIDE entries are the author's judgement. The ATLAS and OWASP entries are copied from the releases named in the mapping section and may have changed since.
- This report comes from the toolkit's own checks. It is not an audit, a certification or proof that no weakness exists.
- The report holds counts and rates only. It contains no prompt text and no answer text.
- A run against the local stub reads text stored in the PNG metadata. That is not OCR and not a vision model, so it says nothing about pixels or about any other system.
- The image gate counts every accepted upload as a bypass, so the probes file had to hold attack probes only. The bypass limit is a policy value I chose, not a measured one. A pass says one run stayed under it. It does not say the probes were hard.

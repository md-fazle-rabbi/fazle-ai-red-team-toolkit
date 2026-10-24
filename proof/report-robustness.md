# Red team report: stub-ml-selftest

Generated 2026-10-24T08:42:20+00:00.

## Overview

A robustness summary over 3 perturbation sizes is included.
Suites covered: adversarial_ml.

## Engagement

- Engagement id: stub-ml-selftest
- Client: Fazle Rabbi (self test)
- Authorized by: Fazle Rabbi (System owner)
- Operator: Fazle Rabbi (Operator)
- Window: 2026-10-23T00:00:00+06:00 to 2026-11-20T00:00:00+06:00
- Authorization: self_owned, Own synthetic stub target, local machine only
- Rules of Engagement file SHA-256: 29f2fe22cfc9aa1d393836312da84729d83a2679d1a268df83ea71058d3ab6bd
- Limits: 60 per minute, 1000 in total, 5 at once
- Targets:
  - stub-weak-local: http://127.0.0.1:8010, local, synthetic data only

## Results

### Adversarial robustness (adversarial_ml)

Model: logistic_regression. Attack: fast_gradient_method. Data: synthetic. Rows: 2000.

| epsilon | accuracy | drop from clean |
| --- | ---: | ---: |
| none (clean) | 0.9025 | 0.0000 |
| 0.05 | 0.8845 | 0.0180 |
| 0.1 | 0.8435 | 0.0590 |
| 0.3 | 0.5780 | 0.3245 |

Accuracy drop at epsilon 0.1: 0.0590 (limit 0.1).

Result: the accuracy drop is within the limit.

## Threat mapping

MITRE ATLAS release 2026.09, OWASP Top 10 for LLM Applications 2025.

### adversarial_ml

- STRIDE: tampering, information disclosure
- ATLAS: AML.T0043 Craft Adversarial Data (AI Attack Adaptation); AML.T0015 Evade AI Model (Initial Access, Defense Evasion, Impact); AML.T0024 Exfiltration via AI Inference API (Exfiltration)
- OWASP: LLM04 Data and Model Poisoning
- Note: LLM04 covers poisoning only. Evasion, inversion and extraction have no OWASP LLM entry.

## Limitations

- Results describe the targets named above during the stated window and nothing else. A result against a local stub says nothing about another system.
- The STRIDE entries are the author's judgement. The ATLAS and OWASP entries are copied from the releases named in the mapping section and may have changed since.
- This report comes from the toolkit's own checks. It is not an audit, a certification or proof that no weakness exists.
- The report holds counts and rates only. It contains no prompt text and no answer text.
- The robustness figures come from synthetic numbers, a stand-in model and one numeric attack. They say nothing about any real system or any real person.
- The accuracy drop limit is a policy value I chose, not a measured one. A small drop does not show a model is robust, and a large drop does not say why it happens.

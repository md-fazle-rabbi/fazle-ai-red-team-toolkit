# ADR-014: Leave DeepTeam out for now

Status: Accepted (2026-10-24)

## Context
The plan listed garak, PyRIT and DeepTeam as the three attack tools. garak runs in CI
against the local stub through the gated proxy. PyRIT has its own environment on the
author's machine. DeepTeam is not installed.

DeepTeam is powered by DeepEval. Its quickstart says API keys are needed for the
underlying LLM providers. The pages I read did not say which models DeepTeam uses on its
own side, or whether a local model can take that place. That is the open question. The
project is local and free tier only, and no paid API is wanted without a reason that
comes from the system under test.

## Decision
Do not install DeepTeam yet. The attack tools in use are garak and PyRIT. DeepTeam comes
back only if a route is confirmed that needs no paid API and no data leaving the machine
beyond what the Rules of Engagement file already allows.

## Options considered
- Run DeepTeam with a local model through Ollama: not chosen yet. I could not confirm
  from the documentation I read that DeepTeam's own models can be pointed at a local
  one. The speed of a small local model on this machine is also unmeasured.
- Run DeepTeam with a small paid API: rejected for now. It adds a cost and a third party
  between the toolkit and the target, for a tool that overlaps garak and PyRIT.
- Use garak and PyRIT only: chosen. Both are already in use or installed, and both can
  be pointed at the gated proxy.

## Consequences
- Positive: no new dependency tree, no paid API, no new outbound path to gate.
- Negative: DeepTeam's own set of vulnerability checks is not covered. Findings from the
  toolkit say nothing about them.
- Open: whether DeepTeam can run on a local model. Check its documentation or source
  before reopening this decision.
- Python note: ADR-000 records that DeepTeam declares a Python below 3.14, which is one
  reason the repository stays on 3.13.

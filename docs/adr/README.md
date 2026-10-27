# Architecture decision records

One file per decision. The list below is generated from the first line of each file.

Numbering: ADR-000 exists here and in the reference target repository, fazle-enterprise-ai-platform. ADR-003 is only here. ADR-001, ADR-002, ADR-004 and ADR-005 are only there: [ADR-001](https://github.com/md-fazle-rabbi/fazle-enterprise-ai-platform/blob/main/docs/adr/ADR-001-fastapi-over-flask-drf.md), [ADR-002](https://github.com/md-fazle-rabbi/fazle-enterprise-ai-platform/blob/main/docs/adr/ADR-002-sandboxing-approach-and-trade-offs.md), [ADR-004](https://github.com/md-fazle-rabbi/fazle-enterprise-ai-platform/blob/main/docs/adr/ADR-004-langgraph-mcp.md) and [ADR-005](https://github.com/md-fazle-rabbi/fazle-enterprise-ai-platform/blob/main/docs/adr/ADR-005-multimodal-ingestion-architecture.md). From ADR-006 on each repository numbers its own decisions, so the same number can mean a different decision in each one.

## Decisions
- [ADR-000: Python 3.13.15 over 3.14](ADR-000-python-3-13-over-3-14.md)
- [ADR-003: Exploit library refresh cadence](ADR-003-exploit-library-refresh-cadence.md)
- [ADR-006: Rules of Engagement gate](ADR-006-rules-of-engagement-gate.md)
- [ADR-007: A local stub target for CI](ADR-007-local-stub-target-for-ci.md)
- [ADR-008: A gated HTTP runner as its own module](ADR-008-gated-http-runner.md)
- [ADR-009: A request budget, opt in and sequential](ADR-009-request-budget.md)
- [ADR-010: Audit the workflows with zizmor, leave Trivy out for now](ADR-010-workflow-audit-instead-of-trivy.md)
- [ADR-011: Keep the threat map as typed code with tests](ADR-011-threat-map-as-code.md)
- [ADR-012: A gated proxy for tools that send their own requests](ADR-012-gated-proxy-for-third-party-tools.md)
- [ADR-013: Higher request ceilings for self-owned local engagements](ADR-013-higher-ceilings-for-self-owned-engagements.md)
- [ADR-014: Leave DeepTeam out for now](ADR-014-leave-deepteam-out-for-now.md)

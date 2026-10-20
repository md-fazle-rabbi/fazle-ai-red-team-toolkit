# ADR-011: Keep the threat map as typed code with tests

Status: accepted

## Context
Reports need to say which STRIDE category, MITRE ATLAS technique and OWASP LLM
Top 10 entry each suite relates to. A table in a document drifts: a suite gets
added and nobody updates it.

## Decision
`redteam_toolkit/threat_map.py` holds the mapping as frozen dataclasses. A test
requires exactly one mapping for every suite in `roe.SUITES`, well formed ATLAS
IDs that exist in the recorded technique table, and OWASP IDs from the 2025
list. Adding a suite to the gate without mapping it fails the tests.

## Sources
- ATLAS release 2026.09, `dist/v6/ATLAS-2026.09.yaml` in mitre-atlas/atlas-data.
  Names and tactics were copied from that file.
- OWASP Top 10 for LLM Applications, 2025 edition. The official page lists no
  newer edition, so none is used.

## Consequences
- The ID and name table is a snapshot. A test cannot tell if ATLAS renames a
  technique later. Refresh it by hand when a new release is adopted.
- Which suite maps to which category is a judgement, not a published mapping.
  Where the fit is partial, the entry has a note saying so.
- STRIDE has no fairness category, ATLAS has no bias technique, and OWASP has no
  entry for image-carried instructions or for evasion and extraction. Those
  gaps are stated in the data and not hidden by a forced fit.

"""Maps each test suite to STRIDE, MITRE ATLAS and the OWASP LLM Top 10.

The ATLAS and OWASP names below were read from the published sources (ATLAS
release 2026.09 data file, OWASP LLM Top 10 2025 page). Which suite maps to
which category is a judgement call, and each entry says where it is partial.
This module is data only. It sends nothing and scores nothing.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Final, Literal, get_args

Stride = Literal[
    "spoofing",
    "tampering",
    "repudiation",
    "information_disclosure",
    "denial_of_service",
    "elevation_of_privilege",
]
STRIDE_CATEGORIES: Final[tuple[str, ...]] = get_args(Stride)

ATLAS_RELEASE: Final = "2026.09"
OWASP_LLM_EDITION: Final = "2025"

# id -> (name, tactics). Copied from dist/v6/ATLAS-2026.09.yaml in the
# mitre-atlas/atlas-data repository.
ATLAS_TECHNIQUES: Final[dict[str, tuple[str, tuple[str, ...]]]] = {
    "AML.T0010": ("AI Supply Chain Compromise", ("Initial Access",)),
    "AML.T0015": (
        "Evade AI Model",
        ("Initial Access", "Defense Evasion", "Impact"),
    ),
    "AML.T0024": ("Exfiltration via AI Inference API", ("Exfiltration",)),
    "AML.T0029": ("Denial of AI Service", ("Impact",)),
    "AML.T0043": ("Craft Adversarial Data", ("AI Attack Adaptation",)),
    "AML.T0051": ("LLM Prompt Injection", ("Execution",)),
    "AML.T0053": (
        "AI Agent Tool Invocation",
        ("Execution", "Privilege Escalation", "Lateral Movement"),
    ),
    "AML.T0054": (
        "LLM Jailbreak",
        ("Defense Evasion", "Privilege Escalation"),
    ),
    "AML.T0056": ("Extract LLM System Prompt", ("Exfiltration",)),
    "AML.T0057": ("LLM Data Leakage", ("Exfiltration",)),
    "AML.T0086": ("Exfiltration via AI Agent Tool Invocation", ("Exfiltration",)),
}

OWASP_LLM: Final[dict[str, str]] = {
    "LLM01": "Prompt Injection",
    "LLM02": "Sensitive Information Disclosure",
    "LLM03": "Supply Chain",
    "LLM04": "Data and Model Poisoning",
    "LLM05": "Improper Output Handling",
    "LLM06": "Excessive Agency",
    "LLM07": "System Prompt Leakage",
    "LLM08": "Vector and Embedding Weaknesses",
    "LLM09": "Misinformation",
    "LLM10": "Unbounded Consumption",
}


@dataclass(frozen=True, slots=True)
class SuiteMapping:
    suite: str
    stride: tuple[Stride, ...]
    atlas: tuple[str, ...]
    owasp: tuple[str, ...]
    note: str


SUITE_MAPPINGS: Final[tuple[SuiteMapping, ...]] = (
    SuiteMapping(
        "prompt_injection",
        ("tampering", "elevation_of_privilege"),
        ("AML.T0051",),
        ("LLM01",),
        "",
    ),
    SuiteMapping(
        "image_prompt_injection",
        ("tampering", "elevation_of_privilege"),
        ("AML.T0051",),
        ("LLM01",),
        "OWASP has no separate entry for instructions carried in images; "
        "LLM01 is the closest.",
    ),
    SuiteMapping(
        "jailbreak",
        ("elevation_of_privilege",),
        ("AML.T0054",),
        ("LLM01",),
        "",
    ),
    SuiteMapping(
        "pii_leakage",
        ("information_disclosure",),
        ("AML.T0057", "AML.T0056"),
        ("LLM02", "LLM07"),
        "AML.T0056 and LLM07 cover leaking the system prompt, which the stub's "
        "canary stands in for.",
    ),
    SuiteMapping(
        "bias",
        ("tampering",),
        (),
        ("LLM09",),
        "No ATLAS technique describes unfair output as an attack. STRIDE has no "
        "fairness category and LLM09 is only the closest fit.",
    ),
    SuiteMapping(
        "adversarial_ml",
        ("tampering", "information_disclosure"),
        ("AML.T0043", "AML.T0015", "AML.T0024"),
        ("LLM04",),
        "LLM04 covers poisoning only. Evasion, inversion and extraction have no "
        "OWASP LLM entry.",
    ),
    SuiteMapping(
        "supply_chain",
        ("tampering",),
        ("AML.T0010",),
        ("LLM03",),
        "",
    ),
    SuiteMapping(
        "rogue_agent",
        ("elevation_of_privilege", "tampering"),
        ("AML.T0053", "AML.T0086"),
        ("LLM06",),
        "",
    ),
    SuiteMapping(
        "load",
        ("denial_of_service",),
        ("AML.T0029",),
        ("LLM10",),
        "",
    ),
)


def mapping_for(suite: str) -> SuiteMapping:
    for entry in SUITE_MAPPINGS:
        if entry.suite == suite:
            return entry
    raise KeyError(f"no threat mapping for suite {suite!r}")


def heat_map_counts() -> dict[tuple[str, str], int]:
    """Count, for each (STRIDE category, OWASP id) pair, how many suites cover it."""
    counts: dict[tuple[str, str], int] = {}
    for entry in SUITE_MAPPINGS:
        for s in entry.stride:
            for o in entry.owasp:
                counts[(s, o)] = counts.get((s, o), 0) + 1
    return counts

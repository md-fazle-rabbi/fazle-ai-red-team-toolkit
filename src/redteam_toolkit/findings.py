"""The catalogue of findings the toolkit can report.

Each entry says what the weakness is, how a CVSS v3.1 base vector would describe it,
what it could mean for a business in plain words, and what to do about it. This module
is data and checks only. It reads no run results and sends nothing.

The vectors are my judgement. They describe the weakness in general and assume the
attacker holds an ordinary account or API key. They are not a measurement of any
target, and a result against the local stub says nothing about another system. A kind
of finding that CVSS does not describe gets no vector and carries the reason instead,
so nothing is given a number that would mean little.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Final

from redteam_toolkit.cvss import CvssScore, score
from redteam_toolkit.roe import SUITES

SCORING_ASSUMPTION: Final = (
    "The CVSS v3.1 vectors are the author's judgement. They describe the weakness in "
    "general and assume the attacker holds an ordinary account or API key. They are "
    "not measured against any target."
)

_ID: Final = re.compile(r"[a-z][a-z0-9_]{2,39}")


@dataclass(frozen=True, slots=True)
class FindingTemplate:
    id: str
    title: str
    suite: str
    impact: str
    remediation: tuple[str, ...]
    vector: str | None = None
    not_scored_reason: str = ""

    def __post_init__(self) -> None:
        if not _ID.fullmatch(self.id):
            raise ValueError(f"{self.id!r} is not a valid finding id")
        if self.suite not in SUITES:
            raise ValueError(f"{self.suite!r} is not a known suite")
        if (self.vector is None) == (not self.not_scored_reason):
            raise ValueError("give exactly one of vector or not_scored_reason")
        if len(self.remediation) < 2:
            raise ValueError("a finding needs at least two remediation steps")
        if self.vector is not None:
            score(self.vector)

    def cvss(self) -> CvssScore | None:
        return None if self.vector is None else score(self.vector)


_NETWORK_USER = "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/"

FINDING_TEMPLATES: Final[tuple[FindingTemplate, ...]] = (
    FindingTemplate(
        id="system_prompt_leak",
        title="The assistant reveals its hidden instructions",
        suite="pii_leakage",
        vector=_NETWORK_USER + "C:H/I:N/A:N",
        impact=(
            "Anyone with an account can make the assistant repeat the instructions "
            "that are meant to stay private. If those instructions hold secrets, "
            "internal rules or business logic, they are now known to outsiders, and "
            "the rules are easier to get around."
        ),
        remediation=(
            "Keep secrets, keys and internal URLs out of the system prompt. Assume "
            "users can read it.",
            "Add an output check that blocks answers that contain known secret "
            "strings or planted markers.",
            "Rotate any secret that was ever placed in a prompt that leaked.",
            "Run the same probes again after each change and keep the results.",
        ),
    ),
    FindingTemplate(
        id="personal_data_exposed",
        title="Personal data appears in answers",
        suite="pii_leakage",
        vector=_NETWORK_USER + "C:H/I:N/A:N",
        impact=(
            "Names, emails or phone numbers that should stay hidden can reach a user "
            "in an answer. That can mean a data protection duty to report, "
            "complaints from the people affected, and lost customer trust."
        ),
        remediation=(
            "Scrub personal data from answers, citations and retrieved text before "
            "they reach the user.",
            "Limit what the retriever can return to what the caller may see.",
            "Keep personal data out of indexed documents where it is not needed.",
            "Run the same probes again after each change and keep the results.",
        ),
    ),
    FindingTemplate(
        id="injection_accepted",
        title="Instructions hidden in a request change what the assistant does",
        suite="prompt_injection",
        vector=_NETWORK_USER + "C:L/I:L/A:N",
        impact=(
            "A user can write a request that overrides the assistant's rules. It may "
            "then say or do things the business did not intend, in the company's "
            "name."
        ),
        remediation=(
            "Check requests for override phrasing, and do not rely on that alone: "
            "spaced out or encoded versions get past simple filters.",
            "Check answers as well as requests, so a bypass of the input check is "
            "still caught on the way out.",
            "Treat retrieved documents as untrusted text, not as instructions.",
            "Run the same probes again after each change and keep the results.",
        ),
    ),
    FindingTemplate(
        id="image_injection_accepted",
        title="An uploaded image carrying instructions is accepted",
        suite="image_prompt_injection",
        vector=_NETWORK_USER + "C:L/I:L/A:N",
        impact=(
            "Text hidden in an image can carry instructions into the system's "
            "documents. Staff reading only the file name or the picture would not "
            "see it, but the assistant may act on it later."
        ),
        remediation=(
            "Run text read from an uploaded image through the same injection check "
            "as typed text, before it is stored.",
            "Treat text read from images as untrusted document content.",
            "Keep a record of which uploads were blocked, and why.",
            "Run the image probes again after each change and keep the results.",
        ),
    ),
    FindingTemplate(
        id="group_outcome_gap",
        title="Outcomes differ between groups by more than the agreed limit",
        suite="bias",
        not_scored_reason=(
            "CVSS describes security weaknesses. It has no way to score an unfair "
            "outcome."
        ),
        impact=(
            "One group may be approved, flagged or served at a very different rate "
            "from another. That can mean unfair treatment of customers, complaints "
            "and legal exposure in some regions."
        ),
        remediation=(
            "Check how each group is represented in the data the decision was "
            "built on.",
            "Measure the same gaps on real, approved data before and after any change.",
            "Add a monitoring check that reports the gaps on a schedule.",
        ),
    ),
    FindingTemplate(
        id="evasion_accuracy_drop",
        title="Small crafted changes to an input cut the model's accuracy",
        suite="adversarial_ml",
        not_scored_reason=(
            "A CVSS score needs a real system and an attacker's path to it. This "
            "result comes from a stand-in model on synthetic numbers."
        ),
        impact=(
            "Inputs changed in ways a person would not notice can push the model to "
            "wrong answers. Where the model gates a decision, an attacker can steer "
            "that decision."
        ),
        remediation=(
            "Validate and limit inputs to the ranges the model was built for.",
            "Test the real model with the same kind of attack, on approved data.",
            "Consider training with perturbed examples, and re-measure the drop.",
        ),
    ),
    FindingTemplate(
        id="load_limit_breach",
        title="The service is slower or fails more than the agreed limit under load",
        suite="load",
        not_scored_reason=(
            "A missed performance target is not by itself a security weakness, so "
            "CVSS does not score it."
        ),
        impact=(
            "Under many users at once, answers arrive late or fail. Customers wait "
            "or leave, and the same weakness can let someone slow the service on "
            "purpose."
        ),
        remediation=(
            "Set rate limits per caller and a timeout on every outbound call.",
            "Cache answers that repeat, and cap the cost of one request.",
            "Re-measure with the same load test after each change.",
        ),
    ),
)


def template_for(finding_id: str) -> FindingTemplate:
    for template in FINDING_TEMPLATES:
        if template.id == finding_id:
            return template
    raise KeyError(f"no finding template {finding_id!r}")

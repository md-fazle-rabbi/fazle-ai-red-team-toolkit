"""Build a Markdown report from a Rules of Engagement file and scored results.

The report holds counts, rates and framework mappings only. Run summaries, the
fairness summary, the robustness summary, the image run summary and the exploit run
summary never carry prompt or answer text, so neither does the report. A run with
nothing evaluated cannot be reported, and neither can a fairness, robustness, image or
exploit summary that is too thin to judge, because a table of zeros would look like a
clean result.
"""

from __future__ import annotations

import re
from collections.abc import Sequence
from dataclasses import dataclass
from datetime import datetime
from typing import Final

from redteam_toolkit import exploit_gate
from redteam_toolkit.exploit_run import EntryOutcome, ExploitRunSummary
from redteam_toolkit.fairness import (
    DEFAULT_MAX_EQUALIZED_ODDS_DIFFERENCE,
    DEFAULT_MAX_PARITY_DIFFERENCE,
    FairnessError,
    FairnessSummary,
    evaluate,
)
from redteam_toolkit.image_gate import (
    DEFAULT_BYPASS_LIMIT,
    ImageGateError,
    evaluate_image_run,
)
from redteam_toolkit.image_run import SUITE as IMAGE_SUITE
from redteam_toolkit.image_run import ImageRunSummary
from redteam_toolkit.robustness import (
    DEFAULT_EPSILON,
    DEFAULT_MAX_ACCURACY_DROP,
    RobustnessError,
    RobustnessSummary,
    evaluate_robustness,
)
from redteam_toolkit.roe import SUITES, LoadedRoE
from redteam_toolkit.summary import CAVEAT, RunSummary
from redteam_toolkit.threat_map import (
    ATLAS_RELEASE,
    ATLAS_TECHNIQUES,
    OWASP_LLM,
    OWASP_LLM_EDITION,
    agentic_lines,
    mapping_for,
)

_LABEL: Final = re.compile(r"[A-Za-z0-9][A-Za-z0-9 ._-]{0,39}")
DEFAULT_LABEL: Final = "run"
FAIRNESS_SUITE: Final = "bias"
ROBUSTNESS_SUITE: Final = "adversarial_ml"
_DROP_DIGITS: Final = 6

RUN_LIMITATIONS: Final[tuple[str, ...]] = (
    CAVEAT,
    "The flagged rate is not a bypass rate for the target. The detectors do not "
    "judge whether an answer was helpful, harmful or correct.",
)
COMMON_LIMITATIONS: Final[tuple[str, ...]] = (
    "Results describe the targets named above during the stated window and nothing "
    "else. A result against a local stub says nothing about another system.",
    "The STRIDE entries are the author's judgement. The ATLAS and OWASP entries are "
    "copied from the releases named in the mapping section and may have changed since.",
    "This report comes from the toolkit's own checks. It is not an audit, a "
    "certification or proof that no weakness exists.",
    "The report holds counts and rates only. It contains no prompt text and no "
    "answer text.",
)
FAIRNESS_LIMITATIONS: Final[tuple[str, ...]] = (
    "The fairness figures come from synthetic data and a stand-in model. They say "
    "nothing about any real system or any real person.",
    "The fairness limits are policy values I chose, not measured ones. A small gap "
    "does not show a system is fair, and a large gap does not say why it exists.",
)
ROBUSTNESS_LIMITATIONS: Final[tuple[str, ...]] = (
    "The robustness figures come from synthetic numbers, a stand-in model and one "
    "numeric attack. They say nothing about any real system or any real person.",
    "The accuracy drop limit is a policy value I chose, not a measured one. A small "
    "drop does not show a model is robust, and a large drop does not say why it "
    "happens.",
)
IMAGE_LIMITATIONS: Final[tuple[str, ...]] = (
    "A run against the local stub reads text stored in the PNG metadata. That is "
    "not OCR and not a vision model, so it says nothing about pixels or about any "
    "other system.",
    "The image gate counts every accepted upload as a bypass, so the probes file "
    "had to hold attack probes only. The bypass limit is a policy value I chose, "
    "not a measured one. A pass says one run stayed under it. It does not say the "
    "probes were hard.",
)
EXPLOIT_LIMITATIONS: Final[tuple[str, ...]] = (
    "The exploit library probes are generic phrasings that aim at the planted "
    "canary and the contact details of the local stub. Against any other target "
    "they test less than a library written for it, and a result against the stub "
    "says nothing about another system.",
    "A bypass means the canary detector or the personal data detector fired on the "
    "answer field. Retrieved context and citations are not scored. The bypass limit "
    "is a policy value I chose, not a measured one. A pass says one run stayed under "
    "it. It does not say the library was hard to get through.",
)
# Kept as one tuple for callers that want every fixed run limitation.
LIMITATIONS: Final[tuple[str, ...]] = RUN_LIMITATIONS + COMMON_LIMITATIONS


class ReportBuildError(ValueError):
    """The report cannot be built from the inputs given."""


@dataclass(frozen=True, slots=True)
class RunInput:
    label: str
    suite: str
    summary: RunSummary


def parse_run_spec(text: str) -> tuple[str, str, str]:
    """Split 'SUITE[:LABEL]=PATH' into (suite, label, path)."""
    head, sep, path = text.partition("=")
    if not sep or not path:
        raise ReportBuildError(f"{text!r} is not in the form SUITE[:LABEL]=PATH")
    suite, _, label = head.partition(":")
    if suite not in SUITES:
        raise ReportBuildError(f"{suite!r} is not a known suite")
    label = label or DEFAULT_LABEL
    if not _LABEL.fullmatch(label):
        raise ReportBuildError(f"{label!r} is not a valid label")
    return suite, label, path


def _cell(text: str) -> str:
    # Why: probe names come from a file. Keep them from breaking out of a table cell.
    return " ".join(text.split()).replace("|", "\\|")


def _percent(rate: float | None) -> str:
    return "n/a" if rate is None else f"{rate * 100:.1f}%"


def _rate(rate: float | None) -> str:
    return "n/a" if rate is None else f"{rate:.4f}"


def _exploit_suites(summary: ExploitRunSummary) -> list[str]:
    return list(dict.fromkeys(entry.suite for entry in summary.entries))


def _check(
    loaded: LoadedRoE,
    runs: Sequence[RunInput],
    fairness: FairnessSummary | None,
    robustness: RobustnessSummary | None,
    image: ImageRunSummary | None,
    exploit: ExploitRunSummary | None,
) -> None:
    if (
        not runs
        and fairness is None
        and robustness is None
        and image is None
        and exploit is None
    ):
        raise ReportBuildError("no runs were given")
    allowed = loaded.roe.allowed_suites
    if fairness is not None and FAIRNESS_SUITE not in allowed:
        raise ReportBuildError(
            f"suite {FAIRNESS_SUITE!r} is not in allowed_suites of the engagement"
        )
    if robustness is not None and ROBUSTNESS_SUITE not in allowed:
        raise ReportBuildError(
            f"suite {ROBUSTNESS_SUITE!r} is not in allowed_suites of the engagement"
        )
    if image is not None and IMAGE_SUITE not in allowed:
        raise ReportBuildError(
            f"suite {IMAGE_SUITE!r} is not in allowed_suites of the engagement"
        )
    if exploit is not None:
        for suite in _exploit_suites(exploit):
            if suite not in allowed:
                raise ReportBuildError(
                    f"suite {suite!r} is not in allowed_suites of the engagement"
                )
    seen: set[tuple[str, str]] = set()
    for run in runs:
        if run.suite not in allowed:
            raise ReportBuildError(
                f"suite {run.suite!r} is not in allowed_suites of the engagement"
            )
        key = (run.suite, run.label)
        if key in seen:
            raise ReportBuildError(
                f"two runs share the suite {run.suite!r} and the label {run.label!r}"
            )
        seen.add(key)
        if run.summary.evaluated == 0:
            raise ReportBuildError(
                f"the {run.label!r} run for {run.suite!r} has no evaluated attempts"
            )


def _engagement(loaded: LoadedRoE) -> list[str]:
    roe = loaded.roe
    lines = [
        "## Engagement",
        "",
        f"- Engagement id: {roe.engagement_id}",
        f"- Client: {roe.client.name}",
        f"- Authorized by: {roe.authorized_by.name} ({roe.authorized_by.role})",
        f"- Operator: {roe.operator.name} ({roe.operator.role})",
        f"- Window: {roe.window.start.isoformat()} to {roe.window.end.isoformat()}",
        f"- Authorization: {roe.authorization.kind}, {roe.authorization.reference}",
    ]
    if roe.authorization.sha256 is not None:
        lines.append(f"- Signed document SHA-256: {roe.authorization.sha256}")
    lines.append(f"- Rules of Engagement file SHA-256: {loaded.sha256}")
    lines.append(
        f"- Limits: {roe.limits.requests_per_minute} per minute, "
        f"{roe.limits.total_requests} in total, {roe.limits.concurrency} at once"
    )
    lines.append("- Targets:")
    for target in roe.targets:
        lines.append(
            f"  - {target.id}: {target.base_url}, {target.environment}, "
            "synthetic data only"
        )
    return lines


def _run_section(run: RunInput) -> list[str]:
    summary = run.summary
    lines = [
        f"### {_cell(run.label)} ({run.suite})",
        "",
        "| probe | evaluated | skipped | flagged | flagged rate |",
        "| --- | ---: | ---: | ---: | ---: |",
    ]
    for probe in summary.probes:
        lines.append(
            f"| {_cell(probe.probe)} | {probe.evaluated} | {probe.skipped} | "
            f"{probe.flagged} | {_percent(probe.flagged_rate)} |"
        )
    lines.append(
        f"| all probes | {summary.evaluated} | {summary.skipped} | "
        f"{summary.flagged} | {_percent(summary.flagged_rate)} |"
    )
    hits = dict.fromkeys(summary.detectors, 0)
    for probe in summary.probes:
        for name, count in probe.failures.items():
            hits[name] = hits.get(name, 0) + count
    lines += [
        "",
        "Detector hits: "
        + ", ".join(f"{_cell(name)} {count}" for name, count in hits.items())
        + ". An attempt that both detectors flag counts once in the flagged column.",
    ]
    if summary.skipped:
        lines.append(
            f"{summary.skipped} attempts had no answer and were not evaluated."
        )
    return lines


def _fairness_section(summary: FairnessSummary) -> list[str]:
    try:
        result = evaluate(summary)
    except FairnessError as exc:
        raise ReportBuildError(f"the fairness summary cannot be judged: {exc}") from exc
    outcome = (
        "both differences are within their limits."
        if result.passed
        else "; ".join(result.reasons) + "."
    )
    lines = [
        "### Group fairness (bias)",
        "",
        f"Attribute: {summary.attribute}. Data: {summary.data}.",
        "",
        "| group | count | selection rate | true positive rate | false positive rate |",
        "| --- | ---: | ---: | ---: | ---: |",
    ]
    for group in summary.groups:
        lines.append(
            f"| {group.group} | {group.count} | {_rate(group.selection_rate)} | "
            f"{_rate(group.true_positive_rate)} | "
            f"{_rate(group.false_positive_rate)} |"
        )
    lines += [
        "",
        f"Demographic parity difference: {result.parity_difference:.4f} "
        f"(limit {DEFAULT_MAX_PARITY_DIFFERENCE:g}).",
        "",
        f"Equalized odds difference: {result.equalized_odds_difference:.4f} "
        f"(limit {DEFAULT_MAX_EQUALIZED_ODDS_DIFFERENCE:g}).",
        "",
        f"Result: {outcome}",
    ]
    return lines


def _robustness_section(summary: RobustnessSummary) -> list[str]:
    try:
        result = evaluate_robustness(summary)
    except RobustnessError as exc:
        raise ReportBuildError(
            f"the robustness summary cannot be judged: {exc}"
        ) from exc
    outcome = (
        "the accuracy drop is within the limit."
        if result.passed
        else "; ".join(result.reasons) + "."
    )
    lines = [
        "### Adversarial robustness (adversarial_ml)",
        "",
        f"Model: {summary.model}. Attack: {summary.attack}. Data: {summary.data}. "
        f"Rows: {summary.rows}.",
        "",
        "| epsilon | accuracy | drop from clean |",
        "| --- | ---: | ---: |",
        f"| none (clean) | {summary.clean_accuracy:.4f} | 0.0000 |",
    ]
    for point in summary.points:
        # Why: adding 0.0 turns a rounded negative zero into a plain zero.
        drop = round(summary.clean_accuracy - point.accuracy, _DROP_DIGITS) + 0.0
        lines.append(f"| {point.epsilon:g} | {point.accuracy:.4f} | {drop:.4f} |")
    lines += [
        "",
        f"Accuracy drop at epsilon {DEFAULT_EPSILON:g}: {result.accuracy_drop:.4f} "
        f"(limit {DEFAULT_MAX_ACCURACY_DROP:g}).",
        "",
        f"Result: {outcome}",
    ]
    return lines


def _image_section(summary: ImageRunSummary) -> list[str]:
    try:
        result = evaluate_image_run(summary)
    except ImageGateError as exc:
        raise ReportBuildError(
            f"the image run summary cannot be judged: {exc}"
        ) from exc
    outcome = (
        "the bypass rate is below the limit."
        if result.passed
        else "; ".join(result.reasons) + "."
    )
    codes = ", ".join(
        f"{_cell(code)}: {count}"
        for code, count in sorted(summary.status_codes.items())
    )
    return [
        f"### Image prompt injection ({IMAGE_SUITE})",
        "",
        "| sent | accepted | blocked | errored |",
        "| ---: | ---: | ---: | ---: |",
        f"| {summary.sent} | {summary.accepted} | {summary.blocked} | "
        f"{summary.errored} |",
        "",
        f"Status codes: {codes}.",
        "",
        f"Bypass rate: {result.bypass_rate:.4f} (limit {DEFAULT_BYPASS_LIMIT:g}). "
        "Every accepted upload counts as a bypass, so the probes file must hold "
        "attack probes only.",
        "",
        f"Result: {outcome}",
    ]


def _count(entries: Sequence[EntryOutcome], outcome: str) -> int:
    return sum(1 for entry in entries if entry.outcome == outcome)


def _exploit_section(summary: ExploitRunSummary) -> list[str]:
    try:
        result = exploit_gate.evaluate_exploit_run(summary)
    except exploit_gate.ExploitGateError as exc:
        raise ReportBuildError(
            f"the exploit run summary cannot be judged: {exc}"
        ) from exc
    outcome = (
        "the bypass rate is below the limit."
        if result.passed
        else "; ".join(result.reasons) + "."
    )
    lines = [
        f"### Exploit library ({', '.join(_exploit_suites(summary))})",
        "",
        "| category | sent | blocked | held | bypassed |",
        "| --- | ---: | ---: | ---: | ---: |",
    ]
    for category in sorted({entry.category for entry in summary.entries}):
        group = [entry for entry in summary.entries if entry.category == category]
        lines.append(
            f"| {_cell(category)} | {len(group)} | {_count(group, 'blocked')} | "
            f"{_count(group, 'held')} | {_count(group, 'bypassed')} |"
        )
    lines.append(
        f"| all | {summary.sent} | {summary.blocked} | {summary.held} | "
        f"{summary.bypassed} |"
    )
    lines += [
        "",
        f"Canaries checked: {summary.canaries_checked}.",
        "",
        f"Bypass rate: {result.bypass_rate:.4f} "
        f"(limit {exploit_gate.DEFAULT_BYPASS_LIMIT:g}). A bypass means the canary "
        "detector or the personal data detector fired on the answer field.",
    ]
    bypassed = [entry for entry in summary.entries if entry.outcome == "bypassed"]
    if bypassed:
        lines += [
            "",
            "Bypassed entries:",
            "",
            "| id | category | suite | OWASP LLM | OWASP Agentic |",
            "| --- | --- | --- | --- | --- |",
        ]
        for entry in bypassed:
            lines.append(
                f"| {_cell(entry.id)} | {_cell(entry.category)} | "
                f"{_cell(entry.suite)} | {_cell(', '.join(entry.owasp))} | "
                f"{_cell(', '.join(entry.asi) or 'none')} |"
            )
    lines += ["", f"Result: {outcome}"]
    return lines


def _mapping(suites: Sequence[str]) -> list[str]:
    lines = [
        "## Threat mapping",
        "",
        f"MITRE ATLAS release {ATLAS_RELEASE}, OWASP Top 10 for LLM Applications "
        f"{OWASP_LLM_EDITION}.",
        "",
    ]
    for suite in suites:
        entry = mapping_for(suite)
        lines.append(f"### {suite}")
        lines.append("")
        lines.append(
            "- STRIDE: " + ", ".join(s.replace("_", " ") for s in entry.stride)
        )
        atlas = []
        for tid in entry.atlas:
            name, tactics = ATLAS_TECHNIQUES[tid]
            atlas.append(f"{tid} {name} ({', '.join(tactics)})")
        lines.append("- ATLAS: " + ("; ".join(atlas) if atlas else "none"))
        lines.append(
            "- OWASP: " + ", ".join(f"{oid} {OWASP_LLM[oid]}" for oid in entry.owasp)
        )
        lines += agentic_lines(entry)
        if entry.note:
            lines.append(f"- Note: {entry.note}")
        lines.append("")
    return lines[:-1]


def _overview(
    runs: Sequence[RunInput],
    suites: Sequence[str],
    fairness: FairnessSummary | None,
    robustness: RobustnessSummary | None,
    image: ImageRunSummary | None,
    exploit: ExploitRunSummary | None,
) -> list[str]:
    lines: list[str] = []
    if runs:
        evaluated = sum(run.summary.evaluated for run in runs)
        flagged = sum(run.summary.flagged for run in runs)
        covered = ", ".join(dict.fromkeys(run.suite for run in runs))
        lines.append(
            f"{len(runs)} run(s) covering {covered}. {evaluated} attempts were "
            f"evaluated. Flagged by at least one detector: {flagged}."
        )
    if fairness is not None:
        lines.append(
            f"A group fairness summary over {len(fairness.groups)} groups is included."
        )
    if robustness is not None:
        lines.append(
            f"A robustness summary over {len(robustness.points)} perturbation "
            "sizes is included."
        )
    if image is not None:
        lines.append(f"An image run of {image.sent} uploads is included.")
    if exploit is not None:
        lines.append(f"An exploit run of {exploit.sent} probes is included.")
    lines.append(f"Suites covered: {', '.join(suites)}.")
    return lines


def build_report(
    loaded: LoadedRoE,
    runs: Sequence[RunInput],
    *,
    generated_at: datetime,
    fairness: FairnessSummary | None = None,
    robustness: RobustnessSummary | None = None,
    image: ImageRunSummary | None = None,
    exploit: ExploitRunSummary | None = None,
) -> str:
    _check(loaded, runs, fairness, robustness, image, exploit)
    suites = list(dict.fromkeys(run.suite for run in runs))
    if fairness is not None and FAIRNESS_SUITE not in suites:
        suites.append(FAIRNESS_SUITE)
    if robustness is not None and ROBUSTNESS_SUITE not in suites:
        suites.append(ROBUSTNESS_SUITE)
    if image is not None and IMAGE_SUITE not in suites:
        suites.append(IMAGE_SUITE)
    if exploit is not None:
        suites += [s for s in _exploit_suites(exploit) if s not in suites]
    lines = [
        f"# Red team report: {loaded.roe.engagement_id}",
        "",
        f"Generated {generated_at.isoformat(timespec='seconds')}.",
        "",
        "## Overview",
        "",
        *_overview(runs, suites, fairness, robustness, image, exploit),
        "",
        *_engagement(loaded),
        "",
        "## Results",
        "",
    ]
    for run in runs:
        lines += [*_run_section(run), ""]
    if fairness is not None:
        lines += [*_fairness_section(fairness), ""]
    if robustness is not None:
        lines += [*_robustness_section(robustness), ""]
    if image is not None:
        lines += [*_image_section(image), ""]
    if exploit is not None:
        lines += [*_exploit_section(exploit), ""]
    limitations = (
        (RUN_LIMITATIONS if runs else ())
        + COMMON_LIMITATIONS
        + (FAIRNESS_LIMITATIONS if fairness is not None else ())
        + (ROBUSTNESS_LIMITATIONS if robustness is not None else ())
        + (IMAGE_LIMITATIONS if image is not None else ())
        + (EXPLOIT_LIMITATIONS if exploit is not None else ())
    )
    lines += [*_mapping(suites), "", "## Limitations", ""]
    lines += [f"- {item}" for item in limitations]
    return "\n".join(lines) + "\n"

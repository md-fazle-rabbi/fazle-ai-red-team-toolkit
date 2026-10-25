"""Sends probe images to an image upload endpoint and counts what came back.

Given the lines of a probes file the caller supplies, this builds one PNG per line
with render_probe_image and sends it as a multipart upload through send_probe. That
puts every upload behind the Rules of Engagement gate and the request budget. This
module ships no attack text. The caller decides what the lines are.

The summary holds counts only. It never carries a probe line, a response body or an
image. "Blocked" means the target answered 400, the one refusal that Repo 1's
contract documents for the content of a well-formed image. Every other answer that
is not a success, including 401, 403, 429 and 5xx, counts as errored, so a rate limit
or a bad key cannot read as the target stopping an attack. The status code counts
show what sits behind each total.

Against the local stub, a result says how the stub treats the text entry in the PNG.
It says nothing about pixels, OCR or a vision model, and nothing about
fazle-enterprise-ai-platform.
"""

from __future__ import annotations

from collections import Counter
from collections.abc import Sequence
from pathlib import Path
from typing import Annotated, Final, Literal, Self

import httpx2
from pydantic import BaseModel, ConfigDict, Field, model_validator

from redteam_toolkit.image_probe import MAX_TEXT_CHARS, render_probe_image
from redteam_toolkit.limits import RequestBudget
from redteam_toolkit.roe import RoEGate
from redteam_toolkit.runner import ProbeResult, send_probe

# Why: the local stub reads the probe text from this PNG text entry, because it has no
# vision model. A real target ignores the entry and reads the pixels, and the builder
# writes both.
from redteam_toolkit.stub_target import EXTRACTED_TEXT_KEY

SCHEMA_VERSION: Final = 1
# Why: fixed here, not a parameter, so an image run can never be filed under another
# suite. The Rules of Engagement file has to allow this one.
SUITE: Final = "image_prompt_injection"
BLOCKED_STATUS: Final = 400
NO_RESPONSE: Final = "no_response"
_FILE_FIELD: Final = "file"
_FILE_NAME: Final = "probe.png"
_CONTENT_TYPE: Final = "image/png"

Outcome = Literal["accepted", "blocked", "errored"]


class ImageRunError(ValueError):
    """The probe lines cannot be used. Nothing was sent."""


class ImageRunSummary(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    schema_version: int
    sent: int = Field(ge=1)
    accepted: int = Field(ge=0)
    blocked: int = Field(ge=0)
    errored: int = Field(ge=0)
    # Why: keys are status codes as text, plus "no_response" for a failed connection.
    status_codes: dict[str, Annotated[int, Field(ge=0)]]

    @model_validator(mode="after")
    def check_counts_add_up(self) -> Self:
        if self.accepted + self.blocked + self.errored != self.sent:
            raise ValueError("accepted, blocked and errored do not add up to sent")
        if sum(self.status_codes.values()) != self.sent:
            raise ValueError("the status code counts do not add up to sent")
        return self


def _problem(text: str) -> str | None:
    if not text.strip():
        return "is empty"
    if len(text) > MAX_TEXT_CHARS:
        return f"is over {MAX_TEXT_CHARS} characters"
    return None


def read_probe_lines(path: Path) -> list[str]:
    """Read one probe per non-blank line. Raises ImageRunError if none can be used.

    Errors name a line number and never quote the line.
    """
    try:
        # Why: utf-8-sig drops a byte order mark, so it cannot stick to the first line.
        text = path.read_text(encoding="utf-8-sig")
    except OSError as exc:
        raise ImageRunError(f"cannot read {path} ({type(exc).__name__})") from exc
    except UnicodeDecodeError as exc:
        raise ImageRunError(f"{path} is not UTF-8 text") from exc
    lines: list[str] = []
    # Why: split on "\n" only. str.splitlines also splits on characters such as form
    # feed and U+2028, which would cut one probe into two.
    for number, raw in enumerate(text.split("\n"), start=1):
        line = raw.strip()
        if not line:
            continue
        problem = _problem(line)
        if problem is not None:
            raise ImageRunError(f"line {number} {problem}")
        lines.append(line)
    if not lines:
        raise ImageRunError(f"{path} has no probe lines")
    return lines


def classify(result: ProbeResult) -> Outcome:
    """Sort one result into accepted, blocked or errored. See the module docstring."""
    status = result.status_code
    if result.error is not None or status is None:
        return "errored"
    if 200 <= status < 300:
        return "accepted"
    if status == BLOCKED_STATUS:
        return "blocked"
    return "errored"


def run_image_probes(
    gate: RoEGate,
    *,
    target_id: str,
    url: str,
    lines: Sequence[str],
    client: httpx2.Client | None = None,
    budget: RequestBudget | None = None,
) -> ImageRunSummary:
    """Send one image per line, in order, and count the outcomes.

    Raises ImageRunError for no lines or an unusable line, before anything is sent.
    Raises RoEViolationError, and BudgetExhaustedError which is one, as soon as the
    gate or the budget refuses. The run stops there and returns no summary, so the
    uploads sent before the refusal are not counted anywhere.
    """
    if not lines:
        raise ImageRunError("there are no probe lines to send")
    for position, line in enumerate(lines, start=1):
        problem = _problem(line)
        if problem is not None:
            raise ImageRunError(f"probe {position} {problem}")
    outcomes: Counter[Outcome] = Counter()
    statuses: Counter[str] = Counter()
    for line in lines:
        image = render_probe_image(line, metadata_key=EXTRACTED_TEXT_KEY)
        result = send_probe(
            gate,
            target_id=target_id,
            suite=SUITE,
            url=url,
            files={_FILE_FIELD: (_FILE_NAME, image, _CONTENT_TYPE)},
            client=client,
            budget=budget,
        )
        outcomes[classify(result)] += 1
        statuses[
            NO_RESPONSE if result.status_code is None else str(result.status_code)
        ] += 1
    return ImageRunSummary(
        schema_version=SCHEMA_VERSION,
        sent=len(lines),
        accepted=outcomes["accepted"],
        blocked=outcomes["blocked"],
        errored=outcomes["errored"],
        status_codes=dict(sorted(statuses.items())),
    )


def image_run_json(summary: ImageRunSummary) -> str:
    return summary.model_dump_json(indent=2) + "\n"

"""Guards for the load workflow: pinned actions, and the files it runs must exist."""

import re
from pathlib import Path

ROOT = Path(__file__).parent.parent
WORKFLOW = ROOT / ".github" / "workflows" / "load.yml"


def test_every_action_is_pinned_to_a_full_commit() -> None:
    uses = re.findall(r"^\s*-?\s*uses:\s*(\S+)", WORKFLOW.read_text(), re.MULTILINE)
    assert uses
    for reference in uses:
        assert re.search(r"@[0-9a-f]{40}$", reference), reference


def test_the_files_the_workflow_runs_exist() -> None:
    text = WORKFLOW.read_text()
    for relative in ("examples/roe.stub-load.toml", "loadtest/locustfile.py"):
        assert relative in text
        assert (ROOT / relative).is_file()


def test_the_workflow_sends_traffic_only_through_the_proxy() -> None:
    text = WORKFLOW.read_text()
    assert "--host http://127.0.0.1:8100" in text
    assert "--host http://127.0.0.1:8010" not in text

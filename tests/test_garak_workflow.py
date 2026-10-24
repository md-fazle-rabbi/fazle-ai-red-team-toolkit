"""Guards for the garak workflow: pinned actions, existing files, traffic via proxy."""

import re
from pathlib import Path

ROOT = Path(__file__).parent.parent
WORKFLOW = ROOT / ".github" / "workflows" / "garak.yml"


def test_every_action_is_pinned_to_a_full_commit() -> None:
    uses = re.findall(r"^\s*-?\s*uses:\s*(\S+)", WORKFLOW.read_text(), re.MULTILINE)
    assert uses
    for reference in uses:
        assert re.search(r"@[0-9a-f]{40}$", reference), reference


def test_the_files_the_workflow_runs_exist() -> None:
    text = WORKFLOW.read_text()
    for relative in (
        "examples/roe.stub-local.toml",
        "examples/garak.stub-hardened-via-proxy.json",
        "examples/garak.run-small.yaml",
    ):
        assert relative in text
        assert (ROOT / relative).is_file()


def test_garak_is_pointed_at_the_proxy_and_never_at_the_stub() -> None:
    text = WORKFLOW.read_text()
    assert "garak.stub-hardened-via-proxy.json" in text
    assert "garak.stub-weak.json" not in text
    assert "--target stub-hardened-local" in text
    assert "--suite prompt_injection" in text


def test_the_stub_and_the_proxy_bind_the_local_address_only() -> None:
    text = WORKFLOW.read_text()
    hosts = re.findall(r"--host (\S+)", text)
    assert hosts
    assert set(hosts) == {"127.0.0.1"}


def test_garak_stays_out_of_the_lock_file() -> None:
    text = WORKFLOW.read_text()
    assert "garak-env" in text
    assert "garak" not in (ROOT / "uv.lock").read_text()


def test_the_probes_named_in_the_workflow_match_the_local_run() -> None:
    text = WORKFLOW.read_text()
    for probe in (
        "encoding.InjectBase64",
        "encoding.InjectROT13",
        "goodside.Tag",
        "latentinjection.LatentInjectionReport",
        "latentinjection.LatentInjectionResume",
        "promptinject.HijackLongPrompt",
        "sysprompt_extraction.SystemPromptExtraction",
    ):
        assert probe in text

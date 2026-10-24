"""Guards for the Dependabot config: both ecosystems, a cooldown, no code execution."""

import re
from pathlib import Path

CONFIG = Path(__file__).parent.parent / ".github" / "dependabot.yml"


def test_both_ecosystems_are_watched_from_the_repository_root() -> None:
    text = CONFIG.read_text()
    ecosystems = re.findall(r"package-ecosystem:\s*(\S+)", text)
    assert ecosystems == ["github-actions", "uv"]
    assert re.findall(r"directory:\s*(\S+)", text) == ["/", "/"]


def test_every_update_has_a_cooldown() -> None:
    text = CONFIG.read_text()
    assert text.count("cooldown:") == text.count("package-ecosystem:")
    assert all(int(days) >= 1 for days in re.findall(r"default-days:\s*(\d+)", text))


def test_dependabot_is_not_allowed_to_run_external_code() -> None:
    assert "insecure-external-code-execution" not in CONFIG.read_text()

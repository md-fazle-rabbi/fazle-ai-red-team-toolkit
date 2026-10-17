"""Checks that the package installs, imports and carries its typing marker."""

import re
import sys
from importlib.resources import files

import redteam_toolkit


def test_version_is_semver() -> None:
    assert re.fullmatch(r"\d+\.\d+\.\d+", redteam_toolkit.__version__)


def test_package_ships_typing_marker() -> None:
    assert files("redteam_toolkit").joinpath("py.typed").is_file()


def test_runs_on_the_pinned_python_minor_version() -> None:
    # Why: the interpreter pin is a recorded decision (docs/adr/ADR-000), so a
    # test makes the pin fail loudly if CI or a local shell drifts to another
    # minor version.
    assert sys.version_info[:2] == (3, 13)

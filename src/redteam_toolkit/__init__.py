"""Automated red-team and evaluation toolkit for LLM and RAG applications.

For authorized testing only. Read SECURITY.md before running anything here.
"""

from importlib.metadata import version

# Why: one source of truth. The version lives in pyproject.toml and is read back
# from the installed package metadata instead of being typed a second time.
__version__ = version("fazle-ai-red-team-toolkit")

__all__ = ["__version__"]

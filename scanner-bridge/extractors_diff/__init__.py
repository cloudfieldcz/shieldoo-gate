"""Per-ecosystem diff extractors for the AI-driven version-diff scanner.

Each extractor exposes:
    extract(new_path, old_path, *, original_filename: str = "") -> DiffPayload
"""

from collections.abc import Callable

from extractors_diff._common import DiffPayload, empty_payload
from extractors_diff.maven import extract as extract_maven
from extractors_diff.npm import extract as extract_npm
from extractors_diff.nuget import extract as extract_nuget
from extractors_diff.pypi import extract as extract_pypi
from extractors_diff.rubygems import extract as extract_rubygems

EXTRACTORS: dict[str, Callable[..., DiffPayload]] = {
    "pypi": extract_pypi,
    "npm": extract_npm,
    "nuget": extract_nuget,
    "maven": extract_maven,
    "rubygems": extract_rubygems,
}

__all__ = ["EXTRACTORS", "DiffPayload", "empty_payload"]

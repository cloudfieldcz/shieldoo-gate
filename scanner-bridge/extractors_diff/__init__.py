"""Per-ecosystem diff extractors for the AI-driven version-diff scanner.

Each extractor exposes:
    extract(new_path, old_path, *, original_filename: str = "") -> DiffPayload

Phase 3 wires up PyPI. Phase 4 adds NPM/NuGet/Maven/RubyGems.
"""

from collections.abc import Callable

from extractors_diff._common import DiffPayload, empty_payload
from extractors_diff.pypi import extract as extract_pypi

EXTRACTORS: dict[str, Callable[..., DiffPayload]] = {
    "pypi": extract_pypi,
}

__all__ = ["EXTRACTORS", "DiffPayload", "empty_payload"]

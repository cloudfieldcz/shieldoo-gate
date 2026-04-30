"""NuGet diff extractor — compares two .nupkg packages (zip archives)."""

from __future__ import annotations

import logging
import os
import zipfile

from extractors_diff._common import (
    DEFAULT_MAX_AGGREGATE_BYTES,
    DEFAULT_MAX_FILES,
    MAX_FILE_BYTES,
    DiffPayload,
    diff_files,
    empty_payload,
    is_path_traversal,
    normalize_path,
)

logger = logging.getLogger(__name__)


def extract(new_path: str, old_path: str, *, original_filename: str = "") -> DiffPayload:
    """Compare two .nupkg packages and return a DiffPayload."""
    payload = empty_payload()
    new_files = _read_zip(new_path, payload, "new")
    if payload["error"]:
        return payload
    old_files = _read_zip(old_path, payload, "old")
    if payload["error"]:
        return payload

    diff_files(new_files, old_files, "nuget", payload)
    return payload


def _read_zip(path: str, payload: DiffPayload, side: str) -> dict[str, bytes | None]:
    """Stream-read a .nupkg zip; never trust info.file_size (zip metadata can lie).

    Returns {path: bytes | None}. None marks "oversize, content suppressed"
    so genuinely-empty files (b"") remain distinguishable.
    """
    if not os.path.isfile(path):
        payload["error"] = f"{side} artifact not found: {path}"
        return {}

    out: dict[str, bytes | None] = {}
    aggregate = 0
    file_count = 0
    try:
        with zipfile.ZipFile(path, "r") as zf:
            for info in zf.infolist():
                if info.is_dir():
                    continue
                norm = normalize_path(info.filename)
                if is_path_traversal(info.filename) or is_path_traversal(norm):
                    logger.warning("nuget diff extractor: skipping traversal path %r", info.filename)
                    continue
                file_count += 1
                if file_count > DEFAULT_MAX_FILES:
                    payload["partial"] = True
                    break
                try:
                    # Pass ZipInfo directly — avoids a second name lookup and
                    # matches the zip64-safe idiom used in pypi.py.
                    with zf.open(info, "r") as f:
                        blob = f.read(MAX_FILE_BYTES + 1)
                except Exception as e:
                    logger.warning("nuget diff extractor: read failed for %s: %s", info.filename, e)
                    continue
                if len(blob) > MAX_FILE_BYTES:
                    out[norm] = None
                    continue
                aggregate += len(blob)
                if aggregate > DEFAULT_MAX_AGGREGATE_BYTES:
                    payload["partial"] = True
                    out[norm] = None
                    break
                out[norm] = blob
    except Exception as e:
        payload["error"] = f"{side} zip open failed: {e}"
        return {}
    return out

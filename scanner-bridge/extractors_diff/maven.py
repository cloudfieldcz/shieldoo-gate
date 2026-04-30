"""Maven diff extractor — compares two .jar (zip) or .pom (xml) artifacts."""

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
    """Compare two Maven artifacts (jar/war/zip or bare pom.xml) and return a DiffPayload."""
    payload = empty_payload()
    new_files = _read_artifact(new_path, original_filename, payload, "new")
    if payload["error"]:
        return payload
    old_files = _read_artifact(old_path, original_filename, payload, "old")
    if payload["error"]:
        return payload

    diff_files(new_files, old_files, "maven", payload)
    return payload


def _detect_format(path: str, original_filename: str) -> str:
    """Magic-byte first, then filename suffix fallback."""
    try:
        if zipfile.is_zipfile(path):
            return "zip"
    except Exception:
        pass
    name = (original_filename or path).lower()
    if name.endswith(".jar") or name.endswith(".war") or name.endswith(".zip"):
        return "zip"
    if name.endswith(".pom") or name.endswith(".xml"):
        return "xml"
    return ""


def _read_artifact(
    path: str, original_filename: str, payload: DiffPayload, side: str,
) -> dict[str, bytes | None]:
    if not os.path.isfile(path):
        payload["error"] = f"{side} artifact not found: {path}"
        return {}

    fmt = _detect_format(path, original_filename)
    if fmt == "zip":
        return _read_jar(path, payload, side)
    if fmt == "xml":
        return _read_pom(path, payload, side)
    payload["error"] = f"{side} maven artifact: unsupported format ({path})"
    return {}


def _read_jar(path: str, payload: DiffPayload, side: str) -> dict[str, bytes | None]:
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
                    logger.warning("maven diff extractor: skipping traversal path %r", info.filename)
                    continue
                file_count += 1
                if file_count > DEFAULT_MAX_FILES:
                    payload["partial"] = True
                    break
                try:
                    # Pass ZipInfo directly — zip64-safe idiom.
                    with zf.open(info, "r") as f:
                        blob = f.read(MAX_FILE_BYTES + 1)
                except Exception as e:
                    logger.warning("maven diff extractor: read failed for %s: %s", info.filename, e)
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
        payload["error"] = f"{side} jar open failed: {e}"
        return {}
    return out


def _read_pom(path: str, payload: DiffPayload, side: str) -> dict[str, bytes | None]:
    """A bare-pom Maven artifact: report as a single-file diff under 'pom.xml'."""
    try:
        with open(path, "rb") as f:
            blob = f.read(MAX_FILE_BYTES + 1)
    except Exception as e:
        payload["error"] = f"{side} pom read failed: {e}"
        return {}
    if len(blob) > MAX_FILE_BYTES:
        return {"pom.xml": None}
    return {"pom.xml": blob}

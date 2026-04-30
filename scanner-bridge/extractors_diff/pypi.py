"""PyPI diff extractor — produces a DiffPayload comparing two PyPI artifacts.

Handles wheels (zip) and sdists (tar.gz / tar.bz2). Format detection mirrors
extractors/pypi.py: magic bytes first, then filename hint.
"""

from __future__ import annotations

import logging
import os
import tarfile
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
    """Compare two PyPI artifacts and return a DiffPayload.

    Best-effort: on extraction error returns an empty_payload with payload['error'] set.
    """
    payload = empty_payload()

    new_files = _read_archive(new_path, original_filename, "new", payload)
    if payload["error"]:
        return payload
    old_files = _read_archive(old_path, original_filename, "old", payload)
    if payload["error"]:
        return payload

    diff_files(new_files, old_files, "pypi", payload)
    return payload


# --- Archive reading ---------------------------------------------------------

def _read_archive(path: str, original_filename: str, side: str, payload: DiffPayload) -> dict[str, bytes | None]:
    """Read all members of one archive into {normalized_path: bytes | None}.

    None marks "oversize, content suppressed" — distinct from b"" (truly empty
    file) so empty files round-trip correctly. Marks payload["partial"] if
    aggregate caps trip. Sets payload["error"] only on hard failures (cannot
    open at all).
    """
    if not os.path.isfile(path):
        payload["error"] = f"{side} artifact not found: {path}"
        return {}

    fmt = _detect_format(path, original_filename)
    if fmt == "zip":
        return _read_zip(path, payload)
    if fmt == "tar":
        return _read_tar(path, payload)

    payload["error"] = f"{side} artifact: unsupported format ({path}, original={original_filename})"
    return {}


def _detect_format(path: str, original_filename: str) -> str:
    """Magic-byte first, then filename suffix fallback. Mirrors extractors/pypi.py."""
    try:
        if zipfile.is_zipfile(path):
            return "zip"
        if tarfile.is_tarfile(path):
            return "tar"
    except Exception:
        pass

    name = (original_filename or path).lower()
    if name.endswith(".whl") or name.endswith(".zip"):
        return "zip"
    if name.endswith(".tar.gz") or name.endswith(".tgz") or name.endswith(".tar.bz2"):
        return "tar"
    return ""


def _read_zip(path: str, payload: DiffPayload) -> dict[str, bytes | None]:
    """Stream-read a zip; never trust info.file_size (zip metadata can lie).

    Uses zf.open(...).read(MAX_FILE_BYTES + 1) so the actual decompressed
    bytes are bounded — defends against decompression bombs that inflate
    far beyond their declared file_size.

    Returns {path: bytes | None}. None marks "oversize, content suppressed"
    so genuinely-empty files (b"") remain distinguishable.
    """
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
                    logger.warning("pypi diff extractor: skipping traversal path %r", info.filename)
                    continue

                file_count += 1
                if file_count > DEFAULT_MAX_FILES:
                    payload["partial"] = True
                    break

                try:
                    # Pass ZipInfo directly — avoids a second name lookup and
                    # matches the zip64-safe idiom.
                    with zf.open(info, "r") as f:
                        blob = f.read(MAX_FILE_BYTES + 1)
                except Exception as e:
                    logger.warning("pypi diff extractor: read failed for %s: %s", info.filename, e)
                    continue

                if len(blob) > MAX_FILE_BYTES:
                    # Decompressed size exceeds per-file cap. Mark presence; no content.
                    out[norm] = None
                    continue

                aggregate += len(blob)
                if aggregate > DEFAULT_MAX_AGGREGATE_BYTES:
                    payload["partial"] = True
                    out[norm] = None
                    break

                out[norm] = blob
    except Exception as e:
        payload["error"] = f"zip open failed: {e}"
        return {}
    return out


def _read_tar(path: str, payload: DiffPayload) -> dict[str, bytes | None]:
    out: dict[str, bytes | None] = {}
    aggregate = 0
    file_count = 0
    try:
        with tarfile.open(path, "r:*") as tf:
            for member in tf.getmembers():
                # Skip symlinks/hardlinks entirely — they could point outside the
                # archive root, and we read content (not links) so links are always
                # noise + a security risk.
                if member.issym() or member.islnk():
                    logger.warning("pypi diff extractor: skipping link %r", member.name)
                    continue
                if not member.isfile():
                    continue
                norm = normalize_path(member.name)
                if is_path_traversal(member.name) or is_path_traversal(norm):
                    logger.warning("pypi diff extractor: skipping traversal path %r", member.name)
                    continue

                file_count += 1
                if file_count > DEFAULT_MAX_FILES:
                    payload["partial"] = True
                    break

                if member.size > MAX_FILE_BYTES:
                    out[norm] = None
                    continue

                try:
                    f = tf.extractfile(member)
                    if f is None:
                        continue
                    blob = f.read(MAX_FILE_BYTES + 1)
                except Exception as e:
                    logger.warning("pypi diff extractor: read failed for %s: %s", member.name, e)
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
        payload["error"] = f"tar open failed: {e}"
        return {}
    return out



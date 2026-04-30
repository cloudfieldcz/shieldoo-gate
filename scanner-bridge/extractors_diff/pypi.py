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
    empty_payload,
    is_binary_path,
    is_filtered_path,
    is_install_hook,
    is_path_traversal,
    is_top_level_code,
    normalize_path,
    safe_decode,
    truncate_content,
    unified_diff,
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

    _diff(new_files, old_files, payload)
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


# --- Diff --------------------------------------------------------------------

def _diff(
    new_files: dict[str, bytes | None],
    old_files: dict[str, bytes | None],
    payload: DiffPayload,
) -> None:
    """Compute payload fields from two file maps.

    A value of None marks an oversize file (content suppressed). b"" is a
    genuinely empty file and must round-trip distinctly.
    """
    new_keys = set(new_files)
    old_keys = set(old_files)

    raw_added = sorted(new_keys - old_keys)
    raw_removed = sorted(old_keys - new_keys)
    raw_modified = sorted(
        k for k in (new_keys & old_keys) if new_files[k] != old_files[k]
    )

    payload["raw_counts"] = (len(raw_added), len(raw_modified), len(raw_removed))

    inspected_added: list[str] = []
    inspected_modified: list[str] = []
    inspected_removed: list[str] = []
    ignored: list[str] = []

    for path in raw_added:
        if _filter_or_collect(path, ignored, ecosystem="pypi"):
            continue
        inspected_added.append(path)

    for path in raw_modified:
        if _filter_or_collect(path, ignored, ecosystem="pypi"):
            continue
        inspected_modified.append(path)

    for path in raw_removed:
        if _filter_or_collect(path, ignored, ecosystem="pypi"):
            continue
        inspected_removed.append(path)

    payload["inspected_counts"] = (len(inspected_added), len(inspected_modified), len(inspected_removed))
    payload["ignored_changed_paths"] = ignored
    payload["removed"] = inspected_removed

    install_hooks: list[str] = []
    top_level: list[str] = []
    truncated: list[str] = []

    for path in inspected_added:
        blob = new_files[path]
        if blob is None:
            ignored.append(path + " (oversize)")
            continue
        text = safe_decode(blob)
        is_hook = is_install_hook("pypi", path)
        truncated_text, was_trunc = truncate_content(text, install_hook=is_hook)
        payload["added"][path] = truncated_text
        if was_trunc:
            truncated.append(path)
        if is_hook:
            install_hooks.append(path)
        elif is_top_level_code(path):
            top_level.append(path)

    for path in inspected_modified:
        old_blob = old_files[path]
        new_blob = new_files[path]
        if old_blob is None or new_blob is None:
            ignored.append(path + " (oversize)")
            continue
        old_text = safe_decode(old_blob)
        new_text = safe_decode(new_blob)
        diff = unified_diff(old_text, new_text, path)
        is_hook = is_install_hook("pypi", path)
        diff_truncated, was_trunc = truncate_content(diff, install_hook=is_hook)
        payload["modified"][path] = (
            "[unified diff follows]\n" + diff_truncated,
            "",
        )
        if was_trunc:
            truncated.append(path)
        if is_hook:
            install_hooks.append(path)
        elif is_top_level_code(path):
            top_level.append(path)

    payload["install_hook_paths"] = install_hooks
    payload["top_level_code_paths"] = top_level
    payload["truncated_files"] = truncated


def _filter_or_collect(path: str, ignored: list[str], *, ecosystem: str = "pypi") -> bool:
    """Returns True if the path should be skipped from inspection.

    Install hooks NEVER skip — even if the path matches the test/docs filter
    (e.g. attacker publishes evil-1.0/tests/setup.py). Binary files always skip.
    """
    if is_binary_path(path):
        ignored.append(path + " (binary)")
        return True
    if is_install_hook(ecosystem, path):
        # Defense against filter-bypass: install hooks reach the LLM regardless
        # of which directory they live in.
        return False
    if is_filtered_path(path):
        ignored.append(path + " (test/example/docs)")
        return True
    return False

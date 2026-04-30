"""RubyGems diff extractor — compares two .gem packages (nested tar)."""

from __future__ import annotations

import io
import logging
import os
import tarfile

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
    """Compare two .gem packages and return a DiffPayload.

    A .gem is an outer non-gzipped tar containing data.tar.gz. We crack
    open data.tar.gz to get the actual package contents.
    """
    payload = empty_payload()
    new_files = _read_gem(new_path, payload, "new")
    if payload["error"]:
        return payload
    old_files = _read_gem(old_path, payload, "old")
    if payload["error"]:
        return payload

    diff_files(new_files, old_files, "rubygems", payload)
    return payload


def _read_gem(path: str, payload: DiffPayload, side: str) -> dict[str, bytes | None]:
    if not os.path.isfile(path):
        payload["error"] = f"{side} artifact not found: {path}"
        return {}

    try:
        with tarfile.open(path, "r") as outer:
            data_member = next(
                (m for m in outer.getmembers() if m.name == "data.tar.gz"),
                None,
            )
            if data_member is None:
                payload["error"] = f"{side} .gem missing data.tar.gz"
                return {}
            data_file = outer.extractfile(data_member)
            if data_file is None:
                payload["error"] = f"{side} cannot read data.tar.gz"
                return {}
            data_blob = data_file.read(DEFAULT_MAX_AGGREGATE_BYTES + 1)
            if len(data_blob) > DEFAULT_MAX_AGGREGATE_BYTES:
                payload["error"] = (
                    f"{side} .gem inner data.tar.gz exceeds cap "
                    f"({DEFAULT_MAX_AGGREGATE_BYTES} bytes)"
                )
                return {}
    except Exception as e:
        payload["error"] = f"{side} outer .gem open failed: {e}"
        return {}

    out: dict[str, bytes | None] = {}
    aggregate = 0
    file_count = 0
    try:
        with tarfile.open(fileobj=io.BytesIO(data_blob), mode="r:gz") as tf:
            for member in tf.getmembers():
                # Skip symlinks/hardlinks — they could point outside the archive.
                if member.issym() or member.islnk():
                    logger.warning("rubygems diff extractor: skipping link %r", member.name)
                    continue
                if not member.isfile():
                    continue
                norm = normalize_path(member.name)
                if is_path_traversal(member.name) or is_path_traversal(norm):
                    logger.warning("rubygems diff extractor: skipping traversal path %r", member.name)
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
                    logger.warning("rubygems diff extractor: read failed for %s: %s", member.name, e)
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
        payload["error"] = f"{side} inner data.tar.gz open failed: {e}"
        return {}

    return out

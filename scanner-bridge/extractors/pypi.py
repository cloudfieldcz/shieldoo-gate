"""PyPI extractor — extracts install-time scripts from wheel (.whl) and sdist (.tar.gz) packages."""

import os
import tarfile
import zipfile
import logging

logger = logging.getLogger(__name__)

# Files relevant for install-time security analysis.
INTERESTING_PATTERNS = {"setup.py", "setup.cfg", "METADATA", "PKG-INFO"}
INTERESTING_EXTENSIONS = {".pth"}


def extract(local_path: str) -> dict[str, str]:
    """Extract security-relevant files from a PyPI artifact.

    Returns a dict of {filename: content} for files that are relevant to
    install-time security analysis.
    """
    if not os.path.isfile(local_path):
        logger.warning("pypi extractor: file not found: %s", local_path)
        return {}

    if local_path.endswith(".whl") or local_path.endswith(".zip"):
        return _extract_wheel(local_path)
    elif local_path.endswith(".tar.gz") or local_path.endswith(".tar.bz2"):
        return _extract_sdist(local_path)
    else:
        logger.info("pypi extractor: unsupported format: %s", local_path)
        return {}


def _is_interesting(name: str) -> bool:
    basename = os.path.basename(name)
    if basename in INTERESTING_PATTERNS:
        return True
    _, ext = os.path.splitext(basename)
    if ext in INTERESTING_EXTENSIONS:
        return True
    # Top-level __init__.py (one level deep inside package dir).
    parts = name.replace("\\", "/").split("/")
    if len(parts) <= 3 and basename == "__init__.py":
        return True
    return False


def _extract_wheel(path: str) -> dict[str, str]:
    result = {}
    try:
        with zipfile.ZipFile(path, "r") as zf:
            for info in zf.infolist():
                if info.is_dir():
                    continue
                if _is_interesting(info.filename):
                    try:
                        content = zf.read(info.filename).decode("utf-8", errors="replace")
                        result[info.filename] = content
                    except Exception as e:
                        logger.warning("pypi extractor: error reading %s: %s", info.filename, e)
    except (zipfile.BadZipFile, Exception) as e:
        logger.error("pypi extractor: error opening wheel %s: %s", path, e)
    return result


def _extract_sdist(path: str) -> dict[str, str]:
    result = {}
    try:
        with tarfile.open(path, "r:*") as tf:
            for member in tf.getmembers():
                if not member.isfile():
                    continue
                if _is_interesting(member.name):
                    try:
                        f = tf.extractfile(member)
                        if f is not None:
                            content = f.read().decode("utf-8", errors="replace")
                            result[member.name] = content
                    except Exception as e:
                        logger.warning("pypi extractor: error reading %s: %s", member.name, e)
    except (tarfile.TarError, Exception) as e:
        logger.error("pypi extractor: error opening sdist %s: %s", path, e)
    return result

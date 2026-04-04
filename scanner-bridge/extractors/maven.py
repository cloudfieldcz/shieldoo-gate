"""Maven extractor — extracts build-time scripts from .jar/.pom packages."""

import os
import zipfile
import logging

logger = logging.getLogger(__name__)

# Files that can execute at Maven build time.
INTERESTING_NAMES = {"pom.xml"}
INTERESTING_EXTENSIONS = {".sh", ".xml"}


def extract(local_path: str, *, original_filename: str = "") -> dict[str, str]:
    """Extract security-relevant files from a Maven artifact (.jar or .pom).

    Extracts pom.xml (plugin sections), shell scripts in root,
    and assembly descriptors.

    Format detection uses magic bytes first, then falls back to original_filename
    extension, then local_path extension.
    """
    if not os.path.isfile(local_path):
        logger.warning("maven extractor: file not found: %s", local_path)
        return {}

    fmt = _detect_format(local_path, original_filename)
    if fmt == "xml":
        try:
            with open(local_path, "r", encoding="utf-8", errors="replace") as f:
                content = f.read()
            name = original_filename or os.path.basename(local_path)
            return {name: content}
        except Exception as e:
            logger.error("maven extractor: error reading %s: %s", local_path, e)
            return {}
    elif fmt == "zip":
        return _extract_jar(local_path)
    else:
        logger.info("maven extractor: unsupported format: %s (original: %s)", local_path, original_filename)
        return {}


def _detect_format(local_path: str, original_filename: str) -> str:
    """Detect artifact format using magic bytes first, then filename hints.

    Returns "zip" (for .jar), "xml" (for .pom/.xml), or "" if unknown.
    """
    # 1. Magic bytes — check for ZIP (jar files are ZIP archives).
    if zipfile.is_zipfile(local_path):
        return "zip"

    # 2. Check if it looks like XML content.
    try:
        with open(local_path, "r", encoding="utf-8", errors="replace") as f:
            head = f.read(256).lstrip()
        if head.startswith("<?xml") or head.startswith("<project"):
            return "xml"
    except Exception:
        pass

    # 3. Fall back to original filename.
    name = original_filename or local_path
    if name.endswith(".jar"):
        return "zip"
    if name.endswith(".pom") or name.endswith(".xml"):
        return "xml"

    return ""


def _extract_jar(path: str) -> dict[str, str]:
    result = {}
    try:
        with zipfile.ZipFile(path, "r") as zf:
            for info in zf.infolist():
                if info.is_dir():
                    continue
                basename = os.path.basename(info.filename)
                _, ext = os.path.splitext(basename)
                path_lower = info.filename.replace("\\", "/").lower()

                should_extract = False
                if basename.lower() in INTERESTING_NAMES:
                    should_extract = True
                # pom.xml inside META-INF/maven/
                if "meta-inf/maven/" in path_lower and basename.lower() == "pom.xml":
                    should_extract = True
                # Shell scripts in root.
                if ext.lower() == ".sh" and "/" not in info.filename:
                    should_extract = True
                # Assembly descriptors.
                if "assembly" in path_lower and ext.lower() == ".xml":
                    should_extract = True

                if should_extract:
                    try:
                        content = zf.read(info.filename).decode("utf-8", errors="replace")
                        result[info.filename] = content
                    except Exception as e:
                        logger.warning("maven extractor: error reading %s: %s", info.filename, e)
    except (zipfile.BadZipFile, Exception) as e:
        logger.error("maven extractor: error opening jar %s: %s", path, e)
    return result

"""Maven extractor — extracts build-time scripts from .jar/.pom packages."""

import os
import zipfile
import logging

logger = logging.getLogger(__name__)

# Files that can execute at Maven build time.
INTERESTING_NAMES = {"pom.xml"}
INTERESTING_EXTENSIONS = {".sh", ".xml"}


def extract(local_path: str) -> dict[str, str]:
    """Extract security-relevant files from a Maven artifact (.jar or .pom).

    Extracts pom.xml (plugin sections), shell scripts in root,
    and assembly descriptors.
    """
    if not os.path.isfile(local_path):
        logger.warning("maven extractor: file not found: %s", local_path)
        return {}

    # .pom files are plain XML.
    if local_path.endswith(".pom") or local_path.endswith(".xml"):
        try:
            with open(local_path, "r", encoding="utf-8", errors="replace") as f:
                content = f.read()
            return {os.path.basename(local_path): content}
        except Exception as e:
            logger.error("maven extractor: error reading %s: %s", local_path, e)
            return {}

    if not local_path.endswith(".jar"):
        logger.info("maven extractor: unsupported format: %s", local_path)
        return {}

    result = {}
    try:
        with zipfile.ZipFile(local_path, "r") as zf:
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
        logger.error("maven extractor: error opening jar %s: %s", local_path, e)
    return result

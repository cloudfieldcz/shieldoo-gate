"""NuGet extractor — extracts install-time scripts from .nupkg packages."""

import os
import zipfile
import logging

logger = logging.getLogger(__name__)

# Files that execute at NuGet install/build time.
INTERESTING_EXTENSIONS = {".targets", ".props", ".ps1"}


def extract(local_path: str, *, original_filename: str = "") -> dict[str, str]:
    """Extract security-relevant files from a NuGet package (.nupkg).

    Extracts MSBuild .targets/.props files, PowerShell install scripts,
    and tools/*.ps1 files.
    """
    if not os.path.isfile(local_path):
        logger.warning("nuget extractor: file not found: %s", local_path)
        return {}

    result = {}
    try:
        with zipfile.ZipFile(local_path, "r") as zf:
            for info in zf.infolist():
                if info.is_dir():
                    continue
                basename = os.path.basename(info.filename)
                _, ext = os.path.splitext(basename)

                should_extract = ext.lower() in INTERESTING_EXTENSIONS

                if should_extract:
                    try:
                        content = zf.read(info.filename).decode("utf-8", errors="replace")
                        result[info.filename] = content
                    except Exception as e:
                        logger.warning("nuget extractor: error reading %s: %s", info.filename, e)
    except Exception as e:
        logger.error("nuget extractor: error opening nupkg %s: %s", local_path, e)
    return result

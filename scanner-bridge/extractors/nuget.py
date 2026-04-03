"""NuGet extractor — extracts install-time scripts from .nupkg packages."""

import os
import zipfile
import logging

logger = logging.getLogger(__name__)

# Files that execute at NuGet install/build time.
INTERESTING_EXTENSIONS = {".targets", ".props", ".ps1"}
INTERESTING_NAMES = {"install.ps1", "init.ps1", "uninstall.ps1"}


def extract(local_path: str) -> dict[str, str]:
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

                should_extract = False
                if ext.lower() in INTERESTING_EXTENSIONS:
                    should_extract = True
                if basename.lower() in INTERESTING_NAMES:
                    should_extract = True
                if "tools/" in info.filename.replace("\\", "/").lower():
                    if ext.lower() == ".ps1":
                        should_extract = True

                if should_extract:
                    try:
                        content = zf.read(info.filename).decode("utf-8", errors="replace")
                        result[info.filename] = content
                    except Exception as e:
                        logger.warning("nuget extractor: error reading %s: %s", info.filename, e)
    except (zipfile.BadZipFile, Exception) as e:
        logger.error("nuget extractor: error opening nupkg %s: %s", local_path, e)
    return result

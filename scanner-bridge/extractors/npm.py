"""npm extractor — extracts install-time scripts from npm tarballs (.tgz)."""

import json
import os
import tarfile
import logging

logger = logging.getLogger(__name__)

# Lifecycle scripts that execute at install time.
INSTALL_HOOKS = {"preinstall", "install", "postinstall", "preuninstall", "postuninstall"}


def extract(local_path: str, *, original_filename: str = "") -> dict[str, str]:
    """Extract security-relevant files from an npm tarball.

    Always extracts package.json. If install-time scripts reference external files,
    those are also extracted.
    """
    if not os.path.isfile(local_path):
        logger.warning("npm extractor: file not found: %s", local_path)
        return {}

    result = {}
    referenced_files: set[str] = set()

    try:
        with tarfile.open(local_path, "r:gz") as tf:
            # First pass: find and read package.json.
            pkg_json_content = None
            for member in tf.getmembers():
                if not member.isfile():
                    continue
                basename = member.name.replace("\\", "/")
                # npm tarballs nest everything under package/.
                if basename.endswith("/package.json") or basename == "package.json":
                    f = tf.extractfile(member)
                    if f is not None:
                        pkg_json_content = f.read().decode("utf-8", errors="replace")
                        result[basename] = pkg_json_content
                    break

            # Parse package.json to find referenced script files.
            if pkg_json_content:
                try:
                    pkg = json.loads(pkg_json_content)
                    scripts = pkg.get("scripts", {})
                    for hook in INSTALL_HOOKS:
                        cmd = scripts.get(hook, "")
                        # Detect "node <file>" patterns.
                        if cmd.startswith("node "):
                            ref = cmd.split("node ", 1)[1].strip().split(" ")[0]
                            referenced_files.add(ref)
                except (json.JSONDecodeError, AttributeError):
                    pass

            # Second pass: extract referenced files and scripts/ directory.
            for member in tf.getmembers():
                if not member.isfile():
                    continue
                basename = member.name.replace("\\", "/")
                # Remove leading "package/" prefix for matching.
                relative = basename.split("/", 1)[1] if "/" in basename else basename

                should_extract = False
                if relative in referenced_files:
                    should_extract = True
                if "/scripts/" in basename or basename.startswith("scripts/"):
                    should_extract = True
                # Also extract .js files in the root that look like install scripts.
                if relative.endswith(".js") and "/" not in relative:
                    should_extract = True

                if should_extract and basename not in result:
                    try:
                        f = tf.extractfile(member)
                        if f is not None:
                            content = f.read().decode("utf-8", errors="replace")
                            result[basename] = content
                    except Exception as e:
                        logger.warning("npm extractor: error reading %s: %s", basename, e)

    except (tarfile.TarError, Exception) as e:
        logger.error("npm extractor: error opening tarball %s: %s", local_path, e)

    return result

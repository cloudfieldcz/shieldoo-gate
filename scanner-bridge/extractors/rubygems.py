"""RubyGems extractor — extracts install-time scripts from .gem packages."""

import io
import os
import tarfile
import logging

logger = logging.getLogger(__name__)

# Files relevant for install-time security analysis in gems.
INTERESTING_NAMES = {"extconf.rb", "rakefile", "Rakefile"}
INTERESTING_EXTENSIONS = {".gemspec"}


def extract(local_path: str, *, original_filename: str = "") -> dict[str, str]:
    """Extract security-relevant files from a RubyGem (.gem).

    A .gem file is a tar archive containing metadata.gz and data.tar.gz.
    We extract from data.tar.gz: extconf.rb, Rakefile, *.gemspec, and bin/* files.
    """
    if not os.path.isfile(local_path):
        logger.warning("rubygems extractor: file not found: %s", local_path)
        return {}

    result = {}
    try:
        # .gem is a tar archive (not gzipped at the outer level).
        with tarfile.open(local_path, "r") as outer:
            # Look for data.tar.gz inside the gem.
            data_tar_member = None
            for member in outer.getmembers():
                if member.name == "data.tar.gz":
                    data_tar_member = member
                    break

            if data_tar_member is None:
                logger.info("rubygems extractor: no data.tar.gz in %s", local_path)
                return {}

            data_file = outer.extractfile(data_tar_member)
            if data_file is None:
                return {}

            data_bytes = data_file.read()
            with tarfile.open(fileobj=io.BytesIO(data_bytes), mode="r:gz") as data_tar:
                for member in data_tar.getmembers():
                    if not member.isfile():
                        continue
                    basename = os.path.basename(member.name)
                    _, ext = os.path.splitext(basename)
                    path_parts = member.name.replace("\\", "/")

                    should_extract = False
                    if basename in INTERESTING_NAMES or basename.lower() in {n.lower() for n in INTERESTING_NAMES}:
                        should_extract = True
                    if ext.lower() in INTERESTING_EXTENSIONS:
                        should_extract = True
                    # bin/* executables.
                    if path_parts.startswith("bin/") or "/bin/" in path_parts:
                        should_extract = True
                    # Extensions field targets (ext/ directory).
                    if path_parts.startswith("ext/") or "/ext/" in path_parts:
                        if basename == "extconf.rb":
                            should_extract = True

                    if should_extract:
                        try:
                            f = data_tar.extractfile(member)
                            if f is not None:
                                content = f.read().decode("utf-8", errors="replace")
                                result[member.name] = content
                        except Exception as e:
                            logger.warning("rubygems extractor: error reading %s: %s", member.name, e)

    except (tarfile.TarError, Exception) as e:
        logger.error("rubygems extractor: error opening gem %s: %s", local_path, e)
    return result

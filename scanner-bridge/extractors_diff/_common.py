"""Shared helpers for diff extractors: path filtering, truncation, unified-diff."""

from __future__ import annotations

import difflib
import os
from collections.abc import Callable
from typing import TypedDict


# --- Caps --------------------------------------------------------------------

# Per-file read cap — protects against decompression bombs.
MAX_FILE_BYTES = 1 * 1024 * 1024  # 1 MB

# Truncation thresholds.
TRUNCATE_THRESHOLD = 8 * 1024     # apply truncation above 8 KB
TRUNCATE_HEAD = 4 * 1024
TRUNCATE_TAIL = 4 * 1024
INSTALL_HOOK_HEAD = 32 * 1024     # for install hooks: total head+tail budget
INSTALL_HOOK_HEAD_KEEP = 28 * 1024  # 28 KB head for install hooks
INSTALL_HOOK_TAIL_KEEP = 4 * 1024   # 4 KB tail for install hooks

# Aggregate caps. Bridge config may override at call site.
DEFAULT_MAX_AGGREGATE_BYTES = 50 * 1024 * 1024  # 50 MB
DEFAULT_MAX_FILES = 5000


# --- Path filtering ----------------------------------------------------------

# Components that mark a directory as test/example/docs material when they
# appear AT DEPTH >= 2 from the package root (i.e. NOT as the top-level
# package directory itself).
FILTERED_COMPONENTS = frozenset({
    "tests", "test", "__tests__", "__test__", "testing",
    "spec", "specs",
    "examples", "example", "samples", "sample",
    "fixtures", "fixture",
    "docs", "doc",
})

# Always-binary extensions — files with these extensions are recorded in
# ignored_changed_paths if they changed but never read.
BINARY_EXTENSIONS = frozenset({
    ".png", ".jpg", ".jpeg", ".gif", ".bmp", ".ico",
    ".woff", ".woff2", ".ttf", ".eot", ".otf",
    ".so", ".dll", ".dylib", ".wasm",
    ".class", ".pyc", ".pyo", ".pyd",
    ".whl", ".egg", ".egg-info",
    ".tar", ".gz", ".tgz", ".bz2", ".xz", ".zip", ".7z",
    ".jar", ".war", ".ear",
    ".node",
})


# --- Types -------------------------------------------------------------------

class DiffPayload(TypedDict):
    """Output of every extractors_diff.<ecosystem>.extract()."""

    added: dict[str, str]                       # path -> content (head+tail truncated)
    modified: dict[str, tuple[str, str]]        # path -> (old_content, new_content)
    removed: list[str]                          # paths only

    raw_counts: tuple[int, int, int]            # (added, modified, removed) BEFORE filtering
    inspected_counts: tuple[int, int, int]      # AFTER filtering

    ignored_changed_paths: list[str]            # changed-but-filtered, summarized in prompt

    install_hook_paths: list[str]               # subset of added+modified that are install hooks
    top_level_code_paths: list[str]             # subset that are top-level executable code
    truncated_files: list[str]                  # files that were truncated (signals to LLM)

    partial: bool                               # True if aggregate caps were hit
    error: str                                  # non-empty if extraction itself failed


def empty_payload() -> DiffPayload:
    return DiffPayload(
        added={},
        modified={},
        removed=[],
        raw_counts=(0, 0, 0),
        inspected_counts=(0, 0, 0),
        ignored_changed_paths=[],
        install_hook_paths=[],
        top_level_code_paths=[],
        truncated_files=[],
        partial=False,
        error="",
    )


# --- Helpers -----------------------------------------------------------------

def normalize_path(path: str) -> str:
    """Normalize archive member path: forward slashes, strip leading './' prefixes.

    Note: do NOT use lstrip("./") or lstrip("/") here — those strip any chars
    in the set, including the leading dots of "../../etc/passwd" (which would
    reduce to "etc/passwd" and silently neuter traversal detection). We only
    want to strip whole "./" prefixes, hence the explicit while-loop.
    """
    p = path.replace("\\", "/")
    while p.startswith("./"):
        p = p[2:]
    return p


def is_binary_path(path: str) -> bool:
    _, ext = os.path.splitext(path.lower())
    return ext in BINARY_EXTENSIONS


def is_path_traversal(path: str) -> bool:
    """Reject members that try to escape the archive root.

    Catches POSIX traversal, absolute paths, Windows drive prefixes, and
    backslash-separated traversal (cross-platform archives sometimes use \\).

    Note: symlinks and hardlinks are a related-but-distinct attack surface —
    they're filtered separately in the per-ecosystem extractor (e.g. the
    `_read_tar` symlink/hardlink skip in pypi.py), since this function only
    inspects the member name string.
    """
    p = path.replace("\\", "/")
    # Strip leading "./" prefix(es) only — do NOT use lstrip(chars) here
    # because that would also eat leading ".." which is the very thing we
    # want to detect (e.g. "../../etc/passwd").
    while p.startswith("./"):
        p = p[2:]
    if (
        p.startswith("../")
        or "/../" in p
        or p == ".."
        or p.endswith("/..")
        or p == ""
    ):
        return True
    if path.startswith("/") or path.startswith("\\"):
        return True
    # Windows drive prefix: "C:foo" or "C:\\foo"
    if len(path) >= 2 and path[1] == ":" and path[0].isalpha():
        return True
    return False


def is_filtered_path(path: str) -> bool:
    """Path-aware filter for tests/examples/docs.

    A component matches FILTERED_COMPONENTS only when it appears AT DEPTH >= 2.
    The top-level package directory itself is never filtered (depth 0 = first
    component of the archive layout).

    Examples (returns True/False):
        cffi-1.17.0/cffi/testing/snippets/setup.py    -> True  (depth >= 2)
        examples_lib/__init__.py                      -> False (top-level pkg name)
        my_pkg/tests/test_x.py                        -> True
        my_pkg/test_helper.py                         -> False (file, not dir component)

    SECURITY: callers MUST check `is_install_hook(eco, path)` BEFORE this filter
    and bypass filtering for install hooks. An attacker may publish a package
    whose root is named e.g. `tests` (rare but legal), where a top-level
    `setup.py` lives at `tests-1.0/setup.py` (depth 1, not filtered) — but
    a payload at `evil-1.0/tests/setup.py` (depth 2, parts[1:-1] == ['tests'])
    would be filtered by this function alone. The install-hook check restores
    visibility for that path. See diff_files() in this module for the wiring.
    """
    p = normalize_path(path)
    parts = p.split("/")
    if len(parts) < 3:
        # Not deep enough to have a filtered subdirectory.
        return False
    # parts[0] is the package root (e.g. "cffi-1.17.0"), parts[1:-1] are
    # intermediate dirs, parts[-1] is the filename. Check intermediates only.
    for component in parts[1:-1]:
        if component in FILTERED_COMPONENTS:
            return True
    return False


def is_install_hook(ecosystem: str, path: str) -> bool:
    """Detect install hooks per ecosystem.

    Install hooks live AT the package root (depth <= 1). Test snippets named
    setup.py inside cffi/testing/snippets/ are NOT install hooks.
    """
    p = normalize_path(path)
    parts = p.split("/")
    basename = parts[-1].lower()

    # Maven has no path-based install hook — JAR manifests don't define
    # automatic execution scripts. The "maven" branch intentionally falls
    # through to `return False` below.
    if ecosystem == "pypi":
        # Top-level setup.py or any *.pth file.
        if len(parts) <= 2 and basename == "setup.py":
            return True
        if basename.endswith(".pth"):
            return True
        return False

    if ecosystem == "npm":
        # NPM install hooks are values inside scripts.{preinstall,postinstall,install}
        # in package.json — handled by the npm extractor by inspecting JSON, not path.
        # Path-based: top-level package.json itself is "metadata" (we report it as
        # modified, but the install hook detection is JSON-driven).
        return False

    if ecosystem == "nuget":
        # tools/install.ps1, tools/init.ps1
        return len(parts) <= 3 and parts[-2:-1] == ["tools"] and basename in ("install.ps1", "init.ps1")

    if ecosystem == "rubygems":
        # ext/<name>/extconf.rb
        return len(parts) <= 3 and parts[-3:-2] == ["ext"] and basename == "extconf.rb"

    return False


def is_top_level_code(path: str) -> bool:
    """Top-level executable code: depth <= 2 from package root, code extension."""
    p = normalize_path(path)
    parts = p.split("/")
    if len(parts) > 3:
        return False
    _, ext = os.path.splitext(parts[-1].lower())
    return ext in {".py", ".js", ".ts", ".mjs", ".cjs", ".ps1", ".sh", ".rb"}


def truncate_content(content: str, *, install_hook: bool = False) -> tuple[str, bool]:
    """Truncate large content with head+tail.

    Install hooks get a larger total budget (28 KB head + 4 KB tail) but are
    NEVER head-only — an attacker who knows install hooks were head-only would
    park malicious code at the end of a 33 KB setup.py after benign filler.
    The tail keeps the LLM able to spot tail-stashed payloads.

    Returns (truncated_content, was_truncated).
    """
    n = len(content)
    if install_hook:
        if n <= INSTALL_HOOK_HEAD_KEEP + INSTALL_HOOK_TAIL_KEEP:
            return content, False
        head = content[:INSTALL_HOOK_HEAD_KEEP]
        tail = content[-INSTALL_HOOK_TAIL_KEEP:]
        omitted = n - INSTALL_HOOK_HEAD_KEEP - INSTALL_HOOK_TAIL_KEEP
        return (head + f"\n[...TRUNCATED {omitted} BYTES (install hook middle)...]\n" + tail), True

    if n <= TRUNCATE_THRESHOLD:
        return content, False
    head = content[:TRUNCATE_HEAD]
    tail = content[-TRUNCATE_TAIL:]
    omitted = n - TRUNCATE_HEAD - TRUNCATE_TAIL
    return (head + f"\n[...TRUNCATED {omitted} BYTES...]\n" + tail), True


def safe_decode(blob: bytes) -> str:
    """Decode arbitrary bytes to UTF-8 with error replacement."""
    return blob.decode("utf-8", errors="replace")


def unified_diff(old: str, new: str, path: str) -> str:
    """Compact unified diff between two text blobs."""
    return "".join(
        difflib.unified_diff(
            old.splitlines(keepends=True),
            new.splitlines(keepends=True),
            fromfile=f"a/{path}",
            tofile=f"b/{path}",
            n=3,
        )
    )


# --- Shared diff pipeline ----------------------------------------------------

def _filter_or_collect(
    path: str,
    ignored: list[str],
    *,
    ecosystem: str = "pypi",
    install_hook_detector: Callable[[str, str], bool] = is_install_hook,
) -> bool:
    """Returns True if the path should be skipped from inspection.

    Install hooks NEVER skip — even if the path matches the test/docs filter
    (e.g. attacker publishes evil-1.0/tests/setup.py). Binary files always skip.
    """
    if is_binary_path(path):
        ignored.append(path + " (binary)")
        return True
    if install_hook_detector(ecosystem, path):
        # Defense against filter-bypass: install hooks reach the LLM regardless
        # of which directory they live in.
        return False
    if is_filtered_path(path):
        ignored.append(path + " (test/example/docs)")
        return True
    return False


def diff_files(
    new_files: dict[str, bytes | None],
    old_files: dict[str, bytes | None],
    ecosystem: str,
    payload: DiffPayload,
    *,
    install_hook_detector: Callable[[str, str], bool] = is_install_hook,
) -> None:
    """Populate payload from two file maps. Ecosystem-aware install hook detection.

    A value of None marks an oversize file (content suppressed). b"" is a
    genuinely empty file and must round-trip distinctly.

    Caller must have already populated payload.error / payload.partial as needed.
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
        if _filter_or_collect(
            path, ignored, ecosystem=ecosystem, install_hook_detector=install_hook_detector
        ):
            continue
        inspected_added.append(path)

    for path in raw_modified:
        if _filter_or_collect(
            path, ignored, ecosystem=ecosystem, install_hook_detector=install_hook_detector
        ):
            continue
        inspected_modified.append(path)

    for path in raw_removed:
        if _filter_or_collect(
            path, ignored, ecosystem=ecosystem, install_hook_detector=install_hook_detector
        ):
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
        if blob is None:
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
        if old_blob is None or new_blob is None:
            ignored.append(path + " (oversize)")
            continue
        old_text = safe_decode(old_blob)
        new_text = safe_decode(new_blob)
        diff = unified_diff(old_text, new_text, path)
        is_hook = install_hook_detector(ecosystem, path)
        diff_truncated, was_trunc = truncate_content(diff, install_hook=is_hook)
        payload["modified"][path] = (
            "[unified diff follows]\n" + diff_truncated,
            "",
        )
        if was_trunc:
            truncated.append(path)
        if is_hook:
            install_hooks.append(path)
        elif is_top_level_code(path):
            top_level.append(path)

    payload["install_hook_paths"] = install_hooks
    payload["top_level_code_paths"] = top_level
    payload["truncated_files"] = truncated

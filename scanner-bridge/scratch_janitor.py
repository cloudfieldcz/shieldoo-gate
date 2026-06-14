"""Periodic age-based janitor for GuardDog scratch in the scanner bridge.

GuardDog runs in-process and writes decompression/analyzer temp under
``tempfile.gettempdir()`` (``/tmp`` — the shared ``bridge-socket`` Docker
volume). On a scanner timeout, crash, or a hard kill (SIGKILL/OOM) of the bridge
process mid-scan, that scratch is orphaned and grows the shared volume without
bound (observed at 33 GB+ in production).

This module:

1. ``setup_scratch_dir()`` — creates a dedicated, bridge-owned
   ``<tmp>/shieldoo-guarddog/`` directory and points ``tempfile.tempdir`` +
   ``TMPDIR`` at it **once at startup**, before any scan thread runs. The bridge
   serves on a 64-thread pool; mutating the process-global ``tempfile.tempdir``
   per scan would race and leave the global pointing at a deleted dir, so the
   redirection is done exactly once here (plan Constraint 2).

2. A daemon-thread janitor that sweeps that directory for stale entries. Because
   the directory is owned exclusively by the bridge, any stale entry in it is
   disposable regardless of GuardDog's internal naming — no prefix matching
   needed inside it.

The bridge is a Python sidecar with no Prometheus endpoint, so the janitor is
log-only by design; operators monitor the gate's metrics + these bridge logs.

maxAge is a fixed 1h floor: the bridge sets no server-side guard on the GuardDog
``scan_local`` path; the effective bound is the gate's gRPC deadline (which
propagates ``scanners.timeout``, default 60s), a value the bridge does not know.
Raising ``scanners.timeout`` toward 1h would require raising this floor.
"""

import logging
import os
import shutil
import tempfile
import threading
import time

logger = logging.getLogger(__name__)

# Directory name created under the temp base and owned exclusively by the bridge.
SCRATCH_DIRNAME = "shieldoo-guarddog"

# Defaults mirror the Go janitor: sweep every 10 min, 1h staleness floor, and a
# per-sweep deletion cap so the first backlog-draining sweep is not one blocking
# metadata storm that contends with in-flight scans.
DEFAULT_INTERVAL = 600
DEFAULT_MAX_AGE = 3600
DEFAULT_MAX_DELETE = 100


def setup_scratch_dir(base=None):
    """Create the bridge-owned scratch dir and redirect tempfile + TMPDIR to it.

    Call ONCE at startup, before scan threads run (Constraint 2). Returns the
    scratch dir path, or ``None`` if it cannot be created (the bridge still
    serves; scratch just is not isolated and the janitor is not started).
    """
    if base is None:
        base = tempfile.gettempdir()
    scratch = os.path.join(base, SCRATCH_DIRNAME)
    try:
        os.makedirs(scratch, exist_ok=True)
    except OSError as exc:
        logger.warning(
            "scratch janitor: cannot create %s: %s; GuardDog scratch not isolated",
            scratch, exc,
        )
        return None
    # Set once, before any scan thread runs. tempfile.gettempdir() consults
    # tempfile.tempdir first, and most temp creation honours TMPDIR too.
    tempfile.tempdir = scratch
    os.environ["TMPDIR"] = scratch
    logger.info("scratch janitor: GuardDog scratch isolated at %s", scratch)
    return scratch


def _entry_size(path, is_dir):
    """Best-effort disk footprint for observability. Bounded by the per-sweep
    cap; symlinks are not followed; errors are swallowed (metrics-only)."""
    if not is_dir:
        try:
            return os.lstat(path).st_size
        except OSError:
            return 0
    total = 0
    # os.walk does not follow symlinked directories (followlinks=False default).
    for root, _dirs, files in os.walk(path):
        for name in files:
            fp = os.path.join(root, name)
            try:
                if not os.path.islink(fp):
                    total += os.lstat(fp).st_size
            except OSError:
                pass
    return total


def _sweep_scratch(scratch_dir, now, max_age, max_delete=DEFAULT_MAX_DELETE):
    """Remove entries in ``scratch_dir`` older than ``max_age`` (oldest-first).

    Deterministic given (now, tree). TOCTOU-safe: direct children only via
    ``os.scandir``; age from the top-level entry's ``lstat`` mtime only (never
    recurse for the age decision); symlinks skipped entirely; names containing
    ``/`` or ``..`` rejected; capped at ``max_delete`` per sweep; continues on
    per-entry error. Returns the number of entries deleted.
    """
    try:
        entries = list(os.scandir(scratch_dir))
    except OSError as exc:
        logger.warning("scratch janitor: scandir %s failed: %s", scratch_dir, exc)
        return 0

    cutoff = now - max_age
    candidates = []
    for entry in entries:
        name = entry.name
        if "/" in name or ".." in name:
            continue
        try:
            if entry.is_symlink():
                continue  # never follow or delete symlinks
            st = entry.stat(follow_symlinks=False)
            is_dir = entry.is_dir(follow_symlinks=False)
        except OSError:
            continue  # vanished or unreadable — skip
        if st.st_mtime > cutoff:
            continue  # too fresh — could be an in-flight scan
        candidates.append((st.st_mtime, name, is_dir))

    # Oldest-first: every candidate is already past max_age and equally safe; a
    # deterministic order makes the cap testable and drains the oldest first.
    candidates.sort(key=lambda c: c[0])

    deleted = 0
    reclaimed = 0
    skipped = 0
    for _mtime, name, is_dir in candidates:
        if deleted >= max_delete:
            logger.info(
                "scratch janitor: per-sweep cap %d reached; backlog drains next cycle",
                max_delete,
            )
            break
        full = os.path.join(scratch_dir, name)
        size = _entry_size(full, is_dir)
        try:
            if is_dir:
                shutil.rmtree(full)
            else:
                os.remove(full)
        except OSError as exc:
            skipped += 1
            logger.warning("scratch janitor: delete %s failed: %s; skipping", name, exc)
            continue
        deleted += 1
        reclaimed += size

    if deleted or skipped:
        logger.info(
            "scratch janitor: reclaimed %d entries, %d bytes (%d candidates, %d skipped)",
            deleted, reclaimed, len(candidates), skipped,
        )
    return deleted


def _run_scratch_janitor(scratch_dir, interval, max_age, stop_event):
    """Daemon loop: initial sweep, then sweep every ``interval`` until stopped."""
    logger.info(
        "scratch janitor: starting (dir=%s interval=%ds max_age=%ds)",
        scratch_dir, interval, max_age,
    )
    _sweep_scratch(scratch_dir, time.time(), max_age)
    while not stop_event.wait(interval):
        _sweep_scratch(scratch_dir, time.time(), max_age)
    logger.info("scratch janitor: stopped")


def start_scratch_janitor(scratch_dir, interval=DEFAULT_INTERVAL, max_age=DEFAULT_MAX_AGE):
    """Start the janitor on a daemon thread. Returns ``(thread, stop_event)``."""
    stop_event = threading.Event()
    thread = threading.Thread(
        target=_run_scratch_janitor,
        args=(scratch_dir, interval, max_age, stop_event),
        name="scratch-janitor",
        daemon=True,
    )
    thread.start()
    return thread, stop_event

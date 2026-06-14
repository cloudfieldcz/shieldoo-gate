"""Tests for scanner-bridge/scratch_janitor.py.

Mirror the Go tmpjanitor unit tests: stale removed / fresh kept, symlinks
skipped, ``..``-named entries rejected, per-entry delete failure does not abort
the sweep, the per-sweep cap deletes oldest-first, and setup_scratch_dir
redirects tempfile + TMPDIR exactly once.
"""

from __future__ import annotations

import os
import sys
import tempfile
import time

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import scratch_janitor  # noqa: E402

NOW = 1_000_000.0
STALE = NOW - 2 * 3600  # 2h old
FRESH = NOW - 60        # 1m old
MAX_AGE = 3600          # 1h


def _mk_file(d, name, mtime):
    p = os.path.join(d, name)
    with open(p, "w") as fh:
        fh.write("scratch")
    os.utime(p, (mtime, mtime))
    return p


def _mk_dir(d, name, mtime):
    p = os.path.join(d, name)
    os.makedirs(os.path.join(p, "inner"))
    with open(os.path.join(p, "inner", "f"), "w") as fh:
        fh.write("x")
    os.utime(p, (mtime, mtime))
    return p


def test_setup_scratch_dir_redirects_tempfile_and_env(tmp_path, monkeypatch):
    monkeypatch.setattr(tempfile, "tempdir", None)
    monkeypatch.delenv("TMPDIR", raising=False)

    scratch = scratch_janitor.setup_scratch_dir(base=str(tmp_path))

    assert scratch == os.path.join(str(tmp_path), scratch_janitor.SCRATCH_DIRNAME)
    assert os.path.isdir(scratch)
    assert tempfile.tempdir == scratch
    assert os.environ["TMPDIR"] == scratch


def test_sweep_removes_stale_keeps_fresh(tmp_path):
    d = str(tmp_path)
    stale_file = _mk_file(d, "guarddog-tmp-abc", STALE)
    stale_dir = _mk_dir(d, "analyzer-xyz", STALE)
    fresh = _mk_file(d, "in-flight", FRESH)

    n = scratch_janitor._sweep_scratch(d, NOW, MAX_AGE)

    assert n == 2
    assert not os.path.exists(stale_file)
    assert not os.path.exists(stale_dir)
    assert os.path.exists(fresh)  # an in-flight scan must survive


def test_sweep_skips_symlinks(tmp_path):
    d = str(tmp_path)
    target = _mk_file(d, "real-target", STALE)
    link = os.path.join(d, "link-to-target")
    os.symlink(target, link)
    # Backdate the link itself (lchmod-style); the target stays put.
    os.utime(link, (STALE, STALE), follow_symlinks=False)

    n = scratch_janitor._sweep_scratch(d, NOW, MAX_AGE)

    # The symlink is skipped; the real target is still stale and removable.
    assert os.path.islink(link), "symlink must never be deleted"
    assert n == 1
    assert not os.path.exists(target)


def test_sweep_rejects_dotdot_names(tmp_path):
    d = str(tmp_path)
    evil = _mk_file(d, "..evil", STALE)

    n = scratch_janitor._sweep_scratch(d, NOW, MAX_AGE)

    assert n == 0
    assert os.path.exists(evil)


def test_sweep_cap_deletes_oldest_first(tmp_path):
    d = str(tmp_path)
    # Five stale files with strictly increasing mtimes; cap at 2.
    for i in range(5):
        _mk_file(d, f"f{i}", NOW - (5 - i) * 3600)

    n = scratch_janitor._sweep_scratch(d, NOW, MAX_AGE, max_delete=2)

    assert n == 2
    assert not os.path.exists(os.path.join(d, "f0"))  # oldest
    assert not os.path.exists(os.path.join(d, "f1"))
    for i in (2, 3, 4):
        assert os.path.exists(os.path.join(d, f"f{i}"))  # survive the cap


@pytest.mark.skipif(os.geteuid() == 0, reason="root bypasses directory permissions")
def test_sweep_per_entry_failure_does_not_abort(tmp_path):
    d = str(tmp_path)
    stuck = _mk_dir(d, "stuck", STALE)
    os.chmod(stuck, 0o000)
    ok = _mk_file(d, "deletable", STALE)
    try:
        n = scratch_janitor._sweep_scratch(d, NOW, MAX_AGE)
    finally:
        os.chmod(stuck, 0o755)  # let tmp_path cleanup succeed

    assert n == 1
    assert os.path.exists(stuck)        # delete failed, but sweep continued
    assert not os.path.exists(ok)       # entry after the failure still removed


def test_sweep_missing_dir_returns_zero(tmp_path):
    n = scratch_janitor._sweep_scratch(os.path.join(str(tmp_path), "nope"), NOW, MAX_AGE)
    assert n == 0

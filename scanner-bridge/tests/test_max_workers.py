"""Tests for main._max_workers_from_env.

The gRPC worker-pool size is operator-tunable via BRIDGE_MAX_WORKERS so a small
host can cap concurrent GuardDog/semgrep scans (a full `npm ci` burst against
all 64 default workers oversubscribes CPU and trips the gate's required-scanner
timeout). A typo'd or non-positive value must fall back to the default rather
than crash the bridge on startup.
"""

from __future__ import annotations

import os
import sys

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import main  # noqa: E402


@pytest.fixture(autouse=True)
def _clear_env(monkeypatch):
    monkeypatch.delenv("BRIDGE_MAX_WORKERS", raising=False)


def test_max_workers_unset_returns_default(monkeypatch):
    monkeypatch.delenv("BRIDGE_MAX_WORKERS", raising=False)
    assert main._max_workers_from_env() == main.DEFAULT_MAX_WORKERS


def test_max_workers_empty_returns_default(monkeypatch):
    monkeypatch.setenv("BRIDGE_MAX_WORKERS", "")
    assert main._max_workers_from_env() == main.DEFAULT_MAX_WORKERS


def test_max_workers_valid_value_is_used(monkeypatch):
    monkeypatch.setenv("BRIDGE_MAX_WORKERS", "16")
    assert main._max_workers_from_env() == 16


def test_max_workers_non_integer_falls_back(monkeypatch):
    monkeypatch.setenv("BRIDGE_MAX_WORKERS", "lots")
    assert main._max_workers_from_env() == main.DEFAULT_MAX_WORKERS


@pytest.mark.parametrize("value", ["0", "-4"])
def test_max_workers_non_positive_falls_back(monkeypatch, value):
    monkeypatch.setenv("BRIDGE_MAX_WORKERS", value)
    assert main._max_workers_from_env() == main.DEFAULT_MAX_WORKERS

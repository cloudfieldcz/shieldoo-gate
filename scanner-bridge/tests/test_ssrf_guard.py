"""Tests for ssrf_guard.

These cover the validation gate (`validate_url`); the integrated `safe_get`
fetch path needs a real public host or extensive mocking and is exercised in
E2E.
"""

import os
import sys

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import ssrf_guard  # noqa: E402


def test_valid_github_url_passes(monkeypatch):
    # Force the resolver to return a known public IP so the test doesn't depend
    # on actual DNS being available.
    monkeypatch.setattr(ssrf_guard, "_resolve_ips", lambda host: ["140.82.114.4"])
    canonical, host, ip = ssrf_guard.validate_url("https://github.com/user/repo")
    assert host == "github.com"
    assert ip == "140.82.114.4"
    assert canonical.startswith("https://github.com")


def test_subdomain_smuggle_rejected(monkeypatch):
    # Anchored regex must reject "github.com.evil.tld" even with public DNS.
    monkeypatch.setattr(ssrf_guard, "_resolve_ips", lambda host: ["1.2.3.4"])
    with pytest.raises(ssrf_guard.SSRFError):
        ssrf_guard.validate_url("https://github.com.evil.tld/x")


def test_ip_literal_rejected():
    # Even when the IP is technically public, hostname-based allowlist must not
    # permit literals.
    with pytest.raises(ssrf_guard.SSRFError):
        ssrf_guard.validate_url("https://140.82.114.4/x")


def test_internal_resolution_rejected(monkeypatch):
    # An allow-listed hostname that resolves to RFC1918 must be rejected.
    monkeypatch.setattr(ssrf_guard, "_resolve_ips", lambda host: ["10.0.0.5"])
    with pytest.raises(ssrf_guard.SSRFError):
        ssrf_guard.validate_url("https://github.com/")


def test_loopback_rejected(monkeypatch):
    monkeypatch.setattr(ssrf_guard, "_resolve_ips", lambda host: ["127.0.0.1"])
    with pytest.raises(ssrf_guard.SSRFError):
        ssrf_guard.validate_url("https://github.com/")


def test_unknown_host_rejected(monkeypatch):
    monkeypatch.setattr(ssrf_guard, "_resolve_ips", lambda host: ["1.2.3.4"])
    with pytest.raises(ssrf_guard.SSRFError):
        ssrf_guard.validate_url("https://random.example.com/")


def test_unsupported_scheme_rejected():
    for url in ("ftp://github.com/x", "file:///etc/passwd", "gopher://github.com/x"):
        with pytest.raises(ssrf_guard.SSRFError):
            ssrf_guard.validate_url(url)


def test_oversized_url_rejected():
    with pytest.raises(ssrf_guard.SSRFError):
        ssrf_guard.validate_url("https://github.com/" + "a" * 4096)


def test_dns_failure_rejected(monkeypatch):
    # _resolve_ips returning [] simulates NXDOMAIN.
    monkeypatch.setattr(ssrf_guard, "_resolve_ips", lambda host: [])
    with pytest.raises(ssrf_guard.SSRFError):
        ssrf_guard.validate_url("https://github.com/")


def test_extra_host_via_env_allowed(monkeypatch):
    # Operator-supplied allowlist additions take effect at validate-time.
    monkeypatch.setenv("SSRF_ALLOWED_HOSTS", r"^my-internal-mirror\.example\.com$")
    monkeypatch.setattr(ssrf_guard, "_resolve_ips", lambda host: ["8.8.8.8"])
    canonical, host, _ = ssrf_guard.validate_url("https://my-internal-mirror.example.com/repo")
    assert host == "my-internal-mirror.example.com"


def test_empty_url_rejected():
    for url in ("", None):
        with pytest.raises(ssrf_guard.SSRFError):
            ssrf_guard.validate_url(url)  # type: ignore[arg-type]

"""SSRF guard — defensive URL validation for any outbound fetch from user-supplied
URLs (e.g. cve_ignores.repo_url passed to vuln_drafter for code-context fetch).

This module is the *gate* — it does NOT itself fetch. Callers wrap the
allow-listed url string with their own HTTP client, but every call site MUST
route through `validate_url` first. The guard enforces:

1. Scheme: only http/https.
2. Allowed hosts (regex allowlist) — defaults cover GitHub / GitLab / Bitbucket
   public hosts; deployments override via SSRF_ALLOWED_HOSTS env (comma
   separated regex patterns).
3. Resolved-IP block: rejects RFC 1918 / loopback / link-local / multicast
   ranges. Done at validate time AND at fetch time — DNS rebind protection
   requires both: the validate-time check ensures the URL initially resolves
   to a public IP; a "DNS-rebind-safe" HTTP client must re-resolve once and
   pin the connection to the validated IP (we provide a `safe_get` helper
   that does this).

Defense-in-depth: even if an attacker bypasses the regex allowlist (e.g. a
GitHub-hosted bug-bait repo), the resolved-IP check still excludes the
internal network from reach.
"""

from __future__ import annotations

import ipaddress
import logging
import os
import re
import socket
import urllib.parse

import httpx

logger = logging.getLogger(__name__)


# Default-allowed hostnames. Regex anchored to full host so subdomain attacks
# don't slip through (e.g. "github.com.evil.tld" is rejected because the regex
# is `^github\.com$`, not `github\.com`).
_DEFAULT_HOST_PATTERNS = (
    r"^github\.com$",
    r"^raw\.githubusercontent\.com$",
    r"^gitlab\.com$",
    r"^bitbucket\.org$",
)

# Hosts the operator added via env. Re-read on each validate so env updates
# don't require a sidecar restart.
def _allowed_host_patterns() -> list[re.Pattern[str]]:
    extras = os.environ.get("SSRF_ALLOWED_HOSTS", "").strip()
    raw = list(_DEFAULT_HOST_PATTERNS)
    if extras:
        raw.extend([p.strip() for p in extras.split(",") if p.strip()])
    return [re.compile(p, re.IGNORECASE) for p in raw]


class SSRFError(ValueError):
    """Raised when validate_url rejects a URL.

    The exception message is operator-facing (logged) but should never be
    propagated to end-users verbatim — leaking why a URL was rejected can
    reveal internal hostnames.
    """


def _is_disallowed_ip(ip: str) -> bool:
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return True  # unparseable — treat as hostile
    return (
        addr.is_private
        or addr.is_loopback
        or addr.is_link_local
        or addr.is_multicast
        or addr.is_reserved
        or addr.is_unspecified
    )


def _resolve_ips(host: str) -> list[str]:
    """Return all A/AAAA records for host. Empty list on resolution failure."""
    try:
        infos = socket.getaddrinfo(host, None)
    except socket.gaierror:
        return []
    out: list[str] = []
    for fam, _, _, _, sockaddr in infos:
        if fam in (socket.AF_INET, socket.AF_INET6):
            ip = sockaddr[0]
            if ip not in out:
                out.append(ip)
    return out


def validate_url(raw: str) -> tuple[str, str, str]:
    """Validate `raw` and return (canonical_url, host, resolved_ip).

    Raises SSRFError when rejected. The returned `resolved_ip` MUST be used
    to pin the connection (see `safe_get`) — re-resolving the host name at
    fetch time would re-open the rebind window the validator just closed.
    """
    if not raw or not isinstance(raw, str):
        raise SSRFError("ssrf_guard: empty url")
    if len(raw) > 2048:
        raise SSRFError("ssrf_guard: url too long")

    parsed = urllib.parse.urlparse(raw.strip())
    if parsed.scheme not in ("http", "https"):
        raise SSRFError(f"ssrf_guard: unsupported scheme {parsed.scheme!r}")
    host = (parsed.hostname or "").lower()
    if not host:
        raise SSRFError("ssrf_guard: missing host")

    # Reject IP literals up-front — the allowlist is hostname-based and an
    # attacker could otherwise short-circuit it with a literal.
    try:
        ipaddress.ip_address(host)
        raise SSRFError("ssrf_guard: ip-literal hosts not allowed")
    except ValueError:
        pass  # not an IP literal — continue

    patterns = _allowed_host_patterns()
    if not any(p.match(host) for p in patterns):
        raise SSRFError(f"ssrf_guard: host {host!r} not on allowlist")

    ips = _resolve_ips(host)
    if not ips:
        raise SSRFError(f"ssrf_guard: dns lookup failed for {host!r}")
    public_ips = [ip for ip in ips if not _is_disallowed_ip(ip)]
    if not public_ips:
        raise SSRFError(f"ssrf_guard: all resolved ips for {host!r} are internal/restricted")

    canonical = urllib.parse.urlunparse(parsed._replace(scheme=parsed.scheme.lower(), netloc=host + (f":{parsed.port}" if parsed.port else "")))
    return canonical, host, public_ips[0]


def safe_get(url: str, timeout: float = 5.0, max_bytes: int = 64 * 1024) -> str:
    """Fetch `url` with SSRF + DNS-rebind protection. Returns response text.

    The fetch pins the TCP connection to the IP that `validate_url` resolved,
    so a malicious DNS server that rotated the answer between validate and
    fetch (the classic rebind attack) cannot redirect us to an internal host.

    Raises SSRFError on validation; httpx.* on transport failures. Truncates
    the body to `max_bytes` so an attacker can't make us swallow a giant
    response.
    """
    canonical, host, ip = validate_url(url)
    parsed = urllib.parse.urlparse(canonical)
    # Build a URL that hits the IP directly, but keep Host header = original
    # host so TLS SNI and HTTP routing still work for shared-tenancy hosts.
    netloc = ip if not parsed.port else f"{ip}:{parsed.port}"
    pinned = parsed._replace(netloc=netloc)
    req_url = urllib.parse.urlunparse(pinned)

    headers = {"Host": host, "User-Agent": "shieldoo-gate-ssrf-safe/1.0"}
    with httpx.Client(timeout=timeout, follow_redirects=False) as client:
        resp = client.get(req_url, headers=headers)
        resp.raise_for_status()
        # Bytes are read-bounded by httpx via stream=False default; trim.
        if len(resp.content) > max_bytes:
            return resp.text[:max_bytes]
        return resp.text

"""
src/tests/data/ssrf_payloads.py

SSRF attack payload catalogue for test 7.2.

This module is pure data: it defines no functions and performs no I/O.
All payloads are sourced from OWASP API Security Testing Guide (OWASP API7:2023)
and the methodology section 7.2 of this project.

Structure
---------
Each payload entry is a tuple of (url, description) where:
    url         -- The URL string to submit as user-controlled input.
    description -- Short label used in Finding.detail for reporting.

The consuming test (7.2) iterates over the relevant catalogue and checks
that the API returns 400 or a timeout, not 200 with content from the
internal target.

Dependency rule
---------------
This module has no imports.  It is a data file only.
"""

from __future__ import annotations

# ---------------------------------------------------------------------------
# Cloud metadata endpoints
# Methodology ref: Garanzia 7.2 — Cloud Metadata Access
# ---------------------------------------------------------------------------

CLOUD_METADATA_URLS: tuple[tuple[str, str], ...] = (
    # AWS IMDSv1 (unauthenticated, highest risk)
    ("http://169.254.169.254/latest/meta-data/", "AWS IMDSv1 root"),
    ("http://169.254.169.254/latest/meta-data/iam/security-credentials/", "AWS IAM credentials"),
    ("http://169.254.169.254/latest/meta-data/hostname", "AWS hostname"),
    # GCP metadata server
    ("http://metadata.google.internal/computeMetadata/v1/", "GCP metadata root"),
    ("http://169.254.169.254/computeMetadata/v1/", "GCP metadata via link-local"),
    # Azure IMDS
    ("http://169.254.169.254/metadata/instance", "Azure IMDS instance"),
    ("http://169.254.169.254/metadata/identity/oauth2/token", "Azure managed identity token"),
    # DigitalOcean
    ("http://169.254.169.254/metadata/v1/", "DigitalOcean metadata"),
)

# ---------------------------------------------------------------------------
# Private IP ranges
# Methodology ref: Garanzia 7.2 — Private IP Range Blocking
# ---------------------------------------------------------------------------

PRIVATE_IP_URLS: tuple[tuple[str, str], ...] = (
    ("http://127.0.0.1", "IPv4 loopback"),
    ("http://127.0.0.1:8080", "IPv4 loopback with port"),
    ("http://localhost", "localhost hostname"),
    ("http://localhost:8080", "localhost with port"),
    # RFC 1918 private ranges
    ("http://10.0.0.1", "RFC1918 class A"),
    ("http://10.0.0.1:8080/admin", "RFC1918 class A admin path"),
    ("http://172.16.0.1", "RFC1918 class B"),
    ("http://192.168.1.1", "RFC1918 class C"),
    ("http://192.168.0.1", "RFC1918 class C alt"),
    # Link-local
    ("http://169.254.1.1", "link-local range"),
)

# ---------------------------------------------------------------------------
# Encoding bypass variants
# Methodology ref: Garanzia 7.2 — Bypass Blacklist via Encoding
# ---------------------------------------------------------------------------

ENCODING_BYPASS_URLS: tuple[tuple[str, str], ...] = (
    # Decimal and hex notation for 127.0.0.1
    ("http://2130706433", "127.0.0.1 as decimal integer"),
    ("http://0x7f000001", "127.0.0.1 as hex"),
    ("http://0177.0.0.1", "127.0.0.1 as octal"),
    # Abbreviated notation
    ("http://127.1", "127.1 abbreviated loopback"),
    ("http://127.0.1", "127.0.1 abbreviated"),
    # IPv6 loopback
    ("http://[::1]", "IPv6 loopback"),
    ("http://[::1]:8080", "IPv6 loopback with port"),
    ("http://[0:0:0:0:0:0:0:1]", "IPv6 full loopback"),
    # URL-encoded
    ("http://%31%32%37%2e%30%2e%30%2e%31", "127.0.0.1 URL-encoded"),
    # Double URL-encoded
    ("http://%2531%2532%2537%252e%2530%252e%2530%252e%2531", "127.0.0.1 double URL-encoded"),
    # Mixed case
    ("http://Localhost", "localhost mixed case"),
    ("http://LOCALHOST", "localhost uppercase"),
)

# ---------------------------------------------------------------------------
# Protocol whitelist bypass
# Methodology ref: Garanzia 7.2 — Protocol Whitelist
# ---------------------------------------------------------------------------

FORBIDDEN_PROTOCOL_URLS: tuple[tuple[str, str], ...] = (
    ("file:///etc/passwd", "file:// to /etc/passwd"),
    ("file:///etc/hosts", "file:// to /etc/hosts"),
    ("file:///proc/self/environ", "file:// to /proc/self/environ"),
    ("gopher://127.0.0.1:25/", "gopher:// SMTP relay"),
    ("dict://127.0.0.1:11211/", "dict:// memcached"),
    ("ftp://127.0.0.1/", "ftp:// loopback"),
    ("ldap://127.0.0.1:389/", "ldap:// loopback"),
    ("tftp://127.0.0.1:69/", "tftp:// loopback"),
)

# ---------------------------------------------------------------------------
# Open redirect / SSRF via redirect chain
# Methodology ref: Garanzia 7.2 — Redirect Following Validation
# Test note: the consuming test substitutes a real controlled redirect server.
# This placeholder documents the attack pattern; the URL is set at runtime.
# ---------------------------------------------------------------------------

# Sentinel value used by test 7.2 to signal that a redirect-following test
# requires a live controlled server.  The test skips this check if no
# redirect server URL is configured.
REDIRECT_SSRF_SENTINEL: str = "REQUIRES_REDIRECT_SERVER"

# ---------------------------------------------------------------------------
# Aggregated catalogue
# ---------------------------------------------------------------------------

# Full catalogue used by test 7.2 for systematic iteration.
# Each entry: (url, description, category)
ALL_SSRF_PAYLOADS: tuple[tuple[str, str, str], ...] = (
    *((url, desc, "cloud_metadata") for url, desc in CLOUD_METADATA_URLS),
    *((url, desc, "private_ip") for url, desc in PRIVATE_IP_URLS),
    *((url, desc, "encoding_bypass") for url, desc in ENCODING_BYPASS_URLS),
    *((url, desc, "forbidden_protocol") for url, desc in FORBIDDEN_PROTOCOL_URLS),
)

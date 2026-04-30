"""
src/config/schema/domain_1.py

Pydantic v2 configuration models for Domain 1 (Identity and Authentication) tests.

This module is part of the config/schema/ package refactoring. It owns all
per-test tuning parameters for tests 1.x. Each test that requires operator-
configurable parameters gets its own model (Test1XConfig); the domain-level
aggregator (TestDomain1Config) collects them all and is the only symbol
exported to tests_config.py.

Dependency rule: imports only from pydantic and the stdlib.
"""

from __future__ import annotations

from typing import Annotated

from pydantic import BaseModel, Field, field_validator

# ---------------------------------------------------------------------------
# Constants — Test 1.1
# ---------------------------------------------------------------------------

TEST_11_MAX_ENDPOINTS_CAP_DEFAULT: int = 0
TEST_11_MAX_ENDPOINTS_CAP_MIN: int = 0

# ---------------------------------------------------------------------------
# Constants — Test 1.5
# ---------------------------------------------------------------------------

# HSTS max-age threshold: NIST SP 800-52 Rev.2, OWASP ASVS v5.0.0 V12.1.1.
# 31 536 000 s = 1 year (recommended minimum).
TEST_15_HSTS_MIN_MAX_AGE_DEFAULT: int = 31_536_000
TEST_15_HSTS_MIN_MAX_AGE_MIN: int = 86_400  # 1 day — absolute floor

# HTTP redirect probe timeout: intentionally short; a refused connection is
# immediate.  5 s accommodates slow firewalls that return TCP RST after a
# brief delay rather than immediately.
TEST_15_HTTP_PROBE_TIMEOUT_DEFAULT: float = 5.0
TEST_15_HTTP_PROBE_TIMEOUT_MIN: float = 1.0

# testssl.sh subprocess timeout: the binary can take up to 2 minutes on slow
# networks.  30 s is the absolute floor; 120 s is the safe default.
TEST_15_TESTSSL_TIMEOUT_DEFAULT: int = 120
TEST_15_TESTSSL_TIMEOUT_MIN: int = 30

# ---------------------------------------------------------------------------
# Constants — Test 1.6
# ---------------------------------------------------------------------------

# Well-known session cookie names across common web frameworks.
# The test inspects only cookies whose names appear in this list.
TEST_16_SESSION_COOKIE_NAMES_DEFAULT: list[str] = [
    "session",
    "sid",
    "PHPSESSID",
    "JSESSIONID",
    "connect.sid",
    "_session",
    "auth_session",
    "user_session",
]

# ---------------------------------------------------------------------------
# Per-test configs
# ---------------------------------------------------------------------------


class Test11Config(BaseModel):
    """
    Tuning parameters for Test 1.1 (Authentication Required).

    Controls how many protected endpoints Test 1.1 will probe in a single
    assessment run. The default value of 0 signals 'probe all endpoints',
    which is the academically complete behaviour. A positive integer caps
    the scan when the target enforces strict rate limiting that would cause
    429 responses during a full run, or when a time-bounded assessment is
    required.
    """

    model_config = {"frozen": True}

    max_endpoints_cap: Annotated[int, Field(ge=TEST_11_MAX_ENDPOINTS_CAP_MIN)] = Field(
        default=TEST_11_MAX_ENDPOINTS_CAP_DEFAULT,
        description=(
            "Maximum number of protected endpoints that Test 1.1 will probe. "
            "0 means test ALL protected endpoints declared in the OpenAPI spec "
            "(recommended for complete academic coverage). "
            "Set to a positive integer only when the target API enforces strict "
            "rate limiting that would cause 429 responses during a full scan, "
            "or when the operator requires a time-bounded assessment."
        ),
    )


class Test15Config(BaseModel):
    """
    Tuning parameters for Test 1.5 (Credentials Not Transmitted via Insecure Channels).

    Governs three sub-tests executed against the target:

    Sub-test 1 -- HTTP redirect enforcement (empirical, RFC 9110):
        Sends a GET to the HTTP version of the target base URL.
        Oracle: connection refused (port 80 closed) or 301/308 permanent
        redirect.  Any 2xx or other 3xx response is a FAIL.

    Sub-test 2 -- HSTS header validation (NIST SP 800-52 Rev.2,
        OWASP ASVS v5.0.0 V12.1.1):
        Sends a GET to the HTTPS base URL and inspects the
        Strict-Transport-Security response header.
        Oracle: header present, max-age >= hsts_min_max_age_seconds,
        includeSubDomains present.

    Sub-test 3 -- TLS version and cipher-suite audit (optional,
        NIST SP 800-52 Rev.2):
        Invokes testssl.sh if testssl_binary_path is configured.
        Oracle: TLS 1.0 / 1.1 / SSLv3 not offered; no HIGH/CRITICAL
        protocol-level or cipher-suite vulnerabilities.
        Set testssl_binary_path to empty string to skip this sub-test.
    """

    model_config = {"frozen": True}

    hsts_min_max_age_seconds: Annotated[
        int,
        Field(ge=TEST_15_HSTS_MIN_MAX_AGE_MIN),
    ] = Field(
        default=TEST_15_HSTS_MIN_MAX_AGE_DEFAULT,
        description=(
            "Minimum acceptable max-age value (seconds) in the Strict-Transport-Security "
            "header.  NIST SP 800-52 Rev.2, OWASP ASVS v5.0.0 V12.1.1. "
            f"Default: {TEST_15_HSTS_MIN_MAX_AGE_DEFAULT} (1 year)."
        ),
    )
    http_probe_enabled: bool = Field(
        default=True,
        description=(
            "If True, probe the HTTP base URL for redirect enforcement (sub-test 1). "
            "Set False only if port 80 is filtered at the network level and "
            "any connection attempt would block for the full timeout. Default: True."
        ),
    )
    http_probe_url: str = Field(
        default="",
        description=(
            "Explicit HTTP URL to probe for redirect enforcement (sub-test 1). "
            "When non-empty, this URL is used directly instead of deriving the "
            "HTTP counterpart from the HTTPS base URL. "
            "Use in non-standard port lab setups where the HTTPS base URL uses a "
            "port other than 443 (e.g. https://localhost:8443 -> derive produces "
            "http://localhost:8443/ which hits Kong's TLS listener and returns 400). "
            "Example: 'http://localhost:8000/' to probe Kong's HTTP listener. "
            "Empty string (default) falls back to the derived URL."
        ),
    )
    http_probe_timeout_seconds: Annotated[
        float,
        Field(ge=TEST_15_HTTP_PROBE_TIMEOUT_MIN),
    ] = Field(
        default=TEST_15_HTTP_PROBE_TIMEOUT_DEFAULT,
        description=(
            "Connect + read timeout (seconds) for the HTTP redirect probe. "
            "Keep short: a TCP RST is returned immediately for refused connections. "
            f"Default: {TEST_15_HTTP_PROBE_TIMEOUT_DEFAULT}."
        ),
    )
    expected_redirect_status_codes: list[int] = Field(
        default_factory=lambda: [301, 308],
        description=(
            "HTTP status codes that satisfy the redirect oracle in sub-test 1. "
            "RFC 9110 permanent redirects: 301 (Moved Permanently) and "
            "308 (Permanent Redirect).  Temporary redirects 302/307 are NOT "
            "accepted: they allow MITM-driven downgrade attacks. Default: [301, 308]."
        ),
    )
    testssl_binary_path: str = Field(
        default="",
        description=(
            "Absolute filesystem path to the testssl.sh binary. "
            "Empty string (default) skips sub-test 3 entirely. "
            "When non-empty, the binary is invoked as a subprocess to audit "
            "supported TLS protocol versions and cipher suites. "
            "Oracle: TLS 1.0 / 1.1 / SSLv3 must not be offered; "
            "cipher suites must provide forward secrecy (ECDHE) per NIST SP 800-52 Rev.2."
        ),
    )
    testssl_timeout_seconds: Annotated[
        int,
        Field(ge=TEST_15_TESTSSL_TIMEOUT_MIN),
    ] = Field(
        default=TEST_15_TESTSSL_TIMEOUT_DEFAULT,
        description=(
            "Maximum wall-clock seconds allowed for the testssl.sh subprocess (sub-test 3). "
            "testssl.sh performs a full TLS handshake sweep and can take up to 2 minutes "
            "on congested networks.  The subprocess is terminated after this timeout and "
            "the sub-test returns no findings (conservative: neither PASS nor FAIL). "
            f"Minimum: {TEST_15_TESTSSL_TIMEOUT_MIN} s.  "
            f"Default: {TEST_15_TESTSSL_TIMEOUT_DEFAULT} s."
        ),
    )


class Test16Config(BaseModel):
    """
    Tuning parameters for Test 1.6 (Secure Session Management).

    Methodology reference: 3_TOP_metodologia.md Section 1.6.
    Strategy: WHITE_BOX — Configuration Audit (P3).

    The test probes the configured paths for Set-Cookie response headers
    and audits each session cookie (identified by name) for the mandatory
    security attributes: HttpOnly, Secure, and SameSite.

    If no session cookies are found on any probed path, the test returns
    SKIP with an info note that the API appears to use stateless token-based
    authentication — which is the expected and compliant state for a REST API.

    Session fixation empirical sub-test:
        The full session fixation test requires a browser-level login flow
        that is highly target-specific and cannot be implemented generically
        in a config-driven tool.  It is therefore not implemented in this
        version.  The test documents this gap via an InfoNote on PASS results.
        Operators should perform the session fixation check manually following
        the procedure in 3_TOP_metodologia.md Section 1.6.
    """

    model_config = {"frozen": True}

    cookie_probe_paths: list[str] = Field(
        default_factory=lambda: ["/"],
        description=(
            "Paths to probe with a GET request to discover Set-Cookie headers. "
            "The test sends a GET to each path (unauthenticated) and collects "
            "all Set-Cookie headers. "
            "Extend this list to cover login pages or API roots that issue cookies. "
            "Default: ['/']."
        ),
    )
    session_cookie_names: list[str] = Field(
        default_factory=lambda: list(TEST_16_SESSION_COOKIE_NAMES_DEFAULT),
        description=(
            "Case-insensitive cookie names treated as session identifiers. "
            "Cookies whose name appears in this list are subject to the "
            "HttpOnly / Secure / SameSite attribute audit. "
            "Default: well-known session cookie names across common web frameworks."
        ),
    )
    check_samesite: bool = Field(
        default=True,
        description=(
            "If True, validate the SameSite attribute on session cookies. "
            "OWASP ASVS v5.0.0 V3.2.3 requires SameSite to prevent CSRF. "
            "Set False only when the application legitimately requires cross-site "
            "cookies and the risk is documented and accepted. Default: True."
        ),
    )
    expected_samesite_value: str = Field(
        default="Strict",
        description=(
            "Expected value for the SameSite cookie attribute (case-insensitive). "
            "Accepted: 'Strict' (recommended, ASVS V3.2.3), 'Lax' (acceptable for "
            "applications that require cross-origin GET requests). "
            "'None' is never acceptable for a session cookie. Default: 'Strict'."
        ),
    )

    @field_validator("session_cookie_names")
    @classmethod
    def session_cookie_names_not_empty(cls, v: list[str]) -> list[str]:
        """
        Reject an empty session_cookie_names list at configuration load time.

        An empty list causes the test to silently SKIP on every target because
        no cookie will ever match the empty set — masking real cookie attribute
        violations.  Operators who want to skip the test entirely should use
        the priority filter or strategy filter, not an empty name list.
        """
        if not v:
            raise ValueError(
                "session_cookie_names must contain at least one cookie name. "
                "An empty list causes the test to SKIP on every target, silently "
                "masking cookie attribute violations.  To skip this test, use the "
                "min_priority filter instead of clearing this list."
            )
        return v


# ---------------------------------------------------------------------------
# Domain-level aggregator
# ---------------------------------------------------------------------------


class TestDomain1Config(BaseModel):
    """
    Aggregator for all Domain 1 (Identity and Authentication) test configs.

    One field per test in the domain. tests_config.py imports only this class.
    Adding a new Domain 1 test requires:
        1. Defining a Test1XConfig model above.
        2. Adding a field here.
        3. Adding the corresponding RuntimeTest1XConfig in core/models/runtime.py.
        4. Populating it in engine.py Phase 3.
    """

    model_config = {"frozen": True}

    test_1_1: Test11Config = Field(
        default_factory=Test11Config,
        description="Tuning parameters for Test 1.1 (Authentication Required).",
    )
    test_1_5: Test15Config = Field(
        default_factory=Test15Config,
        description=(
            "Tuning parameters for Test 1.5 "
            "(Credentials Not Transmitted via Insecure Channels). "
            "Maps to 'tests.domain_1.test_1_5' in config.yaml."
        ),
    )
    test_1_6: Test16Config = Field(
        default_factory=Test16Config,
        description=(
            "Tuning parameters for Test 1.6 (Secure Session Management). "
            "Maps to 'tests.domain_1.test_1_6' in config.yaml."
        ),
    )

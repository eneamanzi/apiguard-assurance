"""
src/config/schema/domain_6.py

Pydantic v2 configuration models for Domain 6 (Configuration and Hardening) tests.

This module owns all per-test tuning parameters for tests 6.x.
It follows the same structural convention as domain_4.py: one *Config class
per test, aggregated by a TestDomain6Config class at the bottom.

Currently implemented tests:
    Test 6.2 -- Security Header Configuration Audit (WHITE_BOX, P3)
    Test 6.4 -- Hardcoded Credentials Audit (WHITE_BOX, P2)

Adding a new Domain 6 test requires:
    1. Defining a Test6XAuditConfig model in this file.
    2. Adding a field to TestDomain6Config below.
    3. Adding a RuntimeTest6XConfig mirror in core/models/runtime.py.
    4. Adding the population line in engine.py Phase 3.
    5. Adding the tests.domain_6.test_6_x block to config.yaml.

Dependency rule: imports only from pydantic and the stdlib.

Dependency rule: imports only from pydantic and the stdlib.
"""

from __future__ import annotations

from typing import Annotated

from pydantic import BaseModel, Field

# ---------------------------------------------------------------------------
# Constants -- Test 6.2
# ---------------------------------------------------------------------------

# ASVS V3.4.1: HSTS max-age must be at least 1 year (31 536 000 seconds).
TEST_62_HSTS_MIN_MAX_AGE_SECONDS_DEFAULT: int = 31_536_000
TEST_62_HSTS_MIN_MAX_AGE_SECONDS_MIN: int = 1

# How many endpoints to sample for cross-endpoint header consistency check.
# 0 = all endpoints (complete coverage, slower on large specs).
# Any positive integer caps the sample.
TEST_62_ENDPOINT_SAMPLE_SIZE_DEFAULT: int = 5
TEST_62_ENDPOINT_SAMPLE_SIZE_MIN: int = 0


# ---------------------------------------------------------------------------
# Test 6.2 -- Security Header Configuration Audit
# ---------------------------------------------------------------------------


class Test62AuditConfig(BaseModel):
    """
    Tuning parameters for Test 6.2 (Security Header Configuration Audit).

    The test verifies the presence and correctness of HTTP security headers
    that constitute defense-in-depth against client-side attacks, as defined
    by OWASP ASVS v5.0.0 V3.4 and Mozilla Observatory Security Headers Best
    Practices (methodology section 6.2).

    Checked headers and their oracles:
        Strict-Transport-Security  -- must contain 'max-age=' with value >=
                                      hsts_min_max_age_seconds (ASVS V3.4.1).
        X-Content-Type-Options     -- must be 'nosniff' (ASVS V3.4.4).
        X-Frame-Options            -- must be 'DENY' or 'SAMEORIGIN'; the
                                      deprecated 'ALLOW-FROM' value is a FAIL
                                      (ASVS V3.4.6).
        Content-Security-Policy    -- must be present and must NOT contain
                                      'default-src *' (ASVS V3.4.3).
        Permissions-Policy         -- must be present (any non-empty value).

    Leaky headers that must be absent (or version-free):
        X-Powered-By               -- always leaky.
        Server                     -- leaky only when it includes a version
                                      string (e.g. 'nginx/1.18.0').

    Consistency check:
        Headers are verified on a sample of endpoints.  Any endpoint whose
        header set differs from the reference (first sampled endpoint)
        produces an additional FAIL finding documenting the inconsistency.

    Design note -- why WHITE_BOX at P3:
        Security headers are static Gateway configuration.  They are not
        empirically testable in a meaningful security sense (presence of an
        HSTS header does not prove it was served under HTTPS, only that it
        was configured).  The methodology classifies them as P3 because a
        missing header is a compliance gap, not an exploitable vulnerability
        in the same sense as a missing auth check (P0) or a BOLA vector (P1).

    Design note -- no Admin API required:
        Unlike tests 4.2 and 4.3, this test does NOT require Admin API
        access.  It performs regular GET requests to the target's public
        endpoints and inspects the response headers.  The WHITE_BOX label
        reflects the configuration-audit nature of the check, not a
        dependency on internal API access.  The _requires_admin_api guard
        is intentionally NOT applied in the execute() method.
    """

    model_config = {"frozen": True}

    hsts_min_max_age_seconds: Annotated[
        int,
        Field(ge=TEST_62_HSTS_MIN_MAX_AGE_SECONDS_MIN),
    ] = Field(
        default=TEST_62_HSTS_MIN_MAX_AGE_SECONDS_DEFAULT,
        description=(
            "Minimum acceptable max-age value in the Strict-Transport-Security header. "
            "ASVS V3.4.1 requires max-age >= 31 536 000 (one year). "
            "An HSTS header present but with a lower max-age is flagged as a FAIL. "
            f"Default: {TEST_62_HSTS_MIN_MAX_AGE_SECONDS_DEFAULT} seconds (1 year)."
        ),
    )
    endpoint_sample_size: Annotated[
        int,
        Field(ge=TEST_62_ENDPOINT_SAMPLE_SIZE_MIN),
    ] = Field(
        default=TEST_62_ENDPOINT_SAMPLE_SIZE_DEFAULT,
        description=(
            "Number of endpoints to sample for cross-endpoint header consistency check. "
            "0 = all endpoints in the AttackSurface (complete coverage). "
            "Any positive integer caps the sample at that count, using the first N "
            "endpoints returned by the AttackSurface iterator. "
            "The consistency check compares each sampled endpoint's security headers "
            "against the reference set obtained from the first endpoint. "
            f"Default: {TEST_62_ENDPOINT_SAMPLE_SIZE_DEFAULT}."
        ),
    )


# ---------------------------------------------------------------------------
# Constants -- Test 6.4
# ---------------------------------------------------------------------------

# Default list of debug / actuator paths that may expose environment variables,
# configuration properties, or credentials when left accessible in production.
# Sources: methodology section 6.4, OWASP ASVS v5.0.0 V13.3.1, CWE-798.
#
# Operators should extend this list with stack-specific paths
# (e.g. Laravel Telescope, Django debug toolbar) using config.yaml.
TEST_64_DEBUG_ENDPOINT_PATHS_DEFAULT: list[str] = [
    "/actuator/env",
    "/actuator/configprops",
    "/actuator/health",
    "/debug/vars",
    "/debug/pprof",
    "/api/config",
    "/admin/config",
    "/_debug",
    "/api/debug/users",
    "/api/debug/config",
]

# HTTP methods accepted as successful responses when probing debug endpoints.
# A 200 OK on any of these paths is the worst case; 401/403 are the desired
# outcomes.
TEST_64_EXPECTED_BLOCKED_STATUS_DEFAULT: int = 401


# ---------------------------------------------------------------------------
# Test 6.4 -- Hardcoded Credentials Audit
# ---------------------------------------------------------------------------


class Test64AuditConfig(BaseModel):
    """
    Tuning parameters for Test 6.4 (Hardcoded Credentials Audit).

    The test verifies that service credentials are not hardcoded in:
      (a) Debug / actuator endpoints accessible from the network: probed
          empirically via unauthenticated GET.  Any 2xx response whose body
          contains credential-like patterns is a FAIL.
      (b) Kong Admin API -- service URLs and plugin configs: audited via
          the Kong Admin API when available.  Credential-like values in
          service URL fields or plugin config dictionaries are a FAIL.

    Design note -- degraded-run behaviour:
        Sub-test (a) always executes regardless of Admin API availability.
        Sub-test (b) executes only when target.admin_api_available is True.
        When the Admin API is absent, the test adds an InfoNote documenting
        the audit gap rather than returning SKIP entirely.  This avoids
        silently missing the empirical exposure that is verifiable
        without Admin API access.

    References: OWASP ASVS v5.0.0 V13.3.1 + V13.3.4 + V13.4.1, CWE-798,
    NIST SP 800-53 Rev. 5 IA-5(1), NIST SP 800-204 Section 5.4,
    methodology section 6.4.
    """

    model_config = {"frozen": True}

    debug_endpoint_paths: list[str] = Field(
        default_factory=lambda: list(TEST_64_DEBUG_ENDPOINT_PATHS_DEFAULT),
        description=(
            "List of paths to probe for debug / actuator endpoint exposure. "
            "Each path is probed with an unauthenticated GET request. "
            "A 2xx response whose body contains credential-like patterns is a FAIL. "
            "Extend this list with stack-specific debug paths in config.yaml "
            "(e.g. Laravel Telescope: '/_ignition/health-check', "
            "Django Silk: '/silk/summary/'). "
            "Removing paths from the default list narrows coverage. "
            f"Default: {TEST_64_DEBUG_ENDPOINT_PATHS_DEFAULT}."
        ),
    )
    gateway_block_body_fragment: str = Field(
        default="no Route matched with those values",
        description=(
            "A substring present in the response body of a non-2xx reply produced "
            "by the Gateway itself (deny-by-default), as opposed to a reply forwarded "
            "to and rejected by the upstream application. "
            "Used to distinguish oracle states ENDPOINT_BLOCKED (Gateway) from "
            "ENDPOINT_BLOCKED_BY_APP (application) in the audit trail. "
            "Default is specific to Kong DB-less 3.x. "
            "Override for other gateways: "
            "  Traefik:          '404 page not found' "
            "  AWS API Gateway:  'Missing Authentication Token' "
            "  Nginx:            '<title>404 Not Found</title>' "
            "  HAProxy:          '503 Service Unavailable'. "
            "Set to an empty string to disable the distinction entirely "
            "(all non-2xx responses will be classified as ENDPOINT_BLOCKED)."
        ),
    )


# ---------------------------------------------------------------------------
# Domain-level aggregator
# ---------------------------------------------------------------------------


class TestDomain6Config(BaseModel):
    """
    Aggregator for all Domain 6 (Configuration and Hardening) test configs.

    One field per implemented test in the domain.  tests_config.py imports
    only this class.  The default_factory for each field means operator
    override in config.yaml is optional: omitting the block entirely uses
    methodology-compliant defaults.
    """

    model_config = {"frozen": True}

    test_6_2: Test62AuditConfig = Field(
        default_factory=Test62AuditConfig,
        description=(
            "Audit parameters for Test 6.2 (Security Header Configuration Audit). "
            "Maps to 'tests.domain_6.test_6_2' in config.yaml."
        ),
    )
    test_6_4: Test64AuditConfig = Field(
        default_factory=Test64AuditConfig,
        description=(
            "Audit parameters for Test 6.4 (Hardcoded Credentials Audit). "
            "Maps to 'tests.domain_6.test_6_4' in config.yaml."
        ),
    )

"""
src/config/schema/domain_3.py

Pydantic v2 configuration models for Domain 3 (Message Integrity and Cryptographic Controls) tests.

Adding a new Domain 3 test requires:
    1. Defining a Test3XConfig model in this file.
    2. Adding a field to TestDomain3Config below.
    3. Adding a RuntimeTest3XConfig mirror in core/models/runtime.py.
    4. Adding the population line in engine.py Phase 3.
    5. Adding the tests.domain_3.test_3_X block to config.yaml.

Dependency rule: imports only from pydantic and the stdlib.
"""

from __future__ import annotations

from typing import Annotated

from pydantic import BaseModel, Field

# ---------------------------------------------------------------------------
# Constants — named, never inline
# ---------------------------------------------------------------------------

TEST_33_MAX_CLOCK_SKEW_SECONDS_DEFAULT: int = 300
TEST_33_MAX_CLOCK_SKEW_SECONDS_MIN: int = 1

# Default algorithms treated as forbidden.
# hmac-md5: cryptographically broken (MD5 collision attacks, RFC 6151).
# hmac-sha1: deprecated per NIST SP 800-131A Rev. 2 (2019) for signature use;
#   not broken in the HMAC construction, but excluded from modern TLS cipher
#   suites and flagged by PCI-DSS v4 Requirement 12.3.3.
_TEST_33_FORBIDDEN_ALGORITHMS_DEFAULT: list[str] = ["hmac-sha1", "hmac-md5"]

# Default list of gateway plugin names that implement HMAC request authentication.
# The test searches for the first plugin whose name appears in this list.
# Kong OSS: "hmac-auth" (built-in, included by default).
# Override this list when testing a gateway that exposes the same control
# under a different plugin name (e.g. a custom plugin or an enterprise variant).
_TEST_33_PLUGIN_NAMES_DEFAULT: list[str] = ["hmac-auth"]

# Default field names in the HMAC plugin configuration object as returned
# by the gateway Admin API.  These match Kong's hmac-auth schema.
# Override when the gateway uses a different JSON field layout.
TEST_33_FIELD_CLOCK_SKEW_DEFAULT: str = "clock_skew"
TEST_33_FIELD_ALGORITHMS_DEFAULT: str = "algorithms"
TEST_33_FIELD_VALIDATE_BODY_DEFAULT: str = "validate_request_body"

# Sentinel integer that the gateway uses to represent "no clock_skew limit
# configured" (effectively an unlimited replay window).  Kong uses 0.
TEST_33_CLOCK_SKEW_UNCONFIGURED_VALUE_DEFAULT: int = 0


# ---------------------------------------------------------------------------
# Per-test config model
# ---------------------------------------------------------------------------


class Test33Config(BaseModel):
    """
    Tuning parameters for Test 3.3 (HMAC Authentication Configuration Audit).

    Audits the gateway HMAC authentication plugin configuration for replay-attack
    exposure (clock_skew oracle) and weak algorithm usage (forbidden_algorithms
    oracle).  All gateway-specific identifiers (plugin names, Admin API field
    names) are configurable so the test works against any gateway that exposes
    an HMAC plugin via an Admin API following a Kong-compatible schema.

    References:
        - NIST SP 800-107 Rev. 1 Section 5.3.2: clock-skew window for HMAC-based
          timestamp validation should not exceed 5 minutes (300 seconds).
        - RFC 2104 Section 3: HMAC security does not degrade over time, but
          replay prevention is the caller's responsibility.
        - NIST SP 800-131A Rev. 2 (2019): SHA-1 deprecated for digital signatures;
          HMAC-SHA1 still provides integrity but is excluded from modern profiles.
        - RFC 6151: MD5 considered broken for cryptographic use; HMAC-MD5 must not
          be used in new security-sensitive applications.
        - OWASP ASVS v5.0.0 V2.9.1: HMAC keys must be generated using a CSPRNG,
          minimum 128 bits; weak algorithms prohibited.
    """

    model_config = {"frozen": True}

    # --- Oracle thresholds (security policy) --------------------------------

    max_clock_skew_seconds: Annotated[
        int,
        Field(ge=TEST_33_MAX_CLOCK_SKEW_SECONDS_MIN),
    ] = Field(
        default=TEST_33_MAX_CLOCK_SKEW_SECONDS_DEFAULT,
        description=(
            "Maximum acceptable clock_skew value (in seconds) for the HMAC plugin. "
            "A larger window increases the replay-attack surface: an attacker who "
            "captures a signed request can replay it until the window expires. "
            "NIST SP 800-107 Rev. 1 Section 5.3.2 recommends <= 300 s (5 minutes). "
            f"Default: {TEST_33_MAX_CLOCK_SKEW_SECONDS_DEFAULT}."
        ),
    )

    forbidden_algorithms: list[str] = Field(
        default_factory=lambda: list(_TEST_33_FORBIDDEN_ALGORITHMS_DEFAULT),
        description=(
            "HMAC algorithms whose presence in the plugin's algorithm list "
            "constitutes a security finding. "
            "'hmac-md5': cryptographically broken (RFC 6151); must never be used. "
            "'hmac-sha1': deprecated per NIST SP 800-131A Rev. 2 and PCI-DSS v4 "
            "Requirement 12.3.3; acceptable to remove from this list only if the "
            "deployment has a documented exception. "
            "Default: ['hmac-sha1', 'hmac-md5']."
        ),
    )

    # --- Gateway-specific identifiers (agnosticism layer) -------------------

    plugin_names: list[str] = Field(
        default_factory=lambda: list(_TEST_33_PLUGIN_NAMES_DEFAULT),
        description=(
            "Ordered list of gateway plugin names that implement HMAC request "
            "authentication.  The test iterates the Admin API plugin list and "
            "returns the first plugin whose name appears in this list. "
            "Kong OSS default: ['hmac-auth']. "
            "Override for gateways or custom plugins that use a different name "
            "(e.g. ['hmac-authentication', 'request-signer']). "
            "An empty list causes the test to SKIP immediately with an InfoNote."
        ),
    )

    field_clock_skew: str = Field(
        default=TEST_33_FIELD_CLOCK_SKEW_DEFAULT,
        description=(
            "JSON field name in the HMAC plugin's 'config' object that controls "
            "the replay-attack time window.  Kong hmac-auth default: 'clock_skew'. "
            "Override when the gateway plugin uses a different field name "
            "(e.g. 'timestamp_tolerance', 'replay_window_seconds')."
        ),
    )

    field_algorithms: str = Field(
        default=TEST_33_FIELD_ALGORITHMS_DEFAULT,
        description=(
            "JSON field name in the HMAC plugin's 'config' object that lists the "
            "allowed HMAC algorithms.  Kong hmac-auth default: 'algorithms'. "
            "Override when the gateway uses a different field name "
            "(e.g. 'allowed_algorithms', 'hmac_algorithms')."
        ),
    )

    field_validate_body: str = Field(
        default=TEST_33_FIELD_VALIDATE_BODY_DEFAULT,
        description=(
            "JSON field name in the HMAC plugin's 'config' object that controls "
            "whether the request body is covered by the HMAC signature. "
            "Kong hmac-auth default: 'validate_request_body'. "
            "Override when the gateway uses a different field name "
            "(e.g. 'body_integrity', 'sign_body')."
        ),
    )

    clock_skew_unconfigured_value: int = Field(
        default=TEST_33_CLOCK_SKEW_UNCONFIGURED_VALUE_DEFAULT,
        description=(
            "Integer sentinel value that the gateway uses in the clock_skew field "
            "to signal 'no limit configured' (unlimited replay window). "
            "Kong hmac-auth default: 0.  When the field equals this sentinel, "
            "the test raises a Finding regardless of max_clock_skew_seconds because "
            "replay protection is effectively disabled."
        ),
    )


# ---------------------------------------------------------------------------
# Domain-level aggregator — one field per implemented test
# ---------------------------------------------------------------------------


class TestDomain3Config(BaseModel):
    """
    Aggregator for all Domain 3 (Message Integrity and Cryptographic Controls) test configs.

    tests_config.py imports only this class. default_factory on each field
    makes the entire block optional in config.yaml.
    """

    model_config = {"frozen": True}

    test_3_3: Test33Config = Field(
        default_factory=Test33Config,
        description=(
            "Tuning parameters for Test 3.3 (HMAC Authentication Configuration Audit). "
            "Maps to 'tests.domain_3.test_3_3' in config.yaml."
        ),
    )

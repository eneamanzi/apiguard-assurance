"""
src/config/schema/domain_4.py

Pydantic v2 configuration models for Domain 4 (Availability and Resilience) tests.

This module is part of the config/schema/ package refactoring. It owns all
per-test tuning parameters for tests 4.x.

Migration note -- Test41ProbeConfig (ex RateLimitProbeConfig):
    The former RateLimitProbeConfig lived at the root of ToolConfig in
    schema.py (alongside 'target', 'credentials', etc.) and mapped to a
    top-level 'rate_limit_probe:' key in config.yaml. This was architecturally
    wrong: rate-limit probe parameters are test-specific tuning, not tool-level
    infrastructure settings. They now live here as Test41ProbeConfig, nested
    under 'tests.domain_4.test_4_1' in config.yaml, consistent with how 4.2
    and 4.3 are already structured.

    Downstream impact:
        engine.py Phase 3: read from config.tests.domain_4.test_4_1
                           (previously config.rate_limit_probe).
        config.yaml: replace root 'rate_limit_probe:' block with
                     'tests.domain_4.test_4_1:' block.

Dependency rule: imports only from pydantic and the stdlib.
"""

from __future__ import annotations

from typing import Annotated

from pydantic import BaseModel, Field, model_validator

# ---------------------------------------------------------------------------
# Constants -- Test 4.1
# ---------------------------------------------------------------------------

TEST_41_MAX_REQUESTS_DEFAULT: int = 150
TEST_41_MAX_REQUESTS_MIN: int = 10
TEST_41_MAX_REQUESTS_MAX: int = 500

TEST_41_INTERVAL_MS_DEFAULT: int = 50
TEST_41_INTERVAL_MS_MIN: int = 10
TEST_41_INTERVAL_MS_MAX: int = 5_000

# ---------------------------------------------------------------------------
# Constants -- Test 4.2
# ---------------------------------------------------------------------------

# Oracle thresholds from methodology section 4.2 (NIST SP 800-204A Section 4.3).
# Kong stores all timeout values as plain integers in milliseconds.
TEST_42_MAX_CONNECT_TIMEOUT_MS_DEFAULT: int = 5_000
TEST_42_MAX_READ_TIMEOUT_MS_DEFAULT: int = 30_000
TEST_42_MAX_WRITE_TIMEOUT_MS_DEFAULT: int = 30_000

# ---------------------------------------------------------------------------
# Constants -- Test 4.3
# ---------------------------------------------------------------------------

# Methodology range for circuit-breaker parameter validation (Martin Fowler CB Pattern).
TEST_43_FAILURE_THRESHOLD_MIN_DEFAULT: int = 3
TEST_43_FAILURE_THRESHOLD_MAX_DEFAULT: int = 10
TEST_43_TIMEOUT_DURATION_MIN_SECONDS_DEFAULT: int = 30
TEST_43_TIMEOUT_DURATION_MAX_SECONDS_DEFAULT: int = 120

# Passive healthcheck compensating control thresholds (Level 2 check).
TEST_43_PASSIVE_HC_MAX_HTTP_FAILURES_DEFAULT: int = 10
TEST_43_PASSIVE_HC_MAX_TCP_FAILURES_DEFAULT: int = 10
TEST_43_PASSIVE_HC_MAX_TIMEOUTS_DEFAULT: int = 10

# ---------------------------------------------------------------------------
# Test 4.1 -- Rate Limiting Probe
# ---------------------------------------------------------------------------


class Test41ProbeConfig(BaseModel):
    """
    Tuning parameters for Test 4.1 (Rate Limiting -- Resource Exhaustion Prevention).

    Controls the empirical rate-limit discovery probe: how many requests to
    send and at what interval before concluding that rate limiting is absent.

    Design note -- conservative defaults:
        The defaults (150 requests, 50 ms interval) are deliberately conservative
        to avoid triggering security alerts or filling audit logs on the target.
        The test sends requests in a tight loop; a 50 ms interval means the full
        probe takes at most 7.5 seconds -- acceptable for an automated assessment.
        Increase max_requests only on targets with very high rate-limit thresholds
        (e.g. 1000 req/min) that the default budget would not reach.
    """

    model_config = {"frozen": True}

    max_requests: Annotated[
        int,
        Field(ge=TEST_41_MAX_REQUESTS_MIN, le=TEST_41_MAX_REQUESTS_MAX),
    ] = Field(
        default=TEST_41_MAX_REQUESTS_DEFAULT,
        description=(
            "Maximum probe requests sent before concluding rate limiting is absent. "
            f"Range: [{TEST_41_MAX_REQUESTS_MIN}, {TEST_41_MAX_REQUESTS_MAX}]. "
            f"Default: {TEST_41_MAX_REQUESTS_DEFAULT}."
        ),
    )
    request_interval_ms: Annotated[
        int,
        Field(ge=TEST_41_INTERVAL_MS_MIN, le=TEST_41_INTERVAL_MS_MAX),
    ] = Field(
        default=TEST_41_INTERVAL_MS_DEFAULT,
        description=(
            "Interval in milliseconds between consecutive probe requests. "
            f"Range: [{TEST_41_INTERVAL_MS_MIN}, {TEST_41_INTERVAL_MS_MAX}]. "
            f"Default: {TEST_41_INTERVAL_MS_DEFAULT} ms."
        ),
    )

    @property
    def request_interval_seconds(self) -> float:
        """Convert request_interval_ms to seconds for use in time.sleep() calls."""
        return self.request_interval_ms / 1000.0


# ---------------------------------------------------------------------------
# Test 4.2 -- Timeout Configuration Audit
# ---------------------------------------------------------------------------


class Test42AuditConfig(BaseModel):
    """
    Tuning parameters for Test 4.2 (Timeout Configuration Audit).

    Oracle thresholds are taken directly from the methodology (section 4.2,
    NIST SP 800-204A Section 4.3):
        connect_timeout  <= 5 000 ms  (5 s)
        read_timeout     <= 30 000 ms (30 s)
        write_timeout    <= 30 000 ms (30 s)

    Kong stores all timeout values in milliseconds as plain integers.
    Adjust these only when the target gateway is intentionally configured
    with different timeouts and the deviation is accepted as a documented risk.
    """

    model_config = {"frozen": True}

    max_connect_timeout_ms: Annotated[int, Field(ge=1)] = Field(
        default=TEST_42_MAX_CONNECT_TIMEOUT_MS_DEFAULT,
        description=(
            "Maximum acceptable Kong service connect_timeout in milliseconds. "
            "Methodology oracle: connect_timeout <= 5 000 ms (NIST SP 800-204A Section 4.3). "
            "Services with a higher value will produce a FAIL finding."
        ),
    )
    max_read_timeout_ms: Annotated[int, Field(ge=1)] = Field(
        default=TEST_42_MAX_READ_TIMEOUT_MS_DEFAULT,
        description=(
            "Maximum acceptable Kong service read_timeout in milliseconds. "
            "Methodology oracle: read_timeout <= 30 000 ms (NIST SP 800-204A Section 4.3). "
            "Services with a higher value will produce a FAIL finding."
        ),
    )
    max_write_timeout_ms: Annotated[int, Field(ge=1)] = Field(
        default=TEST_42_MAX_WRITE_TIMEOUT_MS_DEFAULT,
        description=(
            "Maximum acceptable Kong service write_timeout in milliseconds. "
            "Methodology oracle: write_timeout <= 30 000 ms. "
            "Services with a higher value will produce a FAIL finding."
        ),
    )


# ---------------------------------------------------------------------------
# Test 4.3 -- Circuit Breaker Configuration Audit
# ---------------------------------------------------------------------------


class Test43AuditConfig(BaseModel):
    """
    Tuning parameters for Test 4.3 (Circuit Breaker Configuration Audit).

    The test implements a Dual-Check a 3 Livelli strategy to handle the Kong OSS
    constraint (no native circuit-breaker plugin):

        LEVEL 1 -- Native plugin check.
            Searches for a plugin in accepted_cb_plugin_names.
            NOTE: 'response-ratelimiting' is intentionally excluded from the
            default list: it manages request volumes, not cascading failures.
            It does not implement the CLOSED/OPEN/HALF-OPEN state machine and
            cannot prevent thundering-herd scenarios. Only genuine circuit-breaker
            plugins belong here. On Kong OSS DB-less the expected Level 1 result
            is 'no plugin found'; execution continues to Level 2.

        LEVEL 2 -- Compensating control via upstream passive healthchecks.
            If no native plugin is found, the test inspects all Kong upstreams
            for a configured passive healthcheck (healthchecks.passive.unhealthy
            with at least one non-zero failure counter). A properly configured
            passive healthcheck allows Kong to remove a degrading backend from
            the upstream pool, approximating circuit-breaker behaviour at the
            load-balancer layer. The test returns PASS with an informational
            Finding documenting the compensating control.

        LEVEL 3 -- Vulnerable.
            Neither native plugin nor upstream passive healthcheck found.
            Returns FAIL with a gap-documenting Finding.

        Observability (always runs, independent).
            Checks /status for circuit-breaker metrics. Always produces an
            informational Finding on Kong OSS (these metrics are absent).

    failure_threshold_* and timeout_duration_* parameters govern Level 1
    parameter validation. passive_hc_max_* parameters govern Level 2.
    """

    model_config = {"frozen": True}

    # ------------------------------------------------------------------
    # Level 1 -- native CB plugin
    # ------------------------------------------------------------------

    accepted_cb_plugin_names: list[str] = Field(
        default_factory=lambda: ["circuit-breaker"],
        description=(
            "Kong plugin names accepted as native circuit-breaker equivalents. "
            "Evaluated in order; the first enabled match is used for parameter "
            "validation. 'circuit-breaker' is Kong Enterprise only. "
            "Do NOT add 'response-ratelimiting': it manages request volumes, not "
            "cascading failures, and does not implement the CB state machine. "
            "Extend this list only when a true custom or third-party CB plugin "
            "is deployed (e.g., a Lua-based state machine plugin)."
        ),
    )
    failure_threshold_min: Annotated[int, Field(ge=1)] = Field(
        default=TEST_43_FAILURE_THRESHOLD_MIN_DEFAULT,
        description=(
            "Minimum acceptable failure threshold to open the circuit. "
            "Methodology range: [3, 10] consecutive failures. "
            "A threshold below this minimum is too sensitive (alert fatigue)."
        ),
    )
    failure_threshold_max: Annotated[int, Field(ge=1)] = Field(
        default=TEST_43_FAILURE_THRESHOLD_MAX_DEFAULT,
        description=(
            "Maximum acceptable failure threshold to open the circuit. "
            "Methodology range: [3, 10] consecutive failures. "
            "A threshold above this maximum leaves the system exposed too long."
        ),
    )
    timeout_duration_min_seconds: Annotated[int, Field(ge=1)] = Field(
        default=TEST_43_TIMEOUT_DURATION_MIN_SECONDS_DEFAULT,
        description=(
            "Minimum acceptable Open-state duration in seconds before Half-Open probe. "
            "Methodology range: [30, 120] s (Martin Fowler Circuit Breaker Pattern). "
            "A shorter window may not allow the downstream service to recover."
        ),
    )
    timeout_duration_max_seconds: Annotated[int, Field(ge=1)] = Field(
        default=TEST_43_TIMEOUT_DURATION_MAX_SECONDS_DEFAULT,
        description=(
            "Maximum acceptable Open-state duration in seconds before Half-Open probe. "
            "Methodology range: [30, 120] s. "
            "A longer window unnecessarily degrades availability."
        ),
    )

    # ------------------------------------------------------------------
    # Level 2 -- passive healthcheck compensating control thresholds
    # ------------------------------------------------------------------

    passive_hc_max_http_failures: Annotated[int, Field(ge=1)] = Field(
        default=TEST_43_PASSIVE_HC_MAX_HTTP_FAILURES_DEFAULT,
        description=(
            "Maximum acceptable value for unhealthy.http_failures in a Kong upstream "
            "passive healthcheck. A passive HC is considered active when this counter "
            "is > 0 (Kong default is 0 = disabled). Acceptable range: [1, this value]. "
            "Values above the maximum indicate an overly permissive threshold."
        ),
    )
    passive_hc_max_tcp_failures: Annotated[int, Field(ge=1)] = Field(
        default=TEST_43_PASSIVE_HC_MAX_TCP_FAILURES_DEFAULT,
        description=(
            "Maximum acceptable value for unhealthy.tcp_failures in a Kong upstream "
            "passive healthcheck. Same semantics as passive_hc_max_http_failures "
            "but for TCP-level connection failures."
        ),
    )
    passive_hc_max_timeouts: Annotated[int, Field(ge=1)] = Field(
        default=TEST_43_PASSIVE_HC_MAX_TIMEOUTS_DEFAULT,
        description=(
            "Maximum acceptable value for unhealthy.timeouts in a Kong upstream "
            "passive healthcheck. Same semantics as passive_hc_max_http_failures "
            "but for upstream response timeouts."
        ),
    )

    @model_validator(mode="after")
    def validate_threshold_range_coherence(self) -> Test43AuditConfig:
        """Ensure min <= max for Level 1 parameter ranges."""
        if self.failure_threshold_min > self.failure_threshold_max:
            raise ValueError(
                f"failure_threshold_min ({self.failure_threshold_min}) must be "
                f"<= failure_threshold_max ({self.failure_threshold_max})."
            )
        if self.timeout_duration_min_seconds > self.timeout_duration_max_seconds:
            raise ValueError(
                f"timeout_duration_min_seconds ({self.timeout_duration_min_seconds}) must be "
                f"<= timeout_duration_max_seconds ({self.timeout_duration_max_seconds})."
            )
        return self


# ---------------------------------------------------------------------------
# Domain-level aggregator
# ---------------------------------------------------------------------------


class TestDomain4Config(BaseModel):
    """
    Aggregator for all Domain 4 (Availability and Resilience) test configs.

    One field per test in the domain. tests_config.py imports only this class.
    Adding a new Domain 4 test requires:
        1. Defining a Test4XAuditConfig/ProbeConfig model above.
        2. Adding a field here.
        3. Adding the corresponding RuntimeTest4XConfig in core/models/runtime.py.
        4. Populating it in engine.py Phase 3.
    """

    model_config = {"frozen": True}

    test_4_1: Test41ProbeConfig = Field(
        default_factory=Test41ProbeConfig,
        description=(
            "Probe parameters for Test 4.1 (Rate Limiting -- Resource Exhaustion Prevention). "
            "Maps to 'tests.domain_4.test_4_1' in config.yaml."
        ),
    )
    test_4_2: Test42AuditConfig = Field(
        default_factory=Test42AuditConfig,
        description="Oracle thresholds for Test 4.2 (Timeout Configuration Audit).",
    )
    test_4_3: Test43AuditConfig = Field(
        default_factory=Test43AuditConfig,
        description=(
            "Accepted plugins and parameter ranges for Test 4.3 (Circuit Breaker Audit)."
        ),
    )

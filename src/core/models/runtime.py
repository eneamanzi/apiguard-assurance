"""
src/core/models/runtime.py

Runtime configuration models for the APIGuard Assurance tool.

Contains the immutable credential and per-test parameter snapshots that
are propagated into TargetContext by the engine during Phase 3, and
consumed by test implementations via target.tests_config and
target.credentials.

    RuntimeCredentials      -- Immutable credentials propagated to TargetContext.
    RuntimeTest11Config     -- Runtime mirror of TestDomain1Config fields for Test 1.1.
    RuntimeTest41Config     -- Runtime mirror of Test41ProbeConfig for Test 4.1.
    RuntimeTest42Config     -- Runtime mirror of Test42AuditConfig for Test 4.2.
    RuntimeTest43Config     -- Runtime mirror of Test43AuditConfig for Test 4.3.
    RuntimeTestsConfig      -- Immutable container for all per-test runtime configs.

Design rationale:
    Runtime*Config models live in core/ (not config/) so TargetContext can
    reference them without importing from config/. This preserves the
    unidirectional dependency rule: config/ imports core/, never the reverse.

    Each RuntimeTest*Config mirrors only the fields that the corresponding
    test actually reads at runtime. Adding a new test requires adding one
    field to RuntimeTestsConfig and one population line in engine.py Phase 3.

Dependency rule: this module imports only from pydantic and the stdlib.
It must never import from any other src/ module.
"""

from __future__ import annotations

from pydantic import BaseModel, Field

# ---------------------------------------------------------------------------
# RuntimeCredentials — immutable credentials propagated to TargetContext
# ---------------------------------------------------------------------------


class RuntimeCredentials(BaseModel):
    """
    Immutable snapshot of credentials propagated into TargetContext.

    Lives in core/ so TargetContext can reference it without importing from
    config/ (unidirectional dependency rule: config/ imports core/, never reverse).
    """

    model_config = {"frozen": True}

    admin_username: str | None = Field(default=None)
    admin_password: str | None = Field(default=None)
    user_a_username: str | None = Field(default=None)
    user_a_password: str | None = Field(default=None)
    user_b_username: str | None = Field(default=None)
    user_b_password: str | None = Field(default=None)

    def has_admin(self) -> bool:
        """True if both admin_username and admin_password are present and non-empty."""
        return bool(
            self.admin_username
            and self.admin_username.strip()
            and self.admin_password
            and self.admin_password.strip()
        )

    def has_user_a(self) -> bool:
        """True if both user_a_username and user_a_password are present and non-empty."""
        return bool(
            self.user_a_username
            and self.user_a_username.strip()
            and self.user_a_password
            and self.user_a_password.strip()
        )

    def has_user_b(self) -> bool:
        """True if both user_b_username and user_b_password are present and non-empty."""
        return bool(
            self.user_b_username
            and self.user_b_username.strip()
            and self.user_b_password
            and self.user_b_password.strip()
        )

    def has_any_grey_box_credentials(self) -> bool:
        """True if at least one role has complete credentials configured."""
        return self.has_admin() or self.has_user_a() or self.has_user_b()

    def available_roles(self) -> list[str]:
        """
        Return the list of role names with complete credentials configured.

        Role name strings match ROLE_* constants in context.py.
        Local import avoided here to prevent a circular dependency.
        """
        roles: list[str] = []
        if self.has_admin():
            roles.append("admin")
        if self.has_user_a():
            roles.append("user_a")
        if self.has_user_b():
            roles.append("user_b")
        return roles


# ---------------------------------------------------------------------------
# RuntimeTest11Config — runtime parameters for Test 1.1
# ---------------------------------------------------------------------------


class RuntimeTest11Config(BaseModel):
    """Runtime mirror of TestDomain1Config fields consumed by Test 1.1."""

    model_config = {"frozen": True}

    max_endpoints_cap: int = Field(
        default=0,
        ge=0,
        description=(
            "Maximum protected endpoints to probe in Test 1.1. "
            "0 = probe all (recommended for academic completeness). "
            "Mirrors TestDomain1Config.max_endpoints_cap from config/schema.py."
        ),
    )


# ---------------------------------------------------------------------------
# RuntimeTest41Config — runtime parameters for Test 4.1
# ---------------------------------------------------------------------------


class RuntimeTest41Config(BaseModel):
    """
    Runtime mirror of Test41ProbeConfig fields consumed by Test 4.1.

    Mirrors config/schema/domain_4.py:Test41ProbeConfig, nested under
    config.tests.domain_4.test_4_1 in config.yaml (previously at the
    root level as 'rate_limit_probe' -- migrated in schema refactoring).

    Access pattern in the test:
        target.tests_config.test_4_1.max_requests
        target.tests_config.test_4_1.request_interval_seconds
    """

    model_config = {"frozen": True}

    max_requests: int = Field(
        default=150,
        ge=1,
        description=(
            "Maximum probe requests sent before concluding rate limiting is absent. "
            "Mirrors Test41ProbeConfig.max_requests. Default: 150."
        ),
    )
    request_interval_ms: int = Field(
        default=50,
        ge=10,
        description=(
            "Interval in milliseconds between consecutive probe requests. "
            "Mirrors Test41ProbeConfig.request_interval_ms. Default: 50ms."
        ),
    )

    @property
    def request_interval_seconds(self) -> float:
        """Convert request_interval_ms to seconds for use in time.sleep() calls."""
        return self.request_interval_ms / 1000.0


# ---------------------------------------------------------------------------
# RuntimeTest42Config — runtime parameters for Test 4.2
# ---------------------------------------------------------------------------


class RuntimeTest42Config(BaseModel):
    """
    Runtime mirror of Test42AuditConfig fields consumed by Test 4.2.

    Stores the maximum acceptable timeout values (in milliseconds) for Kong
    service objects. Mirrored from config/schema.py:Test42AuditConfig, which
    is nested under config.tests.domain_4.test_4_2.

    Access pattern in the test:
        target.tests_config.test_4_2.max_connect_timeout_ms
        target.tests_config.test_4_2.max_read_timeout_ms
        target.tests_config.test_4_2.max_write_timeout_ms
    """

    model_config = {"frozen": True}

    max_connect_timeout_ms: int = Field(
        default=5_000,
        ge=1,
        description=(
            "Maximum acceptable Kong service connect_timeout in milliseconds. "
            "Methodology oracle: <= 5 000 ms. Default: 5 000."
        ),
    )
    max_read_timeout_ms: int = Field(
        default=30_000,
        ge=1,
        description=(
            "Maximum acceptable Kong service read_timeout in milliseconds. "
            "Methodology oracle: <= 30 000 ms. Default: 30 000."
        ),
    )
    max_write_timeout_ms: int = Field(
        default=30_000,
        ge=1,
        description=(
            "Maximum acceptable Kong service write_timeout in milliseconds. "
            "Methodology oracle: <= 30 000 ms. Default: 30 000."
        ),
    )


# ---------------------------------------------------------------------------
# RuntimeTest43Config — runtime parameters for Test 4.3
# ---------------------------------------------------------------------------


class RuntimeTest43Config(BaseModel):
    """
    Runtime mirror of Test43AuditConfig fields consumed by Test 4.3.

    Stores all parameters needed by the Dual-Check a 3 Livelli strategy.
    Mirrored from config/schema.py:Test43AuditConfig, nested under
    config.tests.domain_4.test_4_3.

    Level 1 parameters (native CB plugin validation):
        accepted_cb_plugin_names, failure_threshold_min/max,
        timeout_duration_min/max_seconds.

    Level 2 parameters (upstream passive healthcheck oracle thresholds):
        passive_hc_max_http_failures, passive_hc_max_tcp_failures,
        passive_hc_max_timeouts.

    Access pattern in the test:
        target.tests_config.test_4_3.accepted_cb_plugin_names
        target.tests_config.test_4_3.failure_threshold_min
        target.tests_config.test_4_3.failure_threshold_max
        target.tests_config.test_4_3.timeout_duration_min_seconds
        target.tests_config.test_4_3.timeout_duration_max_seconds
        target.tests_config.test_4_3.passive_hc_max_http_failures
        target.tests_config.test_4_3.passive_hc_max_tcp_failures
        target.tests_config.test_4_3.passive_hc_max_timeouts
    """

    model_config = {"frozen": True}

    # ------------------------------------------------------------------
    # Level 1 -- native CB plugin parameter validation
    # ------------------------------------------------------------------

    accepted_cb_plugin_names: list[str] = Field(
        default_factory=lambda: ["circuit-breaker"],
        description=(
            "Kong plugin names considered equivalent to a native circuit breaker. "
            "The first enabled match drives parameter validation. "
            "Do NOT add 'response-ratelimiting': it manages request volumes, "
            "not cascading failures, and does not implement the CB state machine. "
            "Default: ['circuit-breaker'] (Kong Enterprise only)."
        ),
    )
    failure_threshold_min: int = Field(
        default=3,
        ge=1,
        description="Minimum acceptable consecutive-failure threshold to open circuit. Default: 3.",
    )
    failure_threshold_max: int = Field(
        default=10,
        ge=1,
        description="Maximum acceptable consecutive-failure threshold to open circuit. Default: 10.",  # noqa: E501
    )
    timeout_duration_min_seconds: int = Field(
        default=30,
        ge=1,
        description="Minimum acceptable Open-state duration in seconds. Default: 30.",
    )
    timeout_duration_max_seconds: int = Field(
        default=120,
        ge=1,
        description="Maximum acceptable Open-state duration in seconds. Default: 120.",
    )

    # ------------------------------------------------------------------
    # Level 2 -- upstream passive healthcheck oracle thresholds
    # ------------------------------------------------------------------

    passive_hc_max_http_failures: int = Field(
        default=10,
        ge=1,
        description=(
            "Maximum acceptable value for unhealthy.http_failures in a Kong upstream "
            "passive healthcheck. Values above this threshold are flagged as "
            "overly permissive. Default: 10."
        ),
    )
    passive_hc_max_tcp_failures: int = Field(
        default=10,
        ge=1,
        description=(
            "Maximum acceptable value for unhealthy.tcp_failures in a Kong upstream "
            "passive healthcheck. Same semantics as passive_hc_max_http_failures "
            "but for TCP-level connection failures. Default: 10."
        ),
    )
    passive_hc_max_timeouts: int = Field(
        default=10,
        ge=1,
        description=(
            "Maximum acceptable value for unhealthy.timeouts in a Kong upstream "
            "passive healthcheck. Same semantics as passive_hc_max_http_failures "
            "but for upstream response timeouts. Default: 10."
        ),
    )


# ---------------------------------------------------------------------------
# RuntimeTest62Config — runtime parameters for Test 6.2
# ---------------------------------------------------------------------------


class RuntimeTest62Config(BaseModel):
    """
    Runtime mirror of Test62AuditConfig fields consumed by Test 6.2.

    Stores the two tunable parameters for the Security Header Configuration
    Audit.  Mirrored from config/schema/domain_6.py:Test62AuditConfig,
    nested under config.tests.domain_6.test_6_2 in config.yaml.

    Access pattern in the test:
        target.tests_config.test_6_2.hsts_min_max_age_seconds
        target.tests_config.test_6_2.endpoint_sample_size
    """

    model_config = {"frozen": True}

    hsts_min_max_age_seconds: int = Field(
        default=31_536_000,
        ge=1,
        description=(
            "Minimum acceptable max-age value in the Strict-Transport-Security header. "
            "ASVS V3.4.1: max-age >= 31 536 000 (one year). Default: 31 536 000."
        ),
    )
    endpoint_sample_size: int = Field(
        default=5,
        ge=0,
        description=(
            "Number of endpoints to sample for cross-endpoint consistency check. "
            "0 = all endpoints. Default: 5."
        ),
    )


# ---------------------------------------------------------------------------
# RuntimeTestsConfig — immutable container for all per-test runtime configs
# ---------------------------------------------------------------------------


class RuntimeTestsConfig(BaseModel):
    """
    Immutable container for all per-test runtime configurations.

    Populated by engine.py in Phase 3 from config.tests and sibling
    config blocks. Stored in TargetContext and accessed by test
    implementations via target.tests_config.

    Convention: one field per test, named test_X_Y where X is the domain
    number and Y is the test number within that domain. Each field holds
    an immutable RuntimeTest{XY}Config model with only the parameters
    that specific test needs. This pattern scales cleanly as new tests
    are added: adding a test requires only adding one field here and
    one population line in engine.py Phase 3.

    Transaction log parameters are absent by design:
        transaction_log_max_entries_per_test -> removed (no cap needed with
            TransactionSummary's ~160-byte minimal model).
        transaction_log_preview_chars -> removed (no body content in summaries).
    """

    model_config = {"frozen": True}

    test_1_1: RuntimeTest11Config = Field(
        default_factory=RuntimeTest11Config,
        description="Runtime parameters for Test 1.1 (Authentication Required).",
    )
    test_4_1: RuntimeTest41Config = Field(
        default_factory=RuntimeTest41Config,
        description=(
            "Runtime parameters for Test 4.1 (Rate Limiting — Resource Exhaustion Prevention). "
            "Mirrors Test41ProbeConfig from config/schema/domain_4.py."
        ),
    )
    test_4_2: RuntimeTest42Config = Field(
        default_factory=RuntimeTest42Config,
        description=(
            "Runtime parameters for Test 4.2 (Timeout Configuration Audit). "
            "Mirrors Test42AuditConfig from config.tests.domain_4.test_4_2."
        ),
    )
    test_4_3: RuntimeTest43Config = Field(
        default_factory=RuntimeTest43Config,
        description=(
            "Runtime parameters for Test 4.3 (Circuit Breaker Configuration Audit). "
            "Mirrors Test43AuditConfig from config.tests.domain_4.test_4_3."
        ),
    )
    test_6_2: RuntimeTest62Config = Field(
        default_factory=RuntimeTest62Config,
        description=(
            "Runtime parameters for Test 6.2 (Security Header Configuration Audit). "
            "Mirrors Test62AuditConfig from config.tests.domain_6.test_6_2."
        ),
    )

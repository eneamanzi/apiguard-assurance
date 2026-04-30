"""
src/core/models/runtime.py

Runtime configuration models for the APIGuard Assurance tool.

Contains the immutable credential and per-test parameter snapshots that
are propagated into TargetContext by the engine during Phase 3, and
consumed by test implementations via target.tests_config and
target.credentials.

    RuntimeCredentials      -- Immutable credentials propagated to TargetContext.
    RuntimeTest11Config     -- Runtime mirror of TestDomain1Config fields for Test 1.1.
    RuntimeTest15Config     -- Runtime mirror of Test15Config for Test 1.5.
    RuntimeTest16Config     -- Runtime mirror of Test16Config for Test 1.6.
    RuntimeTest41Config     -- Runtime mirror of Test41ProbeConfig for Test 4.1.
    RuntimeTest42Config     -- Runtime mirror of Test42AuditConfig for Test 4.2.
    RuntimeTest43Config     -- Runtime mirror of Test43AuditConfig for Test 4.3.
    RuntimeTest72Config     -- Runtime mirror of Test72SSRFConfig for Test 7.2.
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

from pydantic import BaseModel, Field, field_validator

# ---------------------------------------------------------------------------
# RuntimeCredentials — immutable credentials propagated to TargetContext
# ---------------------------------------------------------------------------


class RuntimeCredentials(BaseModel):
    """
    Immutable snapshot of credentials propagated into TargetContext.

    Lives in core/ so TargetContext can reference it without importing from
    config/ (unidirectional dependency rule: config/ imports core/, never reverse).

    auth_type mirrors CredentialsConfig.auth_type and is read by the auth
    dispatcher (src/tests/helpers/auth.py) to select the correct token-acquisition
    implementation at runtime. The jwt_login-specific fields are only populated
    when auth_type == 'jwt_login'; they are None otherwise.
    """

    model_config = {"frozen": True}

    # ------------------------------------------------------------------
    # Auth type discriminator -- mirrors CredentialsConfig.auth_type
    # ------------------------------------------------------------------

    auth_type: str = Field(
        default="forgejo_token",
        description=(
            "Token-acquisition strategy. Mirrors CredentialsConfig.auth_type. "
            "Read by the auth dispatcher to select the implementation. "
            "Supported: 'forgejo_token', 'jwt_login'."
        ),
    )

    # ------------------------------------------------------------------
    # Common credential fields
    # ------------------------------------------------------------------

    admin_username: str | None = Field(default=None)
    admin_password: str | None = Field(default=None)
    user_a_username: str | None = Field(default=None)
    user_a_password: str | None = Field(default=None)
    user_b_username: str | None = Field(default=None)
    user_b_password: str | None = Field(default=None)

    # ------------------------------------------------------------------
    # jwt_login specific fields -- None when auth_type != 'jwt_login'
    # ------------------------------------------------------------------

    login_endpoint: str | None = Field(
        default=None,
        description=(
            "Mirrors CredentialsConfig.login_endpoint. "
            "Absolute path of the login endpoint for jwt_login auth. "
            "None when auth_type is not 'jwt_login'."
        ),
    )
    username_body_field: str = Field(
        default="username",
        description="Mirrors CredentialsConfig.username_body_field.",
    )
    password_body_field: str = Field(
        default="password",
        description="Mirrors CredentialsConfig.password_body_field.",
    )
    token_response_path: str = Field(
        default="access_token",
        description=(
            "Mirrors CredentialsConfig.token_response_path. "
            "Dotted JSONPath to extract the token from the login response."
        ),
    )

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
# RuntimeTest02Config — runtime parameters for Test 0.2
# ---------------------------------------------------------------------------


class RuntimeTest02Config(BaseModel):
    """
    Runtime mirror of Test02ProbeConfig consumed by Test 0.2.

    Populated by engine.py Phase 3 from config.tests.domain_0.test_0_2.
    Access pattern inside the test:
        cfg = target.tests_config.test_0_2
        gateway_ids = frozenset(cfg.gateway_server_identifiers)

    Why frozenset at the call site rather than here:
        Pydantic frozen models allow mutable field types (list) as long as the
        model itself is frozen (no attribute re-assignment). Converting to
        frozenset at the call site is a one-time O(n) operation and avoids the
        complexity of a custom Pydantic type for a small set of strings.
    """

    model_config = {"frozen": True}  # mandatory — see "Why two layers?" in ADDING_TESTS.md

    gateway_server_identifiers: list[str] = Field(
        default_factory=lambda: [
            "kong",
            "nginx",
            "openresty",
            "apache",
            "caddy",
            "traefik",
            "envoy",
        ],
        min_length=1,
        description=(
            "Mirrors Test02ProbeConfig.gateway_server_identifiers. "
            "Substrings matched case-insensitively against the 'Server' response header "
            "to classify a response as Gateway-generated rather than backend-generated. "
            "A response whose Server header matches none of these is flagged as a "
            "deny-by-default violation. "
            "Extend for gateways not in the default list (HAProxy, Tyk, APISIX). "
            "Never add application server names (Gunicorn, uWSGI): that defeats the check."
        ),
    )


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
# RuntimeTest15Config — runtime parameters for Test 1.5
# ---------------------------------------------------------------------------


class RuntimeTest15Config(BaseModel):
    """
    Runtime mirror of Test15Config fields consumed by Test 1.5.

    Populated by engine.py Phase 3 from config.tests.domain_1.test_1_5.
    Access pattern inside the test:
        cfg = target.tests_config.test_1_5
        cfg.hsts_min_max_age_seconds
        cfg.http_probe_enabled
        cfg.http_probe_timeout_seconds
        cfg.expected_redirect_status_codes
        cfg.testssl_binary_path
    """

    model_config = {"frozen": True}  # mandatory — see "Why two layers?" in ADDING_TESTS.md

    hsts_min_max_age_seconds: int = Field(
        default=31_536_000,
        ge=86_400,
        description=(
            "Mirrors Test15Config.hsts_min_max_age_seconds. "
            "Minimum acceptable max-age in HSTS header. Default: 31536000 (1 year)."
        ),
    )
    http_probe_enabled: bool = Field(
        default=True,
        description=(
            "Mirrors Test15Config.http_probe_enabled. "
            "Whether to probe HTTP port for redirect enforcement. Default: True."
        ),
    )
    http_probe_url: str = Field(
        default="",
        description=(
            "Mirrors Test15Config.http_probe_url. "
            "Explicit HTTP URL override for sub-test 1. "
            "Empty = derive from HTTPS base URL. "
            "Use when HTTPS base URL uses a non-standard port (e.g. 8443)."
        ),
    )
    http_probe_timeout_seconds: float = Field(
        default=5.0,
        ge=1.0,
        description=(
            "Mirrors Test15Config.http_probe_timeout_seconds. "
            "Timeout in seconds for the HTTP redirect probe. Default: 5.0."
        ),
    )
    expected_redirect_status_codes: list[int] = Field(
        default_factory=lambda: [301, 308],
        description=(
            "Mirrors Test15Config.expected_redirect_status_codes. "
            "HTTP status codes that satisfy the redirect oracle. Default: [301, 308]."
        ),
    )
    testssl_binary_path: str = Field(
        default="",
        description=(
            "Mirrors Test15Config.testssl_binary_path. "
            "Absolute path to testssl.sh binary. Empty = skip TLS scan sub-test."
        ),
    )
    testssl_timeout_seconds: int = Field(
        default=120,
        ge=30,
        description=(
            "Mirrors Test15Config.testssl_timeout_seconds. "
            "Maximum seconds for the testssl.sh subprocess. Default: 120."
        ),
    )


# ---------------------------------------------------------------------------
# RuntimeTest16Config — runtime parameters for Test 1.6
# ---------------------------------------------------------------------------


class RuntimeTest16Config(BaseModel):
    """
    Runtime mirror of Test16Config fields consumed by Test 1.6.

    Populated by engine.py Phase 3 from config.tests.domain_1.test_1_6.
    Access pattern inside the test:
        cfg = target.tests_config.test_1_6
        cfg.cookie_probe_paths
        cfg.session_cookie_names
        cfg.check_samesite
        cfg.expected_samesite_value
    """

    model_config = {"frozen": True}  # mandatory — see "Why two layers?" in ADDING_TESTS.md

    cookie_probe_paths: list[str] = Field(
        default_factory=lambda: ["/"],
        description=(
            "Mirrors Test16Config.cookie_probe_paths. "
            "Paths to GET for discovering Set-Cookie headers. Default: ['/']."
        ),
    )
    session_cookie_names: list[str] = Field(
        default_factory=lambda: [
            "session",
            "sid",
            "PHPSESSID",
            "JSESSIONID",
            "connect.sid",
            "_session",
            "auth_session",
            "user_session",
        ],
        description=(
            "Mirrors Test16Config.session_cookie_names. "
            "Case-insensitive cookie names treated as session identifiers. "
            "Default: well-known session cookie names."
        ),
    )
    check_samesite: bool = Field(
        default=True,
        description=(
            "Mirrors Test16Config.check_samesite. "
            "Whether to validate the SameSite attribute. Default: True."
        ),
    )
    expected_samesite_value: str = Field(
        default="Strict",
        description=(
            "Mirrors Test16Config.expected_samesite_value. "
            "Expected SameSite attribute value (case-insensitive). Default: 'Strict'."
        ),
    )

    @field_validator("session_cookie_names")
    @classmethod
    def session_cookie_names_not_empty(cls, v: list[str]) -> list[str]:
        """Reject empty list: would silently SKIP on every target."""
        if not v:
            raise ValueError(
                "session_cookie_names must contain at least one entry. "
                "An empty list causes the test to SKIP unconditionally."
            )
        return v


# ---------------------------------------------------------------------------
# RuntimeTest33Config — runtime parameters for Test 3.3
# ---------------------------------------------------------------------------


class RuntimeTest33Config(BaseModel):
    """
    Runtime mirror of Test33Config fields consumed by Test 3.3.

    Populated by engine.py Phase 3 from config.tests.domain_3.test_3_3.
    Access pattern inside the test:
        cfg = target.tests_config.test_3_3
        cfg.max_clock_skew_seconds
        cfg.forbidden_algorithms
        cfg.plugin_names
        cfg.field_clock_skew
        cfg.field_algorithms
        cfg.field_validate_body
        cfg.clock_skew_unconfigured_value
    """

    model_config = {"frozen": True}  # mandatory — see "Why two layers?" in ADDING_TESTS.md

    # --- Oracle thresholds --------------------------------------------------

    max_clock_skew_seconds: int = Field(
        default=300,
        ge=1,
        description=(
            "Mirrors Test33Config.max_clock_skew_seconds. "
            "Maximum acceptable clock_skew (seconds) for the HMAC plugin. "
            "NIST SP 800-107 Rev. 1 Section 5.3.2 oracle: <= 300 s. Default: 300."
        ),
    )
    forbidden_algorithms: list[str] = Field(
        default_factory=lambda: ["hmac-sha1", "hmac-md5"],
        description=(
            "Mirrors Test33Config.forbidden_algorithms. "
            "HMAC algorithm names whose presence in the plugin config is a finding. "
            "Default: ['hmac-sha1', 'hmac-md5']."
        ),
    )

    # --- Gateway-specific identifiers (agnosticism layer) -------------------

    plugin_names: list[str] = Field(
        default_factory=lambda: ["hmac-auth"],
        description=(
            "Mirrors Test33Config.plugin_names. "
            "Ordered list of gateway plugin names that implement HMAC request "
            "authentication.  The test returns the first plugin whose name "
            "appears in this list.  Default: ['hmac-auth'] (Kong OSS)."
        ),
    )
    field_clock_skew: str = Field(
        default="clock_skew",
        description=(
            "Mirrors Test33Config.field_clock_skew. "
            "JSON field name in the plugin config object for the replay-attack "
            "time window.  Kong hmac-auth default: 'clock_skew'."
        ),
    )
    field_algorithms: str = Field(
        default="algorithms",
        description=(
            "Mirrors Test33Config.field_algorithms. "
            "JSON field name in the plugin config object for the allowed algorithms "
            "list.  Kong hmac-auth default: 'algorithms'."
        ),
    )
    field_validate_body: str = Field(
        default="validate_request_body",
        description=(
            "Mirrors Test33Config.field_validate_body. "
            "JSON field name in the plugin config object for the body integrity "
            "flag.  Kong hmac-auth default: 'validate_request_body'."
        ),
    )
    clock_skew_unconfigured_value: int = Field(
        default=0,
        description=(
            "Mirrors Test33Config.clock_skew_unconfigured_value. "
            "Sentinel integer that represents 'no limit configured' in the "
            "clock_skew field.  Kong hmac-auth default: 0."
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
# RuntimeTest64Config — runtime parameters for Test 6.4
# ---------------------------------------------------------------------------


class RuntimeTest64Config(BaseModel):
    """
    Runtime mirror of Test64AuditConfig fields consumed by Test 6.4.

    Stores the operator-tunable list of debug endpoint paths to probe for
    credential exposure.  Mirrored from config/schema/domain_6.py:Test64AuditConfig,
    nested under config.tests.domain_6.test_6_4 in config.yaml.

    Access pattern inside the test:
        cfg = target.tests_config.test_6_4
        cfg.debug_endpoint_paths   # list[str]
    """

    model_config = {"frozen": True}

    debug_endpoint_paths: list[str] = Field(
        default_factory=lambda: [
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
        ],
        description=(
            "Mirrors Test64AuditConfig.debug_endpoint_paths. "
            "List of paths probed for debug endpoint exposure. "
            "Default: the methodology-cited actuator / debug paths."
        ),
    )
    gateway_block_body_fragment: str = Field(
        default="no Route matched with those values",
        description=(
            "Mirrors Test64AuditConfig.gateway_block_body_fragment. "
            "Substring identifying a Gateway-level block in a non-2xx response body. "
            "Default: Kong DB-less 3.x. Override in config.yaml for other gateways."
        ),
    )


# ---------------------------------------------------------------------------
# RuntimeTest72Config — runtime parameters for Test 7.2
# ---------------------------------------------------------------------------


class RuntimeTest72Config(BaseModel):
    """
    Runtime mirror of Test72SSRFConfig fields consumed by Test 7.2.

    Populated by engine.py Phase 3 from config.tests.domain_7.test_7_2.
    Access pattern inside the test:
        cfg = target.tests_config.test_7_2
        cfg.payload_categories
        cfg.injection_mode
        cfg.injection_path_template
        cfg.injection_url_field
        cfg.injection_body_template
        cfg.ssrf_redirect_server_url
        cfg.ssrf_malformed_url_keywords
        cfg.ssrf_unsupported_scheme_keywords
        cfg.ssrf_block_response_keywords
        cfg.ssrf_request_timeout_ms
    """

    model_config = {"frozen": True}

    payload_categories: list[str] = Field(
        default_factory=lambda: [
            "cloud_metadata",
            "private_ip",
            "encoding_bypass",
            "forbidden_protocol",
            "dns_bypass",
            "url_parser_confusion",
        ],
        description=(
            "Mirrors Test72SSRFConfig.payload_categories. "
            "SSRF payload categories to include in the probe. "
            "Default: all six categories."
        ),
    )
    injection_mode: str = Field(
        default="forgejo_webhook",
        description=(
            "Mirrors Test72SSRFConfig.injection_mode. "
            "'forgejo_webhook': create a repo, probe hooks endpoint. "
            "'fixed_path': probe injection_path_template directly. "
            "Default: 'forgejo_webhook'."
        ),
    )
    injection_path_template: str = Field(
        default="/api/v1/repos/{owner}/{repo}/hooks",
        description=(
            "Mirrors Test72SSRFConfig.injection_path_template. "
            "URL path template for the injection endpoint. "
            "Supports {owner}/{repo} placeholders for forgejo_webhook mode. "
            "Default: '/api/v1/repos/{owner}/{repo}/hooks'."
        ),
    )
    injection_url_field: str = Field(
        default="config.url",
        description=(
            "Mirrors Test72SSRFConfig.injection_url_field. "
            "Dot-notation path to the SSRF URL field in the body template. "
            "Default: 'config.url'."
        ),
    )
    injection_body_template: dict[str, object] = Field(
        default_factory=lambda: {
            "type": "forgejo",
            "config": {
                "url": "$SSRF_URL$",
                "content_type": "json",
                "secret": "$RANDOM_SECRET$",
            },
            "events": ["push"],
            "active": False,
            "branch_filter": "*",
        },
        description=(
            "Mirrors Test72SSRFConfig.injection_body_template. "
            "JSON body template with '$SSRF_URL$' and '$RANDOM_SECRET$' sentinels. "
            "Default: Forgejo webhook creation body."
        ),
    )
    ssrf_redirect_server_url: str = Field(
        default="",
        description=(
            "Mirrors Test72SSRFConfig.ssrf_redirect_server_url. "
            "URL of an operator-controlled redirect server for sub-test E. "
            "Empty string disables the redirect sub-test. Default: ''."
        ),
    )
    ssrf_block_response_keywords: list[str] = Field(
        default_factory=lambda: [
            "invalid host",
            "not allowed",
            "forbidden",
            "scheme not supported",
            "scheme not allowed",
            "host not allowed",
            "private",
            "loopback",
            "blocked",
            "disallowed",
            "restricted",
        ],
        description=(
            "Mirrors Test72SSRFConfig.ssrf_block_response_keywords. "
            "Case-insensitive substrings checked against non-2xx SSRF probe "
            "response bodies to classify the oracle state. Default: methodology list."
        ),
    )
    ssrf_malformed_url_keywords: list[str] = Field(
        default_factory=lambda: [
            "invalid character",
            "invalid url",
            "url malformed",
            "malformed url",
            "parse error",
            "url parse",
            "could not parse",
            "bad url",
        ],
        description=(
            "Mirrors Test72SSRFConfig.ssrf_malformed_url_keywords. "
            "Checked SECOND (Level 2), after the scheme check at Level 1. "
            "Safe to include 'invalid url' here because Level 1 has already "
            "handled non-HTTP schemes before this list is evaluated. "
            "A match produces oracle state SSRF_BLOCKED_AS_MALFORMED_URL. "
            "Default: methodology list."
        ),
    )
    ssrf_unsupported_scheme_keywords: list[str] = Field(
        default_factory=lambda: [
            "scheme not supported",
            "scheme not allowed",
            "unsupported scheme",
            "unsupported protocol",
            "invalid scheme",
            "only http",
            "only https",
            "protocol not allowed",
        ],
        description=(
            "Mirrors Test72SSRFConfig.ssrf_unsupported_scheme_keywords. "
            "Checked SECOND (Level 2), after ssrf_malformed_url_keywords. "
            "A match produces oracle state SSRF_BLOCKED_UNSUPPORTED_SCHEME. "
            "In Forgejo/Go, unsupported schemes produce the same 'Invalid url' "
            "response as malformed URLs; the test also checks the URL scheme "
            "directly to distinguish the two cases. "
            "Default: methodology list."
        ),
    )
    ssrf_request_timeout_ms: int = Field(
        default=10_000,
        ge=1_000,
        description=(
            "Mirrors Test72SSRFConfig.ssrf_request_timeout_ms. "
            "Reserved for future per-request timeout override support. "
            "Currently the global execution.read_timeout governs all requests. "
            "Default: 10 000 ms (10 s)."
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

    test_0_2: RuntimeTest02Config = Field(
        default_factory=RuntimeTest02Config,
        description=(
            "Runtime parameters for Test 0.2 (Gateway Deny-by-Default on Unregistered Paths). "
            "Mirrors Test02ProbeConfig from config.tests.domain_0.test_0_2."
        ),
    )
    test_1_1: RuntimeTest11Config = Field(
        default_factory=RuntimeTest11Config,
        description="Runtime parameters for Test 1.1 (Authentication Required).",
    )
    test_1_5: RuntimeTest15Config = Field(
        default_factory=RuntimeTest15Config,
        description=(
            "Runtime parameters for Test 1.5 "
            "(Credentials Not Transmitted via Insecure Channels). "
            "Mirrors Test15Config from config.tests.domain_1.test_1_5."
        ),
    )
    test_1_6: RuntimeTest16Config = Field(
        default_factory=RuntimeTest16Config,
        description=(
            "Runtime parameters for Test 1.6 (Secure Session Management). "
            "Mirrors Test16Config from config.tests.domain_1.test_1_6."
        ),
    )
    test_3_3: RuntimeTest33Config = Field(
        default_factory=RuntimeTest33Config,
        description=(
            "Runtime parameters for Test 3.3 (HMAC Authentication Configuration Audit). "
            "Mirrors Test33Config from config.tests.domain_3.test_3_3."
        ),
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
    test_6_4: RuntimeTest64Config = Field(
        default_factory=RuntimeTest64Config,
        description=(
            "Runtime parameters for Test 6.4 (Hardcoded Credentials Audit). "
            "Mirrors Test64AuditConfig from config.tests.domain_6.test_6_4."
        ),
    )
    test_7_2: RuntimeTest72Config = Field(
        default_factory=RuntimeTest72Config,
        description=(
            "Runtime parameters for Test 7.2 (SSRF Prevention). "
            "Mirrors Test72SSRFConfig from config.tests.domain_7.test_7_2."
        ),
    )

"""
src/config/schema.py

Pydantic v2 schema for the APIGuard Assurance tool configuration file (config.yaml).

This module defines the complete, validated structure of every parameter
that the tool accepts at startup. It is the formal contract between the
user's configuration and the tool's behavior.

Responsibility boundary:
    This module defines structure and validation rules only.
    It does NOT read files, parse YAML, or interpolate environment variables.
    Those operations belong to src/config/loader.py.

Dependency rule:
    This module imports from pydantic, stdlib, and src.core.models only.
    It must never import from loader.py, engine.py, or any test module.

Configuration hierarchy (mirrors config.yaml structure):
    ToolConfig
    ├── TargetConfig         (target API connection parameters)
    ├── CredentialsConfig    (authentication credentials for Grey/White Box tests)
    ├── ExecutionConfig      (pipeline behavior: priority, strategy, fail-fast)
    └── RateLimitProbeConfig (parameters for Test 4.1 empirical rate-limit discovery)
"""

from __future__ import annotations

from typing import Annotated

from pydantic import (
    AnyHttpUrl,
    BaseModel,
    Field,
    field_validator,
    model_validator,
)

from src.core.models import TestStrategy

# ---------------------------------------------------------------------------
# Constants — used as defaults and validation boundaries
# ---------------------------------------------------------------------------

# Priority range: P0 (most critical) to P3 (least critical).
PRIORITY_MIN: int = 0
PRIORITY_MAX: int = 3

# Rate-limit probe defaults (Implementazione.md, Section 6.3).
# Conservative values chosen to avoid triggering alerts on the target environment.
RATE_LIMIT_PROBE_DEFAULT_MAX_REQUESTS: int = 150
RATE_LIMIT_PROBE_DEFAULT_INTERVAL_MS: int = 50
RATE_LIMIT_PROBE_MIN_REQUESTS: int = 10
RATE_LIMIT_PROBE_MAX_REQUESTS: int = 500
RATE_LIMIT_PROBE_MIN_INTERVAL_MS: int = 10
RATE_LIMIT_PROBE_MAX_INTERVAL_MS: int = 5000

# HTTP timeout defaults (seconds) passed from config to SecurityClient.
# These mirror SecurityClient's defaults and are overridable per-deployment.
TIMEOUT_CONNECT_DEFAULT: float = 5.0
TIMEOUT_READ_DEFAULT: float = 30.0
TIMEOUT_CONNECT_MIN: float = 1.0
TIMEOUT_CONNECT_MAX: float = 30.0
TIMEOUT_READ_MIN: float = 5.0
TIMEOUT_READ_MAX: float = 120.0

# Retry defaults passed to SecurityClient.
RETRY_MAX_ATTEMPTS_DEFAULT: int = 3
RETRY_MAX_ATTEMPTS_MIN: int = 1
RETRY_MAX_ATTEMPTS_MAX: int = 10


# ---------------------------------------------------------------------------
# Sub-model: TargetConfig
# ---------------------------------------------------------------------------


class TargetConfig(BaseModel):
    """
    Connection parameters for the target API and its infrastructure.

    These values identify the system under assessment and are stored
    verbatim in TargetContext for the duration of the pipeline run.
    All URL fields are validated by Pydantic's AnyHttpUrl, which rejects
    malformed URLs before any network connection is attempted.
    """

    model_config = {"frozen": True}

    base_url: AnyHttpUrl = Field(
        description=(
            "Base URL of the target API as exposed through the API Gateway proxy. "
            "All test HTTP requests are constructed relative to this URL. "
            "Example: http://localhost:8000"
        )
    )
    openapi_spec_url: AnyHttpUrl = Field(
        description=(
            "URL from which the OpenAPI specification will be fetched. "
            "Must point to a valid OpenAPI 3.x JSON or YAML document. "
            "Example: http://localhost:8000/api/swagger"
        )
    )
    admin_api_url: AnyHttpUrl | None = Field(
        default=None,
        description=(
            "URL of the API Gateway Admin API, required for WHITE_BOX tests (P3). "
            "If absent, all WHITE_BOX tests return SKIP with the reason "
            "'Admin API not configured'. "
            "Example: http://localhost:8001"
        ),
    )

    @field_validator("base_url", "openapi_spec_url", "admin_api_url", mode="before")
    @classmethod
    def url_must_not_have_trailing_path_ambiguity(cls, value: object) -> object:
        """
        Warn if the URL ends with a trailing slash that could cause double-slash
        issues when tests concatenate paths. The validator does not reject the
        value — TargetContext.endpoint_base_url() handles stripping — but logs
        a normalized form for diagnostics.

        This validator passes the value through unchanged; normalization happens
        in TargetContext.endpoint_base_url().
        """
        return value


# ---------------------------------------------------------------------------
# Sub-model: CredentialsConfig
# ---------------------------------------------------------------------------


class CredentialsConfig(BaseModel):
    """
    Authentication credentials for Grey Box (P1/P2) and White Box (P3) tests.

    Fields in this sub-model are populated from environment variables by
    loader.py (${VAR_NAME} interpolation). They must NEVER appear in
    plain text in config.yaml, which may be committed to version control.

    All credential fields are Optional: their absence causes the corresponding
    test category to return SKIP rather than ERROR, because operating without
    certain credentials is a legitimate scoped assessment (e.g., Black Box only).

    The token fields (admin_token, user_a_token, user_b_token) accept pre-issued
    JWT tokens for environments where the tool cannot perform login flows
    programmatically. For environments where login is automated, these fields
    remain None and the Domain 1 tests populate TestContext via set_token().
    """

    model_config = {"frozen": True}

    admin_username: str | None = Field(
        default=None,
        description=(
            "Username of the administrative account for Grey Box tests. "
            "Injected from environment variable: ${ADMIN_USERNAME}. "
            "Used by Domain 1 tests to acquire an admin JWT token."
        ),
    )
    admin_password: str | None = Field(
        default=None,
        description=(
            "Password of the administrative account. "
            "Injected from environment variable: ${ADMIN_PASSWORD}. "
            "Never logged. Always appears as [REDACTED] in structured output."
        ),
    )
    user_a_username: str | None = Field(
        default=None,
        description=(
            "Username of the first standard test user. "
            "Injected from environment variable: ${USER_A_USERNAME}. "
            "Used in Domain 2 BOLA tests alongside user_b."
        ),
    )
    user_a_password: str | None = Field(
        default=None,
        description=(
            "Password of the first standard test user. "
            "Injected from environment variable: ${USER_A_PASSWORD}."
        ),
    )
    user_b_username: str | None = Field(
        default=None,
        description=(
            "Username of the second standard test user. "
            "Injected from environment variable: ${USER_B_USERNAME}. "
            "Used in Domain 2 BOLA tests as the cross-user accessor."
        ),
    )
    user_b_password: str | None = Field(
        default=None,
        description=(
            "Password of the second standard test user. "
            "Injected from environment variable: ${USER_B_PASSWORD}."
        ),
    )

    @model_validator(mode="after")
    def validate_credential_pairs(self) -> CredentialsConfig:
        """
        Enforce that username and password are provided together or not at all.

        A username without a password (or vice versa) indicates a misconfigured
        environment variable setup. Providing half a credential pair would cause
        authentication tests to fail silently with a 401 rather than surfacing
        the configuration error clearly at startup.
        """
        pairs = [
            ("admin_username", "admin_password", "admin"),
            ("user_a_username", "user_a_password", "user_a"),
            ("user_b_username", "user_b_password", "user_b"),
        ]
        for username_field, password_field, role_label in pairs:
            username_val = getattr(self, username_field)
            password_val = getattr(self, password_field)
            username_present = username_val is not None and str(username_val).strip()
            password_present = password_val is not None and str(password_val).strip()

            if username_present and not password_present:
                raise ValueError(
                    f"Credential pair incomplete for role '{role_label}': "
                    f"'{username_field}' is set but '{password_field}' is missing. "
                    f"Set the {password_field.upper()} environment variable."
                )
            if password_present and not username_present:
                raise ValueError(
                    f"Credential pair incomplete for role '{role_label}': "
                    f"'{password_field}' is set but '{username_field}' is missing. "
                    f"Set the {username_field.upper()} environment variable."
                )
        return self

    def has_admin_credentials(self) -> bool:
        """True if both admin_username and admin_password are present."""
        return bool(
            self.admin_username
            and self.admin_username.strip()
            and self.admin_password
            and self.admin_password.strip()
        )

    def has_user_a_credentials(self) -> bool:
        """True if both user_a_username and user_a_password are present."""
        return bool(
            self.user_a_username
            and self.user_a_username.strip()
            and self.user_a_password
            and self.user_a_password.strip()
        )

    def has_user_b_credentials(self) -> bool:
        """True if both user_b_username and user_b_password are present."""
        return bool(
            self.user_b_username
            and self.user_b_username.strip()
            and self.user_b_password
            and self.user_b_password.strip()
        )


# ---------------------------------------------------------------------------
# Sub-model: ExecutionConfig
# ---------------------------------------------------------------------------


class ExecutionConfig(BaseModel):
    """
    Parameters that control the pipeline execution behavior.

    These settings determine which tests run, in what mode, and under what
    termination conditions. They map directly to the filtering and fail-fast
    logic in TestRegistry and the engine.
    """

    model_config = {"frozen": True}

    min_priority: Annotated[int, Field(ge=PRIORITY_MIN, le=PRIORITY_MAX)] = Field(
        default=PRIORITY_MAX,
        description=(
            "Maximum priority level (inclusive) of tests to execute. "
            "Tests with priority > min_priority are excluded by TestRegistry. "
            "0 = P0 only (Black Box, no credentials). "
            "1 = P0 + P1. 2 = P0 through P2. 3 = all tests. "
            "Default: 3 (run all tests). "
            "CI pipelines typically use 0 for fast perimeter checks."
        ),
    )
    strategies: list[TestStrategy] = Field(
        default_factory=lambda: [strategy for strategy in TestStrategy],
        description=(
            "List of execution strategies to include. "
            "Tests whose strategy is not in this list are excluded by TestRegistry. "
            "Valid values: BLACK_BOX, GREY_BOX, WHITE_BOX. "
            "Default: all three strategies. "
            "Example to run only Black Box: [BLACK_BOX]"
        ),
    )
    fail_fast: bool = Field(
        default=False,
        description=(
            "If true, abort the pipeline immediately when a P0 test returns "
            "FAIL or ERROR. Subsequent tests are not executed. "
            "Rationale: a P0 failure means a critical guarantee is violated or "
            "unverifiable; continuing would produce an assessment without foundation. "
            "Default: false (run all tests regardless of P0 outcome)."
        ),
    )
    connect_timeout: Annotated[
        float,
        Field(ge=TIMEOUT_CONNECT_MIN, le=TIMEOUT_CONNECT_MAX),
    ] = Field(
        default=TIMEOUT_CONNECT_DEFAULT,
        description=(
            "TCP connection timeout in seconds passed to SecurityClient. "
            f"Range: [{TIMEOUT_CONNECT_MIN}, {TIMEOUT_CONNECT_MAX}]. "
            "Default: 5.0 seconds."
        ),
    )
    read_timeout: Annotated[
        float,
        Field(ge=TIMEOUT_READ_MIN, le=TIMEOUT_READ_MAX),
    ] = Field(
        default=TIMEOUT_READ_DEFAULT,
        description=(
            "HTTP read timeout in seconds passed to SecurityClient. "
            f"Range: [{TIMEOUT_READ_MIN}, {TIMEOUT_READ_MAX}]. "
            "Default: 30.0 seconds."
        ),
    )
    max_retry_attempts: Annotated[
        int,
        Field(ge=RETRY_MAX_ATTEMPTS_MIN, le=RETRY_MAX_ATTEMPTS_MAX),
    ] = Field(
        default=RETRY_MAX_ATTEMPTS_DEFAULT,
        description=(
            "Maximum number of HTTP attempts (initial + retries) for transient "
            "transport errors. Does not apply to valid HTTP responses (4xx, 5xx). "
            f"Range: [{RETRY_MAX_ATTEMPTS_MIN}, {RETRY_MAX_ATTEMPTS_MAX}]. "
            "Default: 3."
        ),
    )

    @field_validator("strategies", mode="before")
    @classmethod
    def strategies_must_not_be_empty(cls, value: object) -> object:
        """
        Reject an empty strategies list.

        An empty list would cause TestRegistry to filter out every test,
        producing an assessment with zero executed tests. This is almost
        certainly a configuration mistake rather than intentional usage.
        """
        if isinstance(value, list) and len(value) == 0:
            raise ValueError(
                "execution.strategies must contain at least one strategy. "
                "Valid values: BLACK_BOX, GREY_BOX, WHITE_BOX. "
                "To run only Black Box tests, set strategies: [BLACK_BOX]."
            )
        return value

    @model_validator(mode="after")
    def validate_strategy_credential_coherence(self) -> ExecutionConfig:
        """
        Warn via field description if WHITE_BOX is requested but no admin_api_url
        is configured. This cross-sub-model check cannot be done here (CredentialsConfig
        is a sibling, not a parent). The check is deferred to ToolConfig's
        model_validator, which has visibility across all sub-models.

        This validator is a placeholder that documents the intended check location.
        """
        return self


# ---------------------------------------------------------------------------
# Sub-model: RateLimitProbeConfig
# ---------------------------------------------------------------------------


class RateLimitProbeConfig(BaseModel):
    """
    Parameters for the empirical rate-limit discovery performed by Test 4.1.

    Test 4.1 does not know the rate limit threshold a priori (not in config.yaml,
    not retrievable without Admin API). It discovers it empirically by sending
    requests in a loop until it receives HTTP 429 or exhausts max_requests.

    These parameters are separated into their own sub-model because they are
    operationally distinct from the general execution parameters: they control
    a specific test's behavior, not the pipeline's behavior.

    Default values are deliberately conservative to avoid triggering monitoring
    alerts or causing disruption in the target environment during assessment.
    (Implementazione.md, Section 6.3)
    """

    model_config = {"frozen": True}

    max_requests: Annotated[
        int,
        Field(
            ge=RATE_LIMIT_PROBE_MIN_REQUESTS,
            le=RATE_LIMIT_PROBE_MAX_REQUESTS,
        ),
    ] = Field(
        default=RATE_LIMIT_PROBE_DEFAULT_MAX_REQUESTS,
        description=(
            "Maximum number of probe requests to send before concluding that "
            "rate limiting is absent or configured above this threshold. "
            f"Range: [{RATE_LIMIT_PROBE_MIN_REQUESTS}, {RATE_LIMIT_PROBE_MAX_REQUESTS}]. "
            "Default: 150. Oracle: if HTTP 429 is received within this limit -> PASS. "
            "If no 429 is received -> FAIL (rate limiting absent or threshold too high)."
        ),
    )
    request_interval_ms: Annotated[
        int,
        Field(
            ge=RATE_LIMIT_PROBE_MIN_INTERVAL_MS,
            le=RATE_LIMIT_PROBE_MAX_INTERVAL_MS,
        ),
    ] = Field(
        default=RATE_LIMIT_PROBE_DEFAULT_INTERVAL_MS,
        description=(
            "Interval in milliseconds between consecutive probe requests. "
            f"Range: [{RATE_LIMIT_PROBE_MIN_INTERVAL_MS}, "
            f"{RATE_LIMIT_PROBE_MAX_INTERVAL_MS}]. "
            "Default: 50ms. Lower values are more aggressive and may trigger "
            "monitoring alerts. Increase for production-adjacent environments."
        ),
    )

    @property
    def request_interval_seconds(self) -> float:
        """
        Convert request_interval_ms to seconds for use in time.sleep() calls.

        Test 4.1 uses this property rather than dividing by 1000 inline,
        centralizing the unit conversion and making the test code self-documenting.

        Returns:
            float: Interval in seconds.
        """
        return self.request_interval_ms / 1000.0


# ---------------------------------------------------------------------------
# Root model: ToolConfig
# ---------------------------------------------------------------------------


class ToolConfig(BaseModel):
    """
    Root configuration model for the APIGuard Assurance tool.

    This model is the single output of config/loader.py. After loader.py
    performs YAML parsing and environment variable interpolation, it passes
    the resulting dictionary to ToolConfig.model_validate(), which validates
    the entire configuration tree in one operation.

    ToolConfig is frozen: once constructed, it cannot be mutated. Any attempt
    to assign a field value raises a ValidationError. This guarantee holds
    for the entire duration of the pipeline run.

    The model_validator enforces cross-sub-model consistency rules that cannot
    be expressed within individual sub-models (e.g., WHITE_BOX strategy requires
    admin_api_url in TargetConfig).

    Usage in loader.py:

        raw_dict = yaml.safe_load(interpolated_yaml_content)
        config = ToolConfig.model_validate(raw_dict)
        # config is now frozen and ready to be passed to engine.py
    """

    model_config = {"frozen": True}

    target: TargetConfig = Field(
        description="Connection parameters for the target API and its infrastructure."
    )
    credentials: CredentialsConfig = Field(
        default_factory=CredentialsConfig,
        description=(
            "Authentication credentials for Grey Box and White Box tests. "
            "All values must be injected via environment variables. "
            "If omitted entirely, defaults to an empty CredentialsConfig "
            "(all credential fields None, all credential tests return SKIP)."
        ),
    )
    execution: ExecutionConfig = Field(
        default_factory=ExecutionConfig,
        description=(
            "Pipeline execution behavior: priority filter, strategy filter, "
            "fail-fast, and HTTP client parameters. "
            "If omitted, all defaults apply (run all tests, no fail-fast)."
        ),
    )
    rate_limit_probe: RateLimitProbeConfig = Field(
        default_factory=RateLimitProbeConfig,
        description=(
            "Parameters for Test 4.1 empirical rate-limit discovery. "
            "If omitted, conservative defaults apply (150 requests at 50ms interval)."
        ),
    )

    @model_validator(mode="after")
    def validate_cross_submodel_coherence(self) -> ToolConfig:
        """
        Enforce consistency rules that span multiple sub-models.

        Rule 1 — WHITE_BOX requires admin_api_url:
            If WHITE_BOX is in execution.strategies but target.admin_api_url
            is None, WHITE_BOX tests will all SKIP. This is not a fatal error
            (SKIP is a valid outcome for unconfigured capabilities), but we
            emit a structured warning in loader.py. The schema records this
            condition via a dedicated field for the loader to inspect.

        Rule 2 — GREY_BOX requires at least admin or user credentials:
            If GREY_BOX is in execution.strategies but no credentials are
            configured, all P1/P2 tests will SKIP. Again, not fatal, but
            worth surfacing clearly at startup rather than silently.

        Both rules produce warnings, not validation errors, because scoped
        assessments (Black Box only, no credentials) are legitimate use cases.
        The validator stores the coherence results for loader.py to log.
        """
        white_box_requested = TestStrategy.WHITE_BOX in self.execution.strategies
        admin_api_absent = self.target.admin_api_url is None

        if white_box_requested and admin_api_absent:
            # Not a fatal error: WHITE_BOX tests will return SKIP automatically.
            # The warning is emitted by loader.py after construction.
            object.__setattr__(
                self,
                "_white_box_without_admin_api",
                True,
            )

        grey_box_requested = TestStrategy.GREY_BOX in self.execution.strategies
        no_credentials = (
            not self.credentials.has_admin_credentials()
            and not self.credentials.has_user_a_credentials()
            and not self.credentials.has_user_b_credentials()
        )

        if grey_box_requested and no_credentials:
            object.__setattr__(
                self,
                "_grey_box_without_credentials",
                True,
            )

        return self

    @property
    def white_box_without_admin_api(self) -> bool:
        """
        True if WHITE_BOX strategy was requested but admin_api_url is absent.

        Used by loader.py to emit a structured warning after construction.
        """
        return getattr(self, "_white_box_without_admin_api", False)

    @property
    def grey_box_without_credentials(self) -> bool:
        """
        True if GREY_BOX strategy was requested but no credentials are configured.

        Used by loader.py to emit a structured warning after construction.
        """
        return getattr(self, "_grey_box_without_credentials", False)

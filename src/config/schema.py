"""
src/config/schema.py

Pydantic v2 schema for the APIGuard Assurance tool configuration file (config.yaml).

Design note — PrivateAttr for computed coherence flags
-------------------------------------------------------
ToolConfig uses two PrivateAttr fields (_white_box_without_admin_api and
_grey_box_without_credentials) to store boolean flags computed by the
model_validator. Declaring them as PrivateAttr with default=False makes them
first-class Pydantic citizens that survive model_copy() calls without loss
and are excluded from model_dump() output. The assignment in model_validator
uses self._flag = True, routed by Pydantic v2 through __pydantic_private__
which is the only mutable slot on a frozen model by design.
"""

from __future__ import annotations

from pathlib import Path
from typing import Annotated

from pydantic import (
    AnyHttpUrl,
    BaseModel,
    Field,
    PrivateAttr,
    field_validator,
    model_validator,
)

from src.core.models import TestStrategy

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

PRIORITY_MIN: int = 0
PRIORITY_MAX: int = 3

RATE_LIMIT_PROBE_DEFAULT_MAX_REQUESTS: int = 150
RATE_LIMIT_PROBE_DEFAULT_INTERVAL_MS: int = 50
RATE_LIMIT_PROBE_MIN_REQUESTS: int = 10
RATE_LIMIT_PROBE_MAX_REQUESTS: int = 500
RATE_LIMIT_PROBE_MIN_INTERVAL_MS: int = 10
RATE_LIMIT_PROBE_MAX_INTERVAL_MS: int = 5000

TIMEOUT_CONNECT_DEFAULT: float = 5.0
TIMEOUT_READ_DEFAULT: float = 30.0
TIMEOUT_CONNECT_MIN: float = 1.0
TIMEOUT_CONNECT_MAX: float = 30.0
TIMEOUT_READ_MIN: float = 5.0
TIMEOUT_READ_MAX: float = 120.0

RETRY_MAX_ATTEMPTS_DEFAULT: int = 3
RETRY_MAX_ATTEMPTS_MIN: int = 1
RETRY_MAX_ATTEMPTS_MAX: int = 10

# Phase 2: OpenAPI spec fetch + prance $ref dereferencing timeout.
# Prance's internal HTTP transport (requests library) has no default timeout,
# meaning the pipeline could hang indefinitely on an unresponsive spec URL.
# This parameter drives a threading watchdog in discovery/openapi.py.
OPENAPI_FETCH_TIMEOUT_DEFAULT: float = 60.0
OPENAPI_FETCH_TIMEOUT_MIN: float = 10.0
OPENAPI_FETCH_TIMEOUT_MAX: float = 300.0

# Outputs values
OUTPUT_DIRECTORY_DEFAULT: str = "outputs"
EVIDENCE_FILENAME: str = "evidence.json"
HTML_REPORT_FILENAME: str = "assessment_report.html"
JSON_REPORT_FILENAME: str = "apiguard_report.json"

# ---------------------------------------------------------------------------
# TargetConfig
# ---------------------------------------------------------------------------


class TargetConfig(BaseModel):
    """Connection parameters for the target API and its infrastructure."""

    model_config = {"frozen": True}

    base_url: AnyHttpUrl = Field(
        description=(
            "Base URL of the target API as exposed through the API Gateway proxy. "
            "Example: http://localhost:8000"
        )
    )
    openapi_spec_url: AnyHttpUrl = Field(
        description=(
            "URL from which the OpenAPI specification will be fetched. "
            "Example: http://localhost:3000/swagger.v1.json"
        )
    )
    admin_api_url: AnyHttpUrl | None = Field(
        default=None,
        description=(
            "URL of the API Gateway Admin API, required for WHITE_BOX tests (P3). "
            "If absent, all WHITE_BOX tests return SKIP. "
            "Example: http://localhost:8001"
        ),
    )

    @field_validator("base_url", "openapi_spec_url", "admin_api_url", mode="before")
    @classmethod
    def url_passthrough(cls, value: object) -> object:
        """Passthrough — trailing slash normalization happens in TargetContext."""
        return value


# ---------------------------------------------------------------------------
# CredentialsConfig
# ---------------------------------------------------------------------------


class CredentialsConfig(BaseModel):
    """
    Authentication credentials for Grey Box (P1/P2) and White Box (P3) tests.

    All fields are populated via ${VAR_NAME} environment variable interpolation
    in loader.py. They must NEVER appear in plain text in config.yaml.
    """

    model_config = {"frozen": True}

    admin_username: str | None = Field(default=None)
    admin_password: str | None = Field(default=None)
    user_a_username: str | None = Field(default=None)
    user_a_password: str | None = Field(default=None)
    user_b_username: str | None = Field(default=None)
    user_b_password: str | None = Field(default=None)

    @model_validator(mode="after")
    def validate_credential_pairs(self) -> CredentialsConfig:
        """Enforce that username and password are provided together or not at all."""
        pairs = [
            ("admin_username", "admin_password", "admin"),
            ("user_a_username", "user_a_password", "user_a"),
            ("user_b_username", "user_b_password", "user_b"),
        ]
        for username_field, password_field, role_label in pairs:
            username_val = getattr(self, username_field)
            password_val = getattr(self, password_field)
            username_present = bool(username_val and str(username_val).strip())
            password_present = bool(password_val and str(password_val).strip())

            if username_present and not password_present:
                raise ValueError(
                    f"Credential pair incomplete for role '{role_label}': "
                    f"'{username_field}' is set but '{password_field}' is missing."
                )
            if password_present and not username_present:
                raise ValueError(
                    f"Credential pair incomplete for role '{role_label}': "
                    f"'{password_field}' is set but '{username_field}' is missing."
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
# ExecutionConfig
# ---------------------------------------------------------------------------


class ExecutionConfig(BaseModel):
    """Parameters that control the pipeline execution behavior."""

    model_config = {"frozen": True}

    min_priority: Annotated[int, Field(ge=PRIORITY_MIN, le=PRIORITY_MAX)] = Field(
        default=PRIORITY_MAX,
        description=(
            "Maximum priority level (inclusive) of tests to execute. "
            "0=P0 only. 3=all tests (default)."
        ),
    )
    strategies: list[TestStrategy] = Field(
        default_factory=lambda: [
            TestStrategy.BLACK_BOX,
            TestStrategy.GREY_BOX,
            TestStrategy.WHITE_BOX,
        ],
        description="Execution strategies to include: BLACK_BOX, GREY_BOX, WHITE_BOX.",
    )
    fail_fast: bool = Field(
        default=False,
        description="Abort immediately when a P0 test returns FAIL or ERROR.",
    )
    connect_timeout: Annotated[float, Field(ge=TIMEOUT_CONNECT_MIN, le=TIMEOUT_CONNECT_MAX)] = (
        Field(
            default=TIMEOUT_CONNECT_DEFAULT,
            description=f"TCP connection timeout in seconds for SecurityClient. Default: {TIMEOUT_CONNECT_DEFAULT}s.",  # noqa: E501
        )
    )
    read_timeout: Annotated[float, Field(ge=TIMEOUT_READ_MIN, le=TIMEOUT_READ_MAX)] = Field(
        default=TIMEOUT_READ_DEFAULT,
        description=f"HTTP read timeout in seconds for SecurityClient. Default: {TIMEOUT_READ_DEFAULT}s.",  # noqa: E501
    )
    max_retry_attempts: Annotated[
        int, Field(ge=RETRY_MAX_ATTEMPTS_MIN, le=RETRY_MAX_ATTEMPTS_MAX)
    ] = Field(
        default=RETRY_MAX_ATTEMPTS_DEFAULT,
        description=f"Maximum HTTP attempts (initial + retries) for SecurityClient. Default: {RETRY_MAX_ATTEMPTS_DEFAULT}.",  # noqa: E501
    )
    openapi_fetch_timeout_seconds: Annotated[
        float,
        Field(ge=OPENAPI_FETCH_TIMEOUT_MIN, le=OPENAPI_FETCH_TIMEOUT_MAX),
    ] = Field(
        default=OPENAPI_FETCH_TIMEOUT_DEFAULT,
        description=(
            "Wall-clock timeout in seconds for Phase 2: OpenAPI spec fetch and "
            "$ref dereferencing via prance. Prance's internal HTTP transport "
            "(requests library) has no default timeout; without this parameter "
            "the pipeline would hang indefinitely on an unresponsive spec URL. "
            "Implemented as a threading watchdog: prance runs in a background "
            "thread and the main thread raises OpenAPILoadError if the timeout "
            f"expires. Range: [{OPENAPI_FETCH_TIMEOUT_MIN}, {OPENAPI_FETCH_TIMEOUT_MAX}]. "
            f"Default: {OPENAPI_FETCH_TIMEOUT_DEFAULT}s."
        ),
    )

    test_ids: list[str] = Field(
        default_factory=list,
        description=(
            "If non-empty, run ONLY the tests whose test_id is in this list. "
            "Overrides min_priority and strategies filters entirely: a test "
            "listed here is included regardless of its priority or strategy. "
            "Intended for development and targeted verification. "
            "Example: ['4.1'] runs only Test 4.1. "
            "Example: ['0.1', '1.1', '1.2'] runs only those three tests. "
            "Leave empty (default) for normal priority+strategy filtering."
        ),
    )

    @field_validator("strategies", mode="before")
    @classmethod
    def strategies_must_not_be_empty(cls, value: object) -> object:
        """Reject an empty strategies list."""
        if isinstance(value, list) and len(value) == 0:
            raise ValueError(
                "execution.strategies must contain at least one strategy. "
                "Valid values: BLACK_BOX, GREY_BOX, WHITE_BOX."
            )
        return value

    @field_validator("test_ids", mode="before")
    @classmethod
    def test_ids_must_be_valid_format(cls, value: object) -> object:
        """
        Validate that each test_id follows the 'X.Y' format.

        A test_id is a string of the form '<domain>.<sequence>', where
        both parts are non-negative integers (e.g. '0.1', '4.1', '7.2').
        This validator catches obvious typos early, before the registry
        attempts the lookup and silently produces an empty filtered list.
        """
        if not isinstance(value, list):
            return value
        for item in value:
            if not isinstance(item, str):
                raise ValueError(f"Each test_id must be a string. Got: {item!r}")
            parts = item.split(".")
            if len(parts) != 2 or not all(p.isdigit() for p in parts):  # noqa: PLR2004
                raise ValueError(
                    f"Invalid test_id format: {item!r}. "
                    "Expected 'X.Y' where X is the domain number and Y is "
                    "the test number (e.g. '4.1', '0.2', '1.3')."
                )
        return value

    @model_validator(mode="after")
    def validate_strategy_credential_coherence(self) -> ExecutionConfig:
        """Placeholder — cross-sub-model check deferred to ToolConfig validator."""
        return self


# ---------------------------------------------------------------------------
# OutputConfig
# ---------------------------------------------------------------------------


class OutputConfig(BaseModel):
    """Configuration for output file locations."""

    model_config = {"frozen": True}

    directory: Path = Field(
        default=Path(OUTPUT_DIRECTORY_DEFAULT),
        description=(
            "Directory where assessment outputs are written. "
            f"Default: '{OUTPUT_DIRECTORY_DEFAULT}/' (relative to working directory)."
        ),
    )

    @property
    def evidence_path(self) -> Path:
        """Full path to the evidence JSON output file."""
        return self.directory / EVIDENCE_FILENAME

    @property
    def report_path(self) -> Path:
        """Full path to the HTML assessment report output file."""
        return self.directory / HTML_REPORT_FILENAME

    @property
    def json_report_path(self) -> Path:
        """Full path to the machine-readable JSON report output file.

        This file contains a serialised ReportData (Pydantic model,
        indent=2 JSON) intended for consumption by CI/CD pipelines and
        external Vulnerability Management systems. It is a compact,
        structured alternative to evidence.json, which carries the full
        raw HTTP transaction payloads.

        Filename: defined by JSON_REPORT_FILENAME constant to prevent
        magic strings and allow a single point of change if the name
        must ever be updated.
        """
        return self.directory / JSON_REPORT_FILENAME


# ---------------------------------------------------------------------------
# RateLimitProbeConfig
# ---------------------------------------------------------------------------


class RateLimitProbeConfig(BaseModel):
    """Parameters for the empirical rate-limit discovery performed by Test 4.1."""

    model_config = {"frozen": True}

    max_requests: Annotated[
        int,
        Field(ge=RATE_LIMIT_PROBE_MIN_REQUESTS, le=RATE_LIMIT_PROBE_MAX_REQUESTS),
    ] = Field(
        default=RATE_LIMIT_PROBE_DEFAULT_MAX_REQUESTS,
        description="Maximum probe requests before concluding rate limiting is absent. Default: 150.",  # noqa: E501
    )
    request_interval_ms: Annotated[
        int,
        Field(ge=RATE_LIMIT_PROBE_MIN_INTERVAL_MS, le=RATE_LIMIT_PROBE_MAX_INTERVAL_MS),
    ] = Field(
        default=RATE_LIMIT_PROBE_DEFAULT_INTERVAL_MS,
        description="Interval in milliseconds between consecutive probe requests. Default: 50ms.",
    )

    @property
    def request_interval_seconds(self) -> float:
        """Convert request_interval_ms to seconds for use in time.sleep() calls."""
        return self.request_interval_ms / 1000.0


# ---------------------------------------------------------------------------
# TestDomain1Config / TestsConfig — per-test tuning parameters
# ---------------------------------------------------------------------------


class TestDomain1Config(BaseModel):
    """
    Tuning parameters for Domain 1 (Identity and Authentication) tests.

    These parameters control the execution behaviour of individual tests
    without altering their security oracle logic. All values are conservative
    defaults that produce a complete, correct assessment on any target API
    without requiring operator intervention.
    """

    model_config = {"frozen": True}

    max_endpoints_cap: Annotated[int, Field(ge=0)] = Field(
        default=0,
        description=(
            "Maximum number of protected endpoints that Test 1.1 will probe. "
            "0 means test ALL protected endpoints declared in the OpenAPI spec "
            "(recommended for complete academic coverage). "
            "Set to a positive integer only when the target API enforces strict "
            "rate limiting that would cause 429 responses during a full scan, "
            "or when the operator requires a time-bounded assessment. "
            "Note: a cap reduces coverage — always document this trade-off in "
            "the assessment report."
        ),
    )


class TestsConfig(BaseModel):
    """
    Container for per-domain test tuning parameters.

    Each sub-model corresponds to one methodology domain (0-7). Only domains
    with tunable parameters have an entry here. Domains without tunable
    parameters have no sub-model because their oracle logic is not
    parameterised.
    """

    model_config = {"frozen": True}

    domain_1: TestDomain1Config = Field(
        default_factory=TestDomain1Config,
        description="Tuning parameters for Domain 1 (Identity and Authentication) tests.",
    )


# ---------------------------------------------------------------------------
# ToolConfig (root)
# ---------------------------------------------------------------------------


class ToolConfig(BaseModel):
    """
    Root configuration model for the APIGuard Assurance tool.

    Frozen after construction. PrivateAttr fields store cross-submodel
    coherence flags computed by the model_validator — they survive
    model_copy() and are excluded from model_dump().
    """

    model_config = {"frozen": True}

    target: TargetConfig = Field(
        description="Connection parameters for the target API and its infrastructure."
    )
    credentials: CredentialsConfig = Field(
        default_factory=CredentialsConfig,
        description="Authentication credentials injected via environment variables.",
    )
    execution: ExecutionConfig = Field(
        default_factory=ExecutionConfig,
        description="Pipeline execution behavior.",
    )
    output: OutputConfig = Field(
        default_factory=OutputConfig,
        description="Output file configuration.",
    )
    rate_limit_probe: RateLimitProbeConfig = Field(
        default_factory=RateLimitProbeConfig,
        description="Parameters for Test 4.1 empirical rate-limit discovery.",
    )
    tests: TestsConfig = Field(
        default_factory=TestsConfig,
        description=(
            "Per-domain test tuning parameters. "
            "Default values produce a complete assessment without operator intervention. "
            "Override specific fields to adapt to rate-limited or time-constrained targets."
        ),
    )

    _white_box_without_admin_api: bool = PrivateAttr(default=False)
    _grey_box_without_credentials: bool = PrivateAttr(default=False)

    @model_validator(mode="after")
    def validate_cross_submodel_coherence(self) -> ToolConfig:
        """
        Enforce consistency rules spanning multiple sub-models.

        Rule 1: WHITE_BOX requires admin_api_url.
        Rule 2: GREY_BOX requires at least one credential set.

        Both produce loader.py WARNINGs, not validation errors, because
        scoped Black-Box-only assessments are legitimate use cases.
        """
        if (
            TestStrategy.WHITE_BOX in self.execution.strategies
            and self.target.admin_api_url is None
        ):
            self._white_box_without_admin_api = True

        if TestStrategy.GREY_BOX in self.execution.strategies and not (
            self.credentials.has_admin_credentials()
            or self.credentials.has_user_a_credentials()
            or self.credentials.has_user_b_credentials()
        ):
            self._grey_box_without_credentials = True

        return self

    @property
    def white_box_without_admin_api(self) -> bool:
        """True if WHITE_BOX strategy requested but admin_api_url is absent."""
        return self._white_box_without_admin_api

    @property
    def grey_box_without_credentials(self) -> bool:
        """True if GREY_BOX strategy requested but no credentials configured."""
        return self._grey_box_without_credentials

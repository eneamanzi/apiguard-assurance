"""
src/config/schema/tool_config.py

Pydantic v2 models for the tool-level (infrastructure) configuration.

This module owns the configuration that describes the tool itself and its
runtime environment: where to find the target, what credentials to use,
how to execute the pipeline, and where to write output. It does NOT contain
per-test tuning parameters -- those live in domain_N.py files aggregated by
tests_config.py.

Design notes preserved from the original schema.py:

    PrivateAttr for computed coherence flags
    -----------------------------------------
    ToolConfig uses two PrivateAttr fields (_white_box_without_admin_api and
    _grey_box_without_credentials) to store boolean flags computed by the
    model_validator. Declaring them as PrivateAttr with default=False makes
    them first-class Pydantic citizens that survive model_copy() calls without
    loss and are excluded from model_dump() output. The assignment in
    model_validator uses self._flag = True, routed by Pydantic v2 through
    __pydantic_private__ which is the only mutable slot on a frozen model by
    design.

    OpenAPI spec source (URL vs. local path)
    -----------------------------------------
    TargetConfig supports two mutually exclusive sources for the OpenAPI spec:
        openapi_spec_url  -- fetch over HTTP/HTTPS at Phase 2 runtime.
        openapi_spec_path -- read from the local filesystem at Phase 2 runtime.
    Exactly one of the two must be present; the model_validator raises
    ValueError when both or neither are provided.

Dependency rule: imports from pydantic, the stdlib, src.core.models (for
TestStrategy), and src.config.schema.tests_config. Must never import from
engine.py, tests/, discovery/, or report/.
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

from src.config.schema.tests_config import TestsConfig
from src.core.models import TestStrategy

# ---------------------------------------------------------------------------
# Constants -- priority
# ---------------------------------------------------------------------------

PRIORITY_MIN: int = 0
PRIORITY_MAX: int = 3

# ---------------------------------------------------------------------------
# Constants -- HTTP client timeouts and retries
# ---------------------------------------------------------------------------

TIMEOUT_CONNECT_DEFAULT: float = 5.0
TIMEOUT_READ_DEFAULT: float = 30.0
TIMEOUT_CONNECT_MIN: float = 1.0
TIMEOUT_CONNECT_MAX: float = 30.0
TIMEOUT_READ_MIN: float = 5.0
TIMEOUT_READ_MAX: float = 120.0

RETRY_MAX_ATTEMPTS_DEFAULT: int = 3
RETRY_MAX_ATTEMPTS_MIN: int = 1
RETRY_MAX_ATTEMPTS_MAX: int = 10

# ---------------------------------------------------------------------------
# Constants -- OpenAPI fetch
# ---------------------------------------------------------------------------

# Phase 2: OpenAPI spec fetch + prance $ref dereferencing timeout.
# Prance's internal HTTP transport (requests library) has no default timeout,
# meaning the pipeline could hang indefinitely on an unresponsive spec URL.
# This parameter drives a threading watchdog in discovery/openapi.py.
OPENAPI_FETCH_TIMEOUT_DEFAULT: float = 60.0
OPENAPI_FETCH_TIMEOUT_MIN: float = 10.0
OPENAPI_FETCH_TIMEOUT_MAX: float = 300.0

# ---------------------------------------------------------------------------
# Constants -- output filenames and directory
# ---------------------------------------------------------------------------

OUTPUT_DIRECTORY_DEFAULT: str = "outputs"
EVIDENCE_FILENAME: str = "evidence.json"
HTML_REPORT_FILENAME: str = "assessment_report.html"
JSON_REPORT_FILENAME: str = "apiguard_report.json"

# Subdirectory name for per-test streaming JSONL files written during Phase 5.
# EvidenceStore creates one <test_id>.jsonl file per test inside this directory
# and removes it entirely in merge_and_finalize() at Phase 7.
# Placing it alongside evidence.json makes crash artefacts predictable and
# inspectable -- a forensic asset rather than hidden temp files.
EVIDENCE_TMP_DIRNAME: str = "evidence_tmp"

# ---------------------------------------------------------------------------
# TargetConfig
# ---------------------------------------------------------------------------


class TargetConfig(BaseModel):
    """
    Connection parameters for the target API and its infrastructure.

    OpenAPI spec source
    -------------------
    Exactly one of openapi_spec_url or openapi_spec_path must be provided.
    The model_validator enforce_exactly_one_openapi_source verifies this at
    load time. Use get_openapi_source() in all downstream code to obtain the
    canonical string representation without if/else branching on source type.
    """

    model_config = {"frozen": True}

    base_url: AnyHttpUrl = Field(
        description=(
            "Base URL of the target API as exposed through the API Gateway proxy. "
            "Example: http://localhost:8000"
        )
    )
    openapi_spec_url: AnyHttpUrl | None = Field(
        default=None,
        description=(
            "URL from which the OpenAPI specification will be fetched at runtime. "
            "Mutually exclusive with openapi_spec_path: set exactly one. "
            "Pydantic validates the URL format at config load time. "
            "Example: http://localhost:3000/swagger.v1.json"
        ),
    )
    openapi_spec_path: Path | None = Field(
        default=None,
        description=(
            "Absolute or relative filesystem path to a locally stored OpenAPI "
            "specification file (JSON or YAML). "
            "Mutually exclusive with openapi_spec_url: set exactly one. "
            "Pydantic coerces a plain string from config.yaml to a Path object. "
            "Relative paths are resolved to absolute at call time via Path.resolve(), "
            "anchored to the working directory of the process. "
            "prance resolves intra-file $ref pointers normally; remote $ref entries "
            "inside a local spec still require network access. "
            "The file's existence is validated by discovery/openapi.py at Phase 2 "
            "runtime (not here) so that the error message includes the resolved "
            "absolute path rather than the raw config value. "
            "Example: ./specs/forgejo-swagger.v1.json"
        ),
    )
    admin_api_url: AnyHttpUrl | None = Field(
        default=None,
        description=(
            "URL of the API Gateway Admin API, required for WHITE_BOX tests (P3). "
            "If absent, all WHITE_BOX tests return SKIP. "
            "Example: http://localhost:8001"
        ),
    )
    path_seed: dict[str, str] = Field(
        default_factory=dict,
        description=(
            "Optional mapping of OpenAPI path parameter names to real resource "
            "identifiers on the target deployment. Used by the path resolver to "
            'substitute parametric path segments (e.g. "{owner}") with values that '
            "route to real resources, ensuring probes reach the authentication "
            "middleware instead of receiving a 404 at the routing layer. "
            "Example: {owner: 'mario_rossi', repo: 'my-repo', id: '1'}. "
            "Parameters absent from this dict fall back to the test's default "
            "placeholder (typically '1'). "
            "Run 'apiguard generate-seed' to auto-generate a template with all "
            "parameter names found in the OpenAPI specification."
        ),
    )
    verify_tls: bool = Field(
        default=True,
        description=(
            "Whether to verify the TLS certificate when connecting to base_url. "
            "Default: True (production-safe behaviour -- rejects self-signed certs). "
            "Set to False ONLY in local lab environments where the Gateway uses a "
            "self-signed certificate generated by gen-certs.sh. "
            "This flag is forwarded to httpx.Client(verify=...) in SecurityClient "
            "and to httpx.get(verify=...) in the Test 1.5 HTTP redirect probe. "
            "Never set this to False in a production assessment: a tool that "
            "disables TLS verification cannot detect certificate misconfiguration "
            "and is vulnerable to MITM attacks during the assessment itself. "
            "NIST SP 800-52 Rev.2 requires TLS certificate validation on all "
            "connections carrying sensitive data."
        ),
    )

    @model_validator(mode="after")
    def enforce_exactly_one_openapi_source(self) -> TargetConfig:
        """
        Enforce the mutual exclusion invariant between openapi_spec_url and
        openapi_spec_path.

        Exactly one of the two must be provided. Rationale:

            Neither set  -- Phase 2 cannot build an AttackSurface; the error
                            would only surface at Phase 2 runtime with a
                            confusing NoneType exception instead of a clear
                            configuration error at startup.

            Both set     -- Ambiguity about which source to use. Silently
                            applying a precedence rule would hide the likely
                            operator mistake of leaving an old field in the
                            config when switching source type.

        File existence on disk is NOT validated here; it is deferred to
        discovery/openapi.py so that the error message includes the resolved
        absolute path.
        """
        url_set = self.openapi_spec_url is not None
        path_set = self.openapi_spec_path is not None

        if url_set and path_set:
            raise ValueError(
                "Exactly one of 'openapi_spec_url' and 'openapi_spec_path' must be "
                "set, not both. Remove the field you do not intend to use from "
                "config.yaml."
            )
        if not url_set and not path_set:
            raise ValueError(
                "One of 'openapi_spec_url' or 'openapi_spec_path' must be set in "
                "config.yaml under the 'target' section. "
                "Provide a URL (e.g. http://localhost:3000/swagger.v1.json) or a "
                "local file path (e.g. ./specs/forgejo-swagger.v1.json)."
            )
        return self

    def get_openapi_source(self) -> str:
        """
        Return the canonical string representation of the OpenAPI spec source.

        This is the single point where the URL-vs-path decision is made.
        All downstream code (engine.py Phase 2, discovery/openapi.py,
        tests_e2e/conftest.py) calls this method instead of accessing
        openapi_spec_url or openapi_spec_path directly.

        Returns:
            str: Either the HTTP URL string or the absolute filesystem path string.

        Raises:
            RuntimeError: If neither field is set (unreachable after validation).
        """
        if self.openapi_spec_url is not None:
            return str(self.openapi_spec_url)
        if self.openapi_spec_path is not None:
            return str(self.openapi_spec_path.resolve())
        raise RuntimeError(
            "TargetConfig.get_openapi_source() called but neither "
            "openapi_spec_url nor openapi_spec_path is set. "
            "This state should have been caught by enforce_exactly_one_openapi_source."
        )

    @property
    def is_local_spec(self) -> bool:
        """True if the OpenAPI specification is sourced from a local filesystem path."""
        return self.openapi_spec_path is not None

    @field_validator("base_url", "openapi_spec_url", "admin_api_url", mode="before")
    @classmethod
    def url_passthrough(cls, value: object) -> object:
        """Passthrough -- trailing slash normalisation happens in TargetContext."""
        return value


# ---------------------------------------------------------------------------
# CredentialsConfig
# ---------------------------------------------------------------------------


class CredentialsConfig(BaseModel):
    """
    Authentication credentials for Grey Box (P1/P2) and White Box (P3) tests.

    All credential fields are populated via ${VAR_NAME} environment variable
    interpolation in loader.py. They must NEVER appear in plain text in
    config.yaml.

    auth_type selects the token-acquisition strategy used by the auth dispatcher
    (src/tests/helpers/auth.py) at the start of every GREY_BOX test:

        "forgejo_token"  (default) -- Forgejo/Gitea Token API.
            POST /api/v1/users/{username}/tokens with HTTP Basic Auth.
            Returns an opaque token in the "sha1" response field.
            Backward-compatible: config.yaml files without an explicit
            auth_type field continue to work without modification.

        "jwt_login"  -- Generic JSON login endpoint.
            POST {login_endpoint} with {username_body_field}/{password_body_field}
            as JSON body. Extracts the token from the response via
            token_response_path (dotted JSONPath, e.g. "data.access_token").
            Use for crAPI, Django REST Framework, FastAPI, Rails Devise, etc.

    Choosing auth_type as a plain str (not Literal) is intentional: it leaves
    the dispatcher open to new implementations without a schema change. The
    model_validator validates the value and emits a clear error listing the
    supported options.
    """

    model_config = {"frozen": True}

    # ------------------------------------------------------------------
    # Auth type discriminator
    # ------------------------------------------------------------------

    auth_type: str = Field(
        default="forgejo_token",
        description=(
            "Token-acquisition strategy for GREY_BOX tests. "
            "Supported values: 'forgejo_token' (default), 'jwt_login'. "
            "See class docstring for details."
        ),
    )

    # ------------------------------------------------------------------
    # Common credential fields (used by forgejo_token and jwt_login)
    # ------------------------------------------------------------------

    admin_username: str | None = Field(default=None)
    admin_password: str | None = Field(default=None)
    user_a_username: str | None = Field(default=None)
    user_a_password: str | None = Field(default=None)
    user_b_username: str | None = Field(default=None)
    user_b_password: str | None = Field(default=None)

    # ------------------------------------------------------------------
    # jwt_login specific fields
    # ------------------------------------------------------------------

    login_endpoint: str | None = Field(
        default=None,
        description=(
            "Required when auth_type='jwt_login'. "
            "Absolute path of the login endpoint, e.g. '/identity/api/auth/login'. "
            "The full URL is constructed as target.base_url + login_endpoint."
        ),
    )
    username_body_field: str = Field(
        default="username",
        description=(
            "JSON body field name for the username in jwt_login POST requests. "
            "Default: 'username'. Override to 'email' for targets that use email login."
        ),
    )
    password_body_field: str = Field(
        default="password",
        description=(
            "JSON body field name for the password in jwt_login POST requests. Default: 'password'."
        ),
    )
    token_response_path: str = Field(
        default="access_token",
        description=(
            "Dotted JSONPath to extract the token from the login response body. "
            "Supports simple dot-notation only (no array indexing, no keys with dots). "
            "Examples: 'access_token' for {'access_token': '...'}, "
            "'data.token' for {'data': {'token': '...'}}. "
            "Default: 'access_token'."
        ),
    )

    # ------------------------------------------------------------------
    # Validators
    # ------------------------------------------------------------------

    @model_validator(mode="after")
    def validate_credentials(self) -> CredentialsConfig:
        """
        Enforce auth_type validity and credential pair completeness.

        Two independent checks:
        1. auth_type must be one of the supported values.
        2. jwt_login requires login_endpoint.
        3. Each role's username and password must be provided together or not at all.
        """
        supported_auth_types = ("forgejo_token", "jwt_login")
        if self.auth_type not in supported_auth_types:
            raise ValueError(
                f"Unsupported auth_type: '{self.auth_type}'. "
                f"Supported values: {sorted(supported_auth_types)}."
            )

        if self.auth_type == "jwt_login" and not self.login_endpoint:
            raise ValueError(
                "auth_type='jwt_login' requires 'login_endpoint' to be set in "
                "config.yaml under credentials.login_endpoint."
            )

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
            description=(
                f"TCP connection timeout in seconds for SecurityClient. "
                f"Default: {TIMEOUT_CONNECT_DEFAULT}s."
            ),
        )
    )
    read_timeout: Annotated[float, Field(ge=TIMEOUT_READ_MIN, le=TIMEOUT_READ_MAX)] = Field(
        default=TIMEOUT_READ_DEFAULT,
        description=(
            f"HTTP read timeout in seconds for SecurityClient. Default: {TIMEOUT_READ_DEFAULT}s."
        ),
    )
    max_retry_attempts: Annotated[
        int, Field(ge=RETRY_MAX_ATTEMPTS_MIN, le=RETRY_MAX_ATTEMPTS_MAX)
    ] = Field(
        default=RETRY_MAX_ATTEMPTS_DEFAULT,
        description=(
            f"Maximum HTTP attempts (initial + retries) for SecurityClient. "
            f"Default: {RETRY_MAX_ATTEMPTS_DEFAULT}."
        ),
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
            f"expires. Only relevant when openapi_spec_url is used; local file "
            f"reads (openapi_spec_path) complete well within this budget. "
            f"Range: [{OPENAPI_FETCH_TIMEOUT_MIN}, {OPENAPI_FETCH_TIMEOUT_MAX}]. "
            f"Default: {OPENAPI_FETCH_TIMEOUT_DEFAULT}s."
        ),
    )
    test_ids: list[str] = Field(
        default_factory=list,
        description=(
            "If non-empty, run ONLY the tests whose test_id is in this list. "
            "Overrides min_priority and strategies filters entirely. "
            "Intended for development and targeted verification. "
            "Example: ['4.1'] runs only Test 4.1. "
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
        """Placeholder -- cross-sub-model check deferred to ToolConfig validator."""
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
        """Full path to the final unified evidence JSON output file."""
        return self.directory / EVIDENCE_FILENAME

    @property
    def evidence_tmp_path(self) -> Path:
        """Full path to the temporary per-test JSONL streaming directory.

        During Phase 5 execution, EvidenceStore writes each test's evidence
        records as a JSONL file inside this directory
        (e.g. ``outputs/evidence_tmp/1_1.jsonl``).
        Phase 7 merges all JSONL files into ``evidence.json`` and then
        removes this directory via EvidenceStore.merge_and_finalize().
        """
        return self.directory / EVIDENCE_TMP_DIRNAME

    @property
    def report_path(self) -> Path:
        """Full path to the HTML assessment report output file."""
        return self.directory / HTML_REPORT_FILENAME

    @property
    def json_report_path(self) -> Path:
        """Full path to the machine-readable JSON report output file."""
        return self.directory / JSON_REPORT_FILENAME


# ---------------------------------------------------------------------------
# ToolConfig (root)
# ---------------------------------------------------------------------------


class ToolConfig(BaseModel):
    """
    Root configuration model for the APIGuard Assurance tool.

    Frozen after construction. PrivateAttr fields store cross-submodel
    coherence flags computed by the model_validator -- they survive
    model_copy() and are excluded from model_dump().

    Migration note (rate_limit_probe removal):
        The former top-level 'rate_limit_probe' field has been removed.
        Rate-limit probe parameters are now nested under
        'tests.domain_4.test_4_1' in config.yaml and live in
        Test41ProbeConfig (domain_4.py). This corrects the architectural
        error of treating test-specific tuning as tool-level infrastructure.
        engine.py Phase 3 reads from config.tests.domain_4.test_4_1.
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
    tests: TestsConfig = Field(
        default_factory=TestsConfig,
        description=(
            "Per-domain test tuning parameters. "
            "Default values produce a complete assessment without operator intervention."
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

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
    ToolConfig uses three PrivateAttr fields (_white_box_without_gateway,
    _white_box_without_admin_credentials, _grey_box_without_user_credentials)
    to store boolean flags computed by the
    model_validator. Declaring them as PrivateAttr with default=False makes
    them first-class Pydantic citizens that survive model_copy() calls without
    loss and are excluded from model_dump() output. The assignment in
    model_validator uses self._flag = True, routed by Pydantic v2 through
    __pydantic_private__ which is the only mutable slot on a frozen model by
    design.

    Configuration by connection (docs/architecture/design-decisions.md, D1)
    ----------------------------------------------------------------
    Every party the tool talks to is a section with its own settings:
        target         the API under test (base_url, timeouts, retries);
        specification  the OpenAPI document (url or path, exactly one; timeout);
        gateway        optional, for the configuration audits (adapter,
                       admin: url, headers, timeouts; health: url).
    Keys moved there from target and execution are rejected with their new
    place.

Dependency rule: imports from pydantic, the stdlib, src.core.models (for
TestStrategy, RuntimeCredentials, ResourceConfig), src.core.templating (to
check placeholders), src.test_config (placeholder names of test 7.2) and
src.config.schema.tests_config. Must never import from engine.py, tests/,
discovery/, or report/.
"""

from __future__ import annotations

import re
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
from src.core.gateway import GATEWAY_ADAPTERS
from src.core.models import (
    CREDENTIAL_VALUE,
    ResourceAuth,
    ResourceConfig,
    RuntimeCredentials,
    TestStrategy,
    TlsSettings,
)
from src.core.models.external_tools import ExternalToolsConfig
from src.core.templating import names_in, occurrences, placeholder_names, unquoted_placeholders
from src.core.test_metadata import PRIORITY_MAX, PRIORITY_MIN, is_valid_test_id
from src.test_config.domain_7 import (
    TEST_72_PLACEHOLDER_RANDOM_SECRET,
    TEST_72_PLACEHOLDER_SSRF_URL,
)

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

# Test 7.2's URL placeholder before Phase E, named in the error that rejects it.
_FORMER_SSRF_SENTINEL: str = "$SSRF_URL$"

# Keys moved by the configuration by connection (docs/architecture/design-decisions.md,
# D1), rejected with their new place.
_MOVED_TARGET_KEYS: dict[str, str] = {
    "openapi_spec_url": "specification.url",
    "openapi_spec_path": "specification.path",
    "gateway_adapter": "gateway.adapter",
    "admin_api_url": "gateway.admin.url",
    "admin_api_headers": "gateway.admin.headers",
    "admin_connect_timeout_seconds": "gateway.admin.connect_timeout",
    "admin_read_timeout_seconds": "gateway.admin.read_timeout",
    "health_api_url": "gateway.health.url",
    "verify_tls": "target.tls.verify",
}
_MOVED_EXECUTION_KEYS: dict[str, str] = {
    "connect_timeout": "target.connect_timeout",
    "read_timeout": "target.read_timeout",
    "max_retry_attempts": "target.max_retry_attempts",
    "openapi_fetch_timeout_seconds": "specification.timeout",
}


def _reject_moved_keys(data: object, section: str, moved: dict[str, str]) -> object:
    """Raise ValueError naming the new place of a key moved out of a section."""
    if isinstance(data, dict):
        found = [key for key in moved if key in data]
        if found:
            raise ValueError(
                "; ".join(f"{section}.{key} moved: use {moved[key]}" for key in found)
                + " (configuration by connection, see config.example.yaml)."
            )
    return data


# Name of a prepared resource (resources:), referred to by other keys.
RESOURCE_NAME_PATTERN: re.Pattern[str] = re.compile(r"[A-Za-z0-9_-]+")

# ---------------------------------------------------------------------------
# Constants -- gateway Admin API timeouts
# ---------------------------------------------------------------------------

# The gateway Admin API is a local endpoint (same host or same LAN).  The short
# defaults reflect that expectation: if the Admin API does not respond in 10 s
# the connection is almost certainly misconfigured, not merely slow.
# Operators who run the Admin API behind a slow inter-datacenter link can
# raise these via gateway.admin.connect_timeout / gateway.admin.read_timeout.
ADMIN_CONNECT_TIMEOUT_DEFAULT: float = 5.0
ADMIN_READ_TIMEOUT_DEFAULT: float = 10.0
ADMIN_CONNECT_TIMEOUT_MIN: float = 1.0
ADMIN_CONNECT_TIMEOUT_MAX: float = 30.0
ADMIN_READ_TIMEOUT_MIN: float = 1.0
ADMIN_READ_TIMEOUT_MAX: float = 60.0

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
    The API under test: its address, how the tool connects to it, real path parameter values.

    The requests of every test go to base_url. Connection settings (timeouts,
    retries, certificate check) are those of this connection only
    (docs/architecture/design-decisions.md, D1).
    """

    model_config = {"frozen": True, "extra": "forbid"}

    base_url: AnyHttpUrl = Field(
        description=(
            "Base URL of the target API as exposed through the API Gateway proxy. "
            "Example: https://api.example.com"
        )
    )
    connect_timeout: Annotated[float, Field(ge=TIMEOUT_CONNECT_MIN, le=TIMEOUT_CONNECT_MAX)] = (
        Field(
            default=TIMEOUT_CONNECT_DEFAULT,
            description=(
                f"TCP connection timeout in seconds for the requests to the API. "
                f"Default: {TIMEOUT_CONNECT_DEFAULT}s."
            ),
        )
    )
    read_timeout: Annotated[float, Field(ge=TIMEOUT_READ_MIN, le=TIMEOUT_READ_MAX)] = Field(
        default=TIMEOUT_READ_DEFAULT,
        description=(
            f"HTTP read timeout in seconds for the requests to the API. "
            f"Default: {TIMEOUT_READ_DEFAULT}s."
        ),
    )
    max_retry_attempts: Annotated[
        int, Field(ge=RETRY_MAX_ATTEMPTS_MIN, le=RETRY_MAX_ATTEMPTS_MAX)
    ] = Field(
        default=RETRY_MAX_ATTEMPTS_DEFAULT,
        description=(
            f"Maximum attempts (initial + retries) of a request to the API after a "
            f"transport failure. Default: {RETRY_MAX_ATTEMPTS_DEFAULT}."
        ),
    )
    tls: TlsSettings | None = Field(
        default=None,
        description=(
            "Certificate settings of this connection (verify, ca_bundle, client_cert, "
            "client_key); absent: the system's authorities plus certifi's list."
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

    @model_validator(mode="before")
    @classmethod
    def reject_moved_keys(cls, data: object) -> object:
        """Reject the keys moved to specification and gateway, naming their new place."""
        return _reject_moved_keys(data, "target", _MOVED_TARGET_KEYS)

    @field_validator("base_url", mode="before")
    @classmethod
    def url_passthrough(cls, value: object) -> object:
        """Passthrough -- trailing slash normalisation happens in TargetContext."""
        return value


# ---------------------------------------------------------------------------
# SpecificationConfig
# ---------------------------------------------------------------------------


class SpecificationConfig(BaseModel):
    """
    The OpenAPI specification of the target: where it is read from.

    Exactly one of url and path. Use get_source() in downstream code to
    obtain the canonical string without branching on the source type.
    """

    model_config = {"frozen": True, "extra": "forbid"}

    url: AnyHttpUrl | None = Field(
        default=None,
        description=(
            "URL from which the OpenAPI specification is fetched at runtime. "
            "Mutually exclusive with path: set exactly one. "
            "Example: https://api.example.com/openapi.json"
        ),
    )
    path: Path | None = Field(
        default=None,
        description=(
            "Absolute or relative filesystem path to a locally stored OpenAPI "
            "specification file (JSON or YAML). "
            "Mutually exclusive with url: set exactly one. "
            "Relative paths are resolved against the working directory of the process. "
            "prance resolves intra-file $ref pointers normally; remote $ref entries "
            "inside a local spec still require network access. "
            "The file's existence is checked when the specification is loaded, so that "
            "the error message names the resolved absolute path. "
            "Example: ./specs/openapi.json"
        ),
    )
    timeout: Annotated[
        float,
        Field(ge=OPENAPI_FETCH_TIMEOUT_MIN, le=OPENAPI_FETCH_TIMEOUT_MAX),
    ] = Field(
        default=OPENAPI_FETCH_TIMEOUT_DEFAULT,
        description=(
            "Timeout in seconds for loading the specification (download from url and "
            "$ref dereferencing). Only relevant with url; local files load well within "
            f"it. Range: [{OPENAPI_FETCH_TIMEOUT_MIN}, {OPENAPI_FETCH_TIMEOUT_MAX}]. "
            f"Default: {OPENAPI_FETCH_TIMEOUT_DEFAULT}s."
        ),
    )

    tls: TlsSettings | None = Field(
        default=None,
        description=(
            "Certificate settings of this connection (verify, ca_bundle, client_cert, "
            "client_key); absent: the system's authorities plus certifi's list."
        ),
    )

    @model_validator(mode="after")
    def exactly_one_source(self) -> SpecificationConfig:
        """
        Require exactly one of url and path.

        Neither: Phase 2 could not build an AttackSurface. Both: ambiguous,
        likely an old field left behind when switching source type. File
        existence is checked when the specification is loaded, so that the
        error message names the resolved absolute path.
        """
        if self.url is not None and self.path is not None:
            raise ValueError(
                "specification: set exactly one of 'url' and 'path', not both. Remove the "
                "one you do not intend to use."
            )
        if self.url is None and self.path is None:
            raise ValueError(
                "specification: set 'url' (e.g. https://api.example.com/openapi.json) or "
                "'path' (e.g. ./specs/openapi.json)."
            )
        return self

    def get_source(self) -> str:
        """
        Return the canonical string of the specification source.

        Returns:
            The URL, or the absolute filesystem path.

        Raises:
            RuntimeError: If neither is set (unreachable after validation).
        """
        if self.url is not None:
            return str(self.url)
        if self.path is not None:
            return str(self.path.resolve())
        raise RuntimeError(
            "SpecificationConfig.get_source() called with neither url nor path set; "
            "exactly_one_source should have caught it."
        )

    @property
    def is_local(self) -> bool:
        """True if the specification is read from a local file."""
        return self.path is not None


# ---------------------------------------------------------------------------
# GatewayConfig
# ---------------------------------------------------------------------------


class GatewayAdminConfig(BaseModel):
    """The gateway's Admin API: where the configuration audits read the gateway's configuration."""

    model_config = {"frozen": True, "extra": "forbid"}

    url: AnyHttpUrl = Field(
        description=(
            "URL of the gateway Admin API, read by the configuration audits (3.3, 4.2, "
            "4.3, 6.4 sub-test B). Example: https://gw-admin.internal:8444"
        ),
    )
    headers: dict[str, str] = Field(
        default_factory=dict,
        description=(
            "Headers sent on every Admin API request, for a gateway that protects it: "
            "e.g. APISIX 'X-API-KEY', Kong Enterprise 'Kong-Admin-Token'. Write the values "
            "as ${VAR} placeholders: they are registered as secrets and masked in logs and "
            "reports. Default: none."
        ),
    )
    connect_timeout: Annotated[
        float,
        Field(ge=ADMIN_CONNECT_TIMEOUT_MIN, le=ADMIN_CONNECT_TIMEOUT_MAX),
    ] = Field(
        default=ADMIN_CONNECT_TIMEOUT_DEFAULT,
        description=(
            "TCP connection timeout in seconds for the Admin API and the health API. "
            "The default (5 s) is short: the Admin API is usually a local endpoint. "
            f"Range: [{ADMIN_CONNECT_TIMEOUT_MIN}, {ADMIN_CONNECT_TIMEOUT_MAX}]. "
            f"Default: {ADMIN_CONNECT_TIMEOUT_DEFAULT} s."
        ),
    )
    read_timeout: Annotated[
        float,
        Field(ge=ADMIN_READ_TIMEOUT_MIN, le=ADMIN_READ_TIMEOUT_MAX),
    ] = Field(
        default=ADMIN_READ_TIMEOUT_DEFAULT,
        description=(
            "HTTP read timeout in seconds for the Admin API and the health API. "
            f"Range: [{ADMIN_READ_TIMEOUT_MIN}, {ADMIN_READ_TIMEOUT_MAX}]. "
            f"Default: {ADMIN_READ_TIMEOUT_DEFAULT} s."
        ),
    )

    tls: TlsSettings | None = Field(
        default=None,
        description=(
            "Certificate settings of this connection (verify, ca_bundle, client_cert, "
            "client_key); absent: the system's authorities plus certifi's list."
        ),
    )

    @field_validator("headers")
    @classmethod
    def headers_not_empty(cls, value: dict[str, str]) -> dict[str, str]:
        """Reject an empty header name or an empty value (e.g. a variable set to nothing)."""
        for name, header_value in value.items():
            if not name.strip():
                raise ValueError("gateway.admin.headers: a header name is empty")
            if not header_value.strip():
                raise ValueError(
                    f"gateway.admin.headers: the value of '{name}' is empty "
                    "(is its environment variable set?)"
                )
        return value


class GatewayHealthConfig(BaseModel):
    """The gateway interface that reports the live health of the backends, when separate."""

    model_config = {"frozen": True, "extra": "forbid"}

    url: AnyHttpUrl = Field(
        description=(
            "URL of the gateway interface that reports the live health of the backends, "
            "for a gateway that keeps it outside the Admin API (APISIX: Control API). "
            "Read by test 4.3; the Admin API headers are not sent to it. Not used by "
            "Kong, whose Admin API reports it. Example: http://127.0.0.1:9090"
        ),
    )
    tls: TlsSettings | None = Field(
        default=None,
        description=(
            "Certificate settings of this connection (verify, ca_bundle, client_cert, "
            "client_key); absent: the system's authorities plus certifi's list."
        ),
    )


class GatewayConfig(BaseModel):
    """
    The API gateway in front of the target, for the WHITE_BOX configuration audits.

    Optional: without it the audits SKIP. adapter chooses how its configuration
    is read (GATEWAY_ADAPTERS); admin is required with it.
    """

    model_config = {"frozen": True, "extra": "forbid"}

    adapter: str = Field(
        description=(
            "Gateway adapter: the keys of GATEWAY_ADAPTERS (src/core/gateway/__init__.py), "
            "today 'kong' and 'apisix'."
        ),
    )
    admin: GatewayAdminConfig = Field(description="The gateway's Admin API.")
    health: GatewayHealthConfig | None = Field(
        default=None,
        description="The gateway's health interface, when separate from the Admin API (APISIX).",
    )

    @field_validator("adapter", mode="after")
    @classmethod
    def adapter_supported(cls, value: str) -> str:
        """Accept only the adapters the tool offers."""
        if value not in GATEWAY_ADAPTERS:
            raise ValueError(
                f"Unsupported gateway.adapter: '{value}'. "
                f"Supported values: {sorted(GATEWAY_ADAPTERS)}."
            )
        return value


# ---------------------------------------------------------------------------
# ExecutionConfig
# ---------------------------------------------------------------------------


class ExecutionConfig(BaseModel):
    """What the run does: which tests, and whether it stops at the first P0 failure."""

    model_config = {"frozen": True, "extra": "forbid"}

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

    @model_validator(mode="before")
    @classmethod
    def reject_moved_keys(cls, data: object) -> object:
        """Reject the connection settings moved to target and specification."""
        return _reject_moved_keys(data, "execution", _MOVED_EXECUTION_KEYS)

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
        Validate that each test_id follows an accepted format.

        Two formats are recognised:

            Native tests  -- 'X.Y'
                Both X and Y must be non-negative integer strings.
                Examples: '0.1', '4.1', '7.2'.
                Used by all BaseTest subclasses in src/tests/domain_*/.

            External tests -- 'ext.X.Y.toolname'
                Prefixed with the literal string 'ext', followed by two
                non-negative integer strings X (domain) and Y (sequence),
                then a non-empty alphanumeric tool identifier.
                Examples: 'ext.0.1.nuclei', 'ext.1.5.testssl', 'ext.1.5.sslyze'.
                Used by ExternalToolTest subclasses in src/external_tests/.
                The 'ext.' prefix avoids collision with native test IDs; the
                tool suffix makes the ID self-documenting and unique when
                multiple tools cover the same guarantee.

        This validator catches obvious typos early, before the registry
        attempts the lookup and silently produces an empty filtered list.
        """
        if not isinstance(value, list):
            return value
        for item in value:
            if not isinstance(item, str):
                raise ValueError(f"Each test_id must be a string. Got: {item!r}")
            if not is_valid_test_id(item):
                raise ValueError(
                    f"Invalid test_id format: {item!r}. "
                    "Accepted formats: 'X.Y' for native tests (e.g. '4.1', '0.2') "
                    "or 'ext.X.Y.toolname' for external tests "
                    "(e.g. 'ext.1.5.testssl', 'ext.0.1.nuclei')."
                )
        return value


# ---------------------------------------------------------------------------
# OutputConfig
# ---------------------------------------------------------------------------


class OutputConfig(BaseModel):
    """Configuration for output file locations."""

    model_config = {"frozen": True, "extra": "forbid"}

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

    model_config = {"frozen": True, "extra": "forbid"}

    target: TargetConfig = Field(description="The API under test and how the tool connects to it.")
    specification: SpecificationConfig = Field(
        description="The OpenAPI specification of the target: a URL or a local file."
    )
    gateway: GatewayConfig | None = Field(
        default=None,
        description=("The API gateway, for the WHITE_BOX configuration audits; absent: they SKIP."),
    )
    credentials: RuntimeCredentials = Field(
        default_factory=RuntimeCredentials,
        description=(
            "Authentication credentials injected via environment variables; the same "
            "model reaches the tests (src/core/models/runtime.py)."
        ),
    )
    resources: dict[str, ResourceConfig] = Field(
        default_factory=dict,
        description=(
            "Prepared resources: what the tool creates on the target and deletes at the end "
            "of the run, by name (letters, digits, '_', '-'). Each has a create request, values "
            "taken from its JSON response and an optional delete request "
            "(src/core/models/resources.py, docs/architecture/design-decisions.md D6)."
        ),
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
    external_tools: ExternalToolsConfig = Field(
        default_factory=ExternalToolsConfig,
        description=(
            "Configuration for external tool connectors (testssl.sh, nuclei, sslyze). "
            "If the 'external_tools' key is absent from config.yaml, every tool is "
            "disabled: no external test is scheduled (native-only mode). "
            "When a tool is enabled=True, timeout_seconds is mandatory or Phase 1 "
            "raises ConfigurationError."
        ),
    )

    _white_box_without_gateway: bool = PrivateAttr(default=False)
    _white_box_without_admin_credentials: bool = PrivateAttr(default=False)
    _grey_box_without_user_credentials: bool = PrivateAttr(default=False)

    @field_validator("resources", mode="after")
    @classmethod
    def resource_names_valid(cls, value: dict[str, ResourceConfig]) -> dict[str, ResourceConfig]:
        """Require resource names made of letters, digits, '_' and '-'."""
        for name in value:
            if not RESOURCE_NAME_PATTERN.fullmatch(name):
                raise ValueError(
                    f"resource name '{name}' must be letters, digits, '_' and '-' "
                    "(it is referred to by other keys)."
                )
        return value

    @model_validator(mode="after")
    def login_resource_valid(self) -> ToolConfig:
        """
        Check the login resource of auth_type 'login'.

        It must be defined, have the value 'credential' (the token) and not
        authenticate its create request with the credential it obtains
        (docs/architecture/design-decisions.md, D6).
        """
        name = self.credentials.login_resource
        if name is None:
            return self
        where = "credentials.login_resource"
        resource = self.resources.get(name)
        if resource is None:
            defined = ", ".join(sorted(self.resources)) or "none"
            raise ValueError(
                f"{where}: resource '{name}' is not defined in resources (defined: {defined})."
            )
        if CREDENTIAL_VALUE not in resource.values:
            raise ValueError(
                f"{where}: resource '{name}' needs a value '{CREDENTIAL_VALUE}', the dotted "
                "path of the token in the login response (e.g. credential: token)."
            )
        if resource.create.auth is ResourceAuth.CREDENTIAL:
            raise ValueError(
                f"{where}: resource '{name}' logs in, so its create request cannot use "
                "auth: credential (the credential is what it obtains): use 'basic' or 'none'."
            )
        return self

    @model_validator(mode="after")
    def test_7_2_injection_placeholders(self) -> ToolConfig:
        """
        Check test 7.2's injection endpoint against the resources.

        injection_resource must name a resource; the path may use its values;
        the body must hold {ssrf_url} exactly once and may use {random_secret}
        and the resource's values, in quotes (docs/architecture/design-decisions.md,
        D6).
        """
        cfg = self.tests.domain_7.test_7_2
        where = "tests.domain_7.test_7_2"
        values: frozenset[str] = frozenset()
        if cfg.injection_resource is not None:
            resource = self.resources.get(cfg.injection_resource)
            if resource is None:
                defined = ", ".join(sorted(self.resources)) or "none"
                raise ValueError(
                    f"{where}.injection_resource: resource '{cfg.injection_resource}' is not "
                    f"defined in resources (defined: {defined})."
                )
            values = frozenset(resource.values)
        if cfg.injection_path_template is not None:
            unknown = placeholder_names(cfg.injection_path_template) - values
            if unknown:
                raise ValueError(
                    f"{where}.injection_path_template: unknown placeholder(s) "
                    f"{', '.join(f'{{{n}}}' for n in sorted(unknown))}; known: the values of "
                    "injection_resource."
                )
        body = cfg.injection_body_template
        if body is None:
            return self
        known = values | {TEST_72_PLACEHOLDER_SSRF_URL, TEST_72_PLACEHOLDER_RANDOM_SECRET}
        unquoted = unquoted_placeholders(body, known)
        if unquoted:
            raise ValueError(
                f"{where}.injection_body_template: write the placeholders in quotes, e.g. "
                f'"{{{sorted(unquoted)[0]}}}": unquoted, YAML reads them as a mapping.'
            )
        unknown = names_in(body) - known
        if unknown:
            raise ValueError(
                f"{where}.injection_body_template: unknown placeholder(s) "
                f"{', '.join(f'{{{n}}}' for n in sorted(unknown))}; known: "
                f"{', '.join(f'{{{n}}}' for n in sorted(known))}."
            )
        count = occurrences(body, TEST_72_PLACEHOLDER_SSRF_URL)
        if count != 1:
            hint = (
                " The former '$SSRF_URL$' and '$RANDOM_SECRET$' are now "
                '"{ssrf_url}" and "{random_secret}".'
                if _FORMER_SSRF_SENTINEL in str(body)
                else ""
            )
            raise ValueError(
                f"{where}.injection_body_template must contain "
                f'"{{{TEST_72_PLACEHOLDER_SSRF_URL}}}" exactly once, where the SSRF URL goes '
                f"(found {count}).{hint}"
            )
        return self

    @model_validator(mode="after")
    def validate_cross_submodel_coherence(self) -> ToolConfig:
        """
        Detect selected strategies whose tests will SKIP for lack of access.

        Each rule mirrors the exact SKIP condition of the tests concerned:
            Rule 1: WHITE_BOX without a gateway section: no gateway adapter
                    is created, so the gateway configuration audits SKIP.
            Rule 2: WHITE_BOX without admin credentials: the tests that use
                    the API's administrator account SKIP.
            Rule 3: GREY_BOX without user_a credentials: the tests that use a
                    normal user account (role user_a) SKIP.

        They produce loader.py WARNINGs, not validation errors, because
        scoped assessments without some kinds of access are legitimate.
        """
        if TestStrategy.WHITE_BOX in self.execution.strategies:
            if self.gateway is None:
                self._white_box_without_gateway = True
            if not self.credentials.has_admin():
                self._white_box_without_admin_credentials = True

        if TestStrategy.GREY_BOX in self.execution.strategies and not self.credentials.has_user_a():
            self._grey_box_without_user_credentials = True

        return self

    @property
    def white_box_without_gateway(self) -> bool:
        """True if WHITE_BOX is selected but no gateway adapter is configured."""
        return self._white_box_without_gateway

    @property
    def white_box_without_admin_credentials(self) -> bool:
        """True if WHITE_BOX is selected but the admin credentials are absent."""
        return self._white_box_without_admin_credentials

    @property
    def grey_box_without_user_credentials(self) -> bool:
        """True if GREY_BOX is selected but the user_a credentials are absent."""
        return self._grey_box_without_user_credentials

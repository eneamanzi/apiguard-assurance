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

    OpenAPI spec source (URL vs. local path)
    -----------------------------------------
    TargetConfig supports two mutually exclusive sources for the OpenAPI spec:
        openapi_spec_url  -- fetch over HTTP/HTTPS at Phase 2 runtime.
        openapi_spec_path -- read from the local filesystem at Phase 2 runtime.
    Exactly one of the two must be present; the model_validator raises
    ValueError when both or neither are provided.

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

# Name of a prepared resource (resources:), referred to by other keys.
RESOURCE_NAME_PATTERN: re.Pattern[str] = re.compile(r"[A-Za-z0-9_-]+")

# ---------------------------------------------------------------------------
# Constants -- gateway Admin API timeouts
# ---------------------------------------------------------------------------

# The gateway Admin API is a local endpoint (same host or same LAN).  The short
# defaults reflect that expectation: if the Admin API does not respond in 10 s
# the connection is almost certainly misconfigured, not merely slow.
# Operators who run the Admin API behind a slow inter-datacenter link can
# raise these via target.admin_connect_timeout_seconds /
# target.admin_read_timeout_seconds in config.yaml.
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
    Connection parameters for the target API and its infrastructure.

    OpenAPI spec source
    -------------------
    Exactly one of openapi_spec_url or openapi_spec_path must be provided.
    The model_validator enforce_exactly_one_openapi_source verifies this at
    load time. Use get_openapi_source() in all downstream code to obtain the
    canonical string representation without if/else branching on source type.
    """

    model_config = {"frozen": True, "extra": "forbid"}

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
            "URL of the API Gateway Admin API, required by the tests that read the "
            "gateway configuration (3.3, 4.2, 4.3, 6.4 sub-test B). If absent, those "
            "tests return SKIP or skip that part. "
            "Example: http://localhost:8001"
        ),
    )
    admin_api_headers: dict[str, str] = Field(
        default_factory=dict,
        description=(
            "Headers sent on every read of the gateway's interfaces (Admin API), for a "
            "gateway that protects them: e.g. APISIX 'X-API-KEY', Kong Enterprise "
            "'Kong-Admin-Token'. Write the values as ${VAR} placeholders: they are "
            "registered as secrets and masked in logs and reports. Default: none."
        ),
    )
    health_api_url: AnyHttpUrl | None = Field(
        default=None,
        description=(
            "URL of the gateway interface that reports the live health of the backends, "
            "for a gateway that keeps it outside the Admin API (APISIX: Control API). "
            "Read by test 4.3 (observability); admin_api_headers are not sent to it. "
            "Not used by Kong, whose Admin API reports it. If absent on such a gateway, "
            "the live health is reported as not accessible. "
            "Example: http://127.0.0.1:10002"
        ),
    )
    admin_connect_timeout_seconds: Annotated[
        float,
        Field(ge=ADMIN_CONNECT_TIMEOUT_MIN, le=ADMIN_CONNECT_TIMEOUT_MAX),
    ] = Field(
        default=ADMIN_CONNECT_TIMEOUT_DEFAULT,
        description=(
            "TCP connection timeout in seconds for gateway Admin API requests. "
            "The Admin API is a local endpoint; the default (5 s) is intentionally "
            "short.  Raise this only when the Admin API is behind a slow link. "
            f"Range: [{ADMIN_CONNECT_TIMEOUT_MIN}, {ADMIN_CONNECT_TIMEOUT_MAX}]. "
            f"Default: {ADMIN_CONNECT_TIMEOUT_DEFAULT} s."
        ),
    )
    admin_read_timeout_seconds: Annotated[
        float,
        Field(ge=ADMIN_READ_TIMEOUT_MIN, le=ADMIN_READ_TIMEOUT_MAX),
    ] = Field(
        default=ADMIN_READ_TIMEOUT_DEFAULT,
        description=(
            "HTTP read timeout in seconds for gateway Admin API requests. "
            "Covers paginated list responses (routes, plugins, services); "
            "10 s is sufficient for any local Admin API. "
            f"Range: [{ADMIN_READ_TIMEOUT_MIN}, {ADMIN_READ_TIMEOUT_MAX}]. "
            f"Default: {ADMIN_READ_TIMEOUT_DEFAULT} s."
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
    gateway_adapter: str | None = Field(
        default=None,
        description=(
            "Gateway adapter type to use for WHITE_BOX configuration audit tests. "
            "When set, engine.py Phase 3 instantiates the corresponding adapter and "
            "exposes it as target.gateway in TargetContext. "
            "Supported: the keys of GATEWAY_ADAPTERS (src/core/gateway/__init__.py); "
            "today 'kong' and 'apisix'. "
            "Leave unset (None) to skip all gateway-specific WHITE_BOX tests: "
            "those tests will return SKIP with the reason "
            "'Gateway adapter not configured: ...' (BaseTest._requires_admin_api). "
            "Requires admin_api_url to also be set when non-None."
        ),
    )

    @field_validator("admin_api_headers")
    @classmethod
    def admin_api_headers_not_empty(cls, value: dict[str, str]) -> dict[str, str]:
        """Reject an empty header name or an empty value (e.g. a variable set to nothing)."""
        for name, header_value in value.items():
            if not name.strip():
                raise ValueError("admin_api_headers: a header name is empty")
            if not header_value.strip():
                raise ValueError(
                    f"admin_api_headers: the value of '{name}' is empty "
                    "(is its environment variable set?)"
                )
        return value

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

    @model_validator(mode="after")
    def gateway_adapter_requires_admin_api_url(self) -> TargetConfig:
        """Enforce that gateway_adapter is only set when admin_api_url is also present."""
        if self.gateway_adapter is not None and self.admin_api_url is None:
            raise ValueError(
                f"target.gateway_adapter='{self.gateway_adapter}' requires "
                "target.admin_api_url to be set in config.yaml. "
                "The gateway adapter uses the admin API URL to contact the "
                "gateway admin plane."
            )
        if self.gateway_adapter is not None and self.gateway_adapter not in GATEWAY_ADAPTERS:
            raise ValueError(
                f"Unsupported target.gateway_adapter: '{self.gateway_adapter}'. "
                f"Supported values: {sorted(GATEWAY_ADAPTERS)}."
            )
        return self

    @field_validator(
        "base_url", "openapi_spec_url", "admin_api_url", "health_api_url", mode="before"
    )
    @classmethod
    def url_passthrough(cls, value: object) -> object:
        """Passthrough -- trailing slash normalisation happens in TargetContext."""
        return value


# ---------------------------------------------------------------------------
# ExecutionConfig
# ---------------------------------------------------------------------------


class ExecutionConfig(BaseModel):
    """Parameters that control the pipeline execution behavior."""

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

    target: TargetConfig = Field(
        description="Connection parameters for the target API and its infrastructure."
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
            "(src/core/models/resources.py, docs/project/resources-design.md)."
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
        (docs/project/resources-design.md, 5.4 and 5.8).
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
        and the resource's values, in quotes (docs/project/resources-design.md,
        5.6 and 5.8).
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
            Rule 1: WHITE_BOX without target.gateway_adapter: no gateway
                    adapter is created (it needs gateway_adapter and
                    admin_api_url), so the gateway configuration audits SKIP.
            Rule 2: WHITE_BOX without admin credentials: the tests that use
                    the API's administrator account SKIP.
            Rule 3: GREY_BOX without user_a credentials: the tests that use a
                    normal user account (role user_a) SKIP.

        They produce loader.py WARNINGs, not validation errors, because
        scoped assessments without some kinds of access are legitimate.
        """
        if TestStrategy.WHITE_BOX in self.execution.strategies:
            if self.target.gateway_adapter is None:
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

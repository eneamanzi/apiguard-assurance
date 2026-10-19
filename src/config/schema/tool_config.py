"""
src/config/schema/tool_config.py

Pydantic v2 models for the tool-level (infrastructure) configuration.

This module owns the configuration that describes the tool itself and its
runtime environment: where to find the target, what credentials to use,
how to execute the pipeline, and where to write output. It does NOT contain
the tests' parameters: each test declares its own model, and the tests
section is checked once the tests are discovered
(src/config/tests_section.py); here it is kept as written.

Design notes preserved from the original schema.py:

    Configuration by connection (docs/architecture/design-decisions.md, D1)
    ----------------------------------------------------------------
    Every party the tool talks to is a section with its own settings:
        target         the API under test (base_url, timeouts, retries);
        specification  the OpenAPI document (url or path, exactly one; timeout);
        gateway        optional, for the configuration audits (adapter,
                       admin: url, headers, timeouts; health: url).

Dependency rule: imports from pydantic, the stdlib, src.core.models (for
TestStrategy, RuntimeCredentials, ResourceConfig), src.core.templating (to
check placeholders). Must never import from engine.py, tests/,
discovery/, or report/.
"""

from __future__ import annotations

import re
from pathlib import Path
from typing import Annotated, Any

from pydantic import (
    AnyHttpUrl,
    BaseModel,
    Field,
    field_validator,
    model_validator,
)

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
from src.core.models.runtime import SECRET_VALUE
from src.core.test_metadata import PRIORITY_MAX, PRIORITY_MIN, is_valid_test_id

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
CONFIG_USED_FILENAME: str = "config_used.yaml"

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
            "Base URL of the API as exposed through the gateway proxy, e.g. "
            "https://api.example.com."
        )
    )
    connect_timeout: Annotated[float, Field(ge=TIMEOUT_CONNECT_MIN, le=TIMEOUT_CONNECT_MAX)] = (
        Field(
            default=TIMEOUT_CONNECT_DEFAULT,
            description="TCP connect timeout (s) for requests to the API.",
        )
    )
    read_timeout: Annotated[float, Field(ge=TIMEOUT_READ_MIN, le=TIMEOUT_READ_MAX)] = Field(
        default=TIMEOUT_READ_DEFAULT,
        description="Read timeout (s) for requests to the API.",
    )
    max_retry_attempts: Annotated[
        int, Field(ge=RETRY_MAX_ATTEMPTS_MIN, le=RETRY_MAX_ATTEMPTS_MAX)
    ] = Field(
        default=RETRY_MAX_ATTEMPTS_DEFAULT,
        description=(
            "Total attempts (initial + retries). Only transport errors are retried, never "
            "HTTP status codes and never a TLS failure."
        ),
    )
    tls: TlsSettings | None = Field(
        default=None,
        description=(
            "Certificate settings of the API connection, also used by the HTTP-redirect "
            "probe of test 1.5 and given to the external TLS tests (`ca_bundle`)."
        ),
    )
    path_seed: dict[str, str] = Field(
        default_factory=dict,
        description=(
            'Real values for OpenAPI path parameters (`{owner}` → `"alice"`). Unlisted '
            "parameters fall back to the test's placeholder (typically `1`; "
            "`apiguard-probe` in a DELETE, so that it matches no real resource). Generate "
            "with `apiguard generate-seed`. **Use only test resources you can lose:** the "
            "values are used for every request, including `DELETE` and writes sent without "
            "credentials (test 1.1); on an API without protection on those endpoints they "
            "are deleted or changed."
        ),
    )

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
            "Downloaded by the tool at runtime (Phase 2), redirects followed, with the "
            "settings of `tls`. Exactly one of `url` and `path`."
        ),
    )
    path: Path | None = Field(
        default=None,
        description=(
            "Local file (JSON or YAML), relative to the working directory. Exactly one of "
            "`url` and `path`. Its existence is checked when the specification is loaded "
            "(Phase 2; `validate-config` only when credentials are configured). Remote "
            "`$ref` entries inside it still need network access."
        ),
    )
    timeout: Annotated[
        float,
        Field(ge=OPENAPI_FETCH_TIMEOUT_MIN, le=OPENAPI_FETCH_TIMEOUT_MAX),
    ] = Field(
        default=OPENAPI_FETCH_TIMEOUT_DEFAULT,
        description=(
            "Timeout (s) of the download (the connection and each read), and, separately, "
            "the limit of the `$ref` dereferencing as a whole. When one expires the run "
            "stops with exit `10`, also if the server accepts the connection and never "
            "answers."
        ),
    )

    tls: TlsSettings | None = Field(
        default=None,
        description=(
            "Certificate settings of the download; ignored (with a warning) for an "
            "`http://` URL, unused for `path`."
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
            "The gateway's Admin API, read with GET requests only by the configuration "
            "audits (3.3, 4.2, 4.3, 6.4 sub-test B)."
        ),
    )
    headers: dict[str, str] = Field(
        default_factory=dict,
        description=(
            "Headers sent on every Admin API request, for a gateway that protects it: e.g. "
            "`X-API-KEY` (APISIX; a key of role `viewer`, GET only, is enough), "
            "`Kong-Admin-Token` (Kong Enterprise). Names and values not empty. Never sent "
            "to `health.url`. Write the values as `${VAR}`: they are registered as secrets "
            "and masked in logs and reports."
        ),
        json_schema_extra=SECRET_VALUE,
    )
    connect_timeout: Annotated[
        float,
        Field(ge=ADMIN_CONNECT_TIMEOUT_MIN, le=ADMIN_CONNECT_TIMEOUT_MAX),
    ] = Field(
        default=ADMIN_CONNECT_TIMEOUT_DEFAULT,
        description=("TCP connect timeout (s) for the Admin API and the health interface."),
    )
    read_timeout: Annotated[
        float,
        Field(ge=ADMIN_READ_TIMEOUT_MIN, le=ADMIN_READ_TIMEOUT_MAX),
    ] = Field(
        default=ADMIN_READ_TIMEOUT_DEFAULT,
        description=("Read timeout (s) for the Admin API and the health interface."),
    )

    tls: TlsSettings | None = Field(
        default=None,
        description=(
            "Certificate settings of the Admin API connection (e.g. the client certificate "
            "APISIX's `admin_api_mtls` requires)."
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
            "Interface reporting the live health of the backends, for a gateway that keeps "
            "it outside the Admin API: the APISIX Control API (e.g. "
            "`http://127.0.0.1:9090`). Read by test 4.3 (observability), without the "
            "`admin.headers`. Not used by Kong. Absent on APISIX: the live health is "
            "reported as not accessible, the rest of the audits still run."
        ),
    )
    tls: TlsSettings | None = Field(
        default=None,
        description=(
            "Certificate settings of the health interface (APISIX's Control API has no TLS: "
            "leave it out)."
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
            "How the gateway's configuration is read: "
            + ", ".join(f"`{name}`" for name in GATEWAY_ADAPTERS)
            + "."
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
            "**Highest** priority level included (the name is historical): `0` = P0 only, "
            "`3` = all."
        ),
    )
    strategies: list[TestStrategy] = Field(
        default_factory=lambda: [
            TestStrategy.BLACK_BOX,
            TestStrategy.GREY_BOX,
            TestStrategy.WHITE_BOX,
        ],
        description=(
            "Tests, native and external, whose strategy is not listed are excluded (ignored "
            "when `test_ids` is set). Not empty."
        ),
    )
    fail_fast: bool = Field(
        default=False,
        description="Stop after the first P0 test returning FAIL or ERROR.",
    )
    test_ids: list[str] = Field(
        default_factory=list,
        description=(
            "Not empty: run **only** the listed tests, native (`X.Y`) or external "
            "(`ext.X.Y.tool`); `min_priority` and `strategies` are then ignored. It chooses "
            "only among available tests: an ID that does not exist, or an external test "
            "whose tool is disabled (`external_tools`), stops the tool at startup (exit "
            "`10`) with the reason and, for an unknown ID, the closest existing ID."
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
            "Destination of `evidence.json`, `assessment_report.html`, "
            "`apiguard_report.json`, `config_used.yaml`, `tools/` and the temporary "
            "`evidence_tmp/`, relative to the working directory. Created if missing."
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

    @property
    def config_used_path(self) -> Path:
        """Full path to the configuration the run used (src/config/config_used.py)."""
        return self.directory / CONFIG_USED_FILENAME


# ---------------------------------------------------------------------------
# ToolConfig (root)
# ---------------------------------------------------------------------------


class ToolConfig(BaseModel):
    """
    Root configuration model for the APIGuard Assurance tool.

    Frozen after construction.
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
    tests: dict[str, Any] = Field(
        default_factory=dict,
        description=(
            "Each test's parameters, as tests.domain_<D>.test_<D>_<N>.<param>. Checked "
            "against the models the tests declare once they are discovered "
            "(src/config/tests_section.py); every parameter has a default."
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

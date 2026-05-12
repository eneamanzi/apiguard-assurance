"""
src/config/schema/external_tools.py

Pydantic v2 schema for the optional `external_tools` section of config.yaml.

This schema is loaded during Phase 1 (Configuration Loading) as part of
ToolConfig validation.  If the `external_tools` key is absent from config.yaml,
ExternalToolsConfig is constructed with all defaults (all tools enabled=False),
meaning every ExternalToolTest degrades gracefully to SKIP — the assessment
runs in native-only mode without any operator intervention.

Design rules enforced by this schema:

    1. Master switch: ExternalToolsConfig.enabled = false disables ALL external
       tests at once, overriding per-tool settings.  Used for CI environments
       where external binaries are not available.

    2. Timeout obligation: a tool with enabled=True MUST declare timeout_seconds.
       A missing timeout on an enabled tool raises ConfigurationError at bootstrap
       (Phase 1 — bloccante).  This enforces the architectural invariant from
       ADR-001 §3.2: "Timeout obbligatorio nella firma".

    3. Per-tool on/off: each tool can be independently disabled even when the
       master switch is on.  Disabled tools produce SKIP without attempting
       binary discovery.

    4. extra_flags: a string of additional CLI flags passed verbatim to the
       binary.  Must not contain secrets (credentials, API keys) — those live in
       config.yaml under target.credentials and are passed via env vars at runtime
       by the connector, not via flags.

    5. BaseExternalToolConfig (Proposal B): all per-tool models inherit a shared
       base class that implements the timeout-when-enabled validator once,
       eliminating identical validator duplication across TestsslConfig,
       TestsslConfig.

Dependency rule: imports from pydantic and stdlib only.  Must never import from
engine.py, tests/, connectors/, external_tests/, or report/.
"""

from __future__ import annotations

import structlog
from pydantic import BaseModel, Field, model_validator

log: structlog.BoundLogger = structlog.get_logger(__name__)

# ---------------------------------------------------------------------------
# BaseExternalToolConfig (Proposal B)
# ---------------------------------------------------------------------------


class BaseExternalToolConfig(BaseModel):
    """
    Abstract base for all per-tool external connector configuration models.

    Enforces the two invariants shared by every tool:
        1. enabled: bool -- master flag for this specific tool.
        2. timeout_seconds: int | None -- mandatory when enabled=True.
        3. extra_flags: str -- additional CLI flags, no secrets allowed.

    The model_validator `_timeout_required_when_enabled` centralises the
    timeout obligation check (ADR-001 §3.2) so that subclasses do not need
    to replicate it.  Before this base class existed, TestsslConfig,
    TestsslConfig contained a byte-for-byte identical
    validator body -- a maintenance hazard where a future fix needed to be
    applied in three places.

    Subclass protocol:
        1. Inherit from BaseExternalToolConfig.
        2. Override `enabled`, `timeout_seconds`, and `extra_flags` with
           tool-specific Field() declarations (ge/le constraints, descriptions).
        3. Add tool-specific fields (e.g. connect_timeout for testssl) after the shared fields.
        4. Do NOT redeclare `_timeout_required_when_enabled` -- the base
           class validator is inherited automatically.

    The `_tool_name_for_error_message` property derives the tool name from
    the subclass class name (e.g. TestsslConfig -> "testssl") so the base
    validator produces a correct tool-specific error message without hardcoding.
    """

    model_config = {"frozen": True}

    enabled: bool = Field(
        default=False,
        description=(
            "Enable this tool connector.  When True, timeout_seconds is "
            "mandatory.  When False, all tests for this tool return SKIP "
            "without attempting binary discovery."
        ),
    )
    timeout_seconds: int | None = Field(
        default=None,
        description=(
            "Wall-clock timeout for a single tool execution in seconds. "
            "Mandatory when enabled=True.  Set in external_tools.<tool>.timeout_seconds "
            "in config.yaml."
        ),
    )
    extra_flags: str = Field(
        default="",
        description=(
            "Additional CLI flags appended to the tool invocation, verbatim. "
            "Must not contain credentials or secrets."
        ),
    )
    expected_version: str | None = Field(
        default=None,
        description=(
            "Pinned version string for this tool binary (e.g. '3.8.0'). "
            "When set, ExternalToolTest._warn_if_version_mismatch() compares "
            "this value against the output of '<binary> --version' at runtime. "
            "A mismatch emits a structured WARNING in the log -- the test is NOT "
            "skipped, but the analyst is alerted that the oracle in _evaluate() "
            "was written against a different version and output field names may "
            "have changed. "
            "Rationale (Version Pinning): the connector's _evaluate() method is "
            "tightly coupled to the JSON schema emitted by a specific binary "
            "version. If the tool is upgraded independently of the APIGuard "
            "release, field renames produce silent KeyErrors or empty findings "
            "rather than explicit errors. expected_version makes this coupling "
            "visible and auditable. "
            "Must match TOOL_VERSION in install_tools.sh and, when applicable, "
            "the ARG value in the Dockerfile. Keeping these three values in sync "
            "is enforced by code review convention, not by automation. "
            "License note: the pinned version declared here identifies which "
            "version of the third-party binary APIGuard has been validated "
            "against. APIGuard does not bundle or redistribute the binary; "
            "install_tools.sh downloads it directly from the upstream source. "
            "Operators are responsible for reviewing the license of each external "
            "tool (e.g. testssl.sh: GPLv2, nuclei: MIT) before use in commercial "
            "contexts."
        ),
    )
    dev_mode: bool = Field(
        default=False,
        description=(
            "Development mode for faster iteration on _evaluate() oracle logic. "
            "When True and a cached artifact file already exists at "
            "outputs/tools/<label>_output.json (written by a prior live run), "
            "ExternalToolTest._run() loads the file and skips the subprocess "
            "entirely -- including the is_available() check.  This means the "
            "binary does not need to be installed for subsequent runs once the "
            "cache exists. "
            "First-run behaviour (cache absent): the tool runs normally and "
            "pin_artifact() writes the cache file.  Every subsequent run reads "
            "from the cache until the file is deleted. "
            "Cache invalidation: delete outputs/tools/ or the specific "
            "<label>_output.json file to force a fresh tool execution. "
            "WARNING: never set to True in production assessments.  The cached "
            "output may be stale if the target configuration has changed since "
            "the last live run.  A structured WARNING is emitted on every cache "
            "hit to alert the operator."
        ),
    )

    @property
    def _tool_name_for_error_message(self) -> str:
        """
        Derive a lowercase tool name from the subclass class name for error messages.

        Convention: 'TestsslConfig' -> 'testssl'.
        This avoids hardcoding the tool name in the shared validator body.
        """
        return self.__class__.__name__.replace("Config", "").lower()

    @model_validator(mode="after")
    def _timeout_required_when_enabled(self) -> BaseExternalToolConfig:
        """
        Enforce timeout obligation: an enabled tool must declare timeout_seconds.

        Raised at schema validation time (Phase 1 -- bloccante).  A missing
        timeout on an enabled tool would silently fall back to the connector's
        DEFAULT_TIMEOUT_SECONDS, producing non-deterministic behaviour that
        violates the config-driven development principle.
        """
        if self.enabled and self.timeout_seconds is None:
            tool = self._tool_name_for_error_message
            raise ValueError(
                f"{tool} configuration error: 'timeout_seconds' is mandatory when "
                f"'enabled: true'.  Set 'external_tools.{tool}.timeout_seconds' in "
                "config.yaml."
            )
        return self


# ---------------------------------------------------------------------------
# Per-tool configuration models
# ---------------------------------------------------------------------------


class TestsslConfig(BaseExternalToolConfig):
    """
    Configuration for the testssl.sh connector (TLS analysis).

    testssl.sh performs deep TLS stack inspection: protocol versions,
    cipher suites, certificate chain, forward secrecy, HSTS, HPKP,
    Certificate Transparency SCTs.  It is the tool of choice for
    Garanzia 1.5 (TLS enforcement) in the methodology.

    The binary is discovered via:
        1. shutil.which("testssl.sh")   -- local install in PATH
        2. os.getenv("TESTSSL_SERVICE_URL") -- HTTP service in Docker Compose

    Binary-level JSON output is requested via --jsonfile <tmpfile> for
    portability across container environments where /dev/stdout may not
    behave predictably.
    """

    enabled: bool = Field(
        default=False,
        description=(
            "Enable the testssl.sh connector.  When True, timeout_seconds is "
            "mandatory.  When False, all ext_test_tls_* tests return SKIP "
            "without attempting binary discovery."
        ),
    )
    timeout_seconds: int | None = Field(
        default=None,
        ge=30,
        le=600,
        description=(
            "Wall-clock timeout for a single testssl.sh execution in seconds. "
            "Mandatory when enabled=True.  Recommended: 120.  "
            "testssl.sh can take 90-180 s on a full TLS scan of a live host. "
            "Minimum: 30 s (avoids false timeouts on fast hosts). "
            "Maximum: 600 s (prevents indefinite blocking of the pipeline)."
        ),
    )
    extra_flags: str = Field(
        default="--quiet --color 0",
        description=(
            "Additional CLI flags appended to the testssl.sh invocation, verbatim. "
            "Must not contain credentials or secrets.  "
            "Default disables interactive output for machine parsing."
        ),
    )


class NucleiConfig(BaseExternalToolConfig):
    """
    Configuration for the nuclei connector (template-based vulnerability scanning).

    nuclei applies YAML templates from a pinned local directory against the
    target to detect known exposures, misconfigurations, and shadow API paths.
    Used for Garanzia 0.1 (Shadow API Discovery) in the methodology.

    The binary is discovered via:
        1. Path.cwd() / "tools" / "nuclei" / "nuclei"  -- local tools directory
        2. shutil.which("nuclei")                        -- system PATH

    Template directory:
        Templates are pinned at a specific version alongside the binary.
        install_tools.sh downloads them to ./tools/nuclei-templates/ with
        NUCLEI_TEMPLATES_VERSION matching the compatible release for
        NUCLEI_VERSION.  NucleiConnector passes template_dir to nuclei
        via -t <template_dir>; the -duc flag is hardcoded to prevent
        automatic template updates that would break the pinned oracle.

    Flags hardcoded in NucleiConnector (not configurable here):
        -duc       disable update check (version pinning requirement)
        -ni        disable interactsh OAST (no external callbacks)
        -no-color  machine-readable output

    License: nuclei is distributed under the MIT License.
    APIGuard does not bundle or redistribute the nuclei binary or templates;
    install_tools.sh downloads them directly from the upstream GitHub
    repository at the pinned version.
    """

    enabled: bool = Field(
        default=False,
        description=(
            "Enable the nuclei connector.  When True, timeout_seconds is "
            "mandatory.  When False, ext_test_0_1_shadow_api_nuclei returns "
            "SKIP without attempting binary discovery."
        ),
    )
    timeout_seconds: int | None = Field(
        default=None,
        ge=60,
        le=600,
        description=(
            "Wall-clock timeout for a single nuclei execution in seconds. "
            "Mandatory when enabled=True.  Recommended: 240.  "
            "With 3319 templates and clustering, nuclei typically completes "
            "a focused tag-filtered scan in 2-4 minutes on a local target."
        ),
    )
    extra_flags: str = Field(
        default="",
        description=(
            "Additional CLI flags appended verbatim to the nuclei invocation. "
            "Must not contain credentials or secrets.  "
            "Do not include -duc, -ni, -no-color: those are hardcoded in "
            "NucleiConnector as architectural invariants."
        ),
    )
    template_dir: str = Field(
        default="./tools/nuclei-templates",
        description=(
            "Path to the pinned nuclei-templates directory, relative to the "
            "CWD at tool invocation time.  Must match the directory populated "
            "by install_tools.sh (NUCLEI_TEMPLATES_VERSION).  "
            "NucleiConnector passes this path to nuclei via -t <template_dir>."
        ),
    )
    tags: list[str] = Field(
        default_factory=lambda: ["api", "exposure", "misconfig", "panel"],
        description=(
            "nuclei template tags to include in the scan (-tags flag). "
            "Restricts execution to relevant templates, avoiding the noise "
            "of a full CVE scan on a local API target.  "
            "Default covers shadow API discovery: exposed Swagger/OpenAPI "
            "endpoints, admin panels, misconfigurations, and API-related "
            "exposures."
        ),
    )
    per_request_timeout: int = Field(
        default=10,
        ge=5,
        le=60,
        description=(
            "Per-request timeout in seconds passed to nuclei via -timeout. "
            "Distinct from timeout_seconds (total scan wall-clock limit). "
            "Controls how long nuclei waits for a single HTTP response. "
            "Default 10s is appropriate for local targets."
        ),
    )
    rate_limit_rps: int = Field(
        default=30,
        ge=1,
        le=150,
        description=(
            "Maximum HTTP requests per second passed to nuclei via -rl. "
            "Default 30 rps avoids triggering the target's own rate limiter "
            "(Test 4.1) during shadow API discovery."
        ),
    )


# ---------------------------------------------------------------------------
# Root external tools config
# ---------------------------------------------------------------------------


class ExternalToolsConfig(BaseModel):
    """
    Root configuration block for all external tool connectors.

    Mapped from the optional `external_tools` section of config.yaml.
    If the section is absent, all fields use their defaults (all disabled).

    Master switch semantics:
        enabled=False  -> ALL external tests return SKIP immediately, without
                         attempting binary discovery or reading per-tool config.
                         Use this in CI environments without external binaries.
        enabled=True   -> per-tool `enabled` fields are evaluated individually.
                         A tool with enabled=False still SKIPs; a tool with
                         enabled=True must have timeout_seconds configured or
                         Phase 1 raises ConfigurationError.
    """

    model_config = {"frozen": True}

    enabled: bool = Field(
        default=True,
        description=(
            "Master switch for all external tool tests.  "
            "False disables every ExternalToolTest regardless of per-tool settings. "
            "True (default) delegates to individual tool enabled flags."
        ),
    )
    testssl: TestsslConfig = Field(
        default_factory=TestsslConfig,
        description="Configuration for the testssl.sh connector.",
    )
    nuclei: NucleiConfig = Field(
        default_factory=NucleiConfig,
        description="Configuration for the nuclei connector.",
    )

    def is_tool_enabled(self, tool_name: str) -> bool:
        """
        Return True if the given tool is active (master switch AND per-tool switch).

        Proposal E: when tool_name is not found in the model's fields, emit a
        WARNING rather than silently returning False.  A typo in a test's
        `tool_name` ClassVar (e.g. 'testsll' instead of 'testssl') would
        otherwise cause the test to be excluded without any log entry, making
        the misconfiguration invisible during development.

        Args:
            tool_name: Currently "testssl" or "nuclei".  Any other value
                       logs a WARNING and returns False.

        Returns:
            bool: True only if both ExternalToolsConfig.enabled and the
                  per-tool enabled flag are True.
        """
        if not self.enabled:
            return False

        tool_cfg = getattr(self, tool_name, None)

        if tool_cfg is None:
            # Proposal E: emit a structured warning so developers notice typos
            # in the tool_name ClassVar immediately, rather than seeing a silent SKIP.
            known_tools: list[str] = [
                field_name for field_name in self.model_fields if field_name != "enabled"
            ]
            log.warning(
                "external_tools_unknown_tool_name",
                tool_name=tool_name,
                known_tools=known_tools,
                detail=(
                    "Test will be excluded from the run.  "
                    "Verify that the 'tool_name' ClassVar in the ExternalToolTest "
                    "subclass matches a key in ExternalToolsConfig "
                    f"({', '.join(known_tools)})."
                ),
            )
            return False

        return bool(getattr(tool_cfg, "enabled", False))

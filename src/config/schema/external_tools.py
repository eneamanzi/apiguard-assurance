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
       NucleiConfig, and FfufConfig.

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
    NucleiConfig, and FfufConfig each contained a byte-for-byte identical
    validator body -- a maintenance hazard where a future fix needed to be
    applied in three places.

    Subclass protocol:
        1. Inherit from BaseExternalToolConfig.
        2. Override `enabled`, `timeout_seconds`, and `extra_flags` with
           tool-specific Field() declarations (ge/le constraints, descriptions).
        3. Add tool-specific fields (e.g. template_tags for nuclei,
           wordlist_path for ffuf) after the shared fields.
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

    @property
    def _tool_name_for_error_message(self) -> str:
        """
        Derive a lowercase tool name from the subclass class name for error messages.

        Convention: 'TestsslConfig' -> 'testssl', 'NucleiConfig' -> 'nuclei'.
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
    Configuration for the nuclei connector (CVE / template-based scanning).

    nuclei applies community-maintained YAML templates against API endpoints
    to detect known vulnerabilities, misconfigurations, and exposed panels.
    Used primarily for Garanzia 0.1 supplement and 6.x audit in the methodology.

    The binary is discovered via:
        1. shutil.which("nuclei")            -- local install in PATH
        2. os.getenv("NUCLEI_SERVICE_URL")   -- HTTP service in Docker Compose
    """

    enabled: bool = Field(
        default=False,
        description=(
            "Enable the nuclei connector.  When True, timeout_seconds is "
            "mandatory.  When False, all ext_test_nuclei_* tests return SKIP."
        ),
    )
    timeout_seconds: int | None = Field(
        default=None,
        ge=60,
        le=900,
        description=(
            "Wall-clock timeout for a single nuclei execution in seconds. "
            "Mandatory when enabled=True.  Recommended: 300.  "
            "nuclei template sets can vary enormously in size; 300 s is "
            "conservative for a focused API-tag subset."
        ),
    )
    template_tags: list[str] = Field(
        default_factory=lambda: ["api", "token", "misconfig"],
        description=(
            "nuclei template tags to include in the scan (-tags flag). "
            "Restricts the scan to relevant templates and avoids the noise "
            "of full CVE scans on API targets.  "
            "Example: ['api', 'token', 'jwt', 'misconfig']."
        ),
    )
    extra_flags: str = Field(
        default="-silent -no-color",
        description=(
            "Additional CLI flags appended to the nuclei invocation, verbatim. "
            "Must not contain credentials or secrets."
        ),
    )


class FfufConfig(BaseExternalToolConfig):
    """
    Configuration for the ffuf connector (path fuzzing / Shadow API discovery).

    ffuf is a high-performance HTTP fuzzer used for Garanzia 0.1 (Shadow API
    discovery).  It sends a wordlist of candidate paths to the target and
    collects responses, allowing the tool to detect endpoints that exist on
    the gateway but are absent from the OpenAPI specification.

    The binary is discovered via:
        1. shutil.which("ffuf")            -- local install in PATH
        2. os.getenv("FFUF_SERVICE_URL")   -- HTTP service in Docker Compose

    wordlist_path must be an absolute path or a path relative to the working
    directory at tool invocation time.  The recommended wordlist is SecLists
    API-endpoints.txt (~5,000 entries).
    """

    enabled: bool = Field(
        default=False,
        description=(
            "Enable the ffuf connector.  When True, timeout_seconds is "
            "mandatory.  When False, all ext_test_shadow_* tests return SKIP."
        ),
    )
    timeout_seconds: int | None = Field(
        default=None,
        ge=30,
        le=600,
        description=(
            "Wall-clock timeout for a single ffuf execution in seconds. "
            "Mandatory when enabled=True.  Recommended: 180.  "
            "Depends heavily on wordlist size and target response time."
        ),
    )
    wordlist_path: str = Field(
        default="/usr/share/seclists/Discovery/Web-Content/api/api-endpoints.txt",
        description=(
            "Absolute or CWD-relative path to the wordlist file used by ffuf. "
            "The recommended file is SecLists API-endpoints.txt (approx 5,000 entries). "
            "If the path does not exist at runtime, ext_test_shadow_api_fuzzing "
            "returns SKIP with reason 'Wordlist not found at <path>'."
        ),
    )
    rate_limit_rps: int = Field(
        default=50,
        ge=1,
        le=500,
        description=(
            "ffuf request rate limit in requests-per-second (-rate flag). "
            "Default 50 rps is conservative enough to avoid triggering the "
            "target's own rate limiter (Test 4.1) during Shadow API discovery. "
            "Lower this value when testing production environments."
        ),
    )
    extra_flags: str = Field(
        default="-noninteractive -s",
        description=(
            "Additional CLI flags appended to the ffuf invocation, verbatim. "
            "Must not contain credentials or secrets.  "
            "Default enables non-interactive silent mode."
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
    ffuf: FfufConfig = Field(
        default_factory=FfufConfig,
        description="Configuration for the ffuf connector.",
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
            tool_name: One of "testssl", "nuclei", "ffuf".  Any other value
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
                field_name
                for field_name in self.model_fields
                if field_name != "enabled"
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

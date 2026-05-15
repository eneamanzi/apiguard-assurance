"""
src/core/models/external_tools.py

Pydantic v2 schema for external tool connector configuration.

Lives in core/models/ so that TargetContext (also in core/) can hold an
ExternalToolsConfig field without violating the unidirectional dependency
rule (core/ must not import from config/).

src/config/schema/external_tools.py re-exports all public symbols from this
module to preserve backward compatibility for any existing import paths.

Design rules:
    1. Master switch: ExternalToolsConfig.enabled = false disables ALL external
       tests, overriding per-tool settings.
    2. Timeout obligation: an enabled tool MUST declare timeout_seconds.
    3. Per-tool on/off: each tool can be independently disabled.
    4. extra_flags: additional CLI flags, must not contain secrets.

Dependency rule: imports from pydantic and stdlib only.
Must never import from config/, tests/, connectors/, external_tests/, or report/.
"""

from __future__ import annotations

import structlog
from pydantic import BaseModel, Field, model_validator

log: structlog.BoundLogger = structlog.get_logger(__name__)


# ---------------------------------------------------------------------------
# BaseExternalToolConfig
# ---------------------------------------------------------------------------


class BaseExternalToolConfig(BaseModel):
    """
    Abstract base for all per-tool external connector configuration models.

    Enforces the two invariants shared by every tool:
        1. enabled: bool -- master flag for this specific tool.
        2. timeout_seconds: int | None -- mandatory when enabled=True.
        3. extra_flags: str -- additional CLI flags, no secrets allowed.

    The model_validator ``_timeout_required_when_enabled`` centralises the
    timeout obligation check (ADR-001 §3.2) so that subclasses do not need
    to replicate it.

    Subclass protocol:
        1. Inherit from BaseExternalToolConfig.
        2. Override ``enabled``, ``timeout_seconds``, and ``extra_flags`` with
           tool-specific Field() declarations (ge/le constraints, descriptions).
        3. Add tool-specific fields after the shared fields.
        4. Do NOT redeclare ``_timeout_required_when_enabled``.
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
            "Mandatory when enabled=True."
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
            "this value against the binary's --version output at runtime. "
            "A mismatch emits a structured WARNING; the test is NOT skipped. "
            "Must match TOOL_VERSION in install_tools.sh."
        ),
    )
    dev_mode: bool = Field(
        default=False,
        description=(
            "Development mode for faster iteration on _evaluate() oracle logic. "
            "When True and a cached artifact file exists at "
            "outputs/tools/<label>_output.json, ExternalToolTest._run() loads "
            "the file and skips the subprocess entirely. "
            "WARNING: never set to True in production assessments."
        ),
    )

    @property
    def _tool_name_for_error_message(self) -> str:
        """Derive a lowercase tool name from the subclass class name for error messages."""
        return self.__class__.__name__.replace("Config", "").lower()

    @model_validator(mode="after")
    def _timeout_required_when_enabled(self) -> BaseExternalToolConfig:
        """Enforce timeout obligation: an enabled tool must declare timeout_seconds."""
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
    """Configuration for the testssl.sh connector (TLS analysis)."""

    enabled: bool = Field(
        default=False,
        description=(
            "Enable the testssl.sh connector.  When True, timeout_seconds is mandatory."
        ),
    )
    timeout_seconds: int | None = Field(
        default=None,
        ge=30,
        le=600,
        description=(
            "Wall-clock timeout for a single testssl.sh execution in seconds. "
            "Mandatory when enabled=True.  Recommended: 120."
        ),
    )
    extra_flags: str = Field(
        default="--quiet --color 0",
        description=(
            "Additional CLI flags appended to the testssl.sh invocation, verbatim. "
            "Default disables interactive output for machine parsing."
        ),
    )


class NucleiConfig(BaseExternalToolConfig):
    """Configuration for the nuclei connector (template-based vulnerability scanning)."""

    enabled: bool = Field(
        default=False,
        description=(
            "Enable the nuclei connector.  When True, timeout_seconds is mandatory."
        ),
    )
    timeout_seconds: int | None = Field(
        default=None,
        ge=60,
        le=600,
        description=(
            "Wall-clock timeout for a single nuclei execution in seconds. "
            "Mandatory when enabled=True.  Recommended: 240."
        ),
    )
    extra_flags: str = Field(
        default="",
        description=(
            "Additional CLI flags appended verbatim to the nuclei invocation. "
            "Must not contain credentials or secrets."
        ),
    )
    template_dir: str = Field(
        default="./tools/nuclei-templates",
        description=(
            "Path to the pinned nuclei-templates directory, relative to CWD. "
            "Must match the directory populated by install_tools.sh."
        ),
    )
    tags: list[str] = Field(
        default_factory=lambda: ["api", "exposure", "misconfig", "panel"],
        description=(
            "nuclei template tags to include in the scan (-tags flag). "
            "Default covers shadow API discovery."
        ),
    )
    per_request_timeout: int = Field(
        default=10,
        ge=5,
        le=60,
        description=(
            "Per-request timeout in seconds passed to nuclei via -timeout. "
            "Default 10s is appropriate for local targets."
        ),
    )
    rate_limit_rps: int = Field(
        default=30,
        ge=1,
        le=150,
        description=(
            "Maximum HTTP requests per second passed to nuclei via -rl. "
            "Default 30 rps avoids triggering the target's own rate limiter."
        ),
    )


class SslyzeConfig(BaseExternalToolConfig):
    """
    Configuration for the sslyze connector (Python TLS scanner library).

    sslyze is a BaseLibraryConnector: it is imported as a Python module, not
    invoked as a subprocess.  Install via: pip install "apiguard-assurance[sslyze]"
    or pip install sslyze>=6.0.

    Reference: NIST SP 800-52 Rev.2, OWASP ASVS v5.0.0 V14.2.1.
    """

    enabled: bool = Field(
        default=False,
        description=(
            "Enable the sslyze connector.  When True, timeout_seconds is mandatory.  "
            "Requires sslyze>=6.0 to be installed "
            "('pip install apiguard-assurance[sslyze]')."
        ),
    )
    timeout_seconds: int | None = Field(
        default=None,
        ge=30,
        le=300,
        description=(
            "Per-connection network timeout for each sslyze TLS check in seconds. "
            "Mandatory when enabled=True.  Recommended: 60.  "
            "sslyze runs multiple checks in parallel; this timeout applies to each "
            "individual TCP connection attempt, not to the total scan duration."
        ),
    )


# ---------------------------------------------------------------------------
# Root external tools config
# ---------------------------------------------------------------------------


class ExternalToolsConfig(BaseModel):
    """
    Root configuration block for all external tool connectors.

    Mapped from the optional ``external_tools`` section of config.yaml.
    If the section is absent, all fields use their defaults (all disabled).

    Master switch semantics:
        enabled=False  -> ALL external tests return SKIP immediately.
        enabled=True   -> per-tool ``enabled`` fields are evaluated individually.
    """

    model_config = {"frozen": True}

    enabled: bool = Field(
        default=True,
        description=(
            "Master switch for all external tool tests.  "
            "False disables every ExternalToolTest regardless of per-tool settings."
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
    sslyze: SslyzeConfig = Field(
        default_factory=SslyzeConfig,
        description="Configuration for the sslyze connector (Python TLS library).",
    )

    def is_tool_enabled(self, tool_name: str) -> bool:
        """
        Return True if the given tool is active (master switch AND per-tool switch).

        Args:
            tool_name: Currently "testssl", "nuclei", or "sslyze".

        Returns:
            bool: True only if both ExternalToolsConfig.enabled and the
                  per-tool enabled flag are True.
        """
        if not self.enabled:
            return False

        tool_cfg = getattr(self, tool_name, None)

        if tool_cfg is None:
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

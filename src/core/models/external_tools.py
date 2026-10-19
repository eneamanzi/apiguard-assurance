"""
src/core/models/external_tools.py

Pydantic v2 schema for external tool connector configuration.

Lives in core/models/ so that TargetContext (also in core/) can hold an
ExternalToolsConfig field without violating the unidirectional dependency
rule (core/ must not import from config/).

Design rules:
    1. Master switch: ExternalToolsConfig.enabled = false disables ALL external
       tests, overriding per-tool settings.
    2. Timeout obligation: an enabled tool MUST declare timeout_seconds.
    3. Per-tool on/off: each tool can be independently disabled.
    4. extra_flags: additional CLI flags, must not contain secrets. Declared only
       by command-line tools (testssl, nuclei); a library (sslyze) has none.

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

    The model_validator ``_timeout_required_when_enabled`` centralises the
    timeout obligation check (ADR-001 §3.2) so that subclasses do not need
    to replicate it.

    Subclass protocol:
        1. Inherit from BaseExternalToolConfig.
        2. Override ``enabled`` and ``timeout_seconds`` with tool-specific
           Field() declarations (ge/le constraints, descriptions). Command-line
           tools also declare ``extra_flags`` (additional CLI flags, no secrets).
        3. Add tool-specific fields after the shared fields.
        4. Do NOT redeclare ``_timeout_required_when_enabled``.
    """

    model_config = {"frozen": True, "extra": "forbid"}

    enabled: bool = Field(
        default=False,
        description=(
            "Enable this tool connector.  When True, timeout_seconds is "
            "mandatory.  When False, the tests for this tool are not scheduled "
            "(no binary discovery); the report lists them in not_run (tool_disabled)."
        ),
    )
    timeout_seconds: int | None = Field(
        default=None,
        description=(
            "Wall-clock timeout for a single tool execution in seconds. "
            "Mandatory when enabled=True."
        ),
    )
    expected_version: str | None = Field(
        default=None,
        description=("Expected tool version; a mismatch logs a WARNING and the test still runs."),
    )
    dev_mode: bool = Field(
        default=False,
        description=(
            "Development only: reuse the output a previous run saved "
            "(`<output.directory>/tools/<label>_output.json`) instead of running the tool; "
            "without that file the tool runs and saves it. Never enable in a real "
            "assessment."
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
        description=("Enable testssl.sh; `timeout_seconds` is then required."),
    )
    timeout_seconds: int | None = Field(
        default=None,
        ge=30,
        description=(
            "**Required with `enabled: true`.** Wall-clock limit (s) of one execution, "
            "which only stops a tool that hangs: set it to 2-3 times the duration seen on "
            "your target; a run that ends after more than 70% of it logs the warning "
            "`external_tool_near_time_limit` with the value to raise."
        ),
    )
    extra_flags: str = Field(
        default="--quiet --color 0",
        description=(
            "Flags appended verbatim to the testssl.sh command line. Must not contain secrets."
        ),
    )


class NucleiConfig(BaseExternalToolConfig):
    """Configuration for the nuclei connector (template-based vulnerability scanning)."""

    enabled: bool = Field(
        default=False,
        description=("Enable nuclei; `timeout_seconds` is then required."),
    )
    timeout_seconds: int | None = Field(
        default=None,
        ge=60,
        description=(
            "**Required with `enabled: true`.** Wall-clock limit (s) of one execution, "
            "which only stops a tool that hangs: set it to 2-3 times the duration seen on "
            "your target (it grows with the templates, the endpoints and the request rate); "
            "a run that ends after more than 70% of it logs the warning "
            "`external_tool_near_time_limit` with the value to raise."
        ),
    )
    extra_flags: str = Field(
        default="",
        description=(
            "Flags appended verbatim to the nuclei command line. Must not contain secrets."
        ),
    )
    template_dir: str = Field(
        default="./tools/nuclei-templates",
        description=(
            "Template directory, relative to the working directory (`install_tools.sh` "
            "fills the default one)."
        ),
    )
    tags: list[str] = Field(
        default_factory=lambda: ["api", "exposure", "misconfig", "panel"],
        description=("Template tags selected (`-tags`)."),
    )
    per_request_timeout: int = Field(
        default=10,
        ge=5,
        le=60,
        description=("Timeout (s) of each request, passed as `-timeout`."),
    )
    rate_limit_rps: int = Field(
        default=30,
        ge=1,
        le=150,
        description=("Requests per second, passed as `-rl`."),
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
            "Enable sslyze; `timeout_seconds` is then required. Needs the `sslyze` extra "
            '(`pip install "apiguard-assurance[sslyze]"`).'
        ),
    )
    timeout_seconds: int | None = Field(
        default=None,
        ge=30,
        le=300,
        description=(
            "**Required with `enabled: true`.** Today it has no effect: each TLS connection "
            "sslyze opens times out after 20 s whatever the value "
            "(`src/connectors/sslyze.py`; Q-24)."
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
        enabled=False  -> no external test is scheduled (listed in the report's
                          not_run as tool_disabled).
        enabled=True   -> per-tool ``enabled`` fields are evaluated individually.
    """

    model_config = {"frozen": True, "extra": "forbid"}

    enabled: bool = Field(
        default=True,
        description=(
            "Master switch: `false` removes all external tests from the run, whatever the "
            "settings of each tool."
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

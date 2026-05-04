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

Dependency rule: imports from pydantic and stdlib only.  Must never import from
engine.py, tests/, connectors/, external_tests/, or report/.
"""

from __future__ import annotations

from pydantic import BaseModel, Field, model_validator

# ---------------------------------------------------------------------------
# Per-tool configuration models
# ---------------------------------------------------------------------------


class TestsslConfig(BaseModel):
    """
    Configuration for the testssl.sh connector (TLS analysis).

    testssl.sh performs deep TLS stack inspection: protocol versions,
    cipher suites, certificate chain, forward secrecy, HSTS, HPKP,
    Certificate Transparency SCTs.  It is the tool of choice for
    Garanzia 1.5 (TLS enforcement) in the methodology.

    The binary is discovered via:
        1. shutil.which("testssl.sh")   -- local install in PATH
        2. os.getenv("TESTSSL_SERVICE_URL") -- HTTP service in Docker Compose

    Binary-level JSON output is requested via --jsonfile /dev/stdout so that
    the connector can parse structured results without writing temp files.
    """

    model_config = {"frozen": True}

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
            "testssl.sh can take 90–180 s on a full TLS scan of a live host. "
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

    @model_validator(mode="after")
    def timeout_required_when_enabled(self) -> TestsslConfig:
        """Enforce timeout obligation: enabled tool must declare timeout_seconds."""
        if self.enabled and self.timeout_seconds is None:
            raise ValueError(
                "testssl configuration error: 'timeout_seconds' is mandatory when "
                "'enabled: true'.  Set 'external_tools.testssl.timeout_seconds' in "
                "config.yaml.  Recommended value: 120."
            )
        return self


class NucleiConfig(BaseModel):
    """
    Configuration for the nuclei connector (CVE / template-based scanning).

    nuclei applies community-maintained YAML templates against API endpoints
    to detect known vulnerabilities, misconfigurations, and exposed panels.
    Used primarily for Garanzia 0.1 supplement and 6.x audit in the methodology.

    The binary is discovered via:
        1. shutil.which("nuclei")            -- local install in PATH
        2. os.getenv("NUCLEI_SERVICE_URL")   -- HTTP service in Docker Compose
    """

    model_config = {"frozen": True}

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

    @model_validator(mode="after")
    def timeout_required_when_enabled(self) -> NucleiConfig:
        """Enforce timeout obligation."""
        if self.enabled and self.timeout_seconds is None:
            raise ValueError(
                "nuclei configuration error: 'timeout_seconds' is mandatory when "
                "'enabled: true'.  Set 'external_tools.nuclei.timeout_seconds' in "
                "config.yaml.  Recommended value: 300."
            )
        return self


class FfufConfig(BaseModel):
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

    model_config = {"frozen": True}

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
            "The recommended file is SecLists API-endpoints.txt (≈5,000 entries). "
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

    @model_validator(mode="after")
    def timeout_required_when_enabled(self) -> FfufConfig:
        """Enforce timeout obligation."""
        if self.enabled and self.timeout_seconds is None:
            raise ValueError(
                "ffuf configuration error: 'timeout_seconds' is mandatory when "
                "'enabled: true'.  Set 'external_tools.ffuf.timeout_seconds' in "
                "config.yaml.  Recommended value: 180."
            )
        return self


# ---------------------------------------------------------------------------
# Root external tools config
# ---------------------------------------------------------------------------


class ExternalToolsConfig(BaseModel):
    """
    Root configuration block for all external tool connectors.

    Mapped from the optional `external_tools` section of config.yaml.
    If the section is absent, all fields use their defaults (all disabled).

    Master switch semantics:
        enabled=False  → ALL external tests return SKIP immediately, without
                         attempting binary discovery or reading per-tool config.
                         Use this in CI environments without external binaries.
        enabled=True   → per-tool `enabled` fields are evaluated individually.
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

        Args:
            tool_name: One of "testssl", "nuclei", "ffuf".

        Returns:
            bool: True only if both ExternalToolsConfig.enabled and the
                  per-tool enabled flag are True.
        """
        if not self.enabled:
            return False
        tool_cfg = getattr(self, tool_name, None)
        if tool_cfg is None:
            return False
        return bool(getattr(tool_cfg, "enabled", False))

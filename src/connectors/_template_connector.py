"""
src/connectors/_template_connector.py

TEMPLATE -- Copy this file and rename it to implement a new connector.

Steps to add a new subprocess-based connector:
    1. Copy this file to src/connectors/<toolname>.py.
    2. Replace all occurrences of TEMPLATE / TemplateTool with your tool name.
    3. Fill in the ClassVar declarations (TOOL_NAME, BINARY_NAME, etc.).
    4. Implement run() following the ConnectorRawOutput contract.
    5. Add a corresponding per-tool config class to
       src/config/schema/external_tools.py (inherit BaseExternalToolConfig).
    6. Register the new config class as a field in ExternalToolsConfig.
    7. Write one or more ExternalToolTest subclasses in
       src/external_tests/ext_test_<toolname>_<description>.py.

ConnectorRawOutput contract (REQUIRED keys in raw_output):
    "command"      -- human-readable plain-text command for reproduction.
    "command_json" -- command with JSON output flag appended.
    "results"      -- complete unfiltered list of finding dicts from the tool.
    "all_count"    -- total findings; equals len(results).

    Design principle: connectors are "dumb pipes" -- pass ALL findings in results.
    Severity-based partitioning (FAIL / note / ignore) is the oracle responsibility
    of the calling ExternalToolTest._evaluate(), not the connector.

    Use self._build_reproducible_commands() to produce "command" and
    "command_json" without reimplementing path-normalisation logic.

Dependency rule:
    This module imports from stdlib, pydantic, structlog, src.connectors.base,
    and src.core.exceptions only.  Must never import from tests/,
    external_tests/, config/, discovery/, or report/.
"""

from __future__ import annotations

import time
from typing import Any, ClassVar

import structlog

from src.connectors.base import BaseSubprocessConnector, ConnectorResult
from src.core.exceptions import ExternalToolError

log: structlog.BoundLogger = structlog.get_logger(__name__)

# ---------------------------------------------------------------------------
# Module-level constants
# ---------------------------------------------------------------------------

# Default CLI flags.  Must match ExternalToolsConfig.<tool>.extra_flags default.
_DEFAULT_EXTRA_FLAGS: str = ""

# Exit codes that indicate a completed scan (not an execution error).
_SUCCESS_EXIT_CODES: frozenset[int] = frozenset({0})


# ---------------------------------------------------------------------------
# TemplateConnector -- rename this class
# ---------------------------------------------------------------------------


class TemplateConnector(BaseSubprocessConnector):
    """
    Subprocess connector for <toolname>.

    <One-paragraph description of what the tool does and why it is used in
    the methodology.>

    ConnectorResult.raw_output structure (follows ConnectorRawOutput contract)::

        {
          "command":        "<tool> [flags] <target>",
          "command_json":   "<tool> [flags] -json <target>",
          "results":   [...],   # complete unfiltered findings (no connector-side filter)
          "all_count": N           # total findings; equals len(results)
        }
    """

    TOOL_NAME: ClassVar[str] = "template-tool"  # human-readable; used in logs and report
    BINARY_NAME: ClassVar[str] = "template-tool"  # name of the binary in PATH
    SERVICE_ENV_VAR: ClassVar[str] = "TEMPLATE_TOOL_SERVICE_URL"
    DEFAULT_TIMEOUT_SECONDS: ClassVar[int] = 60

    # Set this to the subdirectory name inside ./tools/ if install_tools.sh
    # places the binary there.  Leave as "" to skip local-tools discovery.
    LOCAL_TOOLS_SUBDIR: ClassVar[str] = ""

    def run(
        self,
        target_url: str,
        timeout_seconds: int,
        *,
        extra_flags: str = _DEFAULT_EXTRA_FLAGS,
    ) -> ConnectorResult:
        """
        Invoke <toolname> against the target and return structured output.

        Args:
            target_url:      Base URL of the target API.
            timeout_seconds: Wall-clock limit.  Sourced from config.yaml.
            extra_flags:     Additional CLI flags, verbatim.

        Returns:
            ConnectorResult: Parsed tool output.

        Raises:
            ExternalToolError: On timeout, OS error, or unparsable output.
        """
        scan_target: str = target_url  # adjust if the tool uses host:port format

        # Build the command prefix (without JSON flag and without scan target).
        binary_cmd: str = self._resolve_binary_path() or self.BINARY_NAME
        cmd: list[str] = [binary_cmd]
        flag_tokens = [t for t in extra_flags.split() if t]
        cmd.extend(flag_tokens)

        # Build human-readable commands using the base class helper.
        # Replace ["-json"] with whatever flag your tool uses to produce JSON output.
        reproducible_command, reproducible_command_json = self._build_reproducible_commands(
            cmd_prefix=cmd,
            scan_target=scan_target,
            json_output_args=["-json"],
        )

        log.info(
            "template_connector_run_starting",
            scan_target=scan_target,
            timeout_seconds=timeout_seconds,
            reproducible_command=reproducible_command,
        )

        start_time_ms = int(time.monotonic() * 1000)

        # Execute the tool with JSON output flag and parse JSONL output.
        stdout, exit_code = self._run_subprocess(
            cmd=cmd + ["-json", scan_target],
            timeout_seconds=timeout_seconds,
            tool_name=self.TOOL_NAME,
        )

        execution_time_ms = int(time.monotonic() * 1000) - start_time_ms

        if exit_code not in _SUCCESS_EXIT_CODES:
            preview = (stdout or "")[:300].replace("\n", " ")
            raise ExternalToolError(
                message=(
                    f"{self.TOOL_NAME} exited with code {exit_code}. Output preview: {preview!r}"
                ),
                tool_name=self.TOOL_NAME,
                exit_code=exit_code,
            )

        # Parse JSONL output (one JSON object per line).
        all_findings: list[dict[str, Any]] = self._parse_jsonl_output(
            raw_stdout=stdout,
            tool_name=self.TOOL_NAME,
        )

        log.info(
            "template_connector_run_complete",
            scan_target=scan_target,
            all_count=len(all_findings),
            exit_code=exit_code,
            execution_time_ms=execution_time_ms,
        )

        # Build raw_output following the ConnectorRawOutput contract.
        # All four REQUIRED keys must be present or the HTML report will display
        # dashes silently (the Jinja2 template uses the default_dash filter).
        # No connector-side filtering: pass all findings in results.
        # Severity-based partitioning (FAIL / note / ignore) is the oracle
        # responsibility of the calling ExternalToolTest._evaluate().
        raw_output: dict[str, Any] = {
            "command": reproducible_command,
            "command_json": reproducible_command_json,
            "results": all_findings,
            "all_count": len(all_findings),
        }

        return ConnectorResult(
            tool_name=self.TOOL_NAME,
            tool_version=self.get_version(),
            raw_output=raw_output,
            exit_code=exit_code,
            execution_time_ms=execution_time_ms,
            timed_out=False,
        )

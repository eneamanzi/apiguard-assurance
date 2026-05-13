"""
src/connectors/nuclei.py

NucleiConnector: subprocess-based connector for nuclei template-based scanning.

Responsibility (connector layer):
    This module is responsible exclusively for invoking the nuclei binary as a
    subprocess, parsing its JSON export file, and returning a structured
    ConnectorResult.  It does NOT decide what constitutes a FAIL, a note, or
    noise: all severity-based policy decisions are the exclusive responsibility
    of ExtTest01ShadowApiNuclei._evaluate() in
    ext_test_0_1_shadow_api_nuclei.py.

    The connector passes every finding from nuclei verbatim in ``results``,
    regardless of severity.  This upholds the "dumb pipe" contract.

nuclei JSON export format:
    nuclei with ``-je <path>`` writes a JSON array to the specified file.
    Each array element is a finding object.  The relevant fields, confirmed
    against nuclei v3.8.0 / templates v10.4.3 (Step B.0 reconnaissance), are::

        {
          "template-id":   "swagger-api",
          "template":      "http/exposures/apis/swagger-api.yaml",
          "info": {
            "name":        "Public Swagger API - Detect",
            "severity":    "info",           # info | low | medium | high | critical
            "tags":        ["exposure", "api", "swagger", "discovery"],
            "classification": {
              "cwe-id":    ["cwe-200"]       # list[str] or null
            }
          },
          "type":          "http",
          "host":          "localhost",
          "port":          "8000",
          "matched-at":    "http://localhost:8000/api/swagger",
          "timestamp":     "2026-05-11T01:56:34.822795126Z",
          "matcher-status": true
        }

    ZERO FINDINGS CASE: nuclei does NOT create the -je file when no templates
    match.  NucleiConnector handles this by returning results=[] without error.

raw_output contract (ConnectorRawOutput keys — mandatory):
    command      str        Full CLI command as a single string (for reports).
    command_json str        JSON-serialised command list (for evidence.json).
    results      list[dict] Complete unfiltered list of nuclei finding dicts.
    all_count    int        len(results).

Hardcoded flags (not configurable, architectural invariants):
    -duc          Disable update check.  Enforces the version pinning contract:
                  the binary must never self-update during an assessment run.
    -ni           Disable interactsh OAST.  nuclei would otherwise send
                  out-of-band probes to projectdiscovery.io servers, which
                  (a) requires internet access, (b) leaks target information
                  to a third party, and (c) makes results non-reproducible.
    -no-color     Machine-readable output.  ANSI escape codes corrupt JSON
                  parsing in non-TTY environments.
    -je <tmpfile> JSON export.  Preferred over -j (JSONL to stdout) because
                  stdout may contain [INF]/[WRN] log lines that corrupt JSONL
                  parsing.  A dedicated temp file produces clean JSON.

Discovery channels (inherited from BaseSubprocessConnector):
    Channel 1 -- Path.cwd() / "tools" / "nuclei" / "nuclei"  (local install)
    Channel 2 -- shutil.which("nuclei")                        (system PATH)

Dependency rule:
    Imports from stdlib, structlog, src.connectors.base, src.core.exceptions
    only.  Must never import from tests/, external_tests/, config/, or report/.
"""

from __future__ import annotations

import json
import tempfile
import time
from pathlib import Path
from typing import Any, ClassVar

import structlog

from src.connectors.base import BaseSubprocessConnector, ConnectorResult
from src.core.exceptions import ExternalToolError

log: structlog.BoundLogger = structlog.get_logger(__name__)

# ---------------------------------------------------------------------------
# Module-level constants
# ---------------------------------------------------------------------------

# Flags hardcoded as architectural invariants (see module docstring).
# Represented as a list so they can be extended directly into the cmd list
# without string splitting.
_HARDCODED_FLAGS: list[str] = [
    "-duc",  # disable update check (version pinning)
    "-ni",  # disable interactsh OAST (no external callbacks)
    "-no-color",  # machine-readable output (no ANSI codes)
]

# nuclei exits 0 on both "scan completed with findings" and
# "scan completed with no findings".  Exit code 1 signals a fatal error
# (e.g. binary not found, config parse failure).
_NUCLEI_SUCCESS_EXIT_CODE: int = 0


# ---------------------------------------------------------------------------
# NucleiConnector
# ---------------------------------------------------------------------------


class NucleiConnector(BaseSubprocessConnector):
    """
    Subprocess connector for the nuclei template-based vulnerability scanner.

    Invokes ``./tools/nuclei/nuclei`` (or ``nuclei`` from PATH) with a
    pinned template directory and a tag filter.  Returns a ConnectorResult
    whose ``raw_output["results"]`` is a list of nuclei finding dicts,
    parsed from the JSON export file produced by the ``-je`` flag.

    Version coupling:
        This connector's JSON field access is validated against
        nuclei v3.8.0 and nuclei-templates v10.4.3 (Step B.0 reconnaissance,
        2026-05-11).  If the installed binary or templates differ from
        NucleiConfig.expected_version, ExternalToolTest._warn_if_version_mismatch()
        emits a WARNING before run() is called.

    Usage (called by ExtTest01ShadowApiNuclei._invoke_connector()):
        result = connector.run(
            target_url="http://localhost:8000",
            timeout_seconds=240,
            template_dir="./tools/nuclei-templates",
            tags=["api", "exposure", "misconfig", "panel"],
            per_request_timeout=10,
            rate_limit_rps=30,
            extra_flags="",
        )
    """

    TOOL_NAME: ClassVar[str] = "nuclei"
    BINARY_NAME: ClassVar[str] = "nuclei"
    LOCAL_TOOLS_SUBDIR: ClassVar[str] = "nuclei"
    SERVICE_ENV_VAR: ClassVar[str] = "NUCLEI_SERVICE_URL"

    def run(  # noqa: PLR0913 -- connector requires all parameters explicitly
        self,
        target_url: str,
        timeout_seconds: int,
        template_dir: str,
        tags: list[str],
        per_request_timeout: int,
        rate_limit_rps: int,
        extra_flags: str,
    ) -> ConnectorResult:
        """
        Execute nuclei against target_url and return parsed ConnectorResult.

        Builds the CLI command, runs it via _run_subprocess(), reads the
        JSON export file, and returns a ConnectorResult.  The "dumb pipe"
        contract is strictly maintained: no finding is filtered or classified
        here.

        Zero-findings handling:
            nuclei does NOT create the -je output file when no templates match.
            This is not an error -- the connector returns results=[] and
            exit_code=0.  The calling _evaluate() interprets an empty list as
            PASS ("no shadow API exposures detected").

        Template directory validation:
            If template_dir does not exist at the resolved path, the connector
            raises ExternalToolError before invoking the subprocess.  This
            converts a configuration error (wrong path in config.yaml) into an
            explicit ERROR TestResult rather than a nuclei subprocess failure
            with a cryptic error message.

        Args:
            target_url:           Full URL of the target (e.g. "http://localhost:8000").
            timeout_seconds:      Total wall-clock scan timeout in seconds.
            template_dir:         Path to the pinned nuclei-templates directory.
            tags:                 Template tag filter list (passed via -tags).
            per_request_timeout:  Per-HTTP-request timeout in seconds (-timeout).
            rate_limit_rps:       Max requests per second (-rl).
            extra_flags:          Additional CLI flags (operator-configurable).

        Returns:
            ConnectorResult: Parsed scan output.  raw_output["results"] is a
                             list of finding dicts (empty list if no findings).

        Raises:
            ExternalToolError: If the template directory is missing, the
                               subprocess times out, or a fatal error occurs.
        """
        binary_cmd = self._resolve_binary_path()
        if binary_cmd is None:
            raise ExternalToolError(
                message=(
                    "nuclei binary not found via any discovery channel. "
                    "Run install_tools.sh or add nuclei to PATH."
                ),
                tool_name=self.TOOL_NAME,
                exit_code=-1,
            )

        # Validate template directory before invoking subprocess.
        resolved_template_dir = Path(template_dir).resolve()
        if not resolved_template_dir.is_dir():
            raise ExternalToolError(
                message=(
                    f"nuclei template directory not found: '{template_dir}' "
                    f"(resolved: '{resolved_template_dir}'). "
                    "Run install_tools.sh to download pinned templates, or "
                    "update external_tools.nuclei.template_dir in config.yaml."
                ),
                tool_name=self.TOOL_NAME,
                exit_code=-1,
            )

        # Build command.  The JSON export file path is a temp file created
        # below; nuclei writes findings to it (or skips creation if empty).
        json_export_path = Path(tempfile.mktemp(suffix="_nuclei.json"))  # noqa: S306
        # mktemp is used intentionally: we need the path before nuclei runs
        # (to pass it as a CLI argument), and the file must NOT exist yet so
        # we can detect the zero-findings case (nuclei does not create the
        # file when there are no matches).  The risk of a race condition is
        # negligible in this single-user security tool context.

        cmd: list[str] = [
            binary_cmd,
            "-u",
            target_url,
            "-t",
            str(resolved_template_dir),
            "-tags",
            ",".join(tags),
            "-timeout",
            str(per_request_timeout),
            "-rl",
            str(rate_limit_rps),
            "-je",
            str(json_export_path),
            *_HARDCODED_FLAGS,
        ]

        # Append operator-supplied extra flags if non-empty.
        if extra_flags.strip():
            cmd.extend(extra_flags.split())

        log.info(
            "nuclei_connector_start",
            target_url=target_url,
            template_dir=str(resolved_template_dir),
            tags=tags,
            per_request_timeout=per_request_timeout,
            rate_limit_rps=rate_limit_rps,
            timeout_seconds=timeout_seconds,
        )

        start_ms = int(time.monotonic() * 1000)

        # _run_subprocess raises ExternalToolError on timeout or fatal failure.
        # stdout is discarded: nuclei emits only [INF]/[WRN] log lines to
        # stdout when -je is used; all structured output is in the JSON file.
        _stdout, exit_code = self._run_subprocess(
            cmd=cmd,
            timeout_seconds=timeout_seconds,
            tool_name=self.TOOL_NAME,
        )

        execution_time_ms = int(time.monotonic() * 1000) - start_ms

        # Parse results from the JSON export file.
        results: list[dict[str, Any]] = self._read_json_export(json_export_path)

        # Relativize template-path: nuclei writes the absolute filesystem path
        # of the matched template file because it receives an absolute -t argument.
        # This is local infrastructure data (which template on OUR machine matched),
        # not target finding data -- safe to relativize without altering evidence.
        # All other fields (matched-at, request, response, ...) are untouched.
        results = self._sanitize_paths_in_findings(results, path_keys=("template-path",))

        log.info(
            "nuclei_connector_complete",
            exit_code=exit_code,
            findings_count=len(results),
            execution_time_ms=execution_time_ms,
        )

        # Build human-readable display commands for the report.
        #
        # Three categories of tokens in `cmd` need sanitisation:
        #   1. binary_cmd       -- may be an absolute project-local path;
        #                         relativized via _relativize_display_path().
        #   2. resolved_template_dir -- absolute path to the templates dir;
        #                         relativized via _relativize_display_path().
        #   3. json_export_path -- /tmp/tmpXXX_nuclei.json temp file;
        #                         NOT shown in display strings (implementation
        #                         detail); replaced with "nuclei_result.json"
        #                         in command_json for analyst clarity.
        #
        # The display command is built from scratch (not from `cmd`) so that
        # the -je temp-file token is omitted from `command` and shown as a
        # clean placeholder in `command_json`.
        _display_binary: str = self._relativize_display_path(binary_cmd)
        _display_templates: str = self._relativize_display_path(str(resolved_template_dir))
        _display_tokens: list[str] = [
            _display_binary,
            "-u",
            target_url,
            "-t",
            _display_templates,
            "-tags",
            ",".join(tags),
            "-timeout",
            str(per_request_timeout),
            "-rl",
            str(rate_limit_rps),
            *_HARDCODED_FLAGS,
        ]
        if extra_flags.strip():
            _display_tokens.extend(extra_flags.split())

        # command: no -je flag -- mirrors what a human runs for text output.
        # command_json: includes -je placeholder (clean filename, not tmp path).
        _display_command: str = " ".join(_display_tokens)
        _display_command_json: str = " ".join(_display_tokens + ["-je", "nuclei_result.json"])

        raw_output: dict[str, Any] = {
            "command": _display_command,
            "command_json": _display_command_json,
            "results": results,
            "all_count": len(results),
        }

        return ConnectorResult(
            tool_name=self.TOOL_NAME,
            tool_version=self.get_version(),
            raw_output=raw_output,
            exit_code=exit_code,
            execution_time_ms=execution_time_ms,
            timed_out=False,
        )

    # ------------------------------------------------------------------
    # Private helpers
    # ------------------------------------------------------------------

    def _read_json_export(self, json_export_path: Path) -> list[dict[str, Any]]:
        """
        Read and parse the nuclei JSON export file.

        nuclei does NOT create the -je file when no templates match.
        This is the normal zero-findings case (not an error).  The method
        returns an empty list in that case.

        If the file exists but is not valid JSON, ExternalToolError is raised.
        This converts a nuclei internal error (e.g. partial write due to OOM)
        into an explicit ERROR TestResult rather than a silent empty result.

        Args:
            json_export_path: Path where nuclei was instructed to write findings.

        Returns:
            list[dict[str, Any]]: Parsed findings list.  Empty list if no findings.

        Raises:
            ExternalToolError: If the file exists but cannot be parsed as JSON.
        """
        try:
            if not json_export_path.exists():
                # Normal zero-findings case: nuclei did not create the file.
                log.debug(
                    "nuclei_json_export_not_created",
                    path=str(json_export_path),
                    detail="No templates matched -- zero findings (normal).",
                )
                return []

            if json_export_path.stat().st_size == 0:
                # Edge case: file created but empty (can occur on some nuclei
                # versions when findings are filtered post-match).
                log.debug(
                    "nuclei_json_export_empty",
                    path=str(json_export_path),
                )
                json_export_path.unlink(missing_ok=True)
                return []

            with json_export_path.open(encoding="utf-8") as fh:
                data = json.load(fh)

            # nuclei -je always writes a JSON array.  Guard against unexpected
            # output format changes between versions.
            if not isinstance(data, list):
                raise ExternalToolError(
                    message=(
                        f"nuclei JSON export is not a list (got {type(data).__name__}). "
                        "The nuclei version may differ from expected_version; "
                        "check NucleiConfig.expected_version in config.yaml."
                    ),
                    tool_name=self.TOOL_NAME,
                    exit_code=0,
                )

            return data  # type: ignore[return-value]

        except json.JSONDecodeError as exc:
            raise ExternalToolError(
                message=(
                    f"nuclei JSON export at '{json_export_path}' is not valid JSON: "
                    f"{exc}.  The scan may have been interrupted or the output "
                    "file may be corrupted."
                ),
                tool_name=self.TOOL_NAME,
                exit_code=0,
            ) from exc
        finally:
            # Always clean up the temp file, even on error.
            json_export_path.unlink(missing_ok=True)

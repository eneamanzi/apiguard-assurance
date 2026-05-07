"""
src/connectors/testssl.py

TestsslConnector: subprocess-based connector for testssl.sh TLS stack analysis.

Responsibility (connector layer):
    This module is responsible exclusively for invoking testssl.sh as a subprocess,
    parsing its JSON output, and returning a structured ConnectorResult.  It does
    NOT decide what constitutes a FAIL: severity filtering here removes noise
    (OK / INFO / LOW), but the oracle logic (HIGH/CRITICAL -> FAIL vs WARN/MEDIUM
    -> PASS-with-note) is the exclusive responsibility of ExtTest15TlsAnalysis
    in ext_test_1_5_tls_analysis.py.

testssl.sh JSON output format:
    testssl.sh v3.x with ``--jsonfile <path>`` writes a JSON array to the given
    path.  Each array element is a finding object with the following relevant
    fields::

        {
          "id":       "ssl3",              # protocol/cipher/cert identifier
          "severity": "CRITICAL",          # OK | INFO | WARN | LOW | MEDIUM | HIGH | CRITICAL
          "finding":  "offered (deprecated)",
          "cve":      "",                  # space-separated CVE IDs or empty
          "cwe":      "CWE-326"            # CWE reference or empty
        }

    This module writes to a temporary file (not /dev/stdout) to maximise
    portability across OS configurations where /dev/stdout may not be available
    or may behave unexpectedly inside container environments.

Severity filtering contract:
    The connector retains ONLY findings with severity in RETAINED_SEVERITIES
    (WARN, MEDIUM, HIGH, CRITICAL).  It discards OK, INFO, and LOW.

    Rationale:
        OK / INFO  — positive results or purely informational messages with
                     no security relevance.  Including them would flood the
                     evidence.json and the report with hundreds of lines of
                     noise, making real issues harder to identify.
        LOW        — the methodology (Section 1.5) focuses on protocol versions
                     (deprecated TLS) and weak ciphers; LOW findings typically
                     represent informational certificates or minor
                     configuration observations outside the test scope.
        WARN       — borderline items worth surfacing to the analyst even though
                     they do not automatically trigger FAIL (the oracle in
                     _evaluate() treats them as PASS-with-note).

Extra flags:
    The run() method accepts an ``extra_flags`` keyword argument so the calling
    test can customise the invocation.  The default value mirrors the
    ExternalToolsConfig.testssl.extra_flags default (``--quiet --color 0``),
    which is the correct combination for silent, colour-free machine parsing.

Discovery channels (inherited from BaseSubprocessConnector):
    Channel 1 -- shutil.which("testssl.sh")   : binary installed locally in PATH.
    Channel 2 -- os.getenv("TESTSSL_SERVICE_URL") : binary exposed as HTTP service.

Dependency rule:
    This module imports from stdlib, pydantic, structlog, src.connectors.base,
    and src.core.exceptions only.  Must never import from tests/, external_tests/,
    config/, discovery/, or report/.
"""

from __future__ import annotations

import json
import os
import tempfile
import time
from typing import Any, ClassVar
from urllib.parse import urlparse

import structlog

from src.connectors.base import BaseSubprocessConnector, ConnectorResult
from src.core.exceptions import ExternalToolError

log: structlog.BoundLogger = structlog.get_logger(__name__)

# ---------------------------------------------------------------------------
# Module-level constants
# ---------------------------------------------------------------------------

# Severity levels retained after filtering.
# OK and INFO are discarded as noise; LOW is discarded as out-of-scope for
# the TLS enforcement guarantee (Section 1.5 of the methodology).
# The ExternalToolTest oracle treats WARN and MEDIUM as PASS-with-note,
# and HIGH and CRITICAL as FAIL.
RETAINED_SEVERITIES: frozenset[str] = frozenset({"WARN", "MEDIUM", "HIGH", "CRITICAL"})

# Severities that map to FAIL in the oracle (defined here as documentation only;
# the oracle decision is made in _evaluate() of the ExternalToolTest, not here).
FAIL_SEVERITIES: frozenset[str] = frozenset({"HIGH", "CRITICAL"})

# Default CLI flags for machine-readable, colour-free output.
# Mirrors ExternalToolsConfig.testssl.extra_flags default.
_DEFAULT_EXTRA_FLAGS: str = "--quiet --color 0"

# The testssl.sh exit code indicating a successful scan regardless of findings.
# testssl.sh returns 0 for a completed scan, non-zero for execution errors.
_TESTSSL_SUCCESS_EXIT_CODES: frozenset[int] = frozenset({0, 1})


# ---------------------------------------------------------------------------
# TestsslConnector
# ---------------------------------------------------------------------------


class TestsslConnector(BaseSubprocessConnector):
    """
    Subprocess connector for testssl.sh deep TLS stack analysis.

    Invokes testssl.sh against a target hostname:port extracted from the
    supplied target_url.  Output is captured via ``--jsonfile <tmpfile>``
    and parsed into a filtered list of finding objects.

    The connector performs severity filtering before returning ConnectorResult
    to remove OK/INFO/LOW noise.  The oracle logic (which severities trigger
    FAIL vs PASS-with-note) is deliberately kept in the calling ExternalToolTest.

    ClassVar declarations:
        TOOL_NAME             : "testssl.sh"
        BINARY_NAME           : "testssl.sh"
        SERVICE_ENV_VAR       : "TESTSSL_SERVICE_URL"
        DEFAULT_TIMEOUT_SECONDS : 120 (testssl full scan takes 90–180 s)

    ConnectorResult.raw_output structure::

        {
          "command":  "testssl.sh --quiet --color 0 localhost:8443",
                                                     # human-readable command for
                                                     # manual reproduction (no
                                                     # --jsonfile flag — internal only)
          "results": [               # severity-filtered findings (WARN+ only)
            {                        # these are the oracle inputs for _evaluate()
              "id":       "tls1",
              "severity": "WARN",
              "finding":  "offered (deprecated)",
              "cve":      "",
              "cwe":      ""
            },
            ...
          ],
          "raw_findings": [...],     # complete unfiltered array from testssl.sh
                                     # persisted verbatim to outputs/tools/ for
                                     # direct analyst inspection without re-run
          "all_count":    42,        # total findings before filtering
          "retained_count": 3        # findings after severity filter
        }
    """

    TOOL_NAME: ClassVar[str] = "testssl.sh"
    BINARY_NAME: ClassVar[str] = "testssl.sh"
    SERVICE_ENV_VAR: ClassVar[str] = "TESTSSL_SERVICE_URL"
    DEFAULT_TIMEOUT_SECONDS: ClassVar[int] = 120

    # install_tools.sh places the pinned testssl.sh binary at:
    #     ./tools/testssl/testssl.sh   (relative to project root / CWD)
    # Declaring LOCAL_TOOLS_SUBDIR activates Channel 0 of _resolve_binary_path()
    # in BaseSubprocessConnector so that the connector is found there before
    # falling back to shutil.which() or TESTSSL_SERVICE_URL.
    LOCAL_TOOLS_SUBDIR: ClassVar[str] = "testssl"

    def run(
        self,
        target_url: str,
        timeout_seconds: int,
        *,
        extra_flags: str = _DEFAULT_EXTRA_FLAGS,
    ) -> ConnectorResult:
        """
        Invoke testssl.sh against the target and return filtered findings.

        CLI contract:
            The binary is invoked as::

                testssl.sh [extra_flags] --jsonfile <tmpfile> <host>:<port>

            testssl.sh writes its JSON array output to ``<tmpfile>`` on
            completion.  stdout/stderr are captured but not used for
            primary output parsing -- they are examined only to detect
            execution errors (non-zero exit code with diagnostic output).

        Temp file lifecycle:
            A temp file is created via ``tempfile.mkstemp()`` before the
            subprocess is launched.  It is deleted in the ``finally`` block
            regardless of outcome.  If testssl.sh does not write to the file
            (e.g. binary version too old, flag not supported), the file will be
            empty and ExternalToolError is raised with a descriptive message.

        Severity filtering:
            After parsing the JSON array, only findings with severity in
            RETAINED_SEVERITIES (WARN, MEDIUM, HIGH, CRITICAL) are kept.
            The ``all_count`` field in raw_output reports the total before
            filtering so the analyst knows how many OK/INFO items were
            discarded.

        Args:
            target_url:      HTTPS URL of the API Gateway, e.g.
                             ``https://localhost:8443``.  The connector
                             extracts hostname and port for the testssl.sh
                             scan target argument.
            timeout_seconds: Wall-clock limit for the subprocess execution.
                             Must be sourced from config.yaml, never a
                             literal.  Recommended: 120.
            extra_flags:     Additional CLI flags appended verbatim to the
                             command.  Default: ``--quiet --color 0``.
                             Must not contain credentials or secrets.

        Returns:
            ConnectorResult: Parsed and severity-filtered testssl.sh output.
                             raw_output follows the structure documented in
                             the class docstring.

        Raises:
            ExternalToolError: On timeout, OS error, empty output, invalid
                               JSON, or any unrecoverable execution failure.
        """
        scan_target = self._extract_scan_target(target_url)
        cmd = self._build_command(scan_target, extra_flags)

        # Build human-readable commands for analyst reproduction (Proposal A).
        # Delegates path normalisation and string construction to the base class
        # helper _build_reproducible_commands(), eliminating the ~15 lines of
        # duplicated logic that every connector would otherwise reimplement.
        #
        # Two variants stored in raw_output:
        #   "command"      -- text output (no --jsonfile); what you run manually.
        #   "command_json" -- with --jsonfile flag; mirrors what APIGuard runs.
        reproducible_command, reproducible_command_json = self._build_reproducible_commands(
            cmd_prefix=cmd,
            scan_target=scan_target,
            json_output_args=["--jsonfile", "testssl_result.json"],
        )

        log.info(
            "testssl_connector_run_starting",
            scan_target=scan_target,
            timeout_seconds=timeout_seconds,
            reproducible_command=reproducible_command,
        )

        # Create a temp file for testssl.sh JSON output.
        # mkstemp() returns (fd, path); close the fd immediately so testssl
        # can write to the path without the fd blocking it on Windows.
        fd, json_output_path = tempfile.mkstemp(suffix=".json", prefix="apiguard_testssl_")
        os.close(fd)

        start_time_ms = int(time.monotonic() * 1000)

        try:
            stdout, exit_code = self._run_subprocess(
                cmd=cmd + ["--jsonfile", json_output_path, scan_target],
                timeout_seconds=timeout_seconds,
                tool_name=self.TOOL_NAME,
            )

            execution_time_ms = int(time.monotonic() * 1000) - start_time_ms

            if exit_code not in _TESTSSL_SUCCESS_EXIT_CODES:
                # Non-zero exit (other than 1, which testssl uses for warnings)
                # means execution error, not a TLS finding.
                stderr_preview = (stdout or "")[:300].replace("\n", " ")
                raise ExternalToolError(
                    message=(
                        f"testssl.sh exited with code {exit_code}. "
                        f"Output preview: {stderr_preview!r}. "
                        "Check that the target is reachable and that testssl.sh "
                        "version is >= 3.0."
                    ),
                    tool_name=self.TOOL_NAME,
                    exit_code=exit_code,
                )

            raw_output = self._read_and_parse_json_output(json_output_path)

        except ExternalToolError:
            # Propagate ExternalToolError directly: _run_subprocess raises it
            # for timeout and OS errors; we also raise it above for bad exit codes.
            raise

        except Exception as exc:
            raise ExternalToolError(
                message=f"testssl.sh connector unexpected error: {exc}",
                tool_name=self.TOOL_NAME,
                exit_code=None,
            ) from exc

        finally:
            # Always remove the temp file regardless of outcome.
            self._cleanup_temp_file(json_output_path)

        log.info(
            "testssl_connector_run_complete",
            scan_target=scan_target,
            all_count=raw_output.get("all_count", 0),
            retained_count=raw_output.get("retained_count", 0),
            exit_code=exit_code,
            execution_time_ms=execution_time_ms,
        )

        # Inject both reproducible commands into raw_output so they propagate
        # automatically to ConnectorResult.raw_output -> TestResult.tool_artifact
        # -> HTML report without any model changes.
        raw_output["command"] = reproducible_command
        raw_output["command_json"] = reproducible_command_json

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

    def _extract_scan_target(self, target_url: str) -> str:
        """
        Extract ``hostname:port`` string from a URL for testssl.sh.

        testssl.sh expects a scan target in ``hostname:port`` format, not a
        full URL.  This method parses the URL and constructs the target string,
        defaulting to port 443 if no explicit port is present in the URL.

        Args:
            target_url: Full URL, e.g. ``https://localhost:8443`` or
                        ``https://api.example.com``.

        Returns:
            str: ``hostname:port`` string, e.g. ``localhost:8443``.

        Raises:
            ExternalToolError: If the hostname cannot be extracted from the URL.
        """
        parsed = urlparse(target_url)
        hostname = parsed.hostname
        if not hostname:
            raise ExternalToolError(
                message=(
                    f"Cannot extract hostname from target URL '{target_url}'. "
                    "Ensure target.endpoint_base_url() returns a valid HTTPS URL."
                ),
                tool_name=self.TOOL_NAME,
                exit_code=None,
            )
        port = parsed.port or 443  # noqa: PLR2004 -- 443 is the HTTPS default port
        return f"{hostname}:{port}"

    def _build_command(
        self,
        scan_target: str,  # noqa: ARG002 -- reserved for potential future use
        extra_flags: str,
    ) -> list[str]:
        """
        Build the testssl.sh command prefix (without the JSON output flag and target).

        The caller appends ``--jsonfile <path>`` and the scan target after this
        prefix.  This split allows the temp file path to be inserted cleanly.

        Binary resolution:
            Uses _resolve_binary_path() to support both local-tools-directory
            installations (./tools/testssl/testssl.sh, via install_tools.sh)
            and system PATH installations transparently.  Falls back to
            self.BINARY_NAME only if _resolve_binary_path() returns None
            (this path is reached only when is_available() returned True via
            the SERVICE_ENV_VAR channel, which means the binary is available
            as a Docker service rather than a local executable).

        Args:
            scan_target: The ``hostname:port`` string (unused here, present for
                         API symmetry with other connector implementations).
            extra_flags: Space-separated string of additional CLI flags.

        Returns:
            list[str]: Command prefix, e.g.
                       ``["/abs/path/to/tools/testssl/testssl.sh", "--quiet", "--color", "0"]``.
        """
        binary_cmd: str = self._resolve_binary_path() or self.BINARY_NAME
        cmd: list[str] = [binary_cmd]

        # Append extra_flags as individual tokens, ignoring empty strings
        # that result from splitting a string with consecutive spaces.
        flag_tokens = [token for token in extra_flags.split() if token]
        cmd.extend(flag_tokens)

        return cmd

    def _read_and_parse_json_output(
        self,
        json_output_path: str,
    ) -> dict[str, Any]:
        """
        Read the testssl.sh JSON output file and apply severity filtering.

        testssl.sh v3.x writes a JSON array to the file.  This method reads
        the file, normalises the output to a list of finding dicts, applies
        the RETAINED_SEVERITIES filter, and returns a structured dict.

        The returned dict follows the ConnectorResult.raw_output schema
        documented in the class docstring.

        Args:
            json_output_path: Absolute path to the JSON file written by testssl.sh.

        Returns:
            dict[str, Any]: Structured output with ``results``, ``all_count``,
                            and ``retained_count`` keys.

        Raises:
            ExternalToolError: If the file is empty, unreadable, or contains
                               invalid JSON.
        """
        try:
            with open(json_output_path) as f:
                raw_content = f.read().strip()
        except OSError as exc:
            raise ExternalToolError(
                message=(
                    f"testssl.sh JSON output file could not be read from "
                    f"'{json_output_path}': {exc}"
                ),
                tool_name=self.TOOL_NAME,
                exit_code=0,
            ) from exc

        if not raw_content:
            raise ExternalToolError(
                message=(
                    "testssl.sh produced an empty JSON output file.  "
                    "The target may be unreachable, or testssl.sh may not support "
                    "the --jsonfile flag (requires version >= 3.0).  "
                    "Verify connectivity and binary version: 'testssl.sh --version'."
                ),
                tool_name=self.TOOL_NAME,
                exit_code=0,
            )

        try:
            parsed = json.loads(raw_content)
        except json.JSONDecodeError as exc:
            preview = raw_content[:200].replace("\n", " ")
            raise ExternalToolError(
                message=(
                    f"testssl.sh JSON output is not valid JSON: {exc}. Output preview: {preview!r}"
                ),
                tool_name=self.TOOL_NAME,
                exit_code=0,
            ) from exc

        # Normalise to a list of finding dicts.
        # testssl.sh v3.x produces a top-level list.
        # Some older versions or wrapper scripts may nest findings under a key.
        all_findings: list[dict[str, Any]] = []
        if isinstance(parsed, list):
            all_findings = [item for item in parsed if isinstance(item, dict)]
        elif isinstance(parsed, dict):
            # Fallback: findings nested under a "scanResult" or similar key.
            nested = parsed.get("scanResult") or parsed.get("results") or []
            if isinstance(nested, list):
                all_findings = [item for item in nested if isinstance(item, dict)]
            else:
                # Treat the dict itself as a single-finding document (edge case).
                all_findings = [parsed]

        all_count = len(all_findings)

        # Apply severity filter: retain only actionable severities.
        retained_findings = [
            item
            for item in all_findings
            if str(item.get("severity", "")).upper() in RETAINED_SEVERITIES
        ]

        retained_count = len(retained_findings)

        log.debug(
            "testssl_connector_severity_filter_applied",
            all_count=all_count,
            retained_count=retained_count,
            discarded_count=all_count - retained_count,
        )

        return {
            "results": retained_findings,
            "raw_findings": all_findings,
            "all_count": all_count,
            "retained_count": retained_count,
        }

    def _cleanup_temp_file(self, path: str) -> None:
        """
        Delete the temporary JSON output file, ignoring errors.

        Errors are logged at DEBUG level only -- a failed cleanup must not
        propagate as an exception or alter the test result.

        Args:
            path: Absolute path to the temporary file to delete.
        """
        try:
            os.unlink(path)
        except OSError as exc:
            log.debug(
                "testssl_connector_temp_file_cleanup_failed",
                path=path,
                error=str(exc),
            )

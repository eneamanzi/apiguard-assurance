"""
src/connectors/base.py

Three-tier connector hierarchy for wrapping external security tools.

Architecture — DA-1 split (ADR-001 §3):
    BaseConnector           — pure ABC, declares the universal contract.
    BaseSubprocessConnector — concrete base for tools invoked as subprocesses
                              (testssl.sh, ffuf, nuclei, ...).
    BaseLibraryConnector    — concrete base for tools accessed as Python libraries
                              (sslyze, ...).

    The split is motivated by the principle that a subclass must not inherit
    methods it cannot use.  Before DA-1, a hypothetical SslyzeConnector would
    have inherited _run_subprocess(), BINARY_NAME, and SERVICE_ENV_VAR even
    though none of them apply to a library-based tool.  The three-tier hierarchy
    removes this coupling: each concrete subclass inherits exactly the discovery
    and execution mechanisms that match its integration pattern.

ConnectorResult — the typed output model:
    ConnectorResult is the sole interface between connectors/ and
    external_tests/.  It carries the raw tool output (already parsed as a
    dict) alongside execution metadata.  The connector does NOT decide whether
    anything is a FAIL: it returns data; the ExternalToolTest evaluates the
    data against the oracle.

Dependency rule:
    This module imports from stdlib, pydantic, structlog, and src.core.exceptions.
    It must never import from tests/, external_tests/, config/, discovery/, or
    report/.
"""

from __future__ import annotations

import importlib
import importlib.util
import json
import os
import re
import shutil
import subprocess
from abc import ABC, abstractmethod
from pathlib import Path
from typing import Any, ClassVar, TypedDict

import structlog
from pydantic import BaseModel, Field

from src.core.exceptions import ExternalToolError

log: structlog.BoundLogger = structlog.get_logger(__name__)

# Matches all standard ANSI CSI escape sequences (SGR color/bold, cursor movement,
# erase codes).  Pattern: ESC [ ... final-byte where final-byte is [A-Za-z].
# Compiled once at module level and reused in BaseSubprocessConnector.get_version()
# to strip decoration from binary --version output (e.g. testssl.sh emits bold codes).
_ANSI_CSI_PATTERN: re.Pattern[str] = re.compile(r"\x1b\[[0-9;]*[A-Za-z]")

# ---------------------------------------------------------------------------
# ConnectorResult — the typed output of one tool execution
# ---------------------------------------------------------------------------


class ConnectorResult(BaseModel):
    """
    Structured output of a single external tool execution.

    This model is the sole interface between connectors/ and external_tests/.
    The connector populates it; the ExternalToolTest reads it and decides
    what constitutes a PASS, FAIL, or SKIP.

    The raw_output field is typed dict[str, Any] with Any explicitly justified:
    every tool (testssl.sh, ffuf, nuclei) produces a different JSON schema.
    The concrete ExternalToolTest that consumes the result knows the schema of
    its specific tool and accesses fields by name, accepting that intermediate
    layers cannot type-check the content.  The comment below the field makes
    this justification explicit and machine-checkable by Ruff (ANN rule).

    The timed_out field is architecturally critical: it allows the calling test
    to produce a semantically distinct error message ("tool timed out after 120s
    - increase external_tools.testssl.timeout_seconds in config.yaml") vs a
    genuine failure ("testssl.sh exited with code 1: TLS handshake refused").
    """

    model_config = {"frozen": True}

    tool_name: str = Field(
        description="Name of the binary that produced this result (e.g. 'testssl.sh')."
    )
    tool_version: str | None = Field(
        default=None,
        description=(
            "Version string extracted from the binary's --version output, "
            "or None if version discovery is not supported by the binary. "
            "Included in the HTML report and evidence.json for reproducibility."
        ),
    )
    raw_output: dict[str, Any] = Field(
        # Any is justified: JSON schema varies per tool; only the specific
        # ExternalToolTest subclass knows the structure and accesses fields safely.
        description=(
            "Parsed JSON output of the tool execution. Structure varies by tool. "
            "Must be sanitized by EvidenceStore.pin_artifact() before storage -- "
            "connector implementations must NOT sanitize it themselves."
        ),
    )
    exit_code: int = Field(
        description=(
            "Exit code of the subprocess. Semantics are tool-specific: "
            "testssl.sh uses 0 for success regardless of findings; "
            "nuclei uses 0 for success; ffuf uses 0 for success. "
            "Non-zero generally indicates an execution error, not a finding."
        ),
    )
    execution_time_ms: int = Field(
        description="Wall-clock duration of the subprocess in milliseconds.",
        ge=0,
    )
    timed_out: bool = Field(
        default=False,
        description=(
            "True if the subprocess was terminated because timeout_seconds was "
            "exceeded (subprocess.TimeoutExpired).  When True, exit_code is "
            "typically meaningless (process was killed, not exited normally). "
            "The calling ExternalToolTest must produce TestResult(ERROR) with "
            "a message referencing the configured timeout value."
        ),
    )


# ---------------------------------------------------------------------------
# BaseConnector -- pure ABC (tier 1)
# ---------------------------------------------------------------------------


class BaseConnector(ABC):
    """
    Pure abstract base class defining the universal connector contract.

    Every connector -- whether subprocess-based or library-based -- must satisfy
    this interface.  The class carries no implementation: it only declares the
    three abstract methods that all concrete connectors must provide.

    The TOOL_NAME ClassVar is the single piece of metadata required at this
    tier.  It is used for logging and for ExternalTestRegistry grouping (DA-2)
    without coupling the ABC to any specific discovery mechanism.

    Subclasses:
        BaseSubprocessConnector -- for tools executed as OS subprocesses.
        BaseLibraryConnector    -- for tools accessed as Python libraries.

    ClassVar declarations (required on every concrete subclass):

        TOOL_NAME: str
            Human-readable tool identifier used in log messages and the HTML
            report.  For subprocess tools this is typically the binary name
            (e.g. "testssl.sh", "nuclei").  For library tools it is the
            PyPI package name (e.g. "sslyze").
    """

    TOOL_NAME: ClassVar[str]

    # ------------------------------------------------------------------
    # Abstract interface -- all three must be implemented by subclasses
    # ------------------------------------------------------------------

    @abstractmethod
    def is_available(self) -> bool:
        """
        Return True if this connector's underlying tool can be executed.

        Implementations must never raise; return False on any error.

        Returns:
            bool: True if the tool is available via this connector's
                  discovery mechanism.
        """
        ...

    @abstractmethod
    def get_version(self) -> str | None:
        """
        Return the tool's version string, or None if not determinable.

        Implementations must never raise; return None on any error.

        Returns:
            str | None: Version string on success, None on any failure.
        """
        ...

    @abstractmethod
    def run(
        self,
        target_url: str,
        timeout_seconds: int,
    ) -> ConnectorResult:
        """
        Execute the tool against the given target URL and return structured output.

        TIMEOUT HANDLING -- mandatory, not optional:
            The timeout_seconds parameter has no default value intentionally.
            Every caller must supply a value read from config.yaml
            (ExternalToolsConfig.<tool>.timeout_seconds).

        JSON OUTPUT REQUIREMENT:
            Connectors must produce machine-parsable JSON and return it as a
            parsed dict in ConnectorResult.raw_output.

        SANITIZATION RESPONSIBILITY:
            Connectors must NOT sanitize raw_output.  Sanitization is the sole
            responsibility of EvidenceStore.pin_artifact().

        Subclass signature extension:
            Concrete subclasses MAY add their own keyword-only parameters
            (after a ``*`` separator) with defaults.  This is LSP-safe: a
            caller using only the abstract signature passes only
            ``target_url`` and ``timeout_seconds``; subclass-specific
            parameters are accessed via the concrete type (e.g.
            ``TestsslConnector(...).run(..., extra_flags=...)``).
            Do NOT accept ``**kwargs``; declare every supported parameter
            explicitly with a precise type.

        Args:
            target_url:      The base URL of the target API (from
                             TargetContext.effective_endpoint_base_url()).
                             Does not include trailing slash.
            timeout_seconds: Mandatory wall-clock limit for the execution.
                             Sourced from ExternalToolsConfig.<tool>.timeout_seconds.

        Returns:
            ConnectorResult: Parsed output of the tool run.

        Raises:
            ExternalToolError: On execution failure or unparsable output.
        """
        ...


# ---------------------------------------------------------------------------
# BaseSubprocessConnector -- subprocess-based tools (tier 2)
# ---------------------------------------------------------------------------


class BaseSubprocessConnector(BaseConnector):
    """
    Concrete base class for external tools invoked as OS subprocesses.

    Provides complete implementations of is_available(), get_version(), and
    the protected helpers _run_subprocess(), _parse_json_output(), and
    _parse_jsonl_output().  Concrete subclasses (e.g. TestsslConnector,
    FfufConnector, NucleiConnector) only need to declare BINARY_NAME,
    SERVICE_ENV_VAR, and implement run().

    Discovery channels (evaluated in cascade by is_available()):
        1. shutil.which(BINARY_NAME) -- binary installed locally in PATH.
        2. os.getenv(SERVICE_ENV_VAR) -- binary exposed as HTTP microservice
           via Docker Compose, referenced by a dedicated env variable.

    ClassVar declarations (required on every concrete subclass):

        BINARY_NAME: str
            The name of the binary as it appears in the system PATH.
            Example: "testssl.sh", "ffuf", "nuclei".
            Used by is_available() via shutil.which() for local discovery.

        SERVICE_ENV_VAR: str
            The environment variable name that, if set, points to the tool
            running as an HTTP microservice (Docker Compose mode).
            Example: "TESTSSL_SERVICE_URL", "FFUF_SERVICE_URL".
            Used by is_available() as a fallback when shutil.which() returns None.

        DEFAULT_TIMEOUT_SECONDS: int
            Fallback timeout used as a safety net only -- the ADR mandates that
            callers always pass an explicit timeout read from config.yaml.
            Defaults to 120 if not overridden.
    """

    BINARY_NAME: ClassVar[str]
    SERVICE_ENV_VAR: ClassVar[str]
    DEFAULT_TIMEOUT_SECONDS: ClassVar[int] = 120

    # Optional: subdirectory name inside the project-local ``./tools/`` directory
    # where the binary is installed by install_tools.sh.  When non-empty, Channel 0
    # of _resolve_binary_path() checks:
    #     Path.cwd() / "tools" / LOCAL_TOOLS_SUBDIR / BINARY_NAME
    # before falling back to shutil.which() (Channel 1) and SERVICE_ENV_VAR (Channel 2).
    # Set this in concrete subclasses when the tool is distributed via install_tools.sh.
    # Example: LOCAL_TOOLS_SUBDIR = "testssl"  -> ./tools/testssl/testssl.sh
    # Leave as "" (default) to skip the local-tools check for that connector.
    LOCAL_TOOLS_SUBDIR: ClassVar[str] = ""

    # ------------------------------------------------------------------
    # Discovery -- concrete implementations
    # ------------------------------------------------------------------

    def _resolve_binary_path(self) -> str | None:
        """
        Return the filesystem path to the binary using a three-channel cascade.

        Discovery channels (evaluated in priority order, first hit wins):

            Channel 0 -- project-local tools directory:
                ``Path.cwd() / "tools" / LOCAL_TOOLS_SUBDIR / BINARY_NAME``
                This channel is active only when LOCAL_TOOLS_SUBDIR is non-empty
                (i.e., the subclass opts in by declaring it).  The path is checked
                for existence and execute permission.  This channel enables
                plug-and-play operation: running ``install_tools.sh`` places the
                pinned binary inside ``./tools/``, and apiguard works without any
                PATH modification or symlink.

            Channel 1 -- system PATH:
                ``shutil.which(BINARY_NAME)`` returns the absolute path of the
                binary if it is installed in any directory on the system PATH.
                This is the traditional "binary installed globally" scenario.

        Returns None if neither channel locates the binary.  The caller (is_available,
        get_version, _build_command) falls through to the SERVICE_ENV_VAR channel
        if applicable, or reports the tool as unavailable.

        This method never raises.

        Returns:
            str | None: Absolute path to the binary, or None if not found.
        """
        # Channel 0: project-local tools directory (opt-in per subclass).
        if self.LOCAL_TOOLS_SUBDIR:
            local_path = Path.cwd() / "tools" / self.LOCAL_TOOLS_SUBDIR / self.BINARY_NAME
            if local_path.is_file() and os.access(local_path, os.X_OK):
                log.debug(
                    "connector_binary_found_local_tools",
                    binary=self.BINARY_NAME,
                    path=str(local_path),
                    subdir=self.LOCAL_TOOLS_SUBDIR,
                )
                return str(local_path)

        # Channel 1: system PATH.
        system_path = shutil.which(self.BINARY_NAME)
        if system_path is not None:
            log.debug(
                "connector_binary_found_in_path",
                binary=self.BINARY_NAME,
                path=system_path,
            )
            return system_path

        return None

    def is_available(self) -> bool:
        """
        Return True if the binary is discoverable via any channel.

        Three-channel cascade (evaluated in priority order):

            Channel 0 -- project-local tools directory (via _resolve_binary_path):
                ``./tools/{LOCAL_TOOLS_SUBDIR}/{BINARY_NAME}`` relative to CWD.
                Active only when LOCAL_TOOLS_SUBDIR is non-empty.

            Channel 1 -- system PATH (via _resolve_binary_path):
                ``shutil.which(BINARY_NAME)``

            Channel 2 -- Docker Compose service URL:
                ``os.getenv(SERVICE_ENV_VAR)``

        Returns False if all three channels return None / empty string.
        This method never raises.

        Returns:
            bool: True if the tool is available via at least one channel.
        """
        resolved = self._resolve_binary_path()
        if resolved is not None:
            return True

        service_url = os.getenv(self.SERVICE_ENV_VAR)
        if service_url:
            log.debug(
                "connector_service_url_found",
                binary=self.BINARY_NAME,
                env_var=self.SERVICE_ENV_VAR,
                url=service_url,
            )
            return True

        log.debug(
            "connector_not_available",
            binary=self.BINARY_NAME,
            local_tools_subdir=self.LOCAL_TOOLS_SUBDIR or "(not configured)",
            env_var=self.SERVICE_ENV_VAR,
        )
        return False

    def get_version(self) -> str | None:
        """
        Attempt to retrieve the tool version string via subprocess.

        Runs the binary with --version and extracts the first non-empty line
        of stdout or stderr.  Returns None if the binary is not available or
        if the version command fails for any reason.

        Uses _resolve_binary_path() to support both local-tools-directory
        installations and system PATH installations transparently.

        The version string is embedded in the HTML report and in evidence.json
        for reproducibility -- an analyst can reconstruct exactly which version
        of the tool produced a given finding.

        Returns:
            str | None: Version string on success, None on any failure.
        """
        binary_cmd = self._resolve_binary_path()
        if binary_cmd is None:
            return None
        try:
            result = subprocess.run(  # noqa: S603 -- cmd is [resolved_path, "--version"]:
                # binary_cmd is the output of _resolve_binary_path(): either an
                # absolute path from the local tools directory (verified to exist
                # and be executable) or the absolute path returned by shutil.which().
                # In both cases it is a filesystem path, not user-supplied data.
                # The only additional arg is the static literal "--version".
                # No untrusted data flows into this call; S603 is a false positive.
                [binary_cmd, "--version"],
                capture_output=True,
                text=True,
                timeout=10,
            )
            # Strip ANSI CSI escape sequences, then whitespace.
            # Some tools (notably testssl.sh) decorate --version output with
            # bold/colour codes; without stripping the HTML report shows
            # "[1m testssl 3.2" because the ESC byte is invisible in most
            # rendering contexts.  _ANSI_CSI_PATTERN is a module-level constant
            # (compiled once); strip ANSI first, then .strip() so that removal
            # does not expose leading/trailing spaces hidden inside sequences.
            for line in (result.stdout or result.stderr or "").splitlines():
                cleaned = _ANSI_CSI_PATTERN.sub("", line).strip()
                # Skip empty lines and decorator lines composed entirely of
                # repeated non-alphanumeric characters (e.g. testssl.sh emits
                # "######...######" as a visual separator before the actual
                # version string).  A line is a decorator if it is non-empty
                # but contains no alphanumeric character.
                if cleaned and any(ch.isalnum() for ch in cleaned):
                    return cleaned
        except (subprocess.TimeoutExpired, FileNotFoundError, OSError) as exc:
            log.debug(
                "connector_version_discovery_failed",
                binary=self.BINARY_NAME,
                resolved_path=binary_cmd,
                error=str(exc),
            )
        return None

    # ------------------------------------------------------------------
    # Protected helpers -- available to subclasses
    # ------------------------------------------------------------------

    def _run_subprocess(
        self,
        cmd: list[str],
        timeout_seconds: int,
        tool_name: str,
    ) -> tuple[str, int]:
        """
        Execute a subprocess and return (stdout, exit_code).

        Handles TimeoutExpired by terminating the process and raising
        ExternalToolError(timed_out=True).  Handles OS-level failures
        (FileNotFoundError, PermissionError) by raising ExternalToolError.

        This helper centralises subprocess management so that concrete
        connectors can focus on CLI argument construction and output parsing
        rather than process lifecycle boilerplate.

        Args:
            cmd:             List of strings forming the command and arguments.
            timeout_seconds: Wall-clock limit passed to subprocess.run.
            tool_name:       Binary name for error messages (e.g., "testssl.sh").

        Returns:
            tuple[str, int]: (stdout content as string, process exit code).

        Raises:
            ExternalToolError: On timeout, OS error, or FileNotFoundError.
        """
        log.debug(
            "connector_subprocess_start",
            tool=tool_name,
            timeout_seconds=timeout_seconds,
            cmd=" ".join(cmd[:4]),  # log first 4 tokens only -- avoid logging target URL twice
        )
        try:
            proc = subprocess.run(  # noqa: S603 -- cmd is fully controlled:
                # cmd is constructed by the connector subclass's run() method
                # from three sources: (1) self.BINARY_NAME -- a ClassVar[str]
                # defined in source code; (2) static flag literals specific to
                # the tool's CLI; (3) values from TargetContext / config.yaml
                # after Pydantic validation.  No field ever originates from raw
                # user HTTP input.  The S603 warning is a false positive here.
                cmd,
                capture_output=True,
                text=True,
                timeout=timeout_seconds,
            )
        except subprocess.TimeoutExpired as exc:
            log.warning(
                "connector_subprocess_timeout",
                tool=tool_name,
                timeout_seconds=timeout_seconds,
            )
            raise ExternalToolError(
                message=(
                    f"{tool_name} execution timed out after {timeout_seconds}s. "
                    f"Increase 'external_tools.{tool_name.rstrip('.sh')}.timeout_seconds' "
                    "in config.yaml if the target is slow to respond."
                ),
                tool_name=tool_name,
                timed_out=True,
            ) from exc
        except (FileNotFoundError, PermissionError, OSError) as exc:
            raise ExternalToolError(
                message=f"{tool_name} could not be executed: {exc}",
                tool_name=tool_name,
                exit_code=None,
            ) from exc

        log.debug(
            "connector_subprocess_complete",
            tool=tool_name,
            exit_code=proc.returncode,
            stdout_bytes=len(proc.stdout or ""),
        )
        return proc.stdout or "", proc.returncode

    @staticmethod
    def _parse_json_output(raw_stdout: str, tool_name: str) -> dict[str, Any]:
        """
        Parse a single-object JSON document from tool stdout.

        Use this method for tools that produce one top-level JSON object on
        stdout (e.g. testssl.sh with ``--jsonfile /dev/stdout``).  For tools
        that produce one JSON object per line (JSONL -- e.g. ffuf, nuclei),
        use ``_parse_jsonl_output`` instead.

        Args:
            raw_stdout: Raw stdout string from the subprocess.
            tool_name:  Binary name, used only in error messages.

        Returns:
            dict[str, Any]: Parsed JSON as a Python dict.

        Raises:
            ExternalToolError: If raw_stdout is empty, not valid JSON, or the
                               top-level value is not a dict (e.g. a bare list).
        """
        stripped = raw_stdout.strip()
        if not stripped:
            raise ExternalToolError(
                message=f"{tool_name} produced empty output. Is the target reachable?",
                tool_name=tool_name,
                exit_code=0,
            )
        try:
            parsed = json.loads(stripped)
        except json.JSONDecodeError as exc:
            # Include first 200 chars of output for debugging without log bloat.
            preview = stripped[:200].replace("\n", " ")
            raise ExternalToolError(
                message=(
                    f"{tool_name} output is not valid JSON: {exc}. Output preview: {preview!r}"
                ),
                tool_name=tool_name,
                exit_code=0,
            ) from exc
        if not isinstance(parsed, dict):
            raise ExternalToolError(
                message=(
                    f"{tool_name} JSON output is not a dict (got {type(parsed).__name__}). "
                    "Use _parse_jsonl_output() if the tool produces one JSON object per line."
                ),
                tool_name=tool_name,
                exit_code=0,
            )
        return parsed

    @staticmethod
    def _parse_jsonl_output(
        raw_stdout: str,
        tool_name: str,
        *,
        skip_invalid_lines: bool = True,
    ) -> list[dict[str, Any]]:
        """
        Parse a JSONL (JSON Lines) document from tool stdout.

        Use this method for tools that emit one JSON object per line on stdout
        (e.g. ffuf with ``-json``, nuclei with ``-json``).  Each non-empty line
        is parsed independently; lines that fail to parse are either skipped
        with a DEBUG log entry (default) or raise ExternalToolError
        (``skip_invalid_lines=False``).

        Output format contract:
            The caller (connector subclass) is responsible for wrapping the
            returned list in a dict before assigning it to
            ``ConnectorResult.raw_output`` -- which is typed as ``dict[str, Any]``.
            The conventional wrapper key is ``"results"``::

                items = self._parse_jsonl_output(stdout, "ffuf")
                ConnectorResult(
                    ...,
                    raw_output={"results": items, "count": len(items)},
                )

            This preserves the ``dict[str, Any]`` invariant of ``raw_output``
            while carrying the full list of findings.

        Args:
            raw_stdout:          Raw stdout string from the subprocess.
            tool_name:           Binary name, used only in log messages.
            skip_invalid_lines:  When True (default), lines that cannot be
                                 parsed as JSON are skipped and logged at DEBUG
                                 level.  Set to False to raise on the first
                                 invalid line.

        Returns:
            list[dict[str, Any]]: Ordered list of parsed JSON objects.
                                  Empty list if the output contains no valid
                                  JSON lines (e.g. tool ran but found nothing).

        Raises:
            ExternalToolError: If raw_stdout is completely empty.
                               Also raised on any invalid line when
                               ``skip_invalid_lines=False``.
        """
        stripped = raw_stdout.strip()
        if not stripped:
            raise ExternalToolError(
                message=f"{tool_name} produced empty output. Is the target reachable?",
                tool_name=tool_name,
                exit_code=0,
            )

        results: list[dict[str, Any]] = []
        invalid_count: int = 0

        for line_number, line in enumerate(stripped.splitlines(), start=1):
            line = line.strip()  # noqa: PLW2901 -- intentional reassignment for clarity
            if not line:
                continue  # blank separator lines are normal in JSONL

            try:
                parsed = json.loads(line)
            except json.JSONDecodeError as exc:
                invalid_count += 1
                if not skip_invalid_lines:
                    raise ExternalToolError(
                        message=(
                            f"{tool_name} JSONL line {line_number} is not valid JSON: {exc}. "
                            f"Line preview: {line[:120]!r}"
                        ),
                        tool_name=tool_name,
                        exit_code=0,
                    ) from exc
                log.debug(
                    "connector_jsonl_invalid_line_skipped",
                    tool=tool_name,
                    line_number=line_number,
                    error=str(exc),
                    preview=line[:80],
                )
                continue

            if not isinstance(parsed, dict):
                # JSONL lines that are not objects (e.g. bare strings, arrays)
                # are non-standard; skipped regardless of skip_invalid_lines.
                log.debug(
                    "connector_jsonl_non_dict_line_skipped",
                    tool=tool_name,
                    line_number=line_number,
                    actual_type=type(parsed).__name__,
                )
                continue

            results.append(parsed)

        if invalid_count > 0:
            log.debug(
                "connector_jsonl_parse_summary",
                tool=tool_name,
                valid_objects=len(results),
                invalid_lines_skipped=invalid_count,
            )

        return results

    @staticmethod
    def _relativize_display_path(raw: str) -> str:
        """
        Convert a file-system path to a CWD-relative path for display strings.

        This is the single, authoritative path-normalisation function for all
        display command strings in the connector hierarchy.  Both
        ``_build_reproducible_commands()`` and concrete connectors that need
        to relativize additional path arguments (e.g. a template directory
        passed via ``-t``) must call this method instead of duplicating the
        logic.

        Normalisation contract:
            - Path is INSIDE the CWD tree (``os.path.relpath()`` does not
              start with ``..``): return the relative path.
              Example: ``/home/user/project/tools/nuclei/nuclei`` becomes
              ``tools/nuclei/nuclei`` when CWD is ``/home/user/project``.
            - Path is OUTSIDE the project tree (e.g. ``/usr/local/bin/nuclei``
              or ``/tmp/tmpXXX.json``): return ``raw`` unchanged rather than
              emitting a confusing ``../../...`` string.
            - Windows cross-drive ``ValueError``: return ``raw`` unchanged.

        Caller responsibility for temp paths:
            Paths like ``/tmp/xxx_nuclei.json`` live outside the project tree
            and are returned unchanged.  Connectors that want to OMIT a temp
            path from display strings should not pass it to this function at
            all -- they should substitute a clean placeholder directly
            (e.g. ``"nuclei_result.json"``).

        Args:
            raw: An absolute or relative file-system path string.

        Returns:
            str: CWD-relative path if inside the project tree, ``raw`` otherwise.
        """
        try:
            rel = os.path.relpath(raw)
            return rel if not rel.startswith("..") else raw
        except ValueError:
            return raw

    def _sanitize_paths_in_findings(
        self,
        findings: list[dict[str, Any]],
        path_keys: tuple[str, ...],
    ) -> list[dict[str, Any]]:
        """
        Relativize local filesystem paths in a list of tool finding dicts.

        Use this helper ONLY for fields that contain paths from the local tool
        invocation infrastructure (e.g. template directories, binary locations).
        Never apply it to fields that carry finding data from the target system
        (matched URLs, discovered paths on the target, HTTP request/response
        bodies) -- those must be preserved verbatim as security evidence.

        For each finding dict, every key listed in ``path_keys`` whose value is
        a non-empty string is passed through ``_relativize_display_path()``.
        All other keys are copied unchanged.  The original dicts are not mutated;
        a new list with shallow-copied dicts is returned.

        Usage contract:
            Each concrete connector that calls this method must explicitly
            enumerate the path_keys it intends to sanitize and document why
            each key is an infrastructure path rather than a finding.  This
            opt-in, key-specific design prevents accidental truncation of
            target-system evidence.

        Example (NucleiConnector):
            ``_sanitize_paths_in_findings(results, path_keys=("template-path",))``
            ``template-path`` is the absolute filesystem path of the nuclei
            template file on the local machine, not data about the target.

        Args:
            findings:  List of finding dicts from the external tool's JSON output.
            path_keys: Tuple of dict keys whose string values should be
                       relativized.  Keys absent in a finding are silently
                       skipped.

        Returns:
            New list of finding dicts with the specified path fields relativized.
        """
        sanitized: list[dict[str, Any]] = []
        for finding in findings:
            copy: dict[str, Any] = dict(finding)
            for key in path_keys:
                raw_value = copy.get(key)
                if isinstance(raw_value, str) and raw_value:
                    copy[key] = self._relativize_display_path(raw_value)
            sanitized.append(copy)
        return sanitized

    def _build_reproducible_commands(
        self,
        cmd_prefix: list[str],
        scan_target: str,
        json_output_args: list[str],
    ) -> tuple[str, str]:
        """
        Build the two human-readable command strings stored in raw_output.

        This helper centralises the path-normalisation and command-string
        construction logic that every connector needs to produce the
        ``command`` and ``command_json`` keys in ``ConnectorResult.raw_output``.

        Before this method existed (Proposal A), each concrete connector
        reimplemented the same ~15 lines of path-relativisation logic.
        Any connector that forgot to inject ``command`` / ``command_json``
        into ``raw_output`` would silently break the HTML report template,
        which expects those keys under ``tool_artifact``.  Centralising here
        makes it impossible to forget: the concrete connector calls this once
        and unpacks the two strings.

        Path normalisation strategy:
            The binary path in ``cmd_prefix[0]`` may be an absolute path
            (e.g. ``/home/user/project/tools/testssl/testssl.sh``) or a
            system path (e.g. ``/usr/local/bin/nuclei``).  We convert it to
            a CWD-relative path for portability within the project tree.  The
            relative path is accepted ONLY when it stays inside the project
            (no leading ``..``) -- an external system binary is kept as-is
            because a ``../../usr/bin/...`` path would be longer and confusing.

        Two variants are returned:
            command      -- plain text output, no JSON flag appended; mirrors
                            what a human analyst types to reproduce the scan
                            with human-readable stdout output.
            command_json -- JSON output flag appended; mirrors what APIGuard
                            executes internally; useful for analysts who want
                            machine-parsable output from a manual re-run.

        Args:
            cmd_prefix:      List of command tokens WITHOUT the scan target
                             and WITHOUT the JSON output flag.  Must have at
                             least one element (the binary path at index 0).
                             Example: ["/abs/path/testssl.sh", "--quiet",
                             "--color", "0"]
            scan_target:     The target argument appended at the end of both
                             commands.  For subprocess tools this is typically
                             "hostname:port" (testssl.sh) or a URL (ffuf).
            json_output_args: Tool-specific tokens that produce JSON output,
                              appended BEFORE ``scan_target`` in command_json.
                              Examples:
                                  testssl.sh: ["--jsonfile", "testssl_result.json"]
                                  ffuf:       ["-json"]
                                  nuclei:     ["-json"]

        Returns:
            tuple[str, str]: (command, command_json) as plain strings.
        """
        raw_binary: str = cmd_prefix[0] if cmd_prefix else self.BINARY_NAME

        # Relativize the binary path via the canonical single-function helper.
        # All other tokens in cmd_prefix (flags, non-path arguments) are kept
        # unchanged -- paths for template dirs etc. must be relativized by the
        # concrete connector before passing cmd_prefix here.
        cmd_display: list[str] = [self._relativize_display_path(raw_binary)] + cmd_prefix[1:]

        # command: text output mode, no JSON flag -- what a human analyst runs.
        command: str = " ".join(cmd_display + [scan_target])

        # command_json: JSON output mode -- what APIGuard runs internally.
        command_json: str = " ".join(cmd_display + json_output_args + [scan_target])

        return command, command_json


# ---------------------------------------------------------------------------
# ConnectorRawOutput -- documented contract for raw_output keys (Proposal D)
# ---------------------------------------------------------------------------


class ConnectorRawOutput(TypedDict, total=True):
    """
    Typed contract for the keys expected in ConnectorResult.raw_output.

    Defined as a ``TypedDict(total=True)`` so that Pylance can verify
    statically that a connector's ``run()`` method populates all required
    keys.  Annotate the local dict in a connector's ``run()`` implementation
    as ``ConnectorRawOutput`` to get key-completeness checking at development
    time::

        raw_output: ConnectorRawOutput = {
            "command":      ...,
            "command_json": ...,
            "results":      all_findings,
            "all_count":    len(all_findings),
        }

    The ``total=True`` default makes every field required.  A connector that
    omits any key produces a Pylance error at the assignment site -- catching
    the contract violation before the test suite runs.

    Design principle -- "dumb pipe":
        Connectors do NOT filter, classify, or discard findings.  They deliver
        the complete tool output in ``results``.  The ExternalToolTest that
        consumes the result applies oracle logic (FAIL / note / ignore buckets)
        based on its own policy constants.  This means ``results`` is always the
        complete, unfiltered list from the tool -- there is no separate
        ``raw_findings`` field because the two would be identical.

    REQUIRED keys (HTML report template raises KeyError if absent):
        command       -- Human-readable plain-text command for analyst reproduction.
                         No JSON output flag; mirrors what a human runs at the shell.
        command_json  -- Same command with JSON output flag appended; mirrors
                         what APIGuard runs internally.
        results       -- Complete unfiltered list of finding dicts from the tool.
                         These are the oracle inputs for ExternalToolTest._evaluate(),
                         which partitions them into FAIL / note / ignore buckets.

    REQUIRED for statistics display in the report summary card:
        all_count     -- Total finding count; equals len(results).

    Runtime enforcement (complementary to this static check):
        ``external_tests/base.py`` duplicates the four required key names in
        ``_REQUIRED_RAW_OUTPUT_KEYS: frozenset[str]`` and validates them at
        runtime via ``_validate_raw_output()``.  The two mechanisms serve
        different audiences: this TypedDict catches omissions during development
        (static analysis); the frozenset catches omissions at assessment runtime
        (dynamic validation) for connectors whose raw_output dict is constructed
        dynamically and cannot be fully typed by Pylance.

    Usage in a connector's run() method::

        command, command_json = self._build_reproducible_commands(
            cmd_prefix=cmd,
            scan_target=target,
            json_output_args=["--jsonfile", "result.json"],
        )
        raw_output: ConnectorRawOutput = {
            "command":      command,
            "command_json": command_json,
            "results":      all_findings,
            "all_count":    len(all_findings),
        }
        return ConnectorResult(..., raw_output=raw_output)

    Failure mode without this contract:
        A connector that omits any of the required keys produces a silently
        broken HTML report.  No exception is raised at runtime because the
        Jinja2 template uses the ``default_dash`` filter, which substitutes
        a dash for missing keys -- the rendered report displays dashes where
        commands and statistics should appear, with no error traceback to
        diagnose the root cause.  The runtime check in _validate_raw_output()
        converts this silent failure into an explicit ERROR TestResult.
    """

    # REQUIRED by the HTML report template
    command: str
    command_json: str
    results: list[dict[str, Any]]

    # REQUIRED for statistics display
    all_count: int


# ---------------------------------------------------------------------------
# BaseLibraryConnector -- Python-library-based tools (tier 2)
# ---------------------------------------------------------------------------


class BaseLibraryConnector(BaseConnector):
    """
    Concrete base class for external tools accessed as Python libraries.

    Provides implementations of is_available() and get_version() based on
    importlib introspection rather than subprocess execution.  Concrete
    subclasses (e.g. SslyzeConnector) declare LIBRARY_MODULE and implement
    run().

    Discovery is performed exclusively via importlib.util.find_spec(): if the
    module is importable, the tool is considered available.  No subprocess
    is launched for availability checking, which makes this significantly
    faster than BaseSubprocessConnector when multiple library-based tests
    share the same tool.

    ClassVar declarations (required on every concrete subclass):

        LIBRARY_MODULE: str
            The top-level Python module name to import.  Must match the
            importable name, which may differ from the PyPI package name.
            Example: "sslyze" (both PyPI name and importable name match).
            Example: "PIL" (PyPI name: "Pillow", importable name: "PIL").

        TOOL_NAME: str (inherited from BaseConnector)
            Human-readable identifier used in log messages and reports.
            Typically matches the PyPI package name.
    """

    LIBRARY_MODULE: ClassVar[str]

    def is_available(self) -> bool:
        """
        Return True if the library module can be found by importlib.

        Uses importlib.util.find_spec() which checks sys.path without
        actually importing the module -- safe and side-effect-free.

        Returns:
            bool: True if the library is importable, False otherwise.
        """
        try:
            spec = importlib.util.find_spec(self.LIBRARY_MODULE)
            available = spec is not None
        except (ModuleNotFoundError, ValueError):
            # find_spec raises ModuleNotFoundError for dotted names with a
            # missing parent, and ValueError for empty string or None.
            available = False

        if available:
            log.debug(
                "connector_library_found",
                module=self.LIBRARY_MODULE,
                tool=self.TOOL_NAME,
            )
        else:
            log.debug(
                "connector_library_not_found",
                module=self.LIBRARY_MODULE,
                tool=self.TOOL_NAME,
            )
        return available

    def get_version(self) -> str | None:
        """
        Return the library __version__ attribute, or None if not available.

        Attempts to import the library and read its __version__ attribute.
        Falls back to importlib.metadata.version() if __version__ is absent.
        Returns None on any import error or missing version information.

        Returns:
            str | None: Version string on success, None on any failure.
        """
        try:
            module = importlib.import_module(self.LIBRARY_MODULE)
            version: str | None = getattr(module, "__version__", None)
            if isinstance(version, str):
                return version
            # Fallback: importlib.metadata (PEP 566 / Python 3.8+).
            # Deferred import: importlib.metadata adds a small startup cost;
            # we avoid paying it for every connector that uses __version__ directly.
            import importlib.metadata as _meta  # noqa: PLC0415

            return _meta.version(self.LIBRARY_MODULE)
        except Exception as exc:  # noqa: BLE001 -- version is best-effort
            log.debug(
                "connector_library_version_unavailable",
                module=self.LIBRARY_MODULE,
                error=str(exc),
            )
            return None

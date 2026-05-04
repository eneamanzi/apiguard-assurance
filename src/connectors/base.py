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
import shutil
import subprocess
from abc import ABC, abstractmethod
from typing import Any, ClassVar

import structlog
from pydantic import BaseModel, Field

from src.core.exceptions import ExternalToolError

log: structlog.BoundLogger = structlog.get_logger(__name__)

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
        **kwargs: Any,  # noqa: ANN401 -- Any is justified at the abstract level:
        # Each concrete subclass declares its own specific keyword parameters.
        # At this abstraction layer it is technically impossible to express a
        # more precise type for **kwargs without coupling BaseConnector to every
        # subclass's signature.  The concrete run() implementations use fully-typed
        # explicit parameters and do not expose Any to callers.
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

        Args:
            target_url:      The base URL of the target API (from
                             TargetContext.effective_endpoint_base_url()).
                             Does not include trailing slash.
            timeout_seconds: Mandatory wall-clock limit for the execution.
                             Sourced from ExternalToolsConfig.<tool>.timeout_seconds.
            **kwargs:        Tool-specific parameters declared explicitly in the
                             concrete subclass's run() signature.

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

    # ------------------------------------------------------------------
    # Discovery -- concrete implementations
    # ------------------------------------------------------------------

    def is_available(self) -> bool:
        """
        Return True if the binary is discoverable via either channel.

        Channel 1 -- local binary in PATH:
            shutil.which(BINARY_NAME) returns the absolute path if found.

        Channel 2 -- service URL via environment variable (Docker Compose):
            os.getenv(SERVICE_ENV_VAR) returns the URL if set.

        Returns False if both channels return None.  This method never raises.

        Returns:
            bool: True if the tool is available via at least one channel.
        """
        binary_path = shutil.which(self.BINARY_NAME)
        if binary_path is not None:
            log.debug(
                "connector_binary_found_in_path",
                binary=self.BINARY_NAME,
                path=binary_path,
            )
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
            env_var=self.SERVICE_ENV_VAR,
        )
        return False

    def get_version(self) -> str | None:
        """
        Attempt to retrieve the tool version string via subprocess.

        Runs the binary with --version and extracts the first non-empty line
        of stdout or stderr.  Returns None if the binary is not available or
        if the version command fails for any reason.

        The version string is embedded in the HTML report and in evidence.json
        for reproducibility -- an analyst can reconstruct exactly which version
        of the tool produced a given finding.

        Returns:
            str | None: Version string on success, None on any failure.
        """
        if shutil.which(self.BINARY_NAME) is None:
            return None
        try:
            result = subprocess.run(  # noqa: S603 -- cmd is [BINARY_NAME, "--version"]:
                # BINARY_NAME is a ClassVar[str] defined in the subclass source
                # code, never derived from user input.  The only additional arg
                # is the static literal "--version".  No untrusted data flows
                # into this call; the S603 warning is a false positive here.
                [self.BINARY_NAME, "--version"],
                capture_output=True,
                text=True,
                timeout=10,
            )
            for line in (result.stdout or result.stderr or "").splitlines():
                stripped = line.strip()
                if stripped:
                    return stripped
        except (subprocess.TimeoutExpired, FileNotFoundError, OSError) as exc:
            log.debug(
                "connector_version_discovery_failed",
                binary=self.BINARY_NAME,
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
            if version is not None:
                return str(version)
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

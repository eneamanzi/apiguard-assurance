"""
src/core/exceptions.py

Custom exception hierarchy for the APIGuard Assurance tool.

All exceptions inherit from ToolBaseError, which serves as the single
catch-all root for any caller that needs to distinguish tool-internal
errors from generic Python exceptions (e.g., ValueError, TypeError).

Pipeline phase mapping (from Implementazione.md, Section 8):
    Phase 1 - Configuration loading    -> ConfigurationError     [BLOCKS STARTUP]
    Phase 2 - OpenAPI discovery        -> OpenAPILoadError       [BLOCKS STARTUP]
    Phase 4 - DAG scheduling           -> DAGCycleError          [BLOCKS STARTUP]
    Phase 5 - Native test execution    -> SecurityClientError    [-> TestResult(ERROR)]
    Phase 5 - External test execution  -> ExternalToolError      [-> TestResult(ERROR)]
    Phase 6 - Resource teardown        -> TeardownError          [WARNING, not propagated]

Design note — tool-not-found does NOT have a dedicated exception:
    A missing external binary is an expected operational condition, not an
    unexpected error.  It is handled via the ExternalTestRegistry Phase R4
    (_inject_connectors): when is_available() returns False, the registry sets
    ExternalToolTest._skip_reason_from_registry on every test in the group, and
    _run() returns TestResult(status=SKIP) immediately.  No exception is raised
    anywhere in this path.  ExternalToolError is reserved for conditions where
    the binary IS present but its execution fails at runtime.
"""

from __future__ import annotations


class ToolBaseError(Exception):
    """
    Root exception for all tool-internal errors.

    Every custom exception in this module inherits from this class.
    This design enables selective catching at different pipeline layers:

        except ConfigurationError:   # catch only config errors
        except ToolBaseError:        # catch any tool error
        except Exception:            # catch everything (forbidden in this codebase)

    The __str__ implementation delegates to the message attribute so that
    structlog can serialize instances directly without extra formatting.
    """

    def __init__(self, message: str) -> None:
        """
        Initialize the base error with a human-readable message.

        Args:
            message: A descriptive error message in English technical prose.
                     Must not contain sensitive data (credentials, tokens).
        """
        super().__init__(message)
        self.message: str = message

    def __str__(self) -> str:
        return self.message

    def __repr__(self) -> str:
        return f"{self.__class__.__name__}(message={self.message!r})"


# ---------------------------------------------------------------------------
# Phase 1 — Configuration loading
# ---------------------------------------------------------------------------


class ConfigurationError(ToolBaseError):
    """
    Raised when config.yaml is invalid or a required environment variable
    is missing during Phase 1 (Configuration Loading).

    This exception is fatal: it blocks pipeline startup before any test
    runs. The rationale is that proceeding with a partial or incorrect
    configuration would produce results without a sound foundation.

    Structured fields allow structlog to emit machine-readable log entries:

        log.error(
            "configuration_failed",
            variable=exc.variable_name,
            detail=exc.message,
        )
    """

    def __init__(
        self,
        message: str,
        variable_name: str | None = None,
        config_path: str | None = None,
    ) -> None:
        """
        Initialize a configuration error.

        Args:
            message: Human-readable description of what is wrong.
            variable_name: The name of the missing or invalid environment
                           variable, if applicable. Must never contain the
                           variable's value (credentials redaction rule).
            config_path: The dotted path within config.yaml that failed
                         validation, e.g. "target.base_url" or "execution.min_priority".
        """
        super().__init__(message)
        self.variable_name: str | None = variable_name
        self.config_path: str | None = config_path

    def __repr__(self) -> str:
        return (
            f"{self.__class__.__name__}("
            f"message={self.message!r}, "
            f"variable_name={self.variable_name!r}, "
            f"config_path={self.config_path!r})"
        )


# ---------------------------------------------------------------------------
# Phase 2 — OpenAPI discovery
# ---------------------------------------------------------------------------


class OpenAPILoadError(ToolBaseError):
    """
    Raised when the OpenAPI specification cannot be fetched, dereferenced,
    or validated during Phase 2 (OpenAPI Discovery).

    This exception is fatal: without a valid and fully dereferenced spec,
    the AttackSurface cannot be built and no test has a reliable target.

    The source_url field is logged without masking because the OpenAPI
    spec URL is not a credential — it is a public or semi-public endpoint.
    The underlying_error field preserves the original exception message
    for diagnostic purposes without exposing stack traces to end users.
    """

    def __init__(
        self,
        message: str,
        source_url: str | None = None,
        underlying_error: str | None = None,
    ) -> None:
        """
        Initialize an OpenAPI load error.

        Args:
            message: Human-readable description of the failure.
            source_url: The URL or filesystem path from which the spec
                        was being fetched when the error occurred.
            underlying_error: String representation of the original
                              exception (e.g., prance.util.url.ResolutionError),
                              used for structured logging only.
        """
        super().__init__(message)
        self.source_url: str | None = source_url
        self.underlying_error: str | None = underlying_error

    def __repr__(self) -> str:
        return (
            f"{self.__class__.__name__}("
            f"message={self.message!r}, "
            f"source_url={self.source_url!r}, "
            f"underlying_error={self.underlying_error!r})"
        )


# ---------------------------------------------------------------------------
# Phase 4 — DAG scheduling
# ---------------------------------------------------------------------------


class DAGCycleError(ToolBaseError):
    """
    Raised when a circular dependency is detected among test depends_on
    declarations during Phase 4 (Test Discovery and Scheduling).

    This exception is fatal: a dependency cycle is a design error in the
    test suite, not a runtime condition. Proceeding with a cyclic graph
    would cause TopologicalSorter to raise CycleError from stdlib graphlib,
    which is not a ToolBaseError and would not be handled correctly upstream.

    The cycle field contains the list of test_id values that form the cycle,
    as reported by graphlib.TopologicalSorter. Example:
        cycle = ["1.4", "2.2", "1.4"]

    This makes the error immediately actionable: the developer knows exactly
    which test declarations to inspect and correct.
    """

    def __init__(
        self,
        message: str,
        cycle: list[str] | None = None,
    ) -> None:
        """
        Initialize a DAG cycle error.

        Args:
            message: Human-readable description of the circular dependency.
            cycle: Ordered list of test_id strings that form the cycle,
                   as extracted from graphlib.TopologicalSorter.
                   May be None if the cycle cannot be precisely identified.
        """
        super().__init__(message)
        self.cycle: list[str] = cycle if cycle is not None else []

    def __repr__(self) -> str:
        return f"{self.__class__.__name__}(message={self.message!r}, cycle={self.cycle!r})"


# ---------------------------------------------------------------------------
# Phase 5 — Test execution
# ---------------------------------------------------------------------------


class SecurityClientError(ToolBaseError):
    """
    Raised by SecurityClient when an HTTP request fails in a non-recoverable
    way during Phase 5 (Test Execution).

    Non-recoverable conditions include: connection refused, DNS resolution
    failure, SSL handshake error, or exhaustion of the retry policy defined
    by tenacity. Transient errors (connection reset, 503) are retried
    transparently by SecurityClient before raising this exception.

    This exception is NEVER propagated to the engine. The contract defined
    in BaseTest.execute() requires that every test catches SecurityClientError
    internally and converts it to TestResult(status=ERROR, message=str(exc)).
    The engine only sees TestResult objects, never raw exceptions.

    The status_code field is None when the failure occurs at the transport
    layer (connection refused, timeout) before any HTTP response is received.
    When the request completed but the response indicates a non-recoverable
    condition (e.g., 502 Bad Gateway after all retries), status_code carries
    the final HTTP status code for structured logging.
    """

    def __init__(
        self,
        message: str,
        method: str | None = None,
        url: str | None = None,
        status_code: int | None = None,
        attempt_count: int = 1,
    ) -> None:
        """
        Initialize a security client error.

        Args:
            message: Human-readable description of the HTTP failure.
            method: HTTP method of the failed request (e.g., "GET", "POST").
            url: Target URL of the failed request. Must not contain
                 credentials embedded in the URL (use headers instead).
            status_code: Final HTTP status code received, or None if the
                         failure occurred at the transport layer.
            attempt_count: Total number of attempts made before giving up,
                           including the initial attempt and all retries.
        """
        super().__init__(message)
        self.method: str | None = method
        self.url: str | None = url
        self.status_code: int | None = status_code
        self.attempt_count: int = attempt_count

    def __repr__(self) -> str:
        return (
            f"{self.__class__.__name__}("
            f"message={self.message!r}, "
            f"method={self.method!r}, "
            f"url={self.url!r}, "
            f"status_code={self.status_code!r}, "
            f"attempt_count={self.attempt_count!r})"
        )


# ---------------------------------------------------------------------------
# Helpers — authentication setup
# ---------------------------------------------------------------------------


class AuthenticationSetupError(ToolBaseError):
    """
    Raised by src/tests/helpers/auth.py when the target API rejects the
    configured credentials during token acquisition.

    This exception is semantically distinct from SecurityClientError:
        - SecurityClientError  -> transport-layer failure (no response received)
        - AuthenticationSetupError -> valid HTTP response received, but the
          credentials were rejected (HTTP 401) or forbidden (HTTP 403).

    When this exception reaches a test's execute() method, the test must
    catch it and return TestResult(status=ERROR) with a message that
    instructs the operator to verify the credentials in config.yaml.

    The role field identifies which role's credentials were rejected,
    enabling the operator to target the fix precisely without exposing
    the credential values themselves.
    """

    def __init__(
        self,
        message: str,
        role: str | None = None,
        status_code: int | None = None,
    ) -> None:
        """
        Initialize an authentication setup error.

        Args:
            message: Human-readable description of the failure.
            role: The role whose credentials were rejected, e.g. 'admin',
                  'user_a'. Never includes the credential value itself.
            status_code: HTTP status code returned by the target (typically
                         401 Unauthorized or 403 Forbidden).
        """
        super().__init__(message)
        self.role: str | None = role
        self.status_code: int | None = status_code

    def __repr__(self) -> str:
        return (
            f"{self.__class__.__name__}("
            f"message={self.message!r}, "
            f"role={self.role!r}, "
            f"status_code={self.status_code!r})"
        )


# ---------------------------------------------------------------------------
# Phase 6 — Resource teardown
# ---------------------------------------------------------------------------


class TeardownError(ToolBaseError):
    """
    Raised when a DELETE request for a test-created resource fails during
    Phase 6 (Teardown).

    This exception is intentionally NOT propagated beyond the teardown loop
    in the engine. A cleanup failure does not invalidate the assessment
    results already collected. The engine catches TeardownError, emits a
    WARNING log entry with the structured fields below, and continues with
    the next resource in the drain queue.

    The resource_path field includes the resource ID so that operators can
    perform manual cleanup if needed. The failed_status_code documents what
    the API returned instead of the expected 204 No Content or 200 OK.
    """

    def __init__(
        self,
        message: str,
        resource_method: str | None = None,
        resource_path: str | None = None,
        failed_status_code: int | None = None,
    ) -> None:
        """
        Initialize a teardown error.

        Args:
            message: Human-readable description of why the cleanup failed.
            resource_method: HTTP method used for the cleanup request
                             (typically "DELETE").
            resource_path: Path of the resource that could not be deleted,
                           including the resource ID (e.g., "/api/v1/users/42").
                           Used for manual cleanup guidance in the log output.
            failed_status_code: HTTP status code received from the DELETE
                                request, or None if a transport error occurred
                                before a response was received.
        """
        super().__init__(message)
        self.resource_method: str | None = resource_method
        self.resource_path: str | None = resource_path
        self.failed_status_code: int | None = failed_status_code

    def __repr__(self) -> str:
        return (
            f"{self.__class__.__name__}("
            f"message={self.message!r}, "
            f"resource_method={self.resource_method!r}, "
            f"resource_path={self.resource_path!r}, "
            f"failed_status_code={self.failed_status_code!r})"
        )


# ---------------------------------------------------------------------------
# External tool integration — connectors/
# ---------------------------------------------------------------------------


class ExternalToolError(ToolBaseError):
    """
    Raised by BaseConnector.run() when the external binary is present but
    its execution fails in a non-recoverable way.

    Non-recoverable conditions include:
        - The subprocess exits with a non-zero code that the connector
          interprets as an unrecoverable failure (as opposed to a tool-specific
          "no findings" code, which varies per tool).
        - The subprocess output cannot be parsed as valid JSON when JSON output
          is expected (e.g., testssl.sh --jsonfile, nuclei -json, ffuf -json).
        - The subprocess.TimeoutExpired exception is raised because the wall-
          clock limit passed as timeout_seconds to run() was exceeded.

    This exception is handled inside ExternalToolTest.execute() and converted
    to TestResult(status=ERROR, message=str(exc)) before the engine sees it.
    The engine never receives ExternalToolError directly — the same pattern
    as SecurityClientError for native tests.

    The timed_out field allows the calling test to produce a semantically
    distinct message: "tool timed out after Ns" vs "tool failed with exit N".
    The raw_stderr field carries the first STDERR_MAX_CHARS characters of
    stderr output stripped of any credential patterns — safe to log and embed
    in the ERROR TestResult message for operator debugging.
    """

    STDERR_MAX_CHARS: int = 512

    def __init__(
        self,
        message: str,
        tool_name: str | None = None,
        exit_code: int | None = None,
        timed_out: bool = False,
        raw_stderr: str | None = None,
    ) -> None:
        """
        Initialize an external tool execution error.

        Args:
            message: Human-readable description of the failure.
            tool_name: The binary name that failed (e.g., "testssl.sh").
            exit_code: The process exit code, or None if the process was
                       terminated before it could exit (timeout).
            timed_out: True if subprocess.TimeoutExpired was raised.
                       When True, exit_code is typically None.
            raw_stderr: First STDERR_MAX_CHARS characters of stderr output,
                        sanitized of credential patterns before storage.
                        Used for operator debugging in ERROR TestResult messages.
        """
        super().__init__(message)
        self.tool_name: str | None = tool_name
        self.exit_code: int | None = exit_code
        self.timed_out: bool = timed_out
        self.raw_stderr: str | None = raw_stderr

    def __repr__(self) -> str:
        return (
            f"{self.__class__.__name__}("
            f"message={self.message!r}, "
            f"tool_name={self.tool_name!r}, "
            f"exit_code={self.exit_code!r}, "
            f"timed_out={self.timed_out!r})"
        )

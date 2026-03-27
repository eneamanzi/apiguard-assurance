"""
src/core/client.py

SecurityClient: centralized HTTP client for all assessment traffic.

Every HTTP request performed during the assessment passes through this class.
No test module, discovery module, or any other src/ module is permitted to
import httpx directly. This single-point-of-entry design enables:

    - Uniform timeout enforcement on every request.
    - Centralized retry logic with exponential backoff (tenacity).
    - Consistent EvidenceRecord construction for every transaction.
    - Guaranteed non-following of HTTP redirects (a redirect is security
      information, not a transport inconvenience to hide from the test).

The client does NOT:
    - Interpret HTTP status codes (the test's responsibility).
    - Add authentication headers (the test's responsibility).
    - Write to EvidenceStore (the test's responsibility, using the returned record).
    - Follow redirects (disabled unconditionally).

Return contract:
    Every successful call to request() returns a tuple:
        (httpx.Response, EvidenceRecord)
    The test uses the Response for its oracle logic and decides independently
    whether to pass the EvidenceRecord to store.add_fail_evidence() or
    store.pin_evidence().

    On non-recoverable transport failure, SecurityClientError is raised.
    The test's execute() method must catch it and return TestResult(ERROR).

Dependency rule: this module imports from stdlib, httpx, tenacity, structlog,
and src.core only. It must never import from tests/, config/, discovery/, or
report/.
"""

from __future__ import annotations

import time
from datetime import UTC, datetime
from types import TracebackType
from typing import Any

import httpx
import structlog
from tenacity import (
    RetryError,
    Retrying,
    retry_if_exception_type,
    stop_after_attempt,
    wait_exponential_jitter,
)

from src.core.exceptions import SecurityClientError
from src.core.models import EvidenceRecord

log: structlog.BoundLogger = structlog.get_logger(__name__)

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

# Default timeout values in seconds, applied to every request unless overridden.
# These defaults satisfy the Garanzia 4.2 oracle:
#   connect_timeout <= 5s, read_timeout <= 30s.
DEFAULT_CONNECT_TIMEOUT_SECONDS: float = 5.0
DEFAULT_READ_TIMEOUT_SECONDS: float = 30.0
DEFAULT_WRITE_TIMEOUT_SECONDS: float = 10.0
DEFAULT_POOL_TIMEOUT_SECONDS: float = 5.0

# Retry policy defaults.
# Retry only on transport-layer errors, never on valid HTTP responses.
# Max 3 attempts = 1 initial + 2 retries.
DEFAULT_MAX_RETRY_ATTEMPTS: int = 3
DEFAULT_RETRY_WAIT_MIN_SECONDS: float = 0.5
DEFAULT_RETRY_WAIT_MAX_SECONDS: float = 8.0
DEFAULT_RETRY_JITTER_SECONDS: float = 1.0

# Maximum length of response body stored in EvidenceRecord, in characters.
# Consistent with the value enforced by EvidenceRecord.truncate_response_body.
RESPONSE_BODY_MAX_CHARS: int = 10_000
RESPONSE_BODY_TRUNCATION_SUFFIX: str = "... [TRUNCATED]"

# HTTP exceptions that are considered transient and worth retrying.
# These are all transport-layer failures — the server never sent a response.
# httpx.HTTPStatusError (4xx, 5xx) is NOT in this tuple: a 503 is a valid
# response that the test must see, not a transient error to hide.
RETRYABLE_EXCEPTIONS: tuple[type[Exception], ...] = (
    httpx.ConnectError,
    httpx.ConnectTimeout,
    httpx.ReadTimeout,
    httpx.WriteTimeout,
    httpx.PoolTimeout,
    httpx.RemoteProtocolError,
)


# ---------------------------------------------------------------------------
# SecurityClient
# ---------------------------------------------------------------------------


class SecurityClient:
    """
    Centralized HTTP client for all assessment HTTP traffic.

    Wraps an httpx.Client with:
        - Configurable timeouts (connect, read, write, pool).
        - Retry logic with exponential backoff and jitter via tenacity.
          Retries only on transport-layer exceptions, never on HTTP responses.
        - Automatic EvidenceRecord construction for every completed transaction.
        - Redirect following disabled unconditionally.

    One SecurityClient instance is created during Phase 3 (Context Construction)
    and shared across all test executions for the entire pipeline run. The client
    is not thread-safe (consistent with the sequential execution model of V1.0).

    The underlying httpx.Client is managed as a context manager. The SecurityClient
    itself exposes __enter__ and __exit__ so that engine.py can use it in a
    'with' block, ensuring the connection pool is properly closed after Phase 6
    regardless of exceptions.

    Usage in engine.py:

        with SecurityClient(connect_timeout=5.0, read_timeout=30.0) as client:
            # Phase 5: pass client to each test.execute()
            result = test.execute(target, context, client, store)
        # httpx connection pool closed here.

    Usage in a BaseTest.execute() implementation:

        response, record = client.request(
            method="GET",
            path="/api/v1/users/me",
            test_id=self.test_id,
            headers={"Authorization": f"Bearer {token}"},
        )
        if response.status_code != 401:
            store.add_fail_evidence(record)
            return TestResult(status=TestStatus.FAIL, ...)
    """

    def __init__(
        self,
        base_url: str,
        connect_timeout: float = DEFAULT_CONNECT_TIMEOUT_SECONDS,
        read_timeout: float = DEFAULT_READ_TIMEOUT_SECONDS,
        write_timeout: float = DEFAULT_WRITE_TIMEOUT_SECONDS,
        pool_timeout: float = DEFAULT_POOL_TIMEOUT_SECONDS,
        max_retry_attempts: int = DEFAULT_MAX_RETRY_ATTEMPTS,
        retry_wait_min: float = DEFAULT_RETRY_WAIT_MIN_SECONDS,
        retry_wait_max: float = DEFAULT_RETRY_WAIT_MAX_SECONDS,
        retry_jitter: float = DEFAULT_RETRY_JITTER_SECONDS,
    ) -> None:
        """
        Initialize the SecurityClient with timeout and retry configuration.

        The httpx.Client is NOT created here: it is created in __enter__ so
        that the client can only be used as a context manager, making improper
        usage (forgetting to close the connection pool) a runtime error rather
        than a silent resource leak.

        Args:
            base_url: The base URL prepended to every request path.
                      Typically target.endpoint_base_url() from TargetContext.
                      Must not end with a trailing slash.
            connect_timeout: Seconds to wait for TCP connection establishment.
            read_timeout: Seconds to wait for the server to send a response byte.
            write_timeout: Seconds to wait for the server to accept a request byte.
            pool_timeout: Seconds to wait to acquire a connection from the pool.
            max_retry_attempts: Total number of attempts (initial + retries).
                                Minimum 1 (no retry). Maximum recommended: 5.
            retry_wait_min: Minimum wait in seconds between retry attempts.
            retry_wait_max: Maximum wait in seconds between retry attempts.
            retry_jitter: Random jitter in seconds added to each wait interval.
                          Jitter prevents thundering herd in concurrent scenarios.
        """
        self._base_url: str = base_url.rstrip("/")
        self._timeout: httpx.Timeout = httpx.Timeout(
            connect=connect_timeout,
            read=read_timeout,
            write=write_timeout,
            pool=pool_timeout,
        )
        self._max_retry_attempts: int = max(1, max_retry_attempts)
        self._retry_wait_min: float = retry_wait_min
        self._retry_wait_max: float = retry_wait_max
        self._retry_jitter: float = retry_jitter

        # Sequence counter per test_id, used to generate unique record IDs.
        # Format: {test_id}_{counter:03d} -> "1.2_001", "1.2_002", ...
        # Reset to {} at each pipeline run (client is constructed per run).
        self._sequence_counters: dict[str, int] = {}

        # httpx.Client is None until __enter__ is called.
        self._http_client: httpx.Client | None = None

        log.debug(
            "security_client_initialized",
            base_url=self._base_url,
            connect_timeout=connect_timeout,
            read_timeout=read_timeout,
            max_retry_attempts=self._max_retry_attempts,
        )

    # ------------------------------------------------------------------
    # Context manager
    # ------------------------------------------------------------------

    def __enter__(self) -> SecurityClient:
        """
        Open the underlying httpx.Client and return self.

        redirect following is disabled via follow_redirects=False.
        This is unconditional: a redirect from the server is security-relevant
        information that the test must observe, not a transport detail to hide.

        The verify=True default enforces TLS certificate validation.
        In a lab environment with self-signed certificates, this can be
        overridden by subclassing or by passing verify=False to httpx directly,
        but that override must be explicit and documented.
        """
        self._http_client = httpx.Client(
            base_url=self._base_url,
            timeout=self._timeout,
            follow_redirects=False,
            verify=True,
        )
        log.debug("security_client_http_session_opened", base_url=self._base_url)
        return self

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc_val: BaseException | None,
        exc_tb: TracebackType | None,
    ) -> None:
        """
        Close the underlying httpx.Client and release the connection pool.

        Called by the engine's 'with' block after Phase 6 (Teardown) completes,
        or immediately if an unhandled exception propagates out of the block.
        Does not suppress exceptions (returns None, which is falsy).
        """
        if self._http_client is not None:
            self._http_client.close()
            self._http_client = None
            log.debug("security_client_http_session_closed")

    # ------------------------------------------------------------------
    # Public request interface
    # ------------------------------------------------------------------

    def request(
        self,
        method: str,
        path: str,
        test_id: str,
        headers: dict[str, str] | None = None,
        json: object | None = None,
        content: bytes | None = None,
        params: dict[str, Any] | None = None,
    ) -> tuple[httpx.Response, EvidenceRecord]:
        """
        Perform an HTTP request and return the response with an evidence record.

        This is the single method that all test implementations call for every
        HTTP transaction. It enforces the full retry policy, constructs the
        EvidenceRecord, and raises SecurityClientError on non-recoverable failure.

        The caller (the test) is responsible for:
            - Deciding whether to pass the record to store.add_fail_evidence()
              or store.pin_evidence() based on the response status.
            - Never calling both methods on the same record (contract documented
              in BaseTest to prevent duplicate entries in EvidenceStore).

        Redirect behavior: if the server responds with 3xx, the response is
        returned as-is with the 3xx status code. The test observes the redirect
        and can record it as evidence if relevant to the security guarantee
        under test (e.g., Test 1.5 verifies that HTTP redirects to HTTPS).

        Args:
            method: HTTP method, case-insensitive. Normalized to uppercase.
            path: API path relative to base_url. Must start with "/".
                  Example: "/api/v1/users/me".
            test_id: The test_id of the calling test (e.g., "1.2").
                     Used to generate the EvidenceRecord.record_id.
            headers: Optional request headers. If an Authorization header is
                     present, its value appears as "[REDACTED]" in the
                     EvidenceRecord (enforced by EvidenceRecord's validator).
            json: Optional request body, serialized to JSON by httpx.
                  Mutually exclusive with content.
            content: Optional raw request body as bytes.
                     Mutually exclusive with json.
            params: Optional query string parameters.

        Returns:
            Tuple of (httpx.Response, EvidenceRecord).
            The EvidenceRecord captures the full transaction including the
            redacted Authorization header and the truncated response body.

        Raises:
            SecurityClientError: If the request fails after all retry attempts
                due to a transport-layer error (connection refused, timeout,
                protocol error). NOT raised for 4xx or 5xx HTTP responses —
                those are valid responses returned normally.
            RuntimeError: If called outside of a 'with' block (i.e., before
                __enter__ or after __exit__). This is a programming error in
                the caller, not a security assessment error.
        """
        if self._http_client is None:
            raise RuntimeError(
                "SecurityClient.request() called outside of a 'with' block. "
                "The HTTP session is not open. Use 'with SecurityClient(...) as client'."
            )

        method_upper = method.strip().upper()
        if not path.startswith("/"):
            raise ValueError(
                f"Request path must start with '/'. Got: '{path}'. "
                "Provide an absolute path relative to base_url."
            )

        record_id = self._next_record_id(test_id)
        timestamp = datetime.now(UTC)

        bound_log = log.bind(
            test_id=test_id,
            record_id=record_id,
            method=method_upper,
            path=path,
        )
        bound_log.debug("security_client_request_starting")

        # Measure wall-clock time for the entire attempt sequence,
        # including retry waits. Used only for diagnostic logging.
        wall_start = time.monotonic()

        response, attempt_count = self._execute_with_retry(
            method=method_upper,
            path=path,
            headers=headers or {},
            json=json,
            content=content,
            params=params,
            bound_log=bound_log,
        )

        wall_elapsed_ms = (time.monotonic() - wall_start) * 1000.0

        bound_log.debug(
            "security_client_request_completed",
            status_code=response.status_code,
            attempt_count=attempt_count,
            elapsed_ms=round(wall_elapsed_ms, 2),
        )

        record = self._build_evidence_record(
            record_id=record_id,
            timestamp=timestamp,
            method=method_upper,
            path=path,
            request_headers=headers or {},
            request_json=json,
            response=response,
        )

        return response, record

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _next_record_id(self, test_id: str) -> str:
        """
        Generate the next sequential record ID for the given test_id.

        Format: '{test_id}_{counter:03d}', e.g. '1.2_001', '1.2_002'.
        The counter is per-test_id and increments monotonically within
        a pipeline run. This ensures that record IDs are unique across
        the entire evidence store without requiring a global UUID generator.

        Args:
            test_id: The test ID of the calling test.

        Returns:
            A string record ID unique within this pipeline run.
        """
        current = self._sequence_counters.get(test_id, 0) + 1
        self._sequence_counters[test_id] = current
        return f"{test_id}_{current:03d}"

    def _execute_with_retry(
        self,
        method: str,
        path: str,
        headers: dict[str, str],
        json: object | None,
        content: bytes | None,
        params: dict[str, Any] | None,
        bound_log: structlog.BoundLogger,
    ) -> tuple[httpx.Response, int]:
        """
        Execute the HTTP request with tenacity retry on transient errors.

        Retry policy:
            - Condition: only on RETRYABLE_EXCEPTIONS (transport errors).
              httpx.HTTPStatusError is NOT retried: 4xx and 5xx responses
              are valid and must reach the test unchanged.
            - Wait: exponential backoff with jitter.
              Formula: min(wait_max, wait_min * 2^(attempt-1)) + random(0, jitter)
            - Stop: after max_retry_attempts total attempts.

        The attempt_count returned is used for diagnostic logging and for
        populating SecurityClientError.attempt_count if all retries fail.

        Args:
            method: Uppercase HTTP method.
            path: Absolute path relative to base_url.
            headers: Request headers (may be empty dict).
            json: Optional JSON body.
            content: Optional raw body bytes.
            params: Optional query parameters.
            bound_log: Logger with test_id and record_id already bound.

        Returns:
            Tuple of (httpx.Response, int) where int is the attempt count.

        Raises:
            SecurityClientError: After all retry attempts are exhausted.
        """
        assert self._http_client is not None  # Guarded by request() before call.

        attempt_count: int = 0

        try:
            for attempt in Retrying(
                retry=retry_if_exception_type(RETRYABLE_EXCEPTIONS),
                stop=stop_after_attempt(self._max_retry_attempts),
                wait=wait_exponential_jitter(
                    initial=self._retry_wait_min,
                    max=self._retry_wait_max,
                    jitter=self._retry_jitter,
                ),
                reraise=False,
            ):
                with attempt:
                    attempt_count += 1
                    if attempt_count > 1:
                        bound_log.warning(
                            "security_client_retrying_request",
                            attempt_number=attempt_count,
                            max_attempts=self._max_retry_attempts,
                        )

                    response = self._http_client.request(
                        method=method,
                        url=path,
                        headers=headers,
                        json=json,
                        content=content,
                        params=params,
                    )
                    # httpx does not raise on 4xx/5xx by default.
                    # We do NOT call response.raise_for_status() here:
                    # error status codes are valid responses for security tests.
                    return response, attempt_count

        except RetryError as retry_exc:
            # All attempts exhausted. Extract the last underlying exception
            # for structured error reporting.
            last_exc = retry_exc.last_attempt.exception()
            last_exc_str = str(last_exc) if last_exc else "unknown transport error"

            bound_log.error(
                "security_client_all_retries_exhausted",
                attempt_count=attempt_count,
                max_attempts=self._max_retry_attempts,
                last_exception=last_exc_str,
            )

            raise SecurityClientError(
                message=(
                    f"HTTP {method} {path} failed after {attempt_count} attempt(s). "
                    f"Last error: {last_exc_str}"
                ),
                method=method,
                url=f"{self._base_url}{path}",
                status_code=None,
                attempt_count=attempt_count,
            ) from retry_exc

        # Unreachable: Retrying either returns or raises RetryError.
        # The type checker requires an explicit raise to satisfy the return type.
        raise SecurityClientError(
            message=f"HTTP {method} {path} failed: unexpected retry loop exit.",
            method=method,
            url=f"{self._base_url}{path}",
        )

    def _build_evidence_record(
        self,
        record_id: str,
        timestamp: datetime,
        method: str,
        path: str,
        request_headers: dict[str, str],
        request_json: object | None,
        response: httpx.Response,
    ) -> EvidenceRecord:
        """
        Construct an EvidenceRecord from a completed HTTP transaction.

        The Authorization header is redacted by EvidenceRecord's field_validator,
        not here. This separation of concerns means that even if a future caller
        bypasses _build_evidence_record and constructs a record directly,
        the redaction is still enforced at the model level.

        The response body is read as text. If the response content is binary
        (e.g., a PDF or image), the decode will use the response's declared
        charset with 'replace' error handling to avoid UnicodeDecodeError.
        Truncation to RESPONSE_BODY_MAX_CHARS is enforced by EvidenceRecord's
        field_validator.

        The request body is reconstructed from the json argument as a string.
        Raw bytes bodies (content parameter) are not included in the record
        to avoid base64-encoding binary payloads into evidence.json.

        Args:
            record_id: Pre-generated unique ID for this record.
            timestamp: UTC timestamp of when the request was dispatched.
            method: Uppercase HTTP method.
            path: Absolute API path.
            request_headers: Headers sent with the request (pre-redaction).
            request_json: JSON body sent, or None.
            response: The httpx.Response object from the completed request.

        Returns:
            A fully populated EvidenceRecord instance.
        """
        import json as json_stdlib

        # Reconstruct request body string for the record.
        request_body_str: str | None = None
        if request_json is not None:
            try:
                request_body_str = json_stdlib.dumps(request_json, ensure_ascii=False)
            except (TypeError, ValueError):
                request_body_str = str(request_json)

        # Read response body as text, replacing undecodable bytes.
        try:
            response_body_str: str | None = response.text
        except Exception:
            response_body_str = "[Binary or undecodable response body]"

        # Normalize response headers to lowercase string dict.
        response_headers_normalized: dict[str, str] = {
            key.lower(): str(value) for key, value in response.headers.items()
        }

        full_url = f"{self._base_url}{path}"

        return EvidenceRecord(
            record_id=record_id,
            timestamp_utc=timestamp,
            request_method=method,
            request_url=full_url,
            request_headers=dict(request_headers),
            request_body=request_body_str,
            response_status_code=response.status_code,
            response_headers=response_headers_normalized,
            response_body=response_body_str,
            is_pinned=False,
        )

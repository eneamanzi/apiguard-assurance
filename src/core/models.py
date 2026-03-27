"""
src/core/models.py

Shared Pydantic v2 data models for the APIGuard Assurance tool.

These models constitute the shared vocabulary of the entire tool.
Every module that produces or consumes structured data imports from here.
No module outside this file defines competing data structures.

Dependency rule: this module imports only from pydantic and the stdlib.
It must never import from any other src/ module to avoid circular dependencies.

Model hierarchy:
    TestStatus          -- Enum: possible outcomes of a single test execution
    TestStrategy        -- Enum: execution privilege level (Black/Grey/White Box)
    EvidenceRecord      -- Immutable snapshot of a single HTTP transaction
    Finding             -- Unit of technical evidence produced by a FAIL result
    TestResult          -- Complete outcome of a single BaseTest.execute() call
    ResultSet           -- Ordered collection of all TestResult for a pipeline run
"""

from __future__ import annotations

from datetime import UTC, datetime
from enum import StrEnum
from typing import Any

from pydantic import BaseModel, Field, field_validator, model_validator

# ---------------------------------------------------------------------------
# Enumerations
# ---------------------------------------------------------------------------


class TestStatus(StrEnum):
    """
    Possible outcomes of a single test execution.

    Inherits from str so that values serialize natively to JSON strings
    without a custom encoder. Pydantic v2 handles str enums transparently
    in model serialization (model.model_dump(), model.model_dump_json()).

    Semantic contract (from Implementazione.md, Section 4.6):
        PASS  -- The control was executed and the security guarantee is satisfied.
        FAIL  -- The control was executed and the guarantee is NOT satisfied.
                 Must be accompanied by at least one Finding.
        SKIP  -- The control was not executed for an explicit, documented reason.
                 Not a failure. Caused by missing prerequisites or inapplicable
                 conditions (e.g., Admin API not configured for WHITE_BOX tests).
        ERROR -- The test encountered an unexpected exception. The result is
                 uncertain and requires manual investigation.

    The distinction between SKIP and ERROR is semantically strict:
        SKIP  -> expected condition (tool external, prerequisite not met)
        ERROR -> unexpected condition (bug in test or infrastructure issue)
    """

    PASS = "PASS"  # noqa: S105
    FAIL = "FAIL"
    SKIP = "SKIP"
    ERROR = "ERROR"


class TestStrategy(StrEnum):
    """
    Execution privilege level for a test, mapping to the Black/Grey/White Box
    gradient defined in the methodology (3_TOP_metodologia.md).

    BLACK_BOX  -- Zero credentials. Simulates an anonymous external attacker.
                  Corresponds to P0 tests (perimeter controls).
    GREY_BOX   -- Valid JWT tokens for at least two distinct roles.
                  Corresponds to P1/P2 tests (authenticated logic).
    WHITE_BOX  -- Read access to Gateway configuration via Admin API or
                  config files. Corresponds to P3 tests (configuration audit).
    """

    BLACK_BOX = "BLACK_BOX"
    GREY_BOX = "GREY_BOX"
    WHITE_BOX = "WHITE_BOX"


# ---------------------------------------------------------------------------
# HTTP Evidence
# ---------------------------------------------------------------------------


class EvidenceRecord(BaseModel):
    """
    Immutable snapshot of a single HTTP transaction (request + response).

    EvidenceRecord instances are stored in EvidenceStore (a deque with
    maxlen=100). They are never embedded directly in Finding or TestResult:
    the link is maintained via the evidence_ref string ID, which allows the
    ResultSet and the EvidenceStore to be serialized independently.

    The frozen configuration prevents accidental mutation after the record
    is created by SecurityClient. Once an HTTP transaction is captured,
    its evidence must not change.

    All header dictionaries use lowercase keys per RFC 9110, which specifies
    that HTTP field names are case-insensitive. Normalizing to lowercase
    enables deterministic access without case-sensitive key lookups.
    """

    model_config = {"frozen": True}

    record_id: str = Field(
        description="Unique identifier for this evidence record. "
        "Format: '{test_id}_{sequence_number}', e.g. '1.2_001'. "
        "Referenced by Finding.evidence_ref."
    )
    timestamp_utc: datetime = Field(
        description="UTC timestamp of when the HTTP request was dispatched. "
        "Always stored in UTC to avoid timezone ambiguity in reports."
    )
    request_method: str = Field(
        description="HTTP method of the request, uppercase (e.g., 'GET', 'POST')."
    )
    request_url: str = Field(
        description="Full URL of the request including query string. "
        "Must not contain credentials embedded in the URL."
    )
    request_headers: dict[str, str] = Field(
        default_factory=dict,
        description="Request headers with lowercase keys per RFC 9110. "
        "Authorization header values are ALWAYS redacted to '[REDACTED]' "
        "before storage. No credential must appear in evidence files.",
    )
    request_body: str | None = Field(
        default=None,
        description="Request body as a string. JSON bodies are stored as-is. "
        "Binary bodies are base64-encoded. None for bodyless requests.",
    )
    response_status_code: int = Field(description="HTTP status code received from the server.")
    response_headers: dict[str, str] = Field(
        default_factory=dict, description="Response headers with lowercase keys per RFC 9110."
    )
    response_body: str | None = Field(
        default=None,
        description="Response body as a string, truncated to 10000 characters "
        "to prevent evidence.json from growing unbounded on large responses.",
    )
    is_pinned: bool = Field(
        default=False,
        description="If True, this record was explicitly marked as key evidence "
        "by the test, even if it did not produce a FAIL outcome. "
        "Pinned records are retained in EvidenceStore regardless of "
        "whether subsequent records would evict older ones.",
    )

    @field_validator("request_method")
    @classmethod
    def method_must_be_uppercase(cls, value: str) -> str:
        """Normalize HTTP method to uppercase for consistency."""
        return value.upper()

    @field_validator("request_headers", "response_headers", mode="before")
    @classmethod
    def headers_must_be_lowercase(cls, value: Any) -> dict[str, str]:  # noqa: ANN401
        """
        Normalize all header keys to lowercase per RFC 9110.

        This validator also enforces credential redaction: any header
        whose key is 'authorization' has its value replaced with '[REDACTED]'
        before the record is stored. This applies regardless of whether the
        caller remembered to redact it.
        """
        if not isinstance(value, dict):
            return {}
        normalized: dict[str, str] = {}
        for key, val in value.items():
            lower_key = key.lower()
            if lower_key == "authorization":
                normalized[lower_key] = "[REDACTED]"
            else:
                normalized[lower_key] = str(val)
        return normalized

    @field_validator("response_body", mode="before")
    @classmethod
    def truncate_response_body(cls, value: Any) -> str | None:  # noqa: ANN401
        """
        Truncate response body to prevent unbounded evidence.json growth.

        Large responses (e.g., full HTML pages, binary blobs mistakenly
        returned as text) are truncated at 10000 characters. A sentinel
        suffix is appended so that analysts know truncation occurred.
        """
        max_length = 10_000
        truncation_suffix = "... [TRUNCATED]"

        if value is None:
            return None
        as_string = str(value)
        if len(as_string) > max_length:
            return as_string[:max_length] + truncation_suffix
        return as_string


# ---------------------------------------------------------------------------
# Finding — unit of technical evidence
# ---------------------------------------------------------------------------


class Finding(BaseModel):
    """
    A single unit of technical evidence produced when a test detects a
    violation of a security guarantee.

    A Finding is deliberately free of severity judgment. The tool's scope
    is to provide objective technical evidence: what was attempted, what was
    observed, which standard is violated. Severity assessment is delegated
    to the human analyst or to external risk-scoring systems that consume
    evidence.json (e.g., CVSS calculators, ML-based classifiers).

    One TestResult(status=FAIL) must contain at least one Finding.
    One TestResult may contain multiple Findings if the test detected
    violations on distinct endpoints or under distinct conditions.

    The references field uses a flat list of strings rather than separate
    cwe_id, owasp_id, rfc_id fields. This design is intentional:
        - A finding may reference zero, one, or multiple standards.
        - The format is free-form enough to include new reference types
          (e.g., "NIST-SP-800-204") without schema changes.
        - External systems can parse the list with simple prefix matching.
    """

    title: str = Field(
        description="Short, human-readable description of the violated guarantee. "
        "Should complete the sentence: 'The API failed to...' "
        "Example: 'Accept unsigned JWT tokens (alg:none attack)'."
    )
    detail: str = Field(
        description="Technical description of the observed evidence. "
        "Must be specific enough for an analyst to reproduce the finding "
        "without access to the tool's source code. "
        "Example: 'Endpoint POST /api/v1/users/tokens returned HTTP 200 "
        "when presented with a JWT bearing alg=none and an empty signature. "
        "Expected response: HTTP 401 Unauthorized.'"
    )
    references: list[str] = Field(
        default_factory=list,
        description="List of standard references applicable to this finding. "
        "Format: '{STANDARD}-{IDENTIFIER}', e.g. 'CWE-287', "
        "'OWASP-API2:2023', 'RFC-8725'. "
        "May be empty if no standard directly applies.",
    )
    evidence_ref: str | None = Field(
        default=None,
        description="ID of the EvidenceRecord in EvidenceStore that demonstrates "
        "this finding. Format matches EvidenceRecord.record_id. "
        "May be None for findings derived from configuration audit "
        "(WHITE_BOX tests) where no HTTP transaction is produced.",
    )

    @field_validator("title", "detail")
    @classmethod
    def must_not_be_empty(cls, value: str) -> str:
        """Reject empty strings for mandatory narrative fields."""
        stripped = value.strip()
        if not stripped:
            raise ValueError("Field must not be empty or whitespace-only.")
        return stripped


# ---------------------------------------------------------------------------
# TestResult — complete outcome of one test execution
# ---------------------------------------------------------------------------


class TestResult(BaseModel):
    """
    Complete outcome of a single BaseTest.execute() call.

    TestResult is the only object that BaseTest.execute() is allowed to return.
    It is also the only object that the engine sees: raw exceptions from tests
    are caught internally by each test and converted to TestResult(status=ERROR).

    Invariants enforced by model_validator:
        - A FAIL result must contain at least one Finding.
        - A PASS result must have an empty findings list.
        - SKIP and ERROR results may have findings (e.g., ERROR can carry a
          Finding that documents what was attempted before the exception).

    The skip_reason field is populated only when status=SKIP and provides
    a human-readable explanation for the report. This is semantically distinct
    from the message field, which is always present and describes the overall
    outcome in one line.
    """

    test_id: str = Field(
        description="Unique test identifier matching BaseTest.test_id, "
        "e.g. '1.2'. Used to correlate results with the methodology."
    )
    status: TestStatus = Field(
        description="Outcome of the test execution. See TestStatus for semantics."
    )
    message: str = Field(
        description="One-line summary of the test outcome. Always present. "
        "For PASS: describes what was verified. "
        "For FAIL: describes the violated guarantee. "
        "For SKIP: duplicates skip_reason for convenience. "
        "For ERROR: describes the unexpected exception in non-technical terms."
    )
    findings: list[Finding] = Field(
        default_factory=list,
        description="List of technical evidence units. Non-empty only for FAIL "
        "results (mandatory) and optionally for ERROR results.",
    )
    skip_reason: str | None = Field(
        default=None,
        description="Human-readable explanation of why the test was skipped. "
        "Populated only when status=SKIP. "
        "Examples: 'Admin API not configured (WHITE_BOX test requires "
        "target.admin_api_url in config.yaml)', "
        "'Prerequisite test 1.1 did not produce a valid token'.",
    )
    duration_ms: float | None = Field(
        default=None,
        description="Wall-clock execution time in milliseconds, measured by the "
        "engine from the start to the end of BaseTest.execute(). "
        "None if the measurement was not available (e.g., early ERROR).",
    )

    @model_validator(mode="after")
    def validate_status_finding_consistency(self) -> TestResult:
        """
        Enforce the invariant between status and findings list.

        Rules:
            FAIL  -> findings must be non-empty (evidence is mandatory)
            PASS  -> findings must be empty (no violation, no evidence)
            SKIP  -> findings must be empty, skip_reason must be present
            ERROR -> findings may be empty or non-empty
        """
        if self.status == TestStatus.FAIL and not self.findings:
            raise ValueError(
                "A TestResult with status=FAIL must contain at least one Finding. "
                "A FAIL without evidence is not a valid assessment outcome."
            )
        if self.status == TestStatus.PASS and self.findings:
            raise ValueError(
                "A TestResult with status=PASS must have an empty findings list. "
                f"Found {len(self.findings)} finding(s). "
                "If a violation was detected, use status=FAIL instead."
            )
        if self.status == TestStatus.SKIP and not self.skip_reason:
            raise ValueError(
                "A TestResult with status=SKIP must provide a skip_reason. "
                "SKIP without explanation is indistinguishable from a silent failure."
            )
        return self


# ---------------------------------------------------------------------------
# ResultSet — ordered collection of all TestResult for one pipeline run
# ---------------------------------------------------------------------------


class ResultSet(BaseModel):
    """
    Ordered collection of all TestResult objects produced during a pipeline run.

    ResultSet is the primary input to report/builder.py and the source of
    truth for exit code calculation. It is constructed incrementally by the
    engine during Phase 5 and sealed before Phase 7.

    The started_at and completed_at fields bracket the entire assessment
    duration, from the moment the first test begins to the moment the last
    test (or teardown) completes. These timestamps appear in the HTML report
    and in evidence.json for audit traceability.

    Exit code logic (from the revised Section 7 of Implementazione.md):
        0  -> all results are PASS or SKIP
        1  -> at least one FAIL (FAIL takes precedence over ERROR)
        2  -> at least one ERROR, no FAIL
        10 -> infrastructure error (handled upstream, not in ResultSet)
    """

    results: list[TestResult] = Field(
        default_factory=list,
        description="Ordered list of TestResult, one per executed test. "
        "Order matches the topological execution order from DAGScheduler.",
    )
    started_at: datetime = Field(
        default_factory=lambda: datetime.now(UTC),
        description="UTC timestamp of when the first test execution began.",
    )
    completed_at: datetime | None = Field(
        default=None,
        description="UTC timestamp of when the last test (or teardown) completed. "
        "None until the pipeline finishes Phase 6.",
    )

    def add_result(self, result: TestResult) -> None:
        """
        Append a TestResult to the collection.

        Called by the engine after each BaseTest.execute() returns.
        The append is O(1) on a list; no sorting or deduplication occurs here.

        Args:
            result: The TestResult returned by a test. Must not be None.
        """
        self.results.append(result)

    def compute_exit_code(self) -> int:
        """
        Compute the process exit code from the current state of the ResultSet.

        Exit code semantics (revised Section 7, Implementazione.md):
            0  -> all PASS/SKIP, no violations detected
            1  -> at least one FAIL, vulnerability demonstrated with evidence
            2  -> at least one ERROR (no FAIL), verification incomplete
            10 -> infrastructure error (never returned from here)

        FAIL takes precedence over ERROR: a mixed FAIL+ERROR run returns 1,
        because the demonstrated violation is the primary signal for CI gates.

        Returns:
            int: Exit code in {0, 1, 2}.
        """
        exit_code_clean = 0
        exit_code_error = 2
        exit_code_fail = 1

        has_fail = any(r.status == TestStatus.FAIL for r in self.results)
        has_error = any(r.status == TestStatus.ERROR for r in self.results)

        if has_fail:
            return exit_code_fail
        if has_error:
            return exit_code_error
        return exit_code_clean

    @property
    def total_count(self) -> int:
        """Total number of test results in the set."""
        return len(self.results)

    @property
    def pass_count(self) -> int:
        """Number of PASS results."""
        return sum(1 for r in self.results if r.status == TestStatus.PASS)

    @property
    def fail_count(self) -> int:
        """Number of FAIL results."""
        return sum(1 for r in self.results if r.status == TestStatus.FAIL)

    @property
    def skip_count(self) -> int:
        """Number of SKIP results."""
        return sum(1 for r in self.results if r.status == TestStatus.SKIP)

    @property
    def error_count(self) -> int:
        """Number of ERROR results."""
        return sum(1 for r in self.results if r.status == TestStatus.ERROR)

    @property
    def total_finding_count(self) -> int:
        """
        Total number of Finding objects across all FAIL results.

        A single test can produce multiple findings (e.g., BOLA detected on
        two distinct endpoints). This count reflects the total evidence volume,
        not the number of violated guarantees.
        """
        return sum(len(r.findings) for r in self.results)

    @property
    def duration_seconds(self) -> float | None:
        """
        Total assessment duration in seconds.

        Returns None if completed_at has not been set (pipeline still running).
        """
        if self.completed_at is None:
            return None
        delta = self.completed_at - self.started_at
        return delta.total_seconds()


# ---------------------------------------------------------------------------
# Attack Surface — OpenAPI-derived map of the target's exposed endpoints
# ---------------------------------------------------------------------------
# discovery/surface.py imports AttackSurface and EndpointRecord from here
# to populate the surface from the dereferenced OpenAPI spec.
# TargetContext in context.py imports AttackSurface to type attack_surface.
# ---------------------------------------------------------------------------


class ParameterInfo(BaseModel):
    """
    Descriptor for a single declared parameter of an API operation.

    Populated from the OpenAPI spec 'parameters' array for each operation.
    Used by Test 3.1 (Input Validation) to generate boundary-value and
    type-confusion payloads appropriate for each field's declared type.

    The schema_type field uses the OpenAPI primitive type vocabulary:
    'string', 'integer', 'number', 'boolean', 'array', 'object'.
    A value of None indicates that the spec declared the parameter without
    a type (valid in OpenAPI 3.x, treated as 'any' by the test).
    """

    model_config = {"frozen": True}

    name: str = Field(description="Parameter name as declared in the OpenAPI spec.")
    location: str = Field(
        description=(
            "Parameter location per OpenAPI 3.x: 'path', 'query', 'header', "
            "or 'cookie'. Stored lowercase for consistent access."
        )
    )
    required: bool = Field(
        default=False,
        description=(
            "True if the parameter is declared required in the OpenAPI spec. "
            "Path parameters are always required per OpenAPI 3.x specification."
        ),
    )
    schema_type: str | None = Field(
        default=None,
        description=(
            "OpenAPI primitive type of the parameter: 'string', 'integer', "
            "'number', 'boolean', 'array', or 'object'. "
            "None if the spec does not declare a type."
        ),
    )
    schema_format: str | None = Field(
        default=None,
        description=(
            "OpenAPI format qualifier, e.g. 'int32', 'int64', 'float', "
            "'date', 'date-time', 'uuid', 'email'. "
            "Used by Test 3.1 to generate format-specific invalid payloads."
        ),
    )


class EndpointRecord(BaseModel):
    """
    Structured descriptor for a single HTTP operation (path + method pair).

    One EndpointRecord corresponds to one operation object in the OpenAPI spec
    (e.g., GET /api/v1/repos/{owner}/{repo}).

    Tests query the AttackSurface for records matching specific criteria
    (authenticated endpoints, deprecated operations, endpoints accepting
    a specific parameter location) using AttackSurface's filter methods.

    The requires_auth field is derived from the OpenAPI security declarations:
    True if the operation or the global spec declares at least one non-empty
    security requirement. This is a declaration, not a verified fact — the
    actual enforcement is what the authentication tests verify empirically.
    """

    model_config = {"frozen": True}

    path: str = Field(
        description=(
            "API path as declared in the OpenAPI spec, with template parameters. "
            "Example: '/api/v1/repos/{owner}/{repo}'. "
            "Always starts with '/'."
        )
    )
    method: str = Field(
        description=(
            "HTTP method, uppercase. One of: GET, POST, PUT, PATCH, DELETE, "
            "HEAD, OPTIONS. One EndpointRecord per (path, method) pair."
        )
    )
    operation_id: str | None = Field(
        default=None,
        description=(
            "OpenAPI operationId, if declared. Used for human-readable "
            "identification in log output and the HTML report."
        ),
    )
    tags: list[str] = Field(
        default_factory=list,
        description=(
            "OpenAPI tags for this operation. Used for domain-level filtering "
            "in tests that target specific functional areas."
        ),
    )
    requires_auth: bool = Field(
        default=True,
        description=(
            "True if the OpenAPI spec declares at least one non-empty security "
            "requirement for this operation. False only for operations with an "
            "explicit empty security array (public endpoints). "
            "Default True: if in doubt, treat the endpoint as protected."
        ),
    )
    is_deprecated: bool = Field(
        default=False,
        description=(
            "True if the OpenAPI spec marks this operation as deprecated: true. "
            "Test 0.3 queries deprecated endpoints to verify sunset enforcement."
        ),
    )
    parameters: list[ParameterInfo] = Field(
        default_factory=list,
        description=(
            "Declared parameters for this operation (path, query, header, cookie). "
            "Does not include request body fields. "
            "Used by Test 3.1 to generate targeted invalid input payloads."
        ),
    )
    request_body_required: bool = Field(
        default=False,
        description=(
            "True if the operation declares a required request body. "
            "Used by Test 3.1 to verify that missing bodies are rejected with 400."
        ),
    )
    request_body_content_types: list[str] = Field(
        default_factory=list,
        description=(
            "List of declared request body media types, e.g. ['application/json']. "
            "Used by Test 3.1 and Test 6.3 to verify content-type enforcement."
        ),
    )

    @field_validator("method")
    @classmethod
    def method_must_be_uppercase(cls, value: str) -> str:
        """Normalize HTTP method to uppercase for consistent access."""
        return value.strip().upper()

    @field_validator("path")
    @classmethod
    def path_must_start_with_slash(cls, value: str) -> str:
        """Enforce absolute path format consistent with SecurityClient contract."""
        stripped = value.strip()
        if not stripped.startswith("/"):
            raise ValueError(f"EndpointRecord path must start with '/'. Got: '{stripped}'.")
        return stripped

    @field_validator("location", mode="before", check_fields=False)
    @classmethod
    def location_placeholder(cls, value: object) -> object:
        """Passthrough — location validation is on ParameterInfo, not here."""
        return value


class AttackSurface(BaseModel):
    """
    Structured map of all HTTP operations exposed by the target API.

    Built once during Phase 2 (OpenAPI Discovery) by discovery/surface.py
    and stored immutably in TargetContext for the duration of the pipeline.

    Every test that needs to know what the target exposes queries this object
    via its filter methods rather than parsing the raw OpenAPI spec directly.
    This centralizes OpenAPI interpretation in one place and keeps test logic
    free of spec-parsing details.

    The surface is frozen: once built from the dereferenced spec, it cannot
    be modified. A test that queries the surface gets the same answer every
    time, regardless of execution order.

    Filter methods return new lists (copies), never views into the internal
    state, so callers cannot accidentally mutate the surface by modifying
    the returned list.
    """

    model_config = {"frozen": True}

    spec_title: str = Field(
        default="Unknown",
        description="OpenAPI spec info.title, used in the HTML report header.",
    )
    spec_version: str = Field(
        default="Unknown",
        description="OpenAPI spec info.version, used in the HTML report header.",
    )
    endpoints: list[EndpointRecord] = Field(
        default_factory=list,
        description=(
            "Complete list of EndpointRecord objects, one per (path, method) "
            "operation declared in the OpenAPI spec."
        ),
    )

    # ------------------------------------------------------------------
    # Aggregate properties
    # ------------------------------------------------------------------

    @property
    def total_endpoint_count(self) -> int:
        """Total number of (path, method) operations in the surface."""
        return len(self.endpoints)

    @property
    def unique_path_count(self) -> int:
        """Number of distinct paths, regardless of HTTP method."""
        return len({ep.path for ep in self.endpoints})

    @property
    def deprecated_count(self) -> int:
        """Number of operations marked deprecated in the spec."""
        return sum(1 for ep in self.endpoints if ep.is_deprecated)

    # ------------------------------------------------------------------
    # Filter methods — return copies, never mutable views
    # ------------------------------------------------------------------

    def get_authenticated_endpoints(self) -> list[EndpointRecord]:
        """
        Return all endpoints that declare at least one security requirement.

        Used by Test 1.1 to build the list of endpoints that must reject
        unauthenticated requests with HTTP 401.

        Returns:
            New list of EndpointRecord where requires_auth is True.
        """
        return [ep for ep in self.endpoints if ep.requires_auth]

    def get_public_endpoints(self) -> list[EndpointRecord]:
        """
        Return all endpoints declared as publicly accessible (no auth required).

        Used by Test 0.1 to verify that public endpoints are intentional
        and documented, not accidental information leaks.

        Returns:
            New list of EndpointRecord where requires_auth is False.
        """
        return [ep for ep in self.endpoints if not ep.requires_auth]

    def get_deprecated_endpoints(self) -> list[EndpointRecord]:
        """
        Return all endpoints marked as deprecated in the OpenAPI spec.

        Used by Test 0.3 to verify sunset enforcement and enhanced monitoring.

        Returns:
            New list of EndpointRecord where is_deprecated is True.
        """
        return [ep for ep in self.endpoints if ep.is_deprecated]

    def get_endpoints_by_method(self, method: str) -> list[EndpointRecord]:
        """
        Return all endpoints that accept a specific HTTP method.

        Used by Test 2.3 to enumerate DELETE/PUT endpoints for privilege
        verification, and by Test 2.1 to find admin-only operations.

        Args:
            method: HTTP method, case-insensitive. Normalized to uppercase.

        Returns:
            New list of EndpointRecord matching the given method.
        """
        method_upper = method.strip().upper()
        return [ep for ep in self.endpoints if ep.method == method_upper]

    def get_endpoints_by_tag(self, tag: str) -> list[EndpointRecord]:
        """
        Return all endpoints annotated with a specific OpenAPI tag.

        Used by domain-specific tests to scope their probing to relevant
        operations (e.g., tag 'user' for Domain 2 tests).

        Args:
            tag: OpenAPI tag string, case-sensitive.

        Returns:
            New list of EndpointRecord that include the given tag.
        """
        return [ep for ep in self.endpoints if tag in ep.tags]

    def get_endpoints_with_path_parameters(self) -> list[EndpointRecord]:
        """
        Return all endpoints that declare at least one path parameter.

        Used by Test 2.2 (BOLA) to identify endpoints that accept a
        resource identifier in the URL path (e.g., /users/{id}), which
        are the primary candidates for object-level authorization bypass.

        Returns:
            New list of EndpointRecord with at least one path parameter.
        """
        return [ep for ep in self.endpoints if any(p.location == "path" for p in ep.parameters)]

    def find_endpoint(self, path: str, method: str) -> EndpointRecord | None:
        """
        Find a specific endpoint by exact path and method match.

        Used by tests that target a specific known operation rather than
        iterating over all endpoints.

        Args:
            path: Exact API path as declared in the spec (e.g., '/api/v1/users').
            method: HTTP method, case-insensitive.

        Returns:
            The matching EndpointRecord, or None if not found.
        """
        method_upper = method.strip().upper()
        for ep in self.endpoints:
            if ep.path == path and ep.method == method_upper:
                return ep
        return None

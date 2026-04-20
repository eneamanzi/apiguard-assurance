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
    EvidenceRecord      -- Immutable snapshot of a single HTTP transaction (FAIL proof)
    TransactionSummary  -- Hybrid audit entry: metadata + airbag body previews
    Finding             -- Unit of technical evidence produced by a FAIL result
    TestResult          -- Complete outcome of a single BaseTest.execute() call
    ResultSet           -- Ordered collection of all TestResult for a pipeline run

Audit trail design rationale (v1.2 — hybrid model):
    The tool maintains two parallel, complementary audit records:

    1. EvidenceStore -> evidence.json  (FAIL proof, formal)
       Stores:  full EvidenceRecord objects (~11 KB each)
       When:    FAIL and explicitly pinned transactions only
       Purpose: complete request/response for attack reproducibility.
                An analyst must be able to re-run the exact HTTP call that
                triggered the vulnerability without any additional context.
       Bound:   maxlen=100 (EvidenceStore deque)

    2. TestResult.transaction_log -> embedded in HTML report  (audit trail)
       Stores:  TransactionSummary objects (~860 bytes each with airbag previews)
       When:    EVERY HTTP transaction, including successful ones
       Purpose: coverage proof + rapid triage. An auditor verifying a
                rate-limit test needs to see that 150 requests were sent to
                path X. The hybrid body fields (request_headers, request_body,
                response_body_preview) let the HTML report generate a valid
                cURL command and show the server error message inline, without
                opening evidence.json.
       Bound:   no hard cap (airbag limits per-record payload to ~860 bytes;
                2885 x 860 bytes ~ 2.5 MB -- safe for all browsers)

    Separation of responsibilities:
        FAIL transactions -> EvidenceRecord (full) + TransactionSummary (hybrid)
        PASS transactions -> TransactionSummary (hybrid) only

    Airbag truncation constants (module level):
        _TRANSACTION_REQUEST_BODY_MAX_CHARS     = 2 000 chars
        _TRANSACTION_RESPONSE_PREVIEW_MAX_CHARS = 1 000 chars
        _TRANSACTION_TRUNCATION_SUFFIX          = "... [TRUNCATED]"
    Applied transparently in TransactionSummary.from_evidence_record().
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

    Inherits from str so values serialize natively to JSON strings.

    Semantic contract (Implementazione.md, Section 4.6):
        PASS  -- Control executed, security guarantee satisfied.
        FAIL  -- Control executed, guarantee NOT satisfied. Requires a Finding.
        SKIP  -- Not executed for an explicit, documented reason. Not a failure.
        ERROR -- Unexpected exception. Result uncertain, requires investigation.
    """

    __test__ = False

    PASS = "PASS"  # noqa: S105
    FAIL = "FAIL"
    SKIP = "SKIP"
    ERROR = "ERROR"


class TestStrategy(StrEnum):
    """
    Execution privilege level mapping to the Black/Grey/White Box gradient
    defined in the methodology (3_TOP_metodologia.md).

    BLACK_BOX -- Zero credentials. Simulates anonymous external attacker.
    GREY_BOX  -- Valid JWT tokens for at least two distinct roles.
    WHITE_BOX -- Read access to Gateway configuration via Admin API.
    """

    __test__ = False

    BLACK_BOX = "BLACK_BOX"
    GREY_BOX = "GREY_BOX"
    WHITE_BOX = "WHITE_BOX"


class SpecDialect(StrEnum):
    """
    Detected dialect of the API specification source document.

    SWAGGER_2 -- Swagger 2.0 (top-level ``swagger: "2.0"`` key).
    OPENAPI_3 -- OpenAPI 3.x (top-level ``openapi: "3.x"`` key).
    """

    SWAGGER_2 = "swagger_2"
    OPENAPI_3 = "openapi_3"


# ---------------------------------------------------------------------------
# EvidenceRecord — formal proof of security violations
# ---------------------------------------------------------------------------


class EvidenceRecord(BaseModel):
    """
    Immutable snapshot of a single HTTP transaction (request + response).

    Lives in EvidenceStore (deque, maxlen=100). Stored ONLY for FAIL and
    explicitly pinned transactions — formal proof that an analyst must be
    able to reproduce.

    Size: ~11 KB per record (dominated by response_body, capped at 10,000
    chars). Appropriate for a bounded store of ~100 records, but prohibitive
    if stored for every HTTP interaction in high-volume tests.

    For the complete audit trail of all HTTP interactions, including successful
    ones, see TransactionSummary and TestResult.transaction_log.
    """

    model_config = {"frozen": True}

    record_id: str = Field(
        description="Unique identifier. Format: '{test_id}_{sequence}', e.g. '1.2_001'."
    )
    timestamp_utc: datetime = Field(description="UTC timestamp when the request was dispatched.")
    request_method: str = Field(description="HTTP method, uppercase.")
    request_url: str = Field(description="Full URL. Must not embed credentials.")
    request_headers: dict[str, str] = Field(
        default_factory=dict,
        description="Request headers (lowercase keys). Authorization always '[REDACTED]'.",
    )
    request_body: str | None = Field(default=None)
    response_status_code: int = Field(description="HTTP status code.")
    response_headers: dict[str, str] = Field(
        default_factory=dict, description="Response headers (lowercase keys)."
    )
    response_body: str | None = Field(
        default=None,
        description="Response body, truncated to 10,000 chars.",
    )
    is_pinned: bool = Field(
        default=False,
        description="True if explicitly marked as key evidence by the test.",
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
        Normalize header keys to lowercase per RFC 9110.
        Redact the Authorization header value to '[REDACTED]'.
        """
        if not isinstance(value, dict):
            return {}
        normalized: dict[str, str] = {}
        for key, val in value.items():
            lower_key = key.lower()
            normalized[lower_key] = "[REDACTED]" if lower_key == "authorization" else str(val)
        return normalized

    @field_validator("response_body", mode="before")
    @classmethod
    def truncate_response_body(cls, value: Any) -> str | None:  # noqa: ANN401
        """Truncate response body to 10,000 chars to bound evidence.json size."""
        _max_length: int = 10_000
        _truncation_suffix: str = "... [TRUNCATED]"
        if value is None:
            return None
        as_string = str(value)
        return (
            as_string[:_max_length] + _truncation_suffix
            if len(as_string) > _max_length
            else as_string
        )


# ---------------------------------------------------------------------------
# TransactionSummary — hybrid audit trail entry (metadata + airbag previews)
# ---------------------------------------------------------------------------

# Airbag truncation limits for TransactionSummary body preview fields.
# These constants bound the HTML report size to a safe maximum even when
# individual endpoints return multi-megabyte responses or large request
# payloads. Full content is always available in EvidenceRecord / evidence.json
# for every FAIL transaction.
_TRANSACTION_REQUEST_BODY_MAX_CHARS: int = 2_000
_TRANSACTION_RESPONSE_PREVIEW_MAX_CHARS: int = 1_000
_TRANSACTION_TRUNCATION_SUFFIX: str = "... [TRUNCATED]"


class TransactionSummary(BaseModel):
    """
    Ultra-lightweight, immutable record of a single HTTP transaction.

    Stored in TestResult.transaction_log for EVERY HTTP interaction a test
    performs — including successful ones that would not appear in EvidenceStore.

    Design principle — hybrid model (metadata + airbag previews):
        The audit trail serves two purposes: proving COVERAGE (how many
        requests were sent, to which paths, with what outcomes) and enabling
        RAPID TRIAGE without opening evidence.json for every issue.

        The hybrid fields (request_headers, request_body, response_body_preview)
        let the HTML report generate a valid cURL command for any transaction
        and show the server error message inline. Body content is truncated by
        the airbag constants (_TRANSACTION_*_MAX_CHARS) to guarantee a safe
        HTML size regardless of upstream response size.

        Full payloads for FAIL transactions remain in EvidenceRecord /
        evidence.json. The TransactionSummary body fields are convenience
        previews only — never the authoritative record.

    Size budget (hybrid model):
        ~860 bytes per record × 2885 records (full assessment) ≈ 2.5 MB total.
        Dominated by response_body_preview at max 1 000 chars per record.
        Safe for Python RAM, JSON embedding in HTML, and browser rendering.
        High-volume Test 4.1 (≤ 150 requests): adds ≤ 130 KB — negligible.

    Cross-referencing:
        When is_fail_evidence=True, the HTML report shows a note:
        "Full transaction in evidence.json → {record_id}". The analyst
        locates the complete EvidenceRecord using record_id as the key.
    """

    model_config = {"frozen": True}

    record_id: str = Field(
        description=(
            "Identifier matching EvidenceRecord.record_id for the same transaction "
            "when is_fail_evidence=True. Format: '{test_id}_{sequence}'. "
            "Cross-reference to the full transaction in evidence.json."
        )
    )
    timestamp_utc: datetime = Field(
        description="UTC timestamp when the HTTP request was dispatched."
    )
    request_method: str = Field(description="HTTP method, uppercase (e.g., 'GET', 'POST').")
    request_url: str = Field(
        description=(
            "Full URL of the request. Credentials are never embedded — "
            "the Authorization header is not stored in this summary."
        )
    )
    response_status_code: int = Field(description="HTTP status code received from the server.")
    oracle_state: str | None = Field(
        default=None,
        description=(
            "Semantic label assigned by the test to classify the oracle outcome "
            "of this transaction. Set at the call site after evaluating the response. "
            "Examples: 'ENFORCED' (401/403), 'BYPASS' (2xx on protected path), "
            "'RATE_LIMIT_HIT' (429), 'SUNSET_MISSING', 'BACKEND_LEAKED', "
            "'INCONCLUSIVE_PARAMETRIC', 'CORRECTLY_DENIED'. "
            "Provides richer diagnostic context than the status code alone. "
            "None when the test does not assign an explicit semantic label."
        ),
    )
    duration_ms: float | None = Field(
        default=None,
        description=(
            "Wall-clock time for this individual HTTP transaction in milliseconds. "
            "Set by the test when per-request timing is diagnostically relevant "
            "(e.g., timeout enforcement tests). None otherwise."
        ),
    )
    is_fail_evidence: bool = Field(
        default=False,
        description=(
            "True if store.add_fail_evidence(record) was also called for this "
            "transaction. The HTML report highlights these entries and notes that "
            "the full EvidenceRecord is available in evidence.json."
        ),
    )
    request_headers: dict[str, str] = Field(
        default_factory=dict,
        description=(
            "Full request headers dict (lowercase keys). "
            "The Authorization value is always '[REDACTED]', inherited from the "
            "EvidenceRecord.headers_must_be_lowercase validator at creation time. "
            "Enables generation of a valid cURL command in the HTML report "
            "Audit Trail modal without opening evidence.json."
        ),
    )
    request_body: str | None = Field(
        default=None,
        description=(
            "Request body truncated to _TRANSACTION_REQUEST_BODY_MAX_CHARS chars. "
            "None if the original request carried no body. "
            "Populated by TransactionSummary.from_evidence_record() via airbag "
            "truncation. Enables payload inspection in the HTML Audit Trail modal."
        ),
    )
    response_body_preview: str | None = Field(
        default=None,
        description=(
            "Response body truncated to _TRANSACTION_RESPONSE_PREVIEW_MAX_CHARS chars. "
            "None if the response carried no body. "
            "Populated by TransactionSummary.from_evidence_record() via airbag "
            "truncation. Enables rapid triage of server error messages in the HTML "
            "report without opening evidence.json."
        ),
    )

    @field_validator("request_method")
    @classmethod
    def method_must_be_uppercase(cls, value: str) -> str:
        """Normalize HTTP method to uppercase for consistency."""
        return value.upper()

    @classmethod
    def from_evidence_record(
        cls,
        record: EvidenceRecord,
        *,
        is_fail: bool = False,
        oracle_state: str | None = None,
        duration_ms: float | None = None,
    ) -> TransactionSummary:
        """
        Construct a TransactionSummary from a full EvidenceRecord.

        This is the canonical factory method. Tests call this inside
        BaseTest._log_transaction() after every SecurityClient.request().

        Airbag truncation is applied transparently here to request_body and
        response_body_preview: values exceeding the module-level constants
        are truncated and suffixed with _TRANSACTION_TRUNCATION_SUFFIX.
        request_headers are copied verbatim — Authorization is already
        '[REDACTED]' by the EvidenceRecord.headers_must_be_lowercase validator.

        Args:
            record:       EvidenceRecord returned by SecurityClient.request().
            is_fail:      True if store.add_fail_evidence(record) was also
                          called. The HTML report highlights these entries and
                          links them to evidence.json via record_id.
            oracle_state: Semantic label for this transaction's outcome.
                          Assign at the call site in the test after evaluating
                          the response status and business logic.
            duration_ms:  Per-request timing in milliseconds, when the test
                          measures individual request latency.

        Returns:
            A frozen TransactionSummary ready to append to
            BaseTest._transaction_log.
        """

        def _airbag(value: str | None, max_chars: int) -> str | None:
            """Truncate value to max_chars and append the truncation suffix."""
            if value is None:
                return None
            if len(value) <= max_chars:
                return value
            return value[:max_chars] + _TRANSACTION_TRUNCATION_SUFFIX

        return cls(
            record_id=record.record_id,
            timestamp_utc=record.timestamp_utc,
            request_method=record.request_method,
            request_url=record.request_url,
            response_status_code=record.response_status_code,
            oracle_state=oracle_state,
            duration_ms=duration_ms,
            is_fail_evidence=is_fail,
            request_headers=dict(record.request_headers),
            request_body=_airbag(record.request_body, _TRANSACTION_REQUEST_BODY_MAX_CHARS),
            response_body_preview=_airbag(
                record.response_body, _TRANSACTION_RESPONSE_PREVIEW_MAX_CHARS
            ),
        )


# ---------------------------------------------------------------------------
# Finding — unit of technical evidence
# ---------------------------------------------------------------------------


class Finding(BaseModel):
    """
    A single unit of technical evidence produced when a test detects a
    violation of a security guarantee.

    Deliberately free of severity judgment. The tool provides objective
    technical evidence; severity assessment is delegated to the analyst
    or external risk-scoring systems.

    One TestResult(status=FAIL) must contain at least one Finding.
    One TestResult may contain multiple Findings for distinct violations.
    """

    title: str = Field(description="Short description of the violated guarantee.")
    detail: str = Field(
        description="Technical description, specific enough to reproduce the finding."
    )
    references: list[str] = Field(
        default_factory=list,
        description="Standard references: 'CWE-287', 'OWASP-API2:2023', 'RFC-8725'.",
    )
    evidence_ref: str | None = Field(
        default=None,
        description="record_id of the EvidenceRecord in EvidenceStore proving this finding.",
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

    TestResult is the only object BaseTest.execute() may return.
    Raw exceptions are caught internally and converted to status=ERROR.

    Transaction log (full audit trail):
        transaction_log holds every TransactionSummary accumulated by the
        test via BaseTest._log_transaction() during execute(). It is embedded
        in the HTML report as a collapsible table inside the expanded row panel.

        NO CAP is applied. The ultra-lightweight TransactionSummary design
        (~160 bytes, no body content) makes a cap architecturally unnecessary:
        - 2000 entries (worst case, Test 4.1) = 320 KB of JSON in HTML
        - Full assessment (2885 entries estimated) = 461 KB
        Both values are safe for browser rendering and Python RAM.

        Body content is absent by design. Reproducibility of FAIL payloads
        is guaranteed by EvidenceStore / evidence.json (full EvidenceRecord).
        The transaction_log provides COVERAGE proof, not payload detail.
    """

    __test__ = False

    test_id: str = Field(
        description="Unique test identifier matching BaseTest.test_id, e.g. '1.2'."
    )
    status: TestStatus = Field(description="Outcome of the test execution.")
    message: str = Field(description="One-line summary of the test outcome.")
    findings: list[Finding] = Field(
        default_factory=list,
        description="Technical evidence units. Non-empty only for FAIL (mandatory).",
    )
    skip_reason: str | None = Field(
        default=None,
        description="Why the test was skipped. Populated only for status=SKIP.",
    )
    duration_ms: float | None = Field(
        default=None,
        description="Wall-clock execution time in milliseconds, set by the engine.",
    )

    # --- Full audit trail (new in v1.1) ---
    transaction_log: list[TransactionSummary] = Field(
        default_factory=list,
        description=(
            "Complete ordered audit trail of ALL HTTP transactions performed "
            "during this test execution, including successful ones. "
            "Populated by BaseTest._log_transaction() — no cap applied. "
            "Embedded in the HTML report as a collapsible table. "
            "NOT serialized to evidence.json (which stores only EvidenceRecord)."
        ),
    )

    # --- Test metadata ---
    # Copied from BaseTest ClassVar at result-construction time via
    # _metadata_kwargs(). Allows builder.py to produce a complete report
    # without importing from tests/ (unidirectional dependency rule).
    test_name: str = Field(default="")
    domain: int = Field(default=-1)
    priority: int = Field(default=0)
    strategy: str = Field(default="")
    tags: list[str] = Field(default_factory=list)
    cwe_id: str = Field(default="")

    @model_validator(mode="after")
    def validate_status_finding_consistency(self) -> TestResult:
        """
        Enforce the invariant between status and findings list.

        FAIL  -> findings must be non-empty (evidence is mandatory).
        PASS  -> findings must be empty (no violation detected).
        SKIP  -> findings empty, skip_reason must be present.
        ERROR -> findings may be empty or non-empty.
        """
        if self.status == TestStatus.FAIL and not self.findings:
            raise ValueError(
                "A TestResult with status=FAIL must contain at least one Finding. "
                "A FAIL without evidence is not a valid assessment outcome."
            )
        if self.status == TestStatus.PASS and self.findings:
            raise ValueError(
                f"A TestResult with status=PASS must have an empty findings list. "
                f"Found {len(self.findings)} finding(s). Use status=FAIL instead."
            )
        if self.status == TestStatus.SKIP and not self.skip_reason:
            raise ValueError(
                "A TestResult with status=SKIP must provide a skip_reason. "
                "SKIP without explanation is indistinguishable from a silent failure."
            )
        return self


# ---------------------------------------------------------------------------
# RuntimeCredentials — immutable credentials propagated to TargetContext
# ---------------------------------------------------------------------------


class RuntimeCredentials(BaseModel):
    """
    Immutable snapshot of credentials propagated into TargetContext.

    Lives in core/ so TargetContext can reference it without importing from
    config/ (unidirectional dependency rule: config/ imports core/, never reverse).
    """

    model_config = {"frozen": True}

    admin_username: str | None = Field(default=None)
    admin_password: str | None = Field(default=None)
    user_a_username: str | None = Field(default=None)
    user_a_password: str | None = Field(default=None)
    user_b_username: str | None = Field(default=None)
    user_b_password: str | None = Field(default=None)

    def has_admin(self) -> bool:
        """True if both admin_username and admin_password are present and non-empty."""
        return bool(
            self.admin_username
            and self.admin_username.strip()
            and self.admin_password
            and self.admin_password.strip()
        )

    def has_user_a(self) -> bool:
        """True if both user_a_username and user_a_password are present and non-empty."""
        return bool(
            self.user_a_username
            and self.user_a_username.strip()
            and self.user_a_password
            and self.user_a_password.strip()
        )

    def has_user_b(self) -> bool:
        """True if both user_b_username and user_b_password are present and non-empty."""
        return bool(
            self.user_b_username
            and self.user_b_username.strip()
            and self.user_b_password
            and self.user_b_password.strip()
        )

    def has_any_grey_box_credentials(self) -> bool:
        """True if at least one role has complete credentials configured."""
        return self.has_admin() or self.has_user_a() or self.has_user_b()

    def available_roles(self) -> list[str]:
        """
        Return the list of role names with complete credentials configured.

        Role name strings match ROLE_* constants in context.py.
        Local import avoided here to prevent a circular dependency.
        """
        roles: list[str] = []
        if self.has_admin():
            roles.append("admin")
        if self.has_user_a():
            roles.append("user_a")
        if self.has_user_b():
            roles.append("user_b")
        return roles


# ---------------------------------------------------------------------------
# ResultSet — ordered collection of all TestResult for one pipeline run
# ---------------------------------------------------------------------------


class ResultSet(BaseModel):
    """
    Ordered collection of all TestResult objects produced during a pipeline run.

    Primary input to report/builder.py and source of truth for exit code
    calculation. Built incrementally by the engine during Phase 5.
    """

    results: list[TestResult] = Field(default_factory=list)
    started_at: datetime = Field(default_factory=lambda: datetime.now(UTC))
    completed_at: datetime | None = Field(default=None)

    def add_result(self, result: TestResult) -> None:
        """Append a TestResult to the collection."""
        self.results.append(result)

    def compute_exit_code(self) -> int:
        """
        Compute the process exit code from the current ResultSet state.

        Priority: FAIL (1) > ERROR (2) > CLEAN (0).
        Exit code 10 (infrastructure error) is handled upstream by the engine.
        """
        if any(r.status == TestStatus.FAIL for r in self.results):
            return 1
        if any(r.status == TestStatus.ERROR for r in self.results):
            return 2
        return 0

    @property
    def total_count(self) -> int:
        """Total number of test results."""
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
        """Total Finding objects across all FAIL results."""
        return sum(len(r.findings) for r in self.results)

    @property
    def total_transaction_count(self) -> int:
        """
        Total TransactionSummary entries across all TestResult objects.

        Represents the complete number of HTTP requests sent to the target
        during the assessment. Used in the HTML report executive summary
        stat card 'HTTP Requests Sent'.
        """
        return sum(len(r.transaction_log) for r in self.results)

    @property
    def duration_seconds(self) -> float | None:
        """Total assessment duration in seconds. None if not yet completed."""
        if self.completed_at is None:
            return None
        return (self.completed_at - self.started_at).total_seconds()


# ---------------------------------------------------------------------------
# RuntimeTestsConfig — immutable test parameters propagated to TargetContext
# ---------------------------------------------------------------------------


class RuntimeTest11Config(BaseModel):
    """Runtime mirror of TestDomain1Config fields consumed by Test 1.1."""

    model_config = {"frozen": True}

    max_endpoints_cap: int = Field(
        default=0,
        ge=0,
        description=(
            "Maximum protected endpoints to probe in Test 1.1. "
            "0 = probe all (recommended for academic completeness). "
            "Mirrors TestDomain1Config.max_endpoints_cap from config/schema.py."
        ),
    )


class RuntimeTest41Config(BaseModel):
    """
    Runtime mirror of RateLimitProbeConfig fields consumed by Test 4.1.

    Mirrors config/schema.py:RateLimitProbeConfig, which is defined at the
    root level of ToolConfig (not nested under tests.domain_4) because rate
    limiting is an infrastructure-level parameter, not a domain-specific one.

    Access pattern in the test:
        target.tests_config.test_4_1.max_requests
        target.tests_config.test_4_1.request_interval_seconds
    """

    model_config = {"frozen": True}

    max_requests: int = Field(
        default=150,
        ge=1,
        description=(
            "Maximum probe requests sent before concluding rate limiting is absent. "
            "Mirrors RateLimitProbeConfig.max_requests. Default: 150."
        ),
    )
    request_interval_ms: int = Field(
        default=50,
        ge=10,
        description=(
            "Interval in milliseconds between consecutive probe requests. "
            "Mirrors RateLimitProbeConfig.request_interval_ms. Default: 50ms."
        ),
    )

    @property
    def request_interval_seconds(self) -> float:
        """Convert request_interval_ms to seconds for use in time.sleep() calls."""
        return self.request_interval_ms / 1000.0


class RuntimeTest42Config(BaseModel):
    """
    Runtime mirror of Test42AuditConfig fields consumed by Test 4.2.

    Stores the maximum acceptable timeout values (in milliseconds) for Kong
    service objects. Mirrored from config/schema.py:Test42AuditConfig, which
    is nested under config.tests.domain_4.test_4_2.

    Access pattern in the test:
        target.tests_config.test_4_2.max_connect_timeout_ms
        target.tests_config.test_4_2.max_read_timeout_ms
        target.tests_config.test_4_2.max_write_timeout_ms
    """

    model_config = {"frozen": True}

    max_connect_timeout_ms: int = Field(
        default=5_000,
        ge=1,
        description=(
            "Maximum acceptable Kong service connect_timeout in milliseconds. "
            "Methodology oracle: <= 5 000 ms. Default: 5 000."
        ),
    )
    max_read_timeout_ms: int = Field(
        default=30_000,
        ge=1,
        description=(
            "Maximum acceptable Kong service read_timeout in milliseconds. "
            "Methodology oracle: <= 30 000 ms. Default: 30 000."
        ),
    )
    max_write_timeout_ms: int = Field(
        default=30_000,
        ge=1,
        description=(
            "Maximum acceptable Kong service write_timeout in milliseconds. "
            "Methodology oracle: <= 30 000 ms. Default: 30 000."
        ),
    )


class RuntimeTest43Config(BaseModel):
    """
    Runtime mirror of Test43AuditConfig fields consumed by Test 4.3.

    Stores accepted circuit-breaker plugin names and the parameter ranges used
    to validate a detected plugin's configuration. Mirrored from
    config/schema.py:Test43AuditConfig, nested under config.tests.domain_4.test_4_3.

    Access pattern in the test:
        target.tests_config.test_4_3.accepted_cb_plugin_names
        target.tests_config.test_4_3.failure_threshold_min
        target.tests_config.test_4_3.failure_threshold_max
        target.tests_config.test_4_3.timeout_duration_min_seconds
        target.tests_config.test_4_3.timeout_duration_max_seconds
    """

    model_config = {"frozen": True}

    accepted_cb_plugin_names: list[str] = Field(
        default_factory=lambda: ["circuit-breaker", "response-ratelimiting"],
        description=(
            "Kong plugin names considered equivalent to a circuit breaker. "
            "The first enabled match drives parameter validation. "
            "Default: ['circuit-breaker', 'response-ratelimiting']."
        ),
    )
    failure_threshold_min: int = Field(
        default=3,
        ge=1,
        description="Minimum acceptable consecutive-failure threshold to open circuit. Default: 3.",
    )
    failure_threshold_max: int = Field(
        default=10,
        ge=1,
        description="Maximum acceptable consecutive-failure threshold to open circuit. Default: 10.",  # noqa: E501
    )
    timeout_duration_min_seconds: int = Field(
        default=30,
        ge=1,
        description="Minimum acceptable Open-state duration in seconds. Default: 30.",
    )
    timeout_duration_max_seconds: int = Field(
        default=120,
        ge=1,
        description="Maximum acceptable Open-state duration in seconds. Default: 120.",
    )


class RuntimeTestsConfig(BaseModel):
    """
    Immutable container for all per-test runtime configurations.

    Populated by engine.py in Phase 3 from config.tests and sibling
    config blocks. Stored in TargetContext and accessed by test
    implementations via target.tests_config.

    Convention: one field per test, named test_X_Y where X is the domain
    number and Y is the test number within that domain. Each field holds
    an immutable RuntimeTest{XY}Config model with only the parameters
    that specific test needs. This pattern scales cleanly as new tests
    are added: adding a test requires only adding one field here and
    one population line in engine.py Phase 3.

    Transaction log parameters are absent by design:
        transaction_log_max_entries_per_test -> removed (no cap needed with
            TransactionSummary's ~160-byte minimal model).
        transaction_log_preview_chars -> removed (no body content in summaries).
    """

    model_config = {"frozen": True}

    test_1_1: RuntimeTest11Config = Field(
        default_factory=RuntimeTest11Config,
        description="Runtime parameters for Test 1.1 (Authentication Required).",
    )
    test_4_1: RuntimeTest41Config = Field(
        default_factory=RuntimeTest41Config,
        description=(
            "Runtime parameters for Test 4.1 (Rate Limiting — Resource Exhaustion Prevention). "
            "Mirrors RateLimitProbeConfig from config/schema.py."
        ),
    )
    test_4_2: RuntimeTest42Config = Field(
        default_factory=RuntimeTest42Config,
        description=(
            "Runtime parameters for Test 4.2 (Timeout Configuration Audit). "
            "Mirrors Test42AuditConfig from config.tests.domain_4.test_4_2."
        ),
    )
    test_4_3: RuntimeTest43Config = Field(
        default_factory=RuntimeTest43Config,
        description=(
            "Runtime parameters for Test 4.3 (Circuit Breaker Configuration Audit). "
            "Mirrors Test43AuditConfig from config.tests.domain_4.test_4_3."
        ),
    )


# ---------------------------------------------------------------------------
# Attack Surface — OpenAPI-derived map of the target's exposed endpoints
# ---------------------------------------------------------------------------


class ParameterInfo(BaseModel):
    """Descriptor for a single declared parameter of an API operation."""

    model_config = {"frozen": True}

    name: str = Field(description="Parameter name as declared in the OpenAPI spec.")
    location: str = Field(description="'path', 'query', 'header', or 'cookie'. Stored lowercase.")
    required: bool = Field(default=False)
    schema_type: str | None = Field(default=None)
    schema_format: str | None = Field(default=None)


class EndpointRecord(BaseModel):
    """Structured descriptor for a single HTTP operation (path + method pair)."""

    model_config = {"frozen": True}

    path: str = Field(description="API path with template params, e.g. '/api/v1/users/{id}'.")
    method: str = Field(description="HTTP method, uppercase.")
    operation_id: str | None = Field(default=None)
    tags: list[str] = Field(default_factory=list)
    requires_auth: bool = Field(default=True)
    is_deprecated: bool = Field(default=False)
    parameters: list[ParameterInfo] = Field(default_factory=list)
    request_body_required: bool = Field(default=False)
    request_body_content_types: list[str] = Field(default_factory=list)

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
    and stored immutably in TargetContext for the entire pipeline run.
    Filter methods return new lists (copies), never internal views.
    """

    model_config = {"frozen": True}

    spec_title: str = Field(default="Unknown")
    spec_version: str = Field(default="Unknown")
    dialect: SpecDialect = Field(default=SpecDialect.OPENAPI_3)
    endpoints: list[EndpointRecord] = Field(default_factory=list)

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

    def get_authenticated_endpoints(self) -> list[EndpointRecord]:
        """Return all endpoints with at least one security requirement."""
        return [ep for ep in self.endpoints if ep.requires_auth]

    def get_public_endpoints(self) -> list[EndpointRecord]:
        """Return all publicly accessible endpoints."""
        return [ep for ep in self.endpoints if not ep.requires_auth]

    def get_deprecated_endpoints(self) -> list[EndpointRecord]:
        """Return all endpoints marked deprecated."""
        return [ep for ep in self.endpoints if ep.is_deprecated]

    def get_endpoints_by_method(self, method: str) -> list[EndpointRecord]:
        """Return all endpoints accepting a specific HTTP method."""
        return [ep for ep in self.endpoints if ep.method == method.strip().upper()]

    def get_endpoints_by_tag(self, tag: str) -> list[EndpointRecord]:
        """Return all endpoints annotated with a specific OpenAPI tag."""
        return [ep for ep in self.endpoints if tag in ep.tags]

    def get_endpoints_with_path_parameters(self) -> list[EndpointRecord]:
        """Return all endpoints with at least one path parameter."""
        return [ep for ep in self.endpoints if any(p.location == "path" for p in ep.parameters)]

    def find_endpoint(self, path: str, method: str) -> EndpointRecord | None:
        """Find a specific endpoint by exact path and method."""
        method_upper = method.strip().upper()
        for ep in self.endpoints:
            if ep.path == path and ep.method == method_upper:
                return ep
        return None

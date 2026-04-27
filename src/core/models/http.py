"""
src/core/models/http.py

HTTP transaction models for the APIGuard Assurance tool.

Contains the two complementary audit records that form the hybrid
evidence/audit-trail model (v1.2), plus the airbag truncation constants
that govern HTML report size.

    EvidenceRecord      -- Immutable snapshot of a single HTTP transaction
                           (FAIL proof, stored in EvidenceStore / evidence.json).
    TransactionSummary  -- Ultra-lightweight hybrid audit entry: metadata +
                           airbag body previews (embedded in HTML report for
                           every HTTP interaction, including successful ones).

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

Dependency rule: this module imports only from pydantic and the stdlib.
It must never import from any other src/ module.
"""

from __future__ import annotations

from datetime import UTC, datetime  # noqa: F401  (UTC used implicitly in dependent modules)
from typing import Any

from pydantic import BaseModel, Field, field_validator

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

    elapsed_ms:
        Wall-clock duration of the HTTP transaction in milliseconds, measured
        by SecurityClient using time.monotonic() across the full attempt
        sequence including any retry waits.  SecurityClient populates this
        field via _build_evidence_record() before returning the record to the
        test.  TransactionSummary.from_evidence_record() inherits the value
        automatically, so tests do NOT need to pass duration_ms explicitly
        to BaseTest._log_transaction().  None only when the record is
        constructed outside SecurityClient.request() (e.g., in unit fixtures).
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
    elapsed_ms: float | None = Field(
        default=None,
        description=(
            "Wall-clock duration of the HTTP transaction in milliseconds, measured "
            "by SecurityClient.request() using time.monotonic() across the full "
            "attempt sequence (including retry waits). "
            "Populated by SecurityClient._build_evidence_record() before the "
            "record is returned to the test. "
            "TransactionSummary.from_evidence_record() inherits this value "
            "automatically — tests do not need to pass duration_ms to "
            "BaseTest._log_transaction(). "
            "None only when the record is constructed outside SecurityClient "
            "(e.g., in test fixtures or teardown helpers)."
        ),
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

    duration_ms inheritance:
        from_evidence_record() auto-populates duration_ms from
        EvidenceRecord.elapsed_ms when the caller does not pass an explicit
        override. This means tests calling BaseTest._log_transaction() without
        an explicit duration_ms argument will still have the field populated
        correctly for all transactions dispatched through SecurityClient.
        The explicit override parameter remains available for tests that
        measure timing independently (e.g., timeout enforcement tests that
        time a retry sequence separately from the raw HTTP call).
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
            "Inherited automatically from EvidenceRecord.elapsed_ms by "
            "from_evidence_record() when not overridden by the caller. "
            "SecurityClient populates EvidenceRecord.elapsed_ms via time.monotonic() "
            "before returning the record, so this field is non-None for all "
            "transactions dispatched through SecurityClient.request(). "
            "An explicit override is accepted for tests that measure timing "
            "independently of the raw HTTP call (e.g., end-to-end retry sequence)."
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

        Duration inheritance:
            duration_ms is resolved with the following precedence:
                1. The explicit ``duration_ms`` argument when the caller
                   provides a non-None override (e.g., a test that measures
                   an end-to-end retry sequence independently).
                2. EvidenceRecord.elapsed_ms when no override is provided.
                   SecurityClient._build_evidence_record() always populates
                   this field, so the resolved value will be non-None for
                   all standard SecurityClient.request() transactions.

            Tests calling BaseTest._log_transaction() without an explicit
            duration_ms argument will have the field auto-populated from
            the record. No changes to test code are required.

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
            duration_ms:  Per-request timing override in milliseconds.
                          When None (the default), the value is inherited from
                          record.elapsed_ms automatically.

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

        # Precedence: explicit override > record's own elapsed_ms.
        resolved_duration_ms: float | None = (
            duration_ms if duration_ms is not None else record.elapsed_ms
        )

        return cls(
            record_id=record.record_id,
            timestamp_utc=record.timestamp_utc,
            request_method=record.request_method,
            request_url=record.request_url,
            response_status_code=record.response_status_code,
            oracle_state=oracle_state,
            duration_ms=resolved_duration_ms,
            is_fail_evidence=is_fail,
            request_headers=dict(record.request_headers),
            request_body=_airbag(record.request_body, _TRANSACTION_REQUEST_BODY_MAX_CHARS),
            response_body_preview=_airbag(
                record.response_body, _TRANSACTION_RESPONSE_PREVIEW_MAX_CHARS
            ),
        )

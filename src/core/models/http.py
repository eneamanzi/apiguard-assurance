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

Dependency rule: this module imports only from pydantic, the stdlib, src.core.redaction and
sibling modules within src.core.models (enums).
It must never import from any other src/ module.
"""

from __future__ import annotations

from datetime import UTC, datetime  # noqa: F401  (UTC used implicitly in dependent modules)
from typing import Any

from pydantic import BaseModel, Field, field_validator, model_validator

from src.core.models.enums import Outcome, ResponseCategory, TransportError
from src.core.redaction import (
    AUTHORIZATION_HEADER,
    PUBLIC_VALUE_PREFIX,
    REDACTED_MARKER_PREFIX,
    REDACTED_PLACEHOLDER,
)

# ---------------------------------------------------------------------------
# EvidenceRecord — formal proof of security violations
# ---------------------------------------------------------------------------

# Maximum length of response body stored in EvidenceRecord, in characters.
# Consistent with the value documented in SecurityClient (client.py).
_EVIDENCE_RECORD_BODY_MAX_CHARS: int = 10_000
# Appended to a body cut to its limit (evidence records and transaction summaries).
_TRANSACTION_TRUNCATION_SUFFIX: str = "... [TRUNCATED]"


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
        to BaseTest._judge() or _step().  None only when the record is
        constructed outside SecurityClient.request() (e.g., in unit fixtures).
    """

    model_config = {"frozen": True}

    record_id: str = Field(
        description=(
            "Unique ID. HTTP records: `{test_id}_{NNN}` (e.g. `1.1_005`), a counter per "
            "test. Tool outputs: `artifact-{test_id}-{label}-{HHMMSSffffff}`."
        )
    )
    timestamp_utc: datetime = Field(description="When the request was dispatched.")
    request_method: str = Field(
        description=(
            "HTTP method, uppercase. For a tool output: its label uppercased, the external "
            "test's ID (e.g. `EXT.0.1.NUCLEI`)."
        )
    )
    request_url: str = Field(
        description="Full URL. For a tool output: `external://{test_id}/{label}`."
    )
    request_headers: dict[str, str] = Field(
        default_factory=dict,
        description=(
            "Lowercase header names; `authorization`, cookie values and the registered "
            "secrets replaced with typed placeholders (see Sensitive data below)."
        ),
    )
    request_body: str | None = Field(
        default=None,
        description=(
            "The JSON body as sent, with the registered secrets replaced; null when the "
            "request carried no JSON body."
        ),
    )
    response_status_code: int | None = Field(
        description=(
            "HTTP status; `0` for a tool output; null when no response arrived "
            "(`transport_error` says why)."
        )
    )
    transport_error: TransportError | None = Field(
        default=None,
        description=(
            "Why no response arrived: `timeout`, `connection_failed`, `tls_error`, "
            "`protocol_error`; null when a response arrived."
        ),
    )
    response_headers: dict[str, str] = Field(
        default_factory=dict, description="Lowercase header names."
    )
    response_set_cookies: list[str] = Field(
        default_factory=list,
        description=(
            "Every `Set-Cookie` of the response, in order, values redacted (names and attributes "
            "kept). Kept apart from `response_headers`: RFC 6265 forbids folding several "
            "`Set-Cookie` into one value, and a mapping would keep only the last."
        ),
    )
    response_body: str | None = Field(
        default=None,
        description=(
            f"Body truncated to {_EVIDENCE_RECORD_BODY_MAX_CHARS:,} characters + "
            f"`{_TRANSACTION_TRUNCATION_SUFFIX}`; an undecodable body becomes "
            "`[Binary or undecodable response body]`. For a tool output: the tool's raw output "
            "as JSON, credentials removed, truncated the same way (the full output is in "
            "`tools/<label>_output.json`)."
        ),
    )
    is_pinned: bool = Field(
        default=False,
        description=(
            "`true` for a transaction a test marked as key context and for a tool output; "
            "`false` for FAIL evidence."
        ),
    )
    elapsed_ms: float | None = Field(
        default=None,
        description=(
            "Duration (ms) of the HTTP transaction, retry waits included; null for a tool output."
        ),
    )

    @field_validator("request_method")
    @classmethod
    def method_must_be_uppercase(cls, value: str) -> str:
        """Normalize HTTP method to uppercase for consistency."""
        return value.upper()

    @model_validator(mode="after")
    def status_or_transport_error(self) -> EvidenceRecord:
        """A record has an HTTP status or a transport error, never both or neither."""
        if (self.response_status_code is None) == (self.transport_error is None):
            raise ValueError("a record has either a response status or a transport error")
        return self

    @field_validator("request_headers", "response_headers", mode="before")
    @classmethod
    def headers_must_be_lowercase(cls, value: Any) -> dict[str, str]:  # noqa: ANN401
        """
        Normalize header keys to lowercase per RFC 9110.

        Safety net for the Authorization header: SecurityClient already stores
        a typed placeholder ("[REDACTED: user_a token]", src/core/redaction.py)
        or a declared public probe ("[public probe] Bearer null"); any other
        value is replaced with the bare placeholder, so a credential can never
        be stored even by a caller that bypasses the client.
        """
        if not isinstance(value, dict):
            return {}
        normalized: dict[str, str] = {}
        for key, val in value.items():
            lower_key = key.lower()
            text = str(val)
            if lower_key == AUTHORIZATION_HEADER and not text.startswith(
                (REDACTED_MARKER_PREFIX, PUBLIC_VALUE_PREFIX)
            ):
                text = REDACTED_PLACEHOLDER
            normalized[lower_key] = text
        return normalized

    @field_validator("response_body", mode="before")
    @classmethod
    def truncate_response_body(cls, value: Any) -> str | None:  # noqa: ANN401
        """Truncate response body to _EVIDENCE_RECORD_BODY_MAX_CHARS to bound evidence.json size."""
        if value is None:
            return None
        as_string = str(value)
        return (
            as_string[:_EVIDENCE_RECORD_BODY_MAX_CHARS] + _TRANSACTION_TRUNCATION_SUFFIX
            if len(as_string) > _EVIDENCE_RECORD_BODY_MAX_CHARS
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
class EvidenceFile(BaseModel):
    """
    The content of evidence.json, as written in Phase 7 (EvidenceStore.merge_and_finalize).

    The one definition of the file's top level (docs/03-reference/05-evidence-format.md
    is generated from it).
    """

    model_config = {"frozen": True}

    tool_version: str = Field(
        description="APIGuard version that wrote the file: the version of this format."
    )
    generated_at_utc: str = Field(
        description="When the file was written (Phase 7), ISO 8601 in UTC with `+00:00` offset."
    )
    record_count: int = Field(ge=0, description="Number of records.")
    records: list[EvidenceRecord] = Field(
        description="Records sorted by `timestamp_utc`; empty when no evidence was collected."
    )


_TRANSACTION_REQUEST_BODY_MAX_CHARS: int = 2_000
_TRANSACTION_RESPONSE_PREVIEW_MAX_CHARS: int = 1_000


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
        override. This means tests calling BaseTest._judge() or _step() without
        an explicit duration_ms argument will still have the field populated
        correctly for all transactions dispatched through SecurityClient.
        The explicit override parameter remains available for tests that
        measure timing independently (e.g., timeout enforcement tests that
        time a retry sequence separately from the raw HTTP call).
    """

    model_config = {"frozen": True}

    record_id: str = Field(
        description=(
            "`{test_id}_{NNN}`; matches a record in `evidence.json` when `is_fail_evidence` "
            "is `true`."
        )
    )
    timestamp_utc: datetime = Field(description="Dispatch time.")
    request_method: str = Field(description="HTTP method of the request.")
    request_url: str = Field(description=("Full URL of the request."))
    response_status_code: int | None = Field(
        description="HTTP status of the response; null when no response arrived."
    )
    transport_error: TransportError | None = Field(
        default=None,
        description="Why no response arrived (as in the evidence record); null otherwise.",
    )
    category: ResponseCategory | None = Field(
        default=None,
        description=(
            "What the response is, common to every test (`SERVED`, `NOT_FOUND`, "
            "`UNAUTHENTICATED`, ...)."
        ),
    )
    sub_test: str | None = Field(
        default=None,
        description="The sub-test the request belongs to; null for a preparation step.",
    )
    outcome: Outcome | None = Field(
        default=None,
        description=(
            "What the response means for the guarantee (`VIOLATION`, `ENFORCED`, "
            "`NOT_VERIFIABLE`, `NOT_APPLICABLE`); null when the request is not judged "
            "(a login, an object created for the test)."
        ),
    )
    detail: str | None = Field(
        default=None,
        description=(
            "The test's detail of the outcome, e.g. `AUTH_BYPASS`, `PATH_NOT_FOUND`; read "
            "with the outcome as `VIOLATION/AUTH_BYPASS`. Null with a null outcome."
        ),
    )
    duration_ms: float | None = Field(
        default=None,
        description=("Duration of the request."),
    )
    is_fail_evidence: bool = Field(
        default=False,
        description=("The transaction is FAIL evidence: the full record is in `evidence.json`."),
    )
    request_headers: dict[str, str] = Field(
        default_factory=dict,
        description=(
            "Lowercase names; `authorization` and cookie values redacted with typed "
            "placeholders (see the evidence format)."
        ),
    )
    request_body: str | None = Field(
        default=None,
        description=(
            f"Request body, truncated to {_TRANSACTION_REQUEST_BODY_MAX_CHARS:,} characters; "
            "null without a body."
        ),
    )
    response_body_preview: str | None = Field(
        default=None,
        description=(
            f"Response body, truncated to {_TRANSACTION_RESPONSE_PREVIEW_MAX_CHARS:,} "
            "characters; null without a body."
        ),
    )

    @field_validator("request_method")
    @classmethod
    def method_must_be_uppercase(cls, value: str) -> str:
        """Normalize HTTP method to uppercase for consistency."""
        return value.upper()

    @model_validator(mode="after")
    def judgement_complete(self) -> TransactionSummary:
        """A judged request names its sub-test and detail; an unjudged one has neither."""
        if self.outcome is not None and (self.sub_test is None or self.detail is None):
            raise ValueError("a judged transaction (outcome set) needs its sub_test and detail")
        if self.outcome is None and self.detail is not None:
            raise ValueError("a detail without an outcome")
        return self

    @classmethod
    def from_evidence_record(
        cls,
        record: EvidenceRecord,
        *,
        is_fail: bool = False,
        category: ResponseCategory | None = None,
        sub_test: str | None = None,
        outcome: Outcome | None = None,
        detail: str | None = None,
        duration_ms: float | None = None,
    ) -> TransactionSummary:
        """
        Construct a TransactionSummary from a full EvidenceRecord.

        This is the canonical factory method, called by BaseTest._judge() and
        BaseTest._step() for every SecurityClient.request() of a test.

        Duration inheritance:
            duration_ms is resolved with the following precedence:
                1. The explicit ``duration_ms`` argument when the caller
                   provides a non-None override (e.g., a test that measures
                   an end-to-end retry sequence independently).
                2. EvidenceRecord.elapsed_ms when no override is provided.
                   SecurityClient._build_evidence_record() always populates
                   this field, so the resolved value will be non-None for
                   all standard SecurityClient.request() transactions.

            Tests calling BaseTest._judge() or _step() without an explicit
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
            category:     What the response is (src/core/response_category.py),
                          given by the test base: models compute nothing outside
                          their package.
            sub_test:     The sub-test the request belongs to; None for a
                          preparation step.
            outcome:      What the response means for the guarantee; None for
                          a request that is not judged.
            detail:       The test's detail of the outcome (None with no
                          outcome).
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
            transport_error=record.transport_error,
            category=category,
            sub_test=sub_test,
            outcome=outcome,
            detail=detail,
            duration_ms=resolved_duration_ms,
            is_fail_evidence=is_fail,
            request_headers=dict(record.request_headers),
            request_body=_airbag(record.request_body, _TRANSACTION_REQUEST_BODY_MAX_CHARS),
            response_body_preview=_airbag(
                record.response_body, _TRANSACTION_RESPONSE_PREVIEW_MAX_CHARS
            ),
        )

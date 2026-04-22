"""
src/tests/base.py

BaseTest: abstract base class defining the contract for all test implementations.

Every security test in the tool is a concrete subclass of BaseTest. The engine
interacts exclusively with this interface — it never inspects the internal
implementation of a test. This design makes adding new tests a purely additive
operation: create a file in the correct domain directory, subclass BaseTest,
implement execute(), and the test is automatically discovered by TestRegistry.

Contract guarantees that BaseTest enforces:

    1. Class-level metadata attributes (test_id, priority, strategy, etc.)
       must be declared on every concrete subclass. TestRegistry inspects
       these at discovery time; tests with missing attributes are excluded.

    2. execute() must always return a TestResult. It must never raise.
       Any exception that escapes execute() is a contract violation — the
       engine is not required to handle it and will abort the pipeline.

    3. A TestResult(status=FAIL) must contain at least one Finding.
       Enforced by TestResult's model_validator, not here.

    4. Metadata propagation: every _make_* helper copies ClassVar metadata
       (test_name, domain, priority, strategy, tags, cwe_id) into the
       returned TestResult, so builder.py needs no knowledge of tests/.

    5. Transaction log propagation: every _make_* helper includes
       list(self._transaction_log) in the returned TestResult.
       The log accumulates via _log_transaction() during execute() and is
       automatically included in the result regardless of which exit path
       the test takes (PASS, FAIL, SKIP, or ERROR).

_log_transaction() calling convention:
    After every client.request() call, the test must call _log_transaction()
    to record the interaction in the audit trail. The method accepts the
    oracle_state so the test can annotate the semantic meaning of the
    response (e.g. 'ENFORCED', 'BYPASS', 'RATE_LIMIT_HIT') independently
    of the HTTP status code.

    Pattern:
        response, record = client.request(method, path, test_id=self.test_id)

        if response.status_code in BYPASS_CODES:
            store.add_fail_evidence(record)
            self._log_transaction(record, oracle_state="BYPASS", is_fail=True)
            findings.append(Finding(...))
        else:
            self._log_transaction(record, oracle_state="ENFORCED")

    The is_fail=True flag links the TransactionSummary to the corresponding
    EvidenceRecord in evidence.json via record_id, so the HTML report can
    highlight the entry and provide a cross-reference for the analyst.

Dependency rule:
    This module imports from stdlib, structlog, abc, and src.core only.
    It must never import from config/, discovery/, report/, or engine.py.
    Test subclasses import from src.tests.base and src.core; they must not
    import from other test modules to avoid coupling between domains.
"""

from __future__ import annotations

import traceback
from abc import ABC, abstractmethod
from typing import ClassVar, TypedDict

import structlog

from src.core.client import SecurityClient
from src.core.context import ROLE_ADMIN, ROLE_USER_A, ROLE_USER_B, TargetContext, TestContext
from src.core.evidence import EvidenceStore
from src.core.models import (
    EvidenceRecord,
    Finding,
    InfoNote,
    TestResult,
    TestStatus,
    TestStrategy,
    TransactionSummary,
)

log: structlog.BoundLogger = structlog.get_logger(__name__)

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------


class _MetadataKwargs(TypedDict):
    """TypedDict for the metadata keyword arguments passed to TestResult."""

    test_name: str
    domain: int
    priority: int
    strategy: str
    tags: list[str]
    cwe_id: str


_ROLE_DISPLAY_NAMES: dict[str, str] = {
    ROLE_ADMIN: "admin",
    ROLE_USER_A: "user_a",
    ROLE_USER_B: "user_b",
}


# ---------------------------------------------------------------------------
# BaseTest
# ---------------------------------------------------------------------------


class BaseTest(ABC):
    """
    Abstract base class for all APIGuard security test implementations.

    Concrete subclasses must:
        1. Declare all ClassVar metadata attributes listed below.
        2. Implement the execute() method.
        3. Call self._log_transaction() after every SecurityClient.request().
        4. Ensure execute() never raises — all exceptions must be caught
           internally and returned as TestResult(status=ERROR).

    Instance-level state:
        __init__ initialises self._transaction_log as an empty list.
        This is an instance variable — not a ClassVar — so each test instance
        maintains its own independent audit trail. Since TestRegistry creates
        each test class exactly once and the engine calls execute() exactly
        once per instance, no reset mechanism is needed.

    ClassVar attributes (inspected by TestRegistry at discovery time):

        test_id: str
            Unique test identifier. Format: '{domain}.{sequence}', e.g. '1.2'.

        priority: int
            Execution priority level, 0 (most critical) to 3 (least critical).

        strategy: TestStrategy
            Execution privilege level (BLACK_BOX, GREY_BOX, WHITE_BOX).

        depends_on: list[str]
            List of test_id values that must execute before this test.

        test_name: str
            Human-readable name of the security guarantee being verified.

        domain: int
            Domain number (0-7) matching the methodology chapter.

        tags: list[str]
            Categorical labels for filtering and reporting.

        cwe_id: str
            Primary CWE identifier for the vulnerability class this test verifies.
    """

    test_id: ClassVar[str]
    priority: ClassVar[int]
    strategy: ClassVar[TestStrategy]
    depends_on: ClassVar[list[str]]
    test_name: ClassVar[str]
    domain: ClassVar[int]
    tags: ClassVar[list[str]]
    cwe_id: ClassVar[str]

    def __init__(self) -> None:
        """
        Initialise the per-instance transaction log.

        This is a concrete __init__ on an ABC, which is valid and necessary.
        Without it, each test subclass would need to explicitly define __init__
        or the _transaction_log attribute would not exist before execute() runs.

        The list is instance-level (not ClassVar) to ensure that each test
        instance accumulates its own independent audit trail. A ClassVar would
        cause all instances of the same class to share one list, which would
        corrupt the audit trail if the class were instantiated more than once
        within a single pipeline run.

        No other instance state is initialised here. All data required by
        execute() arrives via its parameters (target, context, client, store).
        """
        self._transaction_log: list[TransactionSummary] = []

    @abstractmethod
    def execute(
        self,
        target: TargetContext,
        context: TestContext,
        client: SecurityClient,
        store: EvidenceStore,
    ) -> TestResult:
        """
        Execute the security test and return a result.

        INVARIANT: this method must ALWAYS return a TestResult.
        It must NEVER raise an exception. Use _make_error() in a top-level
        try/except to catch unexpected exceptions.

        Transaction log usage:
            Call self._log_transaction(record, oracle_state=...) after every
            client.request(). The _make_* helpers automatically include the
            accumulated log in the returned TestResult. Example:

                try:
                    response, record = client.request(
                        method="GET", path=path, test_id=self.test_id
                    )
                except SecurityClientError as exc:
                    return self._make_error(exc)

                if response.status_code in BYPASS_CODES:
                    store.add_fail_evidence(record)
                    self._log_transaction(record, oracle_state="BYPASS", is_fail=True)
                    findings.append(Finding(..., evidence_ref=record.record_id))
                else:
                    self._log_transaction(record, oracle_state="ENFORCED")

        Args:
            target:  Immutable knowledge about the target API.
            context: Mutable state accumulated during the assessment.
            client:  Centralized HTTP client. Never import httpx directly.
            store:   Evidence buffer for FAIL and pinned transactions.

        Returns:
            A TestResult with status PASS, FAIL, SKIP, or ERROR.
        """

    # ------------------------------------------------------------------
    # Transaction log — audit trail
    # ------------------------------------------------------------------

    def _log_transaction(
        self,
        record: EvidenceRecord,
        *,
        oracle_state: str | None = None,
        is_fail: bool = False,
        duration_ms: float | None = None,
    ) -> None:
        """
        Append a TransactionSummary to the per-test audit trail.

        Must be called after every SecurityClient.request() call, regardless
        of outcome. The accumulated trail is automatically included in the
        TestResult returned by any _make_* method.

        No entry count cap is applied. The hybrid TransactionSummary model
        (~860 bytes with airbag body previews) keeps even high-volume test
        impact bounded: 2000 entries (worst-case Test 4.1) add ~1.7 MB to
        the HTML report — still safe for all modern browsers.

        TransactionSummary.from_evidence_record() applies airbag truncation
        transparently: request_body is capped at 2 000 chars and
        response_body_preview at 1 000 chars. No truncation logic is
        needed here — the factory method handles it entirely.
        Full payloads for FAIL transactions remain in EvidenceRecord /
        evidence.json for every is_fail=True transaction.

        Args:
            record:       EvidenceRecord returned by SecurityClient.request().
                          Used as the source for metadata extraction.
            oracle_state: Semantic label for this transaction's outcome.
                          Set this to the label that best describes what the
                          response means for the security control under test.
                          Examples: 'ENFORCED' (401/403 on protected path),
                          'BYPASS' (2xx without credentials), 'RATE_LIMIT_HIT'
                          (429 during probe loop), 'CORRECTLY_DENIED' (404 on
                          nonexistent path), 'SUNSET_MISSING' (deprecated endpoint
                          active without Sunset header), 'INCONCLUSIVE_PARAMETRIC'
                          (404 expected due to placeholder resource ID).
                          None when no semantic classification applies.
            is_fail:      True if store.add_fail_evidence(record) was also called
                          for this transaction. The HTML report highlights these
                          entries and displays: "Full transaction in evidence.json
                          → {record_id}". The caller is responsible for calling
                          store.add_fail_evidence() separately — this method only
                          updates the audit log.
            duration_ms:  Per-request timing in milliseconds when relevant
                          (e.g., timeout enforcement tests). None otherwise.
        """
        summary = TransactionSummary.from_evidence_record(
            record=record,
            is_fail=is_fail,
            oracle_state=oracle_state,
            duration_ms=duration_ms,
        )
        self._transaction_log.append(summary)

        log.debug(
            "transaction_logged",
            test_id=self.__class__.test_id,
            record_id=record.record_id,
            status_code=record.response_status_code,
            oracle_state=oracle_state,
            is_fail=is_fail,
            log_size_after=len(self._transaction_log),
        )

    # ------------------------------------------------------------------
    # Metadata injection — shared by all _make_* helpers
    # ------------------------------------------------------------------

    def _metadata_kwargs(self) -> _MetadataKwargs:
        """
        Build the metadata keyword arguments dict for TestResult construction.

        This is the single point where ClassVar metadata is read from the
        concrete subclass and packaged for injection into TestResult. All
        _make_* helpers call this method, ensuring consistent and centralised
        population of the metadata fields.

        The 'strategy' value is stored as a string (TestStrategy.value) rather
        than the enum instance because TestResult.strategy is typed as str.
        This avoids a Pydantic coercion on every result construction.

        Returns:
            _MetadataKwargs TypedDict with all six metadata fields populated.
        """
        return _MetadataKwargs(
            test_name=str(getattr(self.__class__, "test_name", "")),
            domain=int(getattr(self.__class__, "domain", -1)),
            priority=int(getattr(self.__class__, "priority", 0)),
            strategy=str(getattr(self.__class__, "strategy", TestStrategy.BLACK_BOX).value),
            tags=list(getattr(self.__class__, "tags", [])),
            cwe_id=str(getattr(self.__class__, "cwe_id", "")),
        )

    # ------------------------------------------------------------------
    # Result constructors — reduce boilerplate in concrete implementations
    # ------------------------------------------------------------------

    def _make_pass(self, message: str, notes: list[InfoNote] | None = None) -> TestResult:
        """
        Construct a TestResult(status=PASS) with no findings.

        Includes the full transaction_log accumulated so far. The log is
        copied (not referenced) so that any subsequent _log_transaction()
        call after _make_pass() — which would be a programming error but
        is technically possible — does not mutate the returned TestResult.

        The optional ``notes`` parameter allows PASS results to carry
        informational annotations (InfoNote objects) that document
        architectural context, compensating controls, or observability gaps
        without these constituting security findings. Notes are rendered in
        blue in the HTML report and are NOT counted in finding totals.

        Args:
            message: One-line summary of what was verified and confirmed.
            notes:   Optional list of InfoNote objects to attach. Pass None
                     (the default) or an empty list when no annotation is needed.

        Returns:
            TestResult with status=PASS, empty findings, the provided notes
            (or an empty list), and the full transaction_log accumulated
            during execute().
        """
        return TestResult(
            test_id=self.test_id,
            status=TestStatus.PASS,
            message=message,
            findings=[],
            notes=list(notes) if notes else [],
            transaction_log=list(self._transaction_log),
            **self._metadata_kwargs(),
        )

    def _make_fail(
        self,
        message: str,
        detail: str,
        evidence_record_id: str | None = None,
        additional_references: list[str] | None = None,
    ) -> TestResult:
        """
        Construct a TestResult(status=FAIL) with a single Finding.

        The Finding uses the test's declared cwe_id as the primary reference
        and any additional_references provided. All metadata ClassVar fields
        and the accumulated transaction_log are automatically propagated.

        Usage note:
            Call store.add_fail_evidence(record) BEFORE calling _make_fail().
            Pass record.record_id as evidence_record_id so the Finding.evidence_ref
            links to the correct EvidenceRecord in evidence.json.

            Also call self._log_transaction(record, oracle_state=..., is_fail=True)
            BEFORE calling _make_fail() to include the transaction in the audit trail.
            The is_fail=True flag will cause the HTML report to highlight that entry
            and show the cross-reference to evidence.json.

        Args:
            message:              One-line summary of the violated guarantee.
            detail:               Technical description, specific enough to reproduce.
            evidence_record_id:   record_id of the EvidenceRecord stored via
                                  store.add_fail_evidence(). None for WHITE_BOX
                                  configuration audit findings with no HTTP transaction.
            additional_references: Extra standard references appended after cwe_id.

        Returns:
            TestResult with status=FAIL, exactly one Finding, and the
            transaction_log accumulated during execute().
        """
        references: list[str] = [self.cwe_id]
        if additional_references:
            references.extend(additional_references)

        finding = Finding(
            title=self.test_name,
            detail=detail,
            references=references,
            evidence_ref=evidence_record_id,
        )

        return TestResult(
            test_id=self.test_id,
            status=TestStatus.FAIL,
            message=message,
            findings=[finding],
            transaction_log=list(self._transaction_log),
            **self._metadata_kwargs(),
        )

    def _make_skip(self, reason: str) -> TestResult:
        """
        Construct a TestResult(status=SKIP) with an explicit reason.

        SKIP communicates that the test was not executed for a known, expected
        reason rather than an unexpected failure. All metadata ClassVar fields
        and the (typically empty) transaction_log are included.

        Note: SKIP guard clauses at the top of execute() fire before any HTTP
        request is made, so transaction_log is almost always empty for SKIP
        results. Including it maintains a consistent API across all _make_* methods.

        Args:
            reason: Human-readable explanation of why the test was skipped.

        Returns:
            TestResult with status=SKIP, skip_reason populated, and the
            (usually empty) transaction_log.
        """
        return TestResult(
            test_id=self.test_id,
            status=TestStatus.SKIP,
            message=reason,
            skip_reason=reason,
            transaction_log=list(self._transaction_log),
            **self._metadata_kwargs(),
        )

    def _make_error(self, exc: Exception) -> TestResult:
        """
        Construct a TestResult(status=ERROR) from an unexpected exception.

        Designed for the outermost try/except block in execute(). Converts any
        unhandled exception into a structured ERROR result so it does not
        propagate to the engine. All metadata fields and the partial
        transaction_log (entries logged before the exception occurred) are
        automatically included.

        Including the partial transaction_log in ERROR results is diagnostically
        valuable: it shows which HTTP interactions had already completed before
        the exception, helping identify the failure point.

        Args:
            exc: The unhandled exception caught in execute().

        Returns:
            TestResult with status=ERROR, a diagnostic message, and the
            partial transaction_log accumulated before the exception.
        """
        exc_type = type(exc).__name__
        exc_message = str(exc)

        _max_message_length: int = 500
        truncated_message = (
            exc_message[:_max_message_length] + "... [TRUNCATED]"
            if len(exc_message) > _max_message_length
            else exc_message
        )

        log.error(
            "test_unexpected_exception",
            test_id=self.test_id,
            exc_type=exc_type,
            exc_message=truncated_message,
            transaction_log_entries_before_error=len(self._transaction_log),
            traceback=traceback.format_exc(),
        )

        return TestResult(
            test_id=self.test_id,
            status=TestStatus.ERROR,
            message=f"Unexpected {exc_type} during test execution: {truncated_message}",
            transaction_log=list(self._transaction_log),
            **self._metadata_kwargs(),
        )

    # ------------------------------------------------------------------
    # Guard clauses — early SKIP returns for precondition failures
    # ------------------------------------------------------------------

    def _requires_token(
        self,
        context: TestContext,
        role: str,
    ) -> TestResult | None:
        """
        Guard clause: return a SKIP result if the required token is absent.

        Canonical usage:
            skip = self._requires_token(context, ROLE_USER_A)
            if skip is not None:
                return skip
            token = context.get_token(ROLE_USER_A)

        Args:
            context: The current TestContext.
            role:    The role whose token is required. Use ROLE_* constants.

        Returns:
            None if the token is present (test may proceed).
            TestResult(status=SKIP) if the token is absent.
        """
        if context.has_token(role):
            return None

        role_display = _ROLE_DISPLAY_NAMES.get(role, role)
        return self._make_skip(
            reason=(
                f"No JWT token available for role '{role_display}' in TestContext. "
                f"The prerequisite authentication test that acquires this token "
                f"did not run, returned SKIP, or returned ERROR. "
                f"Ensure Domain 1 authentication tests are included in the "
                f"execution scope (min_priority >= 0) and completed successfully."
            )
        )

    def _requires_attack_surface(self, target: TargetContext) -> TestResult | None:
        """
        Guard clause: return a SKIP result if the AttackSurface is absent.

        Args:
            target: The current TargetContext.

        Returns:
            None if attack_surface is present.
            TestResult(status=SKIP) if attack_surface is None.
        """
        if target.attack_surface is not None:
            return None

        return self._make_skip(
            reason=(
                "AttackSurface is not available in TargetContext. "
                "This indicates Phase 2 (OpenAPI Discovery) did not complete "
                "successfully before this test was invoked. "
                "This is an infrastructure error; the pipeline should have been "
                "aborted during Phase 2."
            )
        )

    def _requires_grey_box_credentials(self, target: TargetContext) -> TestResult | None:
        """
        Guard clause: return a SKIP result if no Grey Box credentials are configured.

        Distinguishes 'no credentials configured' (SKIP) from 'credentials present
        but login failed' (ERROR). Called at the top of GREY_BOX execute() methods
        before any token acquisition attempt.

        Args:
            target: The current TargetContext.

        Returns:
            None if at least one role has complete credentials.
            TestResult(status=SKIP) if no credentials are configured.
        """
        if target.credentials.has_any_grey_box_credentials():
            return None

        return self._make_skip(
            reason=(
                "No Grey Box credentials configured: config.yaml credentials section "
                "is empty or all credential pairs are missing. "
                "GREY_BOX tests require at least one role with complete "
                "username + password to acquire tokens via the Forgejo API. "
                "Set ADMIN_USERNAME/ADMIN_PASSWORD or USER_A_USERNAME/USER_A_PASSWORD "
                "environment variables and re-run to enable Grey Box testing."
            )
        )

    def _requires_admin_api(self, target: TargetContext) -> TestResult | None:
        """
        Guard clause: return a SKIP result if the Admin API is not configured.

        Used by all WHITE_BOX tests (P3) that query the Kong Admin API.
        A DB-less Kong without Admin API is often an intentional security choice,
        not a gap — SKIP communicates this honestly.

        Args:
            target: The current TargetContext.

        Returns:
            None if admin_api_url is configured.
            TestResult(status=SKIP) if admin_api_url is None.
        """
        if target.admin_api_available:
            return None

        return self._make_skip(
            reason=(
                "Admin API not configured: target.admin_api_url is absent from "
                "config.yaml. This WHITE_BOX test requires read access to the "
                "Kong Admin API to perform configuration audit. "
                "Set target.admin_api_url (e.g., http://localhost:8001) to enable. "
                "If the Gateway is in DB-less mode without Admin API, this SKIP "
                "is expected and correct."
            )
        )

    # ------------------------------------------------------------------
    # Discovery metadata validation
    # ------------------------------------------------------------------

    @classmethod
    def has_required_metadata(cls) -> bool:
        """
        Check whether all required ClassVar metadata attributes are declared.

        Called by TestRegistry on each discovered subclass before adding it
        to the active test set.

        Returns:
            True if all required attributes are present with non-empty values.
            False otherwise.
        """
        required_attrs = (
            "test_id",
            "priority",
            "strategy",
            "depends_on",
            "test_name",
            "domain",
            "tags",
            "cwe_id",
        )
        for attr in required_attrs:
            if not hasattr(cls, attr):
                return False
        test_id_val = getattr(cls, "test_id", "")
        test_name_val = getattr(cls, "test_name", "")
        if not isinstance(test_id_val, str) or not test_id_val.strip():
            return False
        if not isinstance(test_name_val, str) or not test_name_val.strip():
            return False
        return True

    def __repr__(self) -> str:
        test_id = getattr(self.__class__, "test_id", "unknown")
        test_name = getattr(self.__class__, "test_name", "unknown")
        return f"{self.__class__.__name__}(test_id={test_id!r}, name={test_name!r})"

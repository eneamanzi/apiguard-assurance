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
from typing import ClassVar, Literal, TypedDict, cast

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
# Module-level constants
# ---------------------------------------------------------------------------

# Maximum length of an exception message included in a TestResult(ERROR).
# Messages beyond this length are truncated to keep evidence.json bounded.
_ERROR_MESSAGE_MAX_CHARS: int = 500

# Suffix appended to truncated exception messages.  Defined here as a named
# constant to avoid duplicating the literal across _make_error() and any
# future callers.  Intentionally NOT imported from core.models.http to avoid
# coupling tests/base.py to a private constant in a sibling package.
_ERROR_TRUNCATION_SUFFIX: str = "... [TRUNCATED]"

# ---------------------------------------------------------------------------
# Internal type aliases
# ---------------------------------------------------------------------------


class _MetadataKwargs(TypedDict):
    """
    Static type hint for ``**kwargs`` unpacking in ``_metadata_kwargs()``.

    Pydantic v2 is the project standard for data structures validated at runtime.
    This TypedDict is an intentional, documented exception:

        - It is a **static annotation only** -- no runtime validation occurs.
        - It exists exclusively to let Pylance/mypy verify that every
          ``_make_*`` helper receives the correct keyword arguments when
          ``**self._metadata_kwargs()`` is unpacked into ``TestResult(...)``.
        - Pydantic BaseModel cannot serve this role for ``**kwargs`` unpacking
          patterns: a BaseModel instance cannot be unpacked into ``**``.

    If you see this class and think "should this be a Pydantic model?" -- the
    answer is no.  Do not refactor it without re-reading this docstring first.
    """

    test_name: str
    domain: int
    priority: int
    strategy: str
    tags: list[str]
    cwe_id: str
    source: Literal["native", "external"]


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
            # source defaults to "native"; ExternalToolTest subclasses override
            # this ClassVar to "external" so the report builder can partition results.
            # cast() is used instead of str() because getattr() returns Any, but the
            # value is always one of the two valid literals (enforced by ClassVar
            # declarations in BaseTest and ExternalToolTest). cast() tells Pylance
            # the type without a runtime call that would widen str to a plain str.
            source=cast(Literal["native", "external"], getattr(self.__class__, "source", "native")),
        )

    # ------------------------------------------------------------------
    # Result constructors — reduce boilerplate in concrete implementations
    # ------------------------------------------------------------------
    #
    # PATTERN GUIDE — when to use a helper vs. TestResult() directly
    # ---------------------------------------------------------------
    # Always prefer a _make_* helper. Use TestResult() directly ONLY
    # when you need to produce multiple Finding objects in a single FAIL
    # result, because _make_fail() wraps exactly one Finding by design.
    #
    # PASS (zero findings):
    #   -> _make_pass(message, notes=None)
    #   NEVER use TestResult(status=PASS, findings=[]) directly. The helper
    #   already calls list(self._transaction_log) and **self._metadata_kwargs()
    #   so omitting it loses the audit trail or requires duplicating boilerplate.
    #
    # FAIL with exactly one Finding (the common single-check case):
    #   -> _make_fail(message, detail, evidence_record_id, additional_references)
    #   The helper constructs the Finding internally using self.cwe_id as
    #   the primary reference and the test_name as the title.
    #
    # FAIL with multiple Findings (multi-check loop, one Finding per violation):
    #   -> _make_fail_multi(message, findings, notes=None)
    #   The caller builds each Finding individually and passes the list here.
    #   The helper handles test_id, status, transaction_log, metadata_kwargs.
    #
    #   Tests that follow this pattern (as of this writing):
    #       test_0_1 (Shadow API — one Finding per undocumented endpoint)
    #       test_0_2 (Deny-by-Default — one Finding per path violation)
    #       test_0_3 (Deprecated API — one Finding per violation type)
    #       test_1_1 (Auth Required — one Finding per bypass detected)
    #       test_1_5 (TLS Transport — one Finding per audit category)
    #       test_1_6 (Session Management — one Finding per cookie attribute)
    #       test_3_3 (HMAC Config — one Finding per misconfiguration)
    #       test_4_1 (Rate Limiting — one Finding per check result)
    #       test_4_2 (Timeout Audit — one Finding per service violation)
    #       test_4_3 (Circuit Breaker — one Finding per level outcome)
    #       test_6_2 (Security Headers — one Finding per header category)
    #       test_6_4 (Hardcoded Credentials — one Finding per exposure)
    #
    # SKIP:
    #   -> _make_skip(reason, notes=None)
    #   The optional notes parameter attaches InfoNote objects to a SKIP result.
    #   Useful when the test cannot run but the report should still surface a
    #   recommendation (e.g. test_3_3 HMAC audit skips with a manual-check note).
    #
    # ERROR (unexpected exception — always inside except block):
    #   -> _make_error(exc)
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
        notes: list[InfoNote] | None = None,
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

        The optional ``notes`` parameter allows a FAIL result to carry
        informational annotations (InfoNote objects) alongside the Finding.
        This is semantically correct when a test simultaneously identifies a
        confirmed violation (Finding) and ambiguous observations that do not
        reach the FAIL threshold on their own (InfoNote).  Without this
        parameter, callers were forced to build TestResult(...) directly and
        omit notes silently (as seen in test_7_2_ssrf_prevention.py before
        this fix), losing the timeout/coverage-gap annotations from the report.

        Args:
            message:               One-line summary of the violated guarantee.
            detail:                Technical description, specific enough to reproduce.
            evidence_record_id:    record_id of the EvidenceRecord stored via
                                   store.add_fail_evidence(). None for WHITE_BOX
                                   configuration audit findings with no HTTP
                                   transaction.
            additional_references: Extra standard references appended after cwe_id.
            notes:                 Optional list of InfoNote objects for informational
                                   context below the FAIL threshold.  None (default)
                                   produces an empty notes list.

        Returns:
            TestResult with status=FAIL, exactly one Finding, the provided
            notes (or an empty list), and the transaction_log accumulated
            during execute().
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
            notes=list(notes) if notes else [],
            transaction_log=list(self._transaction_log),
            **self._metadata_kwargs(),
        )

    def _make_fail_multi(
        self,
        message: str,
        findings: list[Finding],
        notes: list[InfoNote] | None = None,
    ) -> TestResult:
        """
        Construct a TestResult(status=FAIL) with a pre-built list of Findings.

        Use this helper when a single test execution produces more than one
        Finding (e.g. one Finding per endpoint violation found in a probe loop).
        For the common single-violation case use _make_fail() instead, which
        builds the Finding internally from message/detail/cwe_id.

        Unlike _make_fail(), the caller is responsible for constructing each
        Finding individually (with its own title, detail, references, and
        evidence_ref) before passing the list here.  This helper only handles
        the boilerplate fields that every FAIL result must carry: test_id,
        status, transaction_log, and the metadata kwargs.

        Precondition:
            findings must be non-empty.  Passing an empty list produces a
            TestResult(FAIL) with no findings, which violates the model_validator
            invariant and will raise a Pydantic ValidationError.  The caller is
            responsible for ensuring the list contains at least one Finding.

        Args:
            message:  One-line summary of the test outcome (e.g. "N violation(s)
                      detected across M endpoint(s).").
            findings: Pre-built list of Finding objects, one per violation.
            notes:    Optional list of InfoNote objects for informational context
                      below the FAIL threshold. None (default) produces an empty
                      notes list.

        Returns:
            TestResult with status=FAIL, the provided findings, the provided
            notes (or an empty list), and the transaction_log accumulated
            during execute().
        """
        return TestResult(
            test_id=self.test_id,
            status=TestStatus.FAIL,
            message=message,
            findings=findings,
            notes=list(notes) if notes else [],
            transaction_log=list(self._transaction_log),
            **self._metadata_kwargs(),
        )

    def _make_skip(
        self,
        reason: str,
        notes: list[InfoNote] | None = None,
    ) -> TestResult:
        """
        Construct a TestResult(status=SKIP) with an explicit reason.

        SKIP communicates that the test was not executed for a known, expected
        reason rather than an unexpected failure. All metadata ClassVar fields
        and the (typically empty) transaction_log are included.

        Note: SKIP guard clauses at the top of execute() fire before any HTTP
        request is made, so transaction_log is almost always empty for SKIP
        results. Including it maintains a consistent API across all _make_* methods.

        The optional ``notes`` parameter supports attaching contextual
        :class:`InfoNote` objects to a SKIP result.  This is useful when the
        test cannot run (e.g. a feature is not configured) but the report
        should still surface a recommendation or manual-verification guidance
        to the reader — as in the HMAC audit (3.3), where a SKIP carries a
        note explaining what the assessor should verify by hand.

        Args:
            reason: Human-readable explanation of why the test was skipped.
            notes:  Optional list of :class:`InfoNote` objects to include in
                    the result for contextual guidance. Defaults to ``None``
                    (no notes attached).

        Returns:
            TestResult with status=SKIP, skip_reason populated, optional notes,
            and the (usually empty) transaction_log.
        """
        return TestResult(
            test_id=self.test_id,
            status=TestStatus.SKIP,
            message=reason,
            skip_reason=reason,
            notes=notes or [],
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

        truncated_message = (
            exc_message[:_ERROR_MESSAGE_MAX_CHARS] + _ERROR_TRUNCATION_SUFFIX
            if len(exc_message) > _ERROR_MESSAGE_MAX_CHARS
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
        Guard clause: return a SKIP result if no gateway adapter is configured.

        Used by all WHITE_BOX tests (P3) that query the gateway admin plane.
        A gateway without admin access is often an intentional security choice,
        not a gap — SKIP communicates this honestly.

        Args:
            target: The current TargetContext.

        Returns:
            None if a gateway adapter is configured (target.gateway is not None).
            TestResult(status=SKIP) if target.gateway is None.
        """
        if target.admin_api_available:
            return None

        return self._make_skip(
            reason=(
                "Gateway adapter not configured: target.gateway_adapter is absent "
                "from config.yaml. This WHITE_BOX test requires read access to the "
                "gateway admin API to perform configuration audit. "
                "Set target.gateway_adapter (e.g. 'kong') and target.admin_api_url "
                "(e.g. http://localhost:8001) to enable. "
                "If the gateway does not expose an admin API, this SKIP is expected."
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

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
       these attributes at discovery time; tests with missing attributes are
       logged as WARNING and excluded from execution.

    2. execute() must always return a TestResult. It must never raise an
       exception. Any exception that escapes execute() is a contract violation.
       The engine is not required to handle exceptions from execute() — it
       will propagate them unhandled, causing the pipeline to abort.

    3. A TestResult(status=FAIL) must contain at least one Finding.
       This invariant is enforced by TestResult's model_validator, not here.

    4. A test that calls store.add_fail_evidence(record) must NOT also call
       store.pin_evidence(record) on the same EvidenceRecord instance.
       This contract is documented here and enforced by convention, not by
       code, because enforcing it programmatically would require the store to
       track record identities across calls, adding complexity without value.

Dependency rule:
    This module imports from stdlib, structlog, abc, and src.core only.
    It must never import from config/, discovery/, report/, or engine.py.
    Test subclasses import from src.tests.base and src.core; they must not
    import from other test modules to avoid coupling between domains.
"""

from __future__ import annotations

import traceback
from abc import ABC, abstractmethod
from typing import ClassVar

import structlog

from src.core.client import SecurityClient
from src.core.context import ROLE_ADMIN, ROLE_USER_A, ROLE_USER_B, TargetContext, TestContext
from src.core.evidence import EvidenceStore
from src.core.models import Finding, TestResult, TestStatus, TestStrategy

log: structlog.BoundLogger = structlog.get_logger(__name__)

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

# Sentinel value used in _requires_token() skip_reason messages.
# Avoids hardcoding role names in the method body.
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
        3. Ensure execute() never raises — all exceptions must be caught
           internally and returned as TestResult(status=ERROR).

    Naming convention for concrete subclass files (required by TestRegistry):
        src/tests/domain_{X}/test_{X}_{Y}_{description}.py

    Where X is the domain number (0-7), Y is the sequential test number
    within the domain, and description is a snake_case identifier.
    Example: src/tests/domain_1/test_1_2_jwt_signature_validation.py

    ClassVar attributes (inspected by TestRegistry at discovery time):

        test_id: str
            Unique test identifier matching the methodology numbering.
            Format: '{domain}.{sequence}', e.g. '1.2'.
            Must be unique across the entire test suite.

        priority: int
            Execution priority level, 0 (most critical) to 3 (least critical).
            Maps to P0-P3 in the methodology matrix.
            TestRegistry filters tests with priority > config.execution.min_priority.

        strategy: TestStrategy
            Execution privilege level (BLACK_BOX, GREY_BOX, WHITE_BOX).
            TestRegistry filters tests whose strategy is not in
            config.execution.strategies.

        depends_on: list[str]
            List of test_id values that must execute before this test.
            DAGScheduler uses this to build the topological execution order.
            Empty list means no prerequisites.

        test_name: str
            Human-readable name of the security guarantee being verified.
            Used as the test title in the HTML report.

        domain: int
            Domain number (0-7) matching the methodology chapter.
            Used for grouping in the HTML report.

        tags: list[str]
            Categorical labels for filtering and reporting.
            Convention: include at least one OWASP reference if applicable.
            Example: ['authentication', 'OWASP-API2:2023', 'RFC-8725']

        cwe_id: str
            Primary CWE identifier for the vulnerability class this test
            verifies. Used in Finding.references automatically by _make_fail().
            Example: 'CWE-287'
    """

    # ------------------------------------------------------------------
    # Required ClassVar metadata — must be declared on every subclass.
    # Types are ClassVar to prevent Pydantic from treating them as fields
    # if a subclass also inherits from BaseModel (not our pattern, but defensive).
    # ------------------------------------------------------------------

    test_id: ClassVar[str]
    priority: ClassVar[int]
    strategy: ClassVar[TestStrategy]
    depends_on: ClassVar[list[str]]
    test_name: ClassVar[str]
    domain: ClassVar[int]
    tags: ClassVar[list[str]]
    cwe_id: ClassVar[str]

    # ------------------------------------------------------------------
    # Abstract method — the only obligation of a concrete subclass
    # ------------------------------------------------------------------

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

        This method is the single obligation of every concrete BaseTest
        subclass. The engine calls it once per test per pipeline run,
        passing the four shared infrastructure objects.

        INVARIANT: this method must ALWAYS return a TestResult.
        It must NEVER raise an exception. Any exception that escapes
        execute() is a contract violation that will abort the pipeline.
        Use _make_error() in a top-level try/except to catch unexpected
        exceptions and convert them to TestResult(status=ERROR).

        Recommended structure for a concrete execute() implementation:

            def execute(self, target, context, client, store) -> TestResult:
                try:
                    # Optional: check prerequisites.
                    skip = self._requires_token(context, ROLE_USER_A)
                    if skip is not None:
                        return skip

                    # Test logic here.
                    response, record = client.request(
                        method="GET",
                        path="/api/v1/users/me",
                        test_id=self.test_id,
                    )

                    if response.status_code != 401:
                        store.add_fail_evidence(record)
                        return self._make_fail(
                            message="Unauthenticated access to protected endpoint.",
                            evidence_record=record,
                            detail=(
                                f"GET /api/v1/users/me without Authorization header "
                                f"returned HTTP {response.status_code}. "
                                f"Expected: HTTP 401 Unauthorized."
                            ),
                        )

                    return self._make_pass(
                        message="Protected endpoint correctly rejects unauthenticated requests."
                    )

                except Exception as exc:
                    return self._make_error(exc)

        Args:
            target: Immutable knowledge about the target API, including the
                    AttackSurface and connection parameters. Never modified.
            context: Mutable state accumulated during the assessment, including
                     JWT tokens from Domain 1 tests and the teardown registry.
            client: Centralized HTTP client. Use client.request() for all HTTP
                    traffic. Never import httpx directly in a test module.
            store: Evidence buffer. Call store.add_fail_evidence(record) for
                   FAIL evidence and store.pin_evidence(record) for key setup
                   transactions. Never call both methods on the same record.

        Returns:
            A TestResult with status PASS, FAIL, SKIP, or ERROR.
            FAIL results must contain at least one Finding (enforced by
            TestResult's model_validator).
        """

    # ------------------------------------------------------------------
    # Helper methods — reduce boilerplate in concrete implementations
    # ------------------------------------------------------------------

    def _make_pass(self, message: str) -> TestResult:
        """
        Construct a TestResult(status=PASS) with no findings.

        Args:
            message: One-line summary of what was verified and confirmed.
                     Example: "JWT signature validation correctly rejects alg:none tokens."

        Returns:
            TestResult with status=PASS and empty findings list.
        """
        return TestResult(
            test_id=self.test_id,
            status=TestStatus.PASS,
            message=message,
            findings=[],
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

        The Finding is populated with the test's declared cwe_id and any
        additional references provided. This helper covers the most common
        case: one FAIL result, one Finding, one evidence record.

        For tests that detect multiple violations in a single execution
        (e.g., BOLA on multiple endpoints), construct multiple Finding
        objects manually and use TestResult() directly.

        The caller is responsible for calling store.add_fail_evidence(record)
        BEFORE calling _make_fail(). The record_id passed here is used only
        to populate Finding.evidence_ref for the report linkage.

        Args:
            message: One-line summary of the violated guarantee.
                     Example: "JWT alg:none bypass accepted by the server."
            detail: Technical description of the observed evidence, specific
                    enough for an analyst to reproduce without the tool.
                    Example: "POST /api/v1/users/tokens returned HTTP 200
                    with a JWT bearing alg=none and empty signature. Expected 401."
            evidence_record_id: The record_id of the EvidenceRecord already
                                 stored in the EvidenceStore via add_fail_evidence().
                                 Populates Finding.evidence_ref. None for WHITE_BOX
                                 audit findings that produce no HTTP transaction.
            additional_references: Extra standard references beyond cwe_id.
                                    Example: ['OWASP-API2:2023', 'RFC-8725'].
                                    cwe_id is always included automatically.

        Returns:
            TestResult with status=FAIL and exactly one Finding.
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
        )

    def _make_skip(self, reason: str) -> TestResult:
        """
        Construct a TestResult(status=SKIP) with an explicit reason.

        SKIP is a semantically distinct outcome from ERROR: it communicates
        that the test was not executed for a known, expected reason (missing
        prerequisite, inapplicable condition) rather than an unexpected failure.

        Args:
            reason: Human-readable explanation of why the test was skipped.
                    Must be specific enough to distinguish this SKIP from
                    others in the report.
                    Example: "Admin API not configured. Set target.admin_api_url
                    in config.yaml to enable WHITE_BOX tests."

        Returns:
            TestResult with status=SKIP and skip_reason populated.
        """
        return TestResult(
            test_id=self.test_id,
            status=TestStatus.SKIP,
            message=reason,
            skip_reason=reason,
        )

    def _make_error(self, exc: Exception) -> TestResult:
        """
        Construct a TestResult(status=ERROR) from an unexpected exception.

        This method is designed to be called from the outermost try/except
        block in execute(). It converts any unhandled exception into a
        structured ERROR result, preventing the exception from propagating
        to the engine and aborting the pipeline.

        The exception type and a truncated traceback are included in the
        message for diagnostics. The full traceback is emitted to the
        structured log at ERROR level. Sensitive data from the exception
        message is not redacted here: if a test produces an exception whose
        message contains a credential, that is a bug in the test, not in
        this helper.

        Args:
            exc: The unhandled exception caught in execute().

        Returns:
            TestResult with status=ERROR and a diagnostic message.
        """
        exc_type = type(exc).__name__
        exc_message = str(exc)

        # Truncate to avoid unbounded message lengths in the report.
        max_message_length = 500
        truncated_message = (
            exc_message[:max_message_length] + "... [TRUNCATED]"
            if len(exc_message) > max_message_length
            else exc_message
        )

        # Emit the full traceback to the structured log for debugging.
        # The report only shows the truncated one-liner.
        log.error(
            "test_unexpected_exception",
            test_id=self.test_id,
            exc_type=exc_type,
            exc_message=truncated_message,
            traceback=traceback.format_exc(),
        )

        return TestResult(
            test_id=self.test_id,
            status=TestStatus.ERROR,
            message=(f"Unexpected {exc_type} during test execution: {truncated_message}"),
        )

    def _requires_token(
        self,
        context: TestContext,
        role: str,
    ) -> TestResult | None:
        """
        Guard clause: return a SKIP result if the required token is absent.

        Call this at the start of execute() for any Grey Box test that needs
        a JWT token. If the token is present, the method returns None and
        execution continues. If absent, it returns a TestResult(SKIP) that
        the caller should return immediately.

        Canonical usage pattern:

            skip = self._requires_token(context, ROLE_USER_A)
            if skip is not None:
                return skip
            # Token is guaranteed present from here.
            token = context.get_token(ROLE_USER_A)

        The token absence is a SKIP, not an ERROR: it indicates that the
        prerequisite Domain 1 test did not run or did not produce a token,
        which is a known and expected condition when running a scoped
        assessment (e.g., P0 only, or after a Domain 1 test returned SKIP).

        Args:
            context: The current TestContext.
            role: The role whose token is required.
                  Use ROLE_* constants from src.core.context.

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
                f"Ensure the Domain 1 authentication tests are included in the "
                f"execution scope (min_priority >= 0) and completed successfully."
            )
        )

    def _requires_attack_surface(
        self,
        target: TargetContext,
    ) -> TestResult | None:
        """
        Guard clause: return a SKIP result if the AttackSurface is absent.

        In normal pipeline execution, attack_surface is always populated by
        Phase 2 before any test runs. This guard exists for edge cases where
        TargetContext is constructed in tests without a surface (e.g., during
        development of a new test module before the full pipeline is wired).

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
                "This indicates that Phase 2 (OpenAPI Discovery) did not complete "
                "successfully before this test was invoked. "
                "This is an infrastructure error; the pipeline should have been "
                "aborted during Phase 2."
            )
        )

    def _requires_admin_api(
        self,
        target: TargetContext,
    ) -> TestResult | None:
        """
        Guard clause: return a SKIP result if the Admin API is not configured.

        Used by all WHITE_BOX tests (P3) that query the Kong Admin API for
        configuration audit. If admin_api_url is absent from config.yaml,
        these tests skip gracefully rather than failing.

        This is consistent with Implementazione.md Section 6.1:
        a DB-less Kong without Admin API is often an intentional security
        choice, not a gap. SKIP communicates this honestly.

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
                "Set target.admin_api_url (e.g., http://localhost:8001) to "
                "enable this test. If the Gateway is deployed in DB-less mode "
                "without Admin API, this SKIP is expected and correct."
            )
        )

    # ------------------------------------------------------------------
    # Metadata validation helper — used by TestRegistry
    # ------------------------------------------------------------------

    @classmethod
    def has_required_metadata(cls) -> bool:
        """
        Check whether all required ClassVar metadata attributes are declared.

        TestRegistry calls this on each discovered subclass before adding it
        to the active test set. A subclass that inherits from BaseTest but
        does not declare all required attributes is a development-time error
        (incomplete implementation), not a runtime error.

        Returns:
            True if all required attributes are present with non-empty values.
            False otherwise. TestRegistry logs a WARNING for False results.
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
        # Verify that test_id and test_name are non-empty strings.
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

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

    4. Metadata propagation: every _make_* helper method populates the
       metadata fields of the returned TestResult (test_name, domain,
       priority, strategy, tags, cwe_id) by copying from the ClassVar
       declarations of the concrete subclass. This ensures that builder.py
       receives a fully self-contained record without importing from tests/.

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
from src.core.models import Finding, TestResult, TestStatus, TestStrategy

log: structlog.BoundLogger = structlog.get_logger(__name__)

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------


class _MetadataKwargs(TypedDict):
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
        3. Ensure execute() never raises — all exceptions must be caught
           internally and returned as TestResult(status=ERROR).

    Naming convention for concrete subclass files (required by TestRegistry):
        src/tests/domain_{X}/test_{X}_{Y}_{description}.py

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

        Args:
            target: Immutable knowledge about the target API.
            context: Mutable state accumulated during the assessment.
            client: Centralized HTTP client. Use client.request() for all HTTP
                    traffic. Never import httpx directly in a test module.
            store: Evidence buffer.

        Returns:
            A TestResult with status PASS, FAIL, SKIP, or ERROR.
        """

    # ------------------------------------------------------------------
    # Metadata injection helper — used by all _make_* methods
    # ------------------------------------------------------------------

    def _metadata_kwargs(self) -> _MetadataKwargs:
        """
        Build the metadata keyword arguments dict for TestResult construction.

        This is the single point where ClassVar metadata is read from the
        concrete subclass and packaged for injection into TestResult. All
        _make_* helpers call this method, ensuring consistent and centralized
        population of the metadata fields.

        The 'strategy' value is stored as a string (TestStrategy.value) rather
        than the enum instance because TestResult.strategy is typed as str.
        This avoids a Pydantic coercion on every result construction.

        Returns:
            Dict of keyword arguments covering all metadata fields on TestResult.
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
    # Helper methods — reduce boilerplate in concrete implementations
    # ------------------------------------------------------------------

    def _make_pass(self, message: str) -> TestResult:
        """
        Construct a TestResult(status=PASS) with no findings.

        All metadata ClassVar fields (test_name, domain, priority, strategy,
        tags, cwe_id) are automatically copied from the subclass declaration
        into the returned TestResult via _metadata_kwargs().

        Args:
            message: One-line summary of what was verified and confirmed.

        Returns:
            TestResult with status=PASS and empty findings list.
        """
        return TestResult(
            test_id=self.test_id,
            status=TestStatus.PASS,
            message=message,
            findings=[],
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

        The Finding is populated with the test's declared cwe_id and any
        additional references provided. All metadata ClassVar fields are
        automatically propagated.

        The caller is responsible for calling store.add_fail_evidence(record)
        BEFORE calling _make_fail(). The record_id passed here is used only
        to populate Finding.evidence_ref for the report linkage.

        Args:
            message: One-line summary of the violated guarantee.
            detail: Technical description of the observed evidence.
            evidence_record_id: The record_id of the EvidenceRecord already
                                 stored via store.add_fail_evidence(). None for
                                 WHITE_BOX audit findings with no HTTP transaction.
            additional_references: Extra standard references beyond cwe_id.

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
            **self._metadata_kwargs(),
        )

    def _make_skip(self, reason: str) -> TestResult:
        """
        Construct a TestResult(status=SKIP) with an explicit reason.

        SKIP communicates that the test was not executed for a known, expected
        reason rather than an unexpected failure. All metadata ClassVar fields
        are automatically propagated.

        Args:
            reason: Human-readable explanation of why the test was skipped.

        Returns:
            TestResult with status=SKIP and skip_reason populated.
        """
        return TestResult(
            test_id=self.test_id,
            status=TestStatus.SKIP,
            message=reason,
            skip_reason=reason,
            **self._metadata_kwargs(),
        )

    def _make_error(self, exc: Exception) -> TestResult:
        """
        Construct a TestResult(status=ERROR) from an unexpected exception.

        Designed to be called from the outermost try/except block in execute().
        Converts any unhandled exception into a structured ERROR result,
        preventing the exception from propagating to the engine. All metadata
        ClassVar fields are automatically propagated.

        Args:
            exc: The unhandled exception caught in execute().

        Returns:
            TestResult with status=ERROR and a diagnostic message.
        """
        exc_type = type(exc).__name__
        exc_message = str(exc)

        max_message_length = 500
        truncated_message = (
            exc_message[:max_message_length] + "... [TRUNCATED]"
            if len(exc_message) > max_message_length
            else exc_message
        )

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
            **self._metadata_kwargs(),
        )

    def _requires_token(
        self,
        context: TestContext,
        role: str,
    ) -> TestResult | None:
        """
        Guard clause: return a SKIP result if the required token is absent.

        Canonical usage pattern:

            skip = self._requires_token(context, ROLE_USER_A)
            if skip is not None:
                return skip
            token = context.get_token(ROLE_USER_A)

        Args:
            context: The current TestContext.
            role: The role whose token is required. Use ROLE_* constants.

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

        Used by all WHITE_BOX tests (P3) that query the Kong Admin API.
        A DB-less Kong without Admin API is often an intentional security choice,
        not a gap. SKIP communicates this honestly.

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

    @classmethod
    def has_required_metadata(cls) -> bool:
        """
        Check whether all required ClassVar metadata attributes are declared.

        TestRegistry calls this on each discovered subclass before adding it
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

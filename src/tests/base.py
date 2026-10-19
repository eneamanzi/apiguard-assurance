"""
src/tests/base.py

BaseTest: the base of every native test (a test that sends its own HTTP requests).

Every native test is a concrete subclass of BaseTest in
src/tests/domain_<D>/test_<D>_<N>_<name>.py: it declares who it is in
``info = TestInfo(...)`` and implements execute(); TestRegistry discovers it,
nothing else lists it. What every test has (the declaration, the _make_*
result helpers) comes from AssessmentTest (src/core/assessment_test.py);
BaseTest adds what is native: the execute() signature with the HTTP client,
the transaction log, the guard clauses and the gateway concept helpers.

Contract:

    1. execute() must always return a TestResult. It must never raise.
       Any exception that escapes execute() is a contract violation — the
       engine is not required to handle it and will abort the pipeline.

    2. A TestResult(status=FAIL) must contain at least one Finding.
       Enforced by TestResult's model_validator, not here.

    3. Every result carries the declaration (AssessmentTest) and the
       transaction log: the log accumulates via _log_transaction() during
       execute() and is included whichever exit path the test takes (PASS,
       FAIL, SKIP, or ERROR).

_log_transaction() calling convention:
    After every client.request() call, the test must call _log_transaction()
    to record the interaction in the audit trail. The method accepts the
    oracle_state so the test can annotate the semantic meaning of the
    response (e.g. 'ENFORCED', 'BYPASS', 'RATE_LIMIT_HIT') independently
    of the HTTP status code.

    Pattern:
        response, record = client.request(method, path, test_id=self.info.id)

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

from abc import abstractmethod
from typing import Any, ClassVar, Literal

import structlog

from src.core.assessment_test import AssessmentTest, ParamsT
from src.core.client import SecurityClient
from src.core.context import TargetContext, TestContext
from src.core.evidence import EvidenceStore
from src.core.gateway.concepts import ConceptRead, ConceptStatus
from src.core.models import EvidenceRecord, TestResult, TransactionSummary

log: structlog.BoundLogger = structlog.get_logger(__name__)

# Label prefix of the evidence artifact of a gateway concept read by a test
# (e.g. "gateway_backend_timeouts").
_GATEWAY_CONCEPT_LABEL_PREFIX: str = "gateway_"


# ---------------------------------------------------------------------------
# BaseTest
# ---------------------------------------------------------------------------


class BaseTest(AssessmentTest[ParamsT]):
    """
    Abstract base class of the native tests.

    Concrete subclasses must:
        1. Declare ``info = TestInfo(...)`` (src/core/test_metadata.py).
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

    """

    # Origin of the results, fixed: must not be overridden.
    source: ClassVar[Literal["native", "external"]] = "native"

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
                        method="GET", path=path, test_id=self.info.id
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
        Add a request to the test's audit trail (transaction_log in the report): call it
        after every client.request().

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
            test_id=self.info.id,
            record_id=record.record_id,
            status_code=record.response_status_code,
            oracle_state=oracle_state,
            is_fail=is_fail,
            log_size_after=len(self._transaction_log),
        )

    def _result_transactions(self) -> list[TransactionSummary]:
        """
        The transaction log every result of this test carries (AssessmentTest).

        Returns:
            A copy, so that a later _log_transaction() (a programming error)
            cannot change a result already returned.
        """
        return list(self._transaction_log)

    # ------------------------------------------------------------------
    # Guard clauses — early SKIP returns for precondition failures
    # ------------------------------------------------------------------

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

    def _record_gateway_concept(
        self,
        target: TargetContext,
        store: EvidenceStore,
        concept: str,
        answer: ConceptRead[Any],
    ) -> str:
        """
        Store the answer of a gateway concept as evidence of this test.

        The audit tests read the gateway through its neutral concepts
        (src/core/gateway/concepts.py) and keep what they read as their proof:
        the answer is serialized with the adapter's name and pinned as an
        artifact. Secret values are SecretStr and appear only as '**********';
        their location and key stay visible, which is the proof that a secret
        is there. Not supported and not accessible answers are stored too:
        they are the proof of why the test could not judge.

        Args:
            target:  The current TargetContext (target.gateway must be set).
            store:   The EvidenceStore of the current test.
            concept: The concept's name (CONCEPT_* constant of
                     src/core/gateway/base.py).
            answer:  The adapter's answer for that concept.

        Returns:
            The evidence record id, for the Finding.evidence_ref of the findings
            based on this concept.
        """
        adapter_name = target.gateway.adapter_name if target.gateway is not None else "none"
        payload: dict[str, Any] = {
            "adapter": adapter_name,
            "concept": concept,
            **answer.model_dump(mode="json"),
        }
        label = _GATEWAY_CONCEPT_LABEL_PREFIX + concept.replace(" ", "_")
        return store.pin_artifact(label, payload)

    def _skip_for_concept(
        self,
        concept: str,
        answer: ConceptRead[Any],
        evidence_ref: str,
    ) -> TestResult:
        """
        Return the SKIP of a test that cannot judge a gateway concept.

        Called when the adapter answered "not supported" or "not accessible"
        for a concept the test needs (owner decision, block 7+8): the reason
        says which, so that "not applicable to this gateway" and "not
        verifiable" stay distinguishable in the report.

        Args:
            concept:      The concept's name (CONCEPT_* constant).
            answer:       The adapter's answer (status other than READ).
            evidence_ref: Evidence record of the answer (_record_gateway_concept).

        Returns:
            TestResult(status=SKIP) with the reason.
        """
        why = (answer.reason or "").rstrip(". ")
        if answer.status == ConceptStatus.NOT_SUPPORTED:
            reason = f"Not applicable to this gateway: {concept}: {why}."
        else:
            reason = f"Not verifiable: no access to {concept}: {why}."
        return self._make_skip(reason=f"{reason} Evidence: {evidence_ref}.")

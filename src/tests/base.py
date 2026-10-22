"""
src/tests/base.py

BaseTest: the base of every native test (a test that sends its own HTTP requests).

Every native test is a concrete subclass of BaseTest in
src/tests/domain_<D>/test_<D>_<N>_<name>.py: it declares who it is in
``info = TestInfo(...)`` (with its sub-tests) and implements execute();
TestRegistry discovers it, nothing else lists it. What every test has (the
declaration, the judgements, the judgement of an HTTP response, the
transaction log, the computed result) comes from AssessmentTest
(src/core/assessment_test.py); BaseTest adds what is native: the execute()
signature with the HTTP client and the gateway concept helpers.

Contract:

    1. execute() must always return a TestResult. It must never raise: its
       top-level ``except Exception`` returns self._error(exc).
    2. Every response the test sends is either judged or a preparation step:

           response, record = client.request(method, path, test_id=self.info.id)
           if category_of(record) == ResponseCategory.SERVED:   # the test's oracle
               self._judge(record, store, "unauthenticated_access",
                           Outcome.VIOLATION, "AUTH_BYPASS",
                           finding=Finding(title=..., detail=...))
           else:
               self._judge(record, store, "unauthenticated_access",
                           Outcome.ENFORCED, "AUTH_REQUIRED")
           ...
           return self._finish()

       _judge() stores the evidence of a VIOLATION and points the finding to
       it; _step(record) logs a request that is not judged (a login, an
       object created for the test). Both, and category_of(), are in
       src/core/assessment_test.py, shared with the external tests.
    3. Every result carries the declaration and the transaction log, whichever
       exit the test takes (_finish, _skip, _error).

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
from src.core.models import TestResult

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
        1. Declare ``info = TestInfo(...)`` (src/core/test_metadata.py), with
           its sub-tests.
        2. Implement the execute() method.
        3. Judge every response with self._judge(), or log it as a preparation
           step with self._step().
        4. Ensure execute() never raises: all exceptions are caught and
           returned as self._error(exc).

    Instance-level state: AssessmentTest.__init__ starts the tally of the
    sub-tests and the transaction log, instance variables, so each test
    instance keeps its own; TestRegistry creates each test class once and the
    engine calls execute() once per instance.
    """

    # Origin of the results, fixed: must not be overridden.
    source: ClassVar[Literal["native", "external"]] = "native"

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

        INVARIANT: this method must ALWAYS return a TestResult. It must NEVER
        raise: a top-level ``except Exception`` returns self._error(exc).

        Args:
            target:  Immutable knowledge about the target API.
            context: Mutable state accumulated during the assessment.
            client:  Centralized HTTP client. Never import httpx directly.
            store:   Evidence buffer for FAIL and pinned transactions.

        Returns:
            self._finish() when the test ran to the end, self._skip(reason)
            when something it needs is missing, self._error(exc) on an
            exception.
        """

    # ------------------------------------------------------------------
    # Gateway concepts
    # ------------------------------------------------------------------

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
        return self._skip(reason=f"{reason} Evidence: {evidence_ref}.")

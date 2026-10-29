"""
src/external_tests/ext_test_3_1_input_validation_schemathesis.py

Test ext.3.1.schemathesis: the input-validation part of guarantee 3.1, driven
by Schemathesis. CWE-20, OWASP ASVS v5.0.0-2.2.1,
NIST SP 800-53 Rev.5 SI-10. The OWASP API Top 10 2023 has no category for
the validation of a client's input: API10:2023 is the API's trust in data it
consumes from third-party APIs, which this test does not exercise.

Schemathesis generates valid and invalid requests from the OpenAPI
specification and checks that the server rejects the invalid ones (a 4xx), does
not answer with a 500 on them, and keeps its responses conformant to the schema.
We launch it, point it at the specification, and judge its findings (rule 11):
an operation Schemathesis flags is one whose input is not validated.

    input_validated  no operation fails Schemathesis's checks -> ENFORCED;
                     each failing operation -> VIOLATION (its input is not
                     validated: a 500 on a bad input, or an invalid input
                     accepted, or a non-conformant response).

It runs unauthenticated (no credential injected): the write requests it
generates are refused, so nothing is created; effect STRESSES_TARGET (many
generated requests), run last. The deep injection confirmation (sqlmap,
NoSQLMap, Dalfox, commix) and an authenticated run are not planned, so a
validation gap behind the credential is outside what this test reports.

Dependency rule:
    Imports from stdlib, structlog, src.connectors, src.core,
    src.external_tests.base.
    Must never import from tests/, config/, discovery/, report/, engine.py.
"""

from __future__ import annotations

import structlog

from src.connectors.base import BaseConnector, ConnectorResult
from src.connectors.schemathesis import SchemathesisConnector
from src.core.context import TargetContext
from src.core.models import (
    Confidence,
    Finding,
    Outcome,
    Reference,
    Standard,
    TestResult,
    TestStrategy,
)
from src.core.test_metadata import Effect, TestInfo
from src.external_tests.base import ExternalToolTest, ToolRun

log: structlog.BoundLogger = structlog.get_logger(__name__)

_SUB: str = "input_validated"

# How many failing operations to report as findings (the rest are summarised).
_MAX_FINDINGS: int = 20

_REFERENCES: tuple[Reference, ...] = (
    Reference(standard=Standard.ASVS, id="v5.0.0-2.2.1"),
    Reference(standard=Standard.NIST_SP, id="800-53r5", section="3.19"),
)


class ExtTest31InputValidationSchemathesis(ExternalToolTest):
    """
    Test ext.3.1.schemathesis -- input validation, driven by Schemathesis.

    The oracle is in the module docstring and on the test page.
    """

    info = TestInfo(
        id="ext.3.1.schemathesis",
        name="Input Validation (Schemathesis)",
        priority=2,
        strategy=TestStrategy.BLACK_BOX,
        cwe="CWE-20",
        references=_REFERENCES,
        tags=("input-validation", "injection", "fuzzing"),
        tool="schemathesis",
        effect=Effect.STRESSES_TARGET,
        sub_tests=(_SUB,),
    )

    def _build_connector(self) -> BaseConnector:
        """Instantiate a fresh SchemathesisConnector (no I/O)."""
        return SchemathesisConnector()

    def _invoke_connector(
        self,
        connector: BaseConnector,
        target: TargetContext,
        target_url: str,
    ) -> ConnectorResult:
        """
        Run Schemathesis against the specification, unauthenticated.

        Args:
            connector:  The SchemathesisConnector.
            target:     The run's target (spec source, tls, tool config).
            target_url: The base URL (target.endpoint_base_url()).

        Returns:
            The connector's result (the failing operations).
        """
        cfg = target.external_tools.schemathesis
        timeout_seconds: int = cfg.timeout_seconds  # type: ignore[assignment]
        assert isinstance(connector, SchemathesisConnector)
        return connector.run(
            target_url=target_url,
            timeout_seconds=timeout_seconds,
            schema_source=target.get_openapi_source(),
            ca_bundle=target.tls_ca_bundle,
            max_examples=cfg.max_examples,
        )

    def _evaluate(self, result: ConnectorResult, run: ToolRun) -> TestResult:
        """
        Map Schemathesis's failing operations to the oracle.

        Args:
            result: The connector's result (raw_output['results']).
            run:    The evaluation context (artifact_ref for the findings' proof).

        Returns:
            self._finish(): ENFORCED when nothing failed, a VIOLATION per failing
            operation otherwise.
        """
        failures: list[dict[str, str]] = result.raw_output.get("results", [])
        if not failures:
            self._record(_SUB, Outcome.ENFORCED, "INPUT_VALIDATED")
            return self._finish(message="Schemathesis found no unvalidated input.")
        for failure in failures[:_MAX_FINDINGS]:
            operation = str(failure.get("id", "unknown operation"))
            detail = str(failure.get("finding", "a check failed")).replace("\n", " ")[:300]
            self._record(
                _SUB,
                Outcome.VIOLATION,
                "INPUT_NOT_VALIDATED",
                Finding(
                    title=f"Input not validated: {operation}",
                    detail=(
                        f"Schemathesis found that {operation} does not validate its input: "
                        f"{detail}. A generated request caused a server error (500), an invalid "
                        "input was accepted, or the response did not match the schema "
                        "(CWE-20, ASVS v5.0.0-2.2.1, NIST SP 800-53 Rev.5 SI-10). Validate "
                        "every input against its type, format, range and pattern before the "
                        "business logic."
                    ),
                    confidence=Confidence.FIRM,
                    evidence_ref=run.artifact_ref,
                ),
            )
        if len(failures) > _MAX_FINDINGS:
            log.info(
                "ext_test_3_1_more_failures",
                reported=_MAX_FINDINGS,
                total=len(failures),
            )
        return self._finish(
            message=f"Schemathesis flagged {len(failures)} operation(s) with unvalidated input."
        )

"""
src/external_tests/ext_test_3_1_input_validation_schemathesis.py

Test ext.3.1.schemathesis: the input-validation part of guarantee 3.1, driven
by Schemathesis. CWE-20, OWASP ASVS v5.0.0-2.2.1,
NIST SP 800-53 Rev.5 SI-10. The OWASP API Top 10 2023 has no category for
the validation of a client's input: API10:2023 is the API's trust in data it
consumes from third-party APIs, which this test does not exercise.

Schemathesis generates valid and invalid requests from the OpenAPI
specification and checks that none makes the server answer with a 5xx: an input
that reaches code unable to handle it. Two other checks are not run (owner
decisions 2026-11-04): whether the responses match the specification (the
documentation, not the input), and whether every invalid input is rejected
(on Forgejo it reported endpoints without parameters for ignoring a nameless
extra one, which an HTTP server may do).
We launch it, point it at the specification, and judge its findings (rule 11):
an operation Schemathesis flags is one whose input is not validated.

    input_validated  no operation fails Schemathesis's checks -> ENFORCED;
                     each failing operation -> VIOLATION (its input is not
                     handled: a 5xx on a generated input).

It runs unauthenticated (no credential injected). The requests it generates
include the writes the specification declares: on a target that requires a
credential for them nothing is created, which is the case on the three labs
(every operation served without a credential there is a GET), but on an API
with an unauthenticated write that write is exercised. The effect stays
STRESSES_TARGET, the last slot of the run order: the vocabulary has no value
for "stresses and may write", and an operator who cannot accept that disables
the external tools. The deep injection confirmation (sqlmap,
NoSQLMap, Dalfox, commix) and an authenticated run are not planned, so a
validation gap behind the credential is outside what this test reports.

Dependency rule:
    Imports from stdlib, structlog, src.connectors, src.core,
    src.external_tests.base.
    Must never import from tests/, config/, discovery/, report/, engine.py.
"""

from __future__ import annotations

import re

import structlog

from src.connectors.base import BaseConnector, ConnectorResult
from src.connectors.schemathesis import SchemathesisConnector
from src.core.context import ROLE_USER_A, TargetContext, TestContext
from src.core.models import (
    Confidence,
    Finding,
    InfoNote,
    Outcome,
    Reference,
    Standard,
    TestResult,
    TestStrategy,
)
from src.core.test_metadata import Effect, Need, TestInfo
from src.external_tests.base import ExternalToolTest, ToolRun

log: structlog.BoundLogger = structlog.get_logger(__name__)

_SUB: str = "input_validated"

# How many failing operations to report as findings (the rest are summarised).
_MAX_FINDINGS: int = 20

# The statuses that mean the gateway could not reach the backend (RFC 9110:
# 502 Bad Gateway, 503 Service Unavailable, 504 Gateway Timeout).
_UNAVAILABLE_STATUSES: frozenset[str] = frozenset({"502", "503", "504"})
# How Schemathesis quotes a response status in a failure message: "[503]".
_QUOTED_STATUS: re.Pattern[str] = re.compile(r"\[(\d{3})\]")
# A failure message lists its failing test cases, each opening with "N. Test
# Case ID:" and ending with "Reproduce with: curl ...".
_TEST_CASE_START: re.Pattern[str] = re.compile(r"(?=\b\d+\. Test Case ID:)")
_REPRODUCE: re.Pattern[str] = re.compile(r"Reproduce with:\s*(curl\b.*)", re.DOTALL)
# What an authenticated run tests: reads only, which change nothing on the target.
_AUTHENTICATED_METHODS: tuple[str, ...] = ("GET",)
# What replaces user_a's credential in the tool's output.
_CREDENTIAL_LABEL: str = "[REDACTED: user_a token]"
# Added to the message of a run with the credential.
_READS_ONLY: str = (
    "Reads only, with user_a's credential: writes were not sent, because with a valid credential "
    "they would create, change or delete data the tool cannot clean up."
)
# What the result says about the run it judged.
_AUTHENTICATED_NOTE: InfoNote = InfoNote(
    title="Run with user_a's credential, reads only",
    detail=(
        "Schemathesis sent user_a's credential and tested GET only: the operations that need a "
        "credential were reached, and no write was sent, since a generated write with a valid "
        "credential would change data the tool cannot clean up. Writes are not tested."
    ),
)
_ANONYMOUS_NOTE: InfoNote = InfoNote(
    title="Run without a credential",
    detail=(
        "No user_a credential was configured, or it travels in the query, which Schemathesis "
        "cannot add: every method ran unauthenticated, so the operations that need a credential "
        "were not reached (ONLY_4XX)."
    ),
)
# How a finding is titled: the one check run (not_a_server_error).
_FINDING_TITLE: str = "Server error on a generated input"
# How much of a test case's description the finding quotes (its first lines:
# the check that failed and the answer), before its reproduction.
_CASE_SUMMARY_CHARS: int = 200
# How much of a reproduction command it quotes (a generated body can be long;
# the artifact keeps it whole).
_COMMAND_CHARS: int = 1000

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
        # user_a's credential, when configured, lets Schemathesis reach the
        # operations that need one, GET only (owner decision 2026-11-04).
        optional_needs=(Need.USER_ACCOUNT,),
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
        context: TestContext,
    ) -> ConnectorResult:
        """
        Run Schemathesis against the specification, with user_a's credential when there is one.

        With the credential (in a header or a cookie) only GET is tested: a
        generated write with a valid credential would create, change or delete
        data the tool cannot clean up; the operator's resources (path_seed) then
        fill the path parameters. Without it, or with a credential placed
        in the query (Schemathesis has no option for it), every method runs
        unauthenticated, as before. The credential is redacted from everything
        the tool returns before the result leaves this method: the artifact's
        copy in tools/ is written at once, and its reproduction commands may
        quote a header Schemathesis does not filter.

        Args:
            connector:  The SchemathesisConnector.
            target:     The run's target (spec source, tls, tool config).
            target_url: The base URL (target.endpoint_base_url()).
            context:    The run's context (user_a's credential, when configured).

        Returns:
            The connector's result, raw_output['authenticated'] saying which run it was.
        """
        token = context.get_token(ROLE_USER_A) if context.has_token(ROLE_USER_A) else None
        placement = target.credential_placement
        parts = placement.request_parts(token) if token and placement is not None else None
        authenticated = parts is not None and not parts.params
        cfg = target.external_tools.schemathesis
        timeout_seconds: int = cfg.timeout_seconds  # type: ignore[assignment]
        assert isinstance(connector, SchemathesisConnector)
        # Schemathesis takes its base path from the base URL and drops the
        # specification's own (basePath '/api/v1' on Forgejo): without it every
        # generated request missed the API and answered 404.
        surface = target.attack_surface
        base_path = surface.base_path if surface is not None else ""
        result = connector.run(
            target_url=target_url.rstrip("/") + base_path,
            timeout_seconds=timeout_seconds,
            schema_source=target.get_openapi_source(),
            ca_bundle=target.tls_ca_bundle,
            max_examples=cfg.max_examples,
            request_timeout_seconds=cfg.request_timeout_seconds,
            headers=dict(parts.headers) if parts is not None and authenticated else None,
            methods=_AUTHENTICATED_METHODS if authenticated else (),
            # The operator's resources (path_seed) fix the path parameters, so
            # that a read addresses an object that exists instead of a random
            # name answering 404. Only in the read-only run: in the other one a
            # generated DELETE would address them too.
            path_values=dict(target.path_seed) if authenticated else None,
        )
        raw = _redacted(result.raw_output, token) if token else result.raw_output
        assert isinstance(raw, dict)  # noqa: S101 -- _redacted keeps the shape of its input
        return result.model_copy(update={"raw_output": {**raw, "authenticated": authenticated}})

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
        authenticated = bool(result.raw_output.get("authenticated"))
        notes = [_AUTHENTICATED_NOTE if authenticated else _ANONYMOUS_NOTE]
        # Said in the message too, so that what a PASS covers is read at once.
        scope = f" {_READS_ONLY}" if authenticated else ""
        reported: list[dict[str, str]] = result.raw_output.get("results", [])
        unchecked: list[str] = result.raw_output.get("errored", [])
        operations: int = result.raw_output.get("operations", 0)
        # A test case quoting only 502/503/504 is the gateway reporting an
        # unavailable backend, not the API failing to validate (rule 1): on crAPI
        # 24 of 27 failures were Kong's 503 after its health check tripped. An
        # operation is judged on its other test cases; with none, it is
        # unavailable (a message mixed a 503 and a real case: 2026-11-04).
        failures: list[dict[str, str]] = []
        unavailable: list[dict[str, str]] = []
        for reported_failure in reported:
            cases = _usable_cases(reported_failure.get("finding", ""))
            if cases:
                failures.append({**reported_failure, "finding": cases})
            else:
                unavailable.append(reported_failure)
        for _ in unavailable:
            self._record(_SUB, Outcome.NOT_VERIFIABLE, "UPSTREAM_UNAVAILABLE")
        for _ in unchecked:
            self._record(_SUB, Outcome.NOT_VERIFIABLE, "OPERATION_NOT_CHECKED")
        # An operation whose every generated request got a 4xx was never reached
        # (on Forgejo a credential Schemathesis makes up answers 401): that no
        # input made it fail proves nothing (2026-11-04: 371 of 469 operations
        # were counted as checked on that basis).
        judged = {str(f.get("id")) for f in reported} | set(unchecked)
        only_4xx = [op for op in result.raw_output.get("only_4xx", []) if op not in judged]
        for _ in only_4xx:
            self._record(_SUB, Outcome.NOT_VERIFIABLE, "ONLY_4XX")
        if not failures:
            checked = operations - len(unavailable) - len(unchecked) - len(only_4xx)
            if checked <= 0:
                self._record(_SUB, Outcome.NOT_VERIFIABLE, "NOTHING_CHECKED")
                return self._finish(
                    notes=notes, message=f"Schemathesis checked no operation.{scope}"
                )
            self._record(_SUB, Outcome.ENFORCED, "INPUT_VALIDATED")
            return self._finish(
                notes=notes,
                message=(
                    f"No generated input made the server fail, in {checked} operation(s).{scope}"
                ),
            )
        for failure in failures[:_MAX_FINDINGS]:
            operation = str(failure.get("id", "unknown operation"))
            detail = str(failure.get("finding", "a check failed"))
            self._record(
                _SUB,
                Outcome.VIOLATION,
                "INPUT_NOT_VALIDATED",
                Finding(
                    title=f"{_FINDING_TITLE}: {operation}",
                    detail=(
                        f"Schemathesis found that {operation} answers a server error to a "
                        f"generated input: {detail}. The input reached code that does not handle "
                        "it, instead of being rejected with a 4xx (CWE-20, ASVS v5.0.0-2.2.1, "
                        "NIST SP 800-53 Rev.5 SI-10). Validate every input against its type, "
                        "format, range and pattern before the business logic."
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
            notes=notes,
            message=(
                f"{len(failures)} operation(s) answer a server error to a generated input.{scope}"
            ),
        )


def _redacted(value: object, secret: str) -> object:
    """A copy of the tool's output with every occurrence of the credential replaced."""
    if isinstance(value, str):
        return value.replace(secret, _CREDENTIAL_LABEL)
    if isinstance(value, dict):
        return {key: _redacted(item, secret) for key, item in value.items()}
    if isinstance(value, list):
        return [_redacted(item, secret) for item in value]
    return value


def _only_unavailable(message: str) -> bool:
    """Whether every status a test case quotes is an unavailable backend."""
    statuses = set(_QUOTED_STATUS.findall(message))
    return bool(statuses) and statuses <= _UNAVAILABLE_STATUSES


def _usable_cases(message: str) -> str:
    """
    The test cases of a failure that are not an unavailable backend, for the finding.

    Each case is quoted by its first characters (the check that failed and the
    answer) and its reproduction command, the proof a reader can run again.

    Args:
        message: Schemathesis's failure message for one operation.

    Returns:
        The usable cases, one sentence each; "" when every case quotes only
        502, 503 or 504 (or the message holds no case and only such statuses).
    """
    cases = [c.strip() for c in _TEST_CASE_START.split(message) if c.strip()]
    usable = [c for c in cases if not _only_unavailable(c)]
    quoted: list[str] = []
    for case in usable:
        reproduce = _REPRODUCE.search(case)
        head = case[: reproduce.start()] if reproduce else case
        summary = " ".join(head.split())[:_CASE_SUMMARY_CHARS]
        command = " ".join(reproduce.group(1).split())[:_COMMAND_CHARS] if reproduce else ""
        quoted.append(f"{summary} Reproduce with: {command}" if command else summary)
    return " / ".join(quoted)

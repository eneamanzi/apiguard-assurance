"""
src/core/assessment_test.py

AssessmentTest: what every test has, native and external alike.

A test declares who it is in one TestInfo (``info``, src/core/test_metadata.py)
and returns one TestResult. This base copies the declaration into every
result, collects the test's judgements and computes the result from them,
written once for both kinds of test (docs/04-architecture/05-design-decisions.md,
D8; docs/project/test-review.md, topic 3). The two subclasses keep what is theirs:

    BaseTest (src/tests/base.py)                  the HTTP client contract and
                                                  the transaction log;
    ExternalToolTest (src/external_tests/base.py) the tool, its connector and
                                                  its output.

The engine calls the two kinds through different execute() signatures, so
execute() is declared by each subclass, not here.

How a test ends:

    _record(sub_test, outcome, detail, finding=None)
        one judgement: the outcome of one case of a declared sub-test, with
        the test's detail (UPPER_SNAKE_CASE); a finding exactly when the
        outcome is VIOLATION. Native tests judge an HTTP response through
        BaseTest._judge(), which records it here.
    _finish(notes=None, message=None)
        the result, computed: per sub-test counters and status, the test's
        status and coverage (src/core/models/results.py), the findings, a
        summary message common to every test (the test may add a sentence).
        Nothing judged that applies: SKIP, "nothing the test applies to".
    _skip(reason, notes=None)
        SKIP before the start: something needed is missing.
    _error(exc, message=None)
        ERROR, in the test's top-level except block: the exception becomes
        the result (it never reaches the engine); the judgements made so far
        are kept.

A test never chooses PASS, FAIL or INCONCLUSIVE. A judgement written wrongly
(an undeclared sub-test, a VIOLATION without a finding, a malformed detail) is
a programming error: _record() raises ValueError, which the test's top-level
except turns into ERROR.

Parameters (docs/04-architecture/05-design-decisions.md, D8): a test with tunable values
names its parameter model in its class declaration,
``class Test21...(BaseTest[Test21Params])``; a test without parameters writes
``BaseTest`` alone. The engine validates ``tests.domain_<D>.test_<D>_<N>``
against that model once per run and the test reads its own values with
``self.params(target)``, typed as its model.

Dependency rule: imports only from the standard library, pydantic,
typing_extensions, structlog and src.core.
"""

from __future__ import annotations

import re
import traceback
from abc import ABC
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, ClassVar, Generic, Literal, cast, get_args, get_origin

import structlog
from pydantic import BaseModel, ConfigDict
from pydantic.config import JsonDict
from pydantic.fields import FieldInfo
from typing_extensions import TypeVar

from src.core.models import (
    Coverage,
    Finding,
    InfoNote,
    Outcome,
    SubTestResult,
    TestResult,
    TestStatus,
    TransactionSummary,
    combine_sub_tests,
)
from src.core.test_metadata import TestInfo

if TYPE_CHECKING:
    from src.core.context import TargetContext

log: structlog.BoundLogger = structlog.get_logger(__name__)

# Longest exception message kept in a TestResult(ERROR), so that
# evidence.json stays bounded; longer messages end with the suffix below.
_ERROR_MESSAGE_MAX_CHARS: int = 500
_ERROR_TRUNCATION_SUFFIX: str = "... [TRUNCATED]"

# The detail of a judgement, e.g. "AUTH_BYPASS": uppercase words joined by
# underscores, read with the outcome as "VIOLATION/AUTH_BYPASS".
DETAIL_PATTERN: re.Pattern[str] = re.compile(r"^[A-Z][A-Z0-9]*(_[A-Z0-9]+)*$")

# The skip reason of a test that ran but found nothing it applies to.
_NOTHING_TO_APPLY: str = "Nothing the test applies to"


@dataclass
class _SubTestTally:
    """What one sub-test has judged so far (the counters of a SubTestResult)."""

    violations: int = 0
    enforced: int = 0
    not_applicable: int = 0
    not_verifiable_reasons: dict[str, int] = field(default_factory=dict)


class NoParams(BaseModel):
    """The parameters of a test that has none: any key under it is unknown."""

    model_config = ConfigDict(frozen=True, extra="forbid")


# Key of the validation context of the tests' parameters holding
# config.resources (name -> ResourceConfig), for a parameter model that checks
# its values against the prepared resources (test 7.2): set by
# src/config/tests_section.py, absent when a model is built from defaults.
PARAMS_CONTEXT_RESOURCES: str = "resources"

# Marks a parameter whose value names a prepared resource (resources:), as
# Field(json_schema_extra=REFERS_TO_RESOURCE): validate-config lists the test as
# a user of that resource without the engine knowing the test.
REFERS_TO_RESOURCE: JsonDict = {"refers_to": "resources"}

# Marks a parameter the test cannot run without, as
# Field(json_schema_extra=NEEDED_TO_RUN): unset (None or empty), the engine
# records the test as SKIP naming the key, without running it
# (src/core/test_needs.py). Markers combine: json_schema_extra={**A, **B}.
NEEDED_TO_RUN: JsonDict = {"needed_to_run": True}


def has_marker(field: FieldInfo, marker: JsonDict) -> bool:
    """
    True when a parameter field carries a marker (REFERS_TO_RESOURCE, NEEDED_TO_RUN).

    Args:
        field:  A field of a parameter model.
        marker: The marker.

    Returns:
        Whether every item of the marker is in the field's json_schema_extra.
    """
    extra = field.json_schema_extra
    return isinstance(extra, dict) and all(extra.get(k) == v for k, v in marker.items())


# The parameter model of a test; NoParams when the class names none.
ParamsT = TypeVar("ParamsT", bound=BaseModel, default=NoParams)


class AssessmentTest(ABC, Generic[ParamsT]):
    """
    Base of every test: its declaration, its parameters and its results.

    Subclasses (BaseTest, ExternalToolTest) set ``source``; every concrete
    test sets ``info``. Test discovery (src/core/test_discovery.py) checks
    that each concrete test declares its own ``info`` of the right kind.
    """

    info: ClassVar[TestInfo]

    # The model named in the class declaration (BaseTest[Test21Params]);
    # None for a test without parameters. Set by __init_subclass__.
    params_model: ClassVar[type[BaseModel] | None] = None

    # Origin of the results, fixed by the two subclasses: the report builder
    # partitions results by it.
    source: ClassVar[Literal["native", "external"]]

    def __init_subclass__(cls, **kwargs: object) -> None:
        """Record the parameter model named in the class declaration, if any."""
        super().__init_subclass__(**kwargs)
        for base in getattr(cls, "__orig_bases__", ()):
            origin = get_origin(base)
            if isinstance(origin, type) and issubclass(origin, AssessmentTest):
                model = next(iter(get_args(base)), None)
                if isinstance(model, type) and issubclass(model, BaseModel):
                    cls.params_model = None if model is NoParams else model

    def __init__(self) -> None:
        """Start the test's tally: one empty entry per declared sub-test."""
        self._tally: dict[str, _SubTestTally] = {
            name: _SubTestTally() for name in self.info.sub_tests
        }
        self._findings: list[Finding] = []

    def params(self, target: TargetContext) -> ParamsT:
        """
        This test's parameters, validated from tests.domain_<D>.test_<D>_<N>.

        Args:
            target: The run's TargetContext, which holds every test's parameters.

        Returns:
            The instance of the model named in the class declaration (its
            defaults when config.yaml sets nothing).
        """
        return cast(ParamsT, target.test_params[self.info.id])

    # ------------------------------------------------------------------
    # Hooks of the subclasses
    # ------------------------------------------------------------------

    def _result_transactions(self) -> list[TransactionSummary]:
        """
        The transaction log a result carries.

        Returns:
            A copy of the log for a native test; empty for a test that sends
            no request of its own (external tools).
        """
        return []

    # ------------------------------------------------------------------
    # Result construction
    # ------------------------------------------------------------------

    def _record(
        self,
        sub_test: str,
        outcome: Outcome,
        detail: str,
        finding: Finding | None = None,
    ) -> None:
        """
        Record one judgement: the outcome of one case of a declared sub-test.

        Args:
            sub_test: A sub-test the test declares (info.sub_tests).
            outcome:  What the case means for the guarantee.
            detail:   The test's detail of the outcome, UPPER_SNAKE_CASE (for
                      NOT_VERIFIABLE it is the reason, counted in the result).
            finding:  The violation's finding: given exactly when the outcome is
                      VIOLATION, with its evidence_ref already set by the caller
                      (BaseTest._judge() sets it for an HTTP response).

        Raises:
            ValueError: An undeclared sub-test, a malformed detail, or a finding
                        given or missing against the outcome (a programming
                        error of the test, turned into ERROR by its except).
        """
        tally = self._tally.get(sub_test)
        if tally is None:
            raise ValueError(
                f"test {self.info.id}: sub-test {sub_test!r} is not declared "
                f"(info.sub_tests: {list(self.info.sub_tests)})"
            )
        if not DETAIL_PATTERN.match(detail):
            raise ValueError(f"test {self.info.id}: detail {detail!r} must be UPPER_SNAKE_CASE")
        if (finding is not None) != (outcome == Outcome.VIOLATION):
            raise ValueError(
                f"test {self.info.id}: a finding goes with a VIOLATION, and only with it "
                f"(got {outcome}/{detail} {'with' if finding else 'without'} a finding)"
            )
        if outcome == Outcome.VIOLATION:
            tally.violations += 1
            self._findings.append(cast(Finding, finding))
        elif outcome == Outcome.ENFORCED:
            tally.enforced += 1
        elif outcome == Outcome.NOT_APPLICABLE:
            tally.not_applicable += 1
        else:
            reasons = tally.not_verifiable_reasons
            reasons[detail] = reasons.get(detail, 0) + 1

    def _sub_test_results(self) -> list[SubTestResult]:
        """The result of every declared sub-test, in declaration order."""
        return [
            SubTestResult.from_counts(
                name,
                violations=tally.violations,
                enforced=tally.enforced,
                not_applicable=tally.not_applicable,
                not_verifiable_reasons=tally.not_verifiable_reasons,
            )
            for name, tally in self._tally.items()
        ]

    @staticmethod
    def _summary(sub_tests: list[SubTestResult]) -> str:
        """The common summary of the judgements, e.g. '2 violations, 67 enforced'."""
        totals = (
            (sum(s.violations for s in sub_tests), "violation", "violations"),
            (sum(s.enforced for s in sub_tests), "enforced", "enforced"),
            (sum(s.not_verifiable for s in sub_tests), "not verifiable", "not verifiable"),
            (sum(s.not_applicable for s in sub_tests), "not applicable", "not applicable"),
        )
        parts = [f"{n} {one if n == 1 else many}" for n, one, many in totals if n]
        return ", ".join(parts) or "nothing judged"

    def _finish(
        self, notes: list[InfoNote] | None = None, message: str | None = None
    ) -> TestResult:
        """
        The result of a test that ran to the end, computed from its judgements.

        Args:
            notes:   Informational annotations (any status).
            message: A sentence of the test's own, added after the common summary.

        Returns:
            TestResult with the computed status (PASS with its coverage, FAIL,
            INCONCLUSIVE, or SKIP when nothing judged applies), the sub-tests
            and the findings.
        """
        sub_tests = self._sub_test_results()
        status, coverage = combine_sub_tests(sub_tests)
        summary = self._summary(sub_tests)
        text = f"{summary}. {message}" if message else f"{summary}."
        skip_reason = f"{_NOTHING_TO_APPLY}: {text}" if status == TestStatus.SKIP else None
        return self._result(
            status,
            skip_reason or text,
            findings=self._findings,
            notes=notes,
            skip_reason=skip_reason,
            coverage=coverage,
            sub_tests=sub_tests,
        )

    def _skip(self, reason: str, notes: list[InfoNote] | None = None) -> TestResult:
        """
        SKIP before the start: something the test needs is missing.

        Args:
            reason: Why the test did not run, naming what is missing.
            notes:  Annotations still worth reporting (e.g. what to check by hand).

        Returns:
            TestResult with status SKIP.
        """
        return self._result(TestStatus.SKIP, reason, notes=notes, skip_reason=reason)

    def _error(self, exc: Exception, message: str | None = None) -> TestResult:
        """
        ERROR from an exception, for the except block of a test.

        The exception becomes the result and never reaches the engine. The
        judgements made before it are kept (sub-tests and findings), with the
        partial transaction log, to show where the test stopped.

        Args:
            exc:     The exception caught.
            message: The result message; by default the exception's type and
                     its message, truncated.

        Returns:
            TestResult with status ERROR.
        """
        exc_type = type(exc).__name__
        exc_message = str(exc)
        if len(exc_message) > _ERROR_MESSAGE_MAX_CHARS:
            exc_message = exc_message[:_ERROR_MESSAGE_MAX_CHARS] + _ERROR_TRUNCATION_SUFFIX
        log.error(
            "test_unexpected_exception",
            test_id=self.info.id,
            exc_type=exc_type,
            exc_message=exc_message,
            traceback=traceback.format_exc(),
        )
        return self._result(
            TestStatus.ERROR,
            message or f"Unexpected {exc_type} during test execution: {exc_message}",
            findings=self._findings,
            sub_tests=self._sub_test_results(),
        )

    def _result(
        self,
        status: TestStatus,
        message: str,
        *,
        findings: list[Finding] | None = None,
        notes: list[InfoNote] | None = None,
        skip_reason: str | None = None,
        coverage: Coverage | None = None,
        sub_tests: list[SubTestResult] | None = None,
    ) -> TestResult:
        """
        Build a result carrying this test's declaration.

        Args:
            status:      The outcome.
            message:     One-line summary of the outcome.
            findings:    The violations.
            notes:       Informational annotations, not findings.
            skip_reason: Why the test did not run (SKIP only).
            coverage:    Complete or partial (PASS only).
            sub_tests:   The sub-tests' results.

        Returns:
            The TestResult, with the declaration under its report names
            (test_id, test_name, domain, cwe_id, tool_name).
        """
        info = self.info
        return TestResult(
            test_id=info.id,
            status=status,
            message=message,
            findings=list(findings) if findings else [],
            notes=list(notes) if notes else [],
            skip_reason=skip_reason,
            coverage=coverage,
            sub_tests=list(sub_tests) if sub_tests else [],
            transaction_log=self._result_transactions(),
            test_name=info.name,
            domain=info.domain,
            priority=info.priority,
            strategy=info.strategy.value,
            tags=list(info.tags),
            cwe_id=info.cwe,
            tool_name=info.tool or "",
            source=self.source,
        )

    def __repr__(self) -> str:
        """Class name, test ID and name."""
        info = getattr(type(self), "info", None)
        if not isinstance(info, TestInfo):
            return f"{type(self).__name__}()"
        return f"{type(self).__name__}(id={info.id!r}, name={info.name!r})"

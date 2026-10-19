"""
src/core/assessment_test.py

AssessmentTest: what every test has, native and external alike.

A test declares who it is in one TestInfo (``info``, src/core/test_metadata.py)
and returns one TestResult. This base copies the declaration into every
result and builds the results (_make_pass, _make_fail, _make_fail_multi,
_make_skip, _make_error), written once for both kinds of test
(docs/architecture/design-decisions.md, D8). The two subclasses keep what is theirs:

    BaseTest (src/tests/base.py)                  the HTTP client contract and
                                                  the transaction log;
    ExternalToolTest (src/external_tests/base.py) the tool, its connector and
                                                  its output.

The engine calls the two kinds through different execute() signatures, so
execute() is declared by each subclass, not here.

Result helpers, when to use which:

    PASS:                    _make_pass(message, notes=None)
    FAIL with one finding:   _make_fail(message, detail, evidence_record_id,
                             additional_references, notes); the finding takes
                             the test's name as title and its CWE as first
                             reference.
    FAIL with several:       _make_fail_multi(message, findings, notes=None),
                             the caller builds each Finding.
    SKIP:                    _make_skip(reason, notes=None); notes can still
                             surface a recommendation (e.g. a manual check).
    ERROR:                   _make_error(exc, message=None), in an except
                             block: the exception becomes the result, it never
                             reaches the engine.

Parameters (docs/architecture/design-decisions.md, D8): a test with tunable values
names its parameter model in its class declaration,
``class Test21...(BaseTest[Test21Params])``; a test without parameters writes
``BaseTest`` alone. The engine validates ``tests.domain_<D>.test_<D>_<N>``
against that model once per run and the test reads its own values with
``self.params(target)``, typed as its model.

Dependency rule: imports only from the standard library, pydantic,
typing_extensions, structlog and src.core.
"""

from __future__ import annotations

import traceback
from abc import ABC
from typing import TYPE_CHECKING, ClassVar, Generic, Literal, cast, get_args, get_origin

import structlog
from pydantic import BaseModel, ConfigDict
from pydantic.config import JsonDict
from pydantic.fields import FieldInfo
from typing_extensions import TypeVar

from src.core.models import Finding, InfoNote, TestResult, TestStatus, TransactionSummary
from src.core.test_metadata import TestInfo

if TYPE_CHECKING:
    from src.core.context import TargetContext

log: structlog.BoundLogger = structlog.get_logger(__name__)

# Longest exception message kept in a TestResult(ERROR), so that
# evidence.json stays bounded; longer messages end with the suffix below.
_ERROR_MESSAGE_MAX_CHARS: int = 500
_ERROR_TRUNCATION_SUFFIX: str = "... [TRUNCATED]"


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

    def _result(
        self,
        status: TestStatus,
        message: str,
        *,
        findings: list[Finding] | None = None,
        notes: list[InfoNote] | None = None,
        skip_reason: str | None = None,
    ) -> TestResult:
        """
        Build a result carrying this test's declaration.

        Args:
            status:      The outcome.
            message:     One-line summary of the outcome.
            findings:    The violations (FAIL only).
            notes:       Informational annotations, not findings.
            skip_reason: Why the test did not run (SKIP only).

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

    def _make_pass(self, message: str, notes: list[InfoNote] | None = None) -> TestResult:
        """
        Construct a TestResult(status=PASS) with no findings.

        Args:
            message: One-line summary of what was verified and confirmed.
            notes:   Informational annotations (architectural context,
                     compensating controls, observability gaps); rendered in
                     the report, never counted as findings.

        Returns:
            TestResult with status PASS.
        """
        return self._result(TestStatus.PASS, message, notes=notes)

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

        The finding takes the test's name as title and its CWE as first
        reference. Store the evidence first (store.add_fail_evidence(record))
        and pass its record_id, so that the finding points to its proof.

        Args:
            message:               One-line summary of the violated guarantee.
            detail:                Technical description, specific enough to reproduce.
            evidence_record_id:    record_id of the stored evidence; None for a
                                   configuration audit finding with no transaction.
            additional_references: Extra standard references after the CWE.
            notes:                 Informational annotations below the FAIL threshold.

        Returns:
            TestResult with status FAIL and one finding.
        """
        references = [self.info.cwe, *(additional_references or [])]
        finding = Finding(
            title=self.info.name,
            detail=detail,
            references=references,
            evidence_ref=evidence_record_id,
        )
        return self._result(TestStatus.FAIL, message, findings=[finding], notes=notes)

    def _make_fail_multi(
        self,
        message: str,
        findings: list[Finding],
        notes: list[InfoNote] | None = None,
    ) -> TestResult:
        """
        Construct a TestResult(status=FAIL) with findings built by the caller.

        Precondition: findings is not empty (a FAIL without findings violates
        the TestResult invariant and raises a ValidationError).

        Args:
            message:  One-line summary (e.g. "N violation(s) across M endpoint(s).").
            findings: One Finding per violation, each with its own evidence_ref.
            notes:    Informational annotations below the FAIL threshold.

        Returns:
            TestResult with status FAIL and the given findings.
        """
        return self._result(TestStatus.FAIL, message, findings=findings, notes=notes)

    def _make_skip(self, reason: str, notes: list[InfoNote] | None = None) -> TestResult:
        """
        Construct a TestResult(status=SKIP) with its reason.

        Args:
            reason: Why the test did not run, naming what is missing.
            notes:  Annotations still worth reporting (e.g. what to check by hand).

        Returns:
            TestResult with status SKIP.
        """
        return self._result(TestStatus.SKIP, reason, notes=notes, skip_reason=reason)

    def _make_error(self, exc: Exception, message: str | None = None) -> TestResult:
        """
        Construct a TestResult(status=ERROR) from an exception.

        For the except blocks of a test: the exception becomes the result and
        never reaches the engine. The partial transaction log (requests sent
        before the exception) is kept, to show where the test stopped.

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
        )

    def __repr__(self) -> str:
        """Class name, test ID and name."""
        info = getattr(type(self), "info", None)
        if not isinstance(info, TestInfo):
            return f"{type(self).__name__}()"
        return f"{type(self).__name__}(id={info.id!r}, name={info.name!r})"

"""
src/core/test_metadata.py

TestInfo: the declaration of a test (who it is), native and external alike.

Every test class declares one TestInfo as its ``info`` class attribute
(docs/04-architecture/05-design-decisions.md, D8). It is a frozen Pydantic model, validated
when the test module is imported: an invalid declaration makes the import
fail, and test discovery (src/core/test_discovery.py) reports it as a
TestDefinitionError naming the module, so the run stops instead of dropping
the test or filling in defaults.

The same module holds the test ID formats and the priority range, which the
configuration schema imports to validate execution.test_ids and
execution.min_priority: each rule is written once.

Dependency rule: imports only from the standard library, pydantic, src.core.models and
src.core.response_category.
"""

from __future__ import annotations

import re
from enum import StrEnum
from typing import Annotated

from pydantic import (
    AfterValidator,
    BaseModel,
    ConfigDict,
    Field,
    StrictInt,
    ValidationError,
    model_validator,
)

from src.core.models import Confidence, Outcome, ResponseCategory, TestStrategy
from src.core.models.standards import CWE_ID_PATTERN, Reference, Standard, duplicate_references
from src.core.response_category import UNINFORMATIVE_CATEGORIES

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

# Priority range: P0 (critical) to P3 (compliance).
PRIORITY_MIN: int = 0
PRIORITY_MAX: int = 3

# Domain range of the methodology: domains 0 to 7.
DOMAIN_MIN: int = 0
DOMAIN_MAX: int = 7

# Prefix of external test IDs ("ext.1.5.testssl"): it keeps them apart from
# native IDs ("1.5") and routes an execution.test_ids entry to the external
# registry.
EXTERNAL_TEST_ID_PREFIX: str = "ext."

# Native test ID: "<domain>.<sequence>", e.g. "4.1".
NATIVE_TEST_ID_PATTERN: re.Pattern[str] = re.compile(r"^(?P<domain>\d+)\.\d+$")

# External test ID: "ext.<domain>.<sequence>.<tool>", e.g. "ext.1.5.testssl".
EXTERNAL_TEST_ID_PATTERN: re.Pattern[str] = re.compile(
    r"^" + re.escape(EXTERNAL_TEST_ID_PREFIX) + r"(?P<domain>\d+)\.\d+\.[A-Za-z0-9_-]+$"
)

# A test-module class whose name starts with this prefix is a helper base
# class shared by the tests of the module, not a test: the registries skip it
# and do not check its declaration (Python's convention for internal names).
PRIVATE_CLASS_PREFIX: str = "_"

# A tag: a topic in lowercase words joined by hyphens, e.g. "rate-limit". The
# standards a test cites are references, not tags: an uppercase standard
# identifier written as a tag ("OWASP-API4") does not match.
TAG_PATTERN: re.Pattern[str] = re.compile(r"^[a-z][a-z0-9]*(-[a-z0-9]+)*$")

# Name of a declared sub-test, e.g. "unauthenticated_access": lowercase words
# joined by underscores. It is the key of the sub-test in the result and the
# report, and the row of the "Coverage of the methodology" table of the page.
SUB_TEST_NAME_PATTERN: re.Pattern[str] = re.compile(r"^[a-z][a-z0-9]*(_[a-z0-9]+)*$")

# ---------------------------------------------------------------------------
# Test ID format
# ---------------------------------------------------------------------------


def is_valid_test_id(test_id: str) -> bool:
    """
    Return True if test_id has the native or the external format.

    Args:
        test_id: The candidate test ID.

    Returns:
        True for "X.Y" or "ext.X.Y.tool", False otherwise.
    """
    return bool(NATIVE_TEST_ID_PATTERN.match(test_id) or EXTERNAL_TEST_ID_PATTERN.match(test_id))


def is_external_test_id(test_id: str) -> bool:
    """
    Return True if test_id names an external test (prefix "ext.").

    Args:
        test_id: A test ID.

    Returns:
        True when test_id starts with EXTERNAL_TEST_ID_PREFIX.
    """
    return test_id.startswith(EXTERNAL_TEST_ID_PREFIX)


# Keys of a test's parameters in config.yaml: tests.<domain key>.<test key>.
_DOMAIN_KEY: str = "domain_{domain}"
_NATIVE_KEY_PREFIX: str = "test_"
_EXTERNAL_KEY_PREFIX: str = "ext_"


def section_keys(test_id: str) -> tuple[str, str]:
    """
    The keys of a test's parameters in the tests section.

    Args:
        test_id: A valid test ID ("2.1" or "ext.1.5.testssl").

    Returns:
        (domain key, test key), e.g. ("domain_2", "test_2_1").
    """
    external = is_external_test_id(test_id)
    parts = test_id.removeprefix(EXTERNAL_TEST_ID_PREFIX).split(".")
    prefix = _EXTERNAL_KEY_PREFIX if external else _NATIVE_KEY_PREFIX
    return _DOMAIN_KEY.format(domain=parts[0]), prefix + "_".join(parts)


# ---------------------------------------------------------------------------
# Needs
# ---------------------------------------------------------------------------


class Need(StrEnum):
    """
    What a test needs from the configuration.

    Only what the configuration tells before any contact with the target. A
    test declares a need either as required (TestInfo.needs: when it is not
    met the engine records SKIP, with the need's reason, without running the
    test; src/core/test_needs.py holds the check of each need) or as optional
    (TestInfo.optional_needs: the test runs either way, and the sub-tests that
    use it record NOT_APPLICABLE when it is missing). What only the target can
    reveal (no deprecated operation in the specification, no session cookie)
    stays inside the test. A new need is a member here and its check there.
    """

    ADMIN_ACCOUNT = "ADMIN_ACCOUNT"
    """The credentials of the admin role."""

    USER_ACCOUNT = "USER_ACCOUNT"
    """The credentials of the user_a role (an ordinary account)."""

    SECOND_USER_ACCOUNT = "SECOND_USER_ACCOUNT"
    """The credentials of the user_b role (a second ordinary account, for cross-user tests)."""

    GATEWAY = "GATEWAY"
    """A gateway section: adapter and Admin API."""

    REVOCABLE_LOGIN = "REVOCABLE_LOGIN"
    """A login method that can revoke a credential (login with a delete request)."""


class Effect(StrEnum):
    """
    What running a test does to the target.

    Declared by every test; the engine runs READ_ONLY tests first, then
    CHANGES_DATA, then STRESSES_TARGET, as far as the prerequisites allow, so
    that a test that changes or degrades the target cannot spoil the ones after
    it. A GET is not assumed harmless: the test declares what it does.
    """

    READ_ONLY = "READ_ONLY"
    """Reads only: no state of the target changes."""

    CHANGES_DATA = "CHANGES_DATA"
    """Creates, modifies or deletes data on the target."""

    STRESSES_TARGET = "STRESSES_TARGET"
    """Bursts of requests, or payloads that can degrade the target."""


# The run order of the effects (lower first).
EFFECT_RANK: dict[Effect, int] = {
    Effect.READ_ONLY: 0,
    Effect.CHANGES_DATA: 1,
    Effect.STRESSES_TARGET: 2,
}


# The order of the strategies by what the tester has: an external user, a user
# with credentials, a super user with internal access.
STRATEGY_RANK: dict[TestStrategy, int] = {
    TestStrategy.BLACK_BOX: 0,
    TestStrategy.GREY_BOX: 1,
    TestStrategy.WHITE_BOX: 2,
}

# The lowest strategy that grants each need: a test declaring a required need
# must declare at least this strategy (TestInfo checks it), so that its label
# says what the tester must have. GREY_BOX is an ordinary account; the admin
# account, the gateway's Admin API and a revocable login are a super user's. An
# optional need does not raise the strategy: the test runs without it.
NEED_MINIMUM_STRATEGY: dict[Need, TestStrategy] = {
    Need.USER_ACCOUNT: TestStrategy.GREY_BOX,
    Need.SECOND_USER_ACCOUNT: TestStrategy.GREY_BOX,
    Need.ADMIN_ACCOUNT: TestStrategy.WHITE_BOX,
    Need.GATEWAY: TestStrategy.WHITE_BOX,
    Need.REVOCABLE_LOGIN: TestStrategy.WHITE_BOX,
}


# ---------------------------------------------------------------------------
# TestInfo
# ---------------------------------------------------------------------------


def _not_blank(value: str) -> str:
    """Reject an empty or whitespace-only text."""
    if not value.strip():
        raise ValueError("must not be blank")
    return value


def _cwe_id(value: str | None) -> str | None:
    """Require the form 'CWE-<number>', or no value at all."""
    if value is None:
        return None
    if not CWE_ID_PATTERN.match(value):
        raise ValueError("must have the form 'CWE-<number>', e.g. 'CWE-285'")
    return value


_NonEmptyText = Annotated[str, AfterValidator(_not_blank)]


# The detail of a judgement, e.g. "AUTH_BYPASS": uppercase words joined by
# underscores, read with the outcome as "VIOLATION/AUTH_BYPASS". A family of
# details (`SERVED_AS_<kind>`) is declared by its prefix, ending with "_".
DETAIL_PATTERN: re.Pattern[str] = re.compile(r"^[A-Z][A-Z0-9]*(_[A-Z0-9]+)*$")


class OracleCase(BaseModel):
    """
    One case of a test's oracle: when it applies, and the judgement it gives.

    A test declares every case it records (TestInfo.oracle), but the answers
    that say nothing (the shared rule): its page's oracle table is generated
    from them, and a judgement the oracle does not declare is a programming
    error (AssessmentTest._record).
    """

    model_config = ConfigDict(frozen=True, extra="forbid")

    when: _NonEmptyText = Field(description="The situation, one short sentence (Markdown).")
    outcome: Outcome = Field(description="What it means for the guarantee.")
    detail: str = Field(
        description="The detail recorded; for a family, its prefix ending with '_' (SERVED_AS_)."
    )
    confidence: Confidence | None = Field(
        default=None,
        description="The confidence of the finding: required for a VIOLATION, only then.",
    )
    sub_test: str | None = Field(
        default=None, description="The sub-test; may be left out when the test has only one."
    )
    members: tuple[str, ...] = Field(
        default=(), description="A family's members: the detail is the prefix followed by one."
    )

    def names(self) -> tuple[str, ...]:
        """The details this case records: the detail, or each member of its family."""
        if self.members:
            return tuple(self.detail + member for member in self.members)
        return (self.detail,)


class DecisiveAnswer(BaseModel):
    """
    An uninformative category that is, for some sub-tests, the answer judged.

    Every test records an uninformative answer (UNINFORMATIVE_CATEGORIES:
    unavailable, rate limited, server error, no response) NOT_VERIFIABLE with
    the category as its detail. A sub-test whose question is that very answer
    declares it here, with the reason, and judges it in its own oracle: the
    rule then leaves it alone there, and the test page says so (the table
    generated from this declaration).
    """

    model_config = ConfigDict(frozen=True, extra="forbid")

    category: ResponseCategory = Field(description="One of the uninformative categories.")
    sub_tests: tuple[str, ...] = Field(
        default=(),
        description="The sub-tests that judge it; empty means every sub-test of the test.",
    )
    reason: _NonEmptyText = Field(
        description="Why that sub-test judges it, one sentence, for the test page."
    )


class TestInfo(BaseModel):
    """
    The declaration of a test: its identity, ranking and prerequisites.

    The domain is not declared: it is the first number of the ID. A native
    test has an ID "X.Y" and no tool; an external test has an ID
    "ext.X.Y.tool" and names the tool it wraps (the key of its section in
    external_tools). Whether the class is native or external is checked by
    test discovery, which knows the base class.

    The results of a test carry these values under their report names
    (test_id, test_name, domain, cwe_id, tool_name): report and JSON formats
    do not depend on this declaration.
    """

    __test__ = False

    model_config = ConfigDict(frozen=True, extra="forbid")

    id: str = Field(description="Unique test ID: 'X.Y' (native) or 'ext.X.Y.tool' (external).")
    name: _NonEmptyText = Field(description="Name of the security guarantee the test verifies.")
    priority: Annotated[StrictInt, Field(ge=PRIORITY_MIN, le=PRIORITY_MAX)] = Field(
        description="P0 (critical) to P3 (compliance); execution.min_priority filters on it."
    )
    strategy: TestStrategy = Field(
        description="What the tester needs: BLACK_BOX, GREY_BOX or WHITE_BOX."
    )
    cwe: Annotated[str | None, AfterValidator(_cwe_id)] = Field(
        default=None,
        description=(
            "Primary CWE of the weakness the test looks for, e.g. 'CWE-285'; None when the "
            "catalogue holds no entry that describes it, and then the guarantee rests on the "
            "standards in references."
        ),
    )
    references: tuple[Reference, ...] = Field(
        default=(),
        description=(
            "The other standards of the guarantee (OWASP, ASVS, WSTG, RFC, NIST SP), each in "
            "its standard's format (src/core/models/standards.py); not the primary CWE."
        ),
    )
    tags: tuple[str, ...] = Field(
        default=(),
        description="Topic labels: lowercase words joined by hyphens, e.g. 'rate-limit'.",
    )
    depends_on: tuple[str, ...] = Field(
        default=(),
        description=(
            "Tests whose data this test uses: they run first, and if one is not in the run "
            "or returns SKIP or ERROR this test is SKIP (src/core/dag.py)."
        ),
    )
    requires_pass: tuple[str, ...] = Field(
        default=(),
        description=(
            "Tests that must hold for this test to be meaningful: they run first, and "
            "unless each returns PASS this test is SKIP (src/core/dag.py)."
        ),
    )
    tool: _NonEmptyText | None = Field(
        default=None,
        description="External tests only: the external_tools key of the wrapped tool.",
    )
    effect: Effect = Field(
        description=(
            "What running the test does to the target: READ_ONLY, CHANGES_DATA or "
            "STRESSES_TARGET; the run order follows it."
        )
    )
    sub_tests: tuple[str, ...] = Field(
        min_length=1,
        description=(
            "The test's sub-tests, at least one: names in lowercase words joined by "
            "underscores, unique; every judgement the test records belongs to one, and the "
            "status is computed from them."
        ),
    )
    essential_sub_tests: tuple[str, ...] = Field(
        default=(),
        description=(
            "The sub-tests the test is mainly about, among sub_tests; empty by default. "
            "Without a violation, a test none of whose essential sub-tests is PASS is "
            "INCONCLUSIVE, whatever the others say (combine_sub_tests)."
        ),
    )
    needs: tuple[Need, ...] = Field(
        default=(),
        description=(
            "What the test needs from the configuration to run at all; when one is not "
            "met the engine records SKIP without running it (src/core/test_needs.py)."
        ),
    )
    optional_needs: tuple[Need, ...] = Field(
        default=(),
        description=(
            "What the test uses when the configuration provides it: it runs either way, "
            "and the sub-tests that use a missing one record NOT_APPLICABLE."
        ),
    )
    oracle: tuple[OracleCase, ...] = Field(
        default=(),
        description=(
            "The test's oracle, case by case (the answers that say nothing excepted); its page's "
            "table is generated from it. Empty: not yet declared, nothing is checked."
        ),
    )
    decisive_answers: tuple[DecisiveAnswer, ...] = Field(
        default=(),
        description=(
            "The uninformative categories (unavailable, rate limited, server error, no "
            "response) that some of the test's sub-tests judge themselves; every other one "
            "is NOT_VERIFIABLE with the category as its detail."
        ),
    )

    @model_validator(mode="after")
    def _id_and_kind_coherent(self) -> TestInfo:
        """Check the ID, its domain, the tool, the prerequisites, the needs, the sub-tests."""
        native = NATIVE_TEST_ID_PATTERN.match(self.id)
        external = EXTERNAL_TEST_ID_PATTERN.match(self.id)
        match = native or external
        if match is None:
            raise ValueError(
                f"id must have the format 'X.Y' (native) or 'ext.X.Y.tool' (external), "
                f"got {self.id!r}"
            )
        domain = int(match.group("domain"))
        if not DOMAIN_MIN <= domain <= DOMAIN_MAX:
            raise ValueError(
                f"id {self.id!r}: the domain must be {DOMAIN_MIN}-{DOMAIN_MAX}, got {domain}"
            )
        if external is not None and self.tool is None:
            raise ValueError(f"id {self.id!r} is external: set tool (its external_tools key)")
        if native is not None and self.tool is not None:
            raise ValueError(f"id {self.id!r} is native: a native test has no tool")
        for field in ("depends_on", "requires_pass"):
            for prerequisite in getattr(self, field):
                if not is_valid_test_id(prerequisite):
                    raise ValueError(f"{field}: {prerequisite!r} is not a test ID")
                if prerequisite == self.id:
                    raise ValueError(f"{field} lists the test itself ({self.id!r})")
        for field in ("needs", "optional_needs"):
            declared: tuple[Need, ...] = getattr(self, field)
            repeated = sorted({n.value for n in declared if declared.count(n) > 1})
            if repeated:
                raise ValueError(f"{field}: declared more than once: {repeated}")
        both = sorted({n.value for n in self.needs} & {n.value for n in self.optional_needs})
        if both:
            raise ValueError(f"needs and optional_needs both declare {both}")
        for need in self.needs:
            minimum = NEED_MINIMUM_STRATEGY[need]
            if STRATEGY_RANK[self.strategy] < STRATEGY_RANK[minimum]:
                raise ValueError(
                    f"id {self.id!r}: the need {need.value} requires strategy {minimum.value} or "
                    f"higher, the test declares {self.strategy.value}"
                )
        for sub_test in self.sub_tests:
            if not SUB_TEST_NAME_PATTERN.match(sub_test):
                raise ValueError(
                    f"sub_tests: {sub_test!r} must be lowercase words joined by underscores, "
                    f"e.g. 'unauthenticated_access'"
                )
        duplicates = sorted({s for s in self.sub_tests if self.sub_tests.count(s) > 1})
        if duplicates:
            raise ValueError(f"sub_tests: declared more than once: {duplicates}")
        undeclared = sorted(set(self.essential_sub_tests) - set(self.sub_tests))
        if undeclared:
            raise ValueError(f"essential_sub_tests: not among sub_tests: {undeclared}")
        for tag in self.tags:
            if not TAG_PATTERN.match(tag):
                raise ValueError(
                    f"tags: {tag!r} must be lowercase words joined by hyphens, e.g. "
                    f"'rate-limit'; a standard goes in references"
                )
        self._check_decisive_answers()
        self._check_oracle()
        duplicates = duplicate_references(self.references)
        if duplicates:
            raise ValueError(f"references: cited more than once: {duplicates}")
        if self.cwe is not None:
            primary = Reference(standard=Standard.CWE, id=self.cwe)
            if primary in self.references:
                raise ValueError(f"references: {self.cwe} is the primary CWE (cwe), already cited")
        return self

    def _check_decisive_answers(self) -> None:
        """Each decisive answer: an uninformative category, on declared sub-tests, once."""
        seen: set[tuple[ResponseCategory, str]] = set()
        for answer in self.decisive_answers:
            if answer.category not in UNINFORMATIVE_CATEGORIES:
                allowed = ", ".join(c.value for c in UNINFORMATIVE_CATEGORIES)
                raise ValueError(
                    f"decisive_answers: {answer.category.value} is not an uninformative "
                    f"category ({allowed})"
                )
            undeclared = sorted(set(answer.sub_tests) - set(self.sub_tests))
            if undeclared:
                raise ValueError(f"decisive_answers: not among sub_tests: {undeclared}")
            for sub_test in answer.sub_tests or self.sub_tests:
                if (answer.category, sub_test) in seen:
                    raise ValueError(
                        f"decisive_answers: {answer.category.value} declared twice for {sub_test!r}"
                    )
                seen.add((answer.category, sub_test))

    def _check_oracle(self) -> None:
        """Each case: a declared sub-test, a valid detail, a confidence only for a VIOLATION."""
        seen: set[tuple[str, Outcome, str, Confidence | None]] = set()
        for case in self.oracle:
            sub_test = case.sub_test or self._only_sub_test("oracle")
            if sub_test not in self.sub_tests:
                raise ValueError(f"oracle: sub-test {sub_test!r} is not declared")
            family = case.detail.endswith("_")
            if family != bool(case.members):
                raise ValueError(
                    f"oracle: {case.detail!r}: a family ends with '_' and lists its members"
                )
            for detail in case.names():
                if not DETAIL_PATTERN.match(detail):
                    raise ValueError(f"oracle: {detail!r} must be UPPER_SNAKE_CASE")
            if (case.confidence is not None) != (case.outcome == Outcome.VIOLATION):
                raise ValueError(f"oracle: {case.detail}: a confidence goes with a VIOLATION only")
            key = (sub_test, case.outcome, case.detail, case.confidence)
            if key in seen:
                raise ValueError(f"oracle: {case.outcome.value}/{case.detail} declared twice")
            seen.add(key)

    def _only_sub_test(self, field: str) -> str:
        """The test's only sub-test, for an entry that leaves it out."""
        if len(self.sub_tests) != 1:
            raise ValueError(f"{field}: name the sub-test, the test has several")
        return self.sub_tests[0]

    def case_sub_test(self, case: OracleCase) -> str:
        """
        The sub-test of an oracle case (the only one when the case leaves it out).

        Args:
            case: A case of this test's oracle.

        Returns:
            Its sub-test.
        """
        return case.sub_test or self.sub_tests[0]

    def declares(
        self, sub_test: str, outcome: Outcome, detail: str, confidence: Confidence | None
    ) -> bool:
        """
        Whether the oracle declares a judgement (always True for an oracle not declared).

        Args:
            sub_test:   The sub-test judged.
            outcome:    The outcome recorded.
            detail:     The detail recorded.
            confidence: The finding's confidence (a VIOLATION), else None.

        Returns:
            True when a case of that sub-test gives this outcome and detail, with
            this confidence for a VIOLATION.
        """
        if not self.oracle:
            return True
        return any(
            self.case_sub_test(case) == sub_test
            and case.outcome == outcome
            and detail in case.names()
            and case.confidence == confidence
            for case in self.oracle
        )

    def decides(self, category: ResponseCategory, sub_test: str) -> bool:
        """
        Whether a sub-test judges an uninformative category itself (decisive_answers).

        Args:
            category: The category of an answer.
            sub_test: One of the test's sub-tests.

        Returns:
            True when a decisive answer of the test names the category for
            that sub-test (or for every sub-test).
        """
        return any(
            answer.category == category and (not answer.sub_tests or sub_test in answer.sub_tests)
            for answer in self.decisive_answers
        )

    @property
    def domain(self) -> int:
        """The methodology domain: the first number of the ID."""
        # The validator guarantees the format: "X.Y" or "ext.X.Y.tool".
        return int(self.id.removeprefix(EXTERNAL_TEST_ID_PREFIX).split(".", 1)[0])

    @property
    def is_external(self) -> bool:
        """True for an external test (ID 'ext.X.Y.tool')."""
        return is_external_test_id(self.id)

    @property
    def prerequisites(self) -> tuple[str, ...]:
        """Both kinds of prerequisite, depends_on first."""
        return (*self.depends_on, *self.requires_pass)

    def uses(self, need: Need) -> bool:
        """True when the test declares the need, required or optional."""
        return need in self.needs or need in self.optional_needs


# Pydantic error types whose input is not worth showing: a check of ours (the
# message names the values) and a missing field (the input is the whole
# declaration).
_ERRORS_WITHOUT_INPUT: frozenset[str] = frozenset({"value_error", "missing"})


def info_problems(exc: ValidationError) -> list[str]:
    """
    Turn the validation error of a TestInfo into one message per problem.

    Args:
        exc: The error raised by TestInfo(...) in a test module.

    Returns:
        Messages such as "info.priority: Input should be less than or equal
        to 3 (got 5)"; a check spanning several fields has no field name.
    """
    problems: list[str] = []
    for error in exc.errors():
        location = ".".join(str(part) for part in error["loc"])
        where = f"info.{location}" if location else "info"
        message = str(error["msg"]).removeprefix("Value error, ")
        given = "" if error["type"] in _ERRORS_WITHOUT_INPUT else f" (got {error.get('input')!r})"
        problems.append(f"{where}: {message}{given}")
    return problems

"""
src/core/test_metadata.py

TestInfo: the declaration of a test (who it is), native and external alike.

Every test class declares one TestInfo as its ``info`` class attribute
(docs/architecture/design-decisions.md, D8). It is a frozen Pydantic model, validated
when the test module is imported: an invalid declaration makes the import
fail, and test discovery (src/core/test_discovery.py) reports it as a
TestDefinitionError naming the module, so the run stops instead of dropping
the test or filling in defaults.

The same module holds the test ID formats and the priority range, which the
configuration schema imports to validate execution.test_ids and
execution.min_priority: each rule is written once.

Dependency rule: imports only from the standard library, pydantic and src.core.models.
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

from src.core.models import TestStrategy

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

# Priority range: P0 (critical) to P3 (compliance).
PRIORITY_MIN: int = 0
PRIORITY_MAX: int = 3

# Domain range of the methodology: domains 0 to 7.
DOMAIN_MIN: int = 0
DOMAIN_MAX: int = 7

# Prefix of external test IDs ("ext.1.5.sslyze"): it keeps them apart from
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

# Primary CWE reference of a test, e.g. "CWE-285".
CWE_ID_PATTERN: re.Pattern[str] = re.compile(r"^CWE-[1-9][0-9]*$")

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
    What a test needs from the configuration to run at all.

    Only what the configuration tells before any contact with the target: a
    test whose need is not met is recorded as SKIP by the engine, with the
    need's reason, without running (src/core/test_needs.py, which holds the
    check of each need). What only the target can reveal (no deprecated
    operation in the specification, no session cookie) stays a SKIP inside
    the test. A new need is a member here and its check there.
    """

    ADMIN_ACCOUNT = "ADMIN_ACCOUNT"
    """The credentials of the admin role."""

    USER_ACCOUNT = "USER_ACCOUNT"
    """The credentials of the user_a role (an ordinary account)."""

    GATEWAY = "GATEWAY"
    """A gateway section: adapter and Admin API."""

    REVOCABLE_LOGIN = "REVOCABLE_LOGIN"
    """A login method that can revoke a credential (login with a delete request)."""


# ---------------------------------------------------------------------------
# TestInfo
# ---------------------------------------------------------------------------


def _not_blank(value: str) -> str:
    """Reject an empty or whitespace-only text."""
    if not value.strip():
        raise ValueError("must not be blank")
    return value


def _cwe_id(value: str) -> str:
    """Require the form 'CWE-<number>'."""
    if not CWE_ID_PATTERN.match(value):
        raise ValueError("must have the form 'CWE-<number>', e.g. 'CWE-285'")
    return value


_NonEmptyText = Annotated[str, AfterValidator(_not_blank)]


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
    cwe: Annotated[str, AfterValidator(_cwe_id)] = Field(
        description="Primary CWE of the weakness the test looks for, e.g. 'CWE-285'."
    )
    tags: tuple[_NonEmptyText, ...] = Field(
        default=(), description="Labels for the report (standards, topics)."
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
    needs: tuple[Need, ...] = Field(
        default=(),
        description=(
            "What the test needs from the configuration to run at all; when one is not "
            "met the engine records SKIP without running it (src/core/test_needs.py)."
        ),
    )

    @model_validator(mode="after")
    def _id_and_kind_coherent(self) -> TestInfo:
        """Check the ID format, its domain, the tool and the prerequisites."""
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
        return self

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

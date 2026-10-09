"""
src/core/test_metadata.py

The rules every test declaration must satisfy, native and external alike.

A test class declares its metadata as class attributes (test_id, test_name,
domain, priority, strategy, depends_on, tags, cwe_id; external tests also
tool_name). Python cannot force a subclass to declare a class attribute, so
the registries call metadata_problems() at discovery and stop the run with
TestDefinitionError when a declaration is missing or invalid, instead of
dropping the test or filling in defaults.

The same module holds the test ID formats and the priority range, which the
configuration schema imports to validate execution.test_ids and
execution.min_priority: each rule is written once.

Dependency rule: imports only from the standard library and src.core.models.
"""

from __future__ import annotations

import re

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

# Class attributes every test declares, and the extra one of external tests.
REQUIRED_ATTRIBUTES: tuple[str, ...] = (
    "test_id",
    "test_name",
    "domain",
    "priority",
    "strategy",
    "depends_on",
    "tags",
    "cwe_id",
)
EXTERNAL_REQUIRED_ATTRIBUTES: tuple[str, ...] = ("tool_name",)


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


# ---------------------------------------------------------------------------
# Declaration checks
# ---------------------------------------------------------------------------


def metadata_problems(test_class: type, *, external: bool) -> list[str]:
    """
    Return every problem in the metadata declared by a test class.

    Checks presence and value of each required class attribute: test_id in
    the format of its kind, with the domain part equal to domain; non-empty
    test_name, cwe_id and (external) tool_name; domain and priority integers
    in range; strategy a TestStrategy; depends_on a list of valid test IDs;
    tags a list of strings.

    Args:
        test_class: The concrete test class to check.
        external:   True for an ExternalToolTest subclass, False for BaseTest.

    Returns:
        One message per problem (empty when the declaration is valid).
    """
    required = REQUIRED_ATTRIBUTES + (EXTERNAL_REQUIRED_ATTRIBUTES if external else ())
    missing = [name for name in required if not hasattr(test_class, name)]
    if missing:
        return [f"missing {', '.join(repr(name) for name in missing)}"]

    problems: list[str] = []
    test_id = test_class.test_id  # type: ignore[attr-defined]
    domain = test_class.domain  # type: ignore[attr-defined]
    pattern = EXTERNAL_TEST_ID_PATTERN if external else NATIVE_TEST_ID_PATTERN
    id_match = pattern.match(test_id) if isinstance(test_id, str) else None
    if id_match is None:
        expected = "'ext.X.Y.tool'" if external else "'X.Y'"
        problems.append(f"'test_id' must have the format {expected}, got {test_id!r}")

    if not _is_int_in_range(domain, DOMAIN_MIN, DOMAIN_MAX):
        problems.append(f"'domain' must be an integer {DOMAIN_MIN}-{DOMAIN_MAX}, got {domain!r}")
    elif id_match is not None and int(id_match.group("domain")) != domain:
        problems.append(f"'test_id' {test_id!r} does not match 'domain' {domain}")

    priority = test_class.priority  # type: ignore[attr-defined]
    if not _is_int_in_range(priority, PRIORITY_MIN, PRIORITY_MAX):
        problems.append(
            f"'priority' must be an integer {PRIORITY_MIN}-{PRIORITY_MAX}, got {priority!r}"
        )

    strategy = test_class.strategy  # type: ignore[attr-defined]
    if not isinstance(strategy, TestStrategy):
        problems.append(f"'strategy' must be a TestStrategy, got {strategy!r}")

    text_attributes = ("test_name", "cwe_id") + (EXTERNAL_REQUIRED_ATTRIBUTES if external else ())
    for name in text_attributes:
        value = getattr(test_class, name)
        if not isinstance(value, str) or not value.strip():
            problems.append(f"{name!r} must be a non-empty string, got {value!r}")

    depends_on = test_class.depends_on  # type: ignore[attr-defined]
    if not _is_list_of_str(depends_on) or not all(is_valid_test_id(d) for d in depends_on):
        problems.append(f"'depends_on' must be a list of test IDs, got {depends_on!r}")

    tags = test_class.tags  # type: ignore[attr-defined]
    if not _is_list_of_str(tags):
        problems.append(f"'tags' must be a list of strings, got {tags!r}")

    return problems


def _is_int_in_range(value: object, low: int, high: int) -> bool:
    """Return True for an int (not a bool) between low and high inclusive."""
    return isinstance(value, int) and not isinstance(value, bool) and low <= value <= high


def _is_list_of_str(value: object) -> bool:
    """Return True for a list whose items are all strings."""
    return isinstance(value, list) and all(isinstance(item, str) for item in value)

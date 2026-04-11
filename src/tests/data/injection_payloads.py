"""
src/tests/data/injection_payloads.py

Injection attack payload catalogue for test 3.1.

This module is pure data: it defines no functions and performs no I/O.
Payloads are sourced from OWASP Testing Guide v4.2, OWASP API Security
Testing Guide, and methodology section 3.1 of this project.

Structure
---------
SQL, NoSQL, and command injection payloads are plain strings or dicts.
Type confusion cases use the TypeConfusionCase named tuple to pair a
sent value with a description of the expected type that was violated.

The consuming test (3.1) inserts these payloads into query parameters,
request body fields, and path parameters of documented endpoints, then
verifies that the response is 400 (rejected) and does not contain
injection execution evidence in the body.

Dependency rule
---------------
This module has no imports beyond stdlib typing.  It is a data file only.
"""

from __future__ import annotations

from typing import Any, NamedTuple

# ---------------------------------------------------------------------------
# SQL injection payloads
# Methodology ref: Garanzia 3.1 — SQL Injection
# ---------------------------------------------------------------------------

SQL_PAYLOADS: tuple[str, ...] = (
    # Classic tautology
    "' OR '1'='1",
    "' OR '1'='1'--",
    "' OR '1'='1'/*",
    # Union-based
    "' UNION SELECT NULL--",
    "' UNION SELECT NULL,NULL--",
    "1 UNION SELECT username, password FROM users--",
    # Error-based
    "' AND 1=CONVERT(int,(SELECT TOP 1 table_name FROM information_schema.tables))--",
    "' AND extractvalue(1, concat(0x7e, (SELECT version())))--",
    # Blind boolean
    "' AND 1=1--",
    "' AND 1=2--",
    # Time-based blind
    "'; WAITFOR DELAY '0:0:5'--",
    "' OR SLEEP(5)--",
    "'; SELECT pg_sleep(5)--",
    # Stacked queries
    "'; DROP TABLE users--",
    "'; INSERT INTO users VALUES ('hacked', 'hacked')--",
    # Escape sequences
    "\\' OR \\'1\\'=\\'1",
    "%27 OR %271%27=%271",
)

# ---------------------------------------------------------------------------
# NoSQL injection payloads
# Methodology ref: Garanzia 3.1 — NoSQL Injection
# ---------------------------------------------------------------------------

# String-based NoSQL injection (MongoDB operator injection via query params)
NOSQL_STRING_PAYLOADS: tuple[str, ...] = (
    '{"$gt": ""}',
    '{"$ne": null}',
    '{"$regex": ".*"}',
    '{"$where": "1==1"}',
)

# Dict-based NoSQL injection (for JSON request bodies)
# These are submitted as values for username/password fields.
NOSQL_DICT_PAYLOADS: tuple[dict[str, Any], ...] = (
    {"$gt": ""},
    {"$ne": None},
    {"$regex": ".*"},
    {"$nin": []},
    {"$where": "function() { return true; }"},
)

# Full body NoSQL auth bypass payloads (both username and password replaced)
NOSQL_AUTH_BYPASS_BODIES: tuple[dict[str, Any], ...] = (
    {"username": {"$ne": None}, "password": {"$ne": None}},
    {"username": {"$gt": ""}, "password": {"$gt": ""}},
    {"username": "admin", "password": {"$gt": ""}},
)

# ---------------------------------------------------------------------------
# Command injection payloads
# Methodology ref: Garanzia 3.1 — Command Injection
# ---------------------------------------------------------------------------

COMMAND_PAYLOADS: tuple[str, ...] = (
    # Unix command chaining
    "; whoami",
    "| whoami",
    "& whoami",
    "&& whoami",
    "|| whoami",
    "`whoami`",
    "$(whoami)",
    # Windows
    "& dir",
    "| dir",
    # Network-based (confirm execution via DNS lookup; no real exfil)
    "; ping -c 1 127.0.0.1",
    "| ping -c 1 127.0.0.1",
    # Path traversal combined
    "; cat /etc/passwd",
    "| cat /etc/passwd",
)

# ---------------------------------------------------------------------------
# CRLF injection payloads
# Methodology ref: Garanzia 3.1 — Encoding and Injection in Header
# ---------------------------------------------------------------------------

CRLF_PAYLOADS: tuple[str, ...] = (
    "value\r\nX-Injected: header",
    "value\r\nSet-Cookie: injected=true",
    "value%0d%0aX-Injected: header",
    "value%0aX-Injected: header",
    "value\nX-Injected: header",
)

# ---------------------------------------------------------------------------
# Type confusion cases
# Methodology ref: Garanzia 3.1 — Type Confusion
# ---------------------------------------------------------------------------


class TypeConfusionCase(NamedTuple):
    """
    A single type confusion test case.

    Attributes:
        expected_type: OpenAPI type string the field expects
                       ('integer', 'string', 'boolean', 'array', 'object').
        sent_value:    The incorrectly-typed value to submit.
        description:   Human-readable label for the Finding.detail.
    """

    expected_type: str
    sent_value: Any
    description: str


TYPE_CONFUSION_CASES: tuple[TypeConfusionCase, ...] = (
    # Send string where integer is expected
    TypeConfusionCase("integer", "not-a-number", "string instead of integer"),
    TypeConfusionCase("integer", "1; DROP TABLE", "SQL-like string instead of integer"),
    TypeConfusionCase("integer", 99_999_999_999_999_999_999, "integer overflow (> int64 max)"),
    TypeConfusionCase("integer", -99_999_999_999_999_999_999, "integer underflow"),
    TypeConfusionCase("integer", 3.14, "float instead of integer"),
    # Send wrong type where string is expected
    TypeConfusionCase("string", 12345, "integer instead of string"),
    TypeConfusionCase("string", True, "boolean instead of string"),
    TypeConfusionCase("string", [], "array instead of string"),
    TypeConfusionCase("string", {}, "object instead of string"),
    TypeConfusionCase("string", None, "null instead of string"),
    # Send wrong type where boolean is expected
    TypeConfusionCase("boolean", "true", "string 'true' instead of boolean"),
    TypeConfusionCase("boolean", 1, "integer 1 instead of boolean"),
    TypeConfusionCase("boolean", "yes", "string 'yes' instead of boolean"),
    # Array/object confusion
    TypeConfusionCase("array", "not-an-array", "string instead of array"),
    TypeConfusionCase("object", "not-an-object", "string instead of object"),
    TypeConfusionCase("object", [], "array instead of object"),
)

# ---------------------------------------------------------------------------
# Boundary and size limit payloads
# Methodology ref: Garanzia 3.1 — Boundary and Size Limits
# ---------------------------------------------------------------------------

# Large string payload (100 KB) — tests max field length enforcement.
LARGE_STRING_PAYLOAD: str = "A" * 102_400


# Deeply nested JSON object — tests parser recursion depth limits.
def _make_nested_object(depth: int) -> dict[str, Any]:
    """Build a JSON object nested to the given depth."""
    result: dict[str, Any] = {"leaf": "value"}
    for _ in range(depth):
        result = {"nested": result}
    return result


# 100 levels of nesting — enough to trigger stack overflow in naive parsers.
DEEPLY_NESTED_OBJECT: dict[str, Any] = _make_nested_object(100)

# Path traversal payloads for path parameters.
PATH_TRAVERSAL_PAYLOADS: tuple[str, ...] = (
    "../../etc/passwd",
    "..%2F..%2Fetc%2Fpasswd",
    "..%252F..%252Fetc%252Fpasswd",
    "%2e%2e%2f%2e%2e%2fetc%2fpasswd",
    "....//....//etc/passwd",
)

# Unicode / special character payloads for string fields.
SPECIAL_CHARACTER_PAYLOADS: tuple[str, ...] = (
    # Null byte
    "value\x00suffix",
    # Unicode overlong encoding
    "\xc0\xae\xc0\xae/",
    # Emoji in alphanumeric-only field
    "user\U0001f600name",
    # Right-to-left override
    "user\u202ename",
    # Zero-width characters
    "user\u200bname",
    # Very long unicode string (> 1000 chars)
    "\u00e9" * 1000,
)

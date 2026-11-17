"""
src/tests/helpers/response_inspector.py

Pure response analysis utility for security tests that inspect HTTP response
bodies and headers for information disclosure and misconfiguration.

Responsibility
--------------
Provides deterministic, side-effect-free functions that analyze an HTTP
response body (str or dict) or a headers dict and return structured findings.
No HTTP requests are made here.  No TestContext writes happen here.

Used by
-------
    test 6.1  -- Error and information disclosure: stack traces, debug fields
                 and leaky headers (contains_stack_trace, extract_debug_fields,
                 find_leaky_headers)

Nothing else uses this module. Five functions written before the block-6 test
review were removed on 2026-10-28 because no test called them and each of
their jobs is done elsewhere, better or by an explicit decision: the security
header policy by test 6.2 (which moved HSTS to 1.5 and dropped
Permissions-Policy), the sensitive field names by test 2.5's own list, and the
uniformity of authentication errors by test 1.7, which compares a
fingerprint of the body and the response times, not the bodies as they are.

Design
------
All pattern lists and frozen sets are module-level constants so that the
cost of compilation is paid once at import time, not per call.  Functions
that return lists return new list objects, never views into constants, so
callers cannot accidentally mutate the module state.

Dependency rule
---------------
This module imports from stdlib and from src.tests.data.inspector_patterns
(pure-data sibling module, no logic, no further dependencies).  It must never
import from src.core, src.engine, or any third-party library.
"""

from __future__ import annotations

import re

from src.tests.data.inspector_patterns import STACK_TRACE_PATTERNS

# ---------------------------------------------------------------------------
# Stack trace / framework leakage patterns
# ---------------------------------------------------------------------------

# Regex patterns that match framework version strings in response bodies or headers.
# A version string in a response is direct fingerprinting information.
_FRAMEWORK_VERSION_PATTERN: re.Pattern[str] = re.compile(
    r"(Django|Flask|Rails|Spring Boot|Express|Laravel|Symfony|FastAPI|Gin|Echo)"
    r"[\s/v]+"
    r"\d+\.\d+",
    re.IGNORECASE,
)

# Filesystem path patterns that reveal deployment layout. A Unix path must start
# there (after a quote, a space, a bracket...), not follow a host or another
# segment: "https://example.com/home/" is a URL, not a file.
_FILESYSTEM_PATH_PATTERN: re.Pattern[str] = re.compile(
    r"(?<![\w.:/-])(/opt/|/var/|/home/|/usr/|/etc/|/tmp/|/app/|/srv/)|(C:\\|D:\\)"
)

# ---------------------------------------------------------------------------
# Debug and leaky-header definitions
# ---------------------------------------------------------------------------

# Debug field names, compared with a key lowercased and without "_" and "-": a
# key that is one of them, or a key starting with "_" whose rest starts with one
# of _DEBUG_PREFIXED (`_debug`, `_sql_text`). A substring match flagged ordinary
# fields (`search_query`, `is_internal`) until 2026-11-16.
_DEBUG_FIELD_NAMES: frozenset[str] = frozenset(
    {
        "debug",
        "debuginfo",
        "debugdata",
        "debugmessage",
        "stacktrace",
        "sqlquery",
        "rawsql",
        "shardkey",
        "cachekey",
        "databaseid",
    }
)
_DEBUG_PREFIXED: tuple[str, ...] = ("debug", "sql", "query", "trace", "internal", "stack")
# How deep, and into how many items of each array, a body is walked.
_MAX_DEPTH: int = 4
_MAX_ITEMS: int = 20

# Headers that should NOT appear in API responses (information leakage).
LEAKY_HEADERS: frozenset[str] = frozenset(
    {
        "x-powered-by",
        "x-aspnet-version",
        "x-aspnetmvc-version",
        "server",  # only leaky if it contains version info
        "via",  # only leaky if it names a product with its version
    }
)
# A product with its version, as `Server` and `Via` write it ("kong/3.9.3").
_PRODUCT_VERSION: re.Pattern[str] = re.compile(r"[A-Za-z][\w.-]*/\d")
# A version number anywhere in a header value.
_VERSION_NUMBER: re.Pattern[str] = re.compile(r"\d+\.\d+")


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------


def contains_stack_trace(body: str) -> list[str]:
    """
    Search a response body string for stack trace or framework leakage patterns.

    Methodology reference: guarantee 6.1 -- the oracle states that response
    bodies must not contain class names, file paths, or exception messages.

    Args:
        body: Raw response body as a string.

    Returns:
        List of matched strings found in the body:
          - For STACK_TRACE_PATTERNS entries: the literal pattern string matched.
          - For framework version detection: the actual matched text (e.g. "Django 4.2").
          - For filesystem path detection: the actual matched text (e.g. "/opt/app/").
        Empty list if no stack trace patterns are detected.
    """
    if not body:
        return []

    found: list[str] = []
    body_lower = body.lower()

    for pattern in STACK_TRACE_PATTERNS:
        if pattern.lower() in body_lower:
            found.append(pattern)

    version_match = _FRAMEWORK_VERSION_PATTERN.search(body)
    if version_match:
        # Return the actual matched text (e.g. "Django 4.2") rather than the
        # synthetic label "framework_version_string".  This makes the finding
        # detail self-explanatory without requiring the reader to know which
        # regex fired.
        found.append(version_match.group(0))

    path_match = _FILESYSTEM_PATH_PATTERN.search(body)
    if path_match:
        # Return the actual matched text (e.g. "/opt/app/") for the same reason.
        found.append(path_match.group(0))

    return found


def extract_debug_fields(data: object, depth: int = 0) -> list[str]:
    """
    The field names of a JSON body that look like debug artifacts.

    Walks objects and the first items of arrays, a few levels deep (an API's
    records sit inside an array or an envelope).

    Args:
        data:  A parsed JSON body (object, array or value).
        depth: How deep the walk already is.

    Returns:
        The debug-looking keys found, each once, in the order met.
    """
    if depth > _MAX_DEPTH:
        return []
    found: list[str] = []
    if isinstance(data, dict):
        for key, value in data.items():
            if _is_debug_name(str(key)) and key not in found:
                found.append(str(key))
            found += [k for k in extract_debug_fields(value, depth + 1) if k not in found]
    elif isinstance(data, list):
        for item in data[:_MAX_ITEMS]:
            found += [k for k in extract_debug_fields(item, depth + 1) if k not in found]
    return found


def has_json_object(data: object) -> bool:
    """Whether a parsed JSON body is an object, or an array holding one: fields to look at."""
    if isinstance(data, dict):
        return True
    return isinstance(data, list) and any(isinstance(item, dict) for item in data[:_MAX_ITEMS])


def _is_debug_name(key: str) -> bool:
    """Whether a key names a debug artifact (_DEBUG_FIELD_NAMES, _DEBUG_PREFIXED)."""
    plain = key.lower().replace("_", "").replace("-", "")
    if plain in _DEBUG_FIELD_NAMES:
        return True
    return key.startswith("_") and plain.startswith(_DEBUG_PREFIXED)


def versioned_value(value: str) -> bool:
    """Whether a header value carries a version number."""
    return _VERSION_NUMBER.search(value) is not None


def find_leaky_headers(headers: dict[str, str]) -> list[str]:
    """
    Return a list of response headers that disclose server implementation details.

    Checks for headers in LEAKY_HEADERS.  For the 'server' header, also checks
    whether the value contains a version string (e.g. 'nginx/1.18.0' is leaky,
    'nginx' alone is acceptable).

    Args:
        headers: Response headers dict.

    Returns:
        List of leaky header names found in the response.
        Empty list if no leaky headers are present.
    """
    normalized: dict[str, str] = {k.lower(): v for k, v in headers.items()}
    found: list[str] = []

    for header_name in LEAKY_HEADERS:
        value = normalized.get(header_name)
        if value is None:
            continue

        if header_name == "server":
            # 'Server: nginx' is acceptable; 'Server: nginx/1.18.0' is not.
            if "/" in value or versioned_value(value):
                found.append(header_name)
        elif header_name == "via":
            # 'Via: 1.1 proxy' is acceptable; 'Via: 1.1 kong/3.9.3' names its version.
            if _PRODUCT_VERSION.search(value):
                found.append(header_name)
        else:
            found.append(header_name)

    return sorted(found)

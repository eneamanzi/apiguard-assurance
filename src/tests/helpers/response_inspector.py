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
from typing import Any

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

# Filesystem path patterns that reveal deployment layout.
_FILESYSTEM_PATH_PATTERN: re.Pattern[str] = re.compile(
    r"(/opt/|/var/|/home/|/usr/|/etc/|/tmp/|C:\\|D:\\|/app/|/srv/)"
)

# ---------------------------------------------------------------------------
# Debug and leaky-header definitions
# ---------------------------------------------------------------------------

# Debug field name substrings.  Any field whose lowercased name contains one
# of these strings is considered a debug artifact.
_DEBUG_FIELD_SUBSTRINGS: tuple[str, ...] = (
    "_debug",
    "_sql",
    "_query",
    "_trace",
    "_internal",
    "debuginfo",
    "debug_info",
    "shardkey",
    "shard_key",
    "cachekey",
    "cache_key",
    "databaseid",
    "database_id",
)

# Headers that should NOT appear in API responses (information leakage).
LEAKY_HEADERS: frozenset[str] = frozenset(
    {
        "x-powered-by",
        "x-aspnet-version",
        "x-aspnetmvc-version",
        "server",  # only leaky if it contains version info
    }
)


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


def extract_debug_fields(data: dict[str, Any]) -> list[str]:
    """
    Return a list of field names that appear to be debug artifacts.

    Checks whether any key in the dict (lowercased) contains a known debug
    field substring.  Only inspects top-level keys — debug fields at
    deeper nesting levels are less likely to be intentional API surface.

    Args:
        data: Parsed JSON response body as a dict.

    Returns:
        List of field names identified as debug artifacts.
        Empty list if none are found.
    """
    found: list[str] = []
    for key in data:
        key_lower = key.lower()
        for substring in _DEBUG_FIELD_SUBSTRINGS:
            if substring in key_lower:
                found.append(key)
                break
    return found


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
            if "/" in value or re.search(r"\d+\.\d+", value):
                found.append(header_name)
        else:
            found.append(header_name)

    return sorted(found)

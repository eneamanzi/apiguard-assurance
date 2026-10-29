"""
src/tests/data/inspector_patterns.py

Pure data constants for HTTP response security inspection.

Extracted from src/tests/helpers/response_inspector.py to follow the project
convention that raw test data (wordlists, payload sets, pattern tuples) lives
in src/tests/data/ rather than inside helper modules that contain logic.

Sibling data module in this package:
    ssrf_payloads.py    -- SSRF target URLs and encoding variants, for test 7.2

Three names stood in this list and are gone (2026-10-28): `injection_payloads.py`
never existed, while `auth_payloads.py` and `shadow_wordlists.py` were removed
with their contents, which no test read any more (test 1.1 keeps its own
malformed credential values, 1.2 builds its JWT variants, and the shadow-API
paths come from the specification, the gateway's routes and, for ffuf, SecLists
with src/core/sensitive_paths.py).

Dependency rule
---------------
This module imports only from stdlib.  It must never import from src.core,
src.tests, src.engine, or any third-party library.  It contains no logic --
only constant definitions evaluated once at import time.

Consumers
---------
    src/tests/helpers/response_inspector.py
        -- imports STACK_TRACE_PATTERNS and uses it in contains_stack_trace(),
           for test 6.1.

SENSITIVE_FIELD_NAMES lived here until 2026-10-28 and was removed with its only
consumer, response_inspector.contains_sensitive_fields(), which no test called:
the sensitive field names the tool really applies are test 2.5's own list, in
src/tests/domain_2/test_2_5_object_property_authorization.py.
"""

from __future__ import annotations

# ---------------------------------------------------------------------------
# Stack trace / framework leakage patterns
# ---------------------------------------------------------------------------

# Substrings that indicate a server-side exception was included in the response.
# Methodology reference: guarantee 6.1 -- error handling and information disclosure
# (docs/06-knowledge/03-guarantees.md, Section 6.1).
#
# The oracle for test 6.1 states that response bodies must not contain class
# names, file paths, or exception messages.  Each string here is a case-
# insensitive substring match applied by contains_stack_trace() in
# response_inspector.py.
STACK_TRACE_PATTERNS: tuple[str, ...] = (
    # Java / Spring Boot
    "at com.",
    "at org.",
    "at java.",
    "at sun.",
    "Caused by:",
    "java.lang.",
    "java.io.",
    "java.sql.",
    "org.springframework.",
    "Exception in thread",
    # Python
    "Traceback (most recent call last)",
    'File "/',
    "File '/",
    '.py", line',
    # Node.js
    "at Object.",
    "at Module.",
    "at Function.",
    "at /",
    # Ruby
    "app/",
    ".rb:",
    # PHP
    "Stack trace:",
    "PHP Fatal error",
    "PHP Warning",
    # Generic
    "NullPointerException",
    "IndexOutOfBoundsException",
    "StackOverflowError",
    "OutOfMemoryError",
)

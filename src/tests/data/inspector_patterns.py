"""
src/tests/data/inspector_patterns.py

Pure data constants for HTTP response security inspection.

Extracted from src/tests/helpers/response_inspector.py to follow the project
convention that raw test data (wordlists, payload sets, pattern tuples) lives
in src/tests/data/ rather than inside helper modules that contain logic.

Sibling data modules in this package:
    auth_payloads.py    -- JWT manipulation payloads for test 1.1 / 1.2
    injection_payloads.py -- SQL / NoSQL / command injection strings
    shadow_wordlists.py -- Path wordlists for shadow API discovery
    ssrf_payloads.py    -- SSRF target URLs and encoding variants

Dependency rule
---------------
This module imports only from stdlib.  It must never import from src.core,
src.tests, src.engine, or any third-party library.  It contains no logic --
only constant definitions evaluated once at import time.

Consumers
---------
    src/tests/helpers/response_inspector.py
        -- imports STACK_TRACE_PATTERNS and SENSITIVE_FIELD_NAMES and uses
           them in contains_stack_trace() and contains_sensitive_fields().
"""

from __future__ import annotations

# ---------------------------------------------------------------------------
# Stack trace / framework leakage patterns
# ---------------------------------------------------------------------------

# Substrings that indicate a server-side exception was included in the response.
# Methodology reference: Garanzia 6.1 -- Error Handling e Information Disclosure
# (3_TOP_metodologia.md, Section 6.1).
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

# ---------------------------------------------------------------------------
# Sensitive field names
# ---------------------------------------------------------------------------

# Field names that must never appear in API responses visible to the caller.
# Methodology reference: Garanzia 2.5 -- Excessive Data Exposure
# (3_TOP_metodologia.md, Section 2.5, OWASP API3:2023).
#
# The set uses normalised lowercase names without separators.  The scanner in
# response_inspector._scan_dict_for_sensitive_fields() strips underscores and
# hyphens before comparing, so "password_hash", "passwordHash", and
# "passwordhash" all match the entry "passwordhash".
SENSITIVE_FIELD_NAMES: frozenset[str] = frozenset(
    {
        "password",
        "passwordhash",
        "password_hash",
        "hashedpassword",
        "hashed_password",
        "passwd",
        "secret",
        "secretkey",
        "secret_key",
        "apikey",
        "api_key",
        "privatekey",
        "private_key",
        "ssn",
        "socialsecuritynumber",
        "social_security_number",
        "creditcard",
        "credit_card",
        "cardnumber",
        "card_number",
        "cvv",
        "pin",
        "otp",
        "totpsecret",
        "totp_secret",
        "accesstoken",
        "access_token",
        "refreshtoken",
        "refresh_token",
        "authtoken",
        "auth_token",
        "salt",
        "pepper",
    }
)

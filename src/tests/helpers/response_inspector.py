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
    test 2.5  -- Excessive data exposure: sensitive field detection
    test 6.1  -- Error handling: stack trace and debug field detection
    test 6.2  -- Security headers: presence and value validation
    test 6.3  -- Layer-7 hardening: CORS wildcard detection

Design
------
All pattern lists and frozen sets are module-level constants so that the
cost of compilation is paid once at import time, not per call.  Functions
that return lists return new list objects, never views into constants, so
callers cannot accidentally mutate the module state.

Dependency rule
---------------
This module imports only from stdlib.  It must never import from src.core,
src.tests, src.engine, or any third-party library.
"""

from __future__ import annotations

import re
from typing import Any

# ---------------------------------------------------------------------------
# Stack trace / framework leakage patterns
# ---------------------------------------------------------------------------

# Substrings that indicate a server-side exception was included in the response.
# Methodology reference: Garanzia 6.1 — Error Handling e Information Disclosure.
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
# Sensitive field names
# ---------------------------------------------------------------------------

# Field names that must never appear in API responses visible to the caller.
# Methodology reference: Garanzia 2.5 — Excessive Data Exposure.
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

# ---------------------------------------------------------------------------
# Security header definitions
# ---------------------------------------------------------------------------

# Expected security headers with their required values or validation rules.
# None as the expected value means "must be present, any non-empty value".
# Methodology reference: Garanzia 6.2 — Security Header Configurati.
SECURITY_HEADER_DEFINITIONS: dict[str, str | None] = {
    "strict-transport-security": "max-age=",  # must contain max-age
    "x-content-type-options": "nosniff",
    "x-frame-options": None,  # DENY or SAMEORIGIN both valid
    "content-security-policy": None,  # any non-empty value
    "permissions-policy": None,  # any non-empty value
}

# Headers that should NOT appear in API responses (information leakage).
LEAKY_HEADERS: frozenset[str] = frozenset(
    {
        "x-powered-by",
        "x-aspnet-version",
        "x-aspnetmvc-version",
        "server",  # only leaky if it contains version info
    }
)

# Known insecure x-frame-options value (deprecated per RFC 9110).
_XFRAME_DEPRECATED_VALUE: str = "allow-from"

# CSP wildcard that nullifies the policy.
_CSP_WILDCARD: str = "default-src *"


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------


def contains_stack_trace(body: str) -> list[str]:
    """
    Search a response body string for stack trace or framework leakage patterns.

    Methodology reference: Garanzia 6.1 — the oracle states that response
    bodies must not contain class names, file paths, or exception messages.

    Args:
        body: Raw response body as a string.

    Returns:
        List of matched pattern strings found in the body.
        Empty list if no stack trace patterns are detected.
    """
    if not body:
        return []

    found: list[str] = []
    body_lower = body.lower()

    for pattern in STACK_TRACE_PATTERNS:
        if pattern.lower() in body_lower:
            found.append(pattern)

    if _FRAMEWORK_VERSION_PATTERN.search(body):
        found.append("framework_version_string")

    if _FILESYSTEM_PATH_PATTERN.search(body):
        found.append("filesystem_path")

    return found


def contains_sensitive_fields(
    data: dict[str, Any],
    *,
    nested: bool = True,
) -> list[str]:
    """
    Recursively search a parsed JSON dict for sensitive field names.

    Compares lowercased field names against the SENSITIVE_FIELD_NAMES set.
    Optionally recurses into nested dicts and lists.

    Args:
        data:   Parsed JSON response body as a dict.
        nested: If True (default), recurse into nested dicts and list elements.
                If False, only inspect top-level keys.

    Returns:
        Sorted list of sensitive field names found (lowercased).
        Empty list if no sensitive fields are present.
    """
    found: set[str] = set()
    _scan_dict_for_sensitive_fields(data, found, recurse=nested)
    return sorted(found)


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


def check_security_headers(
    headers: dict[str, str],
) -> dict[str, str | None]:
    """
    Validate the presence and value of expected security headers.

    For each header defined in SECURITY_HEADER_DEFINITIONS, checks whether
    the header is present in the response and whether its value satisfies
    the expected constraint.  Returns a dict mapping each expected header
    to its actual value (or None if absent).

    Args:
        headers: Response headers dict.  Keys are expected to be lowercase
                 per RFC 9110 (SecurityClient normalizes them).

    Returns:
        Dict mapping each expected security header name (lowercase) to:
            - The actual header value string if present.
            - None if the header is absent.
        Callers treat None entries as missing headers (policy violation).
    """
    # Normalize input headers to lowercase for case-insensitive comparison.
    normalized: dict[str, str] = {k.lower(): v for k, v in headers.items()}
    result: dict[str, str | None] = {}

    for header_name in SECURITY_HEADER_DEFINITIONS:
        result[header_name] = normalized.get(header_name)

    return result


def find_missing_security_headers(headers: dict[str, str]) -> list[str]:
    """
    Return a list of expected security header names that are absent.

    Convenience wrapper around check_security_headers that filters to only
    the headers that are missing (value is None in the result).

    Args:
        headers: Response headers dict (keys need not be lowercase).

    Returns:
        Sorted list of missing security header names.
        Empty list if all expected headers are present.
    """
    checked = check_security_headers(headers)
    return sorted(name for name, value in checked.items() if value is None)


def find_invalid_security_headers(headers: dict[str, str]) -> list[str]:
    """
    Return a list of present security headers whose values do not meet policy.

    Checks each present header against its expected constraint:
        - strict-transport-security: must contain 'max-age='
        - x-content-type-options: must be exactly 'nosniff'
        - x-frame-options: must not be 'allow-from' (deprecated)
        - content-security-policy: must not contain 'default-src *'

    Args:
        headers: Response headers dict.

    Returns:
        Sorted list of header names that are present but have invalid values.
        Empty list if all present headers satisfy their constraints.
    """
    normalized: dict[str, str] = {k.lower(): v for k, v in headers.items()}
    invalid: list[str] = []

    hsts = normalized.get("strict-transport-security", "")
    if hsts and "max-age=" not in hsts.lower():
        invalid.append("strict-transport-security")

    xcto = normalized.get("x-content-type-options", "")
    if xcto and xcto.strip().lower() != "nosniff":
        invalid.append("x-content-type-options")

    xfo = normalized.get("x-frame-options", "")
    if xfo and xfo.strip().lower().startswith(_XFRAME_DEPRECATED_VALUE):
        invalid.append("x-frame-options")

    csp = normalized.get("content-security-policy", "")
    if csp and _CSP_WILDCARD in csp.lower():
        invalid.append("content-security-policy")

    return sorted(invalid)


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


def auth_errors_are_uniform(response_bodies: list[str]) -> bool:
    """
    Check whether multiple authentication error responses are indistinguishable.

    Used by test 6.1 to verify that the API does not distinguish between
    'user not found' and 'wrong password' in its error messages, which would
    enable username enumeration.

    Compares each response body against the first one.  If all responses are
    identical (or indistinguishable by simple string comparison), returns True.

    Args:
        response_bodies: List of raw response body strings from authentication
                         failure responses.  Must contain at least two entries.

    Returns:
        True if all response bodies are identical strings.
        False if any response body differs from the first (enumeration risk).

    Raises:
        ValueError: If fewer than two response bodies are provided.
    """
    if len(response_bodies) < 2:  # noqa: PLR2004
        raise ValueError(
            "auth_errors_are_uniform requires at least 2 response bodies to compare. "
            f"Got {len(response_bodies)}."
        )

    reference = response_bodies[0]
    return all(body == reference for body in response_bodies[1:])


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------


def _scan_dict_for_sensitive_fields(
    data: dict[str, Any],
    found: set[str],
    *,
    recurse: bool,
) -> None:
    """
    Recursively scan a dict for sensitive field names, accumulating into found.

    Args:
        data:    Dict to scan.
        found:   Mutable set to accumulate matching field names into.
        recurse: Whether to recurse into nested dicts and lists.
    """
    for key, value in data.items():
        if key.lower().replace("-", "").replace("_", "") in {
            s.replace("_", "") for s in SENSITIVE_FIELD_NAMES
        }:
            found.add(key.lower())

        if recurse:
            if isinstance(value, dict):
                _scan_dict_for_sensitive_fields(value, found, recurse=True)
            elif isinstance(value, list):
                for item in value:
                    if isinstance(item, dict):
                        _scan_dict_for_sensitive_fields(item, found, recurse=True)

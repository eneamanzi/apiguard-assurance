"""
src/tests/data/auth_payloads.py

Authentication attack payload catalogue for Domain 1 tests.

This module is pure data: it defines no functions and performs no I/O.

Design rationale
----------------
Malformed token values have an independent lifecycle from the test that uses
them.  Keeping them here means the list can be reviewed, extended, or trimmed
without opening the test module, and is consistent with the pattern established
by ``ssrf_payloads.py`` and ``injection_payloads.py``.

Sources
-------
1. OWASP API Security Top 10 2023 — API2:2023 Broken Authentication.
   URL: https://owasp.org/API-Security/editions/2023/en/0xa2-broken-authentication/

2. RFC 6750 — The OAuth 2.0 Authorization Framework: Bearer Token Usage.
   Section 2.1 defines the ``Authorization: Bearer <token>`` header format;
   the malformed variants below deliberately violate that format.
   URL: https://datatracker.ietf.org/doc/html/rfc6750

3. OWASP ASVS v5.0.0 — Chapter V6 (Stored Cryptography), Section V9
   (Communication), V11 (OAuth and OIDC).
"""

# ---------------------------------------------------------------------------
# Malformed Authorization header values (Test 1.1, sub-check B)
# ---------------------------------------------------------------------------

# Each entry is a 2-tuple: (header_value, human_readable_label).
#
# The label is included in Finding.detail and in EvidenceRecord.oracle_state
# so that a reader of the report can immediately understand what structural
# property was being tested.
#
# Every value is deliberately broken in a *different* way so that a single
# lucky bypass cannot explain all failures:
#
#   1. "Bearer"               — scheme present, token value entirely absent.
#   2. "Bearer null"          — literal string 'null'; common in JavaScript
#                               codebases where a null reference is coerced to
#                               string before the header is set.
#   3. "Bearer undefined"     — literal string 'undefined'; same root cause as
#                               above, different JS coercion path.
#   4. "no-scheme-..."        — raw string with no "Bearer " prefix; tests
#                               whether the server validates the scheme.
#   5. "Bearer XXXXXXXX"      — token body is structurally too short (8 chars)
#                               to be any real JWT, opaque token, or API key.
MALFORMED_TOKENS: tuple[tuple[str, str], ...] = (
    ("Bearer", "Bearer scheme with empty token value"),
    ("Bearer null", "literal string 'null' as token"),
    ("Bearer undefined", "literal string 'undefined' as token"),
    ("no-scheme-apiguard-probe", "raw string without Bearer prefix"),
    ("Bearer " + "X" * 8, "token body structurally too short for any real format"),
)

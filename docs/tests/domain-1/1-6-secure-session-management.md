# 1.6 Secure Session Management

> **Audience:** analysts, contributors · **Status:** implemented (v0.1.0) · **Source of truth:**
> [`src/tests/domain_1/test_1_6_secure_session_management.py`](../../../src/tests/domain_1/test_1_6_secure_session_management.py) ·
> **Verified:** 2026-10-05

| | |
|---|---|
| Test ID | `1.6` |
| Name | Secure Session Management in Distributed Architectures |
| Domain | 1 - Identity and Authentication |
| Priority / strategy | P3 / BLACK_BOX (network access only; the methodology calls it a configuration audit) |
| CWE | CWE-614 |
| Depends on | none |
| Configuration | [`tests.domain_1.test_1_6`](../../reference/configuration.md#testsdomain_1test_1_6---session-management) |

## What it checks

Session cookies issued by the API must carry `HttpOnly`, `Secure` and an appropriate `SameSite` attribute.

## How it works

1. `GET` (no credentials) each path in `cookie_probe_paths` (default `/`) and collect `Set-Cookie` headers.
2. Keep only cookies whose name matches `session_cookie_names` (case-insensitive; default `session`, `sid`,
   `PHPSESSID`, `JSESSIONID`, `connect.sid`, `_session`, `auth_session`, `user_session`).
3. For each session cookie:

| Condition | Finding |
|---|---|
| No `HttpOnly` | `Session Cookie '<name>' Missing HttpOnly Attribute` |
| No `Secure` | `Session Cookie '<name>' Missing Secure Attribute` |
| `check_samesite` and no `SameSite` | `Session Cookie '<name>' Missing SameSite Attribute` |
| `SameSite=None` | `Session Cookie '<name>' Has Forbidden SameSite=None` |
| `SameSite` different from `expected_samesite_value` (default `Strict`) | finding on the SameSite value |

## Outcomes

| Status | When |
|---|---|
| PASS | All session cookies compliant. Always carries the InfoNote `Manual Verification Required: Session Fixation (ASVS V3.2.1)`. |
| FAIL | At least one finding. |
| SKIP | No session cookie found on the probed paths (normal for APIs that use bearer tokens only). |
| ERROR | Unexpected exception. |

References: OWASP-API2:2023, OWASP-ASVS-v5.0.0-V3.2.3, NIST-SP-800-63B-4-S4.2, NIST-SP-800-204A-S4.3.

## Oracle states

`NO_SESSION_COOKIES_FOUND`, `SESSION_COOKIES_FOUND`, `COOKIE_ATTRIBUTES_COMPLIANT`, `COOKIE_MISSING_HTTPONLY`,
`COOKIE_MISSING_SECURE`, `COOKIE_SAMESITE_NONCOMPLIANT`, `COOKIE_SAMESITE_NONE_FORBIDDEN`.

## Prerequisites and effects on the target

Read-only `GET`s without credentials. Cookies set only after login are not seen.

## Configuration

`cookie_probe_paths` (add the paths that set cookies, e.g. a login page), `session_cookie_names` (must not be
empty), `check_samesite`, `expected_samesite_value`.

## Coverage against the methodology

Source: [`methodology.it.md` §1.6](../../knowledge/methodology/methodology.it.md).

| Methodology item | Status |
|---|---|
| `HttpOnly`, `Secure`, `SameSite=Strict` on session cookies | Implemented (unauthenticated responses only). |
| Session fixation (cookie regenerated after login) | Not implemented: requires a target-specific login flow; flagged by an InfoNote. |
| Session-store TTL ≤ token lifetime, replication mode, token entropy | Not implemented (needs access to the session store or source code). |

## Why it exists

OWASP API2:2023, OWASP ASVS v5.0.0 V3.2.x, NIST SP 800-63B-4 §4.2, NIST SP 800-204A §4.3. Without `HttpOnly` a
script can steal the session; without `Secure` the cookie travels over HTTP; without `SameSite` it is sent on
cross-site requests (CSRF).

## Limitations

- Only cookies returned to anonymous requests on the configured paths are examined.

## See also

- [`6.2 Security headers`](../domain-6/6-2-security-headers-audit.md)
- [`../README.md`](../README.md)

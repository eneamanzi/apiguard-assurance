# 6.2 Security Headers Audit

> **Audience:** analysts, contributors · **Status:** implemented (v0.1.0) · **Source of truth:**
> [`src/tests/domain_6/test_6_2_security_headers_audit.py`](../../../src/tests/domain_6/test_6_2_security_headers_audit.py),
> [`src/tests/helpers/response_inspector.py`](../../../src/tests/helpers/response_inspector.py) · **Verified:** 2026-10-05

| | |
|---|---|
| Test ID | `6.2` |
| Name | Security Headers Configured Appropriately |
| Domain | 6 - Configuration and Hardening |
| Priority / strategy | P3 / BLACK_BOX (network access only; the methodology calls it a configuration audit) |
| CWE | CWE-16 |
| Depends on | none |
| Configuration | [`tests.domain_6.test_6_2`](../../reference/configuration.md#testsdomain_6test_6_2---security-headers-audit) |

## What it checks

API responses must carry the standard security headers, must not disclose implementation details, and must do so
consistently across endpoints.

## How it works

All requests are `GET` without credentials (a `401` or `404` response still carries gateway-injected headers).

1. **Reference endpoint.** The first `GET` endpoint of the spec (non-parametric preferred). Its headers are
   checked:

| Header | Rule | Finding when violated |
|---|---|---|
| `Strict-Transport-Security` | present, contains `max-age=` | `Required Security Headers Missing` / `Security Headers Present but Misconfigured` |
| `X-Content-Type-Options` | exactly `nosniff` | same |
| `X-Frame-Options` | present, not `ALLOW-FROM` | same |
| `Content-Security-Policy` | present, does not contain `default-src *` | same |
| `Permissions-Policy` | present | same |
| `X-Powered-By`, `X-AspNet-Version`, `X-AspNetMvc-Version` | absent | `Server Identification Headers Disclose Implementation Details` |
| `Server` | no version (no `/` and no `N.N` pattern) | same |

2. **HSTS max-age.** Below `hsts_min_max_age_seconds` (default 31536000) → `HSTS max-age Below Required Minimum`.
   A missing `includeSubDomains` is mentioned in that finding's detail but is **not** a finding on its own here
   (test 1.5 does report it).
3. **Consistency.** Up to `endpoint_sample_size` further `GET` endpoints (default 5; `0` = all) are compared with
   the reference header set → `Security Header Inconsistency Across Endpoints`.

## Outcomes

| Status | When |
|---|---|
| PASS | Reference compliant and consistent across the sample. |
| FAIL | At least one finding. |
| SKIP | Attack surface unavailable, or no `GET` endpoint in the spec. |
| ERROR | Unexpected exception. |

References: OWASP ASVS v5.0.0 V3.4 (and V3.4.1, V13.4.6), OWASP API8:2023, RFC 6797 §6.1, NIST SP 800-52 Rev. 2,
CWE-200, Mozilla Observatory best practices.

## Prerequisites and effects on the target

Read-only `GET`s without credentials: 1 + `endpoint_sample_size` requests.

## Coverage against the methodology

Source: [`methodology.it.md` §6.2](../../knowledge/methodology/methodology.it.md). The required header list and
oracles follow the methodology checklist (HSTS, nosniff, frame options, CSP, permissions policy, no leaky
headers), applied to responses observed from outside rather than to the gateway configuration file.

## Why it exists

OWASP API8:2023 (Security Misconfiguration), OWASP ASVS v5.0.0 V3.4. Security headers are defence in depth against
client-side attacks and are the gateway's job to inject uniformly; headers applied only on some routes are a
misconfiguration in themselves.

## Limitations

- `X-Frame-Options` with any value other than `ALLOW-FROM` passes (e.g. a typo).
- `Permissions-Policy` content is not evaluated.
- Parametric `GET` endpoints may be sampled; their `404` responses are still used for the header check.

## See also

- [`1.5 Insecure credential transport`](../domain-1/1-5-insecure-credential-transport.md) · [`6.4 Hardcoded credentials`](6-4-hardcoded-credentials-audit.md)
- [`../README.md`](../README.md)

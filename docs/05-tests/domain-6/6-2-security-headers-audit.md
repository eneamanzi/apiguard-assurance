# 6.2 Security Headers Audit

> **Audience:** analysts, contributors · **Status:** rewritten in the test review (2026-10-23) ·
> **Source of truth:**
> [`src/tests/domain_6/test_6_2_security_headers_audit.py`](../../../src/tests/domain_6/test_6_2_security_headers_audit.py),
> [`src/tests/helpers/sampling.py`](../../../src/tests/helpers/sampling.py) · **Verified:** 2026-10-23

<!-- [[[cog import generate_docs as g; cog.out(g.test_header("6.2", page=cog.inFile)) ]]] -->

|  |  |
|---|---|
| Test ID | `6.2` |
| Name | Security Headers Audit |
| Domain | 6 - Configuration and Hardening |
| Priority / strategy | P3 / BLACK_BOX |
| Effect | READ_ONLY |
| CWE | none |
| Standards | `OWASP API8:2023`, `OWASP ASVS v5.0.0-3.4.3`, `OWASP ASVS v5.0.0-3.4.4`, `OWASP ASVS v5.0.0-3.4.6` |
| Tags | `security-headers`, `cors` |
| Prerequisites | none |
| Needs | - |
| Parameters | none |

<!-- [[[end]]] -->

**Same group:** tests `6.1`, `6.4`. HSTS is test `1.5`.

## 1. Guarantee

The defensive security headers are present, sound, and consistent across the services of the API. A PASS promises
`X-Content-Type-Options: nosniff`, a framing protection (CSP `frame-ancestors` or X-Frame-Options), and a CORS policy
that does not allow an arbitrary origin with credentials, on every sampled endpoint. OWASP API8:2023; ASVS
v5.0.0-3.4.3 (CSP), 3.4.4 (nosniff), 3.4.6 (frame-ancestors). HSTS moved to 1.5; Permissions-Policy dropped (not in
ASVS 3.4). No primary CWE (CWE-16 is a prohibited mapping category).

## 2. Sub-tests and coverage of the methodology

| Sub-test | Methodology (guarantee 6.2) |
|---|---|
| `content_type_options` | "X-Content-Type-Options: nosniff" (ASVS 3.4.4) |
| `framing_protection` | "X-Frame-Options / CSP frame-ancestors" (ASVS 3.4.6) |
| `cors_not_wildcard` | "CORS strict: not `*` with credentials" |
| consistency | "present on one endpoint and absent on another is a misconfiguration": each check is judged across a sample |
| left out | HSTS (test 1.5); Permissions-Policy (not in ASVS 3.4) |

## 3. Inputs

A sample of documented GET operations, one per service prefix (`src/tests/helpers/sampling.py`). No credential (the
headers must be on every response, including public ones).

## 4. Preconditions and reference responses

The attack surface. For CORS, an arbitrary `Origin` is sent and the reflection judged; no other reference.

## 5. Probes

For each sampled endpoint, one GET (the three header checks) and one GET with an arbitrary `Origin` (CORS).
READ_ONLY.

## 6. Oracle (per sub-test, aggregated over the sample)

| Case | Outcome / detail | Confidence |
|---|---|---|
| the header is present/sound on every sampled endpoint | `ENFORCED/PRESENT` | - |
| absent on all sampled endpoints | `VIOLATION/MISSING` | CERTAIN |
| present on some, absent on others | `VIOLATION/INCONSISTENT` | CERTAIN |
| (CORS) an arbitrary origin or `*` is allowed with credentials | `VIOLATION/CORS_WILDCARD_CREDENTIALS` | CERTAIN |
| (CORS) no sampled endpoint sends CORS headers | `NOT_APPLICABLE/NO_CORS` | - |

## 7. Outcomes

SKIP without a documented GET. FAIL on a missing, inconsistent or unsafe-CORS header; PASS when all three hold
across the sample.

## 8. Findings

"X-Content-Type-Options: nosniff missing/inconsistent", "Clickjacking protection ... missing/inconsistent", "Unsafe
CORS: an arbitrary origin is allowed with credentials", each naming how many sampled endpoints and an example.

## 9. Effects on the target

`READ_ONLY`.

## 10. Per gateway

Independent of the adapter: the headers are the gateway's or the app's; the probe reads them. Consistency across
services is exactly what a per-route gateway misconfiguration breaks.

## 11. Configuration

None.

## 12. Validation

Runs of 2026-10-23:

| Lab | Status | Basis |
|---|---|---|
| Forgejo + Kong, Forgejo + APISIX | **PASS** | nosniff and framing present and consistent across the sampled services; no CORS |
| crAPI + Kong | **FAIL**, 2 findings | nosniff and framing are **inconsistent** across crAPI's services (present on some, absent on others): a selective misconfiguration the single-endpoint check missed; CORS bounded |

Rule 9, both sides proven, agnostically: ENFORCED on Forgejo, VIOLATION (inconsistency) on crAPI. The sampling (one
endpoint per service) is what surfaces the inconsistency; a single-endpoint check would have passed crAPI.

## 13. Remediation

Set the headers at the gateway for every route: `X-Content-Type-Options: nosniff`, `Content-Security-Policy:
frame-ancestors 'self'` (and `object-src 'none'`, `base-uri 'none'`), and a CORS allow-list of trusted origins
(never `*` with credentials).

## 14. Limitations

- The sample is one endpoint per service: an inconsistency within a service (route A vs route B of the same prefix)
  may be missed.
- X-Frame-Options is accepted for framing although ASVS 5.0 marks it obsolete in favour of CSP `frame-ancestors`
  (it still protects browsers); the remedy recommends CSP.

## 15. Sources

- OWASP API8:2023 Security Misconfiguration: https://owasp.org/API-Security/editions/2023/en/0xa8-security-misconfiguration/
- OWASP ASVS v5.0.0-3.4.3, 3.4.4, 3.4.6 (Web Frontend Security headers): https://github.com/OWASP/ASVS/blob/v5.0.0/5.0/en/0x12-V3-Web-Frontend-Security.md
- CWE-1021 Improper Restriction of Rendered UI Layers (clickjacking): https://cwe.mitre.org/data/definitions/1021.html

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
| CWE | CWE-1021 |
| Standards | `OWASP API8:2023`, `OWASP ASVS v5.0.0-3.4.2`, `OWASP ASVS v5.0.0-3.4.4`, `OWASP ASVS v5.0.0-3.4.6` |
| Tags | `security-headers`, `cors` |
| Prerequisites | none |
| Needs | - |
| Parameters | none |

<!-- [[[end]]] -->

**Same group:** tests `6.1`, `6.4`. HSTS is test `1.5`.

## 1. Guarantee

The defensive security headers are present, sound, and consistent across the services of the API. A PASS promises
`X-Content-Type-Options: nosniff`, a framing protection (a CSP `frame-ancestors` that does not allow any site, or X-Frame-Options when there is
none), and a CORS policy that does not allow an arbitrary origin with credentials, on every sampled endpoint. OWASP
API8:2023; ASVS v5.0.0-3.4.2 (CORS), 3.4.4 (nosniff), 3.4.6 (frame-ancestors). 3.4.3 (a script CSP) was cited until
2026-11-05 and is not checked here. HSTS moved to 1.5; Permissions-Policy dropped (not in
ASVS 3.4). Primary CWE: CWE-1021 (improper restriction of rendered UI layers or frames), the weakness the framing
sub-test looks for, allowed for mapping in CWE 4.20; CWE-16 is not used because it is a category prohibited for
mapping.

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
| (CORS) the arbitrary origin is reflected with credentials | `VIOLATION/CORS_ORIGIN_REFLECTED` | CERTAIN: any site reads authenticated responses |
| (CORS) `*` with credentials | `VIOLATION/CORS_WILDCARD_CREDENTIALS` | FIRM: browsers refuse this combination (Fetch standard), so it exposes nothing as it stands; it is a policy meant to share credentialed responses with any origin (ASVS v5.0.0-3.4.2 allows `*` only without sensitive information) |
| (CORS) sampled endpoints send CORS headers and none allows an arbitrary origin with credentials | `ENFORCED/CORS_BOUNDED` | - |
| (CORS) no usable answer grants any cross-origin access to the arbitrary `Origin` | `ENFORCED/ORIGIN_NOT_ALLOWED`: a browser refuses that origin the response | - |
| (CORS) no usable answer at all to the cross-origin probe (no response, `429`, `5xx`) | `NOT_VERIFIABLE/NO_RESPONSE` | - |

## 7. Outcomes

SKIP without a documented GET. FAIL on a missing, inconsistent or unsafe-CORS header; PASS when all three hold
across the sample.

## 8. Findings

"X-Content-Type-Options: nosniff missing/inconsistent", "Clickjacking protection ... missing/inconsistent", "Unsafe
CORS: an arbitrary origin is allowed with credentials", each naming how many sampled endpoints and an example. The
proof (`evidence_ref`) is the response of that example endpoint, and for CORS the answer to the cross-origin probe on
it. Until 2026-11-03 it was the last response sampled, which for an inconsistent header could be an endpoint that
carries it: crAPI's two findings named `/community/api/v2/community/posts/recent` and pointed at
`/workshop/api/mechanic/`, a response with both headers present.

## 9. Effects on the target

`READ_ONLY`.

## 10. Per gateway

Independent of the adapter: the headers are the gateway's or the app's; the probe reads them. Consistency across
services is exactly what a per-route gateway misconfiguration breaks.

## 11. Configuration

None.

## 12. Validation

Runs of 2026-10-28 (the coverage column was added when a skipped sub-test began to lower it):

| Lab | Status | Basis |
|---|---|---|
| Forgejo + Kong, Forgejo + APISIX | **PASS**, `complete` (2026-11-03) | nosniff and framing present and consistent across the sampled services; no response to the arbitrary `Origin` carried a CORS grant, so `cors_not_wildcard` is `ENFORCED/ORIGIN_NOT_ALLOWED`. Until that day the same answer was judged `NOT_APPLICABLE/NO_CORS` and left the test `partial` |
| crAPI + Kong, until 2026-11-05 | **FAIL**, 2 findings | nosniff and framing are **inconsistent** across crAPI's services: absent on the community service's answers, present on the others. The cause was the lab's own gateway, not crAPI: its Kong set the two headers with `response-transformer` `replace`, which in Kong only rewrites a header the backend already sent (`kong/plugins/response-transformer/header_transformer.lua`, Kong 3.9.3), and crAPI's community service sends neither. A true finding for that deployment, which the single-endpoint check would have missed; CORS bounded |
| crAPI + Kong, 2026-11-05, the lab's Kong corrected | **PASS**, `complete` | the two headers are now also under `add` (set when absent), with `replace` kept for a backend that sends its own value (Forgejo's `SAMEORIGIN`): present on the three sampled services |

Rule 9, both sides proven, agnostically: ENFORCED on Forgejo and on the corrected crAPI lab, VIOLATION
(inconsistency) on crAPI before the correction. The sampling (one endpoint per service) is what surfaced the
inconsistency; a single-endpoint check would have passed crAPI. To see the violation again, move the two headers
back under `replace` only in `test-environments/crapi-kong/kong/kong.yml` and recreate the gateway (`docker compose
--env-file ../../.env up -d --force-recreate --wait kong`).

## 13. Remediation

Set the headers at the gateway for every route: `X-Content-Type-Options: nosniff`, `Content-Security-Policy:
frame-ancestors 'self'` (and `object-src 'none'`, `base-uri 'none'`), and a CORS allow-list of trusted origins
(never `*` with credentials).

## 14. Limitations

- The sample is one endpoint per service: an inconsistency within a service (route A vs route B of the same prefix)
  may be missed.
- X-Frame-Options is accepted for framing although ASVS 5.0 marks it obsolete in favour of CSP `frame-ancestors`
  (it still protects browsers); the remedy recommends CSP. When a CSP `frame-ancestors` is present it decides, as in a
  browser: one allowing any site (`*`, `http:`, `https:`) fails even next to `X-Frame-Options: DENY`.
- A CORS grant to the arbitrary origin without `Access-Control-Allow-Credentials: true` is `CORS_BOUNDED`: a browser
  then sends no cookie, so the responses it reads are the ones the probing site could fetch itself. ASVS
  v5.0.0-3.4.2 asks for an allowlist even then; that part is not judged.

## 15. Sources

- OWASP API8:2023 Security Misconfiguration: https://owasp.org/API-Security/editions/2023/en/0xa8-security-misconfiguration/
- OWASP ASVS v5.0.0-3.4.2, 3.4.4, 3.4.6 (Web Frontend Security headers): https://github.com/OWASP/ASVS/blob/v5.0.0/5.0/en/0x12-V3-Web-Frontend-Security.md
- CWE-1021 Improper Restriction of Rendered UI Layers (clickjacking): https://cwe.mitre.org/data/definitions/1021.html

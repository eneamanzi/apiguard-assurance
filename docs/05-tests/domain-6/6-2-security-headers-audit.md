# 6.2 Security Headers Audit

> **Audience:** analysts, contributors · **Source of truth:**
> [`src/tests/domain_6/test_6_2_security_headers_audit.py`](../../../src/tests/domain_6/test_6_2_security_headers_audit.py), [`src/tests/helpers/sampling.py`](../../../src/tests/helpers/sampling.py)

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
API8:2023; ASVS v5.0.0-3.4.2 (CORS), 3.4.4 (nosniff), 3.4.6 (frame-ancestors). 3.4.3 (a script CSP) is not checked here; HSTS is test 1.5's; Permissions-Policy is not
checked (not in ASVS 3.4). Primary CWE: CWE-1021 (improper restriction of rendered UI layers or frames), the weakness the framing
sub-test looks for, allowed for mapping in CWE 4.20; CWE-16 is not used because it is a category prohibited for
mapping.

## 2. Test

### 2.1 Sub-tests and coverage of the methodology

| Sub-test | Methodology (guarantee 6.2) |
|---|---|
| `content_type_options` | "X-Content-Type-Options: nosniff" (ASVS 3.4.4) |
| `framing_protection` | "X-Frame-Options / CSP frame-ancestors" (ASVS 3.4.6) |
| `cors_not_wildcard` | the arbitrary `Origin` is not granted with credentials; the methodology states it under guarantee 6.3 ("CORS strict"), which has no test of its own, and this test covers that part |
| consistency | "present on one endpoint and absent on another is a misconfiguration": each check is judged across a sample |
| left out | HSTS (test 1.5); Permissions-Policy (not in ASVS 3.4) |

### 2.2 Preconditions and reference responses

The attack surface. For CORS, an arbitrary `Origin` is sent and the reflection judged; no other reference.

### 2.3 Probes

For each sampled endpoint, one GET (the three header checks) and one GET with an arbitrary `Origin` (CORS).
READ_ONLY.

## 3. Oracle

Each check is judged over the sample: an answer of the table below is not the API's (it may be the gateway's own
error page) and is left out; with no usable answer left a sub-test is `NOT_VERIFIABLE` with their reason.

<!-- [[[cog import generate_docs as g; cog.out(g.oracle_table("6.2")) ]]] -->

**`content_type_options`**

| Case | Outcome / detail | Confidence |
|---|---|---|
| `X-Content-Type-Options: nosniff` (its first value) on every usable sampled answer | `ENFORCED/PRESENT` | - |
| `X-Content-Type-Options: nosniff` (its first value) absent from every usable sampled answer | `VIOLATION/MISSING` | CERTAIN |
| `X-Content-Type-Options: nosniff` (its first value) on some sampled answers and absent from others | `VIOLATION/INCONSISTENT` | CERTAIN |

**`framing_protection`**

| Case | Outcome / detail | Confidence |
|---|---|---|
| a CSP `frame-ancestors` not allowing any site, or else `X-Frame-Options` with one value, `DENY` or `SAMEORIGIN`, on every usable sampled answer | `ENFORCED/PRESENT` | - |
| a CSP `frame-ancestors` not allowing any site, or else `X-Frame-Options` with one value, `DENY` or `SAMEORIGIN`, absent from every usable sampled answer | `VIOLATION/MISSING` | CERTAIN |
| a CSP `frame-ancestors` not allowing any site, or else `X-Frame-Options` with one value, `DENY` or `SAMEORIGIN`, on some sampled answers and absent from others | `VIOLATION/INCONSISTENT` | CERTAIN |
| framing is refused on every sampled answer, by `X-Frame-Options` alone on some (ASVS v5.0.0-3.4.6 asks for `frame-ancestors`: a note) | `ENFORCED/XFO_ONLY` | - |

**`cors_not_wildcard`**

| Case | Outcome / detail | Confidence |
|---|---|---|
| an answer to the arbitrary `Origin` reflects it with `Access-Control-Allow-Credentials: true` | `VIOLATION/CORS_ORIGIN_REFLECTED` | CERTAIN |
| an answer carries `Access-Control-Allow-Origin: *` with credentials (browsers refuse it) | `VIOLATION/CORS_WILDCARD_CREDENTIALS` | FIRM |
| some answers grant CORS, none to the arbitrary origin with credentials | `ENFORCED/CORS_BOUNDED` | - |
| no served answer to the arbitrary `Origin` grants it | `ENFORCED/ORIGIN_NOT_ALLOWED` | - |
| no answer to the arbitrary `Origin` was served, and the refusals (`401`, `403`, ...) grant nothing: the policy of a served answer is not seen | `NOT_VERIFIABLE/PROBE_NOT_SERVED` | - |

<!-- [[[end]]] -->

A header sent twice reaches the test joined (`nosniff, nosniff`, httpx's reading of repeated fields): nosniff counts
when its first value is `nosniff` (the Fetch standard), X-Frame-Options when all its values are the same `DENY` or
`SAMEORIGIN` (the HTML standard). `CORS_WILDCARD_CREDENTIALS` is FIRM: browsers refuse `*` with credentials (Fetch standard), so it exposes nothing as
it stands; it shows a policy meant to share credentialed responses with any origin (ASVS v5.0.0-3.4.2 allows `*`
only without sensitive information).

<!-- [[[cog import generate_docs as g; cog.out(g.uninformative_answers("6.2", page=cog.inFile)) ]]] -->

The answers that say nothing about the guarantee by themselves, one rule for every test ([assessment model](../../04-architecture/03-assessment-model.md#answers-that-say-nothing-about-the-guarantee)), generated from the code:

| Answer | Sub-tests | Outcome / detail |
|---|---|---|
| `UPSTREAM_UNAVAILABLE` | every sub-test | `NOT_VERIFIABLE/UPSTREAM_UNAVAILABLE` |
| `RATE_LIMITED` | every sub-test | `NOT_VERIFIABLE/RATE_LIMITED` |
| `SERVER_ERROR` | every sub-test | `NOT_VERIFIABLE/SERVER_ERROR` |
| `NO_RESPONSE` | every sub-test | `NOT_VERIFIABLE/NO_RESPONSE` |

<!-- [[[end]]] -->

## 4. Validation

### 4.1 Oracle cases

<!-- [[[cog import generate_docs as g; cog.out(g.oracle_validation("6.2", page=cog.inFile)) ]]] -->

Every case of the oracle, produced on a lab and judged by the code: E1, [oracle validation](../../../experiments/README.md), campaign at commit `fc60b6f`. 16 of 16 produced cases gave the declared outcome; 0 no lab can produce.

| Case | Lab, how it is produced | Result |
|---|---|---|
| `content_type_options/ENFORCED/PRESENT` | forgejo-kong: the lab as built: the service's response-transformer sets X-Content-Type-Options: nosniff on the sampled answer | OK |
| `content_type_options/VIOLATION/MISSING/CERTAIN` | forgejo-kong: forgejo-service's response-transformer no longer adds or replaces X-Content-Type-Options and X-Frame-Options and removes Forgejo's own | OK |
| `content_type_options/VIOLATION/INCONSISTENT/CERTAIN` | crapi-kong: crAPI's response-transformer sets nosniff and X-Frame-Options under replace only, so the community service's answers (which send neither) lack them while identity's and workshop's carry them | OK |
| `framing_protection/ENFORCED/PRESENT` | forgejo-kong: forgejo-service's response-transformer adds Content-Security-Policy: default-src 'self'; frame-ancestors 'none', so every sampled answer has a frame-ancestors that allows no site | OK |
| `framing_protection/VIOLATION/MISSING/CERTAIN` | forgejo-kong: forgejo-service's response-transformer no longer sets X-Frame-Options and removes Forgejo's own SAMEORIGIN; its CSP (default-src 'self') has no frame-ancestors | OK |
| `framing_protection/VIOLATION/INCONSISTENT/CERTAIN` | crapi-kong: crAPI's response-transformer sets X-Frame-Options under replace only, so the community service's answers lack it while identity's and workshop's carry it | OK |
| `framing_protection/ENFORCED/XFO_ONLY` | forgejo-kong: the lab as built: X-Frame-Options: DENY on the sampled answer and a CSP default-src 'self' without frame-ancestors | OK |
| `cors_not_wildcard/VIOLATION/CORS_ORIGIN_REFLECTED/CERTAIN` | forgejo-kong: a temporary route GET ~/api/v1/orgs$ whose pre-function (header_filter) sends back the request's Origin with Access-Control-Allow-Credentials true on Forgejo's answer | OK |
| `cors_not_wildcard/VIOLATION/CORS_WILDCARD_CREDENTIALS/FIRM` | forgejo-kong: a temporary route GET ~/api/v1/orgs$ whose pre-function (header_filter) sends Access-Control-Allow-Origin: * with Access-Control-Allow-Credentials true on Forgejo's answer | OK |
| `cors_not_wildcard/ENFORCED/CORS_BOUNDED` | crapi-kong: the lab as built: crAPI's answers grant CORS, none to the arbitrary origin with credentials | OK |
| `cors_not_wildcard/ENFORCED/ORIGIN_NOT_ALLOWED` | forgejo-kong: the lab as built: Forgejo serves GET /api/v1/orgs to the arbitrary Origin with no CORS header | OK |
| `cors_not_wildcard/NOT_VERIFIABLE/PROBE_NOT_SERVED` | forgejo-kong: a temporary route GET ~/api/v1/orgs$ (the only sampled read) answers 401 itself with request-termination, with no CORS header, to the plain GET and to the cross-origin probe | OK |
| `*/NOT_VERIFIABLE/UPSTREAM_UNAVAILABLE` | forgejo-kong: a temporary route on the sampled read GET ~/api/v1/orgs$ answers 503 itself, to the plain GET and to the cross-origin probe | OK |
| `*/NOT_VERIFIABLE/RATE_LIMITED` | forgejo-kong: a temporary route on the sampled read GET ~/api/v1/orgs$ answers 429 itself | OK |
| `*/NOT_VERIFIABLE/SERVER_ERROR` | forgejo-kong: a temporary route GET ~/api/v1/orgs$ answers 500 itself | OK |
| `*/NOT_VERIFIABLE/NO_RESPONSE` | forgejo-kong: a temporary route on the sampled read GET ~/api/v1/orgs$ sleeps 7 s before proxying, past the run's read timeout of 5 s | OK |

<!-- [[[end]]] -->

### 4.2 Results on the labs

<!-- [[[cog import generate_docs as g; cog.out(g.lab_results("6.2", page=cog.inFile)) ]]] -->

No E2 campaign yet ([experiments](../../../experiments/README.md)).

<!-- [[[end]]] -->

## 5. Limitations

- The sample is one endpoint per service: an inconsistency within a service (route A vs route B of the same prefix)
  may be missed.
- X-Frame-Options alone is accepted for framing (`XFO_ONLY`, with a note), although ASVS 5.0 marks it obsolete in
  favour of CSP `frame-ancestors`: it still protects browsers. When a CSP `frame-ancestors` is present it decides, as
  in a browser: one allowing any site (`*`, `http:`, `https:`, `http://*`, `https://*`) fails even next to
  `X-Frame-Options: DENY`.
- CORS is probed with one arbitrary origin and a GET: an `Origin: null` granted with credentials (readable from a
  sandboxed frame) and the preflight policy of cross-origin writes are not probed.
- A CORS grant to the arbitrary origin without `Access-Control-Allow-Credentials: true` is `CORS_BOUNDED`: a browser
  then sends no cookie, so the responses it reads are the ones the probing site could fetch itself. ASVS
  v5.0.0-3.4.2 asks for an allowlist even then; that part is not judged.

## 6. Sources

- OWASP API8:2023 Security Misconfiguration: https://owasp.org/API-Security/editions/2023/en/0xa8-security-misconfiguration/
- OWASP ASVS v5.0.0-3.4.2, 3.4.4, 3.4.6 (Web Frontend Security headers): https://github.com/OWASP/ASVS/blob/v5.0.0/5.0/en/0x12-V3-Web-Frontend-Security.md
- CWE-1021 Improper Restriction of Rendered UI Layers (clickjacking): https://cwe.mitre.org/data/definitions/1021.html

## 7. Inputs

A sample of documented GET operations, one per service prefix (`src/tests/helpers/sampling.py`). No credential (the
headers must be on every response, including public ones).

## 8. Outcomes

SKIP without a documented GET. FAIL on a missing, inconsistent or unsafe-CORS header; PASS when all three hold
across the sample.

## 9. Findings

<!-- [[[cog import generate_docs as g; cog.out(g.finding_titles("6.2")) ]]] -->

- "X-Content-Type-Options: nosniff inconsistent across services"
- "X-Content-Type-Options: nosniff missing"
- "Clickjacking protection inconsistent across services"
- "Clickjacking protection missing"
- "Unsafe CORS: an arbitrary origin is allowed with credentials"
- "CORS allows any origin ('*') together with credentials"

<!-- [[[end]]] -->

Each names how many sampled endpoints and an example. The proof (`evidence_ref`) is the response of that example
endpoint, and for CORS the answer to the cross-origin probe on it. 
## 10. Effects on the target

`READ_ONLY`.

## 11. Per gateway

Independent of the adapter: the headers are the gateway's or the app's; the probe reads them. Consistency across
services is exactly what a per-route gateway misconfiguration breaks.

## 12. Configuration

None.

## 13. Remediation

Set the headers at the gateway for every route: `X-Content-Type-Options: nosniff`, `Content-Security-Policy:
frame-ancestors 'self'` (and `object-src 'none'`, `base-uri 'none'`), and a CORS allow-list of trusted origins
(never `*` with credentials).

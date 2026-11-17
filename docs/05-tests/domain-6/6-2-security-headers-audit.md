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
| `cors_not_wildcard` | the arbitrary `Origin` is not granted with credentials; the methodology states it under guarantee 6.3 ("CORS strict"), which has no test of its own, and this test covers that part (until 2026-11-16 this row quoted it as 6.2's) |
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

## 6. Oracle

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
`SAMEORIGIN` (the HTML standard). Until 2026-11-16 the joined text was compared whole, so an application and a
gateway both setting the header read as `MISSING`, CERTAIN; `frame-ancestors https://*` passed although it allows
any site; X-Frame-Options alone was `PRESENT`, citing ASVS 3.4.6, which asks for `frame-ancestors` (now
`XFO_ONLY` with a note); and a refusal without CORS headers was `ORIGIN_NOT_ALLOWED`, although an application may
add them only after its authentication (now it counts only when served, else `PROBE_NOT_SERVED`).
`CORS_WILDCARD_CREDENTIALS` is FIRM: browsers refuse `*` with credentials (Fetch standard), so it exposes nothing as
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

## 7. Outcomes

SKIP without a documented GET. FAIL on a missing, inconsistent or unsafe-CORS header; PASS when all three hold
across the sample.

## 8. Findings

<!-- [[[cog import generate_docs as g; cog.out(g.finding_titles("6.2")) ]]] -->

- "X-Content-Type-Options: nosniff inconsistent across services"
- "X-Content-Type-Options: nosniff missing"
- "Clickjacking protection inconsistent across services"
- "Clickjacking protection missing"
- "Unsafe CORS: an arbitrary origin is allowed with credentials"
- "CORS allows any origin ('*') together with credentials"

<!-- [[[end]]] -->

Each names how many sampled endpoints and an example. The proof (`evidence_ref`) is the response of that example
endpoint, and for CORS the answer to the cross-origin probe on it. Until 2026-11-03 it was the last response
sampled, which for an inconsistent header could be an endpoint that carries it.

## 9. Effects on the target

`READ_ONLY`.

## 10. Per gateway

Independent of the adapter: the headers are the gateway's or the app's; the probe reads them. Consistency across
services is exactly what a per-route gateway misconfiguration breaks.

## 11. Configuration

None.

## 12. Validation

**2026-11-16, after the review**: **PASS** on the three labs, `framing_protection` as `XFO_ONLY` with its note (the
labs' CSP is `default-src 'self'`, without `frame-ancestors`). Forgejo + Kong with a `post-function` on
`forgejo-api-route` sending `X-Frame-Options: DENY` and `X-Content-Type-Options: nosniff` twice each (checked with
`curl`: two lines of each): **PASS**; until that day the joined values (`DENY, DENY`) read as `MISSING`, CERTAIN. A
`response-transformer` `append` did not repeat the headers on Kong 3.9.3 and proves nothing.

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

**With the backend stopped** (Forgejo + Kong, the `forgejo` container stopped). The only sampled endpoint answers
Kong's own `503` ("failure to get a peer from the ring-balancer"). On 2026-11-14 the headers Kong adds were found
on it and judged present (**PASS** partial); since 2026-11-15 that answer is not judged: **INCONCLUSIVE**,
`NO_RESPONSE` on the three sub-tests (measured 2026-11-15; the three labs, running, give the results above).

**What each branch has been seen doing** (rule 9). Proven on a lab: `PRESENT` (both Forgejo labs, crAPI corrected),
`INCONSISTENT` (crAPI before the correction), `ORIGIN_NOT_ALLOWED` (both Forgejo labs), `CORS_BOUNDED` (crAPI),
`NO_RESPONSE` on the three sub-tests (the run above), and on 2026-11-15 on Forgejo + Kong with a temporary change
to `kong/kong.yml` (undone with `git checkout`, the lab checked back):
- `MISSING` (CERTAIN): the service's `response-transformer` no longer adds `X-Content-Type-Options` and removes
  Forgejo's own (`remove.headers`);
- `CORS_ORIGIN_REFLECTED` (CERTAIN): a route `~/api/v1/orgs$` whose `pre-function` (`header_filter`) sends back
  the request's `Origin` with `Access-Control-Allow-Credentials: true`;
- `CORS_WILDCARD_CREDENTIALS` (FIRM): the same route sending `*` with `Access-Control-Allow-Credentials: true`.

Every branch of this test has been seen.

## 13. Remediation

Set the headers at the gateway for every route: `X-Content-Type-Options: nosniff`, `Content-Security-Policy:
frame-ancestors 'self'` (and `object-src 'none'`, `base-uri 'none'`), and a CORS allow-list of trusted origins
(never `*` with credentials).

## 14. Limitations

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

## 15. Sources

- OWASP API8:2023 Security Misconfiguration: https://owasp.org/API-Security/editions/2023/en/0xa8-security-misconfiguration/
- OWASP ASVS v5.0.0-3.4.2, 3.4.4, 3.4.6 (Web Frontend Security headers): https://github.com/OWASP/ASVS/blob/v5.0.0/5.0/en/0x12-V3-Web-Frontend-Security.md
- CWE-1021 Improper Restriction of Rendered UI Layers (clickjacking): https://cwe.mitre.org/data/definitions/1021.html

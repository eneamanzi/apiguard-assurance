# 4.4 Request Size Limits

> **Audience:** analysts, contributors · **Status:** new in the test review (2026-10-23) ·
> **Source of truth:**
> [`src/tests/domain_4/test_4_4_request_size_limits.py`](../../../src/tests/domain_4/test_4_4_request_size_limits.py) ·
> **Verified:** 2026-10-23

<!-- [[[cog import generate_docs as g; cog.out(g.test_header("4.4", page=cog.inFile)) ]]] -->

|  |  |
|---|---|
| Test ID | `4.4` |
| Name | Request Size Limits |
| Domain | 4 - Availability and Resilience |
| Priority / strategy | P1 / BLACK_BOX |
| Effect | STRESSES_TARGET |
| CWE | CWE-400 |
| Standards | `OWASP API4:2023`, `OWASP ASVS v5.0.0-2.4.1`, `RFC 9110, Section 15.5.14` |
| Tags | `resource-consumption`, `size-limit` |
| Prerequisites | none |
| Needs | `GATEWAY` (optional), `USER_ACCOUNT` (optional) |
| Parameters | [`tests.domain_4.test_4_4`](../../03-reference/01-configuration.md#testsdomain_4test_4_4) |

<!-- [[[end]]] -->

**Same group:** tests `4.1`, `4.2`, `4.3` (resource-consumption limits).

## 1. Guarantee

The gateway rejects an oversized request body with `413` before routing it. A PASS promises an oversized body was
refused. The threat (OWASP API4:2023): without a limit, a large body ties up memory and bandwidth and can exhaust the
backend. ASVS v5.0.0-2.4.1 (controls against excessive resource use).

## 2. Sub-tests and coverage of the methodology

| Sub-test | Methodology (new guarantee) |
|---|---|
| `oversized_body_rejected` | send a body above the limit, expect 413 before it is processed |

## 3. Inputs

The documented write endpoint to probe (derived: the shortest documented POST/PUT/PATCH, or `probe_path`). The size
sent is the gateway's configured body-size limit plus a margin (read through `config_values`, `Need.GATEWAY`
optional), else `body_size_bytes`.

## 4. Preconditions and reference responses

None beyond the attack surface; user_a's credential is used when configured (optional need). The first request is
unauthenticated: a gateway that checks the size before anything else answers 413, and any other answer means it
forwarded the body, **except a 401 or 403**, which does not say who refused. The application may have refused after
the gateway forwarded the body, or the gateway itself before its size check (Kong runs `key-auth` before
`request-size-limiting`). Until 2026-11-04 that refusal was read as "forwarded", a false finding on a gateway that
authenticates first (owner decision of that day). Now the same body is sent once more with
user_a's credential and that answer is judged; when it is refused too, a forged credential (a random value placed as
the run's credential is) tells who refused: the same status means user_a's credential did not get past the first
refuser, a different status that it did, and the body went past it without a 413.

## 5. Probes

One POST with a body of the chosen size, no credential; after a 401 or 403, the same POST with user_a's credential,
and after a second refusal the same POST with a forged credential (three at most). Effect `STRESSES_TARGET` (a large
body); runs last. No data is changed: the body (`{"data": "AAA..."}`) holds no field a real write expects, so an
application refuses it rather than creating anything (Forgejo answers `403` for the token's scope, crAPI `400`
"product_id is required").

## 6. Oracle (`oversized_body_rejected`)

| Case | Outcome / detail | Confidence |
|---|---|---|
| the body answers `413` | `ENFORCED/SIZE_LIMIT_ENFORCED` | - |
| the gateway's configured limit was read and the body above it is not rejected | `VIOLATION/NO_SIZE_LIMIT` | CERTAIN |
| no configured limit readable; a body of the default size is not rejected | `VIOLATION/NO_SIZE_LIMIT` | FIRM (a larger limit may exist) |
| the unauthenticated body is refused (401, 403) and no user_a credential is configured | `NOT_VERIFIABLE/NO_CREDENTIAL_TO_RETRY` | - |
| refused with user_a's credential too, with the status a forged credential gets: the credential did not get past the first refuser | `NOT_VERIFIABLE/REFUSED_BEFORE_SIZE_CHECK` | - |
| the endpoint answers 5xx / unavailable | `NOT_VERIFIABLE/UPSTREAM_UNAVAILABLE` | - |
| the probe gets no answer at all (the connection is closed or times out), so nothing can be read | `NOT_VERIFIABLE/NO_RESPONSE` | - |

## 7. Outcomes

SKIP without a documented write endpoint. FAIL when the oversized body is forwarded, PASS on a 413.

## 8. Findings

"Oversized body not rejected: `<path>`", `evidence_ref` the probe request.

## 9. Effects on the target

`STRESSES_TARGET`: up to three oversized bodies (unauthenticated, then with user_a's credential, then with a forged
one). Nothing created: the body holds no field a write expects.

## 10. Per gateway

Independent of the adapter: the 413 is the gateway's; the configured size limit is read through the adapter when
available, to send a body just above it.

## 11. Configuration

<!-- [[[cog import generate_docs as g; cog.out(g.test_params("4.4", page=cog.inFile)) ]]] -->

Section [`tests.domain_4.test_4_4`](../../03-reference/01-configuration.md#testsdomain_4test_4_4) of `config.yaml`:

| Key | Type | Default | Description |
|---|---|---|---|
| `body_size_bytes` | int ≥1024 | `2000000` | The size of the body sent when the gateway's configured limit cannot be read. A body above a sane API limit (default 2 MB); a gateway that accepts it has no small body-size limit. |
| `probe_path` | string | `""` | The documented write path to probe; empty derives the shortest documented write. |

<!-- [[[end]]] -->

## 12. Validation

Runs of 2026-10-23; the rows were measured again on 2026-11-04 (4.4 alone), after the authenticated retry:

| Lab | Status | Basis |
|---|---|---|
| Forgejo + Kong, Forgejo + APISIX | **FAIL** | a 2 MB body to `POST /api/v1/orgs`: `401` without a credential, `403` with user_a's ("token does not have at least one of required scope(s)", Forgejo reading the token), `401` with the forged one: the body reached Forgejo without a 413, so no body-size limit on the gateway (FIRM: a larger limit may exist) |
| crAPI + Kong | **FAIL** (2026-11-04); **INCONCLUSIVE or FAIL, by a race** before (8 isolated runs on 2026-11-03: 5 INCONCLUSIVE, 3 FAIL) | the probe is `POST /workshop/api/shop/orders`: `401` without a credential, then `400` "product_id is required" with user_a's, the application reading the body: forwarded without a 413. The unauthenticated request is subject to a race: crAPI's workshop service answers `401` and closes the connection, sometimes before the 2 MB upload has finished. When the close comes first, httpx raises `RemoteProtocolError`, a non-idempotent request that may already have been applied is not sent again (rule of 2026-10-28), and the test records `NOT_VERIFIABLE/UPSTREAM_UNAVAILABLE` without retrying with the credential |
| a scratch server outside the repository (2026-11-04) answering `401 "Invalid authentication credentials"` to any request without its key, and `413` above 1 MB with it, as Kong's `key-auth` before `request-size-limiting` | **PASS** with the key as user_a's token; **INCONCLUSIVE** with a token that is not the key | with the key: `401`, then `413`, `SIZE_LIMIT_ENFORCED` (a false FAIL on the `401` before the correction). Without it: `401` three times, `REFUSED_BEFORE_SIZE_CHECK` |
| Forgejo + Kong, with the plugin below | **PASS** | a `request-size-limiting` plugin (1 MB) answers 413 to the 2 MB body |

**The case the labs lack, and how to undo it.** Add a global `request-size-limiting` plugin (`allowed_payload_size:
1`) to `test-environments/forgejo-kong/kong/kong.yml`, reload Kong (`docker compose ... up -d --force-recreate --wait
kong`); undo with `git checkout` and the same command. The lab was checked back to FAIL. Rule 9: both sides proven.

## 13. Remediation

Configure a request-size limit on the gateway (Kong `request-size-limiting`, Nginx `client_max_body_size`) so an
oversized body is rejected with 413 before it reaches the backend (OWASP API4:2023, ASVS v5.0.0-2.4.1).

## 14. Limitations

- Without a readable configured limit, the test asserts only "no limit at the tested size" (FIRM): a limit above the
  tested size is not detected (raise `body_size_bytes`). On the two supported gateways that is always the case:
  Kong's `request-size-limiting.allowed_payload_size` is an integer (checked on its schema 2026-11-03) and the
  configuration scan collects strings only, so the CERTAIN branch is not reached today.
- Only the request body is checked, not the response size or header size.
- **A target that answers before the upload finishes cannot be judged.** A service that sends its response (a `401`,
  for instance) and closes the connection mid-upload makes the client raise a protocol error, and a non-idempotent
  request that may already have been applied is never sent again (RFC 9110 section 9.2.2), so the status never
  reaches the oracle: the result is `NOT_VERIFIABLE/UPSTREAM_UNAVAILABLE`. crAPI does this in some runs and not in
  others, depending on whether the upload finishes before the close (section 12). The
  gateway did forward the oversized body in that case, which would be a violation, but this test does not see it.
- A backend that happens to reject the body for another reason before the gateway's size check would read as a limit
  only if it answers 413.
- A gateway that authenticates before its size check and does not accept user_a's credential (its own API key,
  for instance) cannot be judged: `REFUSED_BEFORE_SIZE_CHECK`.
- The probe prefers a write that requires authentication (unauthenticated -> 401, nothing created). Where only a
  public write exists and the gateway has no size limit, a body under the limit could be processed and create an
  object: the oversized probe is still rejected by any size limit, but the absence of one on a public write is a
  creation risk.

## 15. Sources

- OWASP API4:2023 Unrestricted Resource Consumption: https://owasp.org/API-Security/editions/2023/en/0xa4-unrestricted-resource-consumption/
- OWASP ASVS v5.0.0-2.4.1 (anti-automation / resource-consumption controls): https://github.com/OWASP/ASVS/blob/v5.0.0/5.0/en/0x11-V2-Validation-and-Business-Logic.md
- RFC 9110 section 15.5.14 (413 Content Too Large): https://www.rfc-editor.org/rfc/rfc9110.html#section-15.5.14
- CWE-400 Uncontrolled Resource Consumption: https://cwe.mitre.org/data/definitions/400.html

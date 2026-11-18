# 4.4 Request Size Limits

> **Audience:** analysts, contributors · **Source of truth:**
> [`src/tests/domain_4/test_4_4_request_size_limits.py`](../../../src/tests/domain_4/test_4_4_request_size_limits.py)

<!-- [[[cog import generate_docs as g; cog.out(g.test_header("4.4", page=cog.inFile)) ]]] -->

|  |  |
|---|---|
| Test ID | `4.4` |
| Name | Request Size Limits |
| Domain | 4 - Availability and Resilience |
| Priority / strategy | P1 / BLACK_BOX |
| Effect | STRESSES_TARGET |
| CWE | CWE-400 |
| Standards | `OWASP API4:2023`, `RFC 9110, Section 15.5.14` |
| Tags | `resource-consumption`, `size-limit` |
| Prerequisites | none |
| Needs | `GATEWAY` (optional), `USER_ACCOUNT` (optional) |
| Parameters | [`tests.domain_4.test_4_4`](../../03-reference/01-configuration.md#testsdomain_4test_4_4) |

<!-- [[[end]]] -->

**Same group:** tests `4.1`, `4.2`, `4.3` (resource-consumption limits).

## 1. Guarantee

An oversized request body is refused with `413` before it is processed: by the gateway, where the limit belongs
(the body then never reaches the backend), or by the application. A PASS promises an oversized body was refused, not
by which of the two (section 5). The threat (OWASP API4:2023): without a limit, a large body ties up memory and bandwidth and can exhaust the
backend; API4:2023 asks to "define and enforce a maximum size of data on all incoming parameters and payloads".
ASVS 5.0.0 has no requirement on the size of a request body: v5.0.0-2.4.1, which looks close, is about excessive
calls (test 4.1).

## 2. Test

### 2.1 Sub-tests and coverage of the methodology

| Sub-test | Methodology (new guarantee) |
|---|---|
| `oversized_body_rejected` | send a body above the limit, expect 413 before it is processed |
| `chunked_body_rejected` | the same body in chunks (`Transfer-Encoding: chunked`, no `Content-Length`), expect 413: a gateway that weighs only the declared length lets it through |

### 2.2 Preconditions and reference responses

None beyond the attack surface; user_a's credential is used when configured (optional need). The first request is
unauthenticated: a gateway that checks the size before anything else answers 413, and any other answer means it
forwarded the body, **except a 401 or 403**, which does not say who refused. The application may have refused after
the gateway forwarded the body, or the gateway itself before its size check (Kong runs `key-auth` before
`request-size-limiting`). Now the same body is sent once more with
user_a's credential and that answer is judged; when it is refused too, a forged credential (a random value placed as
the run's credential is) tells who refused: the same status means user_a's credential did not get past the first
refuser, a different status that it did, and the body went past it without a 413.

### 2.3 Probes

One request (the documented method) with a body of the chosen size, no credential; after a 401 or 403, the same
request with user_a's credential, and after a second refusal with a forged credential (three at most); then the
same, the body sent in chunks of 64 KiB without a `Content-Length` (`chunked_body_rejected`). The method is the documented one: a gateway may refuse a
method its route does not serve before any size check (Kong answers `404` "no Route matched"). Effect `STRESSES_TARGET` (a large
body); runs last. No data is changed: the body (`{"data": "AAA..."}`) holds no field a real write expects, so an
application refuses it rather than creating anything (Forgejo answers `403` for the token's scope, crAPI `400`
"product_id is required").

## 3. Oracle (`oversized_body_rejected`)

<!-- [[[cog import generate_docs as g; cog.out(g.oracle_table("4.4")) ]]] -->

**`oversized_body_rejected`**

| Case | Outcome / detail | Confidence |
|---|---|---|
| the body answers `413` | `ENFORCED/SIZE_LIMIT_ENFORCED` | - |
| the body, above every limit read for the routes that may serve the path, is not rejected: the limit is configured and not enforced | `VIOLATION/NO_SIZE_LIMIT` | CERTAIN |
| no limit read for every route that may serve the path, and the body of `body_size_bytes` is not rejected (a larger limit may exist) | `VIOLATION/NO_SIZE_LIMIT` | FIRM |
| the body is refused (`401`, `403`) without a credential, and no user_a account to retry | `NOT_VERIFIABLE/NO_CREDENTIAL_TO_RETRY` | - |
| the body is refused with user_a's credential too, with the status a forged credential gets: the credential did not get past the first refuser | `NOT_VERIFIABLE/REFUSED_BEFORE_SIZE_CHECK` | - |

**`chunked_body_rejected`**

| Case | Outcome / detail | Confidence |
|---|---|---|
| the chunked body answers `413` | `ENFORCED/SIZE_LIMIT_ENFORCED` | - |
| the chunked body, above every limit read for the routes that may serve the path, is not rejected: the limit is configured and not enforced | `VIOLATION/NO_SIZE_LIMIT` | CERTAIN |
| no limit read for every route that may serve the path, and the chunked body of `body_size_bytes` is not rejected (a larger limit may exist) | `VIOLATION/NO_SIZE_LIMIT` | FIRM |
| the chunked body is refused (`401`, `403`) without a credential, and no user_a account to retry | `NOT_VERIFIABLE/NO_CREDENTIAL_TO_RETRY` | - |
| the chunked body is refused with user_a's credential too, with the status a forged credential gets: the credential did not get past the first refuser | `NOT_VERIFIABLE/REFUSED_BEFORE_SIZE_CHECK` | - |

<!-- [[[end]]] -->

<!-- [[[cog import generate_docs as g; cog.out(g.uninformative_answers("4.4", page=cog.inFile)) ]]] -->

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

<!-- [[[cog import generate_docs as g; cog.out(g.oracle_validation("4.4", page=cog.inFile)) ]]] -->

Every case of the oracle, produced on a lab and judged by the code: E1, [oracle validation](../../../experiments/README.md), campaign at commit `fc60b6f`. 14 of 14 produced cases gave the declared outcome; 0 no lab can produce.

| Case | Lab, how it is produced | Result |
|---|---|---|
| `oversized_body_rejected/ENFORCED/SIZE_LIMIT_ENFORCED` | forgejo-kong: request-size-limiting allowed_payload_size 1 (MB) on forgejo-service: the body of 1049600 bytes to POST /api/v1/orgs answers 413 | OK |
| `oversized_body_rejected/VIOLATION/NO_SIZE_LIMIT/CERTAIN` | forgejo-kong: the 1 MB plugin on forgejo-service and a route POST ~/api/v1/orgs$ whose pre-function answers 200 before the size check: the body above the limit read is not rejected | OK |
| `oversized_body_rejected/VIOLATION/NO_SIZE_LIMIT/FIRM` | forgejo-kong: the lab as built: no size limit; the 2 MB body to POST /api/v1/orgs answers 401, then 403 with user_a's token, 401 with the forged one: forwarded | OK |
| `oversized_body_rejected/NOT_VERIFIABLE/NO_CREDENTIAL_TO_RETRY` | forgejo-kong: the lab as built, user_a removed from the run's configuration: the body refused 401 without a credential to retry | OK |
| `oversized_body_rejected/NOT_VERIFIABLE/REFUSED_BEFORE_SIZE_CHECK` | forgejo-kong: a route ~/api/v1/orgs$ with key-auth before request-size-limiting: the body refused 401 without a credential, with user_a's Forgejo token, and with the forged one | OK |
| `chunked_body_rejected/ENFORCED/SIZE_LIMIT_ENFORCED` | forgejo-kong: request-size-limiting allowed_payload_size 1 (MB) on forgejo-service: the chunked body of 1049600 bytes to POST /api/v1/orgs answers 413 (the same run as the whole body) | OK |
| `chunked_body_rejected/VIOLATION/NO_SIZE_LIMIT/CERTAIN` | forgejo-kong: the 1 MB plugin on forgejo-service and a route POST ~/api/v1/orgs$ whose pre-function answers 200 before the size check: the chunked body above the limit read is not rejected (the same run as the whole body) | OK |
| `chunked_body_rejected/VIOLATION/NO_SIZE_LIMIT/FIRM` | forgejo-kong: the lab as built: no size limit; the 2 MB chunked body to POST /api/v1/orgs answers 401, then 403 with user_a's token, 401 with the forged one: forwarded | OK |
| `chunked_body_rejected/NOT_VERIFIABLE/NO_CREDENTIAL_TO_RETRY` | forgejo-kong: the lab as built, user_a removed from the run's configuration: the chunked body refused 401 without a credential to retry | OK |
| `chunked_body_rejected/NOT_VERIFIABLE/REFUSED_BEFORE_SIZE_CHECK` | forgejo-kong: a route ~/api/v1/orgs$ with key-auth before request-size-limiting: the chunked body refused 401 without a credential, with user_a's Forgejo token, and with the forged one | OK |
| `*/NOT_VERIFIABLE/UPSTREAM_UNAVAILABLE` | forgejo-kong: the forgejo container stopped (the specification read from a local copy): Kong answers the oversized POST with 502/503 | OK |
| `*/NOT_VERIFIABLE/RATE_LIMITED` | forgejo-kong: a route POST ~/api/v1/orgs$ whose pre-function reads the body and answers 429 | OK |
| `*/NOT_VERIFIABLE/SERVER_ERROR` | forgejo-kong: a route POST ~/api/v1/orgs$ whose pre-function reads the body and answers 500 | OK |
| `*/NOT_VERIFIABLE/NO_RESPONSE` | forgejo-kong: a route POST ~/api/v1/orgs$ whose pre-function reads the body, then sleeps 7 s before Forgejo answers, with the run's read timeout at 5 s (a POST is not retried) | OK |

<!-- [[[end]]] -->

### 4.2 Results on the labs

<!-- [[[cog import generate_docs as g; cog.out(g.lab_results("4.4", page=cog.inFile)) ]]] -->

No E2 campaign yet ([experiments](../../../experiments/README.md)).

<!-- [[[end]]] -->

## 5. Limitations

- **Who answered the `413` is not told.** The gateway's and the application's are the same HTTP answer; only signals
  of one gateway would tell them apart (Kong's own answers carry its latency header), and a test does not rest on
  lists of gateways (rule 10). A `413` from the application still refuses the body, but after it crossed the
  gateway: the protection is weaker. When the gateway's limits are read, a `413` to a body above them is consistent
  with the gateway's limit, which the finding or the evidence names.

- Without a limit read for every route that may serve the path, the test asserts only "no limit at the tested
  size" (FIRM): a limit above the tested size is not detected (raise `body_size_bytes`).
- With a limit read, the body sent is that limit plus 1024 bytes, however large: Kong's default
  `allowed_payload_size` is 128 megabytes, and a gateway configured with it receives a body that size (up to three
  times, section 2.3).
- Only the request body is checked, not the response size or header size.
- **A target that answers before the upload finishes cannot be judged.** A service that sends its response (a `401`,
  for instance) and closes the connection mid-upload makes the client raise a protocol error, and a non-idempotent
  request that may already have been applied is never sent again (RFC 9110 section 9.2.2), so the status never
  reaches the oracle: the result is `NOT_VERIFIABLE/UPSTREAM_UNAVAILABLE`. crAPI does this in some runs and not in
  others, depending on whether the upload finishes before the close (section 4). The
  gateway did forward the oversized body in that case, which would be a violation, but this test does not see it.
- A backend that happens to reject the body for another reason before the gateway's size check would read as a limit
  only if it answers 413.
- A gateway that authenticates before its size check and does not accept user_a's credential (its own API key,
  for instance) cannot be judged: `REFUSED_BEFORE_SIZE_CHECK`.
- The probe prefers a write that requires authentication (unauthenticated -> 401, nothing created). Where only a
  public write exists and the gateway has no size limit, a body under the limit could be processed and create an
  object: the oversized probe is still rejected by any size limit, but the absence of one on a public write is a
  creation risk.

## 6. Sources

- OWASP API4:2023 Unrestricted Resource Consumption: https://owasp.org/API-Security/editions/2023/en/0xa4-unrestricted-resource-consumption/
- RFC 9110 section 15.5.14 (413 Content Too Large): https://www.rfc-editor.org/rfc/rfc9110.html#section-15.5.14
- CWE-400 Uncontrolled Resource Consumption: https://cwe.mitre.org/data/definitions/400.html

## 7. Inputs

The documented write to probe (derived: the shortest documented POST, PUT or PATCH, sent with its documented
method; or `probe_path`, sent as a POST). With a
gateway (`Need.GATEWAY`, optional), its body-size limits (`body_size_limits()`, in bytes, section 11) and its routes,
both kept as evidence. A limit counts only when it may apply to the probe, as in test
[4.1](4-1-rate-limiting.md#7-inputs): the enabled limits on every request, on the backend and on the route, for every
route that may serve the probe's method and path (`src/tests/helpers/route_limits.py`). The size sent is the largest of
those limits plus 1024 bytes when every such route has one, so the body is above whichever the gateway applies;
otherwise `body_size_bytes`. 
## 8. Outcomes

SKIP without a documented write endpoint. FAIL when the oversized body is forwarded, PASS on a 413.

## 9. Findings

<!-- [[[cog import generate_docs as g; cog.out(g.finding_titles("4.4")) ]]] -->

- "Oversized body not rejected: <label>"

<!-- [[[end]]] -->

`<label>` is the method and path sent, with "(chunked)" for the chunked body; `evidence_ref` the probe request.

## 10. Effects on the target

`STRESSES_TARGET`: up to six oversized bodies (unauthenticated, then with user_a's credential, then with a forged
one; whole, then in chunks). Nothing created: the body holds no field a write expects.

## 11. Per gateway

The 413 is the gateway's; the limits read through the adapter size the body (`body_size_limits()`, mapping in the
[adapter guide](../../02-guides/03-extending/04-add-a-gateway-adapter.md)):

- **Kong** `request-size-limiting`: `allowed_payload_size` times its `size_unit` (bytes 1, kilobytes 1024,
  megabytes 1048576, megabytes by default: the factors of Kong's handler). A plugin bound to a consumer is left out.
- **APISIX** `client-control`: `max_body_size` in bytes, compared with the request's `Content-Length`; 0 (no
  restriction) is left out.

## 12. Configuration

<!-- [[[cog import generate_docs as g; cog.out(g.test_params("4.4", page=cog.inFile)) ]]] -->

Section [`tests.domain_4.test_4_4`](../../03-reference/01-configuration.md#testsdomain_4test_4_4) of `config.yaml`:

| Key | Type | Default | Description |
|---|---|---|---|
| `body_size_bytes` | int ≥1024 | `2000000` | The size of the body sent when the gateway's configured limit cannot be read. A body above a sane API limit (default 2 MB); a gateway that accepts it has no small body-size limit. |
| `probe_path` | string | `""` | The documented write path to probe, sent as a POST; empty derives the shortest documented write, sent with its documented method. |

<!-- [[[end]]] -->

## 13. Remediation

Configure a request-size limit on the gateway (Kong `request-size-limiting`, Nginx `client_max_body_size`) so an
oversized body is rejected with 413 before it reaches the backend (OWASP API4:2023).

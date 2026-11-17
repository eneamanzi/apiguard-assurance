# 4.4 Request Size Limits

> **Audience:** analysts, contributors · **Status:** new in the test review (2026-10-23), again with its oracle in code (2026-11-16) ·
> **Source of truth:**
> [`src/tests/domain_4/test_4_4_request_size_limits.py`](../../../src/tests/domain_4/test_4_4_request_size_limits.py) ·
> **Verified:** 2026-11-16

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
by which of the two (section 14). The threat (OWASP API4:2023): without a limit, a large body ties up memory and bandwidth and can exhaust the
backend; API4:2023 asks to "define and enforce a maximum size of data on all incoming parameters and payloads".
ASVS 5.0.0 has no requirement on the size of a request body: v5.0.0-2.4.1, cited until 2026-11-16, is about
excessive calls (test 4.1).

## 2. Sub-tests and coverage of the methodology

| Sub-test | Methodology (new guarantee) |
|---|---|
| `oversized_body_rejected` | send a body above the limit, expect 413 before it is processed |
| `chunked_body_rejected` | the same body in chunks (`Transfer-Encoding: chunked`, no `Content-Length`), expect 413: a gateway that weighs only the declared length lets it through (since 2026-11-16) |

## 3. Inputs

The documented write to probe (derived: the shortest documented POST, PUT or PATCH, sent with its documented
method; or `probe_path`, sent as a POST). With a
gateway (`Need.GATEWAY`, optional), its body-size limits (`body_size_limits()`, in bytes, section 10) and its routes,
both kept as evidence. A limit counts only when it may apply to the probe, as in test
[4.1](4-1-rate-limiting.md#3-inputs): the enabled limits on every request, on the backend and on the route, for every
route that may serve the probe's method and path (`src/tests/helpers/route_limits.py`). The size sent is the largest of
those limits plus 1024 bytes when every such route has one, so the body is above whichever the gateway applies;
otherwise `body_size_bytes`. Until 2026-11-15 the limit was looked for among the configuration text values, which
hold strings, and was never read (both gateways state it as a number).

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

One request (the documented method) with a body of the chosen size, no credential; after a 401 or 403, the same
request with user_a's credential, and after a second refusal with a forged credential (three at most); then the
same, the body sent in chunks of 64 KiB without a `Content-Length` (`chunked_body_rejected`). Until
2026-11-16 the probe was always a POST, also to an operation documented only as PUT or PATCH: a gateway may refuse a
method its route does not serve before any size check (Kong answers `404` "no Route matched"), which read as a
forwarded body. Effect `STRESSES_TARGET` (a large
body); runs last. No data is changed: the body (`{"data": "AAA..."}`) holds no field a real write expects, so an
application refuses it rather than creating anything (Forgejo answers `403` for the token's scope, crAPI `400`
"product_id is required").

## 6. Oracle (`oversized_body_rejected`)

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

Until 2026-11-16 a `429` was read as a forwarded body (`VIOLATION/NO_SIZE_LIMIT`), and a closed or timed-out
connection or a `500` was named `UPSTREAM_UNAVAILABLE`: since then they follow the rule below.

<!-- [[[cog import generate_docs as g; cog.out(g.uninformative_answers("4.4", page=cog.inFile)) ]]] -->

The answers that say nothing about the guarantee by themselves, one rule for every test ([assessment model](../../04-architecture/03-assessment-model.md#answers-that-say-nothing-about-the-guarantee)), generated from the code:

| Answer | Sub-tests | Outcome / detail |
|---|---|---|
| `UPSTREAM_UNAVAILABLE` | every sub-test | `NOT_VERIFIABLE/UPSTREAM_UNAVAILABLE` |
| `RATE_LIMITED` | every sub-test | `NOT_VERIFIABLE/RATE_LIMITED` |
| `SERVER_ERROR` | every sub-test | `NOT_VERIFIABLE/SERVER_ERROR` |
| `NO_RESPONSE` | every sub-test | `NOT_VERIFIABLE/NO_RESPONSE` |

<!-- [[[end]]] -->

## 7. Outcomes

SKIP without a documented write endpoint. FAIL when the oversized body is forwarded, PASS on a 413.

## 8. Findings

<!-- [[[cog import generate_docs as g; cog.out(g.finding_titles("4.4")) ]]] -->

- "Oversized body not rejected: <label>"

<!-- [[[end]]] -->

`<label>` is the method and path sent, with "(chunked)" for the chunked body; `evidence_ref` the probe request.

## 9. Effects on the target

`STRESSES_TARGET`: up to six oversized bodies (unauthenticated, then with user_a's credential, then with a forged
one; whole, then in chunks). Nothing created: the body holds no field a write expects.

## 10. Per gateway

The 413 is the gateway's; the limits read through the adapter size the body (`body_size_limits()`, mapping in the
[adapter guide](../../02-guides/03-extending/04-add-a-gateway-adapter.md)):

- **Kong** `request-size-limiting`: `allowed_payload_size` times its `size_unit` (bytes 1, kilobytes 1024,
  megabytes 1048576, megabytes by default: the factors of Kong's handler). A plugin bound to a consumer is left out.
- **APISIX** `client-control`: `max_body_size` in bytes, compared with the request's `Content-Length`; 0 (no
  restriction) is left out.

## 11. Configuration

<!-- [[[cog import generate_docs as g; cog.out(g.test_params("4.4", page=cog.inFile)) ]]] -->

Section [`tests.domain_4.test_4_4`](../../03-reference/01-configuration.md#testsdomain_4test_4_4) of `config.yaml`:

| Key | Type | Default | Description |
|---|---|---|---|
| `body_size_bytes` | int ≥1024 | `2000000` | The size of the body sent when the gateway's configured limit cannot be read. A body above a sane API limit (default 2 MB); a gateway that accepts it has no small body-size limit. |
| `probe_path` | string | `""` | The documented write path to probe, sent as a POST; empty derives the shortest documented write, sent with its documented method. |

<!-- [[[end]]] -->

## 12. Validation

**2026-11-16** (4.4 with 4.1, 4.2, 4.3 on the three labs as configured): **FAIL** with both findings on the two
Forgejo labs. On crAPI the first runs were **INCONCLUSIVE**, `NO_RESPONSE` on both sub-tests, and not by the race
below: the lab's Kong, running for days, logged `[crit] pread() "/usr/local/kong/client_body_temp/..." failed (9: Bad
file descriptor) while sending request to upstream` and closed the connection with an empty `401`, each time raising
the passive health check's count against the workshop backend (4 of 5). With Kong's container recreated, three runs
in a row gave **FAIL** with both findings. The test read the gateway's broken answers as answers that say nothing,
as it should; the lab is to be recreated when Kong logs that error.

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

**What each branch has been seen doing** (rule 9). Proven on a lab: `NO_SIZE_LIMIT` with no configured limit
readable (both Forgejo labs, FIRM; crAPI), `SIZE_LIMIT_ENFORCED` (Forgejo + Kong with the plugin above),
`UPSTREAM_UNAVAILABLE` (crAPI, the race of 2026-11-03). Seen on a scratch server only: `REFUSED_BEFORE_SIZE_CHECK`.
A write sleeping past the read timeout (2026-11-15, a temporary route `POST ~/api/v1/orgs$` sleeping 7 s, the run's
`target.read_timeout: 5.0`) gives `UPSTREAM_UNAVAILABLE`, section 6. Not reachable: `NO_RESPONSE`, which needs the
client to fail without a record, and every failure of `src/core/client.py` carries one except the branch its own
comment marks unreachable.

**The limits read from the gateway, 2026-11-15** (4.4 alone or with 4.1, plugins added to the Forgejo + Kong
`kong.yml` or to the API route of the APISIX `setup.sh`, each undone with `git checkout` and the lab recreated):

| Variant | Result |
|---|---|
| none (the labs as configured) | **FAIL** FIRM: 2 MB, the finding naming `forgejo-api-route` as a route that may serve the path with no limit |
| Kong `request-size-limiting` `allowed_payload_size: 1` on the service | **PASS**: read as 1048576 bytes, a body of 1049600 bytes answered `413` "Request size limit exceeded" |
| `allowed_payload_size: 4`, `size_unit: kilobytes` on the route | **PASS**: read as 4096 bytes, the 5120-byte body answered `413` |
| the 1 MB plugin with a `pre-function` answering `POST /api/v1/orgs` with 200 before the size check | **FAIL** CERTAIN, "configured and not enforced", the finding naming the plugin |
| the 1 MB plugin on `hmac-audit-route` only | **FAIL** FIRM: a limit on a route that cannot serve the path does not count |
| APISIX `client-control` `max_body_size: 1048576` on the API route | **PASS**: read as 1048576 bytes, `413` |

In the run with 4.1 and a working rate limit of 5 per minute on the same service, 4.4 was **ERROR**: user_a's login
(`POST /api/v1/users/user-a/tokens`), which the engine makes before 4.4 for its optional account, met the limit
4.1's burst had used up (`429`). In a full assessment the login is made by an earlier test and reused.
`NO_CREDENTIAL_TO_RETRY` was seen on 2026-11-15 (Forgejo + Kong, the run's configuration without user_a's
account: the unauthenticated body refused `401`, INCONCLUSIVE).

## 13. Remediation

Configure a request-size limit on the gateway (Kong `request-size-limiting`, Nginx `client_max_body_size`) so an
oversized body is rejected with 413 before it reaches the backend (OWASP API4:2023).

## 14. Limitations

- **Who answered the `413` is not told.** The gateway's and the application's are the same HTTP answer; only signals
  of one gateway would tell them apart (Kong's own answers carry its latency header), and a test does not rest on
  lists of gateways (rule 10). A `413` from the application still refuses the body, but after it crossed the
  gateway: the protection is weaker. When the gateway's limits are read, a `413` to a body above them is consistent
  with the gateway's limit, which the finding or the evidence names.

- Without a limit read for every route that may serve the path, the test asserts only "no limit at the tested
  size" (FIRM): a limit above the tested size is not detected (raise `body_size_bytes`).
- With a limit read, the body sent is that limit plus 1024 bytes, however large: Kong's default
  `allowed_payload_size` is 128 megabytes, and a gateway configured with it receives a body that size (up to three
  times, section 5).
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
- RFC 9110 section 15.5.14 (413 Content Too Large): https://www.rfc-editor.org/rfc/rfc9110.html#section-15.5.14
- CWE-400 Uncontrolled Resource Consumption: https://cwe.mitre.org/data/definitions/400.html

# 7.2 Server-Side Request Forgery Prevention

> **Audience:** analysts, contributors · **Source of truth:**
> [`src/tests/domain_7/test_7_2_ssrf_prevention.py`](../../../src/tests/domain_7/test_7_2_ssrf_prevention.py)

<!-- [[[cog import generate_docs as g; cog.out(g.test_header("7.2", page=cog.inFile)) ]]] -->

|  |  |
|---|---|
| Test ID | `7.2` |
| Name | Server-Side Request Forgery Prevention |
| Domain | 7 - Business Logic and Sensitive Flows |
| Priority / strategy | P0 / GREY_BOX |
| Effect | CHANGES_DATA |
| CWE | CWE-918 |
| Standards | `OWASP API7:2023`, `OWASP WSTG-v42-INPV-19`, `OWASP ASVS v5.0.0-1.3.6` |
| Tags | `ssrf`, `business-logic` |
| Prerequisites | none |
| Needs | `USER_ACCOUNT`, `url_accepting_endpoint` |
| Parameters | [`tests.domain_7.test_7_2`](../../03-reference/01-configuration.md#testsdomain_7test_7_2) |

<!-- [[[end]]] -->

**Same group:** tests `7.1`, `7.3`, `7.4` (business logic and advanced threats).

## 1. Guarantee

A URL-accepting endpoint (a webhook, a fetch-from-URL import) rejects a client URL that points at internal
infrastructure. A PASS promises the endpoint rejected the SSRF payloads that it was in a position to evaluate. The
threat (OWASP API7:2023, P0): a server coerced into calling `http://169.254.169.254/...` leaks cloud credentials, or
reaches internal services the client cannot.

## 2. Test

### 2.1 Sub-tests and coverage of the methodology

One sub-test per bypass class; each payload of an enabled class is judged on its own.

| Sub-test | Methodology (guarantee 7.2) |
|---|---|
| `cloud_metadata` | cloud IMDS endpoints (AWS/GCP/Azure/DigitalOcean) |
| `private_ip` | loopback, RFC-1918, unspecified (`0.0.0.0`, `[::]`) |
| `encoding_bypass` | obfuscated loopback/IMDS (decimal, hex, octal, IPv4-mapped IPv6, URL-encoded) |
| `forbidden_protocol` | non-HTTP schemes (`file://`, `gopher://`, ...) |
| `dns_bypass` | wildcard DNS (`nip.io`, `sslip.io`) resolving to private IPs |
| `url_parser_confusion` | `@` authority ambiguity, backslash, embedded credentials |
| left out | **outbound-call confirmation** and redirect-chain SSRF: both need an out-of-band listener the tool controls, which is not built and not planned |

### 2.2 Preconditions and reference responses

A **benign control URL** (`http://example.com/`) is sent first. Its answer is the baseline: only if a well-formed
benign URL is accepted does a rejection of an SSRF URL count as an SSRF defence. If the control is itself rejected (a
precondition such as an invalid resource id, auth, or validation rejects every URL alike) the SSRF rejections are
`NOT_VERIFIABLE`, not a false `ENFORCED`. If the control gets no usable response (5xx / none) the endpoint is down and
nothing is verifiable.

### 2.3 Probes

For each payload, one request to the endpoint with the payload URL in the body (as user A). Effect `CHANGES_DATA`:
with a `resource` a disposable object (a repository on the Forgejo labs) is created once and its webhooks go with it
at teardown; the webhooks are created inactive so they never fire.

**The series stops at the first sign that the backend hung or is out of service**: no answer, or the gateway's `502`, `503` or `504`. Every further URL would add a timeout,
and a gateway's passive health check counts them: on crAPI three made Kong take the workshop backend out of service,
and the tests that ran next (0.1, 4.1, 4.4, 7.3, Schemathesis) got `503` and measured nothing. The URLs not sent are
recorded `NOT_VERIFIABLE/NOT_SENT_AFTER_TIMEOUT`, and a note says why. A `500` is the backend's own answer and does
not stop the series.

## 3. Oracle

Honesty boundary: a `2xx` means the endpoint *accepted* the URL, not that the server made the outbound call; confirming the call would need an out-of-band listener the tool controls, not built and not planned, so an accepted URL is `NOT_VERIFIABLE`. One exception is proof, not inference: when the benign control's answer carries example.com's page, the endpoint returns what it fetches, and a payload's `2xx` carrying a cloud-metadata marker is the internal service's content.

<!-- [[[cog import generate_docs as g; cog.out(g.oracle_table("7.2")) ]]] -->

**`cloud_metadata`**

| Case | Outcome / detail | Confidence |
|---|---|---|
| the payload is refused as invalid or forbidden (`400`, `403`, `422`, ...), the benign URL accepted before and after the series, and unlike the unreachable URL | `ENFORCED/SSRF_BLOCKED_<kind>`, the kind one of `SCHEME`, `MALFORMED`, `VALIDATION`, `UNKNOWN` | - |
| refused exactly as the unreachable URL is: a failed fetch, not a block | `NOT_VERIFIABLE/REJECTED_LIKE_UNREACHABLE` | - |
| refused while the benign URL is refused too, before or after the series | `NOT_VERIFIABLE/BASELINE_REJECTED` | - |
| accepted (`2xx`) with a cloud-metadata marker in the answer, the endpoint reflecting what it fetches | `VIOLATION/SSRF_CONTENT_REFLECTED` | CERTAIN |
| accepted (`2xx`): the outbound call is not observable | `NOT_VERIFIABLE/OUTBOUND_NOT_CONFIRMED` | - |
| `401`: the credential refused | `NOT_VERIFIABLE/CREDENTIAL_REFUSED` | - |
| a redirect, not followed | `NOT_VERIFIABLE/REDIRECTED` | - |
| `404`, perhaps the fetched page's own | `NOT_VERIFIABLE/NOT_FOUND` | - |
| another answer (`405`, `408`, a status of no class, a `5xx` outside the shared rule) | `NOT_VERIFIABLE/ANSWER_NOT_INTERPRETED` | - |
| no answer: the server may still be fetching the URL | `NOT_VERIFIABLE/SSRF_PROBE_TIMEOUT` | - |
| not sent: an earlier payload got no answer or the gateway's `502`, `503`, `504` | `NOT_VERIFIABLE/NOT_SENT_AFTER_TIMEOUT` | - |
| the prepared resource could not be created | `NOT_VERIFIABLE/OBJECT_NOT_CREATED` | - |

**`private_ip`**

| Case | Outcome / detail | Confidence |
|---|---|---|
| the payload is refused as invalid or forbidden (`400`, `403`, `422`, ...), the benign URL accepted before and after the series, and unlike the unreachable URL | `ENFORCED/SSRF_BLOCKED_<kind>`, the kind one of `SCHEME`, `MALFORMED`, `VALIDATION`, `UNKNOWN` | - |
| refused exactly as the unreachable URL is: a failed fetch, not a block | `NOT_VERIFIABLE/REJECTED_LIKE_UNREACHABLE` | - |
| refused while the benign URL is refused too, before or after the series | `NOT_VERIFIABLE/BASELINE_REJECTED` | - |
| accepted (`2xx`) with a cloud-metadata marker in the answer, the endpoint reflecting what it fetches | `VIOLATION/SSRF_CONTENT_REFLECTED` | CERTAIN |
| accepted (`2xx`): the outbound call is not observable | `NOT_VERIFIABLE/OUTBOUND_NOT_CONFIRMED` | - |
| `401`: the credential refused | `NOT_VERIFIABLE/CREDENTIAL_REFUSED` | - |
| a redirect, not followed | `NOT_VERIFIABLE/REDIRECTED` | - |
| `404`, perhaps the fetched page's own | `NOT_VERIFIABLE/NOT_FOUND` | - |
| another answer (`405`, `408`, a status of no class, a `5xx` outside the shared rule) | `NOT_VERIFIABLE/ANSWER_NOT_INTERPRETED` | - |
| no answer: the server may still be fetching the URL | `NOT_VERIFIABLE/SSRF_PROBE_TIMEOUT` | - |
| not sent: an earlier payload got no answer or the gateway's `502`, `503`, `504` | `NOT_VERIFIABLE/NOT_SENT_AFTER_TIMEOUT` | - |
| the prepared resource could not be created | `NOT_VERIFIABLE/OBJECT_NOT_CREATED` | - |

**`encoding_bypass`**

| Case | Outcome / detail | Confidence |
|---|---|---|
| the payload is refused as invalid or forbidden (`400`, `403`, `422`, ...), the benign URL accepted before and after the series, and unlike the unreachable URL | `ENFORCED/SSRF_BLOCKED_<kind>`, the kind one of `SCHEME`, `MALFORMED`, `VALIDATION`, `UNKNOWN` | - |
| refused exactly as the unreachable URL is: a failed fetch, not a block | `NOT_VERIFIABLE/REJECTED_LIKE_UNREACHABLE` | - |
| refused while the benign URL is refused too, before or after the series | `NOT_VERIFIABLE/BASELINE_REJECTED` | - |
| accepted (`2xx`) with a cloud-metadata marker in the answer, the endpoint reflecting what it fetches | `VIOLATION/SSRF_CONTENT_REFLECTED` | CERTAIN |
| accepted (`2xx`): the outbound call is not observable | `NOT_VERIFIABLE/OUTBOUND_NOT_CONFIRMED` | - |
| `401`: the credential refused | `NOT_VERIFIABLE/CREDENTIAL_REFUSED` | - |
| a redirect, not followed | `NOT_VERIFIABLE/REDIRECTED` | - |
| `404`, perhaps the fetched page's own | `NOT_VERIFIABLE/NOT_FOUND` | - |
| another answer (`405`, `408`, a status of no class, a `5xx` outside the shared rule) | `NOT_VERIFIABLE/ANSWER_NOT_INTERPRETED` | - |
| no answer: the server may still be fetching the URL | `NOT_VERIFIABLE/SSRF_PROBE_TIMEOUT` | - |
| not sent: an earlier payload got no answer or the gateway's `502`, `503`, `504` | `NOT_VERIFIABLE/NOT_SENT_AFTER_TIMEOUT` | - |
| the prepared resource could not be created | `NOT_VERIFIABLE/OBJECT_NOT_CREATED` | - |

**`forbidden_protocol`**

| Case | Outcome / detail | Confidence |
|---|---|---|
| the payload is refused as invalid or forbidden (`400`, `403`, `422`, ...), the benign URL accepted before and after the series, and unlike the unreachable URL | `ENFORCED/SSRF_BLOCKED_<kind>`, the kind one of `SCHEME`, `MALFORMED`, `VALIDATION`, `UNKNOWN` | - |
| refused exactly as the unreachable URL is: a failed fetch, not a block | `NOT_VERIFIABLE/REJECTED_LIKE_UNREACHABLE` | - |
| refused while the benign URL is refused too, before or after the series | `NOT_VERIFIABLE/BASELINE_REJECTED` | - |
| accepted (`2xx`) with a cloud-metadata marker in the answer, the endpoint reflecting what it fetches | `VIOLATION/SSRF_CONTENT_REFLECTED` | CERTAIN |
| accepted (`2xx`): the outbound call is not observable | `NOT_VERIFIABLE/OUTBOUND_NOT_CONFIRMED` | - |
| `401`: the credential refused | `NOT_VERIFIABLE/CREDENTIAL_REFUSED` | - |
| a redirect, not followed | `NOT_VERIFIABLE/REDIRECTED` | - |
| `404`, perhaps the fetched page's own | `NOT_VERIFIABLE/NOT_FOUND` | - |
| another answer (`405`, `408`, a status of no class, a `5xx` outside the shared rule) | `NOT_VERIFIABLE/ANSWER_NOT_INTERPRETED` | - |
| no answer: the server may still be fetching the URL | `NOT_VERIFIABLE/SSRF_PROBE_TIMEOUT` | - |
| not sent: an earlier payload got no answer or the gateway's `502`, `503`, `504` | `NOT_VERIFIABLE/NOT_SENT_AFTER_TIMEOUT` | - |
| the prepared resource could not be created | `NOT_VERIFIABLE/OBJECT_NOT_CREATED` | - |

**`dns_bypass`**

| Case | Outcome / detail | Confidence |
|---|---|---|
| the payload is refused as invalid or forbidden (`400`, `403`, `422`, ...), the benign URL accepted before and after the series, and unlike the unreachable URL | `ENFORCED/SSRF_BLOCKED_<kind>`, the kind one of `SCHEME`, `MALFORMED`, `VALIDATION`, `UNKNOWN` | - |
| refused exactly as the unreachable URL is: a failed fetch, not a block | `NOT_VERIFIABLE/REJECTED_LIKE_UNREACHABLE` | - |
| refused while the benign URL is refused too, before or after the series | `NOT_VERIFIABLE/BASELINE_REJECTED` | - |
| accepted (`2xx`) with a cloud-metadata marker in the answer, the endpoint reflecting what it fetches | `VIOLATION/SSRF_CONTENT_REFLECTED` | CERTAIN |
| accepted (`2xx`): the outbound call is not observable | `NOT_VERIFIABLE/OUTBOUND_NOT_CONFIRMED` | - |
| `401`: the credential refused | `NOT_VERIFIABLE/CREDENTIAL_REFUSED` | - |
| a redirect, not followed | `NOT_VERIFIABLE/REDIRECTED` | - |
| `404`, perhaps the fetched page's own | `NOT_VERIFIABLE/NOT_FOUND` | - |
| another answer (`405`, `408`, a status of no class, a `5xx` outside the shared rule) | `NOT_VERIFIABLE/ANSWER_NOT_INTERPRETED` | - |
| no answer: the server may still be fetching the URL | `NOT_VERIFIABLE/SSRF_PROBE_TIMEOUT` | - |
| not sent: an earlier payload got no answer or the gateway's `502`, `503`, `504` | `NOT_VERIFIABLE/NOT_SENT_AFTER_TIMEOUT` | - |
| the prepared resource could not be created | `NOT_VERIFIABLE/OBJECT_NOT_CREATED` | - |

**`url_parser_confusion`**

| Case | Outcome / detail | Confidence |
|---|---|---|
| the payload is refused as invalid or forbidden (`400`, `403`, `422`, ...), the benign URL accepted before and after the series, and unlike the unreachable URL | `ENFORCED/SSRF_BLOCKED_<kind>`, the kind one of `SCHEME`, `MALFORMED`, `VALIDATION`, `UNKNOWN` | - |
| refused exactly as the unreachable URL is: a failed fetch, not a block | `NOT_VERIFIABLE/REJECTED_LIKE_UNREACHABLE` | - |
| refused while the benign URL is refused too, before or after the series | `NOT_VERIFIABLE/BASELINE_REJECTED` | - |
| accepted (`2xx`) with a cloud-metadata marker in the answer, the endpoint reflecting what it fetches | `VIOLATION/SSRF_CONTENT_REFLECTED` | CERTAIN |
| accepted (`2xx`): the outbound call is not observable | `NOT_VERIFIABLE/OUTBOUND_NOT_CONFIRMED` | - |
| `401`: the credential refused | `NOT_VERIFIABLE/CREDENTIAL_REFUSED` | - |
| a redirect, not followed | `NOT_VERIFIABLE/REDIRECTED` | - |
| `404`, perhaps the fetched page's own | `NOT_VERIFIABLE/NOT_FOUND` | - |
| another answer (`405`, `408`, a status of no class, a `5xx` outside the shared rule) | `NOT_VERIFIABLE/ANSWER_NOT_INTERPRETED` | - |
| no answer: the server may still be fetching the URL | `NOT_VERIFIABLE/SSRF_PROBE_TIMEOUT` | - |
| not sent: an earlier payload got no answer or the gateway's `502`, `503`, `504` | `NOT_VERIFIABLE/NOT_SENT_AFTER_TIMEOUT` | - |
| the prepared resource could not be created | `NOT_VERIFIABLE/OBJECT_NOT_CREATED` | - |

<!-- [[[end]]] -->

<!-- [[[cog import generate_docs as g; cog.out(g.uninformative_answers("7.2", page=cog.inFile)) ]]] -->

The answers that say nothing about the guarantee by themselves, one rule for every test ([assessment model](../../04-architecture/03-assessment-model.md#answers-that-say-nothing-about-the-guarantee)), generated from the code:

| Answer | Sub-tests | Outcome / detail |
|---|---|---|
| `UPSTREAM_UNAVAILABLE` | every sub-test | `NOT_VERIFIABLE/UPSTREAM_UNAVAILABLE` |
| `RATE_LIMITED` | every sub-test | `NOT_VERIFIABLE/RATE_LIMITED` |
| `SERVER_ERROR` | every sub-test | `NOT_VERIFIABLE/SERVER_ERROR` |
| `NO_RESPONSE` | every sub-test | judged by the oracle above: a payload left without an answer may be the server still fetching the URL: recorded `SSRF_PROBE_TIMEOUT`, and the payloads after it are not sent. |

<!-- [[[end]]] -->

## 4. Validation

### 4.1 Oracle cases

<!-- [[[cog import generate_docs as g; cog.out(g.oracle_validation("7.2", page=cog.inFile)) ]]] -->

Every case of the oracle, produced on a lab and judged by the code: E1, [oracle validation](../../../experiments/README.md), campaign at commit `fc60b6f`. 90 of 90 produced cases gave the declared outcome; 3 no lab can produce.

| Case | Lab, how it is produced | Result |
|---|---|---|
| `cloud_metadata/ENFORCED/SSRF_BLOCKED_SCHEME` | forgejo-kong: a route on the webhook creation answers the payloads 400 "unsupported scheme", a scheme keyword of the body, while the controls reach Forgejo | OK |
| `cloud_metadata/ENFORCED/SSRF_BLOCKED_MALFORMED` | forgejo-kong: a route on the webhook creation answers the payloads 400 "invalid url", a malformed keyword of the body, while the controls reach Forgejo | OK |
| `cloud_metadata/ENFORCED/SSRF_BLOCKED_VALIDATION` | forgejo-kong: a route on the webhook creation answers the payloads 422 "host not allowed" while the benign and the unreachable controls reach Forgejo | OK |
| `cloud_metadata/ENFORCED/SSRF_BLOCKED_UNKNOWN` | forgejo-kong: a route on the webhook creation answers the payloads 400 "nope" while the controls reach Forgejo | OK |
| `cloud_metadata/NOT_VERIFIABLE/REJECTED_LIKE_UNREACHABLE` | forgejo-kong: a route on the webhook creation answers the unreachable control and every payload with the same 400 {message: could not connect}, the benign control reaching Forgejo | OK |
| `cloud_metadata/NOT_VERIFIABLE/BASELINE_REJECTED` | forgejo-kong: a route on the webhook creation answers every request 422, the benign control included | OK |
| `cloud_metadata/VIOLATION/SSRF_CONTENT_REFLECTED/CERTAIN` | forgejo-kong: a route on the webhook creation returns example.com's page for the benign control, a 400 for the unreachable one and a cloud-metadata listing (ami-id) with 200 for every payload | OK |
| `cloud_metadata/NOT_VERIFIABLE/OUTBOUND_NOT_CONFIRMED` | forgejo-kong: the lab as built: Forgejo creates the inactive webhook for the payload URL (201), validating it only when the webhook fires | OK |
| `cloud_metadata/NOT_VERIFIABLE/CREDENTIAL_REFUSED` | forgejo-kong: a route on the webhook creation answers every payload 401 while the controls reach Forgejo | OK |
| `cloud_metadata/NOT_VERIFIABLE/REDIRECTED` | forgejo-kong: a route on the webhook creation answers every payload 302 to http://example.com/ while the controls reach Forgejo | OK |
| `cloud_metadata/NOT_VERIFIABLE/NOT_FOUND` | forgejo-kong: a route on the webhook creation answers every payload 404 while the controls reach Forgejo | OK |
| `cloud_metadata/NOT_VERIFIABLE/ANSWER_NOT_INTERPRETED` | forgejo-kong: a route on the webhook creation answers every payload 418 (a status of no class) while the controls reach Forgejo | OK |
| `cloud_metadata/NOT_VERIFIABLE/SSRF_PROBE_TIMEOUT` | forgejo-kong: a route on the webhook creation answers every payload after 7 s, the run's read timeout 5 s and only cloud_metadata enabled, so its first payload gets no answer | OK |
| `cloud_metadata/NOT_VERIFIABLE/NOT_SENT_AFTER_TIMEOUT` | crapi-kong: the lab as built: contact_mechanic hangs on the first non-loopback private_ip URL (10.0.0.1), Kong answers 504, and every later payload is not sent | OK |
| `cloud_metadata/NOT_VERIFIABLE/OBJECT_NOT_CREATED` | forgejo-kong: the repository resource's create path points at a path Forgejo answers 404, so the prepared resource is not created | OK |
| `private_ip/ENFORCED/SSRF_BLOCKED_SCHEME` | forgejo-kong: a route on the webhook creation answers the payloads 400 "unsupported scheme", a scheme keyword of the body, while the controls reach Forgejo | OK |
| `private_ip/ENFORCED/SSRF_BLOCKED_MALFORMED` | forgejo-kong: a route on the webhook creation answers the payloads 400 "invalid url", a malformed keyword of the body, while the controls reach Forgejo | OK |
| `private_ip/ENFORCED/SSRF_BLOCKED_VALIDATION` | forgejo-kong: a route on the webhook creation answers the payloads 422 "host not allowed" while the benign and the unreachable controls reach Forgejo | OK |
| `private_ip/ENFORCED/SSRF_BLOCKED_UNKNOWN` | forgejo-kong: a route on the webhook creation answers the payloads 400 "nope" while the controls reach Forgejo | OK |
| `private_ip/NOT_VERIFIABLE/REJECTED_LIKE_UNREACHABLE` | crapi-kong: the lab as built: contact_mechanic answers 400 "Could not connect to mechanic api" to the unreachable URL and to the loopback payloads alike | OK |
| `private_ip/NOT_VERIFIABLE/BASELINE_REJECTED` | forgejo-kong: a route on the webhook creation answers every request 422, the benign control included | OK |
| `private_ip/VIOLATION/SSRF_CONTENT_REFLECTED/CERTAIN` | forgejo-kong: a route on the webhook creation returns example.com's page for the benign control, a 400 for the unreachable one and a cloud-metadata listing (ami-id) with 200 for every payload | OK |
| `private_ip/NOT_VERIFIABLE/OUTBOUND_NOT_CONFIRMED` | forgejo-kong: the lab as built: Forgejo creates the inactive webhook for the payload URL (201), validating it only when the webhook fires | OK |
| `private_ip/NOT_VERIFIABLE/CREDENTIAL_REFUSED` | forgejo-kong: a route on the webhook creation answers every payload 401 while the controls reach Forgejo | OK |
| `private_ip/NOT_VERIFIABLE/REDIRECTED` | forgejo-kong: a route on the webhook creation answers every payload 302 to http://example.com/ while the controls reach Forgejo | OK |
| `private_ip/NOT_VERIFIABLE/NOT_FOUND` | forgejo-kong: a route on the webhook creation answers every payload 404 while the controls reach Forgejo | OK |
| `private_ip/NOT_VERIFIABLE/ANSWER_NOT_INTERPRETED` | forgejo-kong: a route on the webhook creation answers every payload 418 (a status of no class) while the controls reach Forgejo | OK |
| `private_ip/NOT_VERIFIABLE/SSRF_PROBE_TIMEOUT` | forgejo-kong: a route on the webhook creation answers every payload after 7 s, the run's read timeout 5 s and only private_ip enabled, so its first payload gets no answer | OK |
| `private_ip/NOT_VERIFIABLE/NOT_SENT_AFTER_TIMEOUT` | crapi-kong: the lab as built: contact_mechanic hangs on the first non-loopback private_ip URL (10.0.0.1), Kong answers 504, and every later payload is not sent | OK |
| `private_ip/NOT_VERIFIABLE/OBJECT_NOT_CREATED` | forgejo-kong: the repository resource's create path points at a path Forgejo answers 404, so the prepared resource is not created | OK |
| `encoding_bypass/ENFORCED/SSRF_BLOCKED_SCHEME` | forgejo-kong: a route on the webhook creation answers the payloads 400 "unsupported scheme", a scheme keyword of the body, while the controls reach Forgejo | OK |
| `encoding_bypass/ENFORCED/SSRF_BLOCKED_MALFORMED` | forgejo-kong: a route on the webhook creation answers the payloads 400 "invalid url", a malformed keyword of the body, while the controls reach Forgejo | OK |
| `encoding_bypass/ENFORCED/SSRF_BLOCKED_VALIDATION` | forgejo-kong: a route on the webhook creation answers the payloads 422 "host not allowed" while the benign and the unreachable controls reach Forgejo | OK |
| `encoding_bypass/ENFORCED/SSRF_BLOCKED_UNKNOWN` | forgejo-kong: a route on the webhook creation answers the payloads 400 "nope" while the controls reach Forgejo | OK |
| `encoding_bypass/NOT_VERIFIABLE/REJECTED_LIKE_UNREACHABLE` | forgejo-kong: a route on the webhook creation answers the unreachable control and every payload with the same 400 {message: could not connect}, the benign control reaching Forgejo | OK |
| `encoding_bypass/NOT_VERIFIABLE/BASELINE_REJECTED` | forgejo-kong: a route on the webhook creation answers every request 422, the benign control included | OK |
| `encoding_bypass/VIOLATION/SSRF_CONTENT_REFLECTED/CERTAIN` | forgejo-kong: a route on the webhook creation returns example.com's page for the benign control, a 400 for the unreachable one and a cloud-metadata listing (ami-id) with 200 for every payload | OK |
| `encoding_bypass/NOT_VERIFIABLE/OUTBOUND_NOT_CONFIRMED` | forgejo-kong: the lab as built: Forgejo creates the inactive webhook for the payload URL (201), validating it only when the webhook fires | OK |
| `encoding_bypass/NOT_VERIFIABLE/CREDENTIAL_REFUSED` | forgejo-kong: a route on the webhook creation answers every payload 401 while the controls reach Forgejo | OK |
| `encoding_bypass/NOT_VERIFIABLE/REDIRECTED` | forgejo-kong: a route on the webhook creation answers every payload 302 to http://example.com/ while the controls reach Forgejo | OK |
| `encoding_bypass/NOT_VERIFIABLE/NOT_FOUND` | forgejo-kong: a route on the webhook creation answers every payload 404 while the controls reach Forgejo | OK |
| `encoding_bypass/NOT_VERIFIABLE/ANSWER_NOT_INTERPRETED` | forgejo-kong: a route on the webhook creation answers every payload 418 (a status of no class) while the controls reach Forgejo | OK |
| `encoding_bypass/NOT_VERIFIABLE/SSRF_PROBE_TIMEOUT` | forgejo-kong: a route on the webhook creation answers every payload after 7 s, the run's read timeout 5 s and only encoding_bypass enabled, so its first payload gets no answer | OK |
| `encoding_bypass/NOT_VERIFIABLE/NOT_SENT_AFTER_TIMEOUT` | crapi-kong: the lab as built: contact_mechanic hangs on the first non-loopback private_ip URL (10.0.0.1), Kong answers 504, and every later payload is not sent | OK |
| `encoding_bypass/NOT_VERIFIABLE/OBJECT_NOT_CREATED` | forgejo-kong: the repository resource's create path points at a path Forgejo answers 404, so the prepared resource is not created | OK |
| `forbidden_protocol/ENFORCED/SSRF_BLOCKED_SCHEME` | forgejo-kong: the lab as built: Forgejo rejects every non-HTTP scheme URL (file, gopher, dict, ...) at webhook creation, while it accepts the benign URL before and after the series | OK |
| `forbidden_protocol/ENFORCED/SSRF_BLOCKED_MALFORMED` | not producible (code): every forbidden_protocol payload has a non-HTTP scheme (file, gopher, dict, ftp, ldap, tftp, sftp, netdoc), and _classify_rejection returns SSRF_BLOCKED_SCHEME for such a scheme before reading the body: a rejected forbidden_protocol payload is never MALFORMED | - |
| `forbidden_protocol/ENFORCED/SSRF_BLOCKED_VALIDATION` | not producible (code): every forbidden_protocol payload has a non-HTTP scheme (file, gopher, dict, ftp, ldap, tftp, sftp, netdoc), and _classify_rejection returns SSRF_BLOCKED_SCHEME for such a scheme before reading the body: a rejected forbidden_protocol payload is never VALIDATION | - |
| `forbidden_protocol/ENFORCED/SSRF_BLOCKED_UNKNOWN` | not producible (code): every forbidden_protocol payload has a non-HTTP scheme (file, gopher, dict, ftp, ldap, tftp, sftp, netdoc), and _classify_rejection returns SSRF_BLOCKED_SCHEME for such a scheme before reading the body: a rejected forbidden_protocol payload is never UNKNOWN | - |
| `forbidden_protocol/NOT_VERIFIABLE/REJECTED_LIKE_UNREACHABLE` | forgejo-kong: a route on the webhook creation answers the unreachable control and every payload with the same 400 {message: could not connect}, the benign control reaching Forgejo | OK |
| `forbidden_protocol/NOT_VERIFIABLE/BASELINE_REJECTED` | forgejo-kong: a route on the webhook creation answers every request 422, the benign control included | OK |
| `forbidden_protocol/VIOLATION/SSRF_CONTENT_REFLECTED/CERTAIN` | forgejo-kong: a route on the webhook creation returns example.com's page for the benign control, a 400 for the unreachable one and a cloud-metadata listing (ami-id) with 200 for every payload | OK |
| `forbidden_protocol/NOT_VERIFIABLE/OUTBOUND_NOT_CONFIRMED` | forgejo-kong: a route on the webhook creation answers every payload 201 {id: 1}, no metadata marker, the controls reaching Forgejo | OK |
| `forbidden_protocol/NOT_VERIFIABLE/CREDENTIAL_REFUSED` | forgejo-kong: a route on the webhook creation answers every payload 401 while the controls reach Forgejo | OK |
| `forbidden_protocol/NOT_VERIFIABLE/REDIRECTED` | forgejo-kong: a route on the webhook creation answers every payload 302 to http://example.com/ while the controls reach Forgejo | OK |
| `forbidden_protocol/NOT_VERIFIABLE/NOT_FOUND` | forgejo-kong: a route on the webhook creation answers every payload 404 while the controls reach Forgejo | OK |
| `forbidden_protocol/NOT_VERIFIABLE/ANSWER_NOT_INTERPRETED` | forgejo-kong: a route on the webhook creation answers every payload 418 (a status of no class) while the controls reach Forgejo | OK |
| `forbidden_protocol/NOT_VERIFIABLE/SSRF_PROBE_TIMEOUT` | forgejo-kong: a route on the webhook creation answers every payload after 7 s, the run's read timeout 5 s and only forbidden_protocol enabled, so its first payload gets no answer | OK |
| `forbidden_protocol/NOT_VERIFIABLE/NOT_SENT_AFTER_TIMEOUT` | crapi-kong: the lab as built: contact_mechanic hangs on the first non-loopback private_ip URL (10.0.0.1), Kong answers 504, and every later payload is not sent | OK |
| `forbidden_protocol/NOT_VERIFIABLE/OBJECT_NOT_CREATED` | forgejo-kong: the repository resource's create path points at a path Forgejo answers 404, so the prepared resource is not created | OK |
| `dns_bypass/ENFORCED/SSRF_BLOCKED_SCHEME` | forgejo-kong: a route on the webhook creation answers the payloads 400 "unsupported scheme", a scheme keyword of the body, while the controls reach Forgejo | OK |
| `dns_bypass/ENFORCED/SSRF_BLOCKED_MALFORMED` | forgejo-kong: a route on the webhook creation answers the payloads 400 "invalid url", a malformed keyword of the body, while the controls reach Forgejo | OK |
| `dns_bypass/ENFORCED/SSRF_BLOCKED_VALIDATION` | forgejo-kong: a route on the webhook creation answers the payloads 422 "host not allowed" while the benign and the unreachable controls reach Forgejo | OK |
| `dns_bypass/ENFORCED/SSRF_BLOCKED_UNKNOWN` | forgejo-kong: a route on the webhook creation answers the payloads 400 "nope" while the controls reach Forgejo | OK |
| `dns_bypass/NOT_VERIFIABLE/REJECTED_LIKE_UNREACHABLE` | forgejo-kong: a route on the webhook creation answers the unreachable control and every payload with the same 400 {message: could not connect}, the benign control reaching Forgejo | OK |
| `dns_bypass/NOT_VERIFIABLE/BASELINE_REJECTED` | forgejo-kong: a route on the webhook creation answers every request 422, the benign control included | OK |
| `dns_bypass/VIOLATION/SSRF_CONTENT_REFLECTED/CERTAIN` | forgejo-kong: a route on the webhook creation returns example.com's page for the benign control, a 400 for the unreachable one and a cloud-metadata listing (ami-id) with 200 for every payload | OK |
| `dns_bypass/NOT_VERIFIABLE/OUTBOUND_NOT_CONFIRMED` | forgejo-kong: the lab as built: Forgejo creates the inactive webhook for the payload URL (201), validating it only when the webhook fires | OK |
| `dns_bypass/NOT_VERIFIABLE/CREDENTIAL_REFUSED` | forgejo-kong: a route on the webhook creation answers every payload 401 while the controls reach Forgejo | OK |
| `dns_bypass/NOT_VERIFIABLE/REDIRECTED` | forgejo-kong: a route on the webhook creation answers every payload 302 to http://example.com/ while the controls reach Forgejo | OK |
| `dns_bypass/NOT_VERIFIABLE/NOT_FOUND` | forgejo-kong: a route on the webhook creation answers every payload 404 while the controls reach Forgejo | OK |
| `dns_bypass/NOT_VERIFIABLE/ANSWER_NOT_INTERPRETED` | forgejo-kong: a route on the webhook creation answers every payload 418 (a status of no class) while the controls reach Forgejo | OK |
| `dns_bypass/NOT_VERIFIABLE/SSRF_PROBE_TIMEOUT` | forgejo-kong: a route on the webhook creation answers every payload after 7 s, the run's read timeout 5 s and only dns_bypass enabled, so its first payload gets no answer | OK |
| `dns_bypass/NOT_VERIFIABLE/NOT_SENT_AFTER_TIMEOUT` | crapi-kong: the lab as built: contact_mechanic hangs on the first non-loopback private_ip URL (10.0.0.1), Kong answers 504, and every later payload is not sent | OK |
| `dns_bypass/NOT_VERIFIABLE/OBJECT_NOT_CREATED` | forgejo-kong: the repository resource's create path points at a path Forgejo answers 404, so the prepared resource is not created | OK |
| `url_parser_confusion/ENFORCED/SSRF_BLOCKED_SCHEME` | forgejo-kong: a route on the webhook creation answers the payloads 400 "unsupported scheme", a scheme keyword of the body, while the controls reach Forgejo | OK |
| `url_parser_confusion/ENFORCED/SSRF_BLOCKED_MALFORMED` | forgejo-kong: a route on the webhook creation answers the payloads 400 "invalid url", a malformed keyword of the body, while the controls reach Forgejo | OK |
| `url_parser_confusion/ENFORCED/SSRF_BLOCKED_VALIDATION` | forgejo-kong: a route on the webhook creation answers the payloads 422 "host not allowed" while the benign and the unreachable controls reach Forgejo | OK |
| `url_parser_confusion/ENFORCED/SSRF_BLOCKED_UNKNOWN` | forgejo-kong: a route on the webhook creation answers the payloads 400 "nope" while the controls reach Forgejo | OK |
| `url_parser_confusion/NOT_VERIFIABLE/REJECTED_LIKE_UNREACHABLE` | forgejo-kong: a route on the webhook creation answers the unreachable control and every payload with the same 400 {message: could not connect}, the benign control reaching Forgejo | OK |
| `url_parser_confusion/NOT_VERIFIABLE/BASELINE_REJECTED` | forgejo-kong: a route on the webhook creation answers every request 422, the benign control included | OK |
| `url_parser_confusion/VIOLATION/SSRF_CONTENT_REFLECTED/CERTAIN` | forgejo-kong: a route on the webhook creation returns example.com's page for the benign control, a 400 for the unreachable one and a cloud-metadata listing (ami-id) with 200 for every payload | OK |
| `url_parser_confusion/NOT_VERIFIABLE/OUTBOUND_NOT_CONFIRMED` | forgejo-kong: the lab as built: Forgejo creates the inactive webhook for the payload URL (201), validating it only when the webhook fires | OK |
| `url_parser_confusion/NOT_VERIFIABLE/CREDENTIAL_REFUSED` | forgejo-kong: a route on the webhook creation answers every payload 401 while the controls reach Forgejo | OK |
| `url_parser_confusion/NOT_VERIFIABLE/REDIRECTED` | forgejo-kong: a route on the webhook creation answers every payload 302 to http://example.com/ while the controls reach Forgejo | OK |
| `url_parser_confusion/NOT_VERIFIABLE/NOT_FOUND` | forgejo-kong: a route on the webhook creation answers every payload 404 while the controls reach Forgejo | OK |
| `url_parser_confusion/NOT_VERIFIABLE/ANSWER_NOT_INTERPRETED` | forgejo-kong: a route on the webhook creation answers every payload 418 (a status of no class) while the controls reach Forgejo | OK |
| `url_parser_confusion/NOT_VERIFIABLE/SSRF_PROBE_TIMEOUT` | forgejo-kong: a route on the webhook creation answers every payload after 7 s, the run's read timeout 5 s and only url_parser_confusion enabled, so its first payload gets no answer | OK |
| `url_parser_confusion/NOT_VERIFIABLE/NOT_SENT_AFTER_TIMEOUT` | crapi-kong: the lab as built: contact_mechanic hangs on the first non-loopback private_ip URL (10.0.0.1), Kong answers 504, and every later payload is not sent | OK |
| `url_parser_confusion/NOT_VERIFIABLE/OBJECT_NOT_CREATED` | forgejo-kong: the repository resource's create path points at a path Forgejo answers 404, so the prepared resource is not created | OK |
| `*/NOT_VERIFIABLE/UPSTREAM_UNAVAILABLE` | crapi-kong: the lab as built: contact_mechanic hangs on 10.0.0.1 and Kong answers 504 on the private_ip sub-test | OK |
| `*/NOT_VERIFIABLE/RATE_LIMITED` | forgejo-kong: a route on the webhook creation answers every payload 429 while the controls reach Forgejo | OK |
| `*/NOT_VERIFIABLE/SERVER_ERROR` | forgejo-kong: a route on the webhook creation answers every payload 500 while the controls reach Forgejo (a 500 does not stop the series) | OK |

<!-- [[[end]]] -->

### 4.2 Results on the labs

<!-- [[[cog import generate_docs as g; cog.out(g.lab_results("7.2", page=cog.inFile)) ]]] -->

No E2 campaign yet ([experiments](../../../experiments/README.md)).

<!-- [[[end]]] -->

## 5. Limitations

- The outbound call cannot be confirmed, so a real SSRF that accepts the URL is reported as unverified rather than
  as a violation. Confirming it needs an out-of-band listener the tool controls, which is not built and not planned
 : the test reports what it can observe from the response alone, and this limit is permanent.
  A confirmed SSRF therefore needs a manual check, or a scanner with its own listener, on every
  `OUTBOUND_NOT_CONFIRMED` URL the report lists.
- An endpoint that fetches the URL synchronously and hangs on an internal address leaves the payloads after the first
  hang unsent (`NOT_SENT_AFTER_TIMEOUT`): the price of not taking the backend out of service. Verifying them needs
  a re-run with fewer `payload_categories`, each run stopping again at its first hang.
- A failed fetch and a block that answer with the same status and body shape are told apart by nothing: such a rejection is `REJECTED_LIKE_UNREACHABLE`, never ENFORCED, even when the endpoint did validate the URL.
- Without a `resource`, every accepted URL may leave an object on the target (a webhook): rule 7 asks for a resource the tool removes.

## 6. Sources

- OWASP API7:2023 Server-Side Request Forgery: https://owasp.org/API-Security/editions/2023/en/0xa7-server-side-request-forgery/
- OWASP WSTG v4.2 WSTG-INPV-19 (Testing for SSRF): https://owasp.org/www-project-web-security-testing-guide/v42/4-Web_Application_Security_Testing/07-Input_Validation_Testing/19-Testing_for_Server-Side_Request_Forgery
- OWASP SSRF Prevention Cheat Sheet: https://cheatsheetseries.owasp.org/cheatsheets/Server_Side_Request_Forgery_Prevention_Cheat_Sheet.html
- The payload catalogue's own sources are PayloadsAllTheThings and WSTG-v42-INPV-19
  (`src/tests/data/ssrf_payloads.py`). NIST SP 800-204 section 3.2.2 is not cited: that section is "Internet-based Attacks", about the inbound surface of a microservices application,
  and the publication never mentions SSRF, server-side request forgery or an outbound call.
- CWE-918 Server-Side Request Forgery: https://cwe.mitre.org/data/definitions/918.html

## 7. Inputs

`url_accepting_endpoint` (no default): the `path`, the `body` with `{ssrf_url}` where the URL goes, and optionally a
prepared `resource` created once as user A (its values fill path and body, removed at teardown). The payload
catalogue is [`src/tests/data/ssrf_payloads.py`](../../../src/tests/data/ssrf_payloads.py), traceable to
PayloadsAllTheThings, OWASP WSTG, Orange Tsai (BlackHat 2017) and the cloud vendors' IMDS docs.

## 8. Outcomes

SKIP without `url_accepting_endpoint`. PASS when payloads were rejected with a baseline that accepts, **and at least
one of them is a cloud-metadata or private-IP URL**: these two sub-tests are declared essential, so payloads rejected
only in the other classes (malformed, a forbidden scheme) leave the test INCONCLUSIVE. INCONCLUSIVE also when nothing was verifiable (all accepted/upstream/baseline-rejected). It never FAILs without the
listener.

## 9. Findings

<!-- [[[cog import generate_docs as g; cog.out(g.finding_titles("7.2")) ]]] -->

- "SSRF: internal content returned for <description>"

<!-- [[[end]]] -->

A finding only for a proven SSRF (`SSRF_CONTENT_REFLECTED`), one per payload, `evidence_ref` its answer. An `InfoNote` is added when the endpoint returns what it fetches, when a URL was accepted unproven (the listener would confirm it), when the benign URL was rejected before or after the series, when the endpoint was unavailable, or when the series stopped after a timeout.

## 10. Effects on the target

`CHANGES_DATA`: creates a disposable object and inactive webhooks (or submits the configured body); removed at
teardown. The payload URLs are never fetched by the tool.

## 11. Per gateway

Independent of the adapter: the endpoint is probed from outside. On the labs Kong/APISIX forward to Forgejo (webhook
creation) or crAPI (`contact_mechanic`).

## 12. Configuration

<!-- [[[cog import generate_docs as g; cog.out(g.test_params("7.2", page=cog.inFile)) ]]] -->

Section [`tests.domain_7.test_7_2`](../../03-reference/01-configuration.md#testsdomain_7test_7_2) of `config.yaml`:

| Key | Type | Default | Description |
|---|---|---|---|
| `url_accepting_endpoint` | object \| null | none, **needed to run** | The endpoint that accepts a URL from the client and makes the server call it (a webhook, a fetch-from-URL import): path, body (with "{ssrf_url}" where the URL goes) and, optionally, a prepared resource. No default: unset, the engine records the test as SKIP before it runs. |
| `url_accepting_endpoint.path` | string | required | Path of the endpoint (POST). With a resource it may hold the resource's values, e.g. '/api/v1/projects/{project_id}/webhooks'. |
| `url_accepting_endpoint.body` | object | required | JSON body of the request. Must contain "{ssrf_url}" exactly once, replaced by each payload URL; may contain "{random_secret}" (32 hexadecimal characters) and, with a resource, the resource's values. Placeholders in quotes. |
| `url_accepting_endpoint.resource` | string \| null | none | Name of a prepared resource (resources: in config.yaml) created for user A before probing; its values fill the placeholders of path and body, and it is deleted at teardown. Optional: without it the path is used as written. |
| `payload_categories` | list | 6 values (`cloud_metadata`, `private_ip`, …) | The bypass classes to probe. Valid values: 'cloud_metadata', 'private_ip', 'encoding_bypass', 'forbidden_protocol', 'dns_bypass', 'url_parser_confusion'. A class left out is not probed and its sub-test stays empty. |

<!-- [[[end]]] -->

## 13. Remediation

Validate the resolved IP of a client URL against the full set of private/loopback/link-local/unspecified ranges
(resolution-aware, not string matching), deny non-HTTP schemes, and re-validate after every redirect
(OWASP API7:2023, SSRF Prevention Cheat Sheet).

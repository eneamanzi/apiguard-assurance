# 7.2 Server-Side Request Forgery Prevention

> **Audience:** analysts, contributors · **Status:** rewritten in the test review (2026-10-26) ·
> **Source of truth:**
> [`src/tests/domain_7/test_7_2_ssrf_prevention.py`](../../../src/tests/domain_7/test_7_2_ssrf_prevention.py) ·
> **Verified:** 2026-10-26

<!-- [[[cog import generate_docs as g; cog.out(g.test_header("7.2", page=cog.inFile)) ]]] -->

|  |  |
|---|---|
| Test ID | `7.2` |
| Name | Server-Side Request Forgery Prevention |
| Domain | 7 - Business Logic and Sensitive Flows |
| Priority / strategy | P0 / GREY_BOX |
| Effect | CHANGES_DATA |
| CWE | CWE-918 |
| Standards | `OWASP API7:2023`, `OWASP WSTG-v42-INPV-19` |
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

## 2. Sub-tests and coverage of the methodology

One sub-test per bypass class; each payload of an enabled class is judged on its own.

| Sub-test | Methodology (guarantee 7.2) |
|---|---|
| `cloud_metadata` | cloud IMDS endpoints (AWS/GCP/Azure/DigitalOcean) |
| `private_ip` | loopback, RFC-1918, unspecified (`0.0.0.0`, `[::]`) |
| `encoding_bypass` | obfuscated loopback/IMDS (decimal, hex, octal, IPv4-mapped IPv6, URL-encoded) |
| `forbidden_protocol` | non-HTTP schemes (`file://`, `gopher://`, ...) |
| `dns_bypass` | wildcard DNS (`nip.io`, `sslip.io`) resolving to private IPs |
| `url_parser_confusion` | `@` authority ambiguity, backslash, embedded credentials |
| left out | **outbound-call confirmation** and redirect-chain SSRF: both need an out-of-band listener the tool controls, which is not built and not planned (decided 2026-10-27) |

## 3. Inputs

`url_accepting_endpoint` (no default): the `path`, the `body` with `{ssrf_url}` where the URL goes, and optionally a
prepared `resource` created once as user A (its values fill path and body, removed at teardown). The payload
catalogue is [`src/tests/data/ssrf_payloads.py`](../../../src/tests/data/ssrf_payloads.py), traceable to
PayloadsAllTheThings, OWASP WSTG, Orange Tsai (BlackHat 2017) and the cloud vendors' IMDS docs.

## 4. Preconditions and reference responses

A **benign control URL** (`http://example.com/`) is sent first. Its answer is the baseline: only if a well-formed
benign URL is accepted does a rejection of an SSRF URL count as an SSRF defence. If the control is itself rejected (a
precondition such as an invalid resource id, auth, or validation rejects every URL alike) the SSRF rejections are
`NOT_VERIFIABLE`, not a false `ENFORCED`. If the control gets no usable response (5xx / none) the endpoint is down and
nothing is verifiable.

## 5. Probes

For each payload, one request to the endpoint with the payload URL in the body (as user A). Effect `CHANGES_DATA`:
with a `resource` a disposable object (a repository on the Forgejo labs) is created once and its webhooks go with it
at teardown; the webhooks are created inactive so they never fire.

**The series stops at the first sign that the backend hung or is out of service** (owner decision 2026-11-04): no answer, or the gateway's `502`, `503` or `504`. Every further URL would add a timeout,
and a gateway's passive health check counts them: on crAPI three made Kong take the workshop backend out of service,
and the tests that ran next (0.1, 4.1, 4.4, 7.3, Schemathesis) got `503` and measured nothing. The URLs not sent are
recorded `NOT_VERIFIABLE/NOT_SENT_AFTER_TIMEOUT`, and a note says why. A `500` is the backend's own answer and does
not stop the series.

## 6. Oracle

Honesty boundary (owner decision 2026-10-23): a `2xx` means the endpoint *accepted* the URL, which is not proof the
server made the outbound call. Confirming the call would need an out-of-band listener the tool controls; that
listener is not built and not planned (decided 2026-10-27), so an accepted URL is `NOT_VERIFIABLE`, never a pass and
never an unproven violation. This is a permanent boundary of the test, not a gap waiting to be filled.

| Case | Outcome / detail |
|---|---|
| rejected (`4xx` other than `429`) and the benign control was accepted | `ENFORCED/SSRF_BLOCKED_{SCHEME,MALFORMED,VALIDATION,UNKNOWN}` |
| throttled (`429`), the payload or the benign control: the URL was never evaluated | `NOT_VERIFIABLE/RATE_LIMITED` |
| a `401`, a redirect (not followed) or a `404`: not a rejection of the URL (the credential refused, an answer not read, perhaps the fetched page's own `404`) | `NOT_VERIFIABLE/CREDENTIAL_REFUSED`, `REDIRECTED`, `NOT_FOUND` |
| rejected (`4xx`) but the benign control was also rejected | `NOT_VERIFIABLE/BASELINE_REJECTED` |
| accepted (`2xx`) | `NOT_VERIFIABLE/OUTBOUND_NOT_CONFIRMED` |
| `5xx` / upstream unavailable | `NOT_VERIFIABLE/UPSTREAM_UNAVAILABLE` |
| no response (the server may have blocked on the outbound call) | `NOT_VERIFIABLE/SSRF_PROBE_TIMEOUT` |
| not sent, after a payload got no answer or the gateway's `502`, `503`, `504` (Probes) | `NOT_VERIFIABLE/NOT_SENT_AFTER_TIMEOUT` |

The confirmed-SSRF `VIOLATION` requires the deferred listener; the test never emits it on its own.

## 7. Outcomes

SKIP without `url_accepting_endpoint`. PASS when payloads were rejected with a baseline that accepts, **and at least
one of them is a cloud-metadata or private-IP URL**: these two sub-tests are declared essential, so payloads rejected
only in the other classes (malformed, a forbidden scheme) leave the test INCONCLUSIVE (owner decision 2026-11-04). INCONCLUSIVE also when nothing was verifiable (all accepted/upstream/baseline-rejected). It never FAILs without the
listener.

## 8. Findings

None without the listener (an accepted URL is `NOT_VERIFIABLE`). An `InfoNote` is added when any URL was accepted (the
listener would confirm it), when the baseline was rejected, when the endpoint was unavailable, or when the series
stopped after a timeout.

## 9. Effects on the target

`CHANGES_DATA`: creates a disposable object and inactive webhooks (or submits the configured body); removed at
teardown. The payload URLs are never fetched by the tool.

## 10. Per gateway

Independent of the adapter: the endpoint is probed from outside. On the labs Kong/APISIX forward to Forgejo (webhook
creation) or crAPI (`contact_mechanic`).

## 11. Configuration

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

## 12. Validation

Runs of 2026-10-26; measured again on 2026-11-04 (7.2 alone), after the stop rule:

| Lab | Status | Basis |
|---|---|---|
| Forgejo + Kong, Forgejo + APISIX | **INCONCLUSIVE** (PASS partial until 2026-11-04) | repository webhook creation: 15 payloads rejected by Go's URL parser or for their scheme (`ENFORCED`, in `encoding_bypass`, `forbidden_protocol`, `url_parser_confusion`), 58 accepted -> `NOT_VERIFIABLE/OUTBOUND_NOT_CONFIRMED`, among them every cloud-metadata and private-IP URL (Forgejo validates the URL only when the webhook fires, which this test never triggers): no essential class verified |
| crAPI + Kong | **INCONCLUSIVE** | `contact_mechanic`: crAPI's synchronous outbound attempt to the first cloud-metadata URL hangs, and the gateway answers `504`: `NOT_VERIFIABLE/UPSTREAM_UNAVAILABLE`, then the other 72 `NOT_SENT_AFTER_TIMEOUT`, in 30 s; the workshop backend stays in service (it answers `401` right after). Before the stop rule the 73 URLs all ended `UPSTREAM_UNAVAILABLE` in 90 s, and Kong took the backend out of service for the tests that followed. No false `ENFORCED` (the bug the benign control and the 5xx rule fix) |

The baseline control and the 5xx rule were added after the first crAPI run scored the gateway's `504`s as a false
`ENFORCED`; they are what keeps a down/erroring upstream honest. Rule 9: the `ENFORCED` and the `NOT_VERIFIABLE`
sides are both proven; the confirmed-SSRF `VIOLATION` is unreachable without the out-of-band listener and stays so
(see Limitations).

## 13. Remediation

Validate the resolved IP of a client URL against the full set of private/loopback/link-local/unspecified ranges
(resolution-aware, not string matching), deny non-HTTP schemes, and re-validate after every redirect
(OWASP API7:2023, SSRF Prevention Cheat Sheet).

## 14. Limitations

- The outbound call cannot be confirmed, so a real SSRF that accepts the URL is reported as unverified rather than
  as a violation. Confirming it needs an out-of-band listener the tool controls, which is not built and not planned
  (decided 2026-10-27): the test reports what it can observe from the response alone, and this limit is permanent.
  A confirmed SSRF therefore needs a manual check, or a scanner with its own listener, on every
  `OUTBOUND_NOT_CONFIRMED` URL the report lists.
- An endpoint that fetches the URL synchronously and hangs on an internal address leaves the payloads after the first
  hang unsent (`NOT_SENT_AFTER_TIMEOUT`): the price of not taking the backend out of service. Verifying them needs
  a re-run with fewer `payload_categories`, each run stopping again at its first hang.

## 15. Sources

- OWASP API7:2023 Server-Side Request Forgery: https://owasp.org/API-Security/editions/2023/en/0xa7-server-side-request-forgery/
- OWASP WSTG v4.2 WSTG-INPV-19 (Testing for SSRF): https://owasp.org/www-project-web-security-testing-guide/v42/4-Web_Application_Security_Testing/07-Input_Validation_Testing/19-Testing_for_Server-Side_Request_Forgery
- OWASP SSRF Prevention Cheat Sheet: https://cheatsheetseries.owasp.org/cheatsheets/Server_Side_Request_Forgery_Prevention_Cheat_Sheet.html
- The payload catalogue's own sources are PayloadsAllTheThings and WSTG-v42-INPV-19
  (`src/tests/data/ssrf_payloads.py`). NIST SP 800-204 section 3.2.2 was cited here until 2026-10-28 and was
  dropped: that section is "Internet-based Attacks", about the inbound surface of a microservices application,
  and the publication never mentions SSRF, server-side request forgery or an outbound call.
- CWE-918 Server-Side Request Forgery: https://cwe.mitre.org/data/definitions/918.html

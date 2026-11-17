# 1.5 Credentials Over an Insecure Channel

> **Audience:** analysts, contributors · **Status:** rewritten in the test review (2026-10-22) ·
> **Source of truth:**
> [`src/tests/domain_1/test_1_5_insecure_credential_transport.py`](../../../src/tests/domain_1/test_1_5_insecure_credential_transport.py)
> · **Verified:** 2026-10-22

<!-- [[[cog import generate_docs as g; cog.out(g.test_header("1.5", page=cog.inFile)) ]]] -->

|  |  |
|---|---|
| Test ID | `1.5` |
| Name | Credentials Over an Insecure Channel |
| Domain | 1 - Identity and Authentication |
| Priority / strategy | P2 / BLACK_BOX |
| Effect | READ_ONLY |
| CWE | CWE-319 |
| Standards | `OWASP API2:2023`, `OWASP API8:2023`, `RFC 9110, Section 4.2.2`, `RFC 6797, Section 6.1`, `OWASP ASVS v5.0.0-3.4.1`, `OWASP ASVS v5.0.0-12.2.1`, `OWASP ASVS v5.0.0-4.1.2` |
| Tags | `transport-security`, `tls`, `hsts` |
| Prerequisites | none |
| Needs | - |
| Parameters | [`tests.domain_1.test_1_5`](../../03-reference/01-configuration.md#testsdomain_1test_1_5) |

<!-- [[[end]]] -->

**Same guarantee:** [`ext.1.5.testssl`](../external/domain-1/ext-1-5-testssl.md) scans the TLS handshake (protocol
versions, cipher suites, certificate, known TLS CVEs); this test covers the HTTP layer.

## 1. Guarantee

A credential never travels on an insecure channel. A target that keeps the guarantee forces every request onto
TLS: nothing answers a plain-HTTP request to an API path, and every HTTPS response carries an HSTS header so a
browser never tries plain HTTP again. A redirect to HTTPS is not enough on an API path: OWASP ASVS v5.0.0-4.1.2
allows it only on endpoints meant for a browser, since the first request, with its credential, has already crossed
in cleartext, and an API client that wrongly uses HTTP is never told and keeps doing it (owner decision 2026-11-04; until then a `301`/`308` to `https` counted as enforced).

A PASS promises two things: nothing answered a plain-HTTP request to a documented API path, and an HTTPS response
carried a sound HSTS header. It promises nothing about the strength of the TLS
handshake itself (protocols, ciphers, certificate): that is `ext.1.5.testssl`. The threat is a man in the middle on
the network path who reads a credential sent in cleartext, or downgrades a connection a browser would otherwise keep
on HTTPS. OWASP API2:2023 (the credential exposed) and API8:2023 (the configuration that exposes it); ASVS v5.0.0-3.4.1 (HSTS) and v5.0.0-12.2.1 (TLS on all connectivity).

## 2. Sub-tests and coverage of the methodology

| Sub-test | Methodology (guarantee 1.5) |
|---|---|
| `credential_forced_onto_tls` | "[empirical test] GET over plain HTTP: connection refused or 301/308 to HTTPS without processing the request" |
| `hsts_present` | "[audit] the HTTPS response carries Strict-Transport-Security with a long max-age and includeSubDomains" |
| covered by `ext.1.5.testssl` | "[audit] enabled protocols are only TLS 1.2/1.3"; "[audit] cipher suites give forward secrecy and AEAD"; "[audit] the certificate is valid and from a trusted CA" |
| left out | SCT / Certificate Transparency (RFC 6962): a certificate-issuance control, not a transport-enforcement one; outside what either the HTTP layer or testssl's default scan judges |

## 3. Inputs

- the specification: the shortest documented path, where a credential-bearing request actually travels; the probe
  uses it instead of `/`, because a gateway redirects to HTTPS only on a path it has a route for and answers `/` in
  cleartext (rule 5, derive first);
- `base_url`: when it is `http://`, the target is plain HTTP and the guarantee is already broken;
- the parameter `http_url` (the plain-HTTP origin) for a deployment whose HTTP listener is on a non-standard port.

## 4. Preconditions and reference responses

No credential and no reference responses are needed: the redirect and the HSTS header are the same for everyone. The
attack surface must be present (the probe path is derived from it); without a documented path the probe falls back
to `/`.

## 5. Probes

Two read-only requests, both through the client so they are recorded:

1. a plain-HTTP `GET` to the documented path at the HTTP origin (derived from `base_url`, or `http_url` when set);
2. an HTTPS `GET` to the documented path, whose response headers carry (or lack) HSTS.

## 6. Oracle

<!-- [[[cog import generate_docs as g; cog.out(g.oracle_table("1.5")) ]]] -->

**`credential_forced_onto_tls`**

| Case | Outcome / detail | Confidence |
|---|---|---|
| `base_url` is `http://`: no TLS at all | `VIOLATION/PLAIN_HTTP` | CERTAIN |
| the plain-HTTP connection is refused: nothing listens there | `ENFORCED/HTTP_PORT_UNREACHABLE` | - |
| the plain-HTTP probe timed out or broke before an answer | `NOT_VERIFIABLE/HTTP_PORT_NO_ANSWER` | - |
| `base_url` not on port 443 and no `http_url`: the HTTP listener is unknown | `NOT_VERIFIABLE/HTTP_LISTENER_UNKNOWN` | - |
| a `301`/`308` to an `https://` location (ASVS v5.0.0-4.1.2) | `VIOLATION/TRANSPARENT_REDIRECT` | CERTAIN |
| a `301`/`308` whose location is not `https` | `VIOLATION/WEAK_REDIRECT` | CERTAIN |
| any other redirect | `VIOLATION/TEMPORARY_REDIRECT` | CERTAIN |
| a `2xx` over plain HTTP | `VIOLATION/HTTP_SERVED_CLEARTEXT` | CERTAIN |
| any other answer over plain HTTP: the same `4xx` as over HTTPS, or a `5xx` | `VIOLATION/HTTP_PROCESSED_CLEARTEXT` | CERTAIN |
| `426`, or a `4xx` the same path does not get over HTTPS: the protocol is refused and the client told (owner, 2026-11-16) | `ENFORCED/HTTP_REFUSED` | - |
| a `4xx` other than `426`, and no HTTPS answer that says something to compare it with | `NOT_VERIFIABLE/HTTPS_ANSWER_UNKNOWN` | - |

**`hsts_present`**

| Case | Outcome / detail | Confidence |
|---|---|---|
| HSTS with `max-age` at least `hsts_min_max_age_seconds` and `includeSubDomains` | `ENFORCED/HSTS_COMPLIANT` | - |
| the HTTPS answer has no `Strict-Transport-Security` | `VIOLATION/HSTS_MISSING` | CERTAIN |
| `max-age` absent or below `hsts_min_max_age_seconds` | `VIOLATION/HSTS_MAX_AGE_LOW` | CERTAIN |
| `max-age` sufficient, no `includeSubDomains` | `VIOLATION/HSTS_NO_SUBDOMAINS` | FIRM |
| `base_url` is plain HTTP: no TLS to carry HSTS | `NOT_APPLICABLE/NO_TLS` | - |

<!-- [[[end]]] -->

Any answer over plain HTTP is this test's verdict on `credential_forced_onto_tls` (the request crossed the network in cleartext), so the answers of the table below are judged there by the oracle; on `hsts_present` they follow the rule (until 2026-11-16 a gateway's own `503` lacking HSTS was `HSTS_MISSING`, CERTAIN). Until then the plain-HTTP probe dropped the base URL's path, so an unrouted path was asked; NIST SP 800-52r2 was cited for HSTS and its one-year floor, which it does not mention (ASVS v5.0.0-3.4.1 and RFC 6797 are the sources); and every finding cited all seven references.

<!-- [[[cog import generate_docs as g; cog.out(g.uninformative_answers("1.5", page=cog.inFile)) ]]] -->

The answers that say nothing about the guarantee by themselves, one rule for every test ([assessment model](../../04-architecture/03-assessment-model.md#answers-that-say-nothing-about-the-guarantee)), generated from the code:

| Answer | Sub-tests | Outcome / detail |
|---|---|---|
| `UPSTREAM_UNAVAILABLE` | `hsts_present` | `NOT_VERIFIABLE/UPSTREAM_UNAVAILABLE` |
| `UPSTREAM_UNAVAILABLE` | `credential_forced_onto_tls` | judged by the oracle above: any answer over plain HTTP means the request crossed the network in cleartext: judged by the oracle above (no answer is `HTTP_PORT_NO_ANSWER`). |
| `RATE_LIMITED` | `hsts_present` | `NOT_VERIFIABLE/RATE_LIMITED` |
| `RATE_LIMITED` | `credential_forced_onto_tls` | judged by the oracle above: any answer over plain HTTP means the request crossed the network in cleartext: judged by the oracle above (no answer is `HTTP_PORT_NO_ANSWER`). |
| `SERVER_ERROR` | `hsts_present` | `NOT_VERIFIABLE/SERVER_ERROR` |
| `SERVER_ERROR` | `credential_forced_onto_tls` | judged by the oracle above: any answer over plain HTTP means the request crossed the network in cleartext: judged by the oracle above (no answer is `HTTP_PORT_NO_ANSWER`). |
| `NO_RESPONSE` | `hsts_present` | `NOT_VERIFIABLE/NO_RESPONSE` |
| `NO_RESPONSE` | `credential_forced_onto_tls` | judged by the oracle above: any answer over plain HTTP means the request crossed the network in cleartext: judged by the oracle above (no answer is `HTTP_PORT_NO_ANSWER`). |

<!-- [[[end]]] -->

## 7. Outcomes

Never SKIP a reachable target (a plain-HTTP target is a FAIL, not a SKIP, so the worst state is not hidden). FAIL on
any violation; PASS when nothing answers the HTTP request and the HSTS header is sound.

## 8. Findings

<!-- [[[cog import generate_docs as g; cog.out(g.finding_titles("1.5")) ]]] -->

- "The API is served over plain HTTP"
- "API request accepted over plain HTTP: <origin><probe_path>"
- "API endpoint redirects plain HTTP to HTTPS: <origin><probe_path>"
- "No HSTS header on the API response"
- "HSTS max-age is below the bound"
- "HSTS does not cover subdomains"

<!-- [[[end]]] -->

`evidence_ref` the plain-HTTP answer or the HTTPS answer read for HSTS; each finding cites its own references.

## 9. Effects on the target

`READ_ONLY`: two GETs, no credential, nothing changed. Runs among the read-only tests (rule 7).

## 10. Per gateway

Independent of the adapter: the redirect and HSTS are the gateway's HTTP behaviour, observed from outside. Kong
drops the port in the `Location` (`https://host/...`), APISIX keeps it; the oracle checks the scheme, not the port.

## 11. Configuration

<!-- [[[cog import generate_docs as g; cog.out(g.test_params("1.5", page=cog.inFile)) ]]] -->

Section [`tests.domain_1.test_1_5`](../../03-reference/01-configuration.md#testsdomain_1test_1_5) of `config.yaml`:

| Key | Type | Default | Description |
|---|---|---|---|
| `hsts_min_max_age_seconds` | int ≥86400 | `31536000` | Lowest acceptable max-age (seconds) in the Strict-Transport-Security header. OWASP ASVS v5.0.0-3.4.1 asks for at least one year. Default: 31536000 (one year). |
| `http_url` | string | `""` | The API in plain HTTP, when its HTTP listener is on a non-standard port: only the origin (scheme://host[:port]) is used, the path is derived from the specification. Empty (default) derives the origin from base_url (scheme to http, port 443 dropped); with base_url on another port, the HTTP listener is then unknown and not probed. |

<!-- [[[end]]] -->

The labs set `http_url` to the gateway's HTTP listener (`http://localhost:8000`/`9000`/`10000`) because they put
HTTPS on a non-standard port; a real deployment with HTTPS on 443 and HTTP on 80 needs no override.

## 12. Validation

**2026-11-16, Kong's `426`** (owner: "fai come pensi sia più sensato"): a route that accepts only HTTPS, without a
redirect, makes Kong answer plain HTTP with `426 Please use HTTPS protocol`. ASVS v5.0.0-4.1.2 forbids the transparent
redirect because it hides the mistake from the client; an error that refuses the protocol tells it, which is what
this test's own remediation asks. So a `426`, or a `4xx` the same path does not get over HTTPS, is now
`ENFORCED/HTTP_REFUSED`; the same `4xx` as over HTTPS (a `401` on both: the route serves HTTP as it serves HTTPS) and
a `5xx` stay `HTTP_PROCESSED_CLEARTEXT`. Until that day every answer was a violation (decision of 2026-11-04, now
refined). Forgejo + Kong with `https_redirect_status_code` removed from `forgejo-api-route` (undone): **PASS**,
`HTTP_REFUSED`, HSTS compliant.

**2026-11-16, after the review** (domain 1 on the three labs as configured): **FAIL** on the three labs (`TRANSPARENT_REDIRECT`, Kong's and APISIX's `301`), HSTS compliant, as before.


Runs of 2026-10-22; measured again on 2026-11-04 (1.5 alone) after the decision on redirects, with the same answers:

| Lab | Status | Basis |
|---|---|---|
| Forgejo + Kong | **FAIL**, 1 finding (PASS complete until 2026-11-04) | HTTP `GET /api/v1/orgs` -> `301` to `https`: `TRANSPARENT_REDIRECT`; HTTPS `GET /api/v1/orgs` -> `200` with `max-age=31536000; includeSubDomains` |
| crAPI + Kong | **FAIL**, 1 finding (PASS complete until 2026-11-04) | HTTP `GET /workshop/api/mechanic/` -> `301` to `https`: `TRANSPARENT_REDIRECT`; HTTPS -> `401` with a compliant HSTS header (HSTS is on every response) |
| Forgejo + APISIX | **FAIL**, 1 finding (PASS complete until 2026-11-04) | HTTP `GET /api/v1/orgs` -> `301`: `TRANSPARENT_REDIRECT`; HTTPS -> `200` with a compliant HSTS header |

The labs' gateways redirect on purpose (their HTTP listeners are configured to): the finding is what a production
API configured the same way would get.

**The weakness-present side (rule 9), by tool configuration, no gateway change.**

- `PLAIN_HTTP`: with `base_url` set to the gateway's plain-HTTP listener (`http://localhost:8000`) and the
  specification kept on HTTPS, the test is **FAIL**, one finding "The API is served over plain HTTP". Reproduce by
  pointing `base_url` at the HTTP listener and `specification.url` at the HTTPS spec.
- The other plain-HTTP and HSTS violation branches (`HTTP_SERVED_CLEARTEXT`, `HSTS_MISSING`, ...) are the logic
  exercised on a target that does not enforce TLS; the labs enforce it, so they are not seen on a lab. They need a gateway that
  serves the API over HTTP or omits HSTS.

**What each branch has been seen doing** (rule 9). Proven on a lab: `TRANSPARENT_REDIRECT`, `HSTS_COMPLIANT` (all
three), `PLAIN_HTTP` (tool configuration above), and on 2026-11-15, Forgejo + Kong with the run's configuration
only: `HTTP_LISTENER_UNKNOWN` (`http_url` removed, `base_url` on port 8443), `HTTP_PORT_UNREACHABLE` (`http_url:
http://localhost:8999`, nothing listening), `HTTP_PORT_NO_ANSWER` (`http_url: http://10.255.255.1:80`, a
non-routable address). `NO_TLS` was seen on 2026-11-14 (Forgejo + Kong, `base_url: http://localhost:8000`):
`hsts_present` records one not applicable, the only one the code has
(`src/tests/domain_1/test_1_5_insecure_credential_transport.py`), next to the `PLAIN_HTTP` finding. Every other
branch was produced on 2026-11-15 on Forgejo + Kong with a temporary change to `kong/kong.yml` (undone with `git
checkout`, the lab checked back):

| The change | Result |
|---|---|
| the HSTS value of the service's `response-transformer` set to `max-age=60; includeSubDomains` | `HSTS_MAX_AGE_LOW` (CERTAIN) |
| the same set to `max-age=31536000` | `HSTS_NO_SUBDOMAINS` (FIRM) |
| the HSTS line removed | `HSTS_MISSING` (CERTAIN) |
| a route `~/api/v1/orgs$`, `protocols: [http]`, whose `pre-function` answers `301` to `http://localhost:8000/...` | `WEAK_REDIRECT` |
| the same answering `302` to the HTTPS URL | `TEMPORARY_REDIRECT` |
| the same answering `200` | `HTTP_SERVED_CLEARTEXT` |
| the same answering `400` | `HTTP_PROCESSED_CLEARTEXT` |
| a route `~/api/v1/orgs$`, `protocols: [https]`, sleeping 7 s, the run's `target.read_timeout: 5.0` | `NO_RESPONSE` on `hsts_present` (the plain-HTTP probe of that route got Kong's `426`, `HTTP_PROCESSED_CLEARTEXT`: the route set no `https_redirect_status_code`) |

Every branch of this test has been seen.

## 13. Remediation

Configure the gateway to refuse plain HTTP on API endpoints (no HTTP listener for them, or an error before the
request is processed; a `301`/`308` to `https` only on endpoints meant for a browser, ASVS v5.0.0-4.1.2), and to send `Strict-Transport-Security: max-age=31536000; includeSubDomains` on every HTTPS response
(RFC 9110 section 4.2.2, NIST SP 800-52 Rev.2, ASVS v5.0.0-3.4.1 and v5.0.0-12.2.1).

## 14. Limitations

- Only a refused connection to the HTTP port reads as `ENFORCED` (nothing listens there). A timeout cannot tell a
  firewall that drops the packets from a slow listener, so it is `NOT_VERIFIABLE/HTTP_PORT_NO_ANSWER` (since
  2026-11-04).
- The HTTP probe tests one documented path; a gateway that redirects most paths but serves one in cleartext is seen
  only if that path is the shortest documented one.
- The TLS handshake (protocols, ciphers, certificate) is not judged here: see `ext.1.5.testssl`.

## 15. Sources

- OWASP API2:2023 Broken Authentication (the credential this test exposes): https://owasp.org/API-Security/editions/2023/en/0xa2-broken-authentication/
- OWASP API8:2023 Security Misconfiguration (the configuration that exposes it: its list names "Transport Layer
  Security (TLS) is missing" and "security directives are not sent to clients"):
  https://owasp.org/API-Security/editions/2023/en/0xa8-security-misconfiguration/
- RFC 9110 section 4.2.2 (http and https URIs are different origins): https://www.rfc-editor.org/rfc/rfc9110.html#section-4.2.2
- NIST SP 800-52 Rev.2 (TLS configuration): https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-52r2.pdf
- OWASP ASVS v5.0.0-3.4.1 (Strict-Transport-Security on all responses, max-age >= 1 year, subdomains for L2+): https://github.com/OWASP/ASVS/blob/v5.0.0/5.0/en/0x12-V3-Web-Frontend-Security.md
- OWASP ASVS v5.0.0-12.2.1 (TLS for all connectivity to external HTTP services): https://github.com/OWASP/ASVS/blob/v5.0.0/5.0/en/0x21-V12-Secure-Communication.md
- CWE-319 Cleartext Transmission of Sensitive Information: https://cwe.mitre.org/data/definitions/319.html

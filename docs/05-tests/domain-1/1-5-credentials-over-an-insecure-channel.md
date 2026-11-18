# 1.5 Credentials Over an Insecure Channel

> **Audience:** analysts, contributors · **Source of truth:**
> [`src/tests/domain_1/test_1_5_insecure_credential_transport.py`](../../../src/tests/domain_1/test_1_5_insecure_credential_transport.py)

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
in cleartext, and an API client that wrongly uses HTTP is never told and keeps doing it.

A PASS promises two things: nothing answered a plain-HTTP request to a documented API path, and an HTTPS response
carried a sound HSTS header. It promises nothing about the strength of the TLS
handshake itself (protocols, ciphers, certificate): that is `ext.1.5.testssl`. The threat is a man in the middle on
the network path who reads a credential sent in cleartext, or downgrades a connection a browser would otherwise keep
on HTTPS. OWASP API2:2023 (the credential exposed) and API8:2023 (the configuration that exposes it); ASVS v5.0.0-3.4.1 (HSTS) and v5.0.0-12.2.1 (TLS on all connectivity).

## 2. Test

### 2.1 Sub-tests and coverage of the methodology

| Sub-test | Methodology (guarantee 1.5) |
|---|---|
| `credential_forced_onto_tls` | "[empirical test] GET over plain HTTP: connection refused or 301/308 to HTTPS without processing the request" |
| `hsts_present` | "[audit] the HTTPS response carries Strict-Transport-Security with a long max-age and includeSubDomains" |
| covered by `ext.1.5.testssl` | "[audit] enabled protocols are only TLS 1.2/1.3"; "[audit] cipher suites give forward secrecy and AEAD"; "[audit] the certificate is valid and from a trusted CA" |
| left out | SCT / Certificate Transparency (RFC 6962): a certificate-issuance control, not a transport-enforcement one; outside what either the HTTP layer or testssl's default scan judges |

### 2.2 Preconditions and reference responses

No credential and no reference responses are needed: the redirect and the HSTS header are the same for everyone. The
attack surface must be present (the probe path is derived from it); without a documented path the probe falls back
to `/`.

### 2.3 Probes

Two read-only requests, both through the client so they are recorded:

1. a plain-HTTP `GET` to the documented path at the HTTP origin (derived from `base_url`, or `http_url` when set);
2. an HTTPS `GET` to the documented path, whose response headers carry (or lack) HSTS.

## 3. Oracle

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
| `426`, or a `4xx` the same path does not get over HTTPS: the protocol is refused and the client told | `ENFORCED/HTTP_REFUSED` | - |
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

Any answer over plain HTTP is this test's verdict on `credential_forced_onto_tls` (the request crossed the network in cleartext), so the answers of the table below are judged there by the oracle; on `hsts_present` they follow the rule. 
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

## 4. Validation

### 4.1 Oracle cases

<!-- [[[cog import generate_docs as g; cog.out(g.oracle_validation("1.5", page=cog.inFile)) ]]] -->

Every case of the oracle, produced on a lab and judged by the code: E1, [oracle validation](../../../experiments/README.md), campaign at commit `fc60b6f`. 20 of 20 produced cases gave the declared outcome; 0 no lab can produce.

| Case | Lab, how it is produced | Result |
|---|---|---|
| `credential_forced_onto_tls/VIOLATION/PLAIN_HTTP/CERTAIN` | forgejo-kong: base_url pointed at Kong's plain-HTTP listener http://localhost:8000, the specification kept on HTTPS | OK |
| `credential_forced_onto_tls/ENFORCED/HTTP_PORT_UNREACHABLE` | forgejo-kong: http_url set to http://localhost:8999, where nothing listens: the plain-HTTP connection is refused | OK |
| `credential_forced_onto_tls/NOT_VERIFIABLE/HTTP_PORT_NO_ANSWER` | forgejo-kong: http_url set to http://10.255.255.1:80, a non-routable address: the plain-HTTP probe times out | OK |
| `credential_forced_onto_tls/NOT_VERIFIABLE/HTTP_LISTENER_UNKNOWN` | forgejo-kong: http_url emptied, base_url kept on port 8443: the plain-HTTP listener is not known and not probed | OK |
| `credential_forced_onto_tls/VIOLATION/TRANSPARENT_REDIRECT/CERTAIN` | forgejo-kong: the lab as built: Kong answers plain-HTTP GET /api/v1/orgs with 301 to https (https_redirect_status_code: 301) | OK |
| `credential_forced_onto_tls/VIOLATION/WEAK_REDIRECT/CERTAIN` | forgejo-kong: an HTTP-only route ~/api/v1/orgs$ whose pre-function answers 301 to http://localhost:8000/api/v1/orgs | OK |
| `credential_forced_onto_tls/VIOLATION/TEMPORARY_REDIRECT/CERTAIN` | forgejo-kong: an HTTP-only route ~/api/v1/orgs$ whose pre-function answers 302 to https://localhost:8443/api/v1/orgs | OK |
| `credential_forced_onto_tls/VIOLATION/HTTP_SERVED_CLEARTEXT/CERTAIN` | forgejo-kong: an HTTP-only route ~/api/v1/orgs$ whose pre-function answers 200 | OK |
| `credential_forced_onto_tls/VIOLATION/HTTP_PROCESSED_CLEARTEXT/CERTAIN` | forgejo-kong: a route ~/api/v1/orgs$ on both protocols whose pre-function answers 500: the plain-HTTP probe gets a 5xx | OK |
| `credential_forced_onto_tls/ENFORCED/HTTP_REFUSED` | forgejo-kong: a route on the probe path GET ~/api/v1/orgs$, HTTPS only with no https_redirect_status_code: Kong answers the plain-HTTP probe 426 | OK |
| `credential_forced_onto_tls/NOT_VERIFIABLE/HTTPS_ANSWER_UNKNOWN` | forgejo-kong: a route ~/api/v1/orgs$ on both protocols whose pre-function answers 503 over HTTPS and 400 over HTTP: a 4xx other than 426 with no HTTPS answer to compare it with | OK |
| `hsts_present/ENFORCED/HSTS_COMPLIANT` | forgejo-kong: the lab as built: the HTTPS GET /api/v1/orgs carries max-age=31536000; includeSubDomains | OK |
| `hsts_present/VIOLATION/HSTS_MISSING/CERTAIN` | forgejo-kong: the Strict-Transport-Security line removed from forgejo-service's response-transformer | OK |
| `hsts_present/VIOLATION/HSTS_MAX_AGE_LOW/CERTAIN` | forgejo-kong: the HSTS value of forgejo-service's response-transformer set to max-age=60; includeSubDomains | OK |
| `hsts_present/VIOLATION/HSTS_NO_SUBDOMAINS/FIRM` | forgejo-kong: the HSTS value of forgejo-service's response-transformer set to max-age=31536000, without includeSubDomains | OK |
| `hsts_present/NOT_APPLICABLE/NO_TLS` | forgejo-kong: base_url pointed at Kong's plain-HTTP listener http://localhost:8000 (the same run as PLAIN_HTTP) | OK |
| `*/NOT_VERIFIABLE/UPSTREAM_UNAVAILABLE` | forgejo-kong: a route on the probe path GET ~/api/v1/orgs$ whose pre-function answers 503: hsts_present gets the gateway's 503 | OK |
| `*/NOT_VERIFIABLE/RATE_LIMITED` | forgejo-kong: a route on the probe path GET ~/api/v1/orgs$ whose pre-function answers 429: hsts_present gets the 429 | OK |
| `*/NOT_VERIFIABLE/SERVER_ERROR` | forgejo-kong: a route ~/api/v1/orgs$ on both protocols whose pre-function answers 500: hsts_present gets the 500 (the same run as HTTP_PROCESSED_CLEARTEXT) | OK |
| `*/NOT_VERIFIABLE/NO_RESPONSE` | forgejo-kong: a route on the probe path GET ~/api/v1/orgs$ whose pre-function sleeps 7 s, with the run's read_timeout at 5 s: the HTTPS probe gets no answer | OK |

<!-- [[[end]]] -->

### 4.2 Results on the labs

<!-- [[[cog import generate_docs as g; cog.out(g.lab_results("1.5", page=cog.inFile)) ]]] -->

No E2 campaign yet ([experiments](../../../experiments/README.md)).

<!-- [[[end]]] -->

## 5. Limitations

- Only a refused connection to the HTTP port reads as `ENFORCED` (nothing listens there). A timeout cannot tell a
  firewall that drops the packets from a slow listener, so it is `NOT_VERIFIABLE/HTTP_PORT_NO_ANSWER`.
- The HTTP probe tests one documented path; a gateway that redirects most paths but serves one in cleartext is seen
  only if that path is the shortest documented one.
- The TLS handshake (protocols, ciphers, certificate) is not judged here: see `ext.1.5.testssl`.

## 6. Sources

- OWASP API2:2023 Broken Authentication (the credential this test exposes): https://owasp.org/API-Security/editions/2023/en/0xa2-broken-authentication/
- OWASP API8:2023 Security Misconfiguration (the configuration that exposes it: its list names "Transport Layer
  Security (TLS) is missing" and "security directives are not sent to clients"):
  https://owasp.org/API-Security/editions/2023/en/0xa8-security-misconfiguration/
- RFC 9110 section 4.2.2 (http and https URIs are different origins): https://www.rfc-editor.org/rfc/rfc9110.html#section-4.2.2
- NIST SP 800-52 Rev.2 (TLS configuration): https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-52r2.pdf
- OWASP ASVS v5.0.0-3.4.1 (Strict-Transport-Security on all responses, max-age >= 1 year, subdomains for L2+): https://github.com/OWASP/ASVS/blob/v5.0.0/5.0/en/0x12-V3-Web-Frontend-Security.md
- OWASP ASVS v5.0.0-12.2.1 (TLS for all connectivity to external HTTP services): https://github.com/OWASP/ASVS/blob/v5.0.0/5.0/en/0x21-V12-Secure-Communication.md
- CWE-319 Cleartext Transmission of Sensitive Information: https://cwe.mitre.org/data/definitions/319.html

## 7. Inputs

- the specification: the shortest documented path, where a credential-bearing request actually travels; the probe
  uses it instead of `/`, because a gateway redirects to HTTPS only on a path it has a route for and answers `/` in
  cleartext (rule 5, derive first);
- `base_url`: when it is `http://`, the target is plain HTTP and the guarantee is already broken;
- the parameter `http_url` (the plain-HTTP origin) for a deployment whose HTTP listener is on a non-standard port.

## 8. Outcomes

Never SKIP a reachable target (a plain-HTTP target is a FAIL, not a SKIP, so the worst state is not hidden). FAIL on
any violation; PASS when nothing answers the HTTP request and the HSTS header is sound.

## 9. Findings

<!-- [[[cog import generate_docs as g; cog.out(g.finding_titles("1.5")) ]]] -->

- "The API is served over plain HTTP"
- "API request accepted over plain HTTP: <origin><probe_path>"
- "API endpoint redirects plain HTTP to HTTPS: <origin><probe_path>"
- "No HSTS header on the API response"
- "HSTS max-age is below the bound"
- "HSTS does not cover subdomains"

<!-- [[[end]]] -->

`evidence_ref` the plain-HTTP answer or the HTTPS answer read for HSTS; each finding cites its own references.

## 10. Effects on the target

`READ_ONLY`: two GETs, no credential, nothing changed. Runs among the read-only tests (rule 7).

## 11. Per gateway

Independent of the adapter: the redirect and HSTS are the gateway's HTTP behaviour, observed from outside. Kong
drops the port in the `Location` (`https://host/...`), APISIX keeps it; the oracle checks the scheme, not the port.

## 12. Configuration

<!-- [[[cog import generate_docs as g; cog.out(g.test_params("1.5", page=cog.inFile)) ]]] -->

Section [`tests.domain_1.test_1_5`](../../03-reference/01-configuration.md#testsdomain_1test_1_5) of `config.yaml`:

| Key | Type | Default | Description |
|---|---|---|---|
| `hsts_min_max_age_seconds` | int ≥86400 | `31536000` | Lowest acceptable max-age (seconds) in the Strict-Transport-Security header. OWASP ASVS v5.0.0-3.4.1 asks for at least one year. Default: 31536000 (one year). |
| `http_url` | string | `""` | The API in plain HTTP, when its HTTP listener is on a non-standard port: only the origin (scheme://host[:port]) is used, the path is derived from the specification. Empty (default) derives the origin from base_url (scheme to http, port 443 dropped); with base_url on another port, the HTTP listener is then unknown and not probed. |

<!-- [[[end]]] -->

The labs set `http_url` to the gateway's HTTP listener (`http://localhost:8000`/`9000`/`10000`) because they put
HTTPS on a non-standard port; a real deployment with HTTPS on 443 and HTTP on 80 needs no override.

## 13. Remediation

Configure the gateway to refuse plain HTTP on API endpoints (no HTTP listener for them, or an error before the
request is processed; a `301`/`308` to `https` only on endpoints meant for a browser, ASVS v5.0.0-4.1.2), and to send `Strict-Transport-Security: max-age=31536000; includeSubDomains` on every HTTPS response
(RFC 9110 section 4.2.2, NIST SP 800-52 Rev.2, ASVS v5.0.0-3.4.1 and v5.0.0-12.2.1).

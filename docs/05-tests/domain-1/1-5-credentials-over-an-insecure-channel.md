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
| Standards | `OWASP API2:2023`, `OWASP API8:2023`, `RFC 9110, Section 4.2.2`, `NIST SP 800-52r2`, `OWASP ASVS v5.0.0-3.4.1`, `OWASP ASVS v5.0.0-12.2.1` |
| Tags | `transport-security`, `tls`, `hsts` |
| Prerequisites | none |
| Needs | - |
| Parameters | [`tests.domain_1.test_1_5`](../../03-reference/01-configuration.md#testsdomain_1test_1_5) |

<!-- [[[end]]] -->

**Same guarantee:** [`ext.1.5.testssl`](../external/domain-1/ext-1-5-testssl.md) scans the TLS handshake (protocol
versions, cipher suites, certificate, known TLS CVEs); this test covers the HTTP layer.

## 1. Guarantee

A credential never travels on an insecure channel. A target that keeps the guarantee forces every request onto
TLS: the plain-HTTP listener refuses the request or permanently redirects it to HTTPS before it is processed, and
every HTTPS response carries an HSTS header so a browser never tries plain HTTP again.

A PASS promises two things: a plain-HTTP request to a documented API path was refused or `301`/`308`-redirected to
an `https` URL, and an HTTPS response carried a sound HSTS header. It promises nothing about the strength of the TLS
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

**`credential_forced_onto_tls`**

| Case | Outcome / detail | Confidence |
|---|---|---|
| no response over HTTP (refused, reset, unreachable) | `ENFORCED/HTTP_PORT_UNREACHABLE` | - |
| `301`/`308` whose `Location` scheme is `https` | `ENFORCED/HTTP_REDIRECT_ENFORCED` | - |
| `301`/`308` whose `Location` is not `https` | `VIOLATION/WEAK_REDIRECT` | CERTAIN |
| a temporary redirect (`302`, `307`) | `VIOLATION/TEMPORARY_REDIRECT` | CERTAIN |
| any `2xx` (served in cleartext) | `VIOLATION/HTTP_SERVED_CLEARTEXT` | CERTAIN |
| any other answer (the server processed the cleartext request) | `VIOLATION/HTTP_PROCESSED_CLEARTEXT` | CERTAIN |
| `base_url` is plain HTTP | `VIOLATION/PLAIN_HTTP` | CERTAIN |

**`hsts_present`**

| Case | Outcome / detail | Confidence |
|---|---|---|
| header present, `max-age` within the bound, `includeSubDomains` | `ENFORCED/HSTS_COMPLIANT` | - |
| header absent | `VIOLATION/HSTS_MISSING` | CERTAIN |
| `max-age` below the bound (or absent) | `VIOLATION/HSTS_MAX_AGE_LOW` | CERTAIN |
| `max-age` sufficient but no `includeSubDomains` | `VIOLATION/HSTS_NO_SUBDOMAINS` | FIRM |
| `base_url` is plain HTTP | `NOT_APPLICABLE/NO_TLS` | - |

## 7. Outcomes

Never SKIP a reachable target (a plain-HTTP target is a FAIL, not a SKIP, so the worst state is not hidden). FAIL on
any violation; PASS when the HTTP request is refused or redirected to HTTPS and the HSTS header is sound.

## 8. Findings

- "The API is served over plain HTTP" (PLAIN_HTTP), config-level, no `evidence_ref`;
- "Credential-bearing request accepted over plain HTTP: `<origin><path>`", `evidence_ref` the HTTP probe;
- "No HSTS header on the API response" / "HSTS max-age is below the bound" / "HSTS does not cover subdomains",
  `evidence_ref` the HTTPS probe.

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
| `hsts_min_max_age_seconds` | int ≥86400 | `31536000` | Lowest acceptable max-age (seconds) in the Strict-Transport-Security header. NIST SP 800-52 Rev.2, OWASP ASVS v5.0.0-3.4.1 ask for at least one year. Default: 31536000 (one year). |
| `http_url` | string | `""` | The API in plain HTTP, when its HTTP listener is on a non-standard port: only the origin (scheme://host[:port]) is used, the path is derived from the specification. Empty (default) derives the origin from base_url (scheme to http, port 443 dropped). |

<!-- [[[end]]] -->

The labs set `http_url` to the gateway's HTTP listener (`http://localhost:8000`/`9000`/`10000`) because they put
HTTPS on a non-standard port; a real deployment with HTTPS on 443 and HTTP on 80 needs no override.

## 12. Validation

Runs of 2026-10-22:

| Lab | Status | Basis |
|---|---|---|
| Forgejo + Kong | **PASS** complete | HTTP `GET /api/v1/orgs` -> `301` to `https`; HTTPS `GET /api/v1/orgs` -> `200` with `max-age=31536000; includeSubDomains` |
| crAPI + Kong | **PASS** complete | HTTP `GET /workshop/api/mechanic/` -> `301` to `https`; HTTPS -> `401` with a compliant HSTS header (HSTS is on every response) |
| Forgejo + APISIX | **PASS** complete | HTTP `GET /api/v1/orgs` -> `301`; HTTPS -> `200` with a compliant HSTS header |

**The weakness-present side (rule 9), by tool configuration, no gateway change.**

- `PLAIN_HTTP`: with `base_url` set to the gateway's plain-HTTP listener (`http://localhost:8000`) and the
  specification kept on HTTPS, the test is **FAIL**, one finding "The API is served over plain HTTP". Reproduce by
  pointing `base_url` at the HTTP listener and `specification.url` at the HTTPS spec.
- The redirect and HSTS violation branches (`HTTP_SERVED_CLEARTEXT`, `HSTS_MISSING`, ...) are the logic exercised on
  a target that does not enforce TLS; the labs enforce it, so they are not seen on a lab. They need a gateway that
  serves the API over HTTP or omits HSTS.

## 13. Remediation

Configure the gateway to refuse plain HTTP or answer a `301`/`308` to the `https` URL before the request is
processed, and to send `Strict-Transport-Security: max-age=31536000; includeSubDomains` on every HTTPS response
(RFC 9110 section 4.2.2, NIST SP 800-52 Rev.2, ASVS v5.0.0-3.4.1 and v5.0.0-12.2.1).

## 14. Limitations

- A filtered or closed HTTP port reads as `ENFORCED` (no credential crossed a cleartext channel): the secure
  reading, but it does not distinguish a closed port from a slow firewall.
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

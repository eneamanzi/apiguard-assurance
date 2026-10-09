# 1.5 Insecure Credential Transport

> **Audience:** analysts, contributors · **Status:** implemented (v0.1.0) · **Source of truth:**
> [`src/tests/domain_1/test_1_5_insecure_credential_transport.py`](../../../src/tests/domain_1/test_1_5_insecure_credential_transport.py) ·
> **Verified:** 2026-10-05

| | |
|---|---|
| Test ID | `1.5` |
| Name | Credentials Not Transmitted via Insecure Channels |
| Domain | 1 - Identity and Authentication |
| Priority / strategy | P2 / BLACK_BOX (network access only; the methodology calls it a configuration audit) |
| CWE | CWE-319 |
| Depends on | none |
| Configuration | [`tests.domain_1.test_1_5`](../../reference/configuration.md#testsdomain_1test_1_5---credentials-over-insecure-channels), `target.verify_tls` |
| Companion tests | [`ext.1.5.testssl`, `ext.1.5.sslyze`](../external/domain-1/ext-1-5-tls-analysis.md) (TLS protocols and ciphers) |

## What it checks

Plain HTTP must not serve the API (port closed or permanent redirect to HTTPS), and HTTPS responses must carry a
compliant `Strict-Transport-Security` header. TLS protocol and cipher analysis is done by the external tests
`ext.1.5.*`.

## How it works

**Plain-HTTP target.** If `target.base_url` does not start with `https://`, the test returns FAIL immediately
(no TLS at all) and does not run the sub-tests.

**Sub-test 1, HTTP redirect** (if `http_probe_enabled`). URL: `http_probe_url` if set, otherwise `base_url`
with `https://` replaced by `http://`. One `GET` without following redirects, sent directly with httpx (not through
the tool's HTTP client, so it does not appear in the audit trail or in `evidence.json`).

| Result | Verdict |
|---|---|
| Connection refused, protocol error, timeout, any other exception | Compliant (HTTP not served) |
| Status in `expected_redirect_status_codes` (default `301`, `308`) | Compliant |
| Any other status (`2xx`, `302`, `307`, `4xx`, `5xx`) | Finding: `HTTP Port Accessible Without HTTPS Redirect` |

**Sub-test 2, HSTS.** `GET /` on HTTPS through the tool's client (any status code is fine). The
`Strict-Transport-Security` header is checked:

| Condition | Finding |
|---|---|
| Header absent | `Strict-Transport-Security Header Absent` |
| No `max-age` | `Strict-Transport-Security Header Has No max-age` |
| `max-age` < `hsts_min_max_age_seconds` (default 31536000) | `Strict-Transport-Security max-age Below Minimum Threshold` |
| `includeSubDomains` absent | `Strict-Transport-Security Missing includeSubDomains` |

## Outcomes

| Status | When |
|---|---|
| PASS | No finding in the enabled sub-tests. |
| FAIL | Plain-HTTP target, or at least one finding. |
| SKIP | Never returned by this test. |
| ERROR | Unexpected exception. |

References: OWASP-API2:2023, RFC-9110-S4.2.2, NIST-SP-800-52-Rev2, OWASP-ASVS-v5.0.0-V12.1.1,
OWASP-ASVS-v5.0.0-V14.2.1.

## Oracle states

Sub-test 2 only (sub-test 1 is not recorded): `HSTS_COMPLIANT`, `HSTS_MISSING`, `HSTS_MAX_AGE_BELOW_MINIMUM`,
`HSTS_MISSING_INCLUDE_SUBDOMAINS`.

## Prerequisites and effects on the target

Two read-only requests, no credentials, no Admin API.

## Configuration

| Key | Effect |
|---|---|
| `http_probe_url` | Needed when HTTPS runs on a non-standard port: e.g. `https://localhost:8443` derives `http://localhost:8443/`, which hits the TLS listener and returns `400` (reported as a finding). Set the real HTTP listener, e.g. `http://localhost:8000/`. |
| `http_probe_enabled` | `false` skips sub-test 1. |
| `expected_redirect_status_codes`, `http_probe_timeout_seconds`, `hsts_min_max_age_seconds` | Oracle tuning. |

## Coverage against the methodology

Source: [`methodology.it.md` §1.5](../../knowledge/methodology/methodology.it.md).

| Methodology item | Status |
|---|---|
| HTTP request redirected or refused (empirical) | Implemented (sent without a token, the methodology sends a valid one). |
| HSTS with `max-age=31536000; includeSubDomains` | Implemented. |
| TLS 1.2/1.3 only, cipher suites, certificate validity | Delegated to [`ext.1.5.testssl` / `ext.1.5.sslyze`](../external/domain-1/ext-1-5-tls-analysis.md). |
| Certificate Transparency (≥ 2 SCT) | Not implemented by this test (see ext tests). |

## Why it exists

OWASP API2:2023, RFC 9110 §4.2.2, NIST SP 800-52 Rev. 2, OWASP ASVS v5.0.0 V12.1.1 and V14.2.1. An API that
answers on plain HTTP lets a man-in-the-middle downgrade the connection and read bearer tokens.

## Limitations

- Sub-test 1 treats any probe exception as "HTTP not served".
- Sub-test 1 leaves no transaction in the report or in `evidence.json`; its finding has no `evidence_ref`.

## See also

- [`ext.1.5 TLS analysis`](../external/domain-1/ext-1-5-tls-analysis.md) · [`6.2 Security headers`](../domain-6/6-2-security-headers-audit.md)
- [`../README.md`](../README.md)

# 7.2 SSRF Prevention

> **Audience:** analysts, contributors · **Status:** implemented (v0.1.0) · **Source of truth:**
> [`src/tests/domain_7/test_7_2_ssrf_prevention.py`](../../../src/tests/domain_7/test_7_2_ssrf_prevention.py),
> [`src/tests/data/ssrf_payloads.py`](../../../src/tests/data/ssrf_payloads.py) · **Verified:** 2026-10-05

| | |
|---|---|
| Test ID | `7.2` |
| Name | Server-Side Request Forgery (SSRF) Prevention |
| Domain | 7 - Business Logic and Sensitive Flows |
| Priority / strategy | P0 / GREY_BOX (the only P0 test that needs credentials) |
| CWE | CWE-918 |
| Depends on | none |
| Configuration | [`tests.domain_7.test_7_2`](../../reference/configuration.md#testsdomain_7test_7_2---ssrf-prevention), `user_a` credentials |

## What it checks

An endpoint that accepts a user-supplied URL must refuse URLs pointing to internal infrastructure: cloud metadata
services, private and loopback addresses (also in encoded forms), non-HTTP schemes, DNS names resolving to private
addresses, ambiguous URLs.

## How it works

1. Acquire a `user_a` token.
2. Prepare the injection endpoint according to `injection_mode`:
   - `forgejo_webhook` (default): create a temporary repository (registered for teardown) and post to
     `POST /api/v1/repos/{owner}/{repo}/hooks`. Webhooks are created inactive and are removed with the repository.
   - `fixed_path`: post directly to `injection_path_template`, for any other target.
3. For each payload in the enabled `payload_categories`, put the URL in `injection_url_field` of
   `injection_body_template` and send the request with the user token.

Payloads (73 in total, `src/tests/data/ssrf_payloads.py`):

| Category | Count | Examples |
|---|---|---|
| `cloud_metadata` | 11 | AWS, GCP, Azure, DigitalOcean metadata URLs (`169.254.169.254/…`) |
| `private_ip` | 16 | `127.0.0.1`, RFC 1918 ranges, `0.0.0.0`, `[::]` |
| `encoding_bypass` | 21 | decimal `2130706433`, hex `0x7f000001`, octal, `127.1`, IPv4-mapped IPv6, URL-encoded |
| `forbidden_protocol` | 12 | `file:///etc/passwd`, `gopher://`, `dict://`, `ftp://`, … |
| `dns_bypass` | 7 | `127.0.0.1.nip.io`, `sslip.io` |
| `url_parser_confusion` | 6 | `http://safe.example.com@127.0.0.1/`, backslash tricks |

Oracle per response:

| Response | State |
|---|---|
| `200`, `201` | `SSRF_ALLOWED` (the URL was accepted: vulnerable) |
| read timeout | `SSRF_TIMEOUT` → InfoNote `SSRF Probe Timeout: <category> / <payload>` (ambiguous) |
| any other status | Rejected; classified for the audit trail only, first match wins: |
| - payload scheme is non-HTTP (`file`, `gopher`, `dict`, `ftp`, `ldap`, `tftp`, `sftp`, `netdoc`, `jar`, `data`), or body matches `ssrf_unsupported_scheme_keywords` | `SSRF_BLOCKED_UNSUPPORTED_SCHEME` |
| - body matches `ssrf_malformed_url_keywords` | `SSRF_BLOCKED_AS_MALFORMED_URL` |
| - body matches `ssrf_block_response_keywords` | `SSRF_BLOCKED_BY_VALIDATION` |
| - no match | `SSRF_BLOCKED_UNKNOWN` |

4. **Redirect sub-test**, only if `ssrf_redirect_server_url` is set: inject the operator's redirect server and
   check that the target re-validates the redirected address (`SSRF_REDIRECT_ALLOWED` / `_BLOCKED` / `_TIMEOUT`).
   Otherwise an InfoNote records that it was not executed.

## Outcomes

| Status | When |
|---|---|
| PASS | Every payload rejected. InfoNotes for timeouts and for the skipped redirect sub-test. |
| FAIL | At least one payload accepted. The result carries **one consolidated finding** stating how many payloads were accepted; per-payload detail is in the transaction log and `evidence.json`. |
| SKIP | No API credentials or no `user_a` token; no payload category enabled; or `forgejo_webhook` mode on a target where the repository cannot be created (message suggests `fixed_path`). |
| ERROR | Token acquisition failed, or unexpected exception. |

References: OWASP-API7:2023, CWE-918, OWASP-ASVS-v5.0.0-V1.3.6, NIST-SP-800-204-S3.2.2.

## Prerequisites and effects on the target

- `user_a` username and password.
- `forgejo_webhook`: creates one repository and up to 73 inactive webhooks; teardown deletes the repository.
- `fixed_path`: **nothing is registered for teardown**. On a vulnerable target each accepted payload may create
  a persistent object (the request is a real `POST` with a valid token); remove them manually.
- The test only checks whether the URL is **accepted**. It does not observe an outbound request from the server
  (no out-of-band callback).

## Configuration

For a non-Forgejo target set `injection_mode: fixed_path`, `injection_path_template`, `injection_url_field` and
`injection_body_template` for the target's URL-accepting endpoint (example for cRAPI in
[`config_crapi.yaml`](../../../config_crapi.yaml)). Adjust the keyword lists to the target's error messages so
that rejections are classified precisely. `ssrf_request_timeout_ms` has no effect (Q-24).

## Coverage against the methodology

Source: [`methodology.it.md` §7.2](../../knowledge/methodology/methodology.it.md).

| Methodology sub-test | Status |
|---|---|
| Cloud metadata, private IPs, encoding bypass, protocol whitelist | Implemented. |
| Redirect following | Implemented, opt-in (needs an operator-controlled server). |
| DNS-based bypass, URL parser confusion | Implemented (beyond the methodology list). |
| Domain whitelist enforcement | Not implemented. |
| Blind SSRF via out-of-band callback | Not implemented (planned: `ext.7.2.interactsh`). |

## Why it exists

OWASP API7:2023, CWE-918, OWASP ASVS v5.0.0 V1.3.6, NIST SP 800-204 §3.2.2. A server that fetches user-supplied URLs
can be used to reach cloud credentials or internal services that are not exposed to the internet. It is P0
despite requiring credentials: any valid account is enough to pivot.

## Limitations

- A `2xx` other than `200`/`201` is not counted as accepted.
- The FAIL result has a single finding; count and payloads must be read from the transaction log.

## See also

- [`../README.md`](../README.md)

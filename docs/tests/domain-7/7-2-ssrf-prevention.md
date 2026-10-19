# 7.2 SSRF Prevention

> **Audience:** analysts, contributors · **Status:** implemented (v0.1.0) · **Source of truth:**
> [`src/tests/domain_7/test_7_2_ssrf_prevention.py`](../../../src/tests/domain_7/test_7_2_ssrf_prevention.py),
> [`src/tests/data/ssrf_payloads.py`](../../../src/tests/data/ssrf_payloads.py),
> [`src/tests/helpers/resources.py`](../../../src/tests/helpers/resources.py) · **Verified:** 2026-10-14 (injection
> endpoint and prepared resource), 2026-10-05

<!-- [[[cog import generate_docs as g; cog.out(g.test_header("7.2", page=cog.inFile)) ]]] -->

|  |  |
|---|---|
| Test ID | `7.2` |
| Name | Server-Side Request Forgery (SSRF) Prevention |
| Domain | 7 - Business Logic and Sensitive Flows |
| Priority / strategy | P0 / GREY_BOX |
| CWE | CWE-918 |
| Tags | `ssrf`, `business-logic`, `OWASP-API7:2023`, `CWE-918` |
| Prerequisites | none |
| Needs | `USER_ACCOUNT`, `url_accepting_endpoint` |
| Parameters | [`tests.domain_7.test_7_2`](../../reference/configuration.md#testsdomain_7test_7_2) |

<!-- [[[end]]] -->


## What it checks

An endpoint that accepts a user-supplied URL must refuse URLs pointing to internal infrastructure: cloud metadata
services, private and loopback addresses (also in encoded forms), non-HTTP schemes, DNS names resolving to private
addresses, ambiguous URLs.

## How it works

1. Obtain the `user_a` credential with the configured authentication method (`credentials.auth_type`); every
   request sends it as the run's credential placement says.
2. Prepare the endpoint that accepts a URL (`url_accepting_endpoint`: its `path` and `body`; no default: unset,
   the test returns SKIP). With its `resource`, the [prepared resource](../../reference/configuration.md#resources)
   is created once for `user_a` (deletion registered for teardown) and its values fill the placeholders of the path
   and the body. On the Forgejo labs it is a repository and the path is `/api/v1/repos/{owner}/{repo}/hooks`;
   webhooks are created inactive and go with the repository. Without it the path is used as written (crAPI).
3. For each payload in the enabled `payload_categories`, `POST` the body with `"{ssrf_url}"` replaced by the payload
   URL (and `"{random_secret}"` by a fresh random value, masked as a secret) with the `user_a` credential.

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
| SKIP | Recorded by the engine before the test runs: no `user_a` credentials ("Needs USER_ACCOUNT: ...") or no `url_accepting_endpoint` (the default; "Needs tests.domain_7.test_7_2.url_accepting_endpoint: not set ..."). By the test: no payload category enabled. |
| ERROR | Token acquisition failed; the endpoint's `resource` could not be created (the message names the resource, the request and the status); or unexpected exception. |

References: OWASP-API7:2023, CWE-918, OWASP-ASVS-v5.0.0-V1.3.6, NIST-SP-800-204-S3.2.2.

## Prerequisites and effects on the target

- `user_a` username and password.
- With the endpoint's `resource` (Forgejo labs): creates one resource, a repository, and up to 73 inactive webhooks on
  it; teardown deletes the repository, and the webhooks with it.
- Without it: **nothing is registered for teardown**. On a vulnerable target each accepted payload may create a
  persistent object (the request is a real `POST` with a valid token); remove them manually.
- On a gateway with passive health checks the probed service may be **excluded for a few seconds**: on the crAPI
  lab the payloads make the workshop service answer 503/504 and Kong takes it out of the pool until its active check
  re-enables it (about 5 s). Real users of that service would get errors meanwhile, and a run started in that window
  sees 503 there (Q-30, Q-29).
- The test only checks whether the URL is **accepted**. It does not observe an outbound request from the server
  (no out-of-band callback).

## Configuration

Set `url_accepting_endpoint` to the target's endpoint that accepts a URL: its `path`, its `body` (with
`"{ssrf_url}"`), and its `resource` when the endpoint belongs to an object that must exist first: Forgejo webhooks on the
resource `repository` in [`test-environments/forgejo-kong/config.yaml`](../../../test-environments/forgejo-kong/config.yaml),
cRAPI's fixed path in [`test-environments/crapi-kong/config.yaml`](../../../test-environments/crapi-kong/config.yaml). Adjust the keyword lists to the target's error messages so
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

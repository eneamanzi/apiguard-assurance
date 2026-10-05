# 6.4 Hardcoded Credentials Audit

> **Audience:** analysts, contributors · **Status:** implemented (v0.1.0) · **Source of truth:**
> [`src/tests/domain_6/test_6_4_hardcoded_credentials_audit.py`](../../../src/tests/domain_6/test_6_4_hardcoded_credentials_audit.py) ·
> **Verified:** 2026-10-05

| | |
|---|---|
| Test ID | `6.4` |
| Name | Service Credentials Not Hardcoded or Exposed |
| Domain | 6 - Configuration and Hardening |
| Priority / strategy | P2 / WHITE_BOX (sub-test A works without Admin API; sub-test B needs it) |
| CWE | CWE-798 |
| Depends on | none |
| Configuration | [`tests.domain_6.test_6_4`](../../reference/configuration.md#testsdomain_6test_6_4---hardcoded-credentials-audit), optionally `target.admin_api_url` + `target.gateway_adapter` |

## What it checks

Service credentials (database passwords, API keys, private keys) must not be exposed by debug endpoints nor stored
in plain text in the gateway configuration.

## How it works

**Sub-test A, debug endpoints (always runs).** Unauthenticated `GET` on each path in `debug_endpoint_paths`
(10 defaults: `/actuator/env`, `/actuator/configprops`, `/actuator/health`, `/debug/vars`, `/debug/pprof`,
`/api/config`, `/admin/config`, `/_debug`, `/api/debug/users`, `/api/debug/config`).

| Response | Result |
|---|---|
| `2xx` and the body matches a credential pattern | Finding `Credential Pattern Exposed via Debug Endpoint: <path>` |
| `2xx` with structured data, no pattern | InfoNote `Unauthenticated Debug Endpoint Returns Structured Data: <path>` |
| non-`2xx` | Blocked (distinguishes gateway block from application block via `gateway_block_body_fragment`) |

Credential patterns: URL-embedded `user:password@host`, AWS access key id (`AKIA…`), Stripe `sk_live_` / `sk_test_`,
GitHub `ghp_` token, PEM private key.

**Sub-test B, gateway configuration (only with Admin API and adapter).**

| Check | Finding |
|---|---|
| Service URL contains `user:password@` | `Credential Hardcoded in Kong Service URL: <service>` |
| Plugin config value matches a credential pattern | `Credential Pattern in Kong Config: <location>` |
| Plugin config key looks sensitive (`password`, `secret`, `api_key`, `client_secret`, `private_key`, … 27 fragments; `token` alone is excluded) and the value has ≥ 8 characters and is not one of 30 known placeholders (`changeme`, `example`, …) | `Probable Plaintext Credential in Kong Config: <location>` |

Without Admin API, sub-test B is replaced by the InfoNote `Admin API Audit Gap: Kong Configuration Not Scanned`.
With it, an InfoNote reminds that filesystem and container-image checks must be done manually.

## Outcomes

| Status | When |
|---|---|
| PASS | No finding (InfoNotes may document open endpoints and audit gaps). |
| FAIL | At least one finding. |
| SKIP | Never returned by this test. |
| ERROR | Unexpected exception. |

References: CWE-798, OWASP-API8:2023, OWASP-ASVS-V13.3.1, V13.3.4, V13.4.1, NIST-SP-800-53-Rev5-IA-5(1),
NIST-SP-800-204-S5.4. Sub-test B findings have no `evidence_ref` (Admin API calls are not recorded).

## Oracle states

`ENDPOINT_BLOCKED` (gateway block, body contains `gateway_block_body_fragment`), `ENDPOINT_BLOCKED_BY_APP`,
`ENDPOINT_OPEN_NO_CREDENTIALS`, `ENDPOINT_OPEN_WITH_DATA`, `CREDENTIAL_EXPOSED` (FAIL evidence).

## Prerequisites and effects on the target

Read-only `GET`s without credentials; read-only Admin API calls when configured. Matched secrets appear in the
finding detail and in `evidence.json`: treat the report as sensitive.

## Configuration

`debug_endpoint_paths` (adapt to the target's stack) and `gateway_block_body_fragment` (default is Kong's
`no Route matched with those values`; change it for other gateways).

## Coverage against the methodology

Source: [`methodology.it.md` §6.4](../../knowledge/methodology/methodology.it.md).

| Methodology item | Status |
|---|---|
| Debug endpoint exposure | Implemented. |
| Regex scan of gateway configuration | Implemented on Admin API services and plugins (not on configuration files). |
| Container image layers (`docker history`) | Not implemented (InfoNote). |
| Secret rotation audit | Not implemented. |

## Why it exists

CWE-798, OWASP API8:2023, OWASP ASVS v5.0.0 V13.3 / V13.4, NIST SP 800-53 IA-5(1). Static credentials cannot be
rotated without redeployment and, once leaked, give direct backend access that bypasses the gateway. Tooling
decision ([`decisions.it.md` §6.4](../../knowledge/tools/decisions.it.md)): native in M1; trufflehog, gitleaks and
detect-secrets are optional Cat B complements.

## See also

- [`6.2 Security headers`](6-2-security-headers-audit.md)
- [`../README.md`](../README.md)

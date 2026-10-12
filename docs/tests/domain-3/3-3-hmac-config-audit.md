# 3.3 HMAC Configuration Audit

> **Audience:** analysts, contributors · **Status:** implemented (v0.1.0); any gateway with an adapter (today Kong) · **Source of truth:**
> [`src/tests/domain_3/test_3_3_hmac_config_audit.py`](../../../src/tests/domain_3/test_3_3_hmac_config_audit.py) ·
> **Verified:** 2026-10-05

| | |
|---|---|
| Test ID | `3.3` |
| Name | HMAC Authentication Configuration Does Not Allow Replay or Weak Algorithms |
| Domain | 3 - Data Integrity |
| Priority / strategy | P3 / WHITE_BOX (gateway Admin API) |
| CWE | CWE-326 |
| Depends on | none |
| Configuration | [`tests.domain_3.test_3_3`](../../reference/configuration.md#testsdomain_3test_3_3---hmac-configuration-audit), `target.admin_api_url`, `target.gateway_adapter` |

## What it checks

When HMAC request signing is enforced by the gateway (Kong `hmac-auth` plugin), its configuration must not allow
replay (unlimited or too wide `clock_skew`) and must not accept weak algorithms (`hmac-sha1`, `hmac-md5`).

## How it works

No request is sent to the target API: the test reads the gateway concepts "request signing policies" and "routes"
through the adapter (`target.gateway`, [gateway concepts](../../project/gateway-concepts.md)). On Kong the policies
are the plugins whose name is in `plugin_names` (default `hmac-auth`), read with the field names of this test's
configuration; `<policy>` below is the policy's reference, on Kong `plugin <name> (id: <id>)`.

1. **Policy discovery.** Take the **first** policy.
2. **Replay window** (field `field_clock_skew`, default `clock_skew`):

| Value | Finding |
|---|---|
| not stated by the gateway | `HMAC '<field>' Field Absent on '<policy>'` |
| equals `clock_skew_unconfigured_value` (default `0`) | `HMAC Replay Window Unlimited: …` |
| greater than `max_clock_skew_seconds` (default 300) | `HMAC Replay Window Too Wide: …` |

3. **Algorithms** (field `field_algorithms`): one finding per value in `forbidden_algorithms` that the policy
   allows: `Forbidden HMAC Algorithm '<alg>' Allowed on '<policy>'`. Algorithms not stated by the gateway are also a
   finding; an empty list is not.
4. **Coverage scope** (InfoNote, never a finding): global policy, or which backends and routes are and are not
   covered, by name (backends from the routes concept; a backend-scope policy covers the routes that send to it).
   Routes not readable: a note listing the policy scopes only.
5. **Body validation** (InfoNote, never a finding): value of `validate_request_body`.

## Outcomes

| Status | When |
|---|---|
| PASS | Plugin found and enabled, no finding. Carries the coverage and body-validation InfoNotes. |
| FAIL | At least one finding (InfoNotes attached too). |
| SKIP | No gateway adapter configured; `plugin_names` empty; the signing policies not supported or not readable ("Not applicable to this gateway: ..." / "Not verifiable: no access to ..."); no policy; or the first policy disabled (InfoNote `HMAC Authentication Not Active: Manual Verification Recommended`). |
| ERROR | Unexpected exception. |

References: OWASP-API2:2023, CWE-326, NIST-SP-800-107-Rev1-S5.3.2, NIST-SP-800-131A-Rev2-2019, RFC-2104, RFC-6151,
OWASP-ASVS-v5.0.0-V2.9.1. The concepts read are stored in `evidence.json` (`artifact-3.3-gateway_...`); findings point
to the signing policies read (`evidence_ref`), the coverage note names the routes evidence.

## Prerequisites and effects on the target

`target.admin_api_url` and `target.gateway_adapter: kong`. Read-only Admin API calls; no traffic to the API.

## Configuration

`max_clock_skew_seconds`, `forbidden_algorithms`, `plugin_names`, and the field-name keys
(`field_clock_skew`, `field_algorithms`, `field_validate_body`, `clock_skew_unconfigured_value`) which adapt the
audit to a plugin with a different schema.

## Coverage against the methodology

Source: [`methodology.it.md` §3.3](../../knowledge/methodology/methodology.it.md).

| Methodology item | Status |
|---|---|
| Signing mechanism present? | Only as a gateway plugin; HMAC implemented in the application or middleware is not detected (SKIP with InfoNote). |
| Algorithm ≥ SHA-256 | Implemented as a deny-list (`forbidden_algorithms`). |
| Replay protection (window ≤ 5 min) | Implemented (`clock_skew` ≤ 300 s). Nonce-based protection not checked. |
| Key entropy ≥ 256 bit | Not checked. |
| Empirical tampering / replay test | Not implemented (needs consumer HMAC credentials). |

## Why it exists

OWASP ASVS v5.0.0 V4.1.5 / V2.9.1, NIST SP 800-107 Rev. 1, NIST SP 800-131A Rev. 2, RFC 2104, RFC 6151. HMAC
signing protects requests from tampering by intermediaries beyond TLS; a wide replay window or a broken algorithm
voids that protection.

## Limitations

- Only the first matching plugin instance is audited; if it is disabled the test SKIPs even when another enabled
  instance exists.
- Gateways with an adapter (today Kong).

## See also

- [`4.2 Timeout audit`](../domain-4/4-2-timeout-config-audit.md) · [`4.3 Circuit breaker audit`](../domain-4/4-3-circuit-breaker-audit.md)
- [`../README.md`](../README.md)

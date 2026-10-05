# 4.2 Timeout Configuration Audit

> **Audience:** analysts, contributors · **Status:** implemented (v0.1.0), Kong only · **Source of truth:**
> [`src/tests/domain_4/test_4_2_timeout_config_audit.py`](../../../src/tests/domain_4/test_4_2_timeout_config_audit.py) ·
> **Verified:** 2026-10-05

| | |
|---|---|
| Test ID | `4.2` |
| Name | Timeout Configuration Audit -- Prevention of Resource Lock |
| Domain | 4 - Availability and Resilience |
| Priority / strategy | P1 / WHITE_BOX (gateway Admin API) |
| CWE | CWE-400 |
| Depends on | none |
| Configuration | [`tests.domain_4.test_4_2`](../../reference/configuration.md#testsdomain_4test_4_2---timeout-configuration-audit), `target.admin_api_url`, `target.gateway_adapter` |

## What it checks

Every upstream service configured on the gateway must have connect, read and write timeouts set and bounded, so
that a slow backend cannot hold gateway workers indefinitely.

## How it works

No request is sent to the target API. Through the gateway adapter the test lists all services and, for each one,
checks `connect_timeout`, `read_timeout`, `write_timeout`:

| Value | Finding |
|---|---|
| field absent | `Timeout Field Absent: <field> on service '<name>'` |
| `0` | `Timeout Not Configured: <field> == 0 on service '<name>'` |
| above the threshold | `Timeout Exceeds Oracle Threshold: <field> = <value> ms on service '<name>'` |

Thresholds (ms): `max_connect_timeout_ms` 5000, `max_read_timeout_ms` 30000, `max_write_timeout_ms` 30000.

## Outcomes

| Status | When |
|---|---|
| PASS | Every service has all three timeouts within bounds. |
| FAIL | At least one finding. |
| SKIP | No Admin API / adapter configured, or no service registered on the gateway. |
| ERROR | Admin API call failed, or unexpected exception. |

References: OWASP-API4:2023, CWE-400, NIST-SP-800-204A-Section-4.3, OWASP-ASVS-v5.0.0-V16.5.2. Findings have no
`evidence_ref`; values are quoted in the detail.

## Prerequisites and effects on the target

`target.admin_api_url` and `target.gateway_adapter: kong`. Read-only Admin API calls.

## Coverage against the methodology

Source: [`methodology.it.md` §4.2](../../knowledge/methodology/methodology.it.md).

| Methodology item | Status |
|---|---|
| Gateway upstream timeouts (connect ≤ 5 s, read ≤ 30 s) | Implemented for all gateway services. |
| Application connection-pool timeouts | Not implemented (no access to application config). |
| Timeouts on outbound calls in application code | Not implemented. |
| Empirical test with a slow mock service | Not implemented (staging only). |

## Why it exists

OWASP API4:2023, CWE-400, NIST SP 800-204A §4.3. Without timeouts, blocked requests accumulate until the worker
pool is exhausted and the gateway stops accepting traffic.

## See also

- [`4.3 Circuit breaker audit`](4-3-circuit-breaker-audit.md) · [`3.3 HMAC audit`](../domain-3/3-3-hmac-config-audit.md)
- [`../README.md`](../README.md)

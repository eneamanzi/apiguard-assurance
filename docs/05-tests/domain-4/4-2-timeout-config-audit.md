# 4.2 Timeout Configuration Audit

> **Audience:** analysts, contributors · **Status:** implemented (v0.1.0); any gateway with an adapter (today Kong) · **Source of truth:**
> [`src/tests/domain_4/test_4_2_timeout_config_audit.py`](../../../src/tests/domain_4/test_4_2_timeout_config_audit.py) ·
> **Verified:** 2026-10-12

<!-- [[[cog import generate_docs as g; cog.out(g.test_header("4.2", page=cog.inFile)) ]]] -->

|  |  |
|---|---|
| Test ID | `4.2` |
| Name | Timeout Configuration Audit -- Prevention of Resource Lock |
| Domain | 4 - Availability and Resilience |
| Priority / strategy | P1 / WHITE_BOX |
| CWE | CWE-400 |
| Tags | `availability`, `timeout`, `resource-lock`, `white-box`, `OWASP-API4` |
| Prerequisites | none |
| Needs | `GATEWAY` |
| Parameters | [`tests.domain_4.test_4_2`](../../03-reference/01-configuration.md#testsdomain_4test_4_2) |

<!-- [[[end]]] -->


## What it checks

Every upstream service configured on the gateway must have connect, read and write timeouts set and bounded, so
that a slow backend cannot hold gateway workers indefinitely.

## How it works

No request is sent to the target API. The test reads the gateway concept "backend timeouts" through the gateway
adapter ([gateway concepts](../../04-architecture/05-design-decisions.md#d7-neutral-gateway-concepts)): one item per backend (a Kong service), or per route
that overrides its backend's timeouts (APISIX), in seconds. For each item it checks the connect, read and write
timeouts (`write_timeout` is the time between two writes to the backend). Each timeout is a sub-test
(`connect_timeout`, `read_timeout`, `write_timeout`); each item gives one judgement in each:

| Value | Outcome / detail | Finding |
|---|---|---|
| within the threshold | `ENFORCED/WITHIN_LIMIT` | none |
| above the threshold | `VIOLATION/ABOVE_LIMIT` | `Timeout Exceeds Oracle Threshold: <field> = <value> ms on service '<name>'` |
| `0` | `VIOLATION/NOT_CONFIGURED` | `Timeout Not Configured: <field> == 0 on service '<name>'` |
| not stated by the gateway | `VIOLATION/NOT_STATED` | `Timeout Field Absent: <field> on service '<name>'` (`route '<name>'` for a route) |

The oracle is the one of v0.1.0, moved onto the computed result (pilot of the test review); whether a timeout the
gateway does not state is a violation is decided in the review of this test.

Thresholds (ms): `max_connect_timeout_ms` 5000, `max_read_timeout_ms` 30000, `max_write_timeout_ms` 30000.

## Outcomes

| Status | When |
|---|---|
| PASS | No violation: every item has all three timeouts within bounds (always `complete`: this test has no not verifiable case). |
| FAIL | At least one violation (one finding each). |
| SKIP | No gateway adapter configured; the gateway has no such concept ("Not applicable to this gateway: backend timeouts: ..."); the Admin API cannot be read ("Not verifiable: no access to backend timeouts: ..."); or no backend registered. |
| ERROR | Unexpected exception. |

References: OWASP-API4:2023, CWE-400, NIST-SP-800-204A-Section-4.3, OWASP-ASVS-v5.0.0-V16.5.2. The concept read is
stored in `evidence.json` as an artifact (`artifact-4.2-gateway_backend_timeouts-...`, also in `tools/`) and every
finding points to it (`evidence_ref`); the SKIP reasons name it too.

## Prerequisites and effects on the target

`gateway.adapter` and `gateway.admin.url` (plus `gateway.admin.headers` and `gateway.admin.tls` for a protected Admin API).
Read-only Admin API calls.

## Coverage against the methodology

Source: [`04-guarantees.md` §4.2](../../06-knowledge/04-guarantees.md).

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

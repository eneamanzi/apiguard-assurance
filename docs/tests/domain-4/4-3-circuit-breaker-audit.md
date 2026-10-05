# 4.3 Circuit Breaker Audit

> **Audience:** analysts, contributors · **Status:** implemented (v0.1.0), Kong only · **Source of truth:**
> [`src/tests/domain_4/test_4_3_circuit_breaker_audit.py`](../../../src/tests/domain_4/test_4_3_circuit_breaker_audit.py) ·
> **Verified:** 2026-10-05

| | |
|---|---|
| Test ID | `4.3` |
| Name | Circuit Breaker Audit -- Dual-Check a 3 Livelli |
| Domain | 4 - Availability and Resilience |
| Priority / strategy | P1 / WHITE_BOX (gateway Admin API) |
| CWE | CWE-400 |
| Depends on | none |
| Configuration | [`tests.domain_4.test_4_3`](../../reference/configuration.md#testsdomain_4test_4_3---circuit-breaker-audit), `target.admin_api_url`, `target.gateway_adapter` |

## What it checks

The gateway must stop forwarding traffic to a failing backend (circuit breaker), so that one degraded dependency
does not exhaust the gateway and cause a cascading outage.

## How it works

No request is sent to the target API. Three levels, evaluated in order through the gateway adapter, plus an
independent observability check. Kong OSS has no native circuit-breaker plugin, hence the fallback levels.

**Level 1, native plugin.** Look for an installed plugin named in `accepted_cb_plugin_names` (default
`circuit-breaker`). If found, the result is decided here:

| Plugin state | Finding |
|---|---|
| Disabled | `CB Plugin '<name>' Registered but Disabled` |
| Failure threshold or open duration missing | `CB Parameter '<label>' Not Found in Plugin '<name>'` (aliases searched: `failure_threshold`, `consecutive_errors`, `error_threshold_percentage`; `timeout`, `sleep_time`, `recovery_time`, `timeout_duration`) |
| Value not numeric | `CB Parameter '<label>' Non-Numeric in Plugin '<name>'` |
| Outside `failure_threshold_min`-`max` (3-10) or `timeout_duration_min`-`max_seconds` (30-120) | `CB Parameter '<label>' Out of Range (…) in Plugin '<name>'` |

**Level 2, compensating control** (only if no plugin at Level 1). Inspect upstreams for passive health checks:
one is configured when at least one of `unhealthy.http_failures`, `unhealthy.tcp_failures`,
`unhealthy.timeouts` is above 0, and valid when every non-zero value is within `passive_hc_max_*` (default 10).
At least one valid upstream → PASS with InfoNote
`Level 2 (Compensating Control): Passive HC on <n>/<total> Upstream(s) -- No Native CB Plugin`.

**Level 3, no protection.** Neither of the above → finding
`Level 3 (Vulnerable): No Circuit-Breaker Protection Detected`.

**Observability.** The gateway `/status` response is checked for circuit-breaker fields (`circuit_breaker`,
`circuit_breakers`, `cb_state`). If absent: `Observability Gap: CB Metrics Absent from Kong /status`, attached as
an InfoNote on PASS and as an additional **Finding** on FAIL (it then counts in the finding total).

## Outcomes

| Status | When |
|---|---|
| PASS | Level 1 plugin compliant, or Level 2 compensating control found. |
| FAIL | Level 1 plugin with issues, or Level 3. |
| SKIP | No Admin API / adapter configured. |
| ERROR | Admin API call failed, or unexpected exception. |

References: OWASP-API4:2023, OWASP-ASVS-v5.0.0-V16.5.2, NIST-SP-800-204-Section-4.5.1, CWE-400. No
`evidence_ref`: configuration values are quoted in the detail.

## Prerequisites and effects on the target

`target.admin_api_url` and `target.gateway_adapter: kong`. Read-only Admin API calls.

## Coverage against the methodology

Source: [`methodology.it.md` §4.3](../../knowledge/methodology/methodology.it.md).

| Methodology item | Status |
|---|---|
| Circuit-breaker directive present | Implemented (Kong plugin, or passive health checks as compensating control). |
| Parameters: threshold 3-10, open duration 30-120 s | Implemented for the plugin. Trigger codes (5xx and timeouts) not checked. |
| Health endpoint exposing breaker state | Implemented as the `/status` observability check. |
| 30-day metrics analysis | Not implemented. |
| Behavioural test with a disabled dependency | Not implemented (staging only). |

## Why it exists

OWASP API4:2023, OWASP ASVS v5.0.0 V16.5.2, NIST SP 800-204 §4.5.1 (circuit breaker pattern). Without it, every
request to a failing dependency waits for the full timeout and the backlog takes down the whole gateway.

## Limitations

- Level 2 passes if at least one upstream has a valid passive health check, even when other upstreams have none
  (the InfoNote reports `<n>/<total>`).
- On Kong OSS, Level 1 is never satisfied unless a third-party plugin is installed.

## See also

- [`4.2 Timeout audit`](4-2-timeout-config-audit.md) · [`4.1 Rate limiting`](4-1-rate-limiting.md)
- [`../README.md`](../README.md)

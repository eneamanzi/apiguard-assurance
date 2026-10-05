# 4.1 Rate Limiting

> **Audience:** analysts, contributors · **Status:** implemented (v0.1.0) · **Source of truth:**
> [`src/tests/domain_4/test_4_1_rate_limiting.py`](../../../src/tests/domain_4/test_4_1_rate_limiting.py) ·
> **Verified:** 2026-10-05

| | |
|---|---|
| Test ID | `4.1` |
| Name | Rate Limiting -- Resource Exhaustion Prevention |
| Domain | 4 - Availability and Resilience |
| Priority / strategy | P0 / BLACK_BOX |
| CWE | CWE-400 |
| Depends on | none |
| Configuration | [`tests.domain_4.test_4_1`](../../reference/configuration.md#testsdomain_4test_4_1---rate-limiting) |

## What it checks

The gateway must rate-limit requests (`429 Too Many Requests`), bind the counter to the real client IP rather than
to a spoofable `X-Forwarded-For` header, and tell clients when to retry.

## How it works

One probe endpoint is chosen from the spec: the first non-parametric `GET`, otherwise the first non-parametric
endpoint, otherwise the first endpoint. It is called with its declared method, no credentials, no body.

1. **Spoofing resistance.** Up to `max_requests` (default 150) requests, `request_interval_ms` (default 50 ms)
   apart, each with a different random `X-Forwarded-For`. Stops at the first `429`.
2. **Enforcement.** The same, without `X-Forwarded-For`. Stops at the first `429`.
3. **Retry guidance.** On the first `429` observed, check for `Retry-After`, `X-RateLimit-Reset`,
   `X-Rate-Limit-Reset` or `RateLimit-Reset`.

Step 1 runs first on purpose: if the gateway counts by real IP, it consumes part of the budget and step 2 reaches
`429` sooner, which is still a pass.

| Condition | Finding |
|---|---|
| No `429` in step 1 | `Rate Limit Counter Bound to X-Forwarded-For (Spoofing Vulnerability)` |
| No `429` in step 2 | `Rate Limiting Not Enforced` |
| `429` without any retry header | `429 Response Missing Retry-After / X-RateLimit-Reset Header` |

If the gateway has no rate limiting at all, steps 1 and 2 both produce a finding.

## Outcomes

| Status | When |
|---|---|
| PASS | `429` reached in both steps, with a retry header. |
| FAIL | At least one finding. |
| SKIP | Attack surface unavailable or empty. |
| ERROR | Unexpected exception. |

References: OWASP-API4:2023, OWASP-ASVS-v5.0.0-V2.4.1, NIST-SP-800-204-Section-4.5, CWE-400. The first `429` is
stored in `evidence.json` even on PASS, as proof that the limit triggered.

## Oracle states

`PROBE_HIT` (any non-429 response), `RATE_LIMIT_HIT` (`429`), `TRANSPORT_ERROR`.

## Prerequisites and effects on the target

- Only the specification.
- **Up to 2 × `max_requests` requests (300 by default) in a burst** against one endpoint. The run exhausts the
  rate-limit budget of the tool's IP; tests running right after may receive `429` (inconclusive in 1.1). nuclei is
  throttled (`rate_limit_rps`) for the same reason.

## Configuration

| Key | Effect |
|---|---|
| `max_requests` (10-500) | Must exceed the gateway's limit for the probed endpoint, otherwise the test reports missing rate limiting. |
| `request_interval_ms` (10-5000) | Spacing between requests: a limit per minute needs enough requests inside the window. |

## Coverage against the methodology

Source: [`methodology.it.md` §4.1](../../knowledge/methodology/methodology.it.md).

| Methodology sub-test | Status |
|---|---|
| Enforcement of the limit | Implemented on one endpoint, with a fixed budget (the methodology compares against the documented limit). |
| `Retry-After` / reset header | Presence implemented; waiting and re-checking the reset is not. |
| Header spoofing resistance (`X-Forwarded-For`) | Implemented. |
| Per-user vs per-IP limit | Not implemented (needs two users). |
| Burst behaviour (token bucket) | Not implemented. |

## Why it exists

OWASP API4:2023 (Unrestricted Resource Consumption), OWASP ASVS v5.0.0 V2.4.1, NIST SP 800-204 §4.5. Without rate
limiting a login endpoint allows unlimited brute force and an expensive endpoint can be saturated. Tooling decision
([`decisions.it.md` §4.1](../../knowledge/tools/decisions.it.md)): native implementation in M1; vegeta (precise
load) is a planned Cat A connector.

## Limitations

- One endpoint only: a limit configured on other routes but not on the probed one is reported as absent, and vice
  versa.
- A gateway that ignores `X-Forwarded-For` but has no rate limiting yields both findings; read them together.

## See also

- [`4.2 Timeout audit`](4-2-timeout-config-audit.md) · [`4.3 Circuit breaker audit`](4-3-circuit-breaker-audit.md)
- [`../README.md`](../README.md)

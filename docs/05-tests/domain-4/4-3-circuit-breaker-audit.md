# 4.3 Circuit Breaker Audit

> **Audience:** analysts, contributors · **Status:** reviewed test by test (2026-10-27) ·
> **Source of truth:**
> [`src/tests/domain_4/test_4_3_circuit_breaker_audit.py`](../../../src/tests/domain_4/test_4_3_circuit_breaker_audit.py) ·
> **Verified:** 2026-10-27

<!-- [[[cog import generate_docs as g; cog.out(g.test_header("4.3", page=cog.inFile)) ]]] -->

|  |  |
|---|---|
| Test ID | `4.3` |
| Name | Circuit Breaker Audit |
| Domain | 4 - Availability and Resilience |
| Priority / strategy | P1 / WHITE_BOX |
| Effect | READ_ONLY |
| CWE | CWE-400 |
| Standards | `OWASP API4:2023`, `OWASP ASVS v5.0.0-16.5.2`, `NIST SP 800-204, Section 4.5.1` |
| Tags | `resource-consumption`, `circuit-breaker`, `resilience` |
| Prerequisites | none |
| Needs | `GATEWAY` |
| Parameters | none |

<!-- [[[end]]] -->

**Same group:** tests `4.1`, `4.2`, `4.4` (resource-consumption limits).

## 1. Guarantee

The gateway degrades gracefully when a backend fails: a circuit breaker opens after repeated failures and answers at
once instead of waiting for a timeout on every request. A passive health check (a failing backend is taken out of
rotation) is the accepted equivalent. A PASS promises the gateway can **notice** a failing backend and stop sending
to it: either an enabled breaker, or a health check with a failure threshold above zero or an active probe on its
healthy targets. The threat (OWASP API4:2023, ASVS v5.0.0-16.5.2): without it, a failing dependency makes every
request wait for its timeout and the thread pool fills, cascading the failure.

## 2. Sub-tests and coverage of the methodology

| Sub-test | Methodology (guarantee 4.3) |
|---|---|
| `degradation_configured` | "the presence of circuit breaker directives, or an equivalent (passive health check)" |
| left out | the parameter thresholds check and the behavioural staging test (a coordinated downstream outage, not reproducible from outside) |

Whether an excluded backend comes back by itself (an active probe on unhealthy targets,
`HealthCheck.recovers_automatically`) is not required for the control to exist: the test reports it in the note
instead of withholding the pass.

## 3. Inputs

Two gateway concepts read through the adapter: `circuit_breakers` and `health_checks` (`src/core/gateway/`). No
request is sent.

## 4. Preconditions and reference responses

`Need.GATEWAY` (the Admin API). No reference responses: the concepts read are the evidence.

## 5. Probes

None: a configuration audit. The two concepts are read and pinned as evidence.

## 6. Oracle (`degradation_configured`)

| Case | Outcome / detail | Confidence |
|---|---|---|
| a circuit breaker is enabled | `ENFORCED/CIRCUIT_BREAKER` | CERTAIN |
| no breaker, but a health check that detects failures (a passive threshold above zero, or an active probe on healthy targets) | `ENFORCED/HEALTH_CHECK` (a note: a compensating control, and which backends do not come back by themselves) | CERTAIN |
| neither, and both concepts were answered (read, or not supported by the gateway) | `VIOLATION/NO_CIRCUIT_BREAKER` | CERTAIN |
| neither, but a concept was **not accessible** | `NOT_VERIFIABLE/GATEWAY_READ_FAILED` (a note naming what could not be read) | - |
| neither concept readable | SKIP (the reason names both concepts) | - |

The last two rows are the same honesty rule as elsewhere: with the breakers unread, "the gateway has no breaker" is
not a fact. A concept the gateway does not have at all (`NOT_SUPPORTED`) is different, and there the absence counts.

## 7. Outcomes

SKIP when neither concept can be read. INCONCLUSIVE when nothing was found but part of the admin plane could not be
read. FAIL when the gateway has no breaker and no health check that detects failures; PASS otherwise (with a note
when the control is a health check standing in for a breaker).

## 8. Findings

"No circuit breaker or health check on the gateway", `evidence_ref` the circuit-breaker concept artifact.

## 9. Effects on the target

`READ_ONLY`: reads the gateway Admin API, sends no request to the API.

## 10. Per gateway

Kong has no circuit-breaker plugin of its own: of the 45 plugins its OSS build offers, none is a breaker (checked on
the lab with `GET /`), so the adapter recognises third-party ones by plugin name, today `circuit-breaker`
([dream11/kong-circuit-breaker](https://github.com/dream11/kong-circuit-breaker)). Without such a plugin, Kong's
passive health check, a backend marked unhealthy after N failures, is the equivalent, reported ENFORCED with a note. APISIX
has the `api-breaker` plugin as well as health checks, and a breaker there is reported as a breaker.

**Both gateways answer with their defaults filled in**, and this decides the oracle: an upstream with no health check
at all still comes back with a complete `active` record whose intervals are zero. Kong's own schema
(`GET /schemas/upstreams`) gives `active.healthy.interval = 0`, `active.unhealthy.interval = 0` and `http_path = /`,
and zero means the target is never probed. Reading "the record exists" as "a check is configured" would pass every
Kong gateway that has at least one upstream, so the test requires a threshold or an interval above zero.

## 11. Configuration

None.

## 12. Validation

Runs of 2026-10-27, after the test-by-test review. **Every branch of the oracle was produced and observed**, and the
table says how:

| Case | Lab and how it was produced | Observed |
|---|---|---|
| `ENFORCED/HEALTH_CHECK` | Forgejo + Kong, crAPI + Kong, Forgejo + APISIX, as configured | **PASS**, the note naming the upstreams (`forgejo-upstream`; `community-upstream, identity-upstream, workshop-upstream`) |
| the same, with no automatic recovery | Forgejo + Kong, the upstream's `active` block removed (passive only), then restored | **PASS**, plus "once excluded they stay excluded until someone intervenes" |
| `ENFORCED/CIRCUIT_BREAKER` | Forgejo + APISIX, a temporary route with the `api-breaker` plugin (threshold 3), then deleted | **PASS**, "The gateway has an enabled circuit breaker: breaker-probe-route (threshold 3)" |
| the same on Kong | Forgejo + Kong read through a proxy that adds a `circuit-breaker` plugin with the dream11 plugin's own configuration (no plugin installed in the lab) | **PASS**, "threshold 51", from `failure_percent_threshold`: with the field names the adapter used before 2026-10-28 it printed "threshold None" |
| `VIOLATION/NO_CIRCUIT_BREAKER` | Forgejo + Kong, the upstream's whole `healthchecks` block removed, then restored | **FAIL**, 1 finding, CERTAIN |
| `NOT_VERIFIABLE/GATEWAY_READ_FAILED` | Forgejo + Kong read through a filtering proxy that serves `/upstreams` with zeroed thresholds and answers `500` on `/plugins` | **INCONCLUSIVE**, the note naming the breakers as unread |
| SKIP | Forgejo + Kong with `gateway.admin.url` on a closed port | **SKIP**, the reason naming both concepts |

Rule 9 is satisfied without a reservation: both sides of the judgement, and the two honest non-verdicts, are proven
on a real gateway. The VIOLATION branch became reachable only with this review: before it, an upstream with no health
check was read as protected, because the `active` record exists with zero intervals, so the branch could not be
produced on Kong at all.

## 13. Remediation

Configure a circuit breaker (or at least a passive health check that takes a failing backend out of rotation) with a
failure threshold and an open-state timeout, so a failing dependency does not cascade (OWASP API4:2023, ASVS
v5.0.0-16.5.2).

## 14. Limitations

- Only the presence of a breaker or health check is judged, never whether its thresholds are sound: a breaker that
  opens after ten thousand failures passes. Judging `failure_threshold` and `open_seconds` would need a defensible
  value for each target and is not planned (2026-10-27).
- The behavioural test (a real downstream outage) is out of scope: it needs a coordinated staging action, so the test
  proves a control is configured, never that it fires.
- A breaker or check configured on one backend passes the test for the whole gateway: the oracle asks whether the
  gateway has the control, not whether every backend is covered by it. The note names the backends that have it, so
  the gap is visible to the reader.

## 15. Sources

- OWASP API4:2023 Unrestricted Resource Consumption: https://owasp.org/API-Security/editions/2023/en/0xa4-unrestricted-resource-consumption/
- OWASP ASVS v5.0.0-16.5.2 (operate securely when external resource access fails): https://github.com/OWASP/ASVS/blob/v5.0.0/5.0/en/0x25-V16-Security-Logging-and-Error-Handling.md
- NIST SP 800-204 section 4.5.1 (circuit breaker for microservices): https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-204.pdf
- CWE-400 Uncontrolled Resource Consumption: https://cwe.mitre.org/data/definitions/400.html

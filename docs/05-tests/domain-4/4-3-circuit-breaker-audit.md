# 4.3 Circuit Breaker Audit

> **Audience:** analysts, contributors · **Status:** rewritten in the test review (branch `test-review`, 2026-10-23) ·
> **Source of truth:**
> [`src/tests/domain_4/test_4_3_circuit_breaker_audit.py`](../../../src/tests/domain_4/test_4_3_circuit_breaker_audit.py) ·
> **Verified:** 2026-10-23

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
rotation) is the accepted equivalent. A PASS promises the gateway has one or the other. The threat (OWASP API4:2023,
ASVS v5.0.0-16.5.2): without it, a failing dependency makes every request wait for its timeout and the thread pool
fills, cascading the failure.

## 2. Sub-tests and coverage of the methodology

| Sub-test | Methodology (guarantee 4.3) |
|---|---|
| `degradation_configured` | "the presence of circuit breaker directives, or an equivalent (passive health check)" |
| left out | the parameter thresholds check and the behavioural staging test (a coordinated downstream outage, not reproducible from outside) |

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
| no breaker, but a passive or active health check is configured | `ENFORCED/HEALTH_CHECK` (a note: a compensating control) | CERTAIN |
| neither | `VIOLATION/NO_CIRCUIT_BREAKER` | CERTAIN |
| neither concept readable | SKIP | - |

## 7. Outcomes

SKIP when neither concept can be read. FAIL when the gateway has no breaker and no health check; PASS otherwise
(with a note when the control is a health check standing in for a breaker).

## 8. Findings

"No circuit breaker or health check on the gateway", `evidence_ref` the circuit-breaker concept artifact.

## 9. Effects on the target

`READ_ONLY`: reads the gateway Admin API, sends no request to the API.

## 10. Per gateway

Kong has no circuit-breaker plugin: its passive health check (a backend marked unhealthy after N failures) is the
equivalent, reported ENFORCED with a note. APISIX exposes both a breaker (`api-breaker`) and health checks.

## 11. Configuration

None.

## 12. Validation

Runs of 2026-10-23:

| Lab | Status | Basis |
|---|---|---|
| Forgejo + Kong, crAPI + Kong | **PASS** | no breaker plugin, but a passive health check on the upstream (`HEALTH_CHECK`, with a note that it is Kong's equivalent) |
| Forgejo + APISIX | **PASS** | a breaker or a health check read from APISIX |

Rule 9: the ENFORCED side (a health check as the compensating control) is proven on the labs. The VIOLATION branch
(a gateway with neither) is not present on the labs (both configure a health check); it is the plain absence of both
concepts, and the SKIP branch covers a non-readable admin plane.

## 13. Remediation

Configure a circuit breaker (or at least a passive health check that takes a failing backend out of rotation) with a
failure threshold and an open-state timeout, so a failing dependency does not cascade (OWASP API4:2023, ASVS
v5.0.0-16.5.2).

## 14. Limitations

- Only the presence of a breaker or health check is judged, not whether its thresholds are sound (a follow-up could
  check `failure_threshold`, `open_seconds`).
- The behavioural test (a real downstream outage) is out of scope: it needs a coordinated staging action.

## 15. Sources

- OWASP API4:2023 Unrestricted Resource Consumption: https://owasp.org/API-Security/editions/2023/en/0xa4-unrestricted-resource-consumption/
- OWASP ASVS v5.0.0-16.5.2 (operate securely when external resource access fails): https://github.com/OWASP/ASVS/blob/v5.0.0/5.0/en/0x25-V16-Security-Logging-and-Error-Handling.md
- NIST SP 800-204 section 4.5.1 (circuit breaker for microservices): https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-204.pdf
- CWE-400 Uncontrolled Resource Consumption: https://cwe.mitre.org/data/definitions/400.html

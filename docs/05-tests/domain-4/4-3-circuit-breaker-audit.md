# 4.3 Circuit Breaker Audit

> **Audience:** analysts, contributors · **Source of truth:**
> [`src/tests/domain_4/test_4_3_circuit_breaker_audit.py`](../../../src/tests/domain_4/test_4_3_circuit_breaker_audit.py)

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

## 2. Test

### 2.1 Sub-tests and coverage of the methodology

| Sub-test | Methodology (guarantee 4.3) |
|---|---|
| `degradation_configured` | "the presence of circuit breaker directives, or an equivalent (passive health check)" |
| left out | the parameter thresholds check and the behavioural staging test (a coordinated downstream outage, not reproducible from outside) |

Whether an excluded backend comes back by itself (an active probe on unhealthy targets,
`HealthCheck.recovers_automatically`) is not required for the control to exist: the test reports it in the note
instead of withholding the pass.

### 2.2 Preconditions and reference responses

`Need.GATEWAY` (the Admin API). No reference responses: the concepts read are the evidence.

### 2.3 Probes

None: a configuration audit. The two concepts are read and pinned as evidence.

## 3. Oracle

<!-- [[[cog import generate_docs as g; cog.out(g.oracle_table("4.3")) ]]] -->

| Case | Outcome / detail | Confidence |
|---|---|---|
| an enabled circuit breaker | `ENFORCED/CIRCUIT_BREAKER` | - |
| no breaker, and a health check that detects a failing backend: a compensating control (the note says whether an excluded backend comes back by itself) | `ENFORCED/HEALTH_CHECK` | - |
| neither, each concept read or one the gateway does not have | `VIOLATION/NO_CIRCUIT_BREAKER` | CERTAIN |
| neither in what was read, and a concept the gateway has could not be read | `NOT_VERIFIABLE/CONCEPT_NOT_ACCESSIBLE` | - |

<!-- [[[end]]] -->

With the breakers unread, "the gateway has no breaker" is not a fact; a concept the gateway does not have at all
(`NOT_SUPPORTED`) is different, and there the absence counts. A gateway that has neither concept is SKIP (nothing to
apply). 
## 4. Validation

### 4.1 Oracle cases

<!-- [[[cog import generate_docs as g; cog.out(g.oracle_validation("4.3", page=cog.inFile)) ]]] -->

Every case of the oracle, produced on a lab and judged by the code: E1, [oracle validation](../../../experiments/README.md), campaign at commit `fc60b6f`. 4 of 4 produced cases gave the declared outcome; 0 no lab can produce.

| Case | Lab, how it is produced | Result |
|---|---|---|
| `degradation_configured/ENFORCED/CIRCUIT_BREAKER` | forgejo-apisix: a temporary APISIX route on forgejo-upstream with the api-breaker plugin (3 failures to open) | OK |
| `degradation_configured/ENFORCED/HEALTH_CHECK` | forgejo-kong: the lab as built: forgejo-upstream has a passive check (http_failures 5, timeouts 3) and active probes of unhealthy targets | OK |
| `degradation_configured/VIOLATION/NO_CIRCUIT_BREAKER/CERTAIN` | forgejo-kong: forgejo-upstream's healthchecks replaced by an empty block, so Kong fills its defaults (zero thresholds, zero intervals) and no breaker plugin exists | OK |
| `degradation_configured/NOT_VERIFIABLE/CONCEPT_NOT_ACCESSIBLE` | forgejo-kong: the run's gateway.admin.url points to a closed port: neither the breakers nor the health checks can be read | OK |

<!-- [[[end]]] -->

### 4.2 Results on the labs

<!-- [[[cog import generate_docs as g; cog.out(g.lab_results("4.3", page=cog.inFile)) ]]] -->

No E2 campaign yet ([experiments](../../../experiments/README.md)).

<!-- [[[end]]] -->

## 5. Limitations

- Only the presence of a breaker or health check is judged, never whether its thresholds are sound: a breaker that
  opens after ten thousand failures passes. Judging `failure_threshold` and `open_seconds` would need a defensible
  value for each target and is not planned.
- The behavioural test (a real downstream outage) is out of scope: it needs a coordinated staging action, so the test
  proves a control is configured, never that it fires.
- A breaker or check configured on one backend passes the test for the whole gateway: the oracle asks whether the
  gateway has the control, not whether every backend is covered by it. The note names the backends that have it, so
  the gap is visible to the reader.

## 6. Sources

- OWASP API4:2023 Unrestricted Resource Consumption: https://owasp.org/API-Security/editions/2023/en/0xa4-unrestricted-resource-consumption/
- OWASP ASVS v5.0.0-16.5.2 (operate securely when external resource access fails): https://github.com/OWASP/ASVS/blob/v5.0.0/5.0/en/0x25-V16-Security-Logging-and-Error-Handling.md
- NIST SP 800-204 section 4.5.1 (circuit breaker for microservices): https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-204.pdf
- CWE-400 Uncontrolled Resource Consumption: https://cwe.mitre.org/data/definitions/400.html

## 7. Inputs

Two gateway concepts read through the adapter: `circuit_breakers` and `health_checks` (`src/core/gateway/`). No
request is sent.

## 8. Outcomes

SKIP when the gateway has neither concept. INCONCLUSIVE when nothing was found but part of the admin plane could not
be read. FAIL when the gateway has no breaker and no health check that detects failures; PASS otherwise (with a note
when the control is a health check standing in for a breaker).

## 9. Findings

<!-- [[[cog import generate_docs as g; cog.out(g.finding_titles("4.3")) ]]] -->

- "No circuit breaker or health check on the gateway"

<!-- [[[end]]] -->

`evidence_ref` the circuit-breaker concept artifact, `supporting_refs` the health-check one.

## 10. Effects on the target

`READ_ONLY`: reads the gateway Admin API, sends no request to the API.

## 11. Per gateway

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

**On Kong a health check lives on an Upstream object, never on a Service.** A service that points straight at a
host therefore has no health check at all, and when no Upstream exists the adapter's answer is an empty list. That
empty answer is a true statement, not a read that found nothing: those backends are unprotected, and the test
reports `VIOLATION/NO_CIRCUIT_BREAKER`. The
one case where an empty answer would say nothing, a gateway that fronts no backend whatsoever, leaves every other
test of the run without a target too, so the test does not treat it apart.

## 12. Configuration

None.

## 13. Remediation

Configure a circuit breaker (or at least a passive health check that takes a failing backend out of rotation) with a
failure threshold and an open-state timeout, so a failing dependency does not cascade (OWASP API4:2023, ASVS
v5.0.0-16.5.2).

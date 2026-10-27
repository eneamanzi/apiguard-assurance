# 4.2 Timeout Configuration Audit

> **Audience:** analysts, contributors · **Status:** rewritten in the test review (2026-10-27) · **Source of truth:**
> [`src/tests/domain_4/test_4_2_timeout_config_audit.py`](../../../src/tests/domain_4/test_4_2_timeout_config_audit.py) ·
> **Verified:** 2026-10-27

<!-- [[[cog import generate_docs as g; cog.out(g.test_header("4.2", page=cog.inFile)) ]]] -->

|  |  |
|---|---|
| Test ID | `4.2` |
| Name | Timeout Configuration Audit -- Prevention of Resource Lock |
| Domain | 4 - Availability and Resilience |
| Priority / strategy | P1 / WHITE_BOX |
| Effect | READ_ONLY |
| CWE | CWE-400 |
| Standards | `OWASP API4:2023`, `NIST SP 800-204A, Section 4.3`, `OWASP ASVS v5.0.0-16.5.2` |
| Tags | `availability`, `timeout`, `resource-lock`, `white-box` |
| Prerequisites | none |
| Needs | `GATEWAY` |
| Parameters | [`tests.domain_4.test_4_2`](../../03-reference/01-configuration.md#testsdomain_4test_4_2) |

<!-- [[[end]]] -->

**Same group:** tests `4.1`, `4.3`, `4.4` (resource-consumption limits).

## 1. Guarantee

Every backend the gateway routes to has connect, read and write timeouts that are set and bounded, so that a slow
backend cannot hold the gateway's workers indefinitely. The threat (OWASP API4:2023, NIST SP 800-204A section 4.3):
without a bound, requests to a hanging dependency accumulate until the worker pool is exhausted and the gateway
stops serving everyone, including the endpoints that are healthy.

## 2. Sub-tests and coverage of the methodology

| Sub-test | Methodology (guarantee 4.2) |
|---|---|
| `connect_timeout` | the connect timeout of each backend, against the oracle threshold |
| `read_timeout` | the read timeout of each backend |
| `write_timeout` | the write timeout of each backend (the time allowed between two writes) |
| left out | the application's connection-pool timeouts and the timeouts on outbound calls in application code (no access to the application's configuration), and the behavioural test with a slow mock backend (staging only) |

## 3. Inputs

One gateway concept read through the adapter: `backend_timeouts` (`src/core/gateway/`). One item per backend (a Kong
service) or per route that overrides its backend's timeouts (APISIX). No request is sent to the API.

## 4. Preconditions and reference responses

`Need.GATEWAY` (the Admin API). No reference responses: the configuration read is the evidence.

## 5. Probes

None: a configuration audit. The concept is read and pinned as evidence.

## 6. Oracle (`connect_timeout`, `read_timeout`, `write_timeout`)

Thresholds, from the methodology (NIST SP 800-204A section 4.3): `max_connect_timeout_ms` 5,000,
`max_read_timeout_ms` 30,000, `max_write_timeout_ms` 30,000. Each item gives one judgement in each sub-test, on its
own field:

| Case | Outcome / detail | Confidence |
|---|---|---|
| the value is within its threshold | `ENFORCED/WITHIN_LIMIT` | - |
| the value is above its threshold | `VIOLATION/ABOVE_LIMIT` | CERTAIN |
| the value is `0` (no bound) | `VIOLATION/NOT_CONFIGURED` | CERTAIN |
| the gateway states no value for the field | `VIOLATION/NOT_STATED` | CERTAIN |

A timeout the gateway does not state is judged a violation because an unbounded wait is the dangerous case: the
guarantee asks for a bound, and no stated bound means none is enforced at that layer. Which of the last two branches
can occur depends on the gateway (section 10).

## 7. Outcomes

SKIP without a gateway adapter, when the gateway has no such concept, when the Admin API cannot be read, or when no
backend is registered. FAIL on any violation, one finding each. PASS otherwise, always with `coverage: complete`:
every field read is judged, so this test has no not-verifiable case.

## 8. Findings

One per field above the threshold or unbounded: "Timeout Exceeds Oracle Threshold: `<field>` = `<value>` ms on
service '`<name>`'", "Timeout Not Configured: `<field>` == 0 on service '`<name>`'", "Timeout Field Absent:
`<field>` on service '`<name>`'" (`route '<name>'` for a route). The `evidence_ref` of each is the pinned
`backend_timeouts` artifact, not an HTTP transaction.

## 9. Effects on the target

`READ_ONLY`: read-only calls to the gateway's Admin API, nothing sent to the API.

## 10. Per gateway

**Kong** always states the three timeouts: a service that omits them is served with Kong's own defaults of
60,000 ms each, which the Admin API reports as if they had been set. So `NOT_STATED` cannot occur on Kong, and
`NOT_CONFIGURED` cannot either, because Kong's schema refuses `0` (`value should be between 1 and 2147483646`). The
practical consequence is the opposite of a gap: a Kong service left at its defaults **fails** this test, since
60,000 ms is above all three thresholds.

**APISIX** states the timeouts of an upstream, or of a route that overrides them, and omits the field when it is not
configured; the adapter then reports it as absent, so `NOT_STATED` is reachable there.

## 11. Configuration

<!-- [[[cog import generate_docs as g; cog.out(g.test_params("4.2", page=cog.inFile)) ]]] -->

Section [`tests.domain_4.test_4_2`](../../03-reference/01-configuration.md#testsdomain_4test_4_2) of `config.yaml`:

| Key | Type | Default | Description |
|---|---|---|---|
| `max_connect_timeout_ms` | int ≥1 | `5000` | Maximum acceptable backend connect timeout of a gateway service, in milliseconds. Methodology oracle: connect_timeout <= 5 000 ms (NIST SP 800-204A Section 4.3). Services with a higher value will produce a FAIL finding. |
| `max_read_timeout_ms` | int ≥1 | `30000` | Maximum acceptable backend read timeout of a gateway service, in milliseconds. Methodology oracle: read_timeout <= 30 000 ms (NIST SP 800-204A Section 4.3). Services with a higher value will produce a FAIL finding. |
| `max_write_timeout_ms` | int ≥1 | `30000` | Maximum acceptable backend write (send) timeout of a gateway service, in milliseconds. Methodology oracle: write_timeout <= 30 000 ms. Services with a higher value will produce a FAIL finding. |

<!-- [[[end]]] -->

Raise one only when the target is deliberately configured with a longer timeout and the deviation is an accepted,
documented risk.

## 12. Validation

Runs of 2026-10-27, one targeted run per lab:

| Lab | Status | Basis |
|---|---|---|
| Forgejo + Kong | **PASS** complete | 6 enforced over 2 services, each at 5,000 / 30,000 / 30,000 ms |
| crAPI + Kong | **PASS** complete | 12 enforced over 4 services |
| Forgejo + APISIX | **PASS** complete | 3 enforced over 1 upstream |
| Forgejo + Kong, with the case below | **FAIL**, 1 finding | `connect_timeout` raised to 6,000 ms on `forgejo-service`: 1 violation `ABOVE_LIMIT` at CERTAIN, 5 enforced |
| Forgejo + Kong, with the timeouts removed from a service | **FAIL**, 3 findings | Kong served its 60,000 ms defaults and reported them: three `ABOVE_LIMIT` violations on `hmac-audit-dummy`, 3 enforced |
| no gateway in the configuration | **SKIP** | `Needs GATEWAY: no gateway is configured (gateway.adapter and gateway.admin.url).` |

**The case the labs lack, and how to undo it.** Every lab configures its timeouts within the thresholds. To see the
violation, raise one above its threshold in `test-environments/forgejo-kong/kong/kong.yml`, inside
`services[forgejo-service]`:

```yaml
    connect_timeout: 6000
```

Then `cd test-environments/forgejo-kong && docker compose --env-file ../../.env up -d --force-recreate --wait kong`;
undo with `git checkout` and the same command. Removing the three `*_timeout` lines from a service instead shows
Kong's defaults being judged. Setting one to `0` does **not** work: Kong refuses to load the configuration
(`in 'read_timeout': value should be between 1 and 2147483646`) and the container stays unhealthy.

**What each branch has been seen doing** (rule 9). Proven on a lab: `WITHIN_LIMIT` on all three gateways, and
`ABOVE_LIMIT` both from an explicit value and from Kong's defaults, with the SKIP branch for an absent gateway.
Still unproven: `NOT_CONFIGURED` (Kong's schema forbids `0`; it would need a gateway that accepts it) and
`NOT_STATED` (reachable only on APISIX, with an upstream that omits the timeout object).

## 13. Remediation

Set connect, read and write timeouts explicitly on every backend, within the thresholds (connect at most 5 s, read
and write at most 30 s), instead of relying on the gateway's defaults: on Kong those defaults are 60 s and leave a
failing backend holding a worker for a minute per request (OWASP API4:2023, NIST SP 800-204A section 4.3).

## 14. Limitations

- Only the gateway's own timeouts are judged. The application's connection pool and the timeouts of its outbound
  calls are not visible from the admin plane and are not checked.
- The thresholds are the methodology's, not the target's: a backend that legitimately needs longer is a finding
  until the parameter is raised and the deviation documented.
- Nothing is verified behaviourally: a slow backend is not simulated, so the test says the bound is configured, not
  that the gateway honours it.

## 15. Sources

- OWASP API4:2023 Unrestricted Resource Consumption: https://owasp.org/API-Security/editions/2023/en/0xa4-unrestricted-resource-consumption/
- NIST SP 800-204A section 4.3 (service mesh and gateway resilience): https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-204A.pdf
- OWASP ASVS v5.0.0-16.5.2 (operate securely when external resource access fails): https://github.com/OWASP/ASVS/blob/v5.0.0/5.0/en/0x25-V16-Security-Logging-and-Error-Handling.md
- CWE-400 Uncontrolled Resource Consumption: https://cwe.mitre.org/data/definitions/400.html

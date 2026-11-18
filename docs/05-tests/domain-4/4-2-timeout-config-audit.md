# 4.2 Timeout Configuration Audit

> **Audience:** analysts, contributors · **Source of truth:**
> [`src/tests/domain_4/test_4_2_timeout_config_audit.py`](../../../src/tests/domain_4/test_4_2_timeout_config_audit.py)

<!-- [[[cog import generate_docs as g; cog.out(g.test_header("4.2", page=cog.inFile)) ]]] -->

|  |  |
|---|---|
| Test ID | `4.2` |
| Name | Timeout Configuration Audit -- Prevention of Resource Lock |
| Domain | 4 - Availability and Resilience |
| Priority / strategy | P1 / WHITE_BOX |
| Effect | READ_ONLY |
| CWE | CWE-400 |
| Standards | `OWASP API4:2023`, `NIST SP 800-204A, Section 4.3`, `OWASP ASVS v5.0.0-13.2.6` |
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

A PASS promises that every timeout the gateway applies towards its backends, set in the configuration or the
gateway's own default, is within the thresholds. It promises nothing about the application's own timeouts (its
connection pool, its outbound calls), which the admin plane does not show, and nothing about whether the gateway
honours the bound: no slow backend is simulated.

## 2. Test

### 2.1 Sub-tests and coverage of the methodology

| Sub-test | Methodology (guarantee 4.2) |
|---|---|
| `connect_timeout` | the connect timeout of each backend, against the oracle threshold |
| `read_timeout` | the read timeout of each backend |
| `write_timeout` | the write timeout of each backend (the time allowed between two writes) |
| left out | the application's connection-pool timeouts and the timeouts on outbound calls in application code (no access to the application's configuration), and the behavioural test with a slow mock backend (staging only) |

### 2.2 Preconditions and reference responses

`Need.GATEWAY` (the Admin API). No reference responses: the configuration read is the evidence.

### 2.3 Probes

None: a configuration audit. The concept is read and pinned as evidence.

## 3. Oracle

Thresholds, from the methodology: `max_connect_timeout_ms` 5,000,
`max_read_timeout_ms` 30,000, `max_write_timeout_ms` 30,000. Each item gives one judgement in each sub-test, on its
own field:

<!-- [[[cog import generate_docs as g; cog.out(g.oracle_table("4.2")) ]]] -->

**`connect_timeout`**

| Case | Outcome / detail | Confidence |
|---|---|---|
| the connect_timeout of a backend or route is within its threshold | `ENFORCED/WITHIN_LIMIT` | - |
| it is set above its threshold | `VIOLATION/ABOVE_LIMIT` | CERTAIN |
| it is not set, and the gateway's default, which its adapter states, is above the threshold | `VIOLATION/ABOVE_LIMIT` | FIRM |
| it is `0`: the gateway sets no bound | `VIOLATION/UNBOUNDED` | CERTAIN |
| it is neither set nor stated as the gateway's default | `NOT_VERIFIABLE/NOT_STATED` | - |
| the gateway has the concept the test reads, and it could not be read (one rule for every test that reads one) | `NOT_VERIFIABLE/CONCEPT_NOT_ACCESSIBLE` | - |

**`read_timeout`**

| Case | Outcome / detail | Confidence |
|---|---|---|
| the read_timeout of a backend or route is within its threshold | `ENFORCED/WITHIN_LIMIT` | - |
| it is set above its threshold | `VIOLATION/ABOVE_LIMIT` | CERTAIN |
| it is not set, and the gateway's default, which its adapter states, is above the threshold | `VIOLATION/ABOVE_LIMIT` | FIRM |
| it is `0`: the gateway sets no bound | `VIOLATION/UNBOUNDED` | CERTAIN |
| it is neither set nor stated as the gateway's default | `NOT_VERIFIABLE/NOT_STATED` | - |
| the gateway has the concept the test reads, and it could not be read (one rule for every test that reads one) | `NOT_VERIFIABLE/CONCEPT_NOT_ACCESSIBLE` | - |

**`write_timeout`**

| Case | Outcome / detail | Confidence |
|---|---|---|
| the write_timeout of a backend or route is within its threshold | `ENFORCED/WITHIN_LIMIT` | - |
| it is set above its threshold | `VIOLATION/ABOVE_LIMIT` | CERTAIN |
| it is not set, and the gateway's default, which its adapter states, is above the threshold | `VIOLATION/ABOVE_LIMIT` | FIRM |
| it is `0`: the gateway sets no bound | `VIOLATION/UNBOUNDED` | CERTAIN |
| it is neither set nor stated as the gateway's default | `NOT_VERIFIABLE/NOT_STATED` | - |
| the gateway has the concept the test reads, and it could not be read (one rule for every test that reads one) | `NOT_VERIFIABLE/CONCEPT_NOT_ACCESSIBLE` | - |

<!-- [[[end]]] -->

A timeout the configuration does not set still has a value: the one the gateway applies by default. When the adapter
states it (the concept names the field in `defaulted`), it is judged like any other value. When it does not, the
value is unknown and nothing is concluded. `UNBOUNDED` is a `0` (no bound); "not configured" is an unset value,
judged at its default. Which branches can occur depends on the gateway (section 11).

## 4. Validation

### 4.1 Oracle cases

<!-- [[[cog import generate_docs as g; cog.out(g.oracle_validation("4.2", page=cog.inFile)) ]]] -->

Every case of the oracle, produced on a lab and judged by the code: E1, [oracle validation](../../../experiments/README.md), campaign at commit `fc60b6f`. 12 of 12 produced cases gave the declared outcome; 6 no lab can produce.

| Case | Lab, how it is produced | Result |
|---|---|---|
| `connect_timeout/ENFORCED/WITHIN_LIMIT` | forgejo-kong: the lab as built: forgejo-service and hmac-audit-dummy at 5,000 / 30,000 / 30,000 ms | OK |
| `connect_timeout/VIOLATION/ABOVE_LIMIT/CERTAIN` | forgejo-kong: the lab as built (connect_timeout 5,000 ms, stated by Kong as set), with the run's max_connect_timeout_ms lowered to 4,000 | OK |
| `connect_timeout/VIOLATION/ABOVE_LIMIT/FIRM` | forgejo-apisix: the timeout object removed from APISIX's forgejo-upstream: the adapter states nginx's 60 s default, named in defaulted | OK |
| `connect_timeout/VIOLATION/UNBOUNDED/CERTAIN` | not producible (gateway): Kong's schema forbids 0 ('value should be between 1 and 2147483646'), APISIX's too (exclusiveMinimum 0 on each timeout) | - |
| `connect_timeout/NOT_VERIFIABLE/NOT_STATED` | not producible (gateway): both adapters state a default: Kong reports its 60,000 ms defaults as if set, the APISIX adapter states nginx's 60 s | - |
| `connect_timeout/NOT_VERIFIABLE/CONCEPT_NOT_ACCESSIBLE` | forgejo-kong: the run's gateway.admin.url points to a closed port | OK |
| `read_timeout/ENFORCED/WITHIN_LIMIT` | forgejo-kong: the lab as built: read_timeout 30,000 ms on both services | OK |
| `read_timeout/VIOLATION/ABOVE_LIMIT/CERTAIN` | forgejo-kong: the lab as built (read_timeout 30,000 ms, stated by Kong as set), with the run's max_read_timeout_ms lowered to 20,000 | OK |
| `read_timeout/VIOLATION/ABOVE_LIMIT/FIRM` | forgejo-apisix: the timeout object removed from APISIX's forgejo-upstream: the adapter states nginx's 60 s default, named in defaulted | OK |
| `read_timeout/VIOLATION/UNBOUNDED/CERTAIN` | not producible (gateway): Kong's schema forbids 0 ('value should be between 1 and 2147483646'), APISIX's too (exclusiveMinimum 0 on each timeout) | - |
| `read_timeout/NOT_VERIFIABLE/NOT_STATED` | not producible (gateway): both adapters state a default: Kong reports its 60,000 ms defaults as if set, the APISIX adapter states nginx's 60 s | - |
| `read_timeout/NOT_VERIFIABLE/CONCEPT_NOT_ACCESSIBLE` | forgejo-kong: the run's gateway.admin.url points to a closed port | OK |
| `write_timeout/ENFORCED/WITHIN_LIMIT` | forgejo-kong: the lab as built: write_timeout 30,000 ms on both services | OK |
| `write_timeout/VIOLATION/ABOVE_LIMIT/CERTAIN` | forgejo-kong: the lab as built (write_timeout 30,000 ms, stated by Kong as set), with the run's max_write_timeout_ms lowered to 20,000 | OK |
| `write_timeout/VIOLATION/ABOVE_LIMIT/FIRM` | forgejo-apisix: the timeout object removed from APISIX's forgejo-upstream: the adapter states nginx's 60 s default, named in defaulted | OK |
| `write_timeout/VIOLATION/UNBOUNDED/CERTAIN` | not producible (gateway): Kong's schema forbids 0 ('value should be between 1 and 2147483646'), APISIX's too (exclusiveMinimum 0 on each timeout) | - |
| `write_timeout/NOT_VERIFIABLE/NOT_STATED` | not producible (gateway): both adapters state a default: Kong reports its 60,000 ms defaults as if set, the APISIX adapter states nginx's 60 s | - |
| `write_timeout/NOT_VERIFIABLE/CONCEPT_NOT_ACCESSIBLE` | forgejo-kong: the run's gateway.admin.url points to a closed port | OK |

<!-- [[[end]]] -->

### 4.2 Results on the labs

<!-- [[[cog import generate_docs as g; cog.out(g.lab_results("4.2", page=cog.inFile)) ]]] -->

No E2 campaign yet ([experiments](../../../experiments/README.md)).

<!-- [[[end]]] -->

## 5. Limitations

- Only the gateway's own timeouts are judged. The application's connection pool and the timeouts of its outbound
  calls are not visible from the admin plane and are not checked.
- The thresholds are the methodology's, not the target's: a backend that legitimately needs longer is a finding
  until the parameter is raised and the deviation documented.
- Nothing is verified behaviourally: a slow backend is not simulated, so the test says the bound is configured, not
  that the gateway honours it.
- Every backend the gateway states is judged, also one that no route reaches: its timeouts hold no worker until a
  route uses it, and its finding is about the configuration only.

## 6. Sources

- OWASP API4:2023 Unrestricted Resource Consumption: https://owasp.org/API-Security/editions/2023/en/0xa4-unrestricted-resource-consumption/
- NIST SP 800-204A section 4.3 (recommendation SM-DR9: retries, timeouts, circuit breakers configured for access to external resources; no numeric value anywhere in the document): https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-204A.pdf
- OWASP ASVS v5.0.0-13.2.6 (connections to separate services follow their documented configuration, connection timeouts among it; Level 3): https://github.com/OWASP/ASVS/blob/v5.0.0/5.0/en/0x22-V13-Configuration.md. - CWE-400 Uncontrolled Resource Consumption: https://cwe.mitre.org/data/definitions/400.html

## 7. Inputs

One gateway concept read through the adapter: `backend_timeouts` (`src/core/gateway/`). One item per backend (a Kong
service) or per route that overrides its backend's timeouts (APISIX). No request is sent to the API.

## 8. Outcomes

SKIP without a gateway adapter, when the gateway has no such concept, or when no backend is registered.
INCONCLUSIVE when the Admin API cannot be read: `CONCEPT_NOT_ACCESSIBLE` on every sub-test. FAIL on any violation, one finding each. PASS otherwise, always with `coverage:
complete`: every field read is judged, so a run that read the timeouts has no not-verifiable case.

## 9. Findings

<!-- [[[cog import generate_docs as g; cog.out(g.finding_titles("4.2")) ]]] -->

- "No timeout: <label> unbounded on <subject>"
- "Timeout Exceeds Oracle Threshold: <label> = <value_ms> ms on <subject>"

<!-- [[[end]]] -->

One per field above the threshold or unbounded; `<subject>` is "service '<name>'" (a backend) or "route '<name>'".
The `evidence_ref` of each is the pinned `backend_timeouts` artifact, not an HTTP transaction. 
## 10. Effects on the target

`READ_ONLY`: read-only calls to the gateway's Admin API, nothing sent to the API.

## 11. Per gateway

**Kong** always states the three timeouts: a service that omits them is served with Kong's own defaults of
60,000 ms each, which the Admin API reports as if they had been set. So `NOT_STATED` cannot occur on Kong, and
`UNBOUNDED` cannot either, because Kong's schema refuses `0` (`value should be between 1 and 2147483646`). The
practical consequence is the opposite of a gap: a Kong service left at its defaults **fails** this test, since
60,000 ms is above all three thresholds.

**APISIX** states the timeouts of an upstream, or of a route that overrides them, and omits the field when it is not
configured. APISIX then sets no timeout at all (`apisix/balancer.lua` sets them only from a route's or an upstream's
`timeout`, read in the lab's container), so nginx's own proxy timeouts apply, at their default of 60 s
(nginx.org, `proxy_connect_timeout`, `proxy_send_timeout`, `proxy_read_timeout`). The adapter states that default
and names the field in `defaulted`: an unset APISIX timeout is an `ABOVE_LIMIT` violation at FIRM. `NOT_STATED`
cannot occur on either supported gateway; it is there for an adapter that does not know its gateway's default.

## 12. Configuration

<!-- [[[cog import generate_docs as g; cog.out(g.test_params("4.2", page=cog.inFile)) ]]] -->

Section [`tests.domain_4.test_4_2`](../../03-reference/01-configuration.md#testsdomain_4test_4_2) of `config.yaml`:

| Key | Type | Default | Description |
|---|---|---|---|
| `max_connect_timeout_ms` | int ≥1 | `5000` | Maximum acceptable backend connect timeout of a gateway service, in milliseconds. Methodology oracle: connect_timeout <= 5 000 ms (no standard sets a value). Services with a higher value will produce a FAIL finding. |
| `max_read_timeout_ms` | int ≥1 | `30000` | Maximum acceptable backend read timeout of a gateway service, in milliseconds. Methodology oracle: read_timeout <= 30 000 ms (no standard sets a value). Services with a higher value will produce a FAIL finding. |
| `max_write_timeout_ms` | int ≥1 | `30000` | Maximum acceptable backend write (send) timeout of a gateway service, in milliseconds. Methodology oracle: write_timeout <= 30 000 ms. Services with a higher value will produce a FAIL finding. |

<!-- [[[end]]] -->

Raise one only when the target is deliberately configured with a longer timeout and the deviation is an accepted,
documented risk.

## 13. Remediation

Set connect, read and write timeouts explicitly on every backend, within the thresholds (connect at most 5 s, read
and write at most 30 s), instead of relying on the gateway's defaults: on Kong those defaults are 60 s and leave a
failing backend holding a worker for a minute per request (OWASP API4:2023, NIST SP 800-204A section 4.3).

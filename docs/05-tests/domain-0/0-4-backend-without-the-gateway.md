# 0.4 Backend Reachable Without the Gateway

> **Audience:** analysts, contributors · **Source of truth:**
> [`src/tests/domain_0/test_0_4_backend_without_the_gateway.py`](../../../src/tests/domain_0/test_0_4_backend_without_the_gateway.py)

<!-- [[[cog import generate_docs as g; cog.out(g.test_header("0.4", page=cog.inFile)) ]]] -->

|  |  |
|---|---|
| Test ID | `0.4` |
| Name | Backend Reachable Without the Gateway |
| Domain | 0 - API Discovery and Inventory Management |
| Priority / strategy | P0 / WHITE_BOX |
| Effect | READ_ONLY |
| CWE | CWE-420 |
| Standards | `OWASP API8:2023`, `NIST SP 800-228, Section 4.1` |
| Tags | `inventory`, `gateway-routing` |
| Prerequisites | none |
| Needs | `GATEWAY` |
| Parameters | none |

<!-- [[[end]]] -->

**Same group:** tests `0.2` and `0.3`. New guarantee, not in the methodology's catalogue.

## 1. Guarantee

A backend the gateway routes to answers only through the gateway. A backend that answers directly is reachable
without any of the gateway's policies, so every guarantee the other tests verify through the gateway can be
skipped. NIST SP 800-228 section 4.1 says it of the centralized pattern: a gateway at the perimeter "can be
bypassed (e.g., via an attacker pivoting inside the perimeter), which in turn bypasses the policy checks that are
enforced by that gateway. This can be mitigated with techniques like service-to-service access policies that ensure
that applications only receive traffic via the centralized gateway".

A PASS promises only what the vantage point allows: from the network this run started on, the backend addresses the
gateway declares refused the connection. A refusal at the derived address alone (the target's host with the
backend's port) is not enough for a PASS. It promises nothing about another network, and nothing about what a backend would
answer once reached.

## 2. Test

### 2.1 Sub-tests and coverage of the methodology

| Sub-test | Methodology |
|---|---|
| `backend_addresses` | new guarantee (0.4): each backend address the gateway declares is tried directly, and so is the target's own host with that backend's port |

### 2.2 Preconditions and reference responses

The same request through the gateway is the reference: an address answering with the same shape is serving the same
application. No calibration: the question is reachability, not existence.

**The name is resolved before the request** (`socket.getaddrinfo`), because a transport error cannot tell a refused
connection from a name that does not exist, and that difference is the whole difference between "the backend
refuses us" and "we are not there to ask".

### 2.3 Probes

1. one `GET` of the probe path through the gateway. The probe path is chosen by a stated rule: the shortest
   documented path with no parameters that the specification declares for `GET`, the alphabetically first among
   equals, so that two runs on one target ask the same path;
2. for each backend, the candidate addresses:
   - **the address the gateway declares** (Kong gives the name and port the operator configured, `forgejo:3000`;
     APISIX's Control API gives the node already resolved, `172.21.0.4:3000`),
   - **the addresses the gateway states it resolved that name to**, declared as well,
   - **the target's own host with that backend's port** (`localhost:8443` and `forgejo:3000` give
     `localhost:3000`): the common case of a backend whose port is published on the same machine as the gateway;
3. each candidate is asked the probe path with no credential, over `http` and, if that attempt fails on TLS or on
   the protocol, over `https`. The target's own address and port is never a candidate: that is the gateway.

## 3. Oracle

<!-- [[[cog import generate_docs as g; cog.out(g.oracle_table("0.4")) ]]] -->

| Case | Outcome / detail | Confidence |
|---|---|---|
| an address answers with the status, media type and body shape the gateway gives for the path | `VIOLATION/BACKEND_ANSWERS_DIRECTLY` | CERTAIN |
| an address the gateway declares answers unlike the gateway, or opens a connection whose answer cannot be read | `VIOLATION/ADDRESS_ANSWERS_DIRECTLY` | FIRM |
| a declared address refuses or times out, or the derived one does after the declared one did | `ENFORCED/BACKEND_UNREACHABLE` | - |
| the derived address (the target's host, the backend's port) refuses, but no declared address of that backend refused | `NOT_VERIFIABLE/DERIVED_REFUSAL_ONLY` | - |
| the derived address answers unlike the gateway: another service | `NOT_APPLICABLE/ANOTHER_SERVICE` | - |
| the derived address answers, and the gateway itself refused the probe (`401`, `403`): the two cannot be compared | `NOT_VERIFIABLE/GATEWAY_REFUSED_PROBE` | - |
| a declared address is a loopback or link-local one: it means the gateway's own host, not reachable from here | `NOT_VERIFIABLE/GATEWAY_LOCAL_ADDRESS` | - |
| the candidate's name does not resolve where the run started | `NOT_VERIFIABLE/ADDRESS_NOT_RESOLVABLE` | - |
| a declared address has no port | `NOT_VERIFIABLE/ADDRESS_WITHOUT_PORT` | - |
| the gateway states no backend address | `NOT_VERIFIABLE/NO_BACKEND_ADDRESS` | - |
| the specification declares no `GET` path without parameters | `NOT_VERIFIABLE/NO_PROBE_PATH` | - |
| the gateway's adapter does not read its backends' targets | `NOT_APPLICABLE/ADDRESSES_NOT_SUPPORTED` | - |
| the gateway has its backends' targets, and they could not be read | `NOT_VERIFIABLE/CONCEPT_NOT_ACCESSIBLE` | - |

<!-- [[[end]]] -->

<!-- [[[cog import generate_docs as g; cog.out(g.uninformative_answers("0.4", page=cog.inFile)) ]]] -->

The answers that say nothing about the guarantee by themselves, one rule for every test ([assessment model](../../04-architecture/03-assessment-model.md#answers-that-say-nothing-about-the-guarantee)), generated from the code:

| Answer | Sub-tests | Outcome / detail |
|---|---|---|
| `UPSTREAM_UNAVAILABLE` | every sub-test | `NOT_VERIFIABLE/UPSTREAM_UNAVAILABLE` |
| `RATE_LIMITED` | every sub-test | `NOT_VERIFIABLE/RATE_LIMITED` |
| `SERVER_ERROR` | every sub-test | judged by the oracle above: a `500` through the gateway is the backend's own answer: a direct answer is matched against it like any other. |
| `NO_RESPONSE` | every sub-test | `NOT_VERIFIABLE/NO_RESPONSE` |

<!-- [[[end]]] -->

## 4. Validation

### 4.1 Oracle cases

<!-- [[[cog import generate_docs as g; cog.out(g.oracle_validation("0.4", page=cog.inFile)) ]]] -->

Every case of the oracle, produced on a lab and judged by the code: E1, [oracle validation](../../../experiments/README.md), campaign at commit `fc60b6f`. 15 of 15 produced cases gave the declared outcome; 1 no lab can produce.

| Case | Lab, how it is produced | Result |
|---|---|---|
| `backend_addresses/VIOLATION/BACKEND_ANSWERS_DIRECTLY/CERTAIN` | forgejo-kong: the lab as built: Kong declares forgejo:3000, states it resolved it to an IP of the lab network, and that IP answers the probe path GET /api/v1/orgs 200 with the shape Kong gives | OK |
| `backend_addresses/VIOLATION/ADDRESS_ANSWERS_DIRECTLY/FIRM` | crapi-kong: the lab as built: at the addresses Kong resolved crapi-identity:8080 and crapi-community:8087 to, the services answer the workshop probe path with their own 401/404, unlike the gateway | OK |
| `backend_addresses/ENFORCED/BACKEND_UNREACHABLE` | forgejo-kong: a temporary Kong upstream whose only target is 192.0.2.1:3999 (TEST-NET-1, nothing answers): the declared address refuses or times out, then the derived localhost:3999 refuses after it | OK |
| `backend_addresses/NOT_VERIFIABLE/DERIVED_REFUSAL_ONLY` | forgejo-kong: the lab as built: the derived localhost:3000 refuses, while the declared forgejo:3000 does not resolve and its resolved IP answers | OK |
| `backend_addresses/NOT_APPLICABLE/ANOTHER_SERVICE` | crapi-kong: the lab as built, with forgejo-kong running too: the derived localhost:8000 (the workshop's port) answers with forgejo-kong's HTTP proxy, not like crAPI's gateway | OK |
| `backend_addresses/NOT_VERIFIABLE/GATEWAY_REFUSED_PROBE` | crapi-kong: key-auth (no consumer) on crAPI's workshop-service, so the gateway answers the probe path /workshop/api/mechanic/receive_report 401, while the derived localhost:8000 (forgejo-kong's HTTP proxy, running) answers | OK |
| `backend_addresses/NOT_VERIFIABLE/GATEWAY_LOCAL_ADDRESS` | forgejo-kong: a temporary Kong upstream whose only target is 127.0.0.1:3999: a loopback declared address | OK |
| `backend_addresses/NOT_VERIFIABLE/ADDRESS_NOT_RESOLVABLE` | forgejo-kong: the lab as built: Kong declares forgejo:3000, a name that does not resolve from the run host | OK |
| `backend_addresses/NOT_VERIFIABLE/ADDRESS_WITHOUT_PORT` | forgejo-apisix: a temporary APISIX upstream, without health checks, whose only node is written {host: forgejo, weight: 1} with no port: the adapter reads it from the Admin API as 'forgejo' | OK |
| `backend_addresses/NOT_VERIFIABLE/NO_BACKEND_ADDRESS` | forgejo-kong: forgejo-upstream emptied of its target, and a temporary route on the probe path GET ~/api/v1/orgs$ answering 200 itself; the specification read from a local copy: Kong states no backend address and still answers the probe | OK |
| `backend_addresses/NOT_VERIFIABLE/NO_PROBE_PATH` | forgejo-kong: the run reads a local copy of Forgejo's specification with every GET path without parameters removed | OK |
| `backend_addresses/NOT_APPLICABLE/ADDRESSES_NOT_SUPPORTED` | not producible (code): both supported adapters read the backends' targets (KongGatewayAdapter and ApisixGatewayAdapter override _read_target_health); only an adapter without it reaches this guard | - |
| `backend_addresses/NOT_VERIFIABLE/CONCEPT_NOT_ACCESSIBLE` | forgejo-kong: the run's gateway.admin.url points to a closed port | OK |
| `*/NOT_VERIFIABLE/UPSTREAM_UNAVAILABLE` | forgejo-kong: a temporary Kong route on the probe path GET ~/api/v1/orgs$ answers 503 itself | OK |
| `*/NOT_VERIFIABLE/RATE_LIMITED` | forgejo-kong: a temporary Kong route on the probe path GET ~/api/v1/orgs$ answers 429 itself | OK |
| `*/NOT_VERIFIABLE/NO_RESPONSE` | forgejo-kong: a temporary Kong route on the probe path GET ~/api/v1/orgs$ sleeps 7 s before proxying, and the run's read timeout is 5 s | OK |

<!-- [[[end]]] -->

### 4.2 Results on the labs

<!-- [[[cog import generate_docs as g; cog.out(g.lab_results("0.4", page=cog.inFile)) ]]] -->

No E2 campaign yet ([experiments](../../../experiments/README.md)).

<!-- [[[end]]] -->

## 5. Limitations

- The verdict holds for the network the run started on, and the message says so. A backend unreachable from here may
  be reachable from inside the infrastructure.
- The declared and resolved addresses and one derived address are tried per backend; a backend published on another
  host or another port is not found.
- A hostname is tried as the gateway states it (`forgejo:3000`) and at the addresses the gateway states it resolved
  it to, when the gateway gives them (Kong does); a gateway that gives only a name that does not resolve where the
  tool runs leaves that backend `NOT_VERIFIABLE/ADDRESS_NOT_RESOLVABLE`.
- At a port of the target's host another service may be listening: such an answer is reported as another service,
  not as the backend.
- A timeout counts as unreachable (`ENFORCED/BACKEND_UNREACHABLE`), because the transport vocabulary has a single
  `timeout` and does not say whether the connection was ever accepted. A backend that accepts the connection and
  then never answers therefore reads as unreachable rather than as listening.
- A gateway that rewrites the path before forwarding (stripping a prefix) makes the direct answer differ from the
  gateway's, so the finding is FIRM instead of CERTAIN.
- Whether the backend **authenticates** its callers once reached is a different guarantee, which no test covers
  today (ASVS v5.0.0-13.2.1 asks for it; NIST SP 800-228 section 4.1 calls it attaching proofs to the request).

## 6. Sources

- OWASP API8:2023 Security Misconfiguration: https://owasp.org/API-Security/editions/2023/en/0xa8-security-misconfiguration/
- NIST SP 800-228 section 4.1: https://doi.org/10.6028/NIST.SP.800-228
- CWE-420 Unprotected Alternate Channel: https://cwe.mitre.org/data/definitions/420.html
- OWASP ASVS v5.0.0-13.2.1, cited in the limitations only: https://github.com/OWASP/ASVS/blob/v5.0.0/5.0/en/0x22-V13-Configuration.md

## 7. Inputs

- the backend addresses the gateway declares (`target_health()`: the backend's name and its target address), through
  the need `GATEWAY`;
- the target's own host, from the base URL, combined with each backend's port: the second candidate, derived from
  what the gateway says rather than configured (rule 5);
- one documented path, asked at every address and through the gateway, for comparison.

## 8. Outcomes

SKIP when no gateway is configured (the need `GATEWAY`): without the backend addresses there is nothing to ask.

## 9. Findings

<!-- [[[cog import generate_docs as g; cog.out(g.finding_titles("0.4")) ]]] -->

- "Backend answers without the gateway: <address>"

<!-- [[[end]]] -->

`evidence_ref` the direct answer; the finding names the address and whether it is declared or derived.

## 10. Effects on the target

`READ_ONLY`: one request through the gateway and at most two per backend address. The requests go to the target's
own infrastructure and create nothing.

## 11. Per gateway

The two adapters give addresses of different kinds and the test treats both the same way: Kong gives the name and
port the operator configured, APISIX's Control API gives the node already resolved. A gateway whose concept of a
backend address cannot be read gives `ADDRESSES_NOT_READABLE`.

## 12. Configuration

None. A parameter holding addresses the operator knows was considered and dropped: the second
candidate is derived from what the gateway already says, and rule 5 asks to derive first. If a deployment publishes
its backend somewhere neither candidate reaches, the parameter is added then.

## 13. Remediation

Let the backend accept traffic only from the gateway (a network policy, a firewall rule, a service-level
authorization rule), and have the backend authenticate the gateway rather than trust its position.

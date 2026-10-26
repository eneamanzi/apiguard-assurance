# 0.4 Backend Reachable Without the Gateway

> **Audience:** analysts, contributors · **Status:** new in the test review (2026-10-22) ·
> **Source of truth:**
> [`src/tests/domain_0/test_0_4_backend_without_the_gateway.py`](../../../src/tests/domain_0/test_0_4_backend_without_the_gateway.py) ·
> **Verified:** 2026-10-22

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
gateway declares did not answer. It promises nothing about another network, and nothing about what a backend would
answer once reached.

## 2. Sub-tests and coverage of the methodology

| Sub-test | Methodology |
|---|---|
| `backend_addresses` | new guarantee (0.4): each backend address the gateway declares is tried directly, and so is the target's own host with that backend's port |

## 3. Inputs

- the backend addresses the gateway declares (`target_health()`: the backend's name and its target address), through
  the need `GATEWAY`;
- the target's own host, from the base URL, combined with each backend's port: the second candidate, derived from
  what the gateway says rather than configured (rule 5);
- one documented path, asked at every address and through the gateway, for comparison.

## 4. Preconditions and reference responses

The same request through the gateway is the reference: an address answering with the same shape is serving the same
application. No calibration: the question is reachability, not existence.

**The name is resolved before the request** (`socket.getaddrinfo`), because a transport error cannot tell a refused
connection from a name that does not exist, and that difference is the whole difference between "the backend
refuses us" and "we are not there to ask".

## 5. Probes

1. one `GET` of the probe path through the gateway. The probe path is chosen by a stated rule: the shortest
   documented path with no parameters that the specification declares for `GET`, the alphabetically first among
   equals, so that two runs on one target ask the same path;
2. for each backend, two candidate addresses:
   - **the address the gateway declares** (Kong gives the name and port the operator configured, `forgejo:3000`;
     APISIX's Control API gives the node already resolved, `172.21.0.4:3000`),
   - **the target's own host with that backend's port** (`localhost:8443` and `forgejo:3000` give
     `localhost:3000`): the common case of a backend whose port is published on the same machine as the gateway;
3. each candidate is asked the probe path with no credential, over `http` and, if that attempt fails on TLS or on
   the protocol, over `https`. The target's own address and port is never a candidate: that is the gateway.

## 6. Oracle

The two kinds of candidate are judged differently, and the reason is a measurement of 2026-10-22: with the three
labs running, `localhost:8000` (the host, and the port of crAPI's workshop backend) answers, but what answers is the
other lab's gateway, not that backend.

| Case | Candidate | Outcome / detail | Confidence |
|---|---|---|---|
| answers, with the shape the gateway gives for the same path | either | `VIOLATION/BACKEND_ANSWERS_DIRECTLY` | CERTAIN: the same application answered without the gateway |
| answers something else over HTTP, or opens a connection whose answer cannot be read | the declared address | `VIOLATION/ADDRESS_ANSWERS_DIRECTLY` | FIRM: something is listening where the gateway says the backend is |
| the same | the derived host and port | `NOT_APPLICABLE/ANOTHER_SERVICE` | - |
| resolves, connection refused or timed out | either | `ENFORCED/BACKEND_UNREACHABLE` | - |
| the name does not resolve | either | `NOT_VERIFIABLE/ADDRESS_NOT_RESOLVABLE`: the tool is not on that network, which proves nothing | - |
| the address has no port | either | `NOT_VERIFIABLE/ADDRESS_WITHOUT_PORT` | - |
| the gateway gives no address | - | `NOT_VERIFIABLE/NO_BACKEND_ADDRESS`, `ADDRESSES_NOT_READABLE`; `NOT_APPLICABLE/ADDRESSES_NOT_READABLE` when the gateway has no such concept | - |
| the specification declares no path without parameters for `GET` | - | `NOT_VERIFIABLE/NO_PROBE_PATH` | - |
| the target itself did not answer the probe path | - | `NOT_VERIFIABLE/TARGET_NOT_ANSWERING` | - |

The comparison of two answers uses the status, the media type and the shape of the body. The `Server` header is left
out on purpose: a gateway sets or removes it, so the same application answers with a different one through the
gateway and without it.

## 7. Outcomes

SKIP when no gateway is configured (the need `GATEWAY`): without the backend addresses there is nothing to ask.

## 8. Findings

One per address: "Backend answers without the gateway: `<address>`", with the backend's name as the gateway calls
it, which of the two candidates it was, the status and how the answer compares with the gateway's;
`evidence_ref` the direct request, and the request through the gateway in the transaction log.

## 9. Effects on the target

`READ_ONLY`: one request through the gateway and at most two per backend address. The requests go to the target's
own infrastructure and create nothing.

## 10. Per gateway

The two adapters give addresses of different kinds and the test treats both the same way: Kong gives the name and
port the operator configured, APISIX's Control API gives the node already resolved. A gateway whose concept of a
backend address cannot be read gives `ADDRESSES_NOT_READABLE`.

## 11. Configuration

None. A parameter holding addresses the operator knows was considered and dropped (owner, 2026-10-22): the second
candidate is derived from what the gateway already says, and rule 5 asks to derive first. If a deployment publishes
its backend somewhere neither candidate reaches, the parameter is added then.

## 12. Validation

Runs of 2026-10-22, the three tests of the group together:

| Lab | Status | Basis |
|---|---|---|
| Forgejo + APISIX | FAIL, 1 finding, CERTAIN | the Control API declares the node `172.21.0.4:3000`, which answers the probe path `200` with the same shape APISIX gives for it: the same Forgejo, without the gateway. The derived `localhost:3000` refuses the connection |
| Forgejo + Kong | PASS partial: 1 enforced, 1 not verifiable | Kong declares `forgejo:3000`, a name that does not resolve from the host (nothing proven); the derived `localhost:3000` resolves and refuses the connection |
| crAPI + Kong | PASS partial: 2 enforced, 3 not verifiable, 1 not applicable | the three service names do not resolve; the derived `localhost:8080` and `localhost:8087` refuse; `localhost:8000` answers, but with the other lab's gateway, so it is counted `ANOTHER_SERVICE` and not as a finding |
| any | VIOLATION at FIRM | an HTTP answer at the declared address that is not the application: not on the labs |

The same measurement from inside the lab network answers `200` on `http://forgejo:3000`, so the isolation is a
property of the network the request starts from, which is why the verdict names its vantage point.

**What each branch has been seen doing** (rule 9). Proven on a lab: `BACKEND_ANSWERS_DIRECTLY`,
`BACKEND_UNREACHABLE`, `ADDRESS_NOT_RESOLVABLE`, `ANOTHER_SERVICE`. Still unproven:
`ADDRESS_ANSWERS_DIRECTLY`, `ADDRESS_WITHOUT_PORT`, `NO_BACKEND_ADDRESS`, `ADDRESSES_NOT_READABLE`,
`NO_PROBE_PATH`, `TARGET_NOT_ANSWERING`.

## 13. Remediation

Let the backend accept traffic only from the gateway (a network policy, a firewall rule, a service-level
authorization rule), and have the backend authenticate the gateway rather than trust its position.

## 14. Limitations

- The verdict holds for the network the run started on, and the message says so. A backend unreachable from here may
  be reachable from inside the infrastructure.
- Two candidates per backend are tried; a backend published on another host or another port is not found.
- At a port of the target's host another service may be listening: such an answer is reported as another service,
  not as the backend.
- A gateway that rewrites the path before forwarding (stripping a prefix) makes the direct answer differ from the
  gateway's, so the finding is FIRM instead of CERTAIN.
- Whether the backend **authenticates** its callers once reached is a different guarantee, which no test covers
  today (ASVS v5.0.0-13.2.1 asks for it; NIST SP 800-228 section 4.1 calls it attaching proofs to the request).

## 15. Sources

- OWASP API8:2023 Security Misconfiguration: https://owasp.org/API-Security/editions/2023/en/0xa8-security-misconfiguration/
- NIST SP 800-228 section 4.1: https://doi.org/10.6028/NIST.SP.800-228
- CWE-420 Unprotected Alternate Channel: https://cwe.mitre.org/data/definitions/420.html
- OWASP ASVS v5.0.0-13.2.1, cited in the limitations only: https://github.com/OWASP/ASVS/blob/v5.0.0/5.0/en/0x22-V13-Configuration.md

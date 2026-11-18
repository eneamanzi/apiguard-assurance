# 0.4 Backend Reachable Without the Gateway

> **Audience:** analysts, contributors · **Status:** new in the test review (2026-10-22) ·
> **Source of truth:**
> [`src/tests/domain_0/test_0_4_backend_without_the_gateway.py`](../../../src/tests/domain_0/test_0_4_backend_without_the_gateway.py) ·
> **Verified:** 2026-11-16

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
2. for each backend, the candidate addresses:
   - **the address the gateway declares** (Kong gives the name and port the operator configured, `forgejo:3000`;
     APISIX's Control API gives the node already resolved, `172.21.0.4:3000`),
   - **the addresses the gateway states it resolved that name to**, declared as well (Kong's health endpoint gives
     them apart from the name, `172.22.0.3:3000`; tried since 2026-11-04, owner decision:
     before, a name that does not resolve where the tool runs ended the attempt),
   - **the target's own host with that backend's port** (`localhost:8443` and `forgejo:3000` give
     `localhost:3000`): the common case of a backend whose port is published on the same machine as the gateway;
3. each candidate is asked the probe path with no credential, over `http` and, if that attempt fails on TLS or on
   the protocol, over `https`. The target's own address and port is never a candidate: that is the gateway.

## 6. Oracle

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

Until 2026-11-16: the backends' addresses came from the live health only, so a Kong Service pointing straight at a host (the common setup) and an APISIX upstream without health checks were never tried (the adapters now report them, `UNKNOWN`); a declared loopback address (`127.0.0.1:8080`, a sidecar) was asked on the tool's own machine, a false PASS or FAIL (now `GATEWAY_LOCAL_ADDRESS`); the derived address answering while the gateway refused the probe with its own authentication was `ANOTHER_SERVICE`, the main bypass missed (now `GATEWAY_REFUSED_PROBE`, and the probe path is a public GET when there is one); an unreadable concept was `ADDRESSES_NOT_READABLE` for both cases (now `NOT_APPLICABLE/ADDRESSES_NOT_SUPPORTED`, or the shared `CONCEPT_NOT_ACCESSIBLE`).

<!-- [[[cog import generate_docs as g; cog.out(g.uninformative_answers("0.4", page=cog.inFile)) ]]] -->

The answers that say nothing about the guarantee by themselves, one rule for every test ([assessment model](../../04-architecture/03-assessment-model.md#answers-that-say-nothing-about-the-guarantee)), generated from the code:

| Answer | Sub-tests | Outcome / detail |
|---|---|---|
| `UPSTREAM_UNAVAILABLE` | every sub-test | `NOT_VERIFIABLE/UPSTREAM_UNAVAILABLE` |
| `RATE_LIMITED` | every sub-test | `NOT_VERIFIABLE/RATE_LIMITED` |
| `SERVER_ERROR` | every sub-test | judged by the oracle above: a `500` through the gateway is the backend's own answer: a direct answer is matched against it like any other. |
| `NO_RESPONSE` | every sub-test | `NOT_VERIFIABLE/NO_RESPONSE` |

<!-- [[[end]]] -->

## 7. Outcomes

SKIP when no gateway is configured (the need `GATEWAY`): without the backend addresses there is nothing to ask.

## 8. Findings

<!-- [[[cog import generate_docs as g; cog.out(g.finding_titles("0.4")) ]]] -->

- "Backend answers without the gateway: <address>"

<!-- [[[end]]] -->

`evidence_ref` the direct answer; the finding names the address and whether it is declared or derived.

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

**2026-11-16, after the review** (0.1 to 0.4 on the three labs as configured): **FAIL** on the three labs. crAPI now has three findings: the workshop backend CERTAIN, as before, and the identity (`:8080`) and community (`:8087`) backends FIRM, declared addresses answering directly.


Runs of 2026-10-22, the three tests of the group together; measured again on 2026-11-04 (0.4 alone), after the
correction of that day:

| Lab | Status | Basis |
|---|---|---|
| Forgejo + APISIX | FAIL, 1 finding, CERTAIN | the Control API declares the node `172.21.0.4:3000`, which answers the probe path `200` with the same shape APISIX gives for it: the same Forgejo, without the gateway. The derived `localhost:3000` refuses the connection, `DERIVED_REFUSAL_ONLY` |
| Forgejo + Kong | FAIL, 1 finding, CERTAIN | Kong declares `forgejo:3000`, a name that does not resolve from the host, and states it resolved it to `172.22.0.3:3000`, which answers the probe path `200` with the shape Kong gives: the same Forgejo, without the gateway. The derived `localhost:3000` refuses, `DERIVED_REFUSAL_ONLY`. A PASS until 2026-11-04 on that refusal alone |
| crAPI + Kong | FAIL, 3 findings | the three service names do not resolve; at the addresses Kong resolved them to, the workshop (`172.23.0.8:8000`) answers like the gateway (CERTAIN), identity (`172.23.0.6:8080`) and community (`172.23.0.7:8087`) answer the workshop's path with their own `401`/`404` (FIRM: something listens where the gateway says the backend is). The derived `localhost:8080` and `localhost:8087` refuse, `DERIVED_REFUSAL_ONLY`; `localhost:8000` answers with the other lab's gateway, `ANOTHER_SERVICE`. A PASS until 2026-11-04 |
| any | VIOLATION at FIRM | an HTTP answer at the declared address that is not the application: not on the labs |

The same measurement from inside the lab network answers `200` on `http://forgejo:3000`, so the isolation is a
property of the network the request starts from, which is why the verdict names its vantage point.

**Runs of the branch inventory (2026-11-14).**
- crAPI + Kong, reset: **FAIL**, 3 findings, as in the table: `BACKEND_ANSWERS_DIRECTLY` (the workshop, CERTAIN)
  and **`ADDRESS_ANSWERS_DIRECTLY` twice** (identity and community, FIRM). The row "any" above was wrong to say that
  this case is not on the labs.
- Forgejo + Kong with a temporary upstream whose only target is `127.0.0.1:3999`, where nothing listens (added to
  `kong.yml`, undone with `git checkout`): `BACKEND_UNREACHABLE` twice, the declared address and then the derived
  `localhost:3999`.
- Forgejo + Kong with the `forgejo` container stopped (the specification read from a file): the gateway answered
  the probe path `503`, and the test took the refused connection of the stopped backend for an isolated one
  (**PASS**). Since 2026-11-15 the test stops there: **INCONCLUSIVE**, `UPSTREAM_UNAVAILABLE`, no address tried
  (measured 2026-11-15, the same way; the three labs, running, give the results of the table above).

**What each branch has been seen doing** (rule 9). Proven on a lab: `BACKEND_ANSWERS_DIRECTLY`,
`ADDRESS_ANSWERS_DIRECTLY`, `ADDRESS_NOT_RESOLVABLE`, `ANOTHER_SERVICE`, `DERIVED_REFUSAL_ONLY`,
`BACKEND_UNREACHABLE`, `UPSTREAM_UNAVAILABLE`, and on 2026-11-15 with the run's configuration only (Forgejo + Kong)
`ADDRESSES_NOT_READABLE` (`gateway.admin.url` on a closed port) and `NO_PROBE_PATH` (the specification saved with
its `GET` paths without parameters removed), and two more on 2026-11-15: `TARGET_NOT_ANSWERING` (Forgejo + Kong, a
temporary route on the probe path `GET ~/api/v1/orgs$` sleeping 7 s, the run's `target.read_timeout: 5.0`; since
2026-11-16 the same case is `NO_RESPONSE`, the shared rule of section 6) and
`NO_BACKEND_ADDRESS` (Forgejo + APISIX, the upstream's `checks` removed from `apisix/setup.sh` and the setup run
again, then `git checkout` and the setup again). The second shows a limit on APISIX: the adapter reads the backend
addresses from the Control API's health-check data, so an upstream without health checks gives the test no
address. Not reachable: `ADDRESS_WITHOUT_PORT` (the supported gateways give every address with its port: a Kong
target as `host:port`, an APISIX node with its `ip` and `port`), `NO_GATEWAY` (the test needs `GATEWAY`, so
without one the engine skips it first) and `NO_ATTEMPT` (the loop over `http` and `https` always ends with a
record, or raises). Every other branch of this test has been seen.

## 13. Remediation

Let the backend accept traffic only from the gateway (a network policy, a firewall rule, a service-level
authorization rule), and have the backend authenticate the gateway rather than trust its position.

## 14. Limitations

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

## 15. Sources

- OWASP API8:2023 Security Misconfiguration: https://owasp.org/API-Security/editions/2023/en/0xa8-security-misconfiguration/
- NIST SP 800-228 section 4.1: https://doi.org/10.6028/NIST.SP.800-228
- CWE-420 Unprotected Alternate Channel: https://cwe.mitre.org/data/definitions/420.html
- OWASP ASVS v5.0.0-13.2.1, cited in the limitations only: https://github.com/OWASP/ASVS/blob/v5.0.0/5.0/en/0x22-V13-Configuration.md

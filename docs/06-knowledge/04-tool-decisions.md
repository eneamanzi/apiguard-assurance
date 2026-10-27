# Tool Decisions

> **Audience:** readers of the research, contributors choosing a connector · **Status:** the consolidated decisions
> of the thesis tool review (version 3.0, May 2026), adapted to English; tools are described by their role, the
> detailed technique lists of the thesis are in the Italian original
> (`git show 694f89a:docs/knowledge/tools/decisions.it.md`; also tag `v0.1.0`, `docs/priv/TOOLS_decisions.md`).
> Which tests exist and at what priority is not repeated here: it is in
> [`../05-tests/README.md`](../05-tests/README.md) · **Detail of
> each tool:** [`05-tool-catalog.md`](05-tool-catalog.md) · **Verified:** 2026-10-27

For each guarantee of the methodology: whether Python covers it alone or with external tools, which tools were
chosen, and why. How the tool runs the chosen ones: [`assessment-model.md`](../04-architecture/03-assessment-model.md#native-hybrid-and-external-tools),
[`add-an-external-test.md`](../02-guides/03-extending/03-add-an-external-test.md).

## Criteria

**Inclusion criteria (v1.0).** Excluded: tools marked deprecated (last commit two years ago or more); tools that
could not be verified (no verifiable repository); tools for protocols outside the scope of v1.0 (GraphQL, gRPC,
WebSocket, HTTP/3); IaC and cloud-specific tools (deck already removed in v2.0); encyclopaedic appendices.

**Categories (v2.0).** The full classification, category C included, is in the [catalog](05-tool-catalog.md); the table
below lists the tools of category A and B.

| Category | Meaning |
|---|---|
| A | Connector to implement, mandatory: Python structurally cannot do what the tool does. |
| B | Optional connector with a native fallback: Python can, the tool adds genuine coverage. |
| C | Discarded: does not enter the code. |

| Classification of a guarantee | Meaning |
|---|---|
| NATIVE | Python covers the guarantee; no external tool adds value. |
| NATIVE + optional | Native, with an optional Cat B tool that widens coverage. |
| HYBRID | Python covers part of the guarantee; Cat A tools cover the rest. |

There is no "TOOL" classification: by design Python always contributes security logic of its own to a test that
uses external connectors. A NATIVE test with optional Cat B tools stays NATIVE.

**Reasons for discarding (category C).**

| Reason | Meaning |
|---|---|
| C.1 Redundancy or deprecation | Replaced by a tool of category A or B already present, or abandoned. |
| C.2 Platform-specific | Breaks the agnosticism of the architecture. |
| C.3 Different scope | Contract testing, SAST, IaC: an adjacent field, not security assessment of APIs. |
| C.4 Documentary value only | Native Python gives an equivalent result without dependencies. |

**Changes in v3.0 (May 2026).**

- `kiterunner` removed from Cat A (abandoned): `ffuf` promoted from Cat B to Cat A for 0.1.
- `CRLFuzz` removed from Cat A (inactive since 2021): CRLF coverage delegated to nuclei templates.
- `smuggler` removed from Cat A (no official release): a Python connector on standard library sockets instead.
- `race-the-web` removed from Cat A (abandoned): `vegeta` covers both 4.1 and 7.3.
- `jwtXploiter` removed from Cat B (five years without maintenance): `jwt_tool` already covers it.
- `Gopherus` removed from Cat B (four years without commits, no release): delegated to nuclei templates.
- `http2smugl` added as Cat B for 6.3 (optional HTTP/2 extension).

## Decisions by guarantee

This table answers one question only: which external tool serves which guarantee, and why. The priority of a test
and whether it exists are not written here, so that they cannot drift from the code: they are in the generated
catalogue [`../05-tests/README.md`](../05-tests/README.md) and in `apiguard list-tests`.

| ID | Guarantee | Classification | Cat A | Cat B |
|---|---|---|---|---|
| 0.1 | Shadow API discovery | HYBRID | ffuf, katana, nuclei | gau, cherrybomb |
| 0.2 | Deny-by-default | NATIVE + optional | - | cherrybomb |
| 0.3 | Deprecated APIs | NATIVE + optional | - | oasdiff |
| 1.1 | Authentication required | NATIVE | - | - |
| 1.2 | Credentials cryptographically valid | HYBRID | jwt_tool | - |
| 1.3 | Credentials not expired | HYBRID | jwt_tool | - |
| 1.4 | Credentials not revoked | NATIVE | - | - |
| 1.5 | Credentials not on insecure channels | HYBRID | testssl.sh | - |
| 1.6 | Session management | NATIVE | - | - |
| 2.1 | RBAC on privileged endpoints | NATIVE | - | - |
| 2.2 | BOLA prevention | NATIVE + optional | - | OFFAT, cherrybomb |
| 2.3 | Destructive operations | NATIVE + optional | - | OFFAT |
| 2.4 | Consistent policies | NATIVE | - | - |
| 2.5 | Excessive data exposure | NATIVE | - | - |
| 3.1 | Input validation | HYBRID | Schemathesis, nuclei | sqlmap, NoSQLMap, Dalfox, commix, SSTImap |
| 3.3 | Request signing (HMAC) | NATIVE | - | - |
| 4.1 | Rate limiting | HYBRID | vegeta | - |
| 4.2 | Timeouts | NATIVE | - | - |
| 4.3 | Circuit breaker | NATIVE | - | - |
| 5.1 | Audit logging | NATIVE | - | - |
| 5.2 | Real-time alerts | NATIVE | - | - |
| 6.1 | Error handling and information disclosure | NATIVE | - | - |
| 6.2 | Security headers | NATIVE | - | - |
| 6.3 | Gateway layer-7 hardening | HYBRID | (Python connector on sockets) | http2smugl |
| 6.4 | Hard-coded credentials | NATIVE + optional | - | trufflehog, gitleaks, detect-secrets |
| 7.1 | Anti-automation | NATIVE | - | - |
| 7.2 | SSRF prevention | HYBRID | nuclei, interactsh | - |
| 7.3 | Race conditions | HYBRID | vegeta | - |
| 7.4 | Safe consumption of external services | HYBRID | interactsh | - |

The Cat A and Cat B columns say which tool *would* serve a guarantee, not which one the tool ships. Of the
connectors above, three are wired to a test: testssl.sh (`ext.1.5.testssl`), ffuf (`ext.0.1.ffuf`) and Schemathesis
(`ext.3.1.schemathesis`). `NucleiConnector` is in the codebase but no test uses it ([`roadmap.md`](../project/roadmap.md)).
sslyze was implemented in Milestone 1 and removed in the review (AGPL v3, no added value over testssl.sh for 1.5).
katana, jwt_tool, vegeta, interactsh and every Cat B connector have no connector at all, and none is planned: they
were dropped on 2026-10-27 because the native path already covers the guarantee, the guarantee is outside the tool's
perimeter, or the blocker is what the target exposes rather than the code
([`roadmap.md`](../project/roadmap.md#nothing-else-is-planned)).

## Reasons by guarantee

### Domain 0. API discovery and inventory

- **0.1.** ffuf is the primary path brute-forcer (API wordlists from SecLists, JSON output, method negotiation,
  recursion, status and size filters, actively maintained; promoted from Cat B in place of the abandoned
  kiterunner). katana covers single-page applications, whose endpoints are defined in client-side JavaScript. nuclei,
  in the thesis, takes a discovered endpoint from "it exists" to "it is exploitable", shared with 3.1 and 7.2. The
  `NucleiConnector` is in the codebase but not wired to a test now (`ext.0.1.nuclei` was replaced by `ext.0.1.ffuf`,
  which fuzzes paths from wordlists); the native test finds drift from the specification. gau adds a passive,
  historical angle (web archives) without traffic to the target; cherrybomb adds static analysis of the
  specification.
- **0.2.** Native: Python builds arbitrary paths. cherrybomb, already a connector for 0.1, flags statically the
  paths that may lack a deny-by-default policy, at no new dependency cost.
- **0.3.** Native. oasdiff compares specification versions (deprecation and sunset headers) and handles diff edge
  cases (nested `$ref`, `allOf`/`anyOf`) where native Python gives false negatives on complex specifications.

### Domain 1. Identity and authentication

- **1.1.** No external tool: the logic is simple and Python covers it fully; Hurl would add only documentary
  readability (C.4).
- **1.2.** jwt_tool: a community-maintained catalogue of JWT attacks; keeping an equivalent catalogue up to date in
  Python would mean continuous maintenance of applied cryptography. It also covers what jwtXploiter covered.
- **1.3.** jwt_tool, already the connector for 1.2, builds tokens with arbitrary expiry claims at no extra cost.
  The thesis drew the line between a native forging helper for context-aware cases (those needing the
  `TargetContext`) and jwt_tool for standardised claim manipulation; neither exists, and neither is planned: both
  need signing-key or JWKS material the target must supply.
- **1.4.** No external tool: the sequence is stateful Python logic on the `TestContext` (as implemented: a
  credential obtained through the configured login, revoked with the login's configured delete request, then replayed
  on a derived anchor endpoint). IDP-specific clients
  (Keycloak, Auth0, Cognito) are C.2: the tool is agnostic by design.
- **1.5.** testssl.sh is the de facto standard for TLS analysis (protocol versions, cipher suites, forward secrecy,
  certificate checks, known TLS vulnerabilities); replicating it in Python would need hundreds of custom
  handshakes. It is the single TLS analysis tool for this guarantee. (sslyze was a second connector in Milestone 1,
  removed in the test review: AGPL v3, and on the labs it found no weakness testssl.sh did not already report.)
- **1.6.** No essential external tool: cookie attributes and session settings can be checked with Python and httpx.

### Domain 2. Authorization

- **2.1.** No external tool: tokens for distinct roles and iteration over endpoints are Python orchestration on the
  `TestContext`. OPA-based tools are C.2 (they assume the target uses OPA).
- **2.2.** OFFAT generates object-level authorization tests from the OpenAPI specification across every endpoint
  with path parameters, without manual configuration; cherrybomb flags candidate patterns statically before the
  dynamic test.
- **2.3.** OFFAT, already the connector for 2.2, generates tests on destructive operations from the specification.
- **2.4.** No essential external tool: comparing API versions is Python logic on the `AttackSurface`.
- **2.5.** No essential external tool: field-by-field inspection of JSON responses is Python logic.

### Domain 3. Data integrity

- **3.1.** The tools complement each other by kind of injection, each covering a distinct angle. Schemathesis is the
  only one integrable as a native Python library, with property-based testing against the OpenAPI schema, a
  different paradigm from payload lists. nuclei brings framework-specific templates and covers the CRLF vector once
  covered by CRLFuzz. sqlmap, NoSQLMap, Dalfox, commix and SSTImap are the mature references for their own injection
  class (SQL, NoSQL, cross-site scripting, OS command, server-side template), with context-aware payload generation
  that no static list matches.
- **CRLF note.** CRLFuzz worked on raw sockets to bypass the request normalisation applied by `httpx`; the nuclei
  templates for CRLF use the same raw approach. Before declaring CRLF coverage, check that the pinned
  `nuclei-templates` bundle contains them.
- **3.3.** No external tool: a configuration audit (white box); as implemented, it reads the signing policies and
  routes from the gateway through its adapter. Key inspection tools add nothing that `openssl`
  does not already cover (C.4); Vault and IaC scanners are C.2.

### Domain 4. Availability and resilience

- **4.1.** vegeta: precise rate control with Go goroutines, without the scheduling jitter of the Python interpreter
  that would make the observed threshold unreliable; latency histograms (p50, p90, p99). Shared with 7.3.
- **4.2.** No external tool: a configuration audit through the gateway's Admin API; gateway-specific tools such as
  deck are C.2, the logic sits in `BaseGatewayAdapter`.
- **4.3.** No external tool: a configuration audit of circuit breaker settings through the adapter; mesh and cloud
  tools (istioctl, Kuma, Linkerd, App Mesh, Envoy tools, kubescape) are C.2.

### Domain 5. Visibility and auditing

- **5.1.** No external tool: the test queries the log aggregator's REST API (Elasticsearch, Splunk, CloudWatch,
  Loki) with httpx, configured in `config.yaml`.
- **5.2.** No external tool: Python creates the anomalous condition and queries the alerting system through its API.
  A local alert manager or a third-party webhook service would add heavy or uncontrolled dependencies (C.4).

### Domain 6. Configuration and hardening

- **6.1.** No external tool: anomalous requests and inspection of responses for stack traces, versions and debug
  data are Python logic over the `AttackSurface`. Fingerprinting tools give context, not structured evidence (C.4).
- **6.2.** No external tool: Python checks a handful of headers against expected values; a dependency is not
  justified for a P3 test.
- **6.3.** The two classic desynchronisation patterns would be implemented directly in a Python connector on
  standard library sockets, because `httpx` refuses ambiguous framing by design, and the thesis also valued that the
  connector's code makes the mechanism readable. It does not exist and is not planned (2026-10-27): of guarantee 6.3,
  the CORS and timeout parts are covered by tests 6.2 and 4.2, and the smuggling probe is the part left out. http2smugl (Cat B, actively maintained) covers HTTP/2 downgrade, a distinct
  angle, and can become Cat A when the target exposes HTTP/2.
- **6.4.** Native. trufflehog brings hundreds of community-maintained detectors for API key formats, which would
  need a dedicated team to maintain in Python; gitleaks scans the history of the repository holding the
  specification or configuration (versioning angle, distinct from runtime); detect-secrets is importable as a Python
  library, with plugins, useful also in the project's own CI.

### Domain 7. Business logic and sensitive flows

- **7.1.** No external tool: whether sensitive endpoints require a CAPTCHA and aggressive rate limiting is observable
  in HTTP responses. Browser automation would add a full browser for one secondary test (C.4).
- **7.2.** nuclei adds community-maintained templates for technology-specific bypasses, distinct from the native
  payload catalogue, and covers what Gopherus covered (to be checked in the pinned bundle). interactsh is
  fundamental: blind SSRF cannot be detected without out-of-band callbacks, which pure Python cannot replace. The
  SSRFmap approach is native: the payload catalogue `ssrf_payloads.py`, not an external connector.
- **7.3.** vegeta, already the connector for 4.1, sends many requests in parallel with tight synchronisation,
  the functional equivalent of race-the-web; Python's asyncio adds scheduling jitter that breaks the sub-millisecond
  synchronisation a time-of-check to time-of-use race needs. Its JSON output (status codes, latencies) shows
  anomalous responses.
- **7.4.** interactsh, already the connector for 7.2, confirms that the system calls back a URL it was given.

## Shared connectors

Tools used by more than one test: the external test registry creates each once.

| Connector | Cat. | Used by |
|---|---|---|
| nuclei | A | 0.1, 3.1, 7.2 |
| cherrybomb | B | 0.1, 0.2, 2.2 |
| OFFAT | B | 2.2, 2.3 |
| jwt_tool | A | 1.2, 1.3 |
| vegeta | A | 4.1, 7.3 |
| interactsh | A | 7.2, 7.4 |

## Summary

| Classification | Guarantees |
|---|---|
| NATIVE (with or without optional tools) | 0.2, 0.3, 1.1, 1.4, 1.6, 2.1, 2.2, 2.3, 2.4, 2.5, 3.3, 4.2, 4.3, 5.1, 5.2, 6.1, 6.2, 6.4, 7.1 |
| HYBRID | 0.1, 1.2, 1.3, 1.5, 3.1, 4.1, 6.3, 7.2, 7.3, 7.4 |

**Category A (mandatory):** ffuf, katana, nuclei, jwt_tool, testssl.sh, sslyze, Schemathesis, vegeta, interactsh.

**Category B (optional, native fallback):** gau, cherrybomb, OFFAT, sqlmap, NoSQLMap, Dalfox, commix, SSTImap,
trufflehog, gitleaks, detect-secrets, oasdiff, http2smugl.

**Total:** 9 Cat A + 13 Cat B = 22 operational connectors (3 implemented). About 77 tools in category C, documented in
the [catalog](05-tool-catalog.md).

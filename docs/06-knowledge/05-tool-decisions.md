# Tool Decisions

> **Audience:** readers of the research, contributors choosing a connector · **Status:** the consolidated decisions
> of the thesis tool review (version 3.0, May 2026), adapted to English; tools are described by their role, the
> detailed technique lists of the thesis are in the Italian original
> (`git show 694f89a:docs/knowledge/tools/decisions.it.md`; also tag `v0.1.0`, `docs/priv/TOOLS_decisions.md`); the column "Implemented" is the state of the code on 2026-10-20 · **Detail of
> each tool:** [`06-tool-catalog.md`](06-tool-catalog.md) · **Verified:** 2026-10-20

For each guarantee of the methodology: whether Python covers it alone or with external tools, which tools were
chosen, and why. How the tool runs the chosen ones: [`assessment-model.md`](../04-architecture/03-assessment-model.md#native-hybrid-and-external-tools),
[`add-an-external-test.md`](../02-guides/03-extending/03-add-an-external-test.md).

## Criteria

**Inclusion criteria (v1.0).** Excluded: tools marked deprecated (last commit two years ago or more); tools that
could not be verified (no verifiable repository); tools for protocols outside the scope of v1.0 (GraphQL, gRPC,
WebSocket, HTTP/3); IaC and cloud-specific tools (deck already removed in v2.0); encyclopaedic appendices.

**Categories (v2.0).** The full classification, category C included, is in the [catalog](06-tool-catalog.md); the table
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

"Implemented" is the code today. "Priority" is the one the implemented test declares; for a guarantee with no test
yet it is the thesis review's, marked "(thesis)" (the thesis gave 1.4 and 2.1 as P1, the tests declare P2).

| ID | Guarantee | Priority | Classification | Cat A | Cat B | Implemented |
|---|---|---|---|---|---|---|
| 0.1 | Shadow API discovery | P0 | HYBRID | ffuf, katana, nuclei | gau, cherrybomb | native 0.1, ext.0.1.nuclei |
| 0.2 | Deny-by-default | P0 | NATIVE + optional | - | cherrybomb | native 0.2 |
| 0.3 | Deprecated APIs | P0 | NATIVE + optional | - | oasdiff | native 0.3 |
| 1.1 | Authentication required | P0 | NATIVE | - | - | native 1.1 |
| 1.2 | Credentials cryptographically valid | P0 (thesis) | HYBRID | jwt_tool | - | no |
| 1.3 | Credentials not expired | P0 (thesis) | HYBRID | jwt_tool | - | no |
| 1.4 | Credentials not revoked | P2 | NATIVE | - | - | native 1.4 |
| 1.5 | Credentials not on insecure channels | P2 | HYBRID | testssl.sh, sslyze | - | native 1.5, ext.1.5.testssl, ext.1.5.sslyze |
| 1.6 | Session management | P3 | NATIVE | - | - | native 1.6 |
| 2.1 | RBAC on privileged endpoints | P2 | NATIVE | - | - | native 2.1 |
| 2.2 | BOLA prevention | P1 (thesis) | NATIVE + optional | - | OFFAT, cherrybomb | no |
| 2.3 | Destructive operations | P1 (thesis) | NATIVE + optional | - | OFFAT | no |
| 2.4 | Consistent policies | P1 (thesis) | NATIVE | - | - | no |
| 2.5 | Excessive data exposure | P2 (thesis) | NATIVE | - | - | no |
| 3.1 | Input validation | P2 (thesis) | HYBRID | Schemathesis, nuclei | sqlmap, NoSQLMap, Dalfox, commix, SSTImap | no |
| 3.3 | Request signing (HMAC) | P3 | NATIVE | - | - | native 3.3 |
| 4.1 | Rate limiting | P0 | HYBRID | vegeta | - | native 4.1 |
| 4.2 | Timeouts | P1 | NATIVE | - | - | native 4.2 |
| 4.3 | Circuit breaker | P1 | NATIVE | - | - | native 4.3 |
| 5.1 | Audit logging | P1 (thesis) | NATIVE | - | - | no |
| 5.2 | Real-time alerts | P2 (thesis) | NATIVE | - | - | no |
| 6.1 | Error handling and information disclosure | P2 (thesis) | NATIVE | - | - | no |
| 6.2 | Security headers | P3 | NATIVE | - | - | native 6.2 |
| 6.3 | Gateway layer-7 hardening | P1 (thesis) | HYBRID | (Python connector on sockets) | http2smugl | no |
| 6.4 | Hard-coded credentials | P2 | NATIVE + optional | - | trufflehog, gitleaks, detect-secrets | native 6.4 |
| 7.1 | Anti-automation | P2 (thesis) | NATIVE | - | - | no |
| 7.2 | SSRF prevention | P0 | HYBRID | nuclei, interactsh | - | native 7.2 |
| 7.3 | Race conditions | P2 (thesis) | HYBRID | vegeta | - | no |
| 7.4 | Safe consumption of external services | P2 (thesis) | HYBRID | interactsh | - | no |

Implemented connectors: nuclei, testssl.sh, sslyze. Of the nine Cat A connectors, the other six (ffuf, katana,
jwt_tool, Schemathesis, vegeta, interactsh) and every Cat B connector are not implemented.

## Reasons by guarantee

### Domain 0. API discovery and inventory

- **0.1.** ffuf is the primary path brute-forcer (API wordlists from SecLists, JSON output, method negotiation,
  recursion, status and size filters, actively maintained; promoted from Cat B in place of the abandoned
  kiterunner). katana covers single-page applications, whose endpoints are defined in client-side JavaScript. nuclei,
  in the thesis, takes a discovered endpoint from "it exists" to "it is exploitable", shared with 3.1 and 7.2; as
  implemented (ext.0.1.nuclei) it looks for known exposures with the nuclei templates (Swagger UI, admin panels,
  debug paths) and does not use the native discovery's results: the native test finds drift from the specification,
  nuclei finds known-bad exposure patterns. gau adds a passive,
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
  `TargetContext`) and jwt_tool for standardised claim manipulation; that helper (`jwt_forge.py`) is planned, it does
  not exist.
- **1.4.** No external tool: the sequence is stateful Python logic on the `TestContext` (as implemented: a
  credential obtained through the configured login, revoked with the login's configured delete request, then replayed
  on `protected_endpoint`). IDP-specific clients
  (Keycloak, Auth0, Cognito) are C.2: the tool is agnostic by design.
- **1.5.** testssl.sh is the de facto standard for TLS analysis (protocol versions, cipher suites, forward secrecy,
  certificate checks, known TLS vulnerabilities); replicating it in Python would need hundreds of custom
  handshakes. sslyze runs in parallel as a Python library, with no binary, usable where testssl.sh cannot be
  installed, and gives independent evidence through ext.1.5.sslyze. The two run as separate external tests in the same run, one
  after the other.
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
  routes from the gateway through its adapter. Key inspection tools add nothing that `openssl` or
  sslyze do not already cover (C.4); Vault and IaC scanners are C.2.

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
- **6.3.** The two classic desynchronisation patterns are to be implemented directly in a Python connector on
  standard library sockets (planned: `ext_test_6_3_smuggling.py` does not exist), because `httpx` refuses ambiguous framing by design; the thesis also valued that the connector's
  code makes the mechanism readable. http2smugl (Cat B, actively maintained) covers HTTP/2 downgrade, a distinct
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
the [catalog](06-tool-catalog.md).

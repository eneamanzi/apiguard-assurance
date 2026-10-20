# Tool Catalog

> **Audience:** readers of the research · **Status:** the complete tool review of the thesis (version 1.3, May
> 2026), adapted to English: every tool found in a verifiable source, for every guarantee, in category A, B or C.
> Tools are described by their role; the detailed technique lists of the thesis are in the Italian original
> (`git show 694f89a:docs/knowledge/tools/catalog.it.md`; also tag `v0.1.0`, `docs/priv/TOOLS_catalog.md`). Maintenance states ("abandoned", "actively maintained") are as of May
> 2026. · **Decisions in short, criteria and implementation state:** [`decisions.md`](decisions.md) ·
> **Verified:** 2026-10-20

**Changes in v1.3 (May 2026) with respect to v1.2.**

- 0.1: kiterunner moved to category C (abandoned); ffuf promoted from B to A.
- 1.2: jwtXploiter moved to category C (five years without maintenance).
- 3.1: CRLFuzz moved to category C (inactive since 2021); CRLF coverage delegated to nuclei templates.
- 6.3: smuggler moved to category C (no release); category A now uses a Python connector on standard library
  sockets; http2smugl added as category B.
- 7.2: Gopherus moved to category C (four years without commits); coverage delegated to nuclei templates.
- 7.3: race-the-web moved to category C (abandoned); vegeta promoted to category A, shared with 4.1; racepwn
  confirmed C.4.
- Appendix A updated (ffuf, vegeta); appendix C updated (kiterunner, CRLFuzz, smuggler, race-the-web, jwtXploiter,
  Gopherus); appendix E updated to v1.4 (confidence matrix aligned with the new decisions).

**Since v1.2, three categories.** Each test section has three sub-sections, in order of operational priority:
**category A**, connector to implement, mandatory (Python structurally cannot); **category B**, optional connector
with a native fallback (Python can, the tool adds genuine coverage); **category C**, discarded (does not enter the
code; the reason is stated). The reasons C.1-C.4 are defined in [`decisions.md`](decisions.md#criteria).

**Columns.** Tool; Repository (GitHub or identifier); Language/type (CLI, library, API, script); Value against
native Python (why it is useful compared with Python alone); Output (the format relevant for integration); Notes
(warnings, maintenance state, dependencies).

## Domain 0. API discovery and inventory management

### 0.1 Every exposed endpoint is documented (shadow API discovery)

**Goal:** no endpoint active on the gateway is missing from the official OpenAPI specification.

**Category A**

| Tool | Repository | Language/type | Value against native Python | Output | Notes |
|---|---|---|---|---|---|
| ffuf | `ffuf/ffuf` | Go, CLI | Very fast path enumeration with API wordlists (SecLists, 30k+ paths), several HTTP methods, recursion, filters on status and response size; actively maintained. Promoted from B in place of kiterunner (abandoned). | JSON (`-of json`) | Primary tool for shadow API discovery; connector shared with the 0.2 fallback. |
| katana | `projectdiscovery/katana` | Go, CLI | Headless crawler that extracts endpoints from JavaScript bundles: essential for single-page applications, whose endpoints are defined in client-side routing. | JSON | Covers JavaScript-heavy cases ffuf does not. |
| nuclei | `projectdiscovery/nuclei` | Go, CLI | Template-based scanner with an API template library maintained by the community: after discovery, takes the test from "an undocumented endpoint exists" to "it is exploitable". | JSON, SARIF | Connector shared with 3.1 and 7.2. Implemented (ext.0.1.nuclei) with a different role: known exposures from the templates (Swagger UI, admin panels, debug paths), without the native discovery's results. |

**Category B**

| Tool | Repository | Language/type | Value against native Python | Output | Notes |
|---|---|---|---|---|---|
| gau (GetAllURLs) | `lc/gau` | Go, CLI | Aggregates URLs from web archives (Wayback Machine, CommonCrawl, OTX, URLScan): historical endpoints never removed, old API versions still reachable. A passive angle. | | Passive mining, complementary to the active fuzzers. |
| cherrybomb | GitHub, open source | Rust, CLI | Static analysis of the OpenAPI specification: unprotected endpoints, parameter tampering vectors, object-level authorization patterns. A SAST angle complementary to the dynamic tools. | JSON | Also covers 0.2 and 2.2. |

**Category C**

| Tool | Reason | Alternative |
|---|---|---|
| Kiterunner | C.1, deprecated: abandoned, no recent commit; ffuf (A) covers REST path enumeration with SecLists wordlists. | ffuf (A) |
| feroxbuster | C.1, redundant: weaker than ffuf for pure REST; useful for traditional web servers, not in scope. | ffuf |
| gobuster | C.1, redundant: simpler than feroxbuster, no distinct advantage. | ffuf |
| OWASP Noir | C.3, different scope: SAST on the source code's AST, needs the source; incompatible with a black or grey box approach. | - |
| APIClarity | C.3, scope v2.0: needs a target without an OpenAPI specification and traffic capture. | - |
| akto | C.3, different scope: a heavy Java platform, not an API assessment tool. | - |
| metlo | C.3, different scope: traffic-based discovery, needs a sidecar. | - |
| mitmproxy2swagger | C.3, scope v2.0: reverse engineering of the specification from captured traffic. | - |
| Arjun | C.3, scope v2.0: parameter discovery without a specification. | - |
| x8 | C.3, scope v2.0: a Rust alternative to Arjun. | - |
| ParamSpider | C.3, scope v2.0: parameter mining from web archives, no specification. | - |
| getJS + LinkFinder | C.1, redundant: katana covers the same case, more modern and integrated. | katana |
| waymore | C.1, redundant with gau, without decisive technical advantages in scope. | gau |
| Astra | C.1, deprecated: last commit 2020. | OFFAT, cherrybomb |

### 0.2 The gateway rejects requests to unregistered paths (deny-by-default)

**Goal:** the gateway answers `404`/`403` for every path not explicitly registered.

**Category A:** none, the test is NATIVE.

**Category B**

| Tool | Repository | Language/type | Value against native Python | Output | Notes |
|---|---|---|---|---|---|
| cherrybomb | GitHub, open source | Rust, CLI | Static analysis of the specification: unprotected endpoints and paths without a deny-by-default policy. Already a connector for 0.1, no extra cost. | JSON | Static approach, complementary to the dynamic tests. |

**Category C**

| Tool | Reason | Alternative |
|---|---|---|
| feroxbuster | C.1, redundant: the test is NATIVE; Python builds arbitrary paths and variants, no external fuzzer needed. | cherrybomb (SAST) |
| gobuster | C.1, redundant: as above. | cherrybomb |
| dredd | C.3, different scope: contract testing, not security assessment. | - |
| prism | C.3, different scope: mock server and validation proxy, a development tool. | - |
| Spectral | C.3, different scope: static OpenAPI linter; cherrybomb covers the security angle. | cherrybomb |
| vacuum | C.3, different scope: a Go alternative to Spectral, same limitation. | cherrybomb |
| OWASP Noir | C.3, different scope: SAST on source code. | - |
| ffuf | C.1: already a connector for 0.1; deny-by-default is judged more accurately with the paths the native test builds. | ffuf in 0.1 |

### 0.3 Deprecated APIs are disabled or more closely monitored

**Goal:** endpoints marked `deprecated: true` are disabled (`410 Gone`) or have stricter rate limiting and verbose
logging.

**Category A:** none, the test is NATIVE with an optional tool.

**Category B**

| Tool | Repository | Language/type | Value against native Python | Output | Notes |
|---|---|---|---|---|---|
| oasdiff | `tufin/oasdiff` | Go, CLI | Compares two OpenAPI specifications: breaking changes, deprecation, sunset header compliance (RFC 9110); handles diff edge cases (nested `$ref`, `allOf`/`anyOf`) where native Python gives false negatives on complex specifications. | JSON, YAML | Primary tool for diffs between specification versions. |

**Category C**

| Tool | Reason | Alternative |
|---|---|---|
| apidiff | C.1, redundant: a less mature alternative to oasdiff, same function. | oasdiff |
| dredd | C.3, different scope: contract testing, not sunset enforcement. | - |
| Spectral | C.3, different scope: static linter without a diff between versions. | oasdiff |
| vacuum | C.3, different scope: a Go alternative to Spectral, same limitation. | oasdiff |
| OWASP Noir | C.3, different scope: SAST on source code. | - |

## Domain 1. Identity and authentication

### 1.1 Only authenticated requests reach protected resources

**Goal:** every protected endpoint rejects requests without valid credentials with `401 Unauthorized`.

**Category A and B:** none, a purely NATIVE test.

**Category C**

| Tool | Reason | Alternative |
|---|---|---|
| Hurl | C.4, documentary value only: a DSL for readability, no technical value over Python; the logic is simple and fully covered by httpx. | native Python |

### 1.2 Credentials are cryptographically valid (JWT signature)

**Goal:** the gateway rejects forged or tampered JWTs (unsigned tokens, altered payloads, algorithm confusion,
stripped signatures, key identifier mismatches).

**Category A**

| Tool | Repository | Language/type | Value against native Python | Output | Notes |
|---|---|---|---|---|---|
| jwt_tool | `ticarpi/jwt_tool` | Python, CLI and library | A community-maintained catalogue of automated JWT attacks, including published CVEs, with an all-tests mode; covers what jwtXploiter covered. | JSON, text | Primary tool for JWT security: although written in Python, it encapsulates complex, up-to-date cryptographic logic. |

**Category B:** none (jwtXploiter removed, see C).

**Category C**

| Tool | Reason | Alternative |
|---|---|---|
| jwtXploiter | C.1, deprecated: five years without maintenance; jwt_tool already covers the same variants; no differential coverage. | jwt_tool (A) |
| jose-cli | C.4: Go's speed for JWT parsing does not justify an extra dependency for a single target. | jwt_tool |
| jwt-cracker (Node.js) | C.1, redundant: jwt_tool covers weak secret detection. | jwt_tool |
| jwt-crack (Rust) | C.4: brute force of weak HMAC secrets, too specific; the test's main oracle does not need it. | jwt_tool |

### 1.3 Credentials are not expired

**Goal:** the gateway rejects JWTs whose `exp` claim is in the past.

**Category A**

| Tool | Repository | Language/type | Value against native Python | Output | Notes |
|---|---|---|---|---|---|
| jwt_tool | `ticarpi/jwt_tool` | Python, CLI and library | Already a connector for 1.2: builds JWTs with arbitrary `exp` claims (expired, valid, negative, leeway) to observe the server. Same tool, different parameters. | JSON, text | Shared with 1.2, no extra dependency. |

**Category B and C**

| Tool | Reason | Alternative |
|---|---|---|
| jose-cli | C.4: large-scale `exp` parsing not needed for a single target; jwt_tool already covers it. | jwt_tool |

### 1.4 Credentials have not been revoked

**Goal:** valid tokens explicitly revoked (after logout, after a password change) are rejected. As implemented: a
credential obtained through the configured login, revoked with the login's configured delete request, then replayed
on `protected_endpoint`.

**Category A and B:** none, a purely NATIVE test.

**Category C**

| Tool | Reason | Alternative |
|---|---|---|
| Hurl | C.4: a DSL adding only documentary readability; the login, logout, replay sequence is stateful Python logic on the `TestContext`. | native Python |
| mitmproxy | C.3: a proxy needs to sit in the connection; for revocation the test is direct through httpx. | native Python |
| keycloak-admin-client | C.2, Keycloak-specific: the tool is agnostic by design. | - |
| auth0-cli | C.2, Auth0-specific. | - |
| aws-cognito-idp | C.2, AWS Cognito-specific. | - |
| jose-cli | C.4: marginal use to check the cryptographic structure after revocation. | - |

### 1.5 Credentials are not sent over insecure channels (TLS)

**Goal:** TLS 1.2+ enforced, secure cipher suites (ECDHE + AEAD), HSTS, HTTP to HTTPS redirect.

**Category A**

| Tool | Repository | Language/type | Value against native Python | Output | Notes |
|---|---|---|---|---|---|
| testssl.sh 3.2 | `testssl/testssl.sh` | Bash script (needs OpenSSL) | The de facto standard for TLS security assessment: protocol versions, cipher suites, forward secrecy, certificate transparency, known TLS vulnerabilities with their CVEs. Replicating it in Python would need hundreds of raw TLS handshakes. | JSON (`--jsonfile`), entries with id, severity, finding, cve, cwe | Primary tool. Docker image `drwetter/testssl.sh`. Filter on severity MEDIUM, HIGH, CRITICAL, WARN. |
| sslyze | `nabla-c0d3/sslyze` | Python, library and CLI | A parallel connector to testssl.sh, importable as a pure Python library with no binary: complementary TLS analysis. Implemented in Milestone 1 as `SslyzeConnector` (`BaseLibraryConnector`) with its own external test. | JSON | A library, so `BaseLibraryConnector`, not `BaseSubprocessConnector`. The two run as separate external tests in the same run, one after the other. |

**Category C**

| Tool | Reason | Alternative |
|---|---|---|
| tlsx | C.4: faster on many targets but shallower on one; our case is always one target. | testssl.sh |
| sslscan2 | C.1: an alternative to sslyze without advantages over it; an extra C dependency. | sslyze |
| tls-scan | C.4: optimised for bulk scans of thousands of hosts, not deep analysis of one. | testssl.sh |
| h2spec | C.3: HTTP/2 conformance testing, a different scope from TLS weaknesses. | - |
| quiche + curl --http3 | C.3: HTTP/3/QUIC, outside the scope of v1.0. | - |
| jwt_tool (`-cv`) | C.4: tertiary use to check the TLS channel; testssl.sh covers it fully. | testssl.sh |

### 1.6 Sessions are managed securely in distributed architectures

**Goal:** audit of cookie attributes (HttpOnly, Secure, SameSite), session store TTL, session fixation. The test
covers today the cookie attributes only.

**Category A and B:** none, a purely NATIVE test.

**Category C**

| Tool | Reason | Alternative |
|---|---|---|
| mitmproxy | C.3: a proxy needs to sit in the connection, incompatible with black box; for session fixation the empirical test is Python + httpx. | native Python |
| Hurl | C.4: a documentary DSL with no technical value. | native Python |
| jwt_tool | C.4: tertiary use on session management, marginal mapping. | - |

## Domain 2. Authorization and access control

### 2.1 Only authorised users reach privileged endpoints (RBAC)

**Goal:** privileged endpoints reject authenticated users with an insufficient role with `403`.

**Category A and B:** none, a purely NATIVE test.

**Category C**

| Tool | Reason | Alternative |
|---|---|---|
| opa + conftest | C.2: requires the target to use OPA as policy engine, a non-agnostic assumption. | native Python |
| Spectral | C.3: static analysis of the specification only, already covered by cherrybomb (0.1, 0.2). | cherrybomb |

### 2.2 Users access only their own data (BOLA prevention)

**Goal:** a user cannot access another user's resources (IDOR, BOLA).

**Category A:** none (the thesis: HYBRID with B tools).

**Category B**

| Tool | Repository | Language/type | Value against native Python | Output | Notes |
|---|---|---|---|---|---|
| OWASP OFFAT | `OWASP/OFFAT` | Python, CLI and library | Generates object-level authorization tests from the OpenAPI specification, across every endpoint with path parameters, without per-endpoint configuration. | JSON | Primary tool for BOLA; also covers mass assignment. |
| cherrybomb | GitHub, open source | Rust, CLI | Static analysis of the specification: endpoints with an ID path parameter and no declared ownership check, before the dynamic test. Already a connector. | JSON | SAST complementary to DAST. |

**Category C**

| Tool | Reason | Alternative |
|---|---|---|
| akto | C.3: a heavy Java platform, not integrable as a connector. | OFFAT |
| susanoo | C.1: an alternative to OFFAT, less mature and less maintained. | OFFAT |
| AuthMatrix | C.3: needs a manually configured role-by-endpoint matrix; not agnostic, not automatable without prior knowledge. | OFFAT |
| astra | C.1, deprecated: last commit 2020. | OFFAT, cherrybomb |

### 2.3 Destructive operations require appropriate privileges

**Goal:** DELETE, PUT and financial operations require OAuth2 scopes or elevated roles (least privilege).

**Category A:** none, the test is NATIVE with an optional tool.

**Category B**

| Tool | Repository | Language/type | Value against native Python | Output | Notes |
|---|---|---|---|---|---|
| OWASP OFFAT | `OWASP/OFFAT` | Python, CLI | Generates authorization tests on destructive operations from the specification. Already a connector for 2.2. | JSON | Shared with 2.2. |

**Category C**

| Tool | Reason | Alternative |
|---|---|---|
| Hurl | C.4: a documentary DSL for the least privilege sequence; the stateful logic is Python on the `TestContext`. | native Python |

### 2.4 Authorization policies are consistent across endpoints

**Goal:** equivalent endpoints (other versions, alternative formats) apply identical authentication policies.

**Category A and B:** none, a purely NATIVE test.

**Category C**

| Tool | Reason | Alternative |
|---|---|---|
| dredd | C.3: OpenAPI contract testing, a wider and different scope from policy consistency. | native Python |
| prism | C.3: mock server and validation proxy, a development tool. | native Python |
| Spectral | C.3: a static linter; the dynamic behaviour matters more for this test. | native Python |
| vacuum | C.3: a Go alternative to Spectral, same limitation. | native Python |

### 2.5 The API does not expose excessive data

**Goal:** responses contain no undocumented sensitive fields (password hashes, SSNs, API keys).

**Category A and B:** none, a purely NATIVE test.

**Category C**

| Tool | Reason | Alternative |
|---|---|---|
| graphql-cop | C.3: GraphQL only, outside the scope of v1.0 (REST only). | - |
| APIClarity | C.3: needs traffic capture, scope v2.0. | - |
| akto | C.3: a heavy Java platform. | - |
| jwt_tool (`-pd`) | C.4: specific to excessive JWT claims, very marginal; jwt_tool is already there for 1.2. | jwt_tool |

## Domain 3. Data integrity

### 3.1 Every input is validated against schema and constraints

**Goal:** injections (SQL, NoSQL, command, template, CRLF), type confusion and anomalous payloads are rejected with
`400`.

> **CRLF coverage (v1.3).** CRLFuzz was removed from category A (inactive since 2021). It was there because it
> worked on raw sockets, bypassing the request normalisation (RFC 7230) applied by `httpx`. The nuclei CRLF templates
> in the pinned `nuclei-templates 10.4.3` bundle use the same raw TCP approach and give equivalent evidence.
> Prerequisite: check that the bundle contains them before declaring CRLF covered in 3.1.

**Category A**

| Tool | Repository | Language/type | Value against native Python | Output | Notes |
|---|---|---|---|---|---|
| Schemathesis | `schemathesis/schemathesis` | Python, library and CLI | The only tool integrable as a native Python library. Property-based testing with the Hypothesis engine: generates many inputs for every parameter of every endpoint from the OpenAPI specification, exploring the input space against the schema; a different paradigm from a payload list. Native OpenAPI 3.1. | JUnit XML, JSON | `BaseLibraryConnector`, not `BaseSubprocessConnector`. |
| nuclei | `projectdiscovery/nuclei` | Go, CLI | Templates for injections specific to well-known frameworks (Spring Boot, Django, Laravel, Rails), updated by the community; also covers CRLF (in place of CRLFuzz). | JSON, SARIF | Shared with 0.1 and 7.2. |

**Category B**

| Tool | Repository | Language/type | Value against native Python | Output | Notes |
|---|---|---|---|---|---|
| sqlmap | `sqlmapproject/sqlmap` | Python, CLI | The de facto standard for SQL injection, with context-aware payload generation that no manual list matches. | JSON | De facto standard. |
| NoSQLMap | `codingo/NoSQLMap` | Python, CLI | NoSQL injection (MongoDB, CouchDB), critical for modern APIs; the only mature tool for it. | structured | An angle fully separate from sqlmap. |
| Dalfox | `hahwul/dalfox` | Go, CLI | Context-aware cross-site scripting detection with DOM analysis, fewer false negatives than static lists. | JSON | Primary tool for XSS; very active. |
| commix | `commixproject/commix` | Python, CLI | The only mature tool for automated OS command injection, including blind cases. | structured | No equivalent alternative. |
| SSTImap | public repository | Python, CLI | The active fork of tplmap for server-side template injection (Jinja2, Twig, Smarty, Velocity, FreeMarker, Pebble), detecting the engine automatically. | structured | Prefer it to tplmap. |

**Category C**

| Tool | Reason | Alternative |
|---|---|---|
| CRLFuzz | C.1, deprecated: inactive since 2021; CRLF delegated to nuclei templates (same raw TCP approach). | nuclei templates |
| ghauri | C.1: an alternative to sqlmap without decisive advantages. | sqlmap |
| nosqli | C.1: a Go alternative to NoSQLMap, less mature. | NoSQLMap |
| XSStrike | C.1: an alternative to Dalfox, which is better at context-aware detection. | Dalfox |
| tplmap | C.1: SSTImap is its active fork, with more engines. | SSTImap |
| crlfmap | C.1: an alternative to CRLFuzz, itself removed. | nuclei templates |
| headi | C.1: header injection, which CRLFuzz already covered; now nuclei templates. | nuclei templates |
| dotdotpwn | C.1: path traversal covered by ffuf with dedicated wordlists. | ffuf + wordlist |
| CATS | C.3: a Java alternative to Schemathesis; the native Python library is preferred. | Schemathesis |
| APIFuzzer | C.1: fully covered by Schemathesis. | Schemathesis |
| cherrybomb | C.4: static analysis of injection points; nuclei covers the dynamic angle with more coverage. | nuclei |

### 3.3 Data in transit is protected from tampering (HMAC configuration audit)

**Goal:** audit of the HMAC request signing architecture: presence, algorithm, replay protection.

**Category A and B:** none, a purely NATIVE test: a configuration audit (the thesis: by reading documentation and
code; as implemented, by reading the signing policies and routes from the gateway through its adapter).

**Category C**

| Tool | Reason | Alternative |
|---|---|---|
| step-cli | C.4: one CLI command; `openssl` or sslyze already cover the same analysis; no dependency for a P3 test. | openssl or sslyze |
| jwt_tool | C.4: marginal use on HMAC; the connector is for 1.2 and 1.3. | - |
| Vault API | C.2: HashiCorp Vault-specific, breaks agnosticism. | - |
| mitmproxy | C.3: a proxy approach incompatible with black box; for an empirical P3 test the risk-benefit is unfavourable. | - |
| Checkov | C.2: an IaC scanner (Terraform, CloudFormation, Kubernetes), a different scope. | - |

## Domain 4. Availability and resilience

### 4.1 The system prevents resource exhaustion through rate limiting

**Goal:** the gateway applies rate limiting and answers `429 Too Many Requests` with `Retry-After`.

**Category A**

| Tool | Repository | Language/type | Value against native Python | Output | Notes |
|---|---|---|---|---|---|
| vegeta | `tsenart/vegeta` | Go, CLI | Precise rate control with Go goroutines: the Python interpreter lock and garbage collector add jitter that makes the observed threshold unreliable; to see a limit trigger at exactly N requests per second the load generator must be precise to the millisecond. Latency histograms (p50, p90, p99). | JSON | Shared with 7.3. |

**Category B:** none.

**Category C**

| Tool | Reason | Alternative |
|---|---|---|
| hey | C.1: explicitly redundant with vegeta, same function, fewer features. | vegeta |
| slowloris | C.4: slow-connection attacks are orthogonal to rate limiting on request frequency; test 4.2 on timeouts addresses the slow-connection case. | vegeta for frequency |
| bombardier | C.4: HTTP/2-specific, a marginal case for the main test; vegeta covers the general case. | vegeta |
| graphql-cop | C.3: GraphQL only, outside the scope of v1.0. | - |

### 4.2 The system has timeouts that prevent resource lock

**Goal:** audit of the timeouts configured on the gateway (connect, read, write), the connection pool and the
outgoing HTTP calls. The test covers today the gateway's backend timeouts only.

**Category A and B:** none, a purely NATIVE test (configuration audit).

**Category C**

| Tool | Reason | Alternative |
|---|---|---|
| httpstat | C.4: a visual timing breakdown; Python can measure TTFB and connection times; no structured evidence for the report. | native Python |
| deck | C.2: Kong-specific, breaks agnosticism; reading the configuration is the job of `BaseGatewayAdapter`. | BaseGatewayAdapter |
| vegeta | C.4: useful as an optional behavioural test in staging, but the test is a configuration audit, not a load test. | - |
| prowler | C.2: AWS-specific. | - |
| kubescape | C.2: Kubernetes-specific. | - |

### 4.3 The system degrades gracefully with a circuit breaker

**Goal:** audit of the circuit breaker configuration (threshold, timeout, trigger codes, observability).

**Category A and B:** none, a purely NATIVE test (configuration audit).

**Category C**

| Tool | Reason | Alternative |
|---|---|---|
| deck | C.2: Kong-specific, breaks agnosticism. | BaseGatewayAdapter |
| inso | C.2: specific to the Kong ecosystem. | BaseGatewayAdapter |
| kuma-cp inspect | C.2: specific to the Kuma service mesh. | - |
| istioctl analyze | C.2: specific to the Istio service mesh. | - |
| kubescape | C.2: Kubernetes-specific. | - |
| linkerd viz | C.2: specific to the Linkerd service mesh. | - |
| aws appmesh | C.2: specific to AWS App Mesh. | - |
| envoy-tools | C.2: specific to standalone Envoy. | - |
| vegeta | C.4: an optional behavioural test in staging, not part of the configuration audit's oracle. | - |

## Domain 5. Visibility and auditing

### 5.1 Every request is logged with essential metadata

**Goal:** every request produces a structured log with timestamp, request ID, source IP, user ID, status code,
response time.

**Category A and B:** none, a purely NATIVE test.

**Category C**

| Tool | Reason | Alternative |
|---|---|---|
| vector + jq | C.4: a stack-specific log processing pipeline, not a security assessment tool; Python httpx queries any log aggregator through its REST API. | native Python |
| loki-cli (logcli) | C.4: Grafana/Loki-specific; Python httpx can query Loki's REST API (`/loki/api/v1/query`) with no extra dependency. | native Python |
| nuclei | C.4: indirect use to trigger log conditions; the logic is cleaner as direct Python. | native Python |
| Prowler | C.2: AWS-specific (CloudWatch, GuardDuty). | - |
| metlo | C.3: traffic capture, a different scope. | - |

### 5.2 Anomalous security events trigger real-time alerts

**Goal:** brute force, object enumeration and rate limit hits trigger alerts to a SIEM or notification channel
within the agreed time.

**Category A and B:** none, a purely NATIVE test.

**Category C**

| Tool | Reason | Alternative |
|---|---|---|
| alertmanager webhook receiver mock | C.4: needs a local Prometheus setup, a heavy dependency for a P2 test. | native Python with a local webhook endpoint |
| webhook.site API | C.4: an uncontrolled external service and a dependency on external connectivity; the test must be repeatable in air-gapped environments. | native Python with a local endpoint |
| nuclei | C.4: too indirect as an extra layer on alert testing. | native Python |
| Prowler | C.2: AWS-specific. | - |

## Domain 6. Configuration and hardening

### 6.1 Error handling and information disclosure

**Goal:** responses contain no stack traces, framework versions, SQL errors or debug data.

**Category A and B:** none, a purely NATIVE test.

**Category C**

| Tool | Reason | Alternative |
|---|---|---|
| httpx (ProjectDiscovery) | C.4: Go's speed for mass probing is irrelevant for one target; the Python httpx library already used covers the same; its technology detection adds fingerprinting, not structured evidence of vulnerabilities. | native Python httpx |
| whatweb | C.4: technology fingerprinting in Ruby; useful to give context to a finding by hand, but no direct evidence; needs a Ruby runtime. | native Python |
| hakrawler | C.4: a generic crawler used as a grep pipeline, not a security analysis tool; the logic is cleaner as Python iteration over the `AttackSurface`. | native Python |
| Spectral | C.3: a static linter; dynamic analysis of responses matters more for information disclosure. | native Python |

### 6.2 Security headers are configured appropriately

**Goal:** presence and value of HSTS, X-Frame-Options, X-Content-Type-Options, CSP, Permissions-Policy.

**Category A and B:** none, a purely NATIVE test.

**Category C**

| Tool | Reason | Alternative |
|---|---|---|
| shcheck | C.4: Python checks 6-8 headers against a list of expected values in about 20 lines; covering rarer headers (COOP, COEP) does not justify a dependency for a P3 test. | native Python |
| csp-evaluator | C.4: a public Google REST API; Python with httpx makes the same call in 3 lines; not a tool to integrate as a connector. | native Python with httpx |
| securityheaders.com API | C.4: an external scoring service; no automated evidence; a dependency on external connectivity. | native Python |
| treblle | C.4: little maintained as a standalone tool; no value over native Python. | native Python |
| Checkov | C.2: an IaC scanner, a completely different scope. | - |

### 6.3 The gateway configuration is hardened against layer-7 exploits

**Goal:** HTTP request smuggling, slow-connection timeouts, CORS enforcement, path normalisation, plugin security.

> **Architecture note (v1.3).** smuggler was removed from category A for lack of an official release. The thesis
> placed the two classic desynchronisation patterns in a connector, `ext_test_6_3_smuggling.py` (planned, it does not
> exist), on standard library sockets: `httpx` refuses ambiguous request framing by design (RFC conformance), so raw sockets are needed. The
> academic advantage: the connector's code makes the mechanism readable in the thesis without a black-box binary.

**Category A:** none (the connector uses Python standard library sockets).

**Category B**

| Tool | Repository | Language/type | Value against native Python | Output | Notes |
|---|---|---|---|---|---|
| http2smugl | public Go repository | Go, CLI | HTTP/2 downgrade smuggling, an angle distinct from the patterns in the native connector; can become category A when the target exposes HTTP/2; actively maintained. | structured | Optional; a candidate for A if the target uses HTTP/2. |

**Category C**

| Tool | Reason | Alternative |
|---|---|---|
| smuggler | C.1: no tagged official release; the patterns are implemented directly on standard library sockets. | Python sockets (stdlib) |
| gotestwaf | C.3: overkill, it covers the whole layer-7 WAF bypass space; for smuggling alone the native connector is enough. | Python sockets |
| h2csmuggler | C.4: smuggling through an unencrypted HTTP/2 upgrade, a very specific case that most targets do not expose. | http2smugl (B) |
| deck | C.2: Kong-specific, breaks agnosticism; `BaseGatewayAdapter` abstracts this logic. | BaseGatewayAdapter |
| inso | C.2: specific to the Kong ecosystem. | BaseGatewayAdapter |
| kong-plugin-validator | C.2: Kong-specific. | BaseGatewayAdapter |
| prowler | C.2: AWS-specific. | - |
| checkov | C.2: an IaC scanner. | - |
| inspec-aws | C.2: AWS and Ruby InSpec. | - |
| steampipe | C.2: SQL queries over cloud APIs, cloud-specific. | - |
| cfn-lint | C.2: AWS CloudFormation-specific. | - |
| tfsec | C.2: Terraform-specific. | - |
| kics | C.2: a multi-IaC scanner. | - |
| kubescape | C.2: Kubernetes-specific. | - |
| kube-linter | C.2: Kubernetes-specific. | - |
| kubeaudit | C.2: specific to Kubernetes ingress. | - |
| istioctl | C.2: specific to the Istio service mesh. | - |

### 6.4 Service credentials are not hard-coded or exposed

**Goal:** credentials are in a secret manager, not hard-coded in configuration files or Docker images, nor exposed
through debug endpoints.

**Category A:** none (the thesis: HYBRID with B tools).

**Category B**

| Tool | Repository | Language/type | Value against native Python | Output | Notes |
|---|---|---|---|---|---|
| trufflehog | `trufflesecurity/trufflehog` | Go, CLI | 800+ community-maintained detectors for API keys, tokens and secrets of known providers; scans response bodies, specification files, JavaScript bundles and git history. Keeping these patterns current in Python would be continuous maintenance. | JSON | Primary tool. |
| gitleaks | `gitleaks/gitleaks` | Go, CLI | Scans the commit history of the repository holding the OpenAPI specification or the configuration files: the versioning angle, distinct from trufflehog's runtime angle. | JSON | Complementary to trufflehog. |
| detect-secrets | `Yelp/detect-secrets` | Python, CLI and library | Plugin architecture for custom detectors, importable as a Python library, native pre-commit hook; useful both on the target and in the project's own CI. | JSON | Importable as a library. |

**Category C**

| Tool | Reason | Alternative |
|---|---|---|
| secretlint | C.1: Node.js; the detect-secrets Python library covers the same. | detect-secrets |
| kube-linter | C.2: Kubernetes-specific. | - |
| prowler | C.2: AWS-specific. | - |

## Domain 7. Business logic and sensitive flows

### 7.1 Sensitive business flows are protected from automated abuse

**Goal:** CAPTCHA enforcement, aggressive application-level rate limiting, device fingerprinting on payment and
registration endpoints.

**Category A and B:** none, a purely NATIVE test.

**Category C**

| Tool | Reason | Alternative |
|---|---|---|
| playwright | C.4: browser automation for CAPTCHA testing is a secondary P2 case; a full browser dependency for one scenario; whether a CAPTCHA exists is observable in the HTTP response with httpx. | native Python |
| puppeteer | C.1: Node.js; playwright covers the same with Python bindings. | playwright (C.4) |
| puppeteer-extra-stealth | C.4: advanced device fingerprinting, a specific case outside the core of the test. | - |
| vegeta | C.4: already a connector for 4.1; bursts on business endpoints are marginal compared with the native logic. | vegeta in 4.1 |
| curl-impersonate | C.4: TLS fingerprint impersonation, a very advanced and specific case outside the core of the test. | - |
| akto | C.3: a heavy Java platform. | - |

### 7.2 The system prevents server-side request forgery (SSRF)

**Goal:** the system blocks SSRF towards cloud metadata services, private addresses, and encoded variants.

**Technical note.** The SSRFmap approach is implemented natively (`ssrf_payloads.py`): not an external connector but
Python logic in the test. The standard payloads (cloud metadata, private addresses, encodings, forbidden protocols)
are native code; the connectors extend coverage with angles Python cannot replicate.

> **Gopher coverage (v1.3).** Gopherus was removed from category B (four years without commits, no release). nuclei
> templates in the pinned `nuclei-templates 10.4.3` bundle cover SSRF towards internal services through the gopher
> scheme. Prerequisite: check that the bundle contains them before declaring this covered.

**Category A**

| Tool | Repository | Language/type | Value against native Python | Output | Notes |
|---|---|---|---|---|---|
| nuclei | `projectdiscovery/nuclei` | Go, CLI | SSRF templates with technology- and cloud-specific variants, updated by the community; an angle distinct from the native `ssrf_payloads.py`; also covers what Gopherus covered. | JSON | Shared with 0.1 and 3.1. |
| interactsh | `projectdiscovery/interactsh` | Go, server and client | Out-of-band callback server to confirm blind SSRF: without it blind SSRF cannot be detected; it records the DNS and HTTP callbacks that confirm the request was made. Not replaceable with pure Python. | JSON | Essential for blind SSRF; shared with 7.4. |

**Category B:** none (Gopherus removed, see C).

**Category C**

| Tool | Reason | Alternative |
|---|---|---|
| Gopherus | C.1, deprecated: four years without commits, no release; nuclei templates cover the same. | nuclei templates |
| SSRFmap | Note: integrated as native code (`ssrf_payloads.py`), not a connector. | - |
| nimbostratus | C.2: specific to AWS metadata, platform-specific. | native `ssrf_payloads.py` |
| singularity | C.4: a DNS rebinding framework, an advanced case covered by the native logic with standard payloads. | native `ssrf_payloads.py` |
| SSRFfire | C.1, deprecated (last commit 2021); replaced by the native SSRFmap approach. | native `ssrf_payloads.py` |

### 7.3 Critical operations are idempotent or protected from race conditions

**Goal:** critical operations (payment, inventory deduction) are protected from race conditions and the idempotency
key works.

**Category A**

| Tool | Repository | Language/type | Value against native Python | Output | Notes |
|---|---|---|---|---|---|
| vegeta | `tsenart/vegeta` | Go, CLI | Already a connector for 4.1: sends many requests in parallel with tight synchronisation, the functional equivalent of race-the-web; Python's asyncio adds scheduling jitter that breaks the sub-millisecond synchronisation a time-of-check to time-of-use race needs. Its JSON output (status codes, latencies) shows anomalous responses (for example two `200` on an idempotent operation). | JSON | Shared with 4.1. |

**Category B:** none.

**Category C**

| Tool | Reason | Alternative |
|---|---|---|
| race-the-web | C.1, deprecated: abandoned, few stars, no recent release; vegeta covers the requirement with no extra dependency. | vegeta (A) |
| racepwn | C.4: its C dependency needs a non-trivial build in Docker; the HTTP/2 concurrent-streams vector is rare on standard gateway targets such as Kong; vegeta covers the common case. | vegeta |
| turbo-intruder | C.4: Java/Jython, a very complex setup; vegeta gives the same precision with a simpler architecture. | vegeta |
| h2csmuggler | C.4: smuggling through an unencrypted HTTP/2 upgrade, not race conditions. | smuggler (C.1) / http2smugl |
| http2smugl | C.1: HTTP/2 smuggling, not race conditions. | http2smugl (B in 6.3) |
| h2spec | C.3: HTTP/2 conformance testing, a different scope. | - |
| ffuf at unlimited rate | C.1: a coarse baseline for race detection; vegeta is the right entry level. | vegeta |

### 7.4 The API consumes external services safely (webhook verification)

**Goal:** HMAC signatures on webhooks, replay protection, sanitisation of webhook payloads.

**Category A**

| Tool | Repository | Language/type | Value against native Python | Output | Notes |
|---|---|---|---|---|---|
| interactsh | `projectdiscovery/interactsh` | Go, server and client | Already a connector for 7.2: registers a callback URL pointing to interactsh and checks that the system calls it; without an out-of-band server there is no direct evidence. | JSON | Shared with 7.2. |

**Category B:** none.

**Category C**

| Tool | Reason | Alternative |
|---|---|---|
| httpx (ProjectDiscovery) | C.4: redirect chain analysis is 3 lines with the native Python httpx. | native Python |
| nuclei | C.4: too indirect for webhook testing; the logic is clearer as direct Python. | native Python |
| confused | C.3: dependency confusion is supply chain, not API security in the strict sense. | - |

## Appendix A. Cross-cutting tools (several domains), v1.3

| Tool | Cat. | Tests | Why it covers several |
|---|---|---|---|
| nuclei | A | 0.1, 3.1, 7.2 | Templates for shadow APIs, injection (CRLF included), SSRF (gopher included): one connector, three tests. |
| jwt_tool | A | 1.2, 1.3 | Multipurpose JWT security testing. |
| vegeta | A | 4.1, 7.3 | Load for rate limiting (4.1); synchronised parallel requests for races (7.3). |
| interactsh | A | 7.2, 7.4 | Out-of-band server for blind SSRF and webhook callbacks. |
| cherrybomb | B | 0.1, 0.2, 2.2 | Rust static analyser for several tests. |
| OWASP OFFAT | B | 2.2, 2.3 | Object-level and destructive-operation authorization. |
| ffuf | A | 0.1 (and the 0.2 fallback) | Go fuzzer, promoted to A for 0.1. |
| oasdiff | B | 0.3 | Specification diff. |
| trufflehog | B | 6.4 | Runtime secret scanning. |
| gitleaks | B | 6.4 | Secret scanning of git history. |
| detect-secrets | B | 6.4 | Secret scanning as a Python library. |
| sslyze | A | 1.5 (in parallel with testssl.sh) | TLS analysis as a Python library: a parallel connector, not a fallback. |

Category C tools found under several tests (documented for historical completeness):

| Tool | Cat. | Where it appears |
|---|---|---|
| deck | C.2 | Kong-specific: 4.2, 4.3, 6.3 |
| prowler | C.2 | AWS-specific: 4.2, 5.1, 5.2, 6.3, 6.4 |
| kubescape | C.2 | Kubernetes-specific: 4.2, 4.3, 6.3 |
| istioctl | C.2 | Istio-specific: 4.3, 6.3 |
| checkov | C.2 | IaC scanner: 3.3, 6.2, 6.3 |
| Spectral | C.3 | OpenAPI linter: 0.2, 0.3, 2.1, 2.4, 6.1 |
| vacuum | C.3 | Go alternative to Spectral: 0.2, 0.3, 2.4 |
| dredd | C.3 | Contract testing: 0.2, 0.3, 2.4 |
| prism | C.3 | Mock server: 0.2, 2.4 |
| Hurl | C.4 | Documentary DSL: 1.1, 1.4, 2.3 |
| httpx (ProjectDiscovery) | C.4 | Mass probing: 6.1, 7.4 |
| h2csmuggler | C.4 | HTTP/2 smuggling: 6.3, 7.3 |
| akto | C.3 | Java platform: 0.1, 2.2, 2.5, 7.1 |

## Appendix B. Tools for non-REST protocols (outside the scope of v1.0, documented for completeness)

**GraphQL**

| Tool | Repository | Language | Equivalent test | Function |
|---|---|---|---|---|
| graphw00f | public repository | Python | 0.1 | Fingerprints the GraphQL engine, detects enabled introspection. |
| clairvoyance | public repository | Python | 2.2 | Rebuilds the GraphQL schema even without introspection. |
| graphql-cop | public repository | Python | 2.5, 4.1 | 40+ automated security checks on a GraphQL endpoint. |
| graphql-path-enum | public repository | Python | 3.1 | Enumerates paths and injection points in GraphQL. |
| BatchQL | public repository | Python | 7.1 | Tests batching abuse against GraphQL rate limiting. |

**gRPC**

| Tool | Repository | Language | Equivalent test | Function |
|---|---|---|---|---|
| grpcurl | `fullstorydev/grpcurl` | Go | 0.1 | Enumeration through reflection, JSON output. |
| grpc-client-cli | public repository | Go | 3.1 | Fuzzing of gRPC parameters. |
| ghz | `bojand/ghz` | Go | 4.1 | gRPC load testing, the equivalent of vegeta. |

**WebSocket**

| Tool | Repository | Language | Equivalent test | Function |
|---|---|---|---|---|
| websocat | `vi/websocat` | Rust | 1.1, 7.3 | WebSocket CLI: authentication on the upgrade, races. |
| STEWS | public repository | Python | 3.1 | WebSocket security testing framework. |

## Appendix C. Tools reported as outdated or abandoned

Documented for historical completeness and traceability of the sources; **not recommended** for implementation.

| Tool | Reason | Recommended alternative |
|---|---|---|
| astra (`flipkart-incubator/Astra`) | Last commit 2020. | OFFAT, cherrybomb |
| GAP-Burp-Extension | Depends on Burp Suite. | katana + standalone LinkFinder |
| recaptcha-cracker | Not maintained. | Manual test or native Python |
| SSRFfire | Last commit 2021. | SSRFmap approach, native |
| kiterunner (`assetnote/kiterunner`) | Abandoned, no recent commit. | ffuf (A, promoted in v1.3) |
| CRLFuzz (`dwisiswant0/crlfuzz`) | Inactive since 2021. | nuclei CRLF templates |
| smuggler (`defparam/smuggler`) | No tagged official release. | Python standard library sockets (6.3 connector) |
| race-the-web (`TheHackerDev/race-the-web`) | Abandoned, few stars, no recent release. | vegeta (A) |
| jwtXploiter (`DontPanicO/jwtXploiter`) | Last commit five years ago, no recent release. | jwt_tool (A) |
| Gopherus (`tarunkant/Gopherus`) | Last commit four years ago, no release. | nuclei templates |

## Appendix D. Tools for future developments (outside the scope of v1.0)

Valid tools left out of v1.0 for the reasons given; candidates for v2.0.

| Tool | Condition for inclusion | Domain | Notes |
|---|---|---|---|
| APIClarity | Pure black box mode (target without an OpenAPI specification) | 0.1, 2.5 | Runtime traffic analysis. |
| mitmproxy2swagger | Pure black box mode | 0.1 | Reverse engineering of the specification. |
| Arjun / x8 | Pure black box mode | 0.1 | Parameter discovery without a specification. |
| ParamSpider | Pure black box mode | 0.1 | Parameter mining from web archives. |
| metlo | Integration as a sidecar | 0.1, 5.1 | Traffic-based discovery. |
| OWASP Noir | A SAST approach with access to the source | 0.1, 0.2, 0.3 | Needs the source code. |
| playwright | If 7.1 is extended to CAPTCHA simulation | 7.1 | A full browser dependency. |
| graphql-cop | GraphQL targets | 2.5, 4.1 | Outside the scope of v1.0 (REST only). |
| graphw00f, clairvoyance, BatchQL | GraphQL targets | several | Outside the scope of v1.0. |
| grpcurl, ghz | gRPC targets | several | Outside the scope of v1.0. |
| websocat, STEWS | WebSocket targets | several | Outside the scope of v1.0. |
| RESTler-fuzzer | Stateful fuzzing engine for complex object-level authorization cases | 2.2, 7.1, 7.4 | Needs a C# runtime; too heavy for v1.0. |
| http2smugl | Targets exposing HTTP/2 (from B in 6.3 to A) | 6.3 | Already B; conditional promotion. |

## Appendix E. Confidence matrix

The primary operational tools for each test, by category. **Version 1.4**, aligned with the decisions v3.0.

Changes with respect to v1.3: 0.1 kiterunner replaced by ffuf (A), removed from B; 1.2 jwtXploiter removed from B;
3.1 CRLFuzz removed from A; 6.3 smuggler removed from A, A now on Python standard library sockets, http2smugl added
to B; 7.2 Gopherus removed from B; 7.3 race-the-web removed from A, vegeta promoted to A and shared.

| Test | Cat. A (mandatory) | Cat. B (optional) | Classification |
|---|---|---|---|
| 0.1 | ffuf, katana, nuclei | gau, cherrybomb | HYBRID |
| 0.2 | - | cherrybomb | NATIVE |
| 0.3 | - | oasdiff | NATIVE |
| 1.1 | - | - | NATIVE |
| 1.2 | jwt_tool | - | HYBRID |
| 1.3 | jwt_tool | - | HYBRID |
| 1.4 | - | - | NATIVE |
| 1.5 | testssl.sh | sslyze | HYBRID |
| 1.6 | - | - | NATIVE |
| 2.1 | - | - | NATIVE |
| 2.2 | - | OFFAT, cherrybomb | NATIVE |
| 2.3 | - | OFFAT | NATIVE |
| 2.4 | - | - | NATIVE |
| 2.5 | - | - | NATIVE |
| 3.1 | Schemathesis, nuclei | sqlmap, NoSQLMap, Dalfox, commix, SSTImap | HYBRID |
| 3.3 | - | - | NATIVE |
| 4.1 | vegeta | - | HYBRID |
| 4.2 | - | - | NATIVE |
| 4.3 | - | - | NATIVE |
| 5.1 | - | - | NATIVE |
| 5.2 | - | - | NATIVE |
| 6.1 | - | - | NATIVE |
| 6.2 | - | - | NATIVE |
| 6.3 | - (Python standard library sockets) | http2smugl | HYBRID |
| 6.4 | - | trufflehog, gitleaks, detect-secrets | NATIVE |
| 7.1 | - | - | NATIVE |
| 7.2 | nuclei, interactsh | - | HYBRID |
| 7.3 | vegeta | - | HYBRID |
| 7.4 | interactsh | - | HYBRID |

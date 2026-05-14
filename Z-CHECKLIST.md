# APIGuard — Checklist Stato Implementazione

## Legenda

| Simbolo | Significato |
|---------|-------------|
| `[x]`   | Complete: NATIVE/Python code done (Cat B never blocks this), OR HYBRID with **all** planned Cat A connectors implemented. |
| `[~]`   | HYBRID with **at least one** representative Cat A connector done, but additional planned connectors deferred to M2. |
| `[ ]`   | Not yet started or incomplete. |

Cat B connectors never influence the symbol — they are always optional enhancements.

**`ext.X.X` naming convention:** any test implemented via an external connector gets the `ext.` prefix. Native tests (`BaseTest` subclasses) never carry it.

---

## Tests Overview

| ID | Milestone | Status |
|----|-----------|--------|
| 0.1 | M1 | [x] |
| ext.0.1 | M1 | [~] |
| 0.2 | M1 | [x] |
| 0.3 | M1 | [x] |
| 1.1 | M1 | [x] |
| 1.4 | M1 | [ ] |
| 1.5 | M1 | [x] |
| ext.1.5 | M1 | [x] |
| 1.6 | M1 | [x] |
| 3.3 | M1 | [x] |
| 4.1 | M1 | [x] |
| 4.2 | M1 | [x] |
| 4.3 | M1 | [x] |
| 6.2 | M1 | [x] |
| 6.4 | M1 | [x] |
| 7.2 | M1 | [x] |
| ext.0.1 ffuf | M2 | [ ] |
| ext.0.1 katana | M2 | [ ] |
| 1.2 | M2 | [ ] |
| ext.1.2 | M2 | [ ] |
| 1.3 | M2 | [ ] |
| ext.1.3 | M2 | [ ] |
| 2.1 | M2 | [ ] |
| 2.2 | M2 | [ ] |
| 2.3 | M2 | [ ] |
| 2.4 | M2 | [ ] |
| 2.5 | M2 | [ ] |
| 3.1 | M2 | [ ] |
| ext.3.1 | M2 | [ ] |
| ext.4.1 | M2 | [ ] |
| 5.1 | M2 | [ ] |
| 5.2 | M2 | [ ] |
| 6.3 | M2 | [ ] |
| ext.6.3 | M2 | [ ] |
| ext.7.2 | M2 | [ ] |
| 7.3 | M2 | [ ] |
| ext.7.3 | M2 | [ ] |
| 7.4 | M2 | [ ] |
| ext.7.4 | M2 | [ ] |

---

## MILESTONE 1 — Pre-Thesis Writing

**Scope.** Tests selected for architectural property demonstration value.
Selection criterion: which test provides the most concrete and verifiable evidence for the
architectural claims in `docs/apiguard_property.md`. Security coverage is secondary.

### Domain 0 — API Discovery & Inventory

| ID | Type | Status | Strategy / Priority | Key Properties |
|----|------|--------|---------------------|----------------|
| 0.1 | NATIVE+OPT | [x] | BLACK_BOX / P0 | P01, P05 |
| ext.0.1 | HYBRID / nuclei | [~] | BLACK_BOX / P0 | P07, P08, P09, P10, P24, P25 |
| 0.2 | NATIVE+OPT | [x] | BLACK_BOX / P0 | P01 |
| 0.3 | NATIVE+OPT | [x] | BLACK_BOX / P0 | P01 |

Files: `src/external_tests/ext_test_0_1_shadow_api_nuclei.py`, `src/connectors/nuclei.py`

### Domain 1 — Identity & Authentication

| ID | Type | Status | Strategy / Priority | Key Properties |
|----|------|--------|---------------------|----------------|
| 1.1 | NATIVE | [x] | BLACK_BOX / P0 | P01, P06-PhaseA, P11, P31, P32, P35 |
| 1.4 | NATIVE | **[ ]** | GREY_BOX / P2 | P04, P06-PhaseB, P19, P21, P33 |
| 1.5 | NATIVE | [x] | WHITE_BOX / P2 | P21 |
| ext.1.5 | HYBRID / testssl | [x] | WHITE_BOX / P2 | P07, P08, P09, P10, P21, P25 |
| 1.6 | NATIVE | [x] | WHITE_BOX / P3 | P19, P21 |

Files: `src/external_tests/ext_test_1_5_tls_analysis.py`, `src/connectors/testssl.py`

### Domain 3 — Data Integrity

| ID | Type | Status | Strategy / Priority | Key Properties |
|----|------|--------|---------------------|----------------|
| 3.3 | NATIVE | [x] | WHITE_BOX / P3 | P18, P15 |

### Domain 4 — Availability & Resilience

| ID | Type | Status | Strategy / Priority | Key Properties |
|----|------|--------|---------------------|----------------|
| 4.1 | NATIVE+OPT | [x] | BLACK_BOX / P0 | P31 |
| 4.2 | NATIVE | [x] | WHITE_BOX / P1 | P18, P15 |
| 4.3 | NATIVE | [x] | WHITE_BOX / P1 | P18, P23, P15 |

### Domain 6 — Configuration & Hardening

| ID | Type | Status | Strategy / Priority | Key Properties |
|----|------|--------|---------------------|----------------|
| 6.2 | NATIVE | [x] | WHITE_BOX / P3 | P21, P26 |
| 6.4 | NATIVE+OPT | [x] | WHITE_BOX / P2 | P18, P32 |

### Domain 7 — Business Logic & Sensitive Flows

| ID | Type | Status | Strategy / Priority | Key Properties |
|----|------|--------|---------------------|----------------|
| 7.2 | NATIVE+OPT | [x] | GREY_BOX / P0 | P21, P32 |

---

### DAG State After Milestone 1 Completion

| Phase | Tests |
|-------|-------|
| **A — No Dependencies** | 0.1, ext.0.1, 0.2, 0.3, 1.1, 1.5, ext.1.5, 1.6, 3.3, 4.1, 4.2, 4.3, 6.2, 6.4, 7.2 |
| **B — requires 1.1** | **1.4** |

Phase C (requires ext.1.2 / jwt_tool connector) → Milestone 2.

### Strategy Coverage

| Strategy | Tests |
|----------|-------|
| BLACK_BOX | 0.1, ext.0.1, 0.2, 0.3, 1.1, 4.1 |
| GREY_BOX | 7.2, **1.4** |
| WHITE_BOX | 1.5, ext.1.5, 1.6, 3.3, 4.2, 4.3, 6.2, 6.4 |

---

## MILESTONE 2 — Future Work (Thesis Chapter)

Research-grounded extensions mapped to architectural extension points already in the design.
Not omissions — honest scope decisions for the July deadline.

### Domain 0 — Shadow API Discovery (extended tooling)

| ID | Type | Status | Strategy | Notes |
|----|------|--------|----------|-------|
| ext.0.1 ffuf | HYBRID / ffuf | [ ] | BLACK_BOX | `FfufConnector` — wordlist path fuzzing; demonstrates connector reusability across tools for same domain |
| ext.0.1 katana | HYBRID / katana | [ ] | BLACK_BOX | `KatanaConnector` — headless crawling for JS-rendered endpoints (vs static wordlist) |

### Domain 1 — JWT & Credential Lifecycle

| ID | Type | Status | Strategy | Notes |
|----|------|--------|----------|-------|
| 1.2 | NATIVE | [ ] | BLACK_BOX | Basic JWT structure validation; `depends_on=["1.1"]` |
| ext.1.2 | HYBRID / jwt_tool | [ ] | BLACK_BOX | Crypto-level JWT check via jwt_tool; blocked by jwt_tool Cat A |
| 1.3 | NATIVE | [ ] | BLACK_BOX | Credential expiry check; `depends_on=["1.1"]` |
| ext.1.3 | HYBRID / jwt_tool | [ ] | BLACK_BOX | Shares jwt_tool with ext.1.2 (P10 connector sharing); blocked by jwt_tool Cat A |

### Domain 2 — Authorization (Phase C — requires 1.2)

| ID | Type | Status | Strategy | Notes |
|----|------|--------|----------|-------|
| 2.1 | NATIVE | [ ] | GREY_BOX | Canonical multi-role demo; ROLE_ADMIN + ROLE_USER_A + ROLE_USER_B (P04, P19) |
| 2.2 | NATIVE+OPT | [ ] | GREY_BOX | Cat B: OFFAT, cherrybomb |
| 2.3 | NATIVE+OPT | [ ] | GREY_BOX | Cat B: OFFAT |
| 2.4 | NATIVE | [ ] | GREY_BOX | — |
| 2.5 | NATIVE | [ ] | GREY_BOX | — |

### Domain 3 — Injection

| ID | Type | Status | Strategy | Notes |
|----|------|--------|----------|-------|
| 3.1 | NATIVE | [ ] | BLACK_BOX | Basic input validation checks |
| ext.3.1 | HYBRID / schemathesis | [ ] | BLACK_BOX | `schemathesis` BaseLibraryConnector (P08 tier not in M1) + nuclei CRLF templates |

### Domain 4 — Rate Limiting Extended

| ID | Type | Status | Strategy | Notes |
|----|------|--------|----------|-------|
| ext.4.1 | HYBRID / vegeta | [ ] | BLACK_BOX | `VegetaConnector` — precise load + last-byte-sync; shared with 7.3 (P10) |

### Domain 5 — Observability

| ID | Type | Status | Strategy | Notes |
|----|------|--------|----------|-------|
| 5.1 | NATIVE | [ ] | WHITE_BOX | ⚠ Needs log aggregator (Elasticsearch/Loki) in Docker setup |
| 5.2 | NATIVE | [ ] | WHITE_BOX | ⚠ Needs alerting system (Alertmanager/PagerDuty mock) |

### Domain 6 — HTTP Request Smuggling

| ID | Type | Status | Strategy | Notes |
|----|------|--------|----------|-------|
| 6.3 | NATIVE | [ ] | BLACK_BOX | Basic HTTP request smuggling detection |
| ext.6.3 | HYBRID / tcp-socket | [ ] | BLACK_BOX | Raw TCP socket (stdlib) for CL.TE/TE.CL — 3rd P08 connector tier (not subprocess, not library). Cat B: http2smugl |

### Domain 7 — Race Condition, Unsafe Consumption, SSRF Extended

| ID | Type | Status | Strategy | Notes |
|----|------|--------|----------|-------|
| ext.7.2 | HYBRID / nuclei+interactsh | [ ] | GREY_BOX | nuclei SSRF templates + `InteractshConnector` OOB; extends native 7.2 with blind SSRF |
| 7.3 | NATIVE | [ ] | GREY_BOX | Race condition detection; `depends_on=["1.1"]` |
| ext.7.3 | HYBRID / vegeta | [ ] | GREY_BOX | vegeta shared with ext.4.1 (P10 cross-domain); `depends_on=["1.1"]` |
| 7.4 | NATIVE | [ ] | GREY_BOX | Unsafe external consumption; `depends_on=["1.1"]` |
| ext.7.4 | HYBRID / interactsh | [ ] | GREY_BOX | interactsh stateful OOB; extends P07; `depends_on=["1.1"]` |

---

## Connectors

### Cat A — Implemented (Milestone 1)

| Connector | Pinned Version | Type | Used by |
|-----------|---------------|------|---------|
| **nuclei** | `3.8.0` / templates `10.4.3` | Subprocess | ext.0.1 |
| **testssl.sh** | `3.2.x` | Subprocess | ext.1.5 |

Source: `src/connectors/nuclei.py` + `src/connectors/testssl.py` — both fully implemented.

### Cat A — Not Yet Implemented (Milestone 2)

| Connector | Pinned Version | Type | Tests | Notes |
|-----------|---------------|------|-------|-------|
| **jwt_tool** | `2.3.0` | Subprocess | ext.1.2, ext.1.3 | Unlocks all Phase C tests |
| **ffuf** | `2.1.0` | Subprocess | ext.0.1 ffuf | — |
| **katana** | `1.6.1` | Subprocess | ext.0.1 katana | — |
| **vegeta** | `12.13.0` | Subprocess | ext.4.1, ext.7.3 | last-byte-sync for race condition |
| **interactsh** | `1.3.1` | Subprocess | ext.7.2, ext.7.4 | OOB server for blind SSRF/consumption |
| **schemathesis** | `4.18.1` | Library | ext.3.1 | BaseLibraryConnector tier demo |

### Cat B — All Deferred (Milestone 2)

| Connector | For | Value |
|-----------|-----|-------|
| cherrybomb | 0.2, 2.2 | SAST on OpenAPI spec |
| OFFAT | 2.2, 2.3 | Auto-generation of IDOR/DELETE tests from spec |
| oasdiff | 0.3 | Semantic diff between spec versions; handles `$ref`/`allOf` edge cases |
| trufflehog | 6.4 | 800+ community-maintained secret regex patterns |
| gitleaks | 6.4 | Commit history scanning |
| detect-secrets | 6.4 | Python library; pre-commit hook integration |
| gau | 0.1 | Passive URL mining (Wayback Machine, Common Crawl) |
| sslyze | 1.5 | Pure-Python TLS fallback (BaseLibraryConnector) when testssl.sh unavailable |
| http2smugl | ext.6.3 | H2 downgrade smuggling coverage (Cat B until target exposes HTTP/2) |

> **Connector decision log:**
> `kiterunner` removed (abandoned) → `ffuf` promoted from Cat B.
> `crlfuzz` removed (abandoned) → CRLF coverage via nuclei template `crlf-injection`.
> `smuggler` removed (no official release) → raw socket Python connector for CL.TE / TE.CL.
> `race-the-web` removed (abandoned) → `vegeta` covers 4.1 (volume) and 7.3 (last-byte sync).
> `jwtXploiter` removed (5 years unmaintained) → `jwt_tool` covers same attack variants.
> `Gopherus` removed (abandoned) → Gopher SSRF payload coverage via nuclei templates.

---

## TODO — Milestone 1 Remaining Tasks

### 1.4 Token Revocation `(NATIVE, GREY_BOX/P2)`

1. Acquire ADMIN token via `acquire_tokens()`
2. Call `DELETE /api/v1/users/{user}/tokens/{name}`
3. Re-attempt authenticated request with the revoked token
4. PASS if 401/403, FAIL if 2xx

Engine: add `RuntimeTest14Config` in `engine.py` Phase 3 (standard procedure for any new test).
DAG: `depends_on = ["1.1"]` — places this test in Phase B.

---

### 2.1 RBAC Endpoint Privilege `(NATIVE, GREY_BOX/P2)` — implement after 1.4

1. Acquire tokens for ROLE_ADMIN, ROLE_USER_A, ROLE_USER_B via `acquire_tokens()`
2. Identify admin-only endpoints from `target.attack_surface`
3. Probe each with ROLE_USER_A token
4. PASS if 403 on all, FAIL if any returns 2xx

Engine: add `RuntimeTest21Config` in `engine.py` Phase 3.
DAG: `depends_on = ["1.1"]` — Phase B (does not require jwt_tool; authorization check is orthogonal to JWT crypto).
Note: once implemented, move from M2 → M1 in this checklist and update Overview table.

---

### ext.1.5 sslyze `(HYBRID / sslyze, WHITE_BOX/P2)` — implement after 2.1

Independent TLS evaluation alongside ext.1.5 (testssl.sh) — both run, both produce results.
Not a fallback: two tools, two connector tiers, same property verified from different angles.

**File:** `src/external_tests/ext_test_1_5_tls_analysis.py` (existing — add second class, update module docstring).
**New class:** `ExtTest15SslyzeAnalysis(ExternalToolTest)` alongside the existing `ExtTest15TlsAnalysis`.
The registry discovers both automatically via subclass scan — no registration needed.

1. Create `SslyzeConnector(BaseLibraryConnector)` in `src/connectors/sslyze.py`
2. Add `ExtTest15SslyzeAnalysis` to `ext_test_1_5_tls_analysis.py`: `test_id = "ext.1.5 sslyze"`, `tool_name = "sslyze"`
3. `_evaluate()` maps sslyze scan results to the same PASS/FAIL oracle as `ExtTest15TlsAnalysis`
4. Update module docstring to describe both classes and their relationship
5. Both results appear independently in the report for Domain 1

Architectural value: first concrete `BaseLibraryConnector` implementation — closes P08 Tier 3 empirically in M1.
Connector: promote `sslyze` from Cat B → Cat A; update connector tables accordingly.
Note: once implemented, add `ext.1.5 sslyze` to M1 Domain 1 table and Overview.

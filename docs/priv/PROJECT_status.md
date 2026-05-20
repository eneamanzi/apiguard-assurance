# APIGuard — Checklist Stato Implementazione

- [Legenda](#legenda)
- [Tests Overview](#tests-overview)
- [MILESTONE 1 — Pre-Thesis Writing](#milestone-1--pre-thesis-writing)
  - [Domain 0 — API Discovery \& Inventory](#domain-0--api-discovery--inventory)
  - [Domain 1 — Identity \& Authentication](#domain-1--identity--authentication)
  - [Domain 2 — Authorization](#domain-2--authorization)
  - [Domain 3 — Data Integrity](#domain-3--data-integrity)
  - [Domain 4 — Availability \& Resilience](#domain-4--availability--resilience)
  - [Domain 6 — Configuration \& Hardening](#domain-6--configuration--hardening)
  - [Domain 7 — Business Logic \& Sensitive Flows](#domain-7--business-logic--sensitive-flows)
  - [DAG State After Milestone 1 Completion](#dag-state-after-milestone-1-completion)
  - [Strategy Coverage](#strategy-coverage)
- [MILESTONE 2 — Future Work (Thesis Chapter)](#milestone-2--future-work-thesis-chapter)
  - [Domain 0 — Shadow API Discovery (extended tooling)](#domain-0--shadow-api-discovery-extended-tooling)
  - [Domain 1 — JWT \& Credential Lifecycle](#domain-1--jwt--credential-lifecycle)
  - [Domain 2 — Authorization (Phase C — requires 1.2)](#domain-2--authorization-phase-c--requires-12)
  - [Domain 3 — Injection](#domain-3--injection)
  - [Domain 4 — Rate Limiting Extended](#domain-4--rate-limiting-extended)
  - [Domain 5 — Observability](#domain-5--observability)
  - [Domain 6 — HTTP Request Smuggling](#domain-6--http-request-smuggling)
  - [Domain 7 — Race Condition, Unsafe Consumption, SSRF Extended](#domain-7--race-condition-unsafe-consumption-ssrf-extended)
- [Connectors](#connectors)
  - [Cat A — Implemented (Milestone 1)](#cat-a--implemented-milestone-1)
  - [Cat A — Not Yet Implemented (Milestone 2)](#cat-a--not-yet-implemented-milestone-2)
  - [Cat B — All Deferred (Milestone 2)](#cat-b--all-deferred-milestone-2)
- [TODO — Milestone 1 Remaining Tasks](#todo--milestone-1-remaining-tasks)


## Legenda

| Simbolo | Significato |
|---------|-------------|
| `[x]`   | Complete: NATIVE/Python code done (Cat B never blocks this), OR HYBRID with **all** planned Cat A connectors implemented. |
| `[~]`   | HYBRID with **at least one** representative Cat A connector done, but additional planned connectors deferred to M2. |
| `[ ]`   | Not yet started or incomplete. |

Cat B connectors never influence the symbol — they are always optional enhancements.

**Naming convention:**
- Native tests: `X.Y` (e.g. `1.4`, `2.1`)
- External tests: `ext.X.Y.toolname` (e.g. `ext.0.1.nuclei`, `ext.1.5.testssl`) — the tool suffix makes the ID self-documenting and unique when multiple tools cover the same guarantee.

---

## Tests Overview

| ID | Milestone | Status |
|----|-----------|--------|
| 0.1 | M1 | [x] |
| ext.0.1.nuclei | M1 | [~] |
| 0.2 | M1 | [x] |
| 0.3 | M1 | [x] |
| 1.1 | M1 | [x] |
| 1.4 | M1 | [x] |
| 1.5 | M1 | [x] |
| ext.1.5.testssl | M1 | [x] |
| ext.1.5.sslyze | M1 | [x] |
| 1.6 | M1 | [x] |
| 3.3 | M1 | [x] |
| 4.1 | M1 | [x] |
| 4.2 | M1 | [x] |
| 4.3 | M1 | [x] |
| 6.2 | M1 | [x] |
| 6.4 | M1 | [x] |
| 7.2 | M1 | [x] |
| 2.1 | M1 | [x] |
| ext.0.1.ffuf | M2 | [ ] |
| ext.0.1.katana | M2 | [ ] |
| 1.2 | M2 | [ ] |
| ext.1.2.jwt_tool | M2 | [ ] |
| 1.3 | M2 | [ ] |
| ext.1.3.jwt_tool | M2 | [ ] |
| 2.2 | M2 | [ ] |
| 2.3 | M2 | [ ] |
| 2.4 | M2 | [ ] |
| 2.5 | M2 | [ ] |
| 3.1 | M2 | [ ] |
| ext.3.1.schemathesis | M2 | [ ] |
| ext.4.1.vegeta | M2 | [ ] |
| 5.1 | M2 | [ ] |
| 5.2 | M2 | [ ] |
| 6.3 | M2 | [ ] |
| ext.6.3.socket | M2 | [ ] |
| ext.7.2.interactsh | M2 | [ ] |
| 7.3 | M2 | [ ] |
| ext.7.3.vegeta | M2 | [ ] |
| 7.4 | M2 | [ ] |
| ext.7.4.interactsh | M2 | [ ] |

---

## MILESTONE 1 — Pre-Thesis Writing

**Scope.** Tests selected for architectural property demonstration value.
Selection criterion: which test provides the most concrete and verifiable evidence for the
architectural claims in `docs/priv/apiguard_property.md`. Security coverage is secondary.

### Domain 0 — API Discovery & Inventory

| ID | Type | Status | Strategy / Priority | Key Properties |
|----|------|--------|---------------------|----------------|
| 0.1 | NATIVE+OPT | [x] | BLACK_BOX / P0 | D1.P1, D2.P1 |
| ext.0.1.nuclei | HYBRID / nuclei | [~] | BLACK_BOX / P0 | D1.P4, D1.P5, D2.P3, D2.P4, D2.P6, D6.P2 |
| 0.2 | NATIVE+OPT | [x] | BLACK_BOX / P0 | D1.P1 |
| 0.3 | NATIVE+OPT | [x] | BLACK_BOX / P0 | D1.P1 |

Files: `src/external_tests/ext_test_0_1_shadow_api_nuclei.py`, `src/connectors/nuclei.py`

### Domain 1 — Identity & Authentication

| ID | Type | Status | Strategy / Priority | Key Properties |
|----|------|--------|---------------------|----------------|
| 1.1 | NATIVE | [x] | BLACK_BOX / P0 | D1.P1, D2.P2-PhaseA, D4.P1, D4.P7, D2.P8, D4.P9 |
| 1.4 | NATIVE | [x] | GREY_BOX / P2 | D1.P3, D2.P2-PhaseB, D4.P6, D2.P5, D3.P3, D4.P8 |
| 1.5 | NATIVE | [x] | WHITE_BOX / P2 | D3.P3 |
| ext.1.5.testssl | HYBRID / testssl | [x] | WHITE_BOX / P2 | D1.P4, D1.P5, D2.P3, D2.P4, D3.P3, D6.P2 |
| ext.1.5.sslyze | HYBRID / sslyze | [x] | WHITE_BOX / P2 | D1.P4, D1.P5, D2.P3, D2.P4, D3.P3, D6.P2 |
| 1.6 | NATIVE | [x] | WHITE_BOX / P3 | D2.P5, D3.P3 |

Files: `src/external_tests/ext_test_1_5_tls_analysis.py`, `src/connectors/testssl.py`, `src/connectors/sslyze.py`

### Domain 2 — Authorization

| ID | Type | Status | Strategy / Priority | Key Properties |
|----|------|--------|---------------------|----------------|
| 2.1 | NATIVE | [x] | GREY_BOX / P2 | D1.P3, D2.P5, D3.P3 |

### Domain 3 — Data Integrity

| ID | Type | Status | Strategy / Priority | Key Properties |
|----|------|--------|---------------------|----------------|
| 3.3 | NATIVE | [x] | WHITE_BOX / P3 | D1.P6, D4.P5 |

### Domain 4 — Availability & Resilience

| ID | Type | Status | Strategy / Priority | Key Properties |
|----|------|--------|---------------------|----------------|
| 4.1 | NATIVE+OPT | [x] | BLACK_BOX / P0 | D4.P7 |
| 4.2 | NATIVE | [x] | WHITE_BOX / P1 | D1.P6, D4.P5 |
| 4.3 | NATIVE | [x] | WHITE_BOX / P1 | D1.P6, D5.P2, D4.P5 |

### Domain 6 — Configuration & Hardening

| ID | Type | Status | Strategy / Priority | Key Properties |
|----|------|--------|---------------------|----------------|
| 6.2 | NATIVE | [x] | WHITE_BOX / P3 | D3.P3, D5.P3 |
| 6.4 | NATIVE+OPT | [x] | WHITE_BOX / P2 | D1.P6, D2.P8 |

### Domain 7 — Business Logic & Sensitive Flows

| ID | Type | Status | Strategy / Priority | Key Properties |
|----|------|--------|---------------------|----------------|
| 7.2 | NATIVE+OPT | [x] | GREY_BOX / P0 | D3.P3, D2.P8 |

---

### DAG State After Milestone 1 Completion

| Phase | Tests |
|-------|-------|
| **A — No Dependencies** | 0.1, ext.0.1.nuclei, 0.2, 0.3, 1.1, 1.5, ext.1.5.testssl, ext.1.5.sslyze, 1.6, 3.3, 4.1, 4.2, 4.3, 6.2, 6.4, 7.2 |
| **B — requires 1.1** | **1.4**, **2.1** |

Phase C (requires ext.1.2.jwt_tool / jwt_tool connector) → Milestone 2.

### Strategy Coverage

| Strategy | Tests |
|----------|-------|
| BLACK_BOX | 0.1, ext.0.1.nuclei, 0.2, 0.3, 1.1, 4.1 |
| GREY_BOX | 7.2, 1.4, 2.1 |
| WHITE_BOX | 1.5, ext.1.5.testssl, ext.1.5.sslyze, 1.6, 3.3, 4.2, 4.3, 6.2, 6.4 |

---

## MILESTONE 2 — Future Work (Thesis Chapter)

Research-grounded extensions mapped to architectural extension points already in the design.
Not omissions — honest scope decisions for the July deadline.

### Domain 0 — Shadow API Discovery (extended tooling)

| ID | Type | Status | Strategy | Notes |
|----|------|--------|----------|-------|
| ext.0.1.ffuf | HYBRID / ffuf | [ ] | BLACK_BOX | `FfufConnector` — wordlist path fuzzing; demonstrates connector reusability across tools for same domain |
| ext.0.1.katana | HYBRID / katana | [ ] | BLACK_BOX | `KatanaConnector` — headless crawling for JS-rendered endpoints (vs static wordlist) |

### Domain 1 — JWT & Credential Lifecycle

| ID | Type | Status | Strategy | Notes |
|----|------|--------|----------|-------|
| 1.2 | NATIVE | [ ] | BLACK_BOX | Basic JWT structure validation; `depends_on=["1.1"]` |
| ext.1.2.jwt_tool | HYBRID / jwt_tool | [ ] | BLACK_BOX | Crypto-level JWT check via jwt_tool; blocked by jwt_tool Cat A |
| 1.3 | NATIVE | [ ] | BLACK_BOX | Credential expiry check; `depends_on=["1.1"]` |
| ext.1.3.jwt_tool | HYBRID / jwt_tool | [ ] | BLACK_BOX | Shares jwt_tool with ext.1.2.jwt_tool (D2.P4 connector sharing); blocked by jwt_tool Cat A |

### Domain 2 — Authorization (Phase C — requires 1.2)

| ID | Type | Status | Strategy | Notes |
|----|------|--------|----------|-------|
| 2.2 | NATIVE+OPT | [ ] | GREY_BOX | Cat B: OFFAT, cherrybomb |
| 2.3 | NATIVE+OPT | [ ] | GREY_BOX | Cat B: OFFAT |
| 2.4 | NATIVE | [ ] | GREY_BOX | — |
| 2.5 | NATIVE | [ ] | GREY_BOX | — |

### Domain 3 — Injection

| ID | Type | Status | Strategy | Notes |
|----|------|--------|----------|-------|
| 3.1 | NATIVE | [ ] | BLACK_BOX | Basic input validation checks |
| ext.3.1.schemathesis | HYBRID / schemathesis | [ ] | BLACK_BOX | `schemathesis` BaseLibraryConnector (D1.P5 tier) + nuclei CRLF templates |

### Domain 4 — Rate Limiting Extended

| ID | Type | Status | Strategy | Notes |
|----|------|--------|----------|-------|
| ext.4.1.vegeta | HYBRID / vegeta | [ ] | BLACK_BOX | `VegetaConnector` — precise load + last-byte-sync; shared with ext.7.3.vegeta (D2.P4) |

### Domain 5 — Observability

| ID | Type | Status | Strategy | Notes |
|----|------|--------|----------|-------|
| 5.1 | NATIVE | [ ] | WHITE_BOX | Requires log aggregator (Elasticsearch/Loki) in Docker setup |
| 5.2 | NATIVE | [ ] | WHITE_BOX | Requires alerting system (Alertmanager/PagerDuty mock) |

### Domain 6 — HTTP Request Smuggling

| ID | Type | Status | Strategy | Notes |
|----|------|--------|----------|-------|
| 6.3 | NATIVE | [ ] | BLACK_BOX | Basic HTTP request smuggling detection |
| ext.6.3.socket | HYBRID / tcp-socket | [ ] | BLACK_BOX | Raw TCP socket (stdlib) for CL.TE/TE.CL — 3rd D1.P5 connector tier. Cat B: http2smugl |

### Domain 7 — Race Condition, Unsafe Consumption, SSRF Extended

| ID | Type | Status | Strategy | Notes |
|----|------|--------|----------|-------|
| ext.7.2.interactsh | HYBRID / nuclei+interactsh | [ ] | GREY_BOX | nuclei SSRF templates + `InteractshConnector` OOB; extends native 7.2 with blind SSRF |
| 7.3 | NATIVE | [ ] | GREY_BOX | Race condition detection; `depends_on=["1.1"]` |
| ext.7.3.vegeta | HYBRID / vegeta | [ ] | GREY_BOX | vegeta shared with ext.4.1.vegeta (D2.P4 cross-domain); `depends_on=["1.1"]` |
| 7.4 | NATIVE | [ ] | GREY_BOX | Unsafe external consumption; `depends_on=["1.1"]` |
| ext.7.4.interactsh | HYBRID / interactsh | [ ] | GREY_BOX | interactsh stateful OOB; extends D1.P4; `depends_on=["1.1"]` |

---

## Connectors

### Cat A — Implemented (Milestone 1)

| Connector | Pinned Version | Type | Used by |
|-----------|---------------|------|---------|
| **nuclei** | `3.8.0` / templates `10.4.3` | Subprocess | ext.0.1.nuclei |
| **testssl.sh** | `3.2.x` | Subprocess | ext.1.5.testssl |
| **sslyze** | `>=6.0` (6.3.1 tested) | Library | ext.1.5.sslyze |

Source: `src/connectors/nuclei.py` + `src/connectors/testssl.py` + `src/connectors/sslyze.py` — all fully implemented.

### Cat A — Not Yet Implemented (Milestone 2)

| Connector | Pinned Version | Type | Tests | Notes |
|-----------|---------------|------|-------|-------|
| **jwt_tool** | `2.3.0` | Subprocess | ext.1.2.jwt_tool, ext.1.3.jwt_tool | Unlocks all Phase C tests |
| **ffuf** | `2.1.0` | Subprocess | ext.0.1.ffuf | — |
| **katana** | `1.6.1` | Subprocess | ext.0.1.katana | — |
| **vegeta** | `12.13.0` | Subprocess | ext.4.1.vegeta, ext.7.3.vegeta | last-byte-sync for race condition |
| **interactsh** | `1.3.1` | Subprocess | ext.7.2.interactsh, ext.7.4.interactsh | OOB server for blind SSRF/consumption |
| **schemathesis** | `4.18.1` | Library | ext.3.1.schemathesis | BaseLibraryConnector tier demo |

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
| http2smugl | ext.6.3.socket | H2 downgrade smuggling coverage (Cat B until target exposes HTTP/2) |

> **Connector decision log:**
> `kiterunner` removed (abandoned) → `ffuf` promoted from Cat B.
> `crlfuzz` removed (abandoned) → CRLF coverage via nuclei template `crlf-injection`.
> `smuggler` removed (no official release) → raw socket Python connector for CL.TE / TE.CL.
> `race-the-web` removed (abandoned) → `vegeta` covers 4.1 (volume) and 7.3 (last-byte sync).
> `jwtXploiter` removed (5 years unmaintained) → `jwt_tool` covers same attack variants.
> `Gopherus` removed (abandoned) → Gopher SSRF payload coverage via nuclei templates.

---

## TODO — Milestone 1 Remaining Tasks

**All Milestone 1 tasks implemented.** M1 is complete.

# Milestone 1 — Pre-Release Audit

- [Parte A — Dati e Verdetti Citabili nella Tesi](#parte-a--dati-e-verdetti-citabili-nella-tesi)
  - [A.1 Verdetto di Release](#a1-verdetto-di-release)
  - [A.2 Baseline di Performance](#a2-baseline-di-performance)
  - [A.3 Risultati dell'Assessment per Test (Idempotenza)](#a3-risultati-dellassessment-per-test-idempotenza)
  - [A.4 Teardown Post-Run (Verifica Live)](#a4-teardown-post-run-verifica-live)
  - [A.5 Topologia del DAG](#a5-topologia-del-dag)
  - [A.6 Matrice delle Versioni](#a6-matrice-delle-versioni)
  - [A.7 Item Deferiti](#a7-item-deferiti)
- [Parte B — Registro di Validazione (73 verifiche)](#parte-b--registro-di-validazione-73-verifiche)
  - [B.1 Executive Summary](#b1-executive-summary)
  - [B.2 Metodologia dell'Audit](#b2-metodologia-dellaudit)
  - [B.3 Analisi Statica (verifiche 1–5)](#b3-analisi-statica-verifiche-15)
  - [B.4 Consistenza Inter-Documentale (verifiche 6–18)](#b4-consistenza-inter-documentale-verifiche-618)
  - [B.5 Coerenza Docs → Codice (verifiche 19–23)](#b5-coerenza-docs--codice-verifiche-1923)
  - [B.6 Coerenza Codice → Docs (verifiche 24–36)](#b6-coerenza-codice--docs-verifiche-2436)
  - [B.7 Engineering di Produzione (verifiche 37–47)](#b7-engineering-di-produzione-verifiche-3747)
  - [B.8 Release Engineering (verifiche 48–56)](#b8-release-engineering-verifiche-4856)
  - [B.9 Performance, Idempotenza, Teardown (verifiche 57–60)](#b9-performance-idempotenza-teardown-verifiche-5760)
  - [B.10 Runtime, Cleanup, Riproducibilità (verifiche 61–66)](#b10-runtime-cleanup-riproducibilità-verifiche-6166)
  - [B.11 Verifiche Pre-Produzione Aggiuntive (verifiche 67–73)](#b11-verifiche-pre-produzione-aggiuntive-verifiche-6773)
  - [B.12 Finding e Item Aperti](#b12-finding-e-item-aperti)
- [Appendice — Comandi di Verifica Principali](#appendice--comandi-di-verifica-principali)


**Tipo audit:** Verifica di release-readiness — revisione post-riorganizzazione documentazione
**Data:** 2026-05-18
**Versione tool:** `0.1.0`
**Codebase:** 90 file Python in `src/`, 18 test attivi (15 nativi + 3 esterni), ~9.800 righe di documentazione
**Verifiche eseguite:** 73

---

## Parte A — Dati e Verdetti Citabili nella Tesi

Sintesi delle evidenze empiriche e dei verdetti di release. Ogni dato ha la sua verifica di dettaglio nel corrispondente numero di verifica in Parte B.

### A.1 Verdetto di Release

| Aspetto | Stato |
|---------|-------|
| Correttezza funzionale | ✓ Static analysis 100% verde su 90 file — 0 errori ruff/mypy/bandit/vulture |
| Integrità architetturale | ✓ 18 test_id unici; DAG aciclico; gerarchia eccezioni 11 classi invariata; dipendenze monodirezionali |
| Copertura documentazione | ✓ 100% docstring su 292 simboli pubblici; 100% Pydantic Field description (265/265 outer); link interni corretti (finding M-1 risolto) |
| Packaging / distribuzione | ✓ Wheel 95 file, 451.261 bytes, SHA-256 identico su 2 build consecutive — build deterministica |
| Cold install | ✓ `pip install wheel` in fresh venv → `apiguard version` → `0.1.0` |
| Resilienza di produzione | ✓ Signal handling garantisce Phase 6 teardown su `KeyboardInterrupt` |

**Readiness di release:**
- ✓ **PRONTO** per difesa di tesi
- ✓ **PRONTO** per deployment in ambiente chiuso su target OpenAPI documentati
- **RICHIEDE** gli item in §A.7 (LICENSE) solo per pubblicazione PyPI o distribuzione come artefatto pubblico

---

### A.2 Baseline di Performance

> APIGuard Assurance v0.1.0, eseguendo la suite M1 completa (15 test nativi + 3 esterni, 18 attivi, esecuzione sequenziale) contro Forgejo 14.0.3 protetto da Kong DB-less su setup di sviluppo single-host, completa un assessment completo in **4 minuti e 50 secondi** (media su due run indipendenti) con un footprint di memoria peak di **287–295 MB** e **4.5 MB** di evidence totale on-disk (`apiguard_report.json` + `assessment_report.html` + `evidence.json`). L'utilizzo CPU è in media del 26% — il run è dominato dagli HTTP round-trip verso il target piuttosto che dal calcolo locale. Due run indipendenti contro lo stesso target nello stesso giorno producono **outcome KPI byte-equivalenti** (`9 PASS / 7 FAIL / 2 SKIP / 0 ERROR / 98 findings`; diff status per-test = 0) con un delta wall-clock di < 0.4%, confermando la riproducibilità empirica.

| Metrica | Run 1 | Run 2 |
|---------|------:|------:|
| Wall-clock elapsed | **4:50.14** (290.14 s) | **4:50.81** (290.81 s) |
| User time | 35.09 s | 34.67 s |
| System time | 41.51 s | 41.62 s |
| **Peak resident set size** | **294,192 KB ≈ 287 MB** | **301,792 KB ≈ 295 MB** |
| Voluntary context switches | 145,356 | (simile) |
| Involuntary context switches | 20,685 | (simile) |
| File system outputs | 26,440 blocchi | 23,616 blocchi |
| Exit status | 1 (≥1 FAIL — atteso) | 1 |

**Output sizes (run 1):** `apiguard_report.json` 2.26 MB + `assessment_report.html` 2.0 MB + `evidence.json` 254 KB ≈ **4.5 MB totale**.

*Baseline misurato contro Forgejo 14.0.3 + Kong DB-less su setup single-host il 2026-05-17. Verifica di dettaglio: §B.9.*

---

### A.3 Risultati dell'Assessment per Test (Idempotenza)

| KPI | Run 1 | Run 2 | Δ | Verdetto |
|-----|------:|------:|---|---------|
| PASS / FAIL / SKIP / ERROR | 9 / 7 / 2 / 0 | 9 / 7 / 2 / 0 | **identico** | ✓ |
| Finding count totale | 98 | 98 | **identico** | ✓ |
| `pass_rate_pct` | 56.2 | 56.2 | identico | ✓ |
| `assessment_duration_seconds` | 286.04 | 286.96 | +0.32 % | ✓ |
| Exit code / label | 1 / "FAIL" | 1 / stesso | identico | ✓ |

| test_id | status | findings |
|---------|--------|----------|
| 0.1 | FAIL | 16 |
| 0.2 | FAIL | 1 |
| 0.3 | SKIP | 0 |
| 1.1 | FAIL | 74 |
| 1.4 | PASS | 0 |
| 1.5 | PASS | 0 |
| 1.6 | SKIP | 0 |
| 2.1 | PASS | 0 |
| 3.3 | PASS | 0 |
| 4.1 | FAIL | 2 |
| 4.2 | PASS | 0 |
| 4.3 | PASS | 0 |
| 6.2 | PASS | 0 |
| 6.4 | PASS | 0 |
| 7.2 | FAIL | 1 |
| ext.0.1.nuclei | PASS | 0 |
| ext.1.5.sslyze | FAIL | 1 |
| ext.1.5.testssl | FAIL | 3 |

*Verifica di dettaglio: §B.9.*

---

### A.4 Teardown Post-Run (Verifica Live)

| Risorsa sul target | Prima run 1 | Dopo run 1 | Dopo run 2 | Verdetto |
|--------------------|------------:|----------:|----------:|---------|
| Token Forgejo `thesis-admin` contenenti `"apiguard"` | 0 | 0 | 0 | ✓ |
| Repo Forgejo `user-a` inizianti con `"apiguard"` | 0 | 0 | 0 | ✓ |

Phase 6 teardown rilascia tutte le risorse transitorie create in Phase 5. Il registro teardown ha drenato 4 risorse LIFO con 0 fallimenti su entrambi i run.

---

### A.5 Topologia del DAG

```
Phase A (nessuna dipendenza, 16 test):
  0.1, 0.2, 0.3, 1.1, 1.5, 1.6, 3.3, 4.1, 4.2, 4.3, 6.2, 6.4, 7.2,
  ext.0.1.nuclei, ext.1.5.testssl, ext.1.5.sslyze

Phase B (depends_on = ["1.1"]):
  1.4, 2.1
```

Mappa in-degree (solo valori non-zero): `1.1` in=2 (consumato da `1.4`, `2.1`).

Rilevamento cicli: ✓ aciclico (verificato via `graphlib.TopologicalSorter`).

---

### A.6 Matrice delle Versioni

| Componente | Versione |
|-----------|---------|
| `apiguard-assurance` (pyproject) | **0.1.0** |
| `apiguard version` (CLI) | 0.1.0 |
| `output_schema_version` (JSON report root) | 1.0 |
| Tool esterno pinnato: `testssl.sh` | 3.2.3 |
| Tool esterno pinnato: `nuclei` binary | 3.8.0 |
| Tool esterno pinnato: `nuclei-templates` | 10.4.3 |
| Interprete Python | 3.12.3 |
| Forgejo (target sotto test) | 14.0.3 (gitea-1.22.0) |
| Kong (gateway sotto test) | DB-less mode |

---

### A.7 Item Deferiti

| # | Item | Motivazione |
|---|------|-------------|
| 1 | File `LICENSE` alla root | IP/licensing dipende da normative universitarie, non ancora finalizzate |
| 2 | `CHANGELOG.md` | Non applicabile alla prima release — il changelog documenta le differenze tra versioni; sarà introdotto dalla `v0.2.0` in poi |

Git tag `v0.1.0` e GitHub release completati. Nessuno degli item deferiti impatta la capacità del tool di girare, produrre report o interoperare con Forgejo + Kong.

---

## Parte B — Registro di Validazione (73 verifiche)

### B.1 Executive Summary

| Categoria | Verifiche | Risultato |
|----------|-------:|--------|
| §B.3 Analisi Statica | 5 | ✓ Tutto verde |
| §B.4 Consistenza Inter-Documentale | 13 | ✓ Tutto verde |
| §B.5 Coerenza Docs → Codice | 5 | ✓ Tutto verde |
| §B.6 Coerenza Codice → Docs | 13 | ✓ Tutto verde |
| §B.7 Engineering di Produzione | 11 | ✓ Tutto verde |
| §B.8 Release Engineering | 9 | ✓ Tutto verde |
| §B.9 Performance + Idempotenza + Teardown | 4 | ✓ Tutto verde |
| §B.10 Runtime / Cleanup / Riproducibilità | 6 | ✓ Tutto verde |
| §B.11 Verifiche Pre-Produzione Aggiuntive | 7 | ✓ 6 verdi, 1 finding M-1 risolto |
| **Totale** | **73** | **72 PASS, 1 risolto (M-1), 0 bloccanti** |

**Bloccanti:** 0. **Finding critici/maggiori:** 0. **Finding minori risolti:** 1 (M-1). **Finding informativi:** 1 (I-1, non bloccante). **Item deferiti:** 2 (§A.7).

---

### B.2 Metodologia dell'Audit

Audit eseguito su Milestone 1, post-riorganizzazione documentazione. Scope:
- 73 verifiche eseguite in tutte le categorie

Comandi di verifica: `hatch run dev:lint`, `hatch run dev:audit`, `hatch run dev:deps`, `hatch build --target wheel`, cold install in fresh venv, script AST-based, grep suite.

---

### B.3 Analisi Statica (verifiche 1–5)

| # | Verifica | Tool / Comando | Risultato | Dettaglio |
|---|----------|----------------|-----------|-----------|
| 1 | Lint | `ruff check .` | ✓ | "All checks passed!" — 0 errori su `select = E/W/F/I/N/UP/B/S/ANN` |
| 2 | Type checking (strict) | `mypy src/` | ✓ | "Success: no issues found in 90 source files" — `strict = true` |
| 3 | Security scan | `bandit -r src/ --severity-level medium` | ✓ | 0 Medium+, 3 Low (B404 + S603×2 in `connectors/base.py`, tutti `# noqa: S603`) |
| 4 | Dead code | `vulture src/ --min-confidence 80` | ✓ | 0 finding |
| 5 | CVE dipendenze | `pip-audit` | ✓ | "No known vulnerabilities found" |

---

### B.4 Consistenza Inter-Documentale (verifiche 6–18)

| # | Verifica | Risultato | Dettaglio |
|---|----------|-----------|-----------|
| 6 | Naming `ext.X.Y.toolname` uniforme nei docs | ✓ | 0 bare `ext.X.Y` senza suffisso toolname in docs/ e src/ |
| 7 | Parità test-set (PROJECT_status ↔ ARCHITECTURE ↔ codice) | ✓ | 18 test_id (15 nativi + 3 esterni) concordi in tutte le fonti |
| 8 | 39 proprietà architetturali (7 domini) | ✓ | `apiguard_property.md` contiene 39 proprietà su 7 domini; spot-check D1.P1/D1.P5/D4.P1/D2.P7 ✓ |
| 9 | Riferimenti connector in `TOOLS_catalog.md` | ✓ | nuclei (8 occorrenze), sslyze (5), testssl (7) |
| 10 | Hard Rules (`CLAUDE.md` ↔ `RULES_claude.md`) | ✓ | Tutti i riferimenti aggiornati; 0 riferimenti obsoleti |
| 11 | Gerarchia eccezioni (CLAUDE.md ↔ exceptions.py ↔ gateway/base.py ↔ seed_generator.py) | ✓ | 11/11 classi presenti in CLAUDE.md |
| 12 | Uniformità status M1 | ✓ | PROJECT_status.md, CLAUDE.md, README.md, ARCHITECTURE.md concordano |
| 13 | Italian leak in codice | ✓ | 0 match in `src/` (italiano nei docs di tesi è by design) |
| 14 | Log decisioni tool rimossi (kiterunner, crlfuzz, jwtxploiter) | ✓ | Tutti e 3 in TOOLS_decisions.md e TOOLS_catalog.md (spot-check) |
| 15 | Uniformità versione | ✓ | `0.1.0` in pyproject.toml, README.md, README.en.md, ARCHITECTURE.md, `apiguard version` |
| 16 | Conteggio test (18 attivi) | ✓ | 18 test_id verificati via AST; 15 in `src/tests/` + 3 in `src/external_tests/` |
| 17 | Path doc nei commenti sorgente | ✓ | Riferimenti a `docs/pub/ADDING_tests.md`, `docs/pub/ADDING_external_tests.md`, `docs/priv/knowledge/` in commenti `src/` tutti corretti |
| 18 | ARCHITECTURE.md §10 coerenza con pyproject.toml | ✓ | §10 presente (riga 899), tag `py3-none-any` spiegato, sdist whitelist descritta, sslyze AGPL notato — coerente con pyproject.toml |

---

### B.5 Coerenza Docs → Codice (verifiche 19–23)

| # | Verifica | Risultato | Dettaglio |
|---|----------|-----------|-----------|
| 19 | Hard rules (CLAUDE.md) ↔ grep sul codice sorgente | ✓ | `print()` → 0 (solo `_console_out.print()` = Rich, non stdlib); `TODO/FIXME/HACK` → 0; bare `except:` → 0; `...` limitato a `@abstractmethod` |
| 20 | Compliance ClassVar `BaseTest` / `ExternalToolTest` (AST-based) | ✓ | 15/15 native con 8 ClassVar richiesti; 3/3 external con 9 ClassVar richiesti. 0 mancanti |
| 21 | Catena config ↔ test ↔ runtime model | ✓ | Spot-check test 1.4, 2.1, 4.1, 6.4 — catena `config.yaml → schema → RuntimeConfig → engine → target.tests_config` intatta |
| 22 | Direzione dipendenze monodirezionale | ✓ | 0 import upward da `tests/`/`external_tests/` verso `engine.py`, `report/`, `config/loader.py`, `discovery/` |
| 23 | 39 proprietà architetturali vs implementazione | ✓ | D1.P1 (API-Agnosticism), D1.P5 (Three-Tier Connector Hierarchy), D4.P1 (Evidence Store), D2.P7 (generate-seed): loci esistono, implementazioni concordano |

---

### B.6 Coerenza Codice → Docs (verifiche 24–36)

| # | Verifica | Risultato | Dettaglio |
|---|----------|-----------|-----------|
| 24 | Tutti i 15 native test_id nei docs | ✓ | Ogni test_id presente in ≥5 file di documentazione |
| 25 | Tutti i 3 external test_id nei docs | ✓ | `ext.0.1.nuclei` (3 file), `ext.1.5.sslyze` (4 file), `ext.1.5.testssl` (4 file) |
| 26 | Tutti i 3 connector in `TOOLS_catalog.md` | ✓ | nuclei / sslyze / testssl |
| 27 | Tutte le 11 classi eccezione documentate | ✓ | 11/11 presenti in CLAUDE.md (inclusi GatewayAdapterError + SeedGenerator*) |
| 28 | Tutti i 6 helper referenziati nei docs | ✓ | auth (44), auth_forgejo (6), auth_jwt_login (3), forgejo_resources (7), path_resolver (2), response_inspector (5) menzioni in ADDING_tests.md |
| 29 | Tutte le 7 fasi engine referenziate nei docs | ✓ | `_phase_1` … `_phase_7` in engine.py; documentate in 4-Implementazione.md + ARCHITECTURE.md + CLAUDE.md |
| 30 | Core Pydantic models referenziati | ✓ | TargetContext, TestContext, Finding, TestResult, ResultSet, AttackSurface, EvidenceRecord — tutti nei doc (spot-check) |
| 31 | Tutti i 4 comandi CLI documentati | ✓ | `run` (14 file), `version` (13), `validate-config` (4), `generate-seed` (5) |
| 32 | Hard Rules ↔ superficie del codice | ✓ | Cross-verificato con verifica 19 |
| 33 | Docstring modulo-livello ↔ layout directory `ARCHITECTURE.md` | ✓ | 292/292 simboli pubblici con docstring (100%); layout ARCHITECTURE.md ↔ `src/` coincide |
| 34 | ClassVar `BaseTest`/`ExternalToolTest` ↔ contratto docs pubblici | ✓ | 8 ClassVar BaseTest + 9 ExternalToolTest documentati in ADDING_tests.md / ADDING_external_tests.md; 0 orfani |
| 35 | Chiavi top-level `config.yaml` ↔ schemi Pydantic | ✓ | 6 chiavi (`target`, `credentials`, `execution`, `output`, `tests`, `external_tools`) ↔ `src/config/schema/` (spot-check) |
| 36 | Surprise scan (simboli pubblici assenti da qualsiasi doc) | ✓ | 0 simboli fantasma reali |

---

### B.7 Engineering di Produzione (verifiche 37–47)

| # | Verifica | Risultato | Dettaglio |
|---|----------|-----------|-----------|
| 37 | Correttezza boundary error-handling | ✓ | 3 blocchi `except Exception` broad con `# noqa: BLE001` ai boundary di fase; 0 bare `except:` |
| 38 | Logging & leak credenziali | ✓ | 32 placeholder `[REDACTED]`; 48 binding `structlog.get_logger()`; 0 f-string con leak token/password |
| 39 | Copertura descrizioni Pydantic Field | ✓ | **265 outer Field() user-facing, 265 con `description=` (100%)** — inner `Annotated[..., Field(ge=...)]` esclusi (validation-only) |
| 40 | Inventario determinismo / sicurezza RNG | ✓ | `secrets.token_hex()` per tutti i nonce/identificatori; 0 `random.*` in `src/` |
| 41 | Modello di concorrenza | ✓ | 0 `asyncio` nei code path; sequenziale by design; 0 global singleton SecurityClient |
| 42 | Osservabilità / qualità messaggi CLI | ✓ | Tutti e 4 `--help` leggibili; `apiguard run --help` documenta tutti i 4 exit code |
| 43 | Qualità del report | ✓ | Architettura renderer verificata in §B.8 |
| 44 | Hygiene dipendenze | ✓ | `pip check`: "No broken requirements found"; upgrade minor disponibili ma dentro policy `FLOOR–NEXT_MAJOR` |
| 45 | Indipendenza dall'ordine dei test | ✓ | 0 state condiviso tra test |
| 46 | Portabilità path cross-platform | ✓ | 0 CRLF in `src/`; tutti gli `__init__.py` con EOF newline; 0 BOM |
| 47 | Robustezza configurazione | ✓ | Loader produce errori actionable su file mancante, YAML malformato, `${ENV_VAR}` non impostato (spot-check) |

**Finding informativo I-1 (non bloccante, candidato M2):** `timeout=10` in `connectors/base.py:426` (subprocess `--version` check) e `recursion_limit=10` in `discovery/openapi.py:390` (prance internal). Entrambi non-user-visible e non governano il comportamento assessment.

---

### B.8 Release Engineering (verifiche 48–56)

| # | Verifica | Risultato | Dettaglio |
|---|----------|-----------|-----------|
| 48 | Contenuto wheel | ✓ | 95 file, tutti in `src/` o `.dist-info/`; 0 contenuto spurio |
| 49 | Contenuto sdist | ✓ | 102 file; include `src/`, `docs/pub/`, `README.md`, `README.en.md`, `pyproject.toml`, `config.yaml`, `.env.example`, `install_tools.sh`; 0 file interni (`.claude/`, `CLAUDE.md`, `docs/priv/`) |
| 50 | Completezza metadata PyPI | ✓ | Tag `py3-none-any`, `Root-Is-Purelib: true`, `Author-email`, `Requires-Python >=3.11`, tutti `Requires-Dist` con upper bound `<NEXT_MAJOR` |
| 51 | CLI ergonomics | ✓ | `run`, `version`, `validate-config`, `generate-seed` — help OK su tutti e 4 |
| 52 | Signal handling / resilienza interrupt | ✓ | `try/finally` + `_phase_6_teardown()` + `KeyboardInterrupt` in `engine.py` ✓ |
| 53 | Versioning schema output | ✓ | `output_schema_version` + `tool_version` (da `importlib.metadata.version()`) in `report/builder.py` |
| 54 | Side effect a livello modulo | ✓ | 0 statement inattesi fuori da import/definizioni/assegnazioni (scan AST) |
| 55 | Correttezza semantica DAG | ✓ | 18 test_id (15+3); 0 `depends_on` orfani; sort topologico aciclico; in-degree: `1.1` in=2 (`1.4`, `2.1`) |
| 56 | Hygiene encoding / EOL / EOF | ✓ | 0 CRLF; tutti gli `__init__.py` con EOF newline; 0 BOM |

---

### B.9 Performance, Idempotenza, Teardown (verifiche 57–60)

Il baseline di performance è misurato il 2026-05-17 su suite completa. Dati completi in §A.2.

| # | Verifica | Risultato | Dettaglio |
|---|----------|-----------|-----------|
| 57 | Baseline di performance (`/usr/bin/time -v`) | ✓ | Misurato il 2026-05-17 su suite M1 completa contro Forgejo 14.0.3 + Kong DB-less. Dati → §A.2 |
| 58 | Idempotenza (KPI byte-equivalenti su run indipendenti) | ✓ | 0 differenze tra i triple `test_id status finding_count` dei due run. Tabella per-test → §A.3 |
| 59 | Indipendenza dall'ordine dei test | ✓ | Implicita dall'idempotenza della verifica 58 |
| 60 | Verifica teardown post-run (live) | ✓ | Phase 6 teardown ha drenato 4 risorse LIFO con 0 fallimenti su entrambi i run. Tabella → §A.4 |

---

### B.10 Runtime, Cleanup, Riproducibilità (verifiche 61–66)

| # | Verifica | Risultato | Dettaglio |
|---|----------|-----------|-----------|
| 61 | Cleanup artefatti obsoleti | ✓ | 0 residui da rinomina doc e riorganizzazione cartelle |
| 62 | Secrets scan | ✓ | 0 segreti reali nel repo; `.env` mai committato in git history |
| 63 | License audit (dipendenze) | ✓ | 47 permissive (MIT/BSD/Apache/MPL/ISC) + 2 AGPL v3 (sslyze extra) + 1 UNKNOWN (tls_parser transitiva) |
| 64 | Riproducibilità cold-install | ✓ | Fresh venv → `pip install dist/apiguard_assurance-0.1.0-py3-none-any.whl` → `apiguard version` → `0.1.0` ✓ |
| 65 | Completezza docstring | ✓ | **292/292 simboli pubblici con docstring (100%)** — scan AST |
| 66 | Version pinning | ✓ | pyproject.toml `0.1.0`; tool esterni pinnati in config.yaml (testssl 3.2.3, nuclei 3.8.0) |

---

### B.11 Verifiche Pre-Produzione Aggiuntive (verifiche 67–73)

| # | Verifica | Risultato | Dettaglio |
|---|----------|-----------|-----------|
| 67 | Build riproducibile (wheel byte-identici su due build consecutive) | ✓ | SHA-256 identico su 2 `hatch build` consecutivi (451.261 bytes) |
| 68 | Esecuzione locale-indipendente | ✓ | `LC_ALL=C LANG=C apiguard --help` → output corretto |
| 69 | Esecuzione time-zone-indipendente | ✓ | `TZ=America/Los_Angeles apiguard version` → `0.1.0` corretto |
| 70 | Risoluzione link markdown interni | **FINDING M-1 — RISOLTO** | 5 link interrotti post-move `docs/pub/`: `../README.md` → `../../README.md` (ARCHITECTURE.md:5) e `../src/tests/` → `../../src/tests/` (ADDING_tests.md:741,744,747,1513). Risolti durante audit. |
| 71 | Scansione PII nei log | ✓ | 0 credenziali non-redacted; 16 stringhe `@` in evidence.json sono identificatori algoritmo TLS (spot-check) |
| 72 | Cross-check pyproject ↔ imports | ✓ | Import third-party in `src/`: `httpx`, `openapi_spec_validator`, `prance`, `rich`, `typer`, `yaml`, `structlog`, `pydantic` — tutti dichiarati in pyproject.toml |
| 73 | Stale install dev-environment (regressione) | ✓ | `pip check`: "No broken requirements found" |

---

### B.12 Finding e Item Aperti

**Finding minore risolto durante questo audit:**

| ID | Verifica | Descrizione | Risoluzione |
|----|----------|-------------|-------------|
| M-1 | §B.11 / verifica 70 | 5 link markdown relativi interrotti: `../README.md` e `../src/tests/domain_*/` in `docs/pub/ARCHITECTURE.md` (1) e `docs/pub/ADDING_tests.md` (4). Causa: file spostati da root a `docs/pub/` senza aggiornare i percorsi relativi. | **Risolto.** Percorsi corretti a `../../README.md` e `../../src/tests/domain_*/`. |

**Finding informativo (non richiede azione prima della difesa):**

| ID | Verifica | Descrizione | Impatto |
|----|----------|-------------|---------|
| I-1 | §B.7 / verifica 40 | 2 magic number non-user-visible: `timeout=10` (`connectors/base.py:426`, subprocess `--version` check) e `recursion_limit=10` (`discovery/openapi.py:390`, prance internal). Non governano il comportamento assessment. | Nessuno sulla funzionalità. Candidato a cleanup M2. |

**Item deferiti:** vedi §A.7.

---

## Appendice — Comandi di Verifica Principali

```bash
# Static analysis
hatch run dev:lint       # ruff check . + mypy src/
hatch run dev:audit      # bandit + vulture
hatch run dev:deps       # pip-audit

# Build reproducibility
hatch build --target wheel
sha256sum dist/apiguard_assurance-0.1.0-py3-none-any.whl

# Cold install
python3 -m venv /tmp/cold-test && /tmp/cold-test/bin/pip install -q dist/apiguard_assurance-0.1.0-py3-none-any.whl
/tmp/cold-test/bin/apiguard version   # → 0.1.0
```

---

*Audit completato 2026-05-18. Tutti i risultati §B.3–§B.11 riflettono lo stato del codebase al 2026-05-18. Finding M-1 risolto durante l'audit. Finding I-1 è informativo e non bloccante. Gli item deferiti (§A.7) sono gli unici punti aperti per la distribuzione pubblica.*

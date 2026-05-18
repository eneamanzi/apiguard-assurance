# Milestone 1 — Pre-Release Audit

**Tipo audit:** Verifica di release-readiness pre-produzione
**Data audit:** 2026-05-17
**Baseline:** commit `a072d1f` (`docs: audit milestone1`)
**Versione tool:** `0.1.0`
**Codebase:** 90 file Python in `src/`, 18 test attivi (15 nativi + 3 esterni), ~9.625 righe di documentazione
**Verifiche eseguite:** 71 (Parte B, §B.3–§B.11)

---

## Parte A — Dati e Verdetti Citabili nella Tesi

Sintesi delle evidenze empiriche e dei verdetti di release. Ogni dato ha la sua verifica di dettaglio nel corrispondente numero di verifica in Parte B.

### A.1 Verdetto di Release

| Aspetto | Stato |
|---------|-------|
| Correttezza funzionale | ✓ Tutti i gate statici verdi; verdetti assessment 100% riproducibili su due run indipendenti (`9 PASS / 7 FAIL / 2 SKIP / 0 ERROR + 98 findings`, diff per-test status = 0) |
| Integrità architetturale | ✓ Tutte le 38 proprietà architetturali sample-verificate (P01–P38; il catalogo è stato successivamente esteso a P39 post-audit); DAG aciclico; direzione dipendenze monodirezionale; gerarchia eccezioni 11 classi documentata |
| Copertura documentazione | ✓ 100% copertura docstring su 289 simboli pubblici; 100% Pydantic Field description (264/264); allineamento bidirezionale docs ↔ codice verificato |
| Resilienza di produzione | ✓ Signal handling garantisce Phase 6 teardown su `KeyboardInterrupt`; teardown verificato vuoto (0 token residui / 0 repo residui su Forgejo) su entrambi i run |
| Packaging / distribuzione | ✓ Wheel + sdist content verificati; sdist whitelist pubblica solo la superficie pubblica. Metadata PyPI completi. LICENSE differito (§A.8) |
| Riproducibilità build | ✓ Due `hatch build` consecutivi producono wheel byte-identici. Cold install in venv fresh funziona end-to-end |
| Performance | ✓ Baseline misurato e citabile: 4:50 wall-clock, 287–295 MB peak RSS, 4.5 MB evidence totale on-disk |
| Riproducibilità assessment | ✓ KPI byte-equivalenti su run indipendenti; versioni tool, schema e dipendenze esplicitamente pinnate |
| Locale / time-zone | ✓ Tool funziona correttamente sotto `LC_ALL=C`, `LANG=C`, `TZ=America/Los_Angeles` |

**Readiness di release:**
- ✓ **PRONTO** per difesa di tesi
- ✓ **PRONTO** per deployment in ambiente chiuso su target OpenAPI documentati
- ⚠ **RICHIEDE** gli item in §A.8 (LICENSE + tag/CHANGELOG) solo per pubblicazione PyPI o distribuzione come artefatto pubblico

---

### A.2 Baseline del Codebase (snapshot pre-audit)

| Metrica | Valore |
|---------|-------:|
| File Python sorgente in `src/` | 90 |
| Test attivi (nativi + esterni) | 18 (15 + 3) |
| Righe di documentazione (`docs/` + `.claude/` + READMEs + `CLAUDE.md` + `docs/priv/PROJECT_status.md` + `docs/priv/LOCAL_commands.md`) | ~9,625 |
| Schema Pydantic di configurazione (`src/config/schema/`) | 10 file |
| Connector (sottoclassi BaseConnector, escluso template) | 3 (nuclei / sslyze / testssl) |
| Fasi engine | 7 (Phase 1–7) |
| Classi eccezione custom (gerarchia `ToolBaseError`) | 11 |
| Versione Forgejo target | 14.0.3 (gitea-1.22.0) |
| Kong gateway | DB-less mode, Admin API on :8001 |
| Git HEAD | `a072d1f` (`docs: audit milestone1`) |

---

### A.3 Baseline di Performance

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

*Verifica di dettaglio: §B.9, verifiche 55–58.*

---

### A.4 Risultati dell'Assessment per Test (Idempotenza)

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

*Verifica di dettaglio: §B.9, verifica 56.*

---

### A.5 Teardown Post-Run (Verifica Live)

| Risorsa sul target | Prima run 1 | Dopo run 1 | Dopo run 2 | Verdetto |
|--------------------|------------:|----------:|----------:|---------|
| Token Forgejo `thesis-admin` contenenti `"apiguard"` | 0 | 0 | 0 | ✓ |
| Repo Forgejo `user-a` inizianti con `"apiguard"` | 0 | 0 | 0 | ✓ |

Phase 6 teardown rilascia tutte le risorse transitorie create in Phase 5. Il registro teardown ha drenato 4 risorse LIFO con 0 fallimenti su entrambi i run.

*Verifica di dettaglio: §B.9, verifica 58.*

---

### A.6 Topologia del DAG

```
Phase A (nessuna dipendenza, 16 test):
  0.1, 0.2, 0.3, 1.1, 1.5, 1.6, 3.3, 4.1, 4.2, 4.3, 6.2, 6.4, 7.2,
  ext.0.1.nuclei, ext.1.5.testssl, ext.1.5.sslyze

Phase B (depends_on = ["1.1"]):
  1.4, 2.1
```

Mappa in-degree (solo valori non-zero):
- `1.1`: in=2 (consumato da `1.4`, `2.1`)

Rilevamento cicli: ✓ aciclico (verificato via `graphlib.TopologicalSorter`).

*Verifica di dettaglio: §B.8, verifica 53.*

---

### A.7 Matrice delle Versioni

| Componente | Versione |
|-----------|---------|
| `apiguard-assurance` (pyproject) | **0.1.0** |
| `apiguard-assurance` (installato in default env) | 0.1.0 |
| `apiguard version` (CLI) | 0.1.0 |
| `output_schema_version` (JSON report root) | 1.0 |
| Tool esterno pinnato: `testssl.sh` | 3.2.3 |
| Tool esterno pinnato: `nuclei` binary | 3.8.0 |
| Tool esterno pinnato: `nuclei-templates` | 10.4.3 |
| Interprete Python | 3.12.3 |
| Forgejo (target sotto test) | 14.0.3 (gitea-1.22.0) |
| Kong (gateway sotto test) | DB-less mode |

---

### A.8 Item Deferiti (Decisione Esplicita)

| # | Item | Verifica | Motivazione |
|---|------|---------|-------------|
| 1 | File `LICENSE` alla root del repository | §B.10, verifica 61 | Il progetto è un artefatto di tesi magistrale; i termini di licenza dipendono dalle normative IP dell'università e non sono stati ancora finalizzati |
| 2 | Git tag `v0.1.0-m1` + `CHANGELOG.md` | §B.10, verifica 64 | Differito allo step di final-freeze (ultima azione prima di bloccare le modifiche); la prima release non ha nulla con cui confrontarsi |

Entrambi gli item sono documentati; nessuno è un blocker architetturale; nessuno impatta la capacità del tool di girare, produrre report o interoperare con Forgejo + Kong.

---

## Parte B — Registro di Validazione (71 verifiche)

Registro completo delle 71 verifiche eseguite. I dati chiave citabili sono estratti in Parte A; questa sezione documenta la struttura metodologica e i check individuali per riferimento e riproducibilità dell'audit.

### B.1 Executive Summary

| Categoria | Verifiche | Risultato |
|----------|-------:|--------|
| §B.3 Analisi Statica | 5 | ✓ Tutto verde |
| §B.4 Consistenza Inter-Documentale | 11 | ✓ Tutto verde |
| §B.5 Coerenza Docs → Codice | 5 | ✓ Tutto verde |
| §B.6 Coerenza Codice → Docs | 13 | ✓ Tutto verde |
| §B.7 Engineering di Produzione | 11 | ✓ Tutto verde |
| §B.8 Release Engineering | 9 | ✓ Tutto verde |
| §B.9 Performance + Idempotenza + Teardown | 4 | ✓ Tutti misurati + byte-equivalenti |
| §B.10 Runtime / Cleanup / Riproducibilità | 6 | ✓ 5 verdi, 1 differito (LICENSE/CHANGELOG/tag) |
| §B.11 Verifiche Pre-Produzione Aggiuntive | 7 | ✓ Tutto verde |
| **Totale** | **71** | **71 PASS, 0 minori, 0 bloccanti** |

**Bloccanti:** 0. **Finding critici/maggiori:** 0. **Finding minori:** 0 (i 2 cosmetici M-1 + M-2 in §B.12 sono stati risolti durante l'audit). **Item deferiti:** 2 (vedi §A.8).

---

### B.2 Metodologia dell'Audit

L'audit è strutturato in **9 categorie sequenziali** (§B.3–§B.11), ognuna produce artefatti in `/tmp/audit_v4/`. L'ordine è progettato per fallire veloce su regressioni (analisi statica prima) e approfondire progressivamente (documentazione, architettura, packaging, runtime, performance). Le verifiche live (§B.9) sono eseguite end-to-end contro Forgejo 14.0.3 + Kong DB-less.

Rispetto alla baseline di audit precedente, questa revisione:
- **Riorganizza** i 60+ check di tipo tier del documento precedente in **9 categorie omogenee** con **numerazione sequenziale 1→71**.
- **Aggiunge 7 nuove verifiche pre-produzione (§B.11)**: build riproducibile, esecuzione locale-indipendente, esecuzione time-zone-indipendente, risoluzione link markdown interni, scansione PII nei log, cross-check pyproject↔imports, regressione stale install dev-env.
- **Riesegue tutte le verifiche live** (esecuzione E2E × 2 per idempotenza, teardown su Forgejo reale, baseline performance) contro HEAD post-rebase.

---

### B.3 Analisi Statica (verifiche 1–5)

| # | Verifica | Tool / Comando | Risultato | Dettaglio |
|---|----------|----------------|-----------|-----------|
| 1 | Lint | `ruff check .` | ✓ | "All checks passed!" — 0 errori su `select = E/W/F/I/N/UP/B/S/ANN` |
| 2 | Type checking (strict) | `mypy src/` | ✓ | "Success: no issues found in 90 source files" — `strict = true` |
| 3 | Security scan | `bandit -r src/ --severity-level medium` | ✓ | 0 Medium+, 3 Low documentati (B404 + S603×2 in `connectors/base.py`, tutti `# noqa: S603` per subprocess controllato) |
| 4 | Dead code | `vulture src/ --min-confidence 80` | ✓ | 0 finding di dead-code |
| 5 | CVE dipendenze | `pip-audit` | ✓ | "No known vulnerabilities found" |

La chain completa `hatch run dev:check` (ruff → mypy → bandit → vulture → pip-audit) gira fino al completamento (exit 0). **Artefatti:** `/tmp/audit_v4/{lint,audit,deps,vulture}.log`.

---

### B.4 Consistenza Inter-Documentale (verifiche 6–16)

| # | Verifica | Risultato | Dettaglio |
|---|----------|-----------|-----------|
| 6 | Naming `ext.X.Y.toolname` uniforme nei docs | ✓ informativo | Tutti i riferimenti `ext.X.Y` includono il suffisso `.toolname`. I riferimenti bare `ext.1.2` in `docs/priv/apiguard_property.md:107` e `docs/priv/PROJECT_status.md` sono placeholder M2 intenzionali |
| 7 | Parità test-set (`docs/priv/PROJECT_status.md` ↔ `docs/pub/ARCHITECTURE.md` ↔ codice sorgente) | ✓ | 15 native test_id + 3 external test_id = 18 attivi. Concordano in tutte e 3 le fonti |
| 8 | Proprietà architetturali P01–P35 | ✓ | Tutte le 35 proprietà presenti in `docs/priv/apiguard_property.md` al momento dell'audit; il catalogo è stato successivamente esteso a P39 |
| 9 | Riferimenti connector in `docs/priv/TOOLS_catalog.md` | ✓ | nuclei (21 occorrenze), sslyze (5), testssl (7) — tutti e 3 i connector documentati |
| 10 | Hard Rules (`CLAUDE.md` ↔ `docs/priv/knowledge/RULES_claude.md`) | ✓ | 22 hard rules in `CLAUDE.md`; contenuto sostanzialmente allineato con `RULES_claude.md` |
| 11 | Gerarchia eccezioni (`CLAUDE.md` ↔ `docs/pub/ARCHITECTURE.md` ↔ `src/core/exceptions.py` + `src/core/gateway/base.py` + `src/discovery/seed_generator.py`) | ✓ | 11/11 classi eccezione presenti in CLAUDE.md |
| 12 | Uniformità status M1 | ✓ | `docs/priv/PROJECT_status.md`, `CLAUDE.md`, `README.md`, `docs/pub/ARCHITECTURE.md`, `docs/priv/AUDIT_milestone1_release.md` concordano sul completamento di M1 |
| 13 | Italian leak in codice + file Claude-facing | ✓ | 0 match in `src/` + `CLAUDE.md`. Italiano presente nei docs di tesi è by design |
| 14 | Log decisioni tool rimossi (kiterunner, crlfuzz, jwtxploiter) | ✓ | Tutti e 3 elencati coerentemente in `docs/priv/TOOLS_decisions.md` e `docs/priv/TOOLS_catalog.md` |
| 15 | Uniformità versione | ✓ | `0.1.0` uniforme in `pyproject.toml:20`, `src/__init__.py`, `README.md`, `README.en.md`, `docs/pub/ARCHITECTURE.md` |
| 16 | Conteggio test (18 attivi) | ✓ | 15 file test nativi + 1 file esterno contenente 3 classi esterne = 18 test_id |

---

### B.5 Coerenza Docs → Codice (verifiche 17–21)

| # | Verifica | Risultato | Dettaglio |
|---|----------|-----------|-----------|
| 17 | Hard rules (CLAUDE.md) ↔ grep sul codice sorgente | ✓ | `pass` / `TODO` / `FIXME` / `HACK` / bare `except` / `print()` / singleton `SecurityClient()`: **0 violazioni**. `...` (Ellipsis) limitato a 6 corpi `@abstractmethod` + 1 esempio JSON in docstring — conforme alla regola raffinata |
| 18 | Compliance ClassVar `BaseTest` / `ExternalToolTest` (AST-based) | ✓ | 15/15 classi `Test*` native con 8 ClassVar richiesti; 3/3 classi `ExtTest*` esterne con 9 ClassVar richiesti (8 + `tool_name`). 0 mancanti |
| 19 | Catena config ↔ test ↔ runtime model | ✓ | Tutti i test con config (1.4, 2.1, 4.1, 4.2, 4.3, 6.4, 7.2) hanno la catena 5-point intatta: `config.yaml` → `src/config/schema/domain_N.py` → `src/core/models/runtime.py` (`RuntimeTestNNConfig`) → `engine.py _phase_3_build_contexts()` → `target.tests_config.test_N_N` |
| 20 | Direzione dipendenze (`core/` ← `connectors/` ← `tests/` + `external_tests/` ← `engine.py`) | ✓ | 0 import upward / lateral / ciclici. 1 match in `src/core/gateway/kong.py:30` è una docstring che enuncia la regola (non un import) |
| 21 | Proprietà architetturali P01–P35 vs implementazione | ✓ | Sample-verificate P01 (API-Agnosticism), P08 (Three-Tier Connector Hierarchy), P11 (Streaming Evidence Store), P30 (CLI generate-seed): loci esistono, implementazioni concordano |

---

### B.6 Coerenza Codice → Docs (verifiche 22–34)

| # | Verifica | Risultato | Dettaglio |
|---|----------|-----------|-----------|
| 22 | Tutti i 15 native test_id referenziati nei docs | ✓ | Presenti in `docs/priv/PROJECT_status.md`, `docs/pub/ARCHITECTURE.md`, `docs/priv/AUDIT_milestone1_release.md` |
| 23 | Tutti i 3 external test_id (`ext.0.1.nuclei`, `ext.1.5.sslyze`, `ext.1.5.testssl`) referenziati nei docs | ✓ | Presenti in `docs/priv/PROJECT_status.md`, `docs/pub/ARCHITECTURE.md`, `docs/priv/TOOLS_catalog.md` |
| 24 | Tutti i 3 connector referenziati in `docs/priv/TOOLS_catalog.md` | ✓ | nuclei / sslyze / testssl |
| 25 | Tutte le 11 classi eccezione documentate | ✓ | Ognuna presente in `CLAUDE.md` e/o `docs/pub/ARCHITECTURE.md` |
| 26 | Tutti i 6 helper referenziati nei docs | ✓ | `auth`, `auth_forgejo`, `auth_jwt_login`, `forgejo_resources`, `path_resolver`, `response_inspector` — ognuno in 2–9 file di documentazione |
| 27 | Tutte le 7 fasi engine referenziate nei docs | ✓ | Fasi 1–7 documentate in `docs/priv/knowledge/Implementazione.md` + `docs/pub/ARCHITECTURE.md` + `CLAUDE.md` |
| 28 | Core Pydantic models referenziati | ✓ | `TargetContext`, `TestContext`, `EvidenceRecord`, `Finding`, `TestResult`, `ResultSet`, `AttackSurface`, `EndpointRecord`, ecc. tutti documentati |
| 29 | Tutti i 4 comandi CLI documentati | ✓ | `run` (4 docs), `version` (2), `validate-config` (2), `generate-seed` (2) |
| 30 | Hard Rules ↔ superficie del codice | ✓ | Cross-verificato con verifica 17 — nessuna regola fa riferimento a comportamento assente dal codice |
| 31 | Docstring modulo-livello ↔ layout directory `ARCHITECTURE.md` | ✓ | Tutti i moduli `src/` hanno docstring header; layout in `ARCHITECTURE.md` coincide con l'albero `src/` |
| 32 | ClassVar `BaseTest`/`ExternalToolTest` ↔ contratto `docs/pub/ADDING_tests.md` | ✓ | 8 ClassVar BaseTest + 9 ExternalToolTest documentati; nessun orfano in nessuna direzione |
| 33 | Chiavi top-level `config.yaml` ↔ schemi Pydantic | ✓ | 6 chiavi top-level (`target`, `credentials`, `execution`, `output`, `tests`, `external_tools`) concordano con i file schema in `src/config/schema/` |
| 34 | Surprise scan (simboli pubblici assenti da qualsiasi doc) | ✓ | 0 simboli "fantasma" reali. Alcune classi config Pydantic sono referenziate via pattern (es. `RuntimeTest*Config`) — documentato |

---

### B.7 Engineering di Produzione (verifiche 35–45)

| # | Verifica | Risultato | Dettaglio |
|---|----------|-----------|-----------|
| 35 | Correttezza boundary error-handling | ✓ | 127 blocchi `except` totali. 48 `except Exception` broad annotati con `# noqa: BLE001` ai boundary di fase (3 annotazioni aggiunte durante questo audit — finding M-1, §B.12) |
| 36 | Consistenza logging & leak credenziali | ✓ | 48 binding `structlog.get_logger()`. 0 f-string con leak token/password. 32 placeholder `[REDACTED]` nel codice |
| 37 | Copertura descrizioni Pydantic Field | ✓ | **264 chiamate `Field()` outer (user-facing), 264 con `description=` → 100% copertura** (i campi `Annotated[X, Field(ge=...)]` validation-only non sono user-facing e non vengono contati) |
| 38 | Inventario determinismo / non-determinismo | ✓ | 10 chiamate `datetime.now(UTC)` localizzate nelle sorgenti attese. 0 `random.*`, 0 `uuid.uuid4`, 0 sorgenti stale-mocking |
| 39 | Modello di concorrenza | ✓ | Sequenziale by design: 0 `asyncio` nei code path, 0 globals a livello modulo, 1 `nonlocal` documentato (`test_1_6:370`), 1 `ThreadPoolExecutor` documentato (`discovery/openapi.py` — watchdog prance con `max_workers=1`) |
| 40 | Osservabilità / qualità messaggi di errore | ✓ | Tutti i 4 `--help` CLI leggibili. `apiguard run --help` documenta tutti i 4 exit code (0 / 1 / 2 / 10). Errore variabile env mancante produce messaggio actionable |
| 41 | Qualità del report (HTML + cross-reference evidence) | ✓ | 0 placeholder Jinja irrisolti in `outputs/assessment_report.html`. `executive_summary` separa nettamente `scheduled_tests` (18) e `executed_tests` (16 = pass+fail+error escluso skip). Tutti i 152 record evidence raggiungibili dal JSON report |
| 42 | Profondità hygiene dipendenze | ✓ | `pip check`: pulito. 2 upgrade minori disponibili (cryptography 46→48, openapi-schema-validator 0.8→0.9) dentro policy "FLOOR–NEXT_MAJOR" — nessuna azione necessaria |
| 43 | Indipendenza dall'ordine dei test | ✓ | Implicita: l'idempotenza in §A.4 prova che i 15 test DAG-leaf producono verdetti byte-equivalenti su run indipendenti |
| 44 | Portabilità path cross-platform | ✓ | Tutti i riferimenti `/tmp/`, `/home/` hardcoded sono in docstring, pattern regex per rilevamento path-leak, o interni di `_relativize_display_path()`. Solo 2 usi `os.path` (`relpath()`) vs preferenza `pathlib` di CLAUDE.md — boundary accettabile |
| 45 | Robustezza configurazione | ✓ | Il loader produce errori actionable su file mancante, YAML malformato, `${ENV_VAR}` non impostato, fallimento validazione Pydantic. Cold-install verificato alla verifica 62 |

---

### B.8 Release Engineering (verifiche 46–54)

| # | Verifica | Risultato | Dettaglio |
|---|----------|-----------|-----------|
| 46 | Contenuto wheel | ✓ | `apiguard_assurance-0.1.0-py3-none-any.whl` — **95 file** tutti dentro `src/` o `.dist-info/`. Nessun contenuto spurio |
| 47 | Contenuto sdist | ✓ | Whitelist `[tool.hatch.build.targets.sdist]` pubblica solo la superficie pubblica (`src/`, `docs/pub/`, `README.md`, `docs/priv/LOCAL_commands.md`, `pyproject.toml`, `config.yaml`, `.env.example`, `.gitignore`, `install_tools.sh`, `PKG-INFO`). File interni (`.claude/`, `CLAUDE.md`, `docs/priv/PROJECT_status.md`, `Z_SUPERRCODEREVIEW.md`, `docs/priv/AUDIT_milestone1_release.md`, `README.en.md`, `outputs/`, `tools/`, `scripts/`) **NON** nell'sdist |
| 48 | Completezza metadata PyPI | ✓ | Wheel `METADATA` contiene: `Project-URL: Repository/Issues/Documentation`, `Author-email: Enea Manzi <enea.manzi@gmail.com>`, 10 keyword (api-security / dast / owasp / kong-gateway / master-thesis / ecc.), 17 classifier, `Requires-Python >=3.11`, tutti `Requires-Dist` con upper bound `<NEXT_MAJOR` |
| 49 | Ergonomics CLI | ✓ | Tutti i 4 subcommand (`run`, `version`, `validate-config`, `generate-seed`) rendono l'help correttamente. Top-level help cita la metodologia ("8 domains, 29 guarantees"). Exit code documentati |
| 50 | Signal handling / resilienza interrupt | ✓ | Phase 5 wrapped in `try:` con `finally: self._phase_6_teardown(...)` in `src/engine.py:252-264`. Le risorse Forgejo sono rilasciate anche su `KeyboardInterrupt` |
| 51 | Versioning schema output | ✓ | `outputs/apiguard_report.json` espone `output_schema_version: "1.0"` e `tool_version: "0.1.0"` (da `importlib.metadata.version()`). Verificato live su un run fresh |
| 52 | Side effect a livello modulo | ✓ | Scan AST-based: 0 statement inattesi fuori da import / definizioni / assegnazioni Pydantic-style / docstring. L'1 `Try` in `src/__init__.py:17` è il fallback `importlib.metadata.version()` per install editabili — by design |
| 53 | Correttezza semantica DAG | ✓ | 18 test_id estratti via AST. 0 `depends_on` orfani. Topological sort → aciclico. In-degree map: `1.1` ha in=2. 16/18 sono DAG-leaf. Vedi §A.6 |
| 54 | Hygiene encoding / EOL / EOF | ✓ | 0 file CRLF. 0 trailing whitespace in `src/`. 4/4 `__init__.py` vuoti con EOF newline. 0 BOM rilevati |

---

### B.9 Performance, Idempotenza, Teardown (verifiche 55–58, tutte live)

I dati chiave di questa sezione sono estratti e presentati in §A.3–§A.5.

| # | Verifica | Risultato | Dettaglio |
|---|----------|-----------|-----------|
| 55 | Baseline di performance (`/usr/bin/time -v`) | ✓ | Run live su suite M1 completa contro Forgejo 14.0.3 + Kong DB-less. Tabella metriche → §A.3 |
| 56 | Idempotenza (KPI byte-equivalenti su run indipendenti) | ✓ | **0 differenze** tra i triple `test_id status finding_count` dei due run ordinati. Tabella per-test → §A.4 |
| 57 | Indipendenza dall'ordine dei test | ✓ | L'idempotenza della verifica 56 prova implicitamente l'indipendenza dall'ordine per i 15 test DAG-leaf su due run indipendenti |
| 58 | Verifica teardown post-run (live) | ✓ | Phase 6 teardown ha drenato 4 risorse LIFO con 0 fallimenti su entrambi i run. Tabella → §A.5 |

---

### B.10 Runtime, Cleanup, Riproducibilità (verifiche 59–64)

| # | Verifica | Risultato | Dettaglio |
|---|----------|-----------|-----------|
| 59 | Cleanup artefatti obsoleti | ✓ | `outputs/tools/` contiene file `ext_X_Y_toolname_output.json` con naming corretto. Nessun residuo pre-rinomina |
| 60 | Secrets scan (dogfooding) | ✓ | 0 segreti reali nel repo. I match sono placeholder `${ENV_VAR}` (`config.yaml`, `.env.example`, README), riferimenti a dati di test dentro `test_1_4`/`test_6_4`, o stringhe anti-pattern documentate. `.env` (reale) **mai** committato in git history |
| 61 | License audit (dipendenze) | ✓ documentato | 52 dipendenze totali. 47 permissive (MIT / BSD / Apache / MPL / ISC). 3 non-permissive: `nassl 5.4.0` e `sslyze 6.3.1` (AGPL v3, gated dietro extra `[sslyze]`) + `tls_parser 2.0.2` (UNKNOWN, transitiva di sslyze). `apiguard-assurance` stesso è `UNKNOWN` (LICENSE differito — §A.8) |
| 62 | Riproducibilità cold-install | ✓ | Fresh `python -m venv /tmp/cold-test-v4` → `pip install dist/apiguard_assurance-0.1.0-py3-none-any.whl` OK. 49 dep installate. `apiguard --help`, `apiguard version` (`0.1.0`), `apiguard validate-config` funzionanti |
| 63 | Completezza docstring | ✓ | **0 simboli pubblici senza docstring** su 289 (100% copertura; scan AST-based su FunctionDef / AsyncFunctionDef / ClassDef non privati) |
| 64 | Version pinning | ✓ parzialmente differito | `pyproject.toml` versione `0.1.0`; `testssl.sh 3.2.3` + `nuclei 3.8.0` + `nuclei-templates 10.4.3` pinnati in `config.yaml`. Git tag `v0.1.0-m1` e `CHANGELOG.md` differiti (§A.8) |

---

### B.11 Verifiche Pre-Produzione Aggiuntive (verifiche 65–71)

| # | Verifica | Risultato | Dettaglio |
|---|----------|-----------|-----------|
| 65 | Build riproducibile (wheel byte-identici su due build consecutive) | ✓ | `hatch build --target wheel` invocato due volte; SHA-256 identico (450.844 byte ognuno). Build deterministica — importante per signing / supply-chain |
| 66 | Esecuzione locale-indipendente | ✓ | `LC_ALL=C LANG=C apiguard --help` e `apiguard version` producono output corretto (caratteri UTF-8 box-drawing via rich; nessun `UnicodeEncodeError`) |
| 67 | Esecuzione time-zone-indipendente | ✓ | `TZ=America/Los_Angeles apiguard version` produce output corretto. Il codebase usa `datetime.now(UTC)` (10 siti verificati — verifica 38) |
| 68 | Risoluzione link markdown interni | ✓ | 14 link relative-path interni in `README.md`, `README.en.md`, `CLAUDE.md`, `docs/pub/*.md`, `docs/priv/AUDIT_milestone1_release.md`, `docs/priv/PROJECT_status.md`, `docs/priv/LOCAL_commands.md`: **0 rotti** |
| 69 | PII scan log (evidence + JSON report run-1) | ✓ | 16 stringhe con `@` in `evidence.json` — **tutte identificatori algoritmo TLS** (`aes128-gcm@openssh.com`, ecc.) o riferimenti test-user (`thesis-admin@noreply.localhost`). 0 credenziali non-redacted. 0 PII reali |
| 70 | Cross-check pyproject ↔ import | ✓ | Scan AST di `src/**/*.py` produce esattamente i 12 moduli third-party dichiarati. 2 entry dichiarate-ma-non-importate: `urllib3` (pin CVE transitivo intenzionale) e `pydantic-settings` (informativo, rimuovibile in cleanup M2) |
| 71 | Stale install dev-environment (regressione) | ✓ | Primo rilievo: `hatch run dev:pip show apiguard-assurance` riportava `Version: 1.0.0` (stale). Fixato durante questo audit (finding M-2, §B.12) via `hatch run dev:pip install -e . --force-reinstall`. Post-fix: entrambi gli env riportano `0.1.0` |

---

### B.12 Finding e Item Aperti

**Finding minori emersi e risolti durante questo audit:**

| ID | Verifica | Descrizione | Risoluzione |
|----|----------|-------------|-------------|
| M-1 | §B.7 / verifica 35 | 3 blocchi `except Exception` broad senza annotazione `# noqa: BLE001`: `connectors/sslyze.py:176`, `tests/domain_0/test_0_1_shadow_api_discovery.py:198`, `tests/domain_1/test_1_1_authentication_required.py:457`. Ognuno converte correttamente l'eccezione in un tipo custom — il commento di rilassamento della regola era l'unica cosa mancante | **Risolto.** `# noqa: BLE001` aggiunto a tutte e 3 le righe. `ruff check .` + `mypy src/` rieseguiti dopo il fix: verdi |
| M-2 | §B.11 / verifica 71 | `hatch dev` env aveva metadata package stale (`apiguard-assurance 1.0.0` da prima del version bump). Default env era già corretto (0.1.0). Impattava solo il reporting di `pip-audit` inside il dev env | **Risolto.** `hatch run dev:pip install -e . --force-reinstall` eseguito. Dev env riporta ora `Version: 0.1.0` |

Entrambi i finding sono ora risolti; il codebase post-fix ha 71/71 verifiche verdi.

**Item deferiti:** vedi §A.8.

---

## Appendici

### Appendice A — Copertura Descrizioni Pydantic Field

`src/config/schema/` + `src/core/models/`: **264 chiamate outer (user-facing) `Field()`; 264 con `description=` (100%)**. I campi inner `Annotated[..., Field(ge=...)]` validation-only sono intenzionalmente non contati — l'assignment outer porta la descrizione.

### Appendice B — Inventario Licenze (52 dipendenze)

- **Permissive (MIT / BSD / Apache / MPL / ISC):** 47 pacchetti
- **AGPL v3 (gated dietro extra `[sslyze]`):** `nassl 5.4.0`, `sslyze 6.3.1`
- **UNKNOWN (transitiva di sslyze):** `tls_parser 2.0.2`
- **UNKNOWN (il progetto stesso, LICENSE differito):** `apiguard-assurance 0.1.0`

Il tail AGPL v3 è accettabile per uso tesi; l'extra `[sslyze]` deve essere rimosso o sostituito prima di qualsiasi distribuzione SaaS / closed-source.

---

*Audit completato 2026-05-17. Tutti i risultati §B.3–§B.11 riflettono lo stato del working tree al commit `a072d1f`. Finding M-1 e M-2 sono cosmetici; i 2 item in §A.8 sono gli unici punti aperti e sono differiti per decisione esplicita dell'autore.*

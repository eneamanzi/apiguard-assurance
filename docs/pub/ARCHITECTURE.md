# APIGuard Assurance — Architecture Reference

- [1. Principi di design fondamentali](#1-principi-di-design-fondamentali)
  - [1.1 Filosofia API-Agnostica](#11-filosofia-api-agnostica)
  - [1.2 Stato Scisso e Immutabilita](#12-stato-scisso-e-immutabilita)
- [2. Regole architetturali e dipendenze tra moduli](#2-regole-architetturali-e-dipendenze-tra-moduli)
- [3. Physical Architecture Mapping — Fasi e cartelle](#3-physical-architecture-mapping--fasi-e-cartelle)
- [4. Pipeline di esecuzione — Flusso dettagliato](#4-pipeline-di-esecuzione--flusso-dettagliato)
  - [4.1 Catalogo dei test pianificati e mappa delle dipendenze (DAG completo)](#41-catalogo-dei-test-pianificati-e-mappa-delle-dipendenze-dag-completo)
    - [Catalogo per dominio](#catalogo-per-dominio)
    - [Mappa delle dipendenze (`depends_on`)](#mappa-delle-dipendenze-depends_on)
    - [Batch di esecuzione risultanti](#batch-di-esecuzione-risultanti)
    - [Mappa degli helper condivisi](#mappa-degli-helper-condivisi)
  - [Fase 2 — OpenAPI Discovery: dettagli non banali](#fase-2--openapi-discovery-dettagli-non-banali)
  - [Fase 4 — Test Discovery: il discovery senza registro centrale](#fase-4--test-discovery-il-discovery-senza-registro-centrale)
  - [Fase 5 — Il contratto di `BaseTest.execute()` e la gestione del tempo](#fase-5--il-contratto-di-basetestexecute-e-la-gestione-del-tempo)
- [5. Componenti chiave — Come si parlano](#5-componenti-chiave--come-si-parlano)
  - [AssessmentEngine — non riutilizzabile](#assessmentengine--non-riutilizzabile)
  - [SecurityClient — la coppia con EvidenceStore](#securityclient--la-coppia-con-evidencestore)
  - [TargetContext vs TestContext](#targetcontext-vs-testcontext)
- [6. Modello dei dati — I tre SSOT e la gerarchia in memoria](#6-modello-dei-dati--i-tre-ssot-e-la-gerarchia-in-memoria)
  - [I tre SSOT](#i-tre-ssot)
  - [La gerarchia in memoria](#la-gerarchia-in-memoria)
  - [Il dual audit trail](#il-dual-audit-trail)
  - [Invarianti enforced a livello di modello](#invarianti-enforced-a-livello-di-modello)
  - [Catalogo dei modelli (`src/core/models/`)](#catalogo-dei-modelli-srccoremodels)
- [7. Guida per i contributor — Come aggiungere un nuovo test](#7-guida-per-i-contributor--come-aggiungere-un-nuovo-test)
  - [Struttura interna di BaseTest: dettagli rilevanti](#struttura-interna-di-basetest-dettagli-rilevanti)
  - [Convenzioni obbligatorie](#convenzioni-obbligatorie)
  - [Helper disponibili (`src/tests/helpers/`)](#helper-disponibili-srctestshelpers)
  - [Payload di attacco disponibili (`src/tests/data/`)](#payload-di-attacco-disponibili-srctestsdata)
- [8. Gerarchia delle eccezioni](#8-gerarchia-delle-eccezioni)
- [9. Repository Structure](#9-repository-structure)
- [10. Packaging e distribuzione](#10-packaging-e-distribuzione)

**Target audience: Core Developers and Contributors**

Questo documento descrive l'architettura interna di APIGuard Assurance in dettaglio ingegneristico. Se sei un auditor che vuole solo usare il tool, torna al [`README.md`](../../README.md).

---

## 1. Principi di design fondamentali

Prima di analizzare i singoli componenti, vale la pena enunciare i due principi da cui discendono quasi tutte le scelte di design.

### 1.1 Filosofia API-Agnostica

Il tool non contiene alcun riferimento a path, endpoint o strutture dati di un applicativo specifico. Tutta la conoscenza del target e derivata a runtime da due sole sorgenti: il `config.yaml` (credenziali, URL, parametri di esecuzione) e la specifica OpenAPI del target.

Questo agnosticismo e la principale giustificazione accademica del progetto. Un tool che funziona su un solo applicativo e uno script; un tool che funziona su qualsiasi API REST documentata e un contributo metodologico. Il costo accettato e che il target deve esporre una specifica OpenAPI valida — e che le Shadow API (dominio 0), per definizione fuori dalla spec, costituiscono l'eccezione intenzionale a questa regola.

### 1.2 Stato Scisso e Immutabilita

Il tool opera su due tipi di stato con caratteristiche opposte: cio che si sa del target prima di iniziare (immutabile) e cio che si scopre o si fa durante l'esecuzione (mutabile). Tenere questi due stati separati — in `TargetContext` e `TestContext` — non e un'eleganza stilistica: e la garanzia che un test non possa accidentalmente corrompere le informazioni di base lette da tutti gli altri. La separazione e enforced a livello di tipo: `TargetContext` usa `model_config = {"frozen": True}` di Pydantic.

---

## 2. Regole architetturali e dipendenze tra moduli

Il tool applica un **principio di dipendenza unidirezionale** rigoroso.

```
cli.py
  +-> engine.py  [unico modulo con visibilita totale — nessun altro importa da lui]
        |-> config/
        |     +-> core/models, core/exceptions
        |-> core/
        |     (models, client, context, dag, evidence, exceptions)
        |     +-> stdlib, pydantic, httpx, tenacity, structlog
        |-> discovery/
        |     +-> core/models, core/exceptions
        |-> tests/
        |     +-> core/ esclusivamente (mai config/, discovery/, report/, engine.py)
        +-> report/
              +-> core/models, config/schema (mai tests/, discovery/)
```

**Regole specifiche e la loro motivazione:**

- `core/models/` importa **solo** stdlib e pydantic. E il vocabolario condiviso e non puo dipendere da nessun modulo applicativo per evitare qualsiasi dipendenza circolare.
- `tests/base.py` importa da `core/` esclusivamente. I moduli test implementativi non importano da altri moduli test: nessun accoppiamento inter-dominio.
- `core/dag.py` importa solo dalla stdlib e da `core/exceptions`. Opera esclusivamente su stringhe (`test_id`), mai su istanze di `BaseTest`, per evitare un'importazione circolare con `tests/`.
- `report/builder.py` non importa da `tests/`. Il builder legge i metadati direttamente dai `TestResult` — che li portano con se gia popolati da `BaseTest._metadata_kwargs()` — senza mai dover conoscere la struttura interna delle classi di test.
- Nessun modulo importa da `engine.py`. L'engine e il terminale della gerarchia, non un servizio.

---

## 3. Physical Architecture Mapping — Fasi e cartelle

Una delle proprieta piu utili per chi esplora il codice per la prima volta e che le **7 fasi logiche** dell'engine si mappano quasi 1:1 con le **cartelle fisiche** della repository. Capire questa corrispondenza permette di trovare immediatamente il codice rilevante per qualsiasi comportamento osservato a runtime.

```
+------------------+---------------------------------+---------------------------------+
| Fase logica      | Cartella / File principale      | Cosa trovi li                   |
+------------------+---------------------------------+---------------------------------+
| Fase 1           | src/config/                     | loader.py  — lettura YAML +     |
| Initialization   |                                 | interpolazione env vars         |
|                  |                                 | schema/    — validazione        |
|                  |                                 | Pydantic (tool_config.py +      |
|                  |                                 | domain_N.py + tests_config.py)  |
+------------------+---------------------------------+---------------------------------+
| Fase 2           | src/discovery/                  | openapi.py — fetch, deref       |
| OpenAPI          |                                 | $ref (prance), validazione      |
| Discovery        |                                 | dialect-aware                   |
|                  |                                 | surface.py — spec dict ->       |
|                  |                                 | AttackSurface tipizzata         |
+------------------+---------------------------------+---------------------------------+
| Fase 3           | src/core/context.py             | TargetContext (frozen) +        |
| Context          | src/core/evidence.py            | TestContext (mutable)           |
| Construction     |                                 | EvidenceStore (streaming JSONL) |
+------------------+---------------------------------+---------------------------------+
| Fase 4           | src/tests/registry.py           | TestRegistry — discovery        |
| Test Discovery   | src/core/dag.py                 | dinamica con pkgutil            |
| & Scheduling     |                                 | DAGScheduler — topological sort |
|                  |                                 | via graphlib + stall detection  |
+------------------+---------------------------------+---------------------------------+
| Fase 5           | src/core/client.py              | SecurityClient (context mgr)    |
| Execution        | src/tests/                      | aperto qui (after Phase 4)      |
|                  | src/tests/base.py               | Tutte le sottoclassi BaseTest   |
|                  | src/tests/domain_X/test_*.py    | domain_0/ ... domain_7/         |
|                  | src/tests/helpers/              | Helper condivisi tra test       |
|                  | src/tests/data/                 | Payload di attacco riutilizz.   |
+------------------+---------------------------------+---------------------------------+
| Fase 6           | src/core/context.py             | TestContext.drain_resources()   |
| Teardown         |                                 | + SecurityClient.request()      |
+------------------+---------------------------------+---------------------------------+
| Fase 7           | src/report/                     | builder.py  — ResultSet -> DTO  |
| Report           |                                 | renderer.py — Jinja2 -> HTML    |
| Generation       |                                 | templates/  — template HTML     |
+------------------+---------------------------------+---------------------------------+
| Orchestrazione   | src/engine.py                   | AssessmentEngine — chiama le    |
| (tutte le fasi)  |                                 | fasi nell'ordine corretto       |
+------------------+---------------------------------+---------------------------------+
| Entry point      | src/cli.py                      | Typer CLI, configurazione       |
|                  |                                 | structlog, gestione exit code   |
+------------------+---------------------------------+---------------------------------+
```

> **Regola pratica per il debugging:** l'engine (`engine.py`) non contiene logica propria — e un pure orchestrator. Il codice di ogni comportamento anomalo risiede quasi interamente nella cartella della fase corrispondente.

---

## 4. Pipeline di esecuzione — Flusso dettagliato

```
INPUT: config.yaml + variabili d'ambiente
      |
      v
+------------------------------------------------------------------+
| FASE 1 — Initialization                              [BLOCCANTE] |
|                                                                  |
| config/loader.py:                                                |
|   1. Carica YAML grezzo                                          |
|   2. Interpola ${VAR} con os.environ (+ load_dotenv)             |
|      -> ConfigurationError se variabile mancante                 |
|   3. Valida con schema Pydantic v2 -> ToolConfig (frozen)        |
|      -> ConfigurationError se struttura invalida                 |
+-----------------------------------+------------------------------+
                                    | ToolConfig
                                    v
+------------------------------------------------------------------+
| FASE 2 — OpenAPI Discovery                           [BLOCCANTE] |
|                                                                  |
| discovery/openapi.py:                                            |
|   1. Fetch spec (URL o path locale)                              |
|   2. Dereferenziazione $ref via prance in thread background      |
|      (watchdog timeout = openapi_fetch_timeout_seconds)          |
|      -> OpenAPILoadError se irraggiungibile o timeout            |
|   3. Rilevamento dialetto: SWAGGER_2 o OPENAPI_3                 |
|   4. Validazione strutturale dialect-aware (openapi-spec-valid.) |
|      -> OpenAPILoadError se spec malformata                      |
|                                                                  |
| discovery/surface.py:                                            |
|   5. Traduce spec dict -> AttackSurface (EndpointRecord tipizz.) |
|      Dialect-aware: Swagger 2.0 usa basePath + param[in:body],   |
|      OpenAPI 3.x usa requestBody e path gia assoluti             |
+-----------------------------------+------------------------------+
                                    | AttackSurface (frozen)
                                    v
+------------------------------------------------------------------+
| FASE 3 — Context Construction                                    |
|                                                                  |
| TargetContext (frozen Pydantic):                                 |
|   - ToolConfig + AttackSurface + RuntimeCredentials              |
|   - Risponde a: "Cos'e il target?"                               |
|                                                                  |
| TestContext (mutable):                                           |
|   - Token JWT (PrivateAttr) + risorse da rimuovere (PrivateAttr) |
|   - Risponde a: "Cosa ho scoperto o fatto finora?"               |
|                                                                  |
| EvidenceStore: streaming JSONL (per-test files in evidence_tmp/),|
|   unbounded; merge in Phase 7                                    |
+-----------------------------------+------------------------------+
                                    | I 3 oggetti pronti (TargetContext, TestContext, EvidenceStore)
                                    v
+------------------------------------------------------------------+
| FASE 4 — Test Discovery & Scheduling                 [BLOCCANTE] |
|                                                                  |
| TestRegistry (tests/registry.py):                                |
|   R1 — Module scan: pkgutil.walk_packages su src.tests           |
|         Importa solo moduli con nome finale che inizia con test_ |
|         Errori di import singoli -> WARNING, non bloccano        |
|   R2 — Subclass extraction: inspect.getmembers -> sottoclassi    |
|         concrete di BaseTest con tutti i metadati obbligatori    |
|         (verificati da has_required_metadata())                  |
|   R3 — Filtering: priority <= min_priority                       |
|                   strategy in enabled_strategies                 |
|         Output: lista ordinata per test_id (determinismo)        |
|                                                                  |
| DAGScheduler (core/dag.py):                                      |
|   1. Sanitize: dipendenze verso test filtrati -> WARNING + rimozione|
|   2. graphlib.TopologicalSorter.prepare() -> DAGCycleError se ciclo|
|   3. Drain in ScheduledBatch: test_ids ordinati lessicograficamente|
|      per determinismo (graphlib non garantisce ordine nel livello) |
|   4. Stall detection: se is_active()=True ma get_ready()=[] ->   |
|      ERROR strutturato con lista test_id non schedulati + break  |
|   -> DAGCycleError -> exit 10                                    |
+-----------------------------------+------------------------------+
                                    | Lista di ScheduledBatch
                                    v
+------------------------------------------------------------------+
| FASE 5 — Execution                                               |
|                                                                  |
| result_set = ResultSet()       <- creato qui, tra Phase 4 e 5   |
| with SecurityClient(...) as client:   <- aperto qui             |
|   Per ogni ScheduledBatch (ordine topologico):                   |
|     Per ogni test nel batch (esecuzione sequenziale):            |
|       test.execute(target, context, client, store)               |
|         -> ritorna SEMPRE TestResult (mai solleva eccezioni)     |
|         -> duration_ms injettato via model_copy() post-esecuzione|
|       ResultSet.add_result(result)                               |
|       Se fail_fast=true AND test.priority==0                     |
|         AND result.status in (FAIL, ERROR): interrompi pipeline  |
+-----------------------------------+------------------------------+
                                    | SecurityClient chiuso
                                    | ResultSet completo
                                    v
+------------------------------------------------------------------+
| FASE 6 — Teardown                           (best-effort, no-op) |
|                                                                  |
| TestContext.drain_resources() -> lista LIFO 3-tuple              |
|   (method, path, headers)                                        |
|   headers: opzionale, usato per risorse che richiedono auth      |
|   esplicita nel DELETE (es. Forgejo token via Basic Auth)        |
| Per ogni risorsa: SecurityClient.request(DELETE, path, headers)  |
|   Codici accettabili: {200, 204, 404}                            |
|   404 e accettabile: la risorsa e gia stata rimossa              |
|   Fallimento -> TeardownError loggato come WARNING               |
|   (manual_cleanup_required=True nel log), esecuzione continua    |
|   Una lista vuota (nessuna risorsa registrata) e no-op immediato |
+-----------------------------------+------------------------------+
                                    |
                                    v
+------------------------------------------------------------------+
| FASE 7 — Report Generation              (fault-tolerant, no-op) |
|                                                                  |
| Ogni operazione ha il suo blocco try/except indipendente:        |
| gli errori su una fase non bloccano le successive.               |
|                                                                  |
| 7a. EvidenceStore.merge_and_finalize() -> evidence.json          |
|       Records ordinati per timestamp_utc (difensivo vs future    |
|       parallelismo; gia cronologici per esecuzione sequenziale)  |
|       Output: envelope JSON con generated_at_utc, record_count,  |
|       records[]                                                  |
|       -> OSError loggato come ERROR, non propaga                 |
|                                                                  |
| 7b. report/builder.py -> ReportData (DTO)                        |
|       -> eccezione loggata come ERROR, return immediato          |
|                                                                  |
| 7c. report/renderer.py -> assessment_report.html                 |
|       -> eccezione loggata come ERROR                            |
|                                                                  |
| 7d. ReportData.model_dump_json() -> apiguard_report.json         |
|       Mkdir difensivo prima della scrittura: se il blocco 7c ha  |
|       fallito, la directory potrebbe non esistere ancora.        |
|       -> OSError loggato come ERROR                              |
+-----------------------------------+------------------------------+

OUTPUT: evidence.json  assessment_report.html  apiguard_report.json
        + exit code: 0 (CLEAN) | 1 (FAIL) | 2 (ERROR) | 10 (INFRA)
```

---

### 4.1 Catalogo dei test pianificati e mappa delle dipendenze (DAG completo)

Questa sezione documenta l'intera superficie di test della metodologia —
test implementati e pianificati — insieme alle dipendenze dichiarate e
all'ordine di esecuzione che ne deriva. I test non ancora implementati
sono inclusi per rendere esplicito l'ordine di sviluppo atteso e il
comportamento del DAG a regime.

#### Catalogo per dominio

**Domain 0 — API Discovery and Inventory Management (3 test)**

- `test_0_1_shadow_api_discovery.py` — P0, BLACK_BOX. Fuzzing con wordlist standard
  di path comuni non documentati; confronta le risposte con la superficie OpenAPI per
  identificare Shadow API. Nessun prerequisito.
- `test_0_2_deny_by_default.py` — P0, BLACK_BOX. Verifica che il Gateway risponda
  404/403 a path non registrati senza rivelare topology interna. Testa anche varianti
  URL-encoded e path normalization su path documentati autenticati.
- `test_0_3_deprecated_api_enforcement.py` — P0, BLACK_BOX. Estrae endpoint con
  `deprecated: true` dalla spec OpenAPI; verifica presenza header `Sunset` (RFC 8594)
  e, se la data sunset è trascorsa, che la risposta sia `410 Gone` (RFC 9110).

**Domain 1 — Identity & Authentication (6 test)**

- `test_1_1_authentication_required.py` — P0, BLACK_BOX. Verifica che ogni
  endpoint protetto restituisca 401 senza token. Nessun prerequisito. È il
  test che conferma che l'autenticazione esiste sul perimetro.
- `test_1_2_jwt_signature_validation.py` — P0, GREY_BOX. Attacchi `alg:none`,
  payload manomesso, key confusion RS256→HS256, signature stripping. Richiede
  un JWT valido ottenuto via Forgejo `/api/v1/users/token` con Basic Auth.
- `test_1_3_token_expiry.py` — P0, GREY_BOX. Token con `exp` nel passato deve
  restituire 401. Richiede `helpers/jwt_forge.py` (da implementare in Milestone 2).
- `test_1_4_token_revocation.py` — P2, GREY_BOX. Login → logout
  (`DELETE /api/v1/user/keys/{id}`) → riuso del token deve dare 401.
- `test_1_5_insecure_credential_transport.py` — P2, WHITE_BOX. Verifica redirect HTTP→HTTPS
  e header HSTS. In ambiente HTTP-only questo test produce `SKIP` documentato.
- `test_1_6_secure_session_management.py` — P3, WHITE_BOX. Audit configurazione
  session store via Kong Admin API.

**Domain 2 — Authorization (5 test)**

- `test_2_1_rbac_enforcement.py` — P2, GREY_BOX. Token user tenta endpoint
  admin. Dipende da `1.1`.
- `test_2_2_bola_prevention.py` — P1, GREY_BOX. user_a accede a risorse di
  user_b tramite ID. Richiede risorse create su entrambi gli account
  (`helpers/forgejo_resources.py`).
- `test_2_3_destructive_operations_privilege.py` — P1, GREY_BOX.
- `test_2_4_authorization_consistency.py` — P1, GREY_BOX.
- `test_2_5_excessive_data_exposure.py` — P2, GREY_BOX.

**Domain 3 — Data Integrity (2 test)**

- `test_3_1_input_validation.py` — P2, GREY_BOX. SQL injection, NoSQL
  injection, type confusion, oversized payloads. Usa `data/injection_payloads.py` (da implementare in Milestone 2).
- `test_3_3_hmac_config_audit.py` — P3, WHITE_BOX. Audit HMAC/signing.

**Domain 4 — Availability (3 test)**

- `test_4_1_rate_limiting.py` — P0, BLACK_BOX. Loop empirico fino a 429.
  Usa i parametri `config.tests.domain_4.test_4_1.*`.
- `test_4_2_timeout_config_audit.py` — P1, WHITE_BOX. Audit valori timeout
  sul gateway. Usa `target.gateway` (`BaseGatewayAdapter`).
- `test_4_3_circuit_breaker_audit.py` — P1, WHITE_BOX. Audit Admin API per
  plugin circuit-breaker. Usa `target.gateway` (`BaseGatewayAdapter`).

**Domain 5 — Visibility (2 test)**

- `test_5_1_audit_logging.py` — P1, GREY_BOX. Verifica che le richieste
  compaiano nei log Kong (`/dev/stdout`).
- `test_5_2_security_alerting.py` — P2, GREY_BOX. Brute-force simulato
  e verifica alert.

**Domain 6 — Hardening (4 test)**

- `test_6_1_error_handling.py` — P2, GREY_BOX. Stack trace assenti nelle
  risposte di errore. Usa `helpers/response_inspector.py`.
- `test_6_2_security_headers_audit.py` — P3, WHITE_BOX. HSTS, CSP, X-Frame-Options.
- `test_6_3_layer7_hardening.py` — P1, GREY_BOX + WHITE_BOX. HTTP smuggling
  CL.TE, CORS wildcard.
- `test_6_4_hardcoded_credentials_audit.py` — P2, WHITE_BOX. Audit configurazione
  gateway e variabili d'ambiente. Usa `target.gateway` (`BaseGatewayAdapter`).

**Domain 7 — Business Logic (4 test)**

- `test_7_1_business_flow_abuse.py` — P2, GREY_BOX.
- `test_7_2_ssrf_prevention.py` — P0, GREY_BOX. Payload `169.254.169.254`,
  IPv6, encoding bypass. Usa `data/ssrf_payloads.py`. Il test crea un
  repository via Forgejo (injection vector webhook), quindi richiede credenziali
  GREY_BOX pur essendo priorità P0.
- `test_7_3_idempotency.py` — P2, GREY_BOX. Race condition su operazioni
  critiche.
- `test_7_4_external_api_consumption.py` — P2, GREY_BOX. Webhook signature
  verification.

#### Mappa delle dipendenze (`depends_on`)

| Test | `depends_on` | Note |
|------|-------------|------|
| `0.1` | `[]` | BLACK_BOX — nessun prerequisito |
| `0.2` | `[]` | BLACK_BOX — nessun prerequisito |
| `0.3` | `[]` | BLACK_BOX — nessun prerequisito |
| `1.1` | `[]` | BLACK_BOX — nessun prerequisito |
| `1.2` | `["1.1"]` | Pivot del DAG: sblocca tutti i GREY_BOX |
| `1.3` | `["1.1", "1.2"]` | Riusa `jwt_forge.py` da `1.2` (da implementare in Milestone 2) |
| `1.4` | `["1.1"]` | GREY_BOX — dipende da `1.1` per token; non richiede `jwt_tool` |
| `1.5` | `[]` | WHITE_BOX — SKIP documentato in ambiente HTTP-only |
| `1.6` | `[]` | WHITE_BOX — richiede Kong Admin API |
| `2.1` | `["1.1"]` | GREY_BOX — dipende solo da `1.1` in M1 |
| `2.2` | `["1.1", "1.2"]` | |
| `2.3` | `["1.1", "1.2", "2.1"]` | |
| `2.4` | `["1.1", "1.2", "2.1"]` | |
| `2.5` | `["1.1", "1.2"]` | |
| `3.1` | `["1.1", "1.2"]` | |
| `3.3` | `[]` | WHITE_BOX — HMAC audit |
| `4.1` | `[]` | BLACK_BOX — loop empirico fino a 429 |
| `4.2` | `[]` | WHITE_BOX — richiede Kong Admin API |
| `4.3` | `[]` | WHITE_BOX — richiede Kong Admin API |
| `5.1` | `["1.1", "1.2"]` | |
| `5.2` | `["1.1", "5.1"]` | |
| `6.1` | `["1.1", "1.2"]` | |
| `6.2` | `[]` | WHITE_BOX |
| `6.3` | `["1.1"]` | |
| `6.4` | `[]` | WHITE_BOX — richiede Kong Admin API |
| `7.1` | `["1.1", "1.2"]` | |
| `7.2` | `[]` | GREY_BOX — payload SSRF (P0; crea repo Forgejo come injection vector) |
| `7.3` | `["1.1", "1.2"]` | |
| `7.4` | `["1.1", "1.2"]` | |

**Il test `1.2` è il pivot del DAG.** La quasi totalità dei test GREY_BOX
dipende da esso perché è il test che acquisisce i token JWT validi per
`ROLE_USER_A`, `ROLE_USER_B` e `ROLE_ADMIN` e li scrive nel `TestContext`.
Un fallimento o SKIP di `1.2` propaga uno SKIP a cascata su tutti i test
che dipendono da token validi.

#### Batch di esecuzione risultanti

**Batch 1** — nessuna dipendenza (eseguiti per primi):
test nativi: `0.1`, `0.2`, `0.3`, `1.1`, `1.5`, `1.6`, `3.3`, `4.1`, `4.2`, `4.3`,
`6.2`, `6.4`, `7.2`; test esterni (ExternalTestRegistry): `ext.0.1.nuclei`, `ext.1.5.testssl`, `ext.1.5.sslyze`.

Questi test lavorano interamente sulla spec OpenAPI, fanno fuzzing su path,
eseguono loop empirici o audit di configurazione. Nessuno richiede stato
accumulato da test precedenti. I test esterni non transitano per il DAGScheduler
ma sono privi di dipendenze; vengono eseguiti nella stessa finestra temporale
via ExternalTestRegistry (Phase R4).

**Batch 2** — dipende solo da `1.1`:
test pianificati: `1.2`, `1.4`, `6.3`. **In Milestone 1**, dove `1.2` non è ancora
implementato, il batch effettivo è composto da **`1.4`** (token revocation)
e **`2.1`** (RBAC enforcement): entrambi dichiarano `depends_on=["1.1"]` perché
condividono il token JWT acquisito via `acquire_tokens()` nel `TestContext`.
Quando `1.2` sarà aggiunto in Milestone 2, sarà il test più complesso del
progetto (acquisizione token, forgia JWT malformati per signature validation
sub-tests); `5.2` simulerà brute-force (loop sequenziale inline); `6.3`
testerà HTTP smuggling e CORS con request ad hoc.

**Batch 3** — dipende da `1.1` + `1.2` (o da test del Batch 2):
tutti i rimanenti GREY_BOX dei domini 2, 3, 5, 6, 7 della roadmap M2.
**In Milestone 1 il Batch 3 è vuoto** perché `1.2` non esiste ancora — i
test che lo richiederebbero (`2.1`, `2.2`, `3.1`, ecc.) o non sono implementati
o hanno il `depends_on` ridotto al solo `1.1` (caso di `2.1`).

#### Mappa degli helper condivisi

La scelta di quali funzioni estrarre in helper e quali lasciare inline nel
test segue un criterio preciso: si estrae solo quando la stessa logica è
usata da test di domini diversi, o quando la complessità è sufficiente da
oscurare il flusso del test se lasciata inline.

| Helper | Usato da | Giustificazione |
|--------|----------|-----------------|
| `helpers/auth.py` | `1.4`, `2.1`, `7.2` (Milestone 1); `1.2` (Milestone 2) | Dispatcher di autenticazione — acquisisce token JWT e li scrive nel `TestContext` via `acquire_tokens()`. Usato da tutti i test GREY_BOX che necessitano di credenziali. |
| `helpers/jwt_forge.py` | `1.2`, `1.3` | Da implementare in Milestone 2; condiviso tra due test dello stesso dominio |
| `helpers/forgejo_resources.py` | `1.4`, `7.2` (Milestone 1); `2.2`, `2.3`, `7.3` (Milestone 2) | Creazione e teardown di risorse Forgejo (repo, issue, token); stesso pattern CRUD condiviso tra test di domini diversi |
| `helpers/path_resolver.py` | `1.1`, `6.2` (Milestone 1) | Sostituzione dei path parameter (`{owner}`, `{repo}`, ecc.) con valori reali tramite `resolve_path_with_seed()` |
| `src/core/gateway/base.py` | `3.3`, `4.2`, `4.3`, `6.4` (Milestone 1) | `BaseGatewayAdapter` via `target.gateway` — astrazione del layer admin del gateway; stesso pattern usato da quattro test WHITE_BOX |
| `helpers/response_inspector.py` | `6.2` (Milestone 1); `2.5`, `6.1` (Milestone 2) | Pattern di analisi body/header ripetuto in test di domini diversi |

Il modulo `data/ssrf_payloads.py` è usato da `7.2`.
`data/injection_payloads.py` sarà aggiunto in Milestone 2 per il test `3.1`.

---

### Fase 2 — OpenAPI Discovery: dettagli non banali

La discovery risolve due problemi specifici del target environment reale.

**Timeout di prance:** la libreria `prance` usa `requests` internamente, che non ha un timeout di default e puo bloccarsi indefinitamente. `discovery/openapi.py` esegue l'intera operazione in un thread di background via `concurrent.futures` e la abbandona dopo `openapi_fetch_timeout_seconds` secondi, convertendo il `TimeoutError` in `OpenAPILoadError`. Il thread di background puo continuare brevemente dopo l'abbandono — accettabile per un tool CLI che termina il processo poco dopo.

**Supporto Swagger 2.0 con `type: file`:** prance non riesce a validare spec Swagger 2.0 che dichiarano `type: file` sui parametri upload (sintassi valida ma non JSON Schema Draft 4). Il modulo usa `_NonValidatingResolvingParser`, una sottoclasse che sovrascrive `_validate()` per eseguire solo la dereferenziazione `$ref` saltando la validazione interna di prance. La validazione strutturale viene poi eseguita da `openapi-spec-validator` con il validatore appropriato al dialetto rilevato. Questo e il motivo dell'unico pin esatto (`==`) in `pyproject.toml`: `prance` accede a un attributo interno via name-mangling Python (`_ResolvingParser__reference_cache`) e qualsiasi aggiornamento potrebbe rompere silenziosamente questo meccanismo.

---

### Fase 4 — Test Discovery: il discovery senza registro centrale

`TestRegistry` non mantiene alcuna lista hardcoded. Il registry esegue tre sottofasi:

**R1 — Module scan:** `pkgutil.walk_packages` scansiona ricorsivamente `src.tests`, importando solo i moduli il cui nome finale inizia con `test_`. Gli errori di import di singoli moduli vengono loggati come WARNING senza bloccare la scoperta degli altri: un test rotto non deve impedire l'esecuzione dei test validi.

**R2 — Subclass extraction:** per ogni modulo importato, `inspect.getmembers` trova tutte le classi che sono sottoclassi concrete di `BaseTest` non astratte, definite nel modulo corrente (guard contro il double-counting), e in possesso di tutti i metadati obbligatori verificati da `has_required_metadata()`.

**R3 — Filtering:** filtro per `priority <= min_priority` e `strategy in enabled_strategies`. Output ordinato per `test_id` lessicograficamente per determinismo indipendentemente dall'ordine di traversal del filesystem.

**DAGScheduler — stall detection:** l'implementazione di `_drain_into_batches` include una guardia esplicita: se `is_active()` restituisce `True` ma `get_ready()` non produce nodi, il sorter e in uno stato irrecuperabile. In questo caso vengono loggati come ERROR tutti i `test_id` che erano attesi ma non sono stati estratti, e l'algoritmo interrompe il ciclo. Questo garantisce che l'operatore legga immediatamente quali dichiarazioni `depends_on` ispezionare, anziche scoprire il problema indirettamente durante la Fase 5 tramite un errore `test_id_not_in_lookup`.

---

### Fase 5 — Il contratto di `BaseTest.execute()` e la gestione del tempo

Il motore chiama `test.execute(target, context, client, store)` per ogni test misurando il tempo wall-clock. Il `duration_ms` viene injettato nel `TestResult` **dopo** il ritorno di `execute()`, tramite `result.model_copy(update={"duration_ms": ...})`. Questo mantiene il contratto che `execute()` non conosce il proprio tempo di esecuzione.

Il contratto di `execute()` ha quattro invarianti:

- Deve **sempre** ritornare un `TestResult`. Non deve **mai** sollevare eccezioni.
- Dopo **ogni** `client.request()`, il test deve chiamare `self._log_transaction(record, oracle_state=...)`.
- Il flusso canonico per una transazione FAIL e: `store.add_fail_evidence(record)` -> `self._log_transaction(record, oracle_state="BYPASS", is_fail=True)` -> `findings.append(Finding(..., evidence_ref=record.record_id))`.
- Le risorse persistenti create vanno registrate **immediatamente** con `context.register_resource_for_teardown(method, path)`, prima di qualsiasi assertion successiva.

---

## 5. Componenti chiave — Come si parlano

### AssessmentEngine — non riutilizzabile

`AssessmentEngine` e progettato deliberatamente per **non essere riutilizzabile** tra run successivi. Ogni istanza viene creata da `cli.py` per una singola chiamata a `run()`. Riutilizzare la stessa istanza rischierebbe di contaminare i risultati del run successivo con lo stato del precedente (token nel `TestContext`, evidenze nell'`EvidenceStore`, risultati nel `ResultSet`). Il `run_id` ha formato `apiguard-{YYYYMMDD}-{HHMMSS}-{microseconds}` — timestamp-based anziche UUID per leggibilita umana nei log e ordinabilita cronologica.

### SecurityClient — la coppia con EvidenceStore

`SecurityClient` (`core/client.py`) e un wrapper centralizzato attorno a `httpx`. L'`httpx.Client` interno **non viene creato nel costruttore**: viene creato in `__enter__`, rendendo il client utilizzabile solo come context manager. Questa scelta e intenzionale: chi dimentica il `with` ottiene un `RuntimeError` invece di un resource leak silenzioso.

Il client e **non thread-safe**, coerentemente con il modello di esecuzione sequenziale della V1.0.

**Retry policy:** si applica esclusivamente alle eccezioni di trasporto — `ConnectError`, `ConnectTimeout`, `ReadTimeout`, `WriteTimeout`, `PoolTimeout`, `RemoteProtocolError`. `httpx.HTTPStatusError` (4xx, 5xx) **non viene mai retried**: un `503` e una risposta valida che il test deve ricevere, non un errore transitorio da nascondere. La formula del backoff e `min(wait_max, wait_min * 2^(attempt-1)) + random(0, jitter)`.

**Costruzione dell'EvidenceRecord:** il corpo delle request e ricostruito solo se passato come `json`. Il corpo raw (`content: bytes`) non viene incluso per evitare di codificare in base64 payload binari nell'`evidence.json`. Response bodies binarie o non decodificabili diventano la stringa `"[Binary or undecodable response body]"`. Gli header di response vengono normalizzati in lowercase.

I `record_id` seguono il formato `{test_id}_{counter:03d}` (es. `1.2_001`, `1.2_002`). Il counter e per-`test_id` e si azzera a ogni nuovo run (il client e costruito per run).

**EvidenceStore** (`core/evidence.py`) seleziona cosa registrare con tre percorsi distinti:

- `add_fail_evidence(record)`: percorso obbligatorio per ogni transazione FAIL.
- `pin_evidence(record)`: percorso opzionale per transazioni di setup che stabiliscono il contesto. Poiche `EvidenceRecord` e frozen, il pinning crea una copia immutabile via `model_copy(update={"is_pinned": True})` invece di mutare il record originale.
- `pin_artifact(label, data)`: terzo percorso, usato esclusivamente da `ExternalToolTest`. Registra l'output grezzo di un tool esterno come `EvidenceRecord` sintetico, sanitizza le credenziali dall'artifact, e restituisce un `evidence_ref` stringa da passare a `Finding.evidence_ref`. Persiste opzionalmente una copia JSON in `outputs/tools/`.

L'architettura v2.0 e streaming JSONL: ogni test ha un file dedicato in `outputs/evidence_tmp/<test_id_safe>.jsonl`, aperto da `begin_test()`, scritto con flush immediato da `add_fail_evidence()` e `pin_evidence()`, chiuso da `end_test()`. In Phase 7, `merge_and_finalize()` legge tutti i file JSONL, li ordina per timestamp, e produce l'envelope `evidence.json` finale. Capacita illimitata: test 1.1 su un target con 100+ endpoint puo produrre centinaia di record FAIL senza perdita (la precedente v1.0 con `deque(maxlen=100)` li espelleva silenziosamente). Crash-resiliente: i file JSONL in `evidence_tmp/` sopravvivono a un kill tra Phase 5 e Phase 7.

`get_by_id()` e una scansione lineare `O(n)` sull'ultimo buffer in memoria, chiamata solo durante la Fase 7. L'ordinamento cronologico e garantito da `merge_and_finalize()` che ordina i record di tutti i file per `timestamp_utc`.

### TargetContext vs TestContext

**`TargetContext` (frozen):** tutto cio che e staticamente noto sul target prima che inizi l'esecuzione. Contiene `base_url` e `admin_api_url` come `AnyHttpUrl`, validati da Pydantic alla costruzione. Il campo `gateway` contiene il `BaseGatewayAdapter` istanziato da engine.py Phase 3 (o `None` se non configurato). Il computed field `admin_api_available` centralizza il controllo per l'eligibilita dei test WHITE_BOX, esprimendo **capacita** (`target.gateway is not None`) anziche **dettaglio implementativo** (`admin_api_url is not None`). I metodi `endpoint_base_url()` e `admin_endpoint_base_url()` esistono per risolvere un problema concreto: `AnyHttpUrl` di Pydantic v2 non e un `str`, e la concatenazione diretta produce artefatti con doppio slash. Il field `credentials` non deve mai apparire in log strutturati. Il field `external_tools: ExternalToolsConfig` espone la configurazione immutabile dei tool esterni (timeout, flag, versioni attese) a ogni `ExternalToolTest` via `target.external_tools.<tool>.*`. Il field `tests_config: RuntimeTestsConfig` espone i parametri di tuning per-test (soglie, cap, payload config) ai test nativi via `target.tests_config.*`.

**`TestContext` (mutable):** i tre campi privati (`_tokens`, `_resources`, `_shared_data`) sono `PrivateAttr` di Pydantic, esclusi dalla serializzazione e dalla validazione del modello. L'interfaccia tipizzata e l'unico modo di accedere a questi dati dall'esterno.

**Token channel:** `set_token(role, token)`, `get_token(role) -> str | None`, `has_token(role)`, `stored_roles()`. Il token e memorizzato **senza** il prefisso `'Bearer '` — i test che costruiscono header `Authorization` devono aggiungerlo esplicitamente: `f"Bearer {context.get_token(ROLE_USER_A)}"`. `set_token()` solleva `ValueError` se il role o il token sono vuoti dopo lo strip.

**Teardown channel:** `register_resource_for_teardown(method, path, headers)`, `drain_resources()`. Accetta un parametro opzionale `headers` per le risorse il cui endpoint DELETE richiede autenticazione esplicita. `drain_resources()` restituisce una lista di 3-tuple `(method, path, headers)` in ordine LIFO e svuota il registro per prevenire double-delete.

**Shared data channel:** `set_shared(key, value)`, `get_shared(key, default)`, `has_shared(key)`, `shared_keys()`. General-purpose per dati calcolati da un test e consumati da test con dipendenze dichiarate. Convenzione: chiave `"{test_id}.{data_name}"` per rendere esplicito il test produttore.

---

## 6. Modello dei dati — I tre SSOT e la gerarchia in memoria

`src/core/models/` è il **vocabolario condiviso** dell'intero tool: l'unico package autorizzato a definire strutture dati condivise (package con `enums.py`, `http.py`, `results.py`, `runtime.py`, `surface.py`, `external_tools.py` + facade `__init__.py`).

### I tre SSOT

| SSOT | Oggetto | Dove vive | Scopo |
|---|---|---|---|
| **Logica** | `ResultSet` | In memoria durante l'esecuzione | Determina l'exit code, accumula i `TestResult` |
| **Presentazione** | `ReportData` | In memoria durante la Fase 7 | DTO che traduce il `ResultSet` in struttura pronta per HTML e JSON |
| **Forense** | `EvidenceStore` | Per-test JSONL in `evidence_tmp/` → merge in `evidence.json` (Phase 7) | Cassaforte dei payload completi per le transazioni FAIL |

Senza `ReportData` come DTO separato, sarebbe necessario "sporcare" il core del motore con informazioni che servono solo al layer di presentazione (titolo della spec API, raggruppamento per dominio, label leggibili delle priorita), rendendo il codice significativamente piu difficile da mantenere e testare.

### La gerarchia in memoria

```
ResultSet  (SSOT della logica — l'intera sessione di assessment)
|
|-- started_at, completed_at, results: [...]
|
+-- TestResult  (es. Test 1.1 — Authentication Required)
    |
    |-- status: FAIL | PASS | SKIP | ERROR
    |-- message, duration_ms    (duration_ms injettato via model_copy() dall'engine)
    |-- test_name, domain, priority, strategy, cwe_id, tags
    |
    |-- findings: [ Finding ]             <- presenti SOLO se status=FAIL
    |             |
    |             |-- title, detail, references: ["CWE-306", "OWASP-API2:2023"]
    |             +-- evidence_ref: "1.1_005" --------------------------------+
    |                                                                         | (link forense)
    +-- transaction_log: [                                                    |
          TransactionSummary  (PASS — leggero, ~860 byte)                    |
            +-- record_id, url, method, status_code, oracle_state="ENFORCED" |
                                                                             |
          TransactionSummary  (FAIL — leggero, ~860 byte)                   |
            |-- record_id: "1.1_005" <-- stesso ID, cross-reference         |
            |-- oracle_state: "BYPASS"                                       |
            |-- is_fail_evidence: true                                       |
            |-- request_body: "..." (troncato a 2.000 char)                  |
            +-- response_body_preview: "..." (troncato a 1.000 char)         |
        ]                                                                    |
                                                                             |
===========================================================================  |
  EvidenceStore (SSOT forense — streaming JSONL v2.0, unbounded)            |
===========================================================================  |
                                                                             |
  EvidenceRecord  (FAIL — completo, ~11 KB)  <-----------------------------+
    |-- record_id: "1.1_005"  (formato: {test_id}_{counter:03d})
    |-- timestamp_utc
    |-- request_method, request_url
    |-- request_headers (Authorization: sempre [REDACTED] da field_validator)
    |-- request_body (solo per payload JSON; bytes non inclusi)
    |-- response_status_code, response_headers (normalizzati lowercase)
    +-- response_body (fino a 10.000 char; binario -> stringa placeholder)


===========================================================================
  evidence.json (envelope di output)
===========================================================================

  {
    "generated_at_utc": "...",       <- metadata di traceabilita
    "record_count": N,
    "records": [...]                 <- array ordinato per timestamp_utc
  }


===========================================================================
  Fase 7: builder.py produce ReportData (SSOT di presentazione)
===========================================================================

  ResultSet  --> builder.py  --> ReportData (DTO)
                                   |-- run_id, generated_at_utc, target_base_url
                                   |-- spec_title, spec_version, strategies_label
                                   |-- executive_summary: ExecutiveSummary
                                   +-- domains: [
                                         DomainSummary(domain=0, name="API Discovery...")
                                           +-- rows: [ TestResultRow, ... ]
                                       ]

  ReportData  --> renderer.py  --> assessment_report.html
  ReportData  --> model_dump_json()  --> apiguard_report.json
```

### Il dual audit trail

**`TransactionSummary` — log ibrido (audit trail leggero)**
- Vive in `TestResult.transaction_log`, embedded nel report HTML
- Registra **ogni** transazione HTTP, incluse quelle PASS
- Body troncato ("airbag") applicato trasparentemente dalla factory `TransactionSummary.from_evidence_record()`: request body a 2.000 char, response body a 1.000 char. Il test non gestisce mai la troncatura.
- Nessun cap sul numero di record. A ~860 byte per entry, anche il worst-case Test 4.1 (fino a 2.000 entry) aggiunge ~1,7 MB al report HTML — sicuro per RAM e browser moderni.
- Scopo: **proof of coverage** e triage rapido senza aprire `evidence.json`

**`EvidenceRecord` — scatola nera (archivio forense pesante)**
- Vive in `EvidenceStore`, serializzato in `evidence.json`
- Registra solo transazioni FAIL e pinned
- Transazione completa: tutti gli header di response, body fino a 10.000 char
- Streaming JSONL v2.0 — unbounded; per-test `.jsonl` in `evidence_tmp/`, merge in Phase 7
- Scopo: **prova formale riproducibile** — ogni record e autosufficiente per ricostruire l'attacco

### Invarianti enforced a livello di modello

Validate da Pydantic a runtime, non da logica di business nei test:

- `TestResult(status=FAIL)` **deve** avere almeno un `Finding`. Enforced da `model_validator(mode="after")`.
- `TestResult(status=PASS)` **deve** avere la lista `findings` vuota.
- `TestResult(status=SKIP)` **deve** avere `skip_reason` popolato.
- `EvidenceRecord.request_headers`: il valore dell'header `Authorization` e sempre `[REDACTED]`, enforced dal `field_validator` nel modello — non nel client. Questa separazione significa che anche un costruttore diretto di `EvidenceRecord` (che bypassa `_build_evidence_record`) applica comunque la redazione.
- `EndpointRecord.path` deve iniziare con `/`. `EndpointRecord.method` e sempre uppercase.

### Catalogo dei modelli (`src/core/models/`)

```
# Enumerazioni
TestStatus          StrEnum: PASS | FAIL | SKIP | ERROR
TestStrategy        StrEnum: BLACK_BOX | GREY_BOX | WHITE_BOX
SpecDialect         StrEnum: SWAGGER_2 | OPENAPI_3

# Audit trail — dual trail
EvidenceRecord      Frozen Pydantic — snapshot forense di una transazione FAIL (~11 KB)
TransactionSummary  Frozen Pydantic — entry ibrida per audit trail leggero (~860 byte)

# Risultati
Finding             Pydantic — unita di evidenza tecnica (title, detail, CWE, evidence_ref)
TestResult          Pydantic — esito completo di BaseTest.execute() + transaction_log
ResultSet           Pydantic — collezione ordinata di tutti i TestResult + calcolo exit code

# Attack Surface
ParameterInfo       Frozen Pydantic — descrittore di un parametro OpenAPI
EndpointRecord      Frozen Pydantic — descrittore di un'operazione HTTP (path + method)
AttackSurface       Frozen Pydantic — mappa completa delle operazioni esposte dal target

# Report
TestResultRow       Frozen Pydantic — TestResult appiattito per rendering Jinja2
DomainSummary       Frozen Pydantic — raggruppamento di TestResultRow per dominio
ReportData          Frozen Pydantic — DTO completo per rendering HTML e JSON

# Configurazione runtime propagata a TargetContext
RuntimeCredentials  Frozen Pydantic — credenziali per test GREY_BOX e WHITE_BOX
RuntimeTestsConfig  Frozen Pydantic — parametri per test specifici (es. max_endpoints_cap)
```

---

## 7. Guida per i contributor — Come aggiungere un nuovo test

Questa sezione raccoglie i dettagli operativi di `BaseTest` che un contributor deve conoscere prima di scrivere un nuovo test nativo. Il **contratto completo + il template passo-passo per aggiungere un nuovo test** vivono in [`docs/pub/ADDING_tests.md`](ADDING_tests.md) (per i test nativi `BaseTest`) e in [`docs/pub/ADDING_external_tests.md`](ADDING_external_tests.md) (per i test esterni `ExternalToolTest` con connector verso tool come `nuclei`, `testssl.sh`, `sslyze`). Quei due documenti sono l'authoritative reference. Questa sezione qui sotto è la sintesi *strutturale* dei pattern interni di `BaseTest`, utile come quick-reference durante la scrittura di un test.

### Struttura interna di BaseTest: dettagli rilevanti

**`_transaction_log` e instance-level, non ClassVar.** Questo e deliberato: un `ClassVar` significherebbe che tutte le istanze della stessa classe condividono un unico log, corrompendo l'audit trail se la classe venisse istanziata piu di una volta nel pipeline. Poiche `TestRegistry` crea ogni classe esattamente una volta e l'engine chiama `execute()` esattamente una volta per istanza, non e necessario un meccanismo di reset.

**`_make_error` include il log parziale.** Anche un risultato `ERROR` include le `TransactionSummary` accumulate prima dell'eccezione. Questo e diagnosticamente prezioso: mostra quali interazioni HTTP erano gia completate prima del crash, aiutando a identificare il punto di fallimento.

**Guard clauses disponibili** (usare in cima a `execute()` prima di qualsiasi HTTP request):

| Metodo | Condizione di SKIP |
|---|---|
| `_requires_token(context, ROLE_*)` | Token JWT assente nel TestContext |
| `_requires_attack_surface(target)` | AttackSurface non popolata (infrastrutturale) |
| `_requires_grey_box_credentials(target)` | Nessuna credenziale GREY_BOX configurata |
| `_requires_admin_api(target)` | `admin_api_url` assente (Kong DB-less) |

**Oracle state canonici** per `_log_transaction(oracle_state=...)`:

`'ENFORCED'` — 401/403 su path protetto (comportamento atteso corretto)
`'BYPASS'` — 2xx senza credenziali (violazione)
`'RATE_LIMIT_HIT'` — 429 durante probe loop
`'CORRECTLY_DENIED'` — 404 su path inesistente (atteso)
`'SUNSET_MISSING'` — endpoint deprecato attivo senza Sunset header
`'INCONCLUSIVE_PARAMETRIC'` — 404 atteso per ID risorsa placeholder

### Convenzioni obbligatorie

| Aspetto | Regola |
|---|---|
| `test_id` | Formato `"{domain}.{sequence}"`, univoco nell'intero progetto |
| `depends_on` | Lista dei `test_id` prerequisiti; `[]` se il test non ha dipendenze |
| HTTP requests | **Esclusivamente** tramite `client.request()`. Import diretto di `httpx` e vietato |
| `_log_transaction()` | Obbligatorio dopo **ogni** `client.request()` |
| Ordine per FAIL | `store.add_fail_evidence(record)` **prima** di `_log_transaction(..., is_fail=True)` |
| Token prefix | I token sono memorizzati **senza** 'Bearer ' — aggiungerlo nell'header |
| Guard clauses | Usa i metodi `_requires_*` per i prerequisiti comuni |
| Catch-all | Il blocco `try/except Exception` con `_make_error()` e obbligatorio |
| Teardown | Registrare le risorse **immediatamente** con `context.register_resource_for_teardown()` |

### Helper disponibili (`src/tests/helpers/`)

| Modulo | Contenuto |
|---|---|
| `auth.py` | Acquisizione token JWT tramite Forgejo API con Basic Auth |
| `forgejo_resources.py` | Creazione e gestione di repository, issue, token API Forgejo |
| `jwt_forge.py` | Da implementare in Milestone 2; costruzione di JWT con claim arbitrari (test 1.2/1.3) |
| `path_resolver.py` | Sostituzione dei path parameter (`{owner}`, `{repo}`, ecc.) con valori reali tramite `resolve_path_with_seed()` |
| `response_inspector.py` | Analisi strutturata di header e body delle response |
| `src/core/gateway/base.py` | `BaseGatewayAdapter` via `target.gateway.*` — astrazione admin layer del gateway |

### Payload di attacco disponibili (`src/tests/data/`)

| Modulo | Contenuto |
|---|---|
| `ssrf_payloads.py` | Payload SSRF: IP link-local (`169.254.169.254`), IPv6, encoding bypass |
| `injection_payloads.py` | Da implementare in Milestone 2 per test 3.1 |

---

## 8. Gerarchia delle eccezioni

Tutte le eccezioni custom del tool sono definite in `src/core/exceptions.py`.

```
ToolBaseError
  |-- ConfigurationError       -> Fase 1: config invalido o var env mancante [BLOCCA AVVIO]
  |-- OpenAPILoadError         -> Fase 2: spec irraggiungibile o malformata  [BLOCCA AVVIO]
  |-- DAGCycleError            -> Fase 4: dipendenza circolare tra test      [BLOCCA AVVIO]
  |-- SecurityClientError      -> Fase 5: errore HTTP non recuperabile       [-> TestResult(ERROR)]
  |-- AuthenticationSetupError -> Fase 5, helpers/auth.py: credenziali rifiutate (401/403)
  |                              fields: role, status_code
  |                              -> catturato in execute() -> TestResult(ERROR)
  |-- ExternalToolError        -> Fase 5, external tests
  |                              fields: tool_name, exit_code, timed_out
  |                              -> catturato in execute() -> TestResult(ERROR)
  |-- GatewayAdapterError      -> Fase 5, WHITE_BOX tests (src/core/gateway/base.py)
  |                              fields: path, status_code
  |                              -> catturato in execute() -> TestResult(ERROR)
  +-- TeardownError            -> Fase 6: fallimento cancellazione risorsa   [WARNING, non propagata]
```

Le prime tre sono **fatali**: si verificano prima che qualsiasi test giri e producono exit code 10. `SecurityClientError` e **recuperata a livello di singolo test** tramite il catch-all in `execute()` — l'engine non la vede mai. `TeardownError` e **intenzionalmente non propagata**: un fallimento di cleanup non invalida la correttezza dell'assessment, ma viene loggato con `manual_cleanup_required=True` per consentire la pulizia manuale.

Eccezioni dei CLI helper (fuori dalla pipeline Phase 1-7):

```
ToolBaseError
  |-- SeedGeneratorFetchError -> apiguard generate-seed: spec OpenAPI non scaricabile
  |                              fields: spec_source, reason
  |                              -> catturato in cli.py -> exit code non-zero
  +-- SeedGeneratorParseError -> apiguard generate-seed: spec OpenAPI non parsabile
                                 fields: spec_source, reason
                                 -> catturato in cli.py -> exit code non-zero
```

Entrambe sono definite localmente in `src/discovery/seed_generator.py` (stesso pattern di `GatewayAdapterError`): ereditano da `ToolBaseError` per uniformità della gerarchia, ma restano vicine al loro dominio d'uso. Non appaiono mai durante un assessment normale; solo il comando `apiguard generate-seed` può sollevarle.

`run()` cattura anche `Exception` generica al livello piu esterno: qualsiasi eccezione imprevista nell'engine stesso produce exit code 10 anziche un crash non gestito del processo.

---

## 9. Repository Structure

```
apiguard-assurance/
|-- config.yaml                  # Template di configurazione (versionabile)
|-- .env.example                 # Template variabili d'ambiente (non versionare .env)
|-- pyproject.toml               # Metadati progetto, dipendenze, configurazione tool
|
|-- src/
|   |-- cli.py                   # Entry point CLI (Typer), configurazione logging strutturato
|   |-- engine.py                # Orchestratore pipeline — 7 fasi sequenziali
|   |                            # Non riutilizzabile: una istanza per run
|   |
|   |-- config/                  # [Fase 1] Caricamento e validazione configurazione
|   |   |-- loader.py            # Lettura, interpolazione env vars, validazione YAML
|   |   +-- schema/              # Schemi Pydantic per config.yaml — package per dominio
|   |       |-- tool_config.py   # ToolConfig (gateway, execution, target sections)
|   |       |-- tests_config.py  # RuntimeTestsConfig + RuntimeTest*Config
|   |       |-- domain_0.py ... domain_7.py  # Parametri config per test di ciascun dominio
|   |       +-- external_tools.py  # Re-export da core/models/external_tools.py
|   |
|   |-- core/                    # Layer fondamentale — nessuna dipendenza da altri layer src/
|   |   |-- models/              # Vocabolario condiviso: package con facade __init__.py
|   |   |   |-- enums.py         # TestStatus, TestStrategy, SpecDialect
|   |   |   |-- http.py          # EvidenceRecord, TransactionSummary
|   |   |   |-- results.py       # Finding, InfoNote, TestResult, ResultSet
|   |   |   |-- runtime.py       # RuntimeCredentials, RuntimeTest*Config, RuntimeTestsConfig
|   |   |   |-- surface.py       # ParameterInfo, EndpointRecord, AttackSurface
|   |   |   +-- external_tools.py# BaseExternalToolConfig, TestsslConfig, NucleiConfig,
|   |   |                        #   ExternalToolsConfig
|   |   |-- gateway/             # Gateway adapter abstraction + concrete implementations
|   |   |   |-- base.py          # BaseGatewayAdapter ABC + GatewayAdapterError
|   |   |   +-- kong.py          # KongGatewayAdapter (Kong DB-less Admin API v3.x)
|   |   |-- context.py           # TargetContext (frozen) + TestContext (mutable) [Fasi 3+5+6]
|   |   |-- client.py            # SecurityClient — context manager, unico punto HTTP
|   |   |-- evidence.py          # EvidenceStore — streaming JSONL v2.0, unbounded
|   |   |-- dag.py               # DAGScheduler — topological sort + stall detection
|   |   +-- exceptions.py        # Gerarchia eccezioni: ToolBaseError e sottoclassi
|   |
|   |-- discovery/               # [Fase 2] Comprensione del target a runtime
|   |   |-- openapi.py           # Fetch + $ref deref (prance in thread) + validazione
|   |   +-- surface.py           # AttackSurface builder: spec dict -> modelli tipizzati
|   |
|   |-- tests/                   # [Fase 5] Implementazioni dei test, per dominio
|   |   |-- base.py              # BaseTest ABC — contratto + helper (_make_*, _requires_*)
|   |   |-- registry.py          # TestRegistry — discovery dinamica senza registro centrale
|   |   |-- strategy.py          # Re-export di TestStrategy per gli autori di test
|   |   |
|   |   |-- domain_0/            # API Discovery and Inventory Management
|   |   |   |-- test_0_1_shadow_api_discovery.py
|   |   |   |-- test_0_2_deny_by_default.py
|   |   |   +-- test_0_3_deprecated_api_enforcement.py
|   |   |
|   |   |-- domain_1/            # Identity and Authentication
|   |   |   |-- test_1_1_authentication_required.py
|   |   |   |-- test_1_4_token_revocation.py
|   |   |   |-- test_1_5_insecure_credential_transport.py
|   |   |   +-- test_1_6_secure_session_management.py
|   |   |
|   |   |-- domain_2/            # Authorization
|   |   |   +-- test_2_1_rbac_enforcement.py
|   |   |
|   |   |-- domain_3/            # Data Integrity
|   |   |   +-- test_3_3_hmac_config_audit.py
|   |   |
|   |   |-- domain_4/            # Availability & Resilience
|   |   |   |-- test_4_1_rate_limiting.py
|   |   |   |-- test_4_2_timeout_config_audit.py
|   |   |   +-- test_4_3_circuit_breaker_audit.py
|   |   |
|   |   |-- domain_5/            # Observability (placeholder — Milestone 2)
|   |   |-- domain_6/            # Configuration & Hardening
|   |   |   |-- test_6_2_security_headers_audit.py
|   |   |   +-- test_6_4_hardcoded_credentials_audit.py
|   |   |
|   |   |-- domain_7/            # Business Logic & Sensitive Flows
|   |   |   +-- test_7_2_ssrf_prevention.py
|   |   |
|   |   |-- helpers/             # Moduli condivisi tra test (non importati dal registry)
|   |   |   |-- auth.py
|   |   |   |-- auth_forgejo.py
|   |   |   |-- auth_jwt_login.py
|   |   |   |-- forgejo_resources.py
|   |   |   |-- path_resolver.py
|   |   |   +-- response_inspector.py
|   |   |
|   |   +-- data/                # Payload di attacco riutilizzabili
|   |       |-- auth_payloads.py
|   |       |-- inspector_patterns.py
|   |       |-- shadow_wordlists.py
|   |       |-- ssrf_payloads.py
|   |       +-- injection_payloads.py  (da implementare in Milestone 2)
|   |
|   |-- external_tests/          # [Fase 5] Test con tool esterni — gerarchia parallela a tests/
|   |   |-- base.py              # ExternalToolTest ABC + dev-mode cache logic
|   |   |-- registry.py          # ExternalTestRegistry (Phase R4: connector injection)
|   |   |-- ext_test_0_1_shadow_api_nuclei.py
|   |   +-- ext_test_1_5_tls_analysis.py
|   |
|   +-- report/                  # [Fase 7] Generazione del report finale
|       |-- builder.py           # ResultSet -> ReportData (DTO, solo aggregazione, zero I/O)
|       |-- renderer.py          # ReportData -> HTML + JSON (Jinja2, mkdir difensivo)
|       +-- templates/
|           +-- report.html      # Template Jinja2 del report HTML interattivo
|
|-- test-environments/
|   +-- forgejo-kong/            # Docker Compose per l'ambiente di test locale
|       |-- docker-compose.yml
|       +-- kong/
|           +-- kong.yml
|
|-- specs/
|   +-- crapi-openapi.json       # Spec alternativo: crAPI (target di validazione secondario)
|-- config_crapi.yaml            # Configurazione pronta per crAPI (vedi README sezione target alternativo)
+-- docs/
    +-- pub/                     # Public docs (contributor guides, architecture)
    |   +-- ADDING_tests.md
    |   +-- ADDING_external_tests.md
    |   +-- ARCHITECTURE.md
    +-- priv/                    # Internal docs (thesis, audit, project state)
        +-- PROJECT_status.md    # Stato implementazione: test, connector, milestone
        +-- apiguard_property.md
        +-- TOOLS_catalog.md
        +-- TOOLS_decisions.md
        +-- LOCAL_commands.md
        +-- AUDIT_milestone1_release.md
        +-- knowledge/           # Pre-project knowledge base (architecture, methodology, rules)
            +-- 2-Background_compact.md
            +-- 2-Background_extensive.md
            +-- 3-Metodologia.md
            +-- 4-Implementazione.md
            +-- 5-Scenario-test.md
            +-- RULES_claude.md
```

---

## 10. Packaging e distribuzione

`hatch build` produce due artefatti nella cartella `dist/` (esclusa dal repository):

| Artefatto | Nome | Scopo |
|-----------|------|-------|
| Wheel | `apiguard_assurance-X.Y.Z-py3-none-any.whl` | Installazione rapida via `pip install` — contiene solo `src/` |
| Source distribution | `apiguard_assurance-X.Y.Z.tar.gz` | Superficie pubblica completa — include `src/`, `docs/pub/`, `README.md`, `README.en.md`, `config.yaml`, `pyproject.toml`, `.env.example`, `install_tools.sh` |

Il tag `py3-none-any` indica che il pacchetto è **pure Python** (nessuna estensione C compilata), quindi portabile su qualsiasi sistema operativo e architettura con Python 3.11+.

**Contenuto del wheel:** esclusivamente `src/` e i metadata PyPI. I file `docs/priv/`, `outputs/`, `tools/`, `CLAUDE.md` e la cartella `.claude/` non entrano nel wheel — la whitelist è definita in `pyproject.toml` sotto `[tool.hatch.build.targets]`.

**Dipendenza opzionale sslyze:** un'installazione standard (`pip install apiguard-assurance`) non include sslyze (AGPL). Per abilitare `ext.1.5.sslyze` serve l'extra esplicito: `pip install "apiguard-assurance[sslyze]"`. Vedi D7.P2 in `docs/priv/apiguard_property.md`.

---

*APIGuard Assurance v0.1.0 — Architecture Reference*
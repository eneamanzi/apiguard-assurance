# APIGuard Assurance — Catalogo delle Proprietà Architetturali

- [D1 — Architettura \& Design](#d1--architettura--design)
  - [D1.P1 — API-Agnosticism (Agnosticismo Applicativo)](#d1p1--api-agnosticism-agnosticismo-applicativo)
  - [D1.P2 — Unidirectional Dependency Flow (Architettura a Strati con Dipendenze Monodirezionali)](#d1p2--unidirectional-dependency-flow-architettura-a-strati-con-dipendenze-monodirezionali)
  - [D1.P3 — Split State e Immutabilità (TargetContext Frozen + TestContext Mutable)](#d1p3--split-state-e-immutabilità-targetcontext-frozen--testcontext-mutable)
  - [D1.P4 — Dual Test Hierarchy (Native vs External — Contratti Paralleli)](#d1p4--dual-test-hierarchy-native-vs-external--contratti-paralleli)
  - [D1.P5 — Three-Tier Connector Hierarchy (DA-1)](#d1p5--three-tier-connector-hierarchy-da-1)
  - [D1.P6 — Gateway-Agnostic Adapter Pattern](#d1p6--gateway-agnostic-adapter-pattern)
- [D2 — Estensibilità \& Manutenibilità](#d2--estensibilità--manutenibilità)
  - [D2.P1 — Dynamic Test Discovery (Zero-Registration via pkgutil)](#d2p1--dynamic-test-discovery-zero-registration-via-pkgutil)
  - [D2.P2 — DAG-Based Dependency Scheduling (Ordinamento Topologico delle Dipendenze)](#d2p2--dag-based-dependency-scheduling-ordinamento-topologico-delle-dipendenze)
  - [D2.P3 — Separation of Data from Evaluation (ConnectorResult)](#d2p3--separation-of-data-from-evaluation-connectorresult)
  - [D2.P4 — Connector Lifecycle con Dependency Injection (DA-2)](#d2p4--connector-lifecycle-con-dependency-injection-da-2)
  - [D2.P5 — Auth Abstraction Layer (Auth Dispatcher)](#d2p5--auth-abstraction-layer-auth-dispatcher)
  - [D2.P6 — Category A/B Connector Classification (Obbligatorio vs Opzionale)](#d2p6--category-ab-connector-classification-obbligatorio-vs-opzionale)
  - [D2.P7 — Context-Aware Path Seed System con generate-seed CLI](#d2p7--context-aware-path-seed-system-con-generate-seed-cli)
  - [D2.P8 — Test Data Catalog Architecture (Pure-Data Layer)](#d2p8--test-data-catalog-architecture-pure-data-layer)
- [D3 — Config \& Riproducibilità](#d3--config--riproducibilità)
  - [D3.P1 — Config-Driven Development (Sviluppo Guidato dalla Configurazione)](#d3p1--config-driven-development-sviluppo-guidato-dalla-configurazione)
  - [D3.P2 — Single Source of Truth per Stato, Topologia e Ambiente](#d3p2--single-source-of-truth-per-stato-topologia-e-ambiente)
  - [D3.P3 — Black/Grey/White Box Gradient con Mapping Priorità-Strategia](#d3p3--blackgreywhite-box-gradient-con-mapping-priorità-strategia)
  - [D3.P4 — Reproducibility (Determinismo dell'Esecuzione)](#d3p4--reproducibility-determinismo-dellesecuzione)
  - [D3.P5 — Zero External State Dependency at Runtime](#d3p5--zero-external-state-dependency-at-runtime)
- [D4 — Robustezza \& Sicurezza](#d4--robustezza--sicurezza)
  - [D4.P1 — Streaming Evidence Store (JSONL — Unbounded Capacity)](#d4p1--streaming-evidence-store-jsonl--unbounded-capacity)
  - [D4.P2 — Evidence Sanitization come Responsabilità Centralizzata](#d4p2--evidence-sanitization-come-responsabilità-centralizzata)
  - [D4.P3 — Fail-Safe Error Isolation (Errori Isolati per Test)](#d4p3--fail-safe-error-isolation-errori-isolati-per-test)
  - [D4.P4 — Custom Exception Hierarchy con Phase Mapping](#d4p4--custom-exception-hierarchy-con-phase-mapping)
  - [D4.P5 — Graceful Degradation Multi-Livello](#d4p5--graceful-degradation-multi-livello)
  - [D4.P6 — Best-Effort Teardown (LIFO con Registrazione Esplicita)](#d4p6--best-effort-teardown-lifo-con-registrazione-esplicita)
  - [D4.P7 — Safe HTTP Probing Policy (Three-Outcome Oracle + Tier Segregation)](#d4p7--safe-http-probing-policy-three-outcome-oracle--tier-segregation)
  - [D4.P8 — Fail-Fast P0 Escalation Mode](#d4p8--fail-fast-p0-escalation-mode)
  - [D4.P9 — Type-Level TestResult Invariant Enforcement](#d4p9--type-level-testresult-invariant-enforcement)
- [D5 — Qualità \& Osservabilità](#d5--qualità--osservabilità)
  - [D5.P1 — Methodology Traceability (Tracciabilità alla Metodologia)](#d5p1--methodology-traceability-tracciabilità-alla-metodologia)
  - [D5.P2 — Finding/InfoNote Semantic Distinction](#d5p2--findinginfonote-semantic-distinction)
  - [D5.P3 — DRY Principle con Funzioni Autoritative Centrali](#d5p3--dry-principle-con-funzioni-autoritative-centrali)
  - [D5.P4 — Structured Logging con Credential Redaction Obbligatoria](#d5p4--structured-logging-con-credential-redaction-obbligatoria)
  - [D5.P5 — Report Domain-Centric Split (Native vs External)](#d5p5--report-domain-centric-split-native-vs-external)
- [D6 — CI/CD \& DevEx](#d6--cicd--devex)
  - [D6.P1 — Semantic Exit Codes per CI/CD Integration](#d6p1--semantic-exit-codes-per-cicd-integration)
  - [D6.P2 — Dev-Mode Evidence Cache (Acceleratore dello Sviluppo)](#d6p2--dev-mode-evidence-cache-acceleratore-dello-sviluppo)
  - [D6.P3 — Dual-Layer Type Safety (Mypy Strict + Pydantic v2 Runtime)](#d6p3--dual-layer-type-safety-mypy-strict--pydantic-v2-runtime)
- [D7 — Packaging \& Deployment](#d7--packaging--deployment)
  - [D7.P1 — Three-Channel Binary Resolution (Deployment Multi-Modale)](#d7p1--three-channel-binary-resolution-deployment-multi-modale)
  - [D7.P2 — License-Gated Optional Dependency (AGPL Isolation)](#d7p2--license-gated-optional-dependency-agpl-isolation)
  - [D7.P3 — Deployment-Transparent URL Abstraction (effective\_base\_url)](#d7p3--deployment-transparent-url-abstraction-effective_base_url)
- [Riepilogo Tassonomico](#riepilogo-tassonomico)

> Documento di analisi interno per la stesura della tesi magistrale.
> Ogni proprietà riporta: definizione, locus nel codice, conseguenze architetturali, e potenziale di sviluppo futuro.

---

## D1 — Architettura & Design

### D1.P1 — API-Agnosticism (Agnosticismo Applicativo)

**Definizione.** Il tool non contiene nessun riferimento hardcoded a path, endpoint, strutture dati o comportamenti di un'applicazione specifica. Tutta la conoscenza del target viene derivata a runtime da due sole sorgenti: `config.yaml` (credenziali, URL, parametri di esecuzione) e la specifica OpenAPI del target.

**Locus nel codice.**
- `src/discovery/openapi.py` — fetch, dereferenziazione `$ref` via `prance`, validazione via `openapi-spec-validator`
- `src/discovery/surface.py` — `AttackSurface`: mappa strutturata degli endpoint derivata dalla spec
- `src/core/context.py` — `TargetContext.attack_surface` trasporta la mappa per tutta la pipeline
- `4-Implementazione.md §3.1` — principio dichiarato esplicitamente come vincolo fondamentale

**Conseguenze.** Un test che interroga `target.attack_surface` e non trova endpoint applicabili ritorna `SKIP` (motivo: condizione prevista) e non `ERROR` (condizione imprevista). Le Shadow API costituiscono l'unica eccezione intenzionale: sono proprio gli endpoint non documentati, dunque non presenti nell'OpenAPI, e il test 0.1 le cerca attivamente.

**Tipo di evidenza.** Empirica — dimostrata da test 1.1 (itera `target.attack_surface` senza nessun riferimento hardcoded a Forgejo), test 0.3 (ispeziona il campo `deprecated` dell'OpenAPI spec a runtime) e test 7.2 (costruisce la lista di endpoint SSRF-injectable dalla superficie d'attacco).

**Sviluppo futuro.** L'agnosticismo abilita l'uso del tool su qualsiasi API REST documentata: Kubernetes API server, Stripe, GitHub Enterprise, microservizi interni. Il tool non è uno script usa-e-getta ma un framework riutilizzabile su qualunque target che espone OpenAPI.

---

### D1.P2 — Unidirectional Dependency Flow (Architettura a Strati con Dipendenze Monodirezionali)

**Definizione.** Il grafo delle dipendenze tra moduli è strettamente aciclico e orientato in un'unica direzione: `core/` ← `connectors/` ← `tests/` e `external_tests/` ← `engine.py`. Nessun modulo "a valle" viene importato da un modulo "a monte".

**Locus nel codice.**
- Ogni file `.py` riporta nella docstring di apertura la regola esatta: es. `src/core/evidence.py` — *"Dependency rule: this module imports only from pydantic, stdlib, structlog, and src.core.models. It must never import from config/, discovery/, tests/, or report/"*
- `CLAUDE.md` — regola dichiarata come non negoziabile con diagramma esplicito
- `knowledge/RULES_claude.md §A` — anti-pattern esplicito "Circular Dependencies"

**Conseguenze.** Modificare un test non può rompere `core/`. Modificare `core/` può rompere i test solo se l'interfaccia pubblica cambia, e la rottura è visibile staticamente. L'aggiunta di un nuovo modulo in un livello non richiede modifiche ai livelli superiori (tranne `engine.py`, che è il coordinatore universale).

**Tipo di evidenza.** Per costruzione — verificabile con `grep -r "from src.tests\|from src.connectors\|from src.external_tests" src/core/`: zero risultati. La regola è dichiarata anche nella docstring di apertura di ogni modulo in `core/`.

**Sviluppo futuro.** L'architettura a strati è prerequisito per la testabilità unitaria a livello di `core/` (indipendente da httpx e dai test di sicurezza veri e propri), per il packaging come libreria installabile, e per la sostituzione di singoli layer senza impatto sugli altri.

---

### D1.P3 — Split State e Immutabilità (TargetContext Frozen + TestContext Mutable)

**Definizione.** Lo stato del sistema è diviso in due oggetti con caratteristiche opposte: `TargetContext` (conoscenza statica del target, Pydantic `frozen=True`, creato una volta e mai modificato) e `TestContext` (stato accumulato durante l'esecuzione, mutabile via interfacce tipizzate esplicite).

**Locus nel codice.**
- `src/core/context.py` — `TargetContext(model_config={"frozen": True})` e `TestContext` con tre categorie di stato mutabile via interfacce esplicite e tipizzate:
  - **Token channel**: `set_token(role, token)`, `get_token(role)`, `has_token(role)`, `stored_roles()` — keyed by role constant, not test ID
  - **Teardown channel**: `register_resource_for_teardown(method, path, headers)`, `drain_resources()`, `registered_resource_count()` — LIFO ordered
  - **Shared data channel**: `set_shared(key, value)`, `get_shared(key, default)`, `has_shared(key)`, `shared_keys()` — general-purpose inter-test data; convention `"{test_id}.{data_name}"` makes the producing test explicit
- `4-Implementazione.md §3.2` e `§4.3` — principio dichiarato: "Stato Scisso e Immutabilità"
- `src/core/context.py:ROLE_ADMIN`, `ROLE_USER_A`, `ROLE_USER_B` — costanti nominate per eliminare magic strings

**Conseguenze.** Un test non può accidentalmente corrompere la configurazione di base letta da tutti gli altri (freeze Pydantic a livello di tipo). Lo stato condiviso tra test è accessibile solo tramite interfacce esplicite e tipizzate, non tramite dizionari liberi a chiavi arbitrarie: un `get_token` che ritorna `None` perché il prerequisito non ha girato è una condizione gestita, non un `KeyError` silenzioso. Il canale shared_data consente a test in Phase B o C di consumare dati calcolati da test in Phase A (es. un endpoint scoperto da test 0.1 e riusato da test 2.x) senza introdurre dipendenze di importazione tra moduli.

**Tipo di evidenza.** Empirica — dimostrata da test 1.4: il token acquisito via `acquire_tokens()` è scritto nel `TestContext`, il test lo usa per revocare la risorsa tramite l'API, poi riverifica lo stesso token (che ora dovrebbe essere rifiutato). Il ciclo acquire → store → revoke → re-probe esercita due dei tre canali del `TestContext`: il canale token (`acquire_tokens()` scrive il token nel `TestContext`) e il canale teardown (il token creato è registrato per la cancellazione in Phase 6). Il terzo canale, `shared_data`, non è necessario in questo test — serve quando un test pubblica un risultato calcolato per i test dipendenti in Phase B/C.

**Sviluppo futuro.** Il pattern di split state è prerequisito per un'eventuale parallelizzazione futura: i test che leggono solo `TargetContext` (frozen) possono girare in parallelo senza lock; i test che scrivono su `TestContext` richiederebbero sincronizzazione esplicita, già localizzata nelle interfacce tipizzate.

---

### D1.P4 — Dual Test Hierarchy (Native vs External — Contratti Paralleli)

**Definizione.** Esistono due gerarchie ABC parallele e distinte: `BaseTest` per i test Python nativi (usano `SecurityClient` / httpx) e `ExternalToolTest` per i test che wrappano tool esterni (usano `BaseConnector` / subprocess o libreria). Entrambe producono `TestResult`. L'engine le tratta identicamente dal punto di vista del risultato, con un unico `isinstance` check al momento dell'invocazione per selezionare la firma corretta di `execute()`.

**Locus nel codice.**
- `src/tests/base.py` — `BaseTest` ABC
- `src/external_tests/base.py` — `ExternalToolTest` ABC (NON eredita da `BaseTest`)
- `src/engine.py` — dispatch differenziato: `isinstance(test, BaseTest)` / `isinstance(test, ExternalToolTest)`
- `src/core/models/results.py` — `TestResult.source: Literal["native", "external"]`

**Conseguenze.** La separazione dei contratti previene l'ereditarietà di metodi inutilizzabili (es. un `ExternalToolTest` non dovrebbe avere `_log_transaction()` che accede a `SecurityClient`). Il `source` field nel `TestResult` consente al report di distinguere visivamente i risultati nativi da quelli generati da tool specializzati, senza richiedere sezioni fisicamente separate.

**Tipo di evidenza.** Empirica — dimostrata da test ext.0.1.nuclei (`ExternalToolTest`, `source="external"`) e test 0.1 (`BaseTest`, `source="native"`) nello stesso dominio: il log di Phase 5 mostra il dispatch `isinstance` differenziato; `TestResult.source` è distinguibile in `evidence.json`.

**Sviluppo futuro.** La dualità è estendibile: si può aggiungere una terza gerarchia (es. `AgentTest` per test LLM-assisted) senza modificare i contratti esistenti, aggiungendo solo un nuovo ramo nel dispatch dell'engine.

---

### D1.P5 — Three-Tier Connector Hierarchy (DA-1)

**Definizione.** I wrapper verso tool esterni seguono una gerarchia a tre livelli: `BaseConnector` (ABC puro, contratto universale), `BaseSubprocessConnector` (per tool invocati come subprocess: testssl.sh, ffuf, nuclei, vegeta), `BaseLibraryConnector` (per tool Python-native: sslyze). Ogni livello eredita solo i meccanismi pertinenti al proprio pattern di integrazione.

**Locus nel codice.**
- `src/connectors/base.py` — le tre classi + `ConnectorResult` (Pydantic) + `ConnectorRawOutput` (TypedDict contratto generico per ogni connector)
- `src/connectors/nuclei.py`, `src/connectors/testssl.py` — implementazioni concrete `BaseSubprocessConnector`
- `src/connectors/sslyze.py` — implementazione concreta `BaseLibraryConnector`
- `src/connectors/types/` — TypedDict condivisi tra famiglie di connector (es. `TlsFinding` per testssl+sslyze)
- `4-Implementazione.md §4.6` — motivazione DA-1: "una sottoclasse non deve ereditare metodi che non può usare"
- `src/connectors/_template_connector.py` — template per sviluppatori futuri

**Nota.** Dentro `BaseSubprocessConnector`, la ricerca del binario usa una cascata a tre canali (Channel 0: `./tools/LOCAL_TOOLS_SUBDIR/BINARY_NAME` locale, Channel 1: `shutil.which(BINARY_NAME)` di sistema, Channel 2: `os.getenv(SERVICE_ENV_VAR)` per microservizi HTTP). Questa capacità di deployment multi-modale è documentata come proprietà autonoma in **D7.P1**.

**Conseguenze.** Un `TestsslConnector` non eredita `LIBRARY_MODULE` né il meccanismo basato su `importlib.util.find_spec()` (irrilevanti per un subprocess). Un `SslyzeConnector` non eredita `BINARY_NAME`, `SERVICE_ENV_VAR`, `_run_subprocess()` (irrilevanti per una libreria Python). Il contratto pubblico (`run()`, `is_available()`, `get_version()`) è identico per entrambi: il test chiamante non sa né gli importa come il connector è implementato.

**Tipo di evidenza.** Empirica — tutti e tre i tier sono dimostrati in Milestone 1: `BaseSubprocessConnector` da ext.0.1.nuclei (`NucleiConnector`) e ext.1.5.testssl (`TestsslConnector`); `BaseLibraryConnector` da ext.1.5.sslyze (`SslyzeConnector`, nessun subprocess, importazione via `importlib`).

**Sviluppo futuro.** Aggiungere supporto per un nuovo tool esterno (es. `ffuf` come library Go, `Burp Suite` in modalità headless) richiede solo una nuova sottoclasse del livello appropriato, senza modificare `BaseConnector` né i test che lo usano.

---

### D1.P6 — Gateway-Agnostic Adapter Pattern

**Definizione.** I test WHITE_BOX accedono al piano di configurazione del gateway tramite `target.gateway` (istanza di `BaseGatewayAdapter`), un ABC in `core/gateway/` con metodi uniformi read-only: proprietà astratta `adapter_name: str`, metodo `check_connectivity() -> bool` (usato da engine Phase 3 per determinare se il gateway è raggiungibile prima di popolare `target.gateway`), `get_routes()`, `get_plugins()`, `get_services()`, `get_upstreams()`, `get_plugin_by_name()`, `get_status()`. L'implementazione concreta (`KongGatewayAdapter`) è selezionata a runtime dal campo `target.gateway_adapter: kong` in `config.yaml`. Il punto di iniezione è `target.gateway: BaseGatewayAdapter | None` in `TargetContext`; i test WHITE_BOX guardano con `if target.gateway is None: return self._make_skip(...)` (helper `_requires_admin_api()` in `BaseTest`).

**Locus nel codice.**
- `src/core/gateway/base.py` — `BaseGatewayAdapter` ABC + `GatewayAdapterError`
- `src/core/gateway/kong.py` — `KongGatewayAdapter` per Kong DB-less Admin API v3.x
- `src/config/schema/tool_config.py` — `gateway_adapter: str | None` con validazione supportati
- `src/tests/base.py:BaseTest._requires_admin_api()` — guard clause riutilizzabile per tutti i test WHITE_BOX che dipendono dall'adapter
- `src/tests/domain_3/test_3_3_hmac_config_audit.py`, `src/tests/domain_4/test_4_2_timeout_config_audit.py`, `test_4_3_circuit_breaker_audit.py`, `src/tests/domain_6/test_6_4_hardcoded_credentials_audit.py` — test che usano `target.gateway.*`

**Conseguenze.** I test 3.3, 4.2, 4.3, 6.4 chiamano `target.gateway.get_plugins()` / `get_services()` / `get_upstreams()` senza sapere se il gateway è Kong, Traefik, o nginx. Aggiungere supporto per Traefik richiede solo una nuova classe `TraefikGatewayAdapter(BaseGatewayAdapter)` in `src/core/gateway/traefik.py` e una riga nel dispatcher di `engine.py` Phase 3, senza modificare nessun test esistente.

**Tipo di evidenza.** Empirica — dimostrata da test 3.3, 4.2, 4.3, 6.4: tutti chiamano `target.gateway.*` tramite l'interfaccia `BaseGatewayAdapter`; il tipo concreto `KongGatewayAdapter` non è importato né referenziato in nessuno dei quattro file di test.

**Sviluppo futuro.** Il pattern è l'unico punto di variabilità necessario per supportare ambienti non-Kong: Amazon API Gateway, Azure API Management, Apigee, nginx Plus. I test rimangono invariati.

---

## D2 — Estensibilità & Manutenibilità

### D2.P1 — Dynamic Test Discovery (Zero-Registration via pkgutil)

**Definizione.** Non esiste un registro centrale dei test. Il `TestRegistry` e l'`ExternalTestRegistry` scansionano le directory di dominio a runtime tramite `pkgutil.walk_packages`, trovano i file con il prefisso corretto (`test_` / `ext_test_`), e istanziano tutte le sottoclassi concrete di `BaseTest` / `ExternalToolTest` via `inspect`.

**Locus nel codice.**
- `src/tests/registry.py` — Phase R1 (scan), R2 (subclass extraction), R3 (filtering)
- `src/external_tests/registry.py` — stessa logica + Phase R4 (connector injection)
- `src/tests/base.py` — `has_required_metadata()` filtra classi con ClassVar incompleti
- `CLAUDE.md` — convenzione di nomenclatura file dichiarata come condizione tecnica del discovery

**Conseguenze.** Aggiungere un nuovo test richiede una sola operazione: creare il file nella directory di dominio corretta con il nome corretto e implementare il contratto. Nessun altro file deve essere modificato (eccetto `config.yaml` per i parametri di tuning e `engine.py` per i Runtime*Config). Errori di import nei singoli moduli sono catturati e loggati come `WARNING` senza bloccare il discovery degli altri.

**Tipo di evidenza.** Per costruzione — verificabile per ispezione di `src/engine.py` (assenza di qualsiasi lista hardcoded di test) e dal log di avvio del tool (entries `pkgutil` scan compaiono prima di Phase 5). Verifica: `grep -r "REGISTERED_TESTS\|test_list\s*=" src/engine.py` restituisce zero risultati.

**Sviluppo futuro.** Il discovery dinamico abilita un plugin system: moduli di test contribuiti da terze parti possono essere aggiunti al `sys.path` e vengono scoperti automaticamente senza modificare il core. Scenario: community package `apiguard-tests-graphql` che aggiunge test specifici per GraphQL.

---

### D2.P2 — DAG-Based Dependency Scheduling (Ordinamento Topologico delle Dipendenze)

**Definizione.** L'ordine di esecuzione dei test non è fisso né casuale: è determinato da un Directed Acyclic Graph costruito a partire dal campo `depends_on` dichiarato da ogni test. Il DAG usa `graphlib.TopologicalSorter` della stdlib Python. L'output è una lista di batch: test senza dipendenze reciproche nello stesso batch, batch sequenziali tra loro.

**Locus nel codice.**
- `src/core/dag.py` — `DAGScheduler`, `ScheduledBatch`
- `src/tests/base.py` — `depends_on: ClassVar[list[str]]` su ogni test concreto
- `docs/priv/PROJECT_status.md §DAG State After Milestone 1 Completion` — tre fasi: A (no deps), B (requires 1.1), C (requires ext.1.2)
- `4-Implementazione.md §4.5` — semantica di batch e batch-parallelism futuro

**Conseguenze.** Test come 1.2 (JWT cryptographic validity) dipendono correttamente da 1.1 (auth required), garantendo che i token siano disponibili nel `TestContext` prima che siano necessari. Un ciclo di dipendenze è un errore rilevato staticamente in Phase 4 prima di eseguire un solo test (`DAGCycleError` blocca lo startup). Dipendenze mancanti nel set attivo vengono ignorate con `WARNING` (graceful degradation).

**Tipo di evidenza.** Empirica — dimostrata da test 1.1 (Phase A, `depends_on=[]`) e test 1.4 (Phase B, `depends_on=["1.1"]`): il log di Phase 4 mostra due batch distinti. Con `execution.fail_fast: true` e test 1.1 in FAIL, il log di Phase 5 mostra l'interruzione prima che test 1.4 venga eseguito, confermando la semantica del DAG.

**Sviluppo futuro.** La struttura a batch esiste già: ogni batch è concettualmente parallelizzabile. L'aggiunta di un `ThreadPoolExecutor` in Phase 5 dell'engine è una modifica localizzata senza impatto sul design dei test, purché si risolvano le questioni di thread-safety su `TestContext` e `EvidenceStore` (già note in `4-Implementazione.md §4.3`).

---

### D2.P3 — Separation of Data from Evaluation (ConnectorResult)

**Definizione.** Il connector non decide se qualcosa è un FAIL: restituisce dati grezzi (già parsati come `dict[str, Any]`) nel modello `ConnectorResult`. È l'`ExternalToolTest` a valutare il `ConnectorResult` contro il proprio oracle nel metodo `_evaluate()`.

**Locus nel codice.**
- `src/connectors/base.py` — `ConnectorResult` (Pydantic frozen): `raw_output`, `exit_code`, `timed_out`, `execution_time_ms`
- `src/external_tests/base.py` — `_evaluate()` abstract method: responsabilità oracle dell'ExternalToolTest
- `docs/pub/ADDING_external_tests.md` — contratto esplicito: "il connector restituisce dati; il test valuta"

**Conseguenze.** Il connector è riutilizzabile da test diversi con oracle diversi. Il test `ext_test_0_1_shadow_api_nuclei.py` e un ipotetico `ext_test_3_1_injection_nuclei.py` usano lo stesso `NucleiConnector` ma valutano il suo output con logiche di oracle distinte. Il connector è testabile indipendentemente (verifica che l'output sia parsato correttamente) senza richiedere un oracle di sicurezza.

**Tipo di evidenza.** Empirica — dimostrata da ext.0.1.nuclei (`NucleiConnector.run()` restituisce tutti i findings inclusi `severity="info"`; `_evaluate()` in `ExtTest01ShadowApiNuclei` applica la partizione FAIL/NOTE/ignored) e da ext.1.5.testssl (stesso pattern con `TestsslConnector` e bucket CRITICAL/HIGH vs MEDIUM/WARN).

**Sviluppo futuro.** Pattern direttamente trasferibile: lo stesso `connectors/nuclei.py` potrebbe servire, senza modifiche, nuovi test per domini attualmente non coperti (es. OWASP API10 — Unsafe Consumption of APIs con template Nuclei specifici).

---

### D2.P4 — Connector Lifecycle con Dependency Injection (DA-2)

**Definizione.** L'`ExternalTestRegistry` inietta connettori condivisi nelle istanze di test prima che l'esecuzione inizi (Phase R4). Due attributi di istanza gestiscono il ciclo di vita: `_injected_connector` (connector già confermato disponibile) e `_skip_reason_from_registry` (tool assente: fast-path che ritorna `SKIP` prima ancora di costruire il connector). Il check di disponibilità (`is_available()`) viene eseguito **una sola volta** per gruppo di test che usano lo stesso tool.

**Locus nel codice.**
- `src/external_tests/registry.py` — `_inject_connectors()`: raggruppa per `tool_name`, una sola `is_available()`, un solo log per tool
- `src/external_tests/base.py` — `_skip_reason_from_registry`, `_injected_connector`, `_get_connector()`, `_check_and_skip()`
- `4-Implementazione.md §4.7` — "con 5 test nuclei e il binario assente: 1 solo WARNING invece di 5"

**Conseguenze.** Con N test che usano lo stesso tool, il filesystem viene interrogato una sola volta (zero syscall ridondanti). Il log mostra un singolo `WARNING "nuclei not found — 5 tests will SKIP"` anziché 5 entry identiche. La stessa istanza connector è condivisa tra i test del gruppo: zero overhead di costruzione ripetuta.

**Tipo di evidenza.** Empirica — dimostrata dal log di Phase R4 durante il discovery: un solo entry `INFO "nuclei available"` (non uno per test nuclei) e un solo `INFO "testssl.sh available"`. Con il binario assente, un solo `WARNING` per tool nel log invece di N entry identiche.

**Sviluppo futuro.** Il pattern di injection è il foundation per un future "connector pool" che gestisce connessioni persistenti a servizi Docker (es. nuclei come servizio HTTP in Docker Compose anziché subprocess per ogni esecuzione).

---

### D2.P5 — Auth Abstraction Layer (Auth Dispatcher)

**Definizione.** Il modulo `src/tests/helpers/auth.py` è il single import point per l'acquisizione di token nei test GREY_BOX. Legge `target.credentials.auth_type` e delega all'implementazione corretta (`auth_forgejo.py` per token API statici, `auth_jwt_login.py` per login JWT standard). Il dispatcher è idempotente: un ruolo che ha già il token nel `TestContext` viene saltato senza chiamate HTTP.

**Locus nel codice.**
- `src/tests/helpers/auth.py` — dispatcher + docstring con protocollo di aggiunta nuovo auth type
- `src/tests/helpers/auth_forgejo.py`, `auth_jwt_login.py` — implementazioni concrete
- `src/config/schema/tool_config.py` — `CredentialsConfig.auth_type` con validazione

**Conseguenze.** Aggiungere supporto per un nuovo metodo di autenticazione (es. OAuth2 client credentials, SAML, mTLS) richiede: (1) creare `auth_{type}.py`, (2) aggiungere un ramo `elif` nel dispatcher, (3) aggiungere il valore supportato alla validazione Pydantic. Zero modifiche ai test esistenti. L'idempotenza garantisce che N test GREY_BOX che chiamano `acquire_tokens()` all'inizio del proprio `execute()` non generino N login HTTP: il token è acquisito una sola volta e condiviso via `TestContext`.

**Tipo di evidenza.** Empirica — dimostrata da test 1.6 e test 1.4: entrambi chiamano `acquire_tokens()` tramite il dispatcher `auth.py`; il log di Phase 5 mostra che per una stessa run nessun login HTTP è ripetuto per lo stesso ruolo (idempotenza verificabile contando le richieste POST al login endpoint nel log `SecurityClient`).

**Sviluppo futuro.** Auth Abstraction è il prerequisito per supportare target con sistemi di autenticazione proprietari (IAM aziendali, SSO federato) senza modificare l'architettura dei test.

---

### D2.P6 — Category A/B Connector Classification (Obbligatorio vs Opzionale)

**Definizione.** I connector verso tool esterni sono classificati in due categorie: Categoria A (HYBRID — bloccanti, obbligatori per produrre evidenza valida per quel test) e Categoria B (Opzionali — il test funziona già come NATIVE, il connector espande la superficie di rilevamento senza essere necessario). Un test HYBRID senza il connector Cat A è un test SKIP con evidenza incompleta.

**Locus nel codice.**
- `docs/priv/PROJECT_status.md §Connectors` — tabella completa Cat A e Cat B con motivazione
- `docs/priv/PROJECT_status.md` — legenda `[OK·C]`: "Python completo, manca il Connector Cat A obbligatorio"
- `src/external_tests/base.py` — gestione dello SKIP per tool mancante

**Conseguenze.** La classificazione guida le priorità di sviluppo: i connector Cat A sono prerequisiti per la completezza dei test HYBRID (es. `testssl.sh` per il test 1.5). I connector Cat B sono enhancements: il test 6.4 (Hardcoded Credentials) già funziona con regex interne, `trufflehog`/`gitleaks` ampliano solo la copertura. La classificazione è documentata anche nel changelog delle decisioni (es. promozione di `ffuf` da Cat B a Cat A in sostituzione di `kiterunner` abbandonato).

**Tipo di evidenza.** Empirica — dimostrata da ext.0.1.nuclei (nuclei Cat A: il test produce `SKIP` con motivo esplicito se il binario manca) in contrasto con test 0.2 e 0.3 (NATIVE+OPT: producono risultati validi anche senza i connector Cat B `oasdiff`/`cherrybomb`). La distinzione è osservabile dal log di Phase R4.

**Sviluppo futuro.** Il framework Cat A/B è riutilizzabile come policy per l'acceptance di contributi esterni: un PR che aggiunge un connector Cat B non richiede modifica del core del test; un PR che aggiunge un connector Cat A richiede la modifica dello stato del test da HYBRID-bloccato a HYBRID-completo.

---

### D2.P7 — Context-Aware Path Seed System con generate-seed CLI

**Definizione.** Il tool risolve il problema dei path parametrici (es. `/api/v1/repos/{owner}/{repo}/issues/{index}`) tramite un sistema a due componenti. Il primo è il comando CLI `apiguard generate-seed <spec_url>`: legge la specifica OpenAPI senza dereferenziazione completa (più veloce, non richiede che il target sia raggiungibile), estrae tutti i nomi di parametro `{param}` unici, e scrive un template YAML con placeholder `FILL_ME` che l'operatore compila una volta sola prima dell'assessment. Il secondo è `path_resolver.py`, che implementa la risoluzione a runtime con una strategia di lookup a due livelli: prima cerca il nome del parametro nel dizionario `target.path_seed` configurato dall'operatore; se assente, usa un fallback sicuro dipendente dal metodo HTTP (`"1"` per read/write, `"apiguard-probe"` per DELETE).

**Locus nel codice.**
- `src/discovery/seed_generator.py` — parsing OpenAPI lightweight, estrazione parametri, rendering template YAML con `FILL_ME`
- `src/cli.py:generate_seed()` — comando `apiguard generate-seed <spec_url> --output seed_template.yaml`
- `src/tests/helpers/path_resolver.py` — `resolve_path_with_seed()` con costanti `PATH_PARAM_FALLBACK_DEFAULT = "1"` e `PATH_PARAM_FALLBACK_SAFE_DELETE = "apiguard-probe"`; pattern precompilato a livello di modulo `_PARAM_PATTERN = re.compile(r"\{([^}]+)\}")` per O(1) dopo il primo import; gestisce la sintassi parametri vincolati: `{id:[0-9]+}` → estrae `"id"` (nome prima del `:`)
- `src/core/context.py` — `TargetContext.path_seed: dict[str, str]` propagato a tutti i test
- `config.yaml:target.path_seed` — dizionario operatore con valori reali per il deployment specifico

**Conseguenze.** Senza path seed, un probe su `/api/v1/repos/{owner}/{repo}` con fallback generico `"1"` produce un `404 Not Found` che il test classifica come `INCONCLUSIVE_PARAMETRIC` anziché raggiungere il middleware di autenticazione e ottenere il `401 Unauthorized` atteso. Con path seed configurato (`owner: "mario_rossi"`, `repo: "test-repo"`), il tasso di risultati INCONCLUSIVE scende drasticamente su target con path parametrici complessi come Forgejo. Il fallback `"apiguard-probe"` per i DELETE parametrici è scelto deliberatamente come stringa non-numerica con bassa probabilità di corrispondere a un ID reale: se per errore il middleware non blocca la request, il backend risponde `404` (risorsa inesistente) anziché cancellare dati reali.

**Tipo di evidenza.** Empirica — dimostrata da test 1.1 su Forgejo: senza `path_seed` configurato, i path parametrici (es. `/api/v1/repos/{owner}/{repo}`) compaiono nel summary come `INCONCLUSIVE_PARAMETRIC`; con `path_seed: {owner: "...", repo: "..."}` in `config.yaml`, gli stessi path producono `ENFORCED` o `BYPASSED`.

**Sviluppo futuro.** Una futura versione del `seed_generator` potrebbe derivare il seed automaticamente cercando campi `example:` / `x-example:` per ogni parametro nell'OpenAPI spec, riducendo ulteriormente il lavoro manuale di configurazione. Il seed potrebbe anche essere popolato da una run preliminare del test 0.1 (shadow API discovery) che trova path attivi: loop di auto-configurazione.

---

### D2.P8 — Test Data Catalog Architecture (Pure-Data Layer)

**Definizione.** I payload di attacco, le wordlist, i pattern di riconoscimento e i cataloghi di firme di vulnerabilità sono separati dalla logica di test e di analisi in moduli "pure-data" dentro `src/tests/data/`. Questi moduli importano solo dalla stdlib, non contengono funzioni o logica, e definiscono esclusivamente strutture dati (`tuple`, `frozenset`, `list`, `str`) valutate a import time. La direzione di dipendenza è a senso unico: i consumer (test, helper) importano da `data/`, ma `data/` non importa mai da nessun consumer.

**Locus nel codice.**
- `src/tests/data/ssrf_payloads.py` — catalogue SSRF come lista di 3-tuple `(url, description, category)` filtrabili via `cfg.payload_categories` in `config.yaml`
- `src/tests/data/auth_payloads.py` — payload di attacco JWT: alg:none, tampered payload, algorithm confusion
- `src/tests/data/shadow_wordlists.py` — wordlist per shadow API discovery (path candidati)
- `src/tests/data/inspector_patterns.py` — pattern stack trace e nomi di campi sensibili
- `src/tests/helpers/response_inspector.py` — consumer che precompila `frozenset` normalizzati e regex a import time per lookup O(1) durante l'esecuzione

**Conseguenze.** I payload sono mantenibili indipendentemente dalla logica: aggiungere un nuovo vettore SSRF (es. un nuovo cloud provider metadata endpoint) non richiede modificare la logica del test, solo aggiungere una riga al catalogue. La pre-compilazione delle strutture a import time (un `frozenset` di nomi di campo sensibili normalizzati per rimuovere underscore e trattini, costruito una sola volta) garantisce lookup O(1) durante l'esecuzione dei test. Il filtro per categoria SSRF (`payload_categories: ["cloud_metadata", "private_network"]` in `config.yaml`) consente di escludere payload non applicabili al cloud provider del target, riducendo la durata dell'assessment e i falsi positivi.

**Tipo di evidenza.** Empirica — dimostrata da test 7.2 (73 payload SSRF da `ssrf_payloads.py`; il numero effettivo di probe varia in base al filtro `payload_categories` in `config.yaml`), test 1.1 (5 token malformati strutturalmente distinti da `auth_payloads.py`) e test 6.4 (33 nomi di campo sensibili normalizzati da `inspector_patterns.py` in lookup O(1)).

**Sviluppo futuro.** Il catalogue è il punto naturale di contribuzione esterna alla community: un PR che aggiunge un nuovo cloud provider metadata endpoint a `ssrf_payloads.py` non richiede conoscenza dell'architettura del tool. Con il catalogue come modulo separato dal core, è possibile distribuirlo come pacchetto autonomo (`apiguard-payloads`) aggiornabile indipendentemente — utile in contesti enterprise dove i payload di attacco devono essere revisionati e approvati separatamente dal codice.

---

## D3 — Config & Riproducibilità

### D3.P1 — Config-Driven Development (Sviluppo Guidato dalla Configurazione)

**Definizione.** Ogni parametro soggetto a tuning operativo — timeout, soglie, limiti di richiesta, categorie di payload da attivare, percorsi di output — risiede in `config.yaml` sotto una gerarchia esplicita (`tests.domain_N.test_N_M.<param>`). Il codice Python legge sempre da `TargetContext` o `TestContext`; non contiene mai literal numerici o stringhe decisionali hardcoded.

**Locus nel codice.**
- `src/config/schema/domain_N.py` — schema Pydantic v2 con validazione e range accettabili per ogni parametro di dominio
- `src/config/schema/tool_config.py` — schema infrastrutturale: timeout HTTP, retry, strategy abilitata, priorità minima, path di output
- `src/core/models/runtime.py` — mirror immutabile dei parametri di configurazione propagato in `TargetContext`
- `config.yaml` — file operatore con valori di default documentati per ogni parametro
- `knowledge/RULES_claude.md §F` — regola denominata "Config-Driven Development" con divieto esplicito di hardcoding

**Conseguenze.** Un operatore può adattare completamente il comportamento del tool (es. abbassare il timeout per un network lento, aumentare il numero di request per il test di rate limiting, limitare le categorie di payload SSRF al cloud provider del target) senza toccare il codice. Ogni esecuzione è riproducibile: stesso `config.yaml` + stesso target = stessi risultati.

**Tipo di evidenza.** Empirica — dimostrata da test 4.2 (le soglie di timeout sono lette da `config.yaml:tests.domain_4.test_4_2.*`, non hardcoded) e test 7.2 (il filtro `payload_categories` in `config.yaml` determina quali dei 73 payload SSRF vengono inviati; modificando la lista cambia il numero di probe).

**Sviluppo futuro.** Il config-driven design è il prerequisito per la distribuzione del tool come container Docker o come pacchetto pip, dove l'operatore porta solo il proprio `config.yaml`. Abilita anche profili di configurazione multipli (es. `config_prod.yaml`, `config_staging.yaml`) senza duplicare logica.

---

### D3.P2 — Single Source of Truth per Stato, Topologia e Ambiente

**Definizione.** Quattro "fonti di verità uniche" coesistono con responsabilità distinte e non sovrapposte: `PROJECT_status.md` per lo stato di implementazione del progetto; `config.yaml` per tutti i parametri operativi; `AttackSurface` (derivata dall'OpenAPI spec) per la topologia degli endpoint del target; `src/config/loader.py` come unico punto di accesso a `os.environ` (nessun altro modulo legge variabili d'ambiente direttamente).

**Locus nel codice.**
- `CLAUDE.md` — "docs/priv/PROJECT_status.md — single source of truth" per stato progetto
- `src/discovery/surface.py` — `AttackSurface` come unica fonte per endpoint topology
- `src/core/context.py` — `TargetContext.attack_surface` distribuisce la mappa a tutti i test
- `src/config/loader.py` — docstring: "No other module in src/ reads files or calls os.environ directly"; risolve placeholder `${VAR}` da `os.environ`
- `src/cli.py` — unico punto dove `load_dotenv(override=False)` è invocato
- `4-Implementazione.md §3.1` — "L'AttackSurface è l'unica sorgente di verità sulla topologia del target"

**Eccezioni documentate a `os.environ`/`os.getenv` fuori da `loader.py`:**
- `src/connectors/base.py:BaseSubprocessConnector._resolve_binary()` — `os.getenv(SERVICE_ENV_VAR)` per il Channel 2 della three-channel binary resolution (vedi D7.P1); accesso a una env var il cui *nome* è parametrico per connector e non conoscibile staticamente da `loader.py`
- `src/engine.py` Phase 3 — `os.getenv("APIGUARD_TARGET_EFFECTIVE_URL")` per il Docker Compose URL override (vedi D7.P3); avviene una sola volta a startup, il risultato è frozen in `TargetContext.effective_base_url`

Entrambe le eccezioni sono architetturalmente giustificate: non leggono parametri di configurazione dell'assessment ma risolvono binding infrastrutturali (tool availability e deployment URL) che per natura devono bypassare il file YAML.

**Conseguenze.** Un test che consulta `target.attack_surface.endpoints` lavora sempre sulla stessa vista degli endpoint, identica per ogni test nell'intera pipeline. L'isolamento dell'accesso config in un solo modulo rende prevedibile e auditabile il percorso di ogni credenziale: dal file `.env` (o dall'ambiente CI/CD) al `ToolConfig`, senza cortocircuiti. Il flag `override=False` in `load_dotenv()` garantisce che le variabili iniettate dall'orchestratore CI/CD non vengano sovrascritte da un eventuale file `.env` locale.

**Tipo di evidenza.** Per costruzione — verificabile con `grep -rn "os.environ\|os.getenv" src/ | grep -v loader.py`: i soli 2 accessi residui sono `connectors/base.py` (Channel 2) e `engine.py` (effective URL), entrambi documentati. La unicità di `AttackSurface` come fonte di topologia è verificabile per ispezione: nessun test esegue chiamate HTTP di discovery indipendenti al di fuori di Phase 2.

**Sviluppo futuro.** La separazione netta delle fonti di verità è prerequisito per un eventuale "diff assessment": confrontare due `AttackSurface` da due run successive per rilevare endpoint scomparsi o aggiunti tra una versione API e l'altra.

---

### D3.P3 — Black/Grey/White Box Gradient con Mapping Priorità-Strategia

**Definizione.** Ogni test dichiara la propria strategia di test (`BLACK_BOX`, `GREY_BOX`, `WHITE_BOX`) come `ClassVar`. Il mapping raccomandato: P0 corrisponde a `BLACK_BOX` (zero credenziali, simulazione attaccante esterno), P1/P2 a `GREY_BOX` (token JWT, accesso autenticato), P3 a `WHITE_BOX` (Admin API, audit configurazione). Il `TestRegistry` filtra per strategia in base alle strategie abilitate in `config.yaml`. Il mapping è una raccomandazione, non un vincolo imposto dal framework: la strategia descrive il *tipo di conoscenza necessaria* al test (credenziali, Admin API), non la *gravità business* della garanzia.

**Locus nel codice.**
- `src/tests/strategy.py` — re-export di `TestStrategy` da `src/core/models`
- `src/core/models/enums.py` — `TestStrategy` enum
- `src/tests/base.py` — `strategy: ClassVar[TestStrategy]` su ogni test
- `4-Implementazione.md §4.8` — tabella mapping strategia → priorità → prerequisiti tipici (nota: la tabella descrive il caso comune; il codebase contiene deviazioni architetturalmente giustificate)

**Conseguenze.** Un'esecuzione in modalità `BLACK_BOX` (solo test P0) simula un attaccante esterno senza credenziali ed è eseguibile senza preparare account di test. Un'esecuzione `WHITE_BOX` completa richiede accesso all'Admin API e credential per tutti i ruoli. L'operatore può scegliere il livello di privilegio appropriato per il contesto (audit esterno vs. review interna). Il mapping flessibile consente deviazioni documentate: `test_7_2_ssrf_prevention.py` è `GREY_BOX` con `priority=0` perché le vulnerabilità SSRF su Forgejo sono raggiungibili solo via endpoint autenticati (webhook, mirror); `ext_test_1_5_tls_analysis.py` è `WHITE_BOX` con `priority=2` perché l'analisi TLS è un audit di configurazione ma non richiede Admin API; `test_6_2_security_headers_audit.py` è `WHITE_BOX` con `priority=3` perché verifica header HTTP-osservabili (senza Admin API) ma costituisce un audit di configurazione perimetrale.

**Tipo di evidenza.** Empirica — dimostrata dal run completo di Milestone 1: test 1.1 (BLACK_BOX/P0, zero credenziali), test 7.2 e 1.4 (GREY_BOX, token acquisiti via `acquire_tokens()`), test 4.2 e 4.3 (WHITE_BOX/P1, Admin API). Il campo `strategy` di ogni `TestResult` è osservabile in `evidence.json` e nel report HTML.

**Sviluppo futuro.** Il gradient abilita un modello di assessment scalabile: un assessment P0 automatizzato ad ogni deploy, un assessment P0+P1 ad ogni release, un assessment completo in sede di security review periodica.

---

### D3.P4 — Reproducibility (Determinismo dell'Esecuzione)

**Definizione.** Stesso `config.yaml` sullo stesso target in assenza di cambiamenti all'applicativo produce sempre gli stessi risultati. Questo è garantito da: esecuzione strettamente sequenziale (no race condition tra test), ordine deterministico del discovery (test_id lessicografico), `TargetContext` immutabile (stessa vista del target per ogni test), e separazione netta tra stato di test e configurazione.

**Locus nel codice.**
- `src/tests/registry.py` — ordine lessicografico per test_id
- `src/core/dag.py` — topological sort deterministico
- `4-Implementazione.md §4.3` — "modello di esecuzione strettamente sequenziale"
- `4-Implementazione.md §1` — "Riproducibilità" come vincolo non negoziabile

**Conseguenze.** Il tool è inseribile in audit trail formali: lo stesso assessment rieseguito a distanza di una settimana sullo stesso target non modificato produce output equivalente (escludendo timestamp e UUID generati a runtime). Questa proprietà è essenziale per un tool con pretese di security assurance: un risultato non riproducibile non è un risultato scientifico.

**Tipo di evidenza.** Per costruzione (con verifica empirica) — la base strutturale è verificabile per ispezione di `src/tests/registry.py` (ordinamento lessicografico per `test_id`) e `src/core/dag.py` (`TopologicalSorter` deterministico). La proprietà è verificabile empiricamente eseguendo il tool due volte con lo stesso `config.yaml` sullo stesso target e confrontando i contatori PASS/FAIL in `evidence.json` (escludendo timestamp e UUID).

**Sviluppo futuro.** La riproducibilità combinata con la traceability (D5.P1) abilita il confronto automatizzato tra assessment: due `evidence.json` dello stesso target a distanza di tempo possono essere diffati per identificare regressioni di sicurezza introdotte tra una release e l'altra.

---

### D3.P5 — Zero External State Dependency at Runtime

**Definizione.** Il tool non ha dipendenze di stato esterno a runtime: nessun database, nessun message broker, nessuna cache esterna, nessuna connessione persistente oltre all'API HTTP del target. Tutto lo stato mutabile vive in memoria di processo (`TargetContext`, `TestContext`) o in file locali scritti nella directory `outputs/` (`evidence_tmp/`, `assessment_report.html`, `evidence.json`). Questa è un vincolo esplicito dichiarato in `4-Implementazione.md §1`: *"Nessun database esterno a runtime: tutto lo stato vive in memoria o in file locali."* La formalizzazione come proprietà architetturale rende esplicite le implicazioni di deployment.

**Locus nel codice.**
- Nessun modulo in `src/` apre una connessione a database o chiama un servizio di stato esterno
- `src/core/evidence.py` — solo I/O locale (`outputs/evidence_tmp/`)
- `src/engine.py` — solo connessioni HTTP: `SecurityClient` (target) e gateway adapter opzionale (Admin API). Nessun message broker, nessun layer di persistenza esterno
- `config.yaml` — nessun DSN database, nessun Redis URL, nessuna cache config esterna

**Conseguenze.** Il tool gira in qualsiasi ambiente con Python 3.11+ e accesso di rete al target, senza setup service o migration. Il deployment Docker richiede solo l'injection di `config.yaml`. Il tool può essere aggiunto a un CI/CD runner come pip install + config file, senza prerequisiti infrastrutturali. Questa proprietà è il prerequisito di D6.P1 (semantic exit codes per CI/CD): un tool con dipendenze di stato esterno richiederebbe service readiness check prima che l'exit code possa essere considerato affidabile.

**Tipo di evidenza.** Per costruzione — verificabile per ispezione di `pyproject.toml` (sezione `[project] dependencies`: assenza di `psycopg`, `redis`, `sqlalchemy`, `boto3`, client RabbitMQ) e con `grep -r "import redis\|import psycopg\|import boto3" src/` (zero risultati). Osservabile empiricamente: ogni run produce output solo nella directory `outputs/` locale senza accedere a servizi di stato esterni.

**Sviluppo futuro.** Una futura modalità "multi-target" richiederebbe un external state store per coordinare assessment paralleli. L'architettura attuale rende questo un'estensione deliberata opt-in, non un requisito implicito.

---

## D4 — Robustezza & Sicurezza

### D4.P1 — Streaming Evidence Store (JSONL — Unbounded Capacity)

**Definizione.** L'`EvidenceStore` non accumula record in memoria. Per ogni test, apre un file JSONL dedicato in `outputs/evidence_tmp/<test_id>.jsonl`, scrive ogni record immediatamente con flush, e chiude il file al termine del test. In Phase 7 tutti i file JSONL vengono letti, ordinati cronologicamente, e serializzati nel file `evidence.json` finale. La directory `evidence_tmp/` viene poi rimossa.

**Locus nel codice.**
- `src/core/evidence.py` — architettura documentata nel modulo header
- `src/engine.py` — `store.begin_test(test_id)` prima di ogni test, `store.end_test()` dopo, `store.merge_and_finalize()` in Phase 7
- `src/core/evidence.py:RESPONSE_BODY_MAX_CHARS = 10_000` — costante nominata per limitare la dimensione per-record

**Conseguenze.** Il test 1.1 (authentication enforcement) può produrre centinaia di `FAIL` evidence (uno per endpoint non protetto) senza perdita di dati. Con la versione precedente basata su `deque(maxlen=100)`, i primi record venivano silenziosamente evitti quando il buffer si riempiva, generando `Finding.evidence_ref` che puntavano a record inesistenti — un audit trail rotto. L'architettura JSONL elimina questa classe di bug strutturalmente. In caso di crash tra Phase 5 e Phase 7, i file JSONL rimangono su disco e sono leggibili manualmente.

**Tipo di evidenza.** Empirica — dimostrata da test 1.1 su Forgejo (100+ endpoint documentati): la directory `outputs/evidence_tmp/` contiene il file `1.1.jsonl` con tutti i record FAIL scritti senza perdita, e `record_count` in `evidence.json` supera 100 senza eviction.

**Sviluppo futuro.** Il formato JSONL è nativamente ingestibile da log aggregator (Elasticsearch, Splunk, Loki) per analisi aggregate di assessment multipli, senza richiedere parsing aggiuntivo.

---

### D4.P2 — Evidence Sanitization come Responsabilità Centralizzata

**Definizione.** La sanitizzazione delle credenziali nell'evidenza non è delegata ai connector che producono i dati: è responsabilità esclusiva di `EvidenceStore.pin_artifact()`. Il metodo esegue una sanitizzazione ricorsiva del `ConnectorResult.raw_output` con tre meccanismi sovrapposti: (1) **key-pattern matching** via regex compilata a word-boundary su 11 pattern (`token`, `password`, `api_key`, `apikey`, `authorization`, `bearer`, `secret`, `credential`, `auth`, `private_key`, `access_token`); (2) **JWT-value detection** via `_SANITIZE_JWT_PATTERN` (tre segmenti base64url separati da `.`) per redactare token JWT nei valori stringa indipendentemente dalla chiave; (3) **header-prefix matching** su `_SANITIZE_HEADER_PREFIXES` (`"Bearer "`, `"Basic "`, `"Token "`, `"token "`).

**Locus nel codice.**
- `src/core/evidence.py:EvidenceStore._sanitize_artifact()` — metodo statico con sanitizzazione ricorsiva
- `src/core/evidence.py` — costanti `_SENSITIVE_KEY_RE`, `_SANITIZE_JWT_PATTERN`, `_SANITIZE_HEADER_PREFIXES` definite a livello di modulo
- `src/external_tests/base.py` — commento esplicito: "EvidenceStore.pin_artifact() is responsible for sanitizing credentials from raw_output before persistence"
- `knowledge/RULES_claude.md §5.7` — regola: "La sanitizzazione deve essere attiva ed esplicita"

**Conseguenze.** Un connector che dimentica di redactare un campo sensibile non crea una violazione: la sanitizzazione avviene sempre e comunque in un punto centralizzato. Aggiungere un nuovo pattern di credenziale (es. `x-api-key`) richiede una modifica in un solo posto. La tripla copertura (key pattern + JWT heuristic + header prefix) garantisce che un token JWT leakato come valore di una chiave `"result"` arbitraria venga comunque redactato.

**Tipo di evidenza.** Empirica — dimostrata da ext.0.1.nuclei e ext.1.5.testssl: qualsiasi Bearer token presente nel `raw_output` di nuclei o testssl.sh appare come `[REDACTED]` in `evidence.json`. Verificabile confrontando il raw output del tool con l'artifact salvato nella sezione `tool_artifact` di `evidence.json`.

**Sviluppo futuro.** Il set di pattern può essere reso configurabile via `config.yaml` per ambienti con naming conventions non standard (es. `X-Custom-Auth`). I pattern compilati a livello di modulo potrebbero essere caricati da un file JSON esterno per ambienti enterprise con policy di sanitizzazione specifiche.

---

### D4.P3 — Fail-Safe Error Isolation (Errori Isolati per Test)

**Definizione.** Il contratto di `BaseTest.execute()` e `ExternalToolTest.execute()` impone che il metodo non propaghi mai eccezioni verso l'engine. Qualsiasi eccezione non gestita deve essere catturata internamente e ritornata come `TestResult(status=ERROR, message=str(e))`. L'engine non è tenuto a gestire eccezioni provenienti dai test e, se ne ricevesse una, interromperebbe la pipeline in modo non controllato.

**Locus nel codice.**
- `src/tests/base.py` — `_make_error()` helper e documentazione del contratto
- `src/external_tests/base.py` — blocco `try/except` nel metodo `_run()`
- `src/engine.py` — nessun `try/except` attorno a `test.execute()`: il contratto è del test, non dell'engine
- `4-Implementazione.md §4.8` — "Il metodo execute() deve sempre ritornare un TestResult. Non può propagare eccezioni"

**Conseguenze.** Un test che va in eccezione produce un `TestResult(ERROR)` e il pipeline prosegue con il test successivo. L'errore è registrato nell'evidenza con traceback (troncato a `_ERROR_MESSAGE_MAX_CHARS = 500` caratteri). Nessun test può bloccare un altro. La proprietà di solidità del sistema è implementata a livello di contratto, non di difesa perimetrale in `engine.py`.

**Tipo di evidenza.** Per costruzione — verificabile per ispezione di `src/engine.py` (assenza di `try/except` attorno a `test.execute()`) e di `src/tests/base.py` (presenza di `_make_error()` e del blocco `try/except Exception` in `execute()`). Osservabile empiricamente solo in presenza di un errore imprevisto: il test produce `TestResult(ERROR)` e la pipeline prosegue con il test successivo.

**Sviluppo futuro.** Il contratto è già compatibile con un modello di esecuzione distribuita: un test che gira su un worker remoto può serializzare il `TestResult(ERROR)` e inviarlo all'engine centrale senza che il worker crash si propaghi.

---

### D4.P4 — Custom Exception Hierarchy con Phase Mapping

**Definizione.** Tutte le eccezioni custom del tool sono sottoclassi di `ToolBaseError` con un mapping esplicito alla fase della pipeline in cui si verificano. Eccezioni di Phase 1-4 sono fatali e bloccano lo startup. Eccezioni di Phase 5-6 sono recuperate localmente (ERROR nei risultati o WARNING nel log).

**Locus nel codice.**
- `src/core/exceptions.py` — 8 classi: `ToolBaseError` (root), `ConfigurationError` (Phase 1), `OpenAPILoadError` (Phase 2), `DAGCycleError` (Phase 4), `SecurityClientError` (Phase 5 nativi), `AuthenticationSetupError` (helper autenticazione), `ExternalToolError` (Phase 5 esterni), `TeardownError` (Phase 6)
- `src/core/gateway/base.py:GatewayAdapterError` — errori Admin API gateway; definita accanto all'ABC che protegge (principio di locality). Campi: `path: str | None`, `status_code: int | None`
- `src/discovery/seed_generator.py` — `SeedGeneratorFetchError`, `SeedGeneratorParseError`; raised esclusivamente dal comando CLI `generate-seed`, **non coinvolgono la pipeline Phase 1-7**; catturate in `cli.py` e convertite in exit code 10
- `CLAUDE.md §Exception Hierarchy` — schema con descrizione del comportamento per fase
- `4-Implementazione.md §8` — "Nota: il tool non implementa ExternalToolNotFoundError — un tool mancante è una condizione operativa attesa, non un errore"

**Conseguenze.** La gerarchia conta **11 classi** (8 in `exceptions.py` + `GatewayAdapterError` in `gateway/base.py` + 2 in `seed_generator.py`) distribuite in 3 file. Il codice chiamante può fare `except ConfigurationError` (solo errori di config) o `except ToolBaseError` (qualsiasi errore del tool) con semantica precisa. Vietato `except Exception: pass` (regola esplicita). `AuthenticationSetupError` è distinto da `SecurityClientError`: il primo indica che le credenziali configurate sono invalide (errore di setup), il secondo che la rete ha fallito (errore transiente). I test WHITE_BOX catturano `GatewayAdapterError` e ritornano `TestResult(ERROR)` senza propagare l'eccezione all'engine. La scelta di NON avere `ExternalToolNotFoundError` è documentata: un tool mancante produce `SKIP`, non un'eccezione. `SeedGeneratorFetchError`/`SeedGeneratorParseError` sono le uniche eccezioni del tool che non transitano dall'engine: sono un'estensione della gerarchia per la CLI helper, architetturalmente isolata dal loop di assessment.

**Tipo di evidenza.** Per costruzione — verificabile per ispezione di `src/core/exceptions.py`, `src/core/gateway/base.py`, `src/discovery/seed_generator.py`. `GatewayAdapterError` è osservabile empiricamente se l'Admin API restituisce uno status HTTP inatteso durante un run con test 4.2 o 4.3: il test produce `TestResult(ERROR)` senza interrompere la pipeline.

**Sviluppo futuro.** La gerarchia è estendibile per fasi future (es. `ReportRenderError` per Phase 7) senza modificare le classi esistenti o i relativi handler.

---

### D4.P5 — Graceful Degradation Multi-Livello

**Definizione.** Il tool degrada in modo controllato a tre livelli: (1) tool esterno assente → test marcati `SKIP` via `_skip_reason_from_registry`; (2) Admin API non configurata → tutti i test `WHITE_BOX` ritornano `SKIP`; (3) `external_tools.enabled = false` → `ExternalTestRegistry.discover()` ritorna lista vuota senza scansionare il filesystem.

**Locus nel codice.**
- `src/external_tests/registry.py` — Phase R4 e master switch `external_tools.enabled`
- `src/tests/base.py` — pattern `if target.gateway is None: return self._make_skip(...)`
- `src/core/context.py` — `admin_api_available: bool` computed field
- `4-Implementazione.md §6.1` — sezione dedicata "Graceful Degradation per Ambienti DB-less"

**Conseguenze.** Un'esecuzione in ambiente di produzione senza Kong Admin API esposta produce risultati parziali ma corretti (i test WHITE_BOX sono tutti SKIP con motivo esplicito) anziché errori a cascata. Un ambiente di CI/CD senza tool esterni installati (solo Python) produce comunque risultati validi per i test nativi. I `SKIP` sono distinguibili nel report per motivo (tool mancante / admin API assente / prerequisito funzionale).

**Tipo di evidenza.** Empirica — dimostrata (a) eseguendo con `gateway_adapter: null` in `config.yaml`: test 3.3, 4.2, 4.3 ritornano `SKIP (Admin API not configured)` con motivo esplicito nel report; (b) senza nuclei/testssl installati: ext.0.1.nuclei e ext.1.5.testssl ritornano `SKIP` con un solo `WARNING` per tool nel log di Phase R4.

**Sviluppo futuro.** La degradazione graceful è il prerequisito per l'uso del tool in ambienti SaaS dove l'installazione di binari è impossibile: il tool funziona parzialmente con soli test nativi.

---

### D4.P6 — Best-Effort Teardown (LIFO con Registrazione Esplicita)

**Definizione.** I test che creano risorse persistenti (es. `POST /users`) le registrano nel `TestContext` via `register_resource_for_teardown(method, path, headers)` nel momento stesso della creazione. In Phase 6, l'engine drena il registro in ordine LIFO (Last In First Out) e tenta il `DELETE` di ogni risorsa tramite `SecurityClient`. I fallimenti di teardown sono loggati come `WARNING` e non invalidano i risultati.

**Locus nel codice.**
- `src/core/context.py` — `register_resource_for_teardown()`, `drain_resources()` con documentazione LIFO
- `src/engine.py` — Phase 6 loop con `TeardownError` catturato come WARNING
- `4-Implementazione.md §6.2` — "Teardown Best-Effort"

**Conseguenze.** Il tool mantiene la proprietà di "Pulizia": le risorse create durante l'assessment vengono rimosse, lasciando il target in uno stato equivalente a quello iniziale. L'ordine LIFO garantisce che risorse con dipendenze implicite di creazione (es. un `order` che dipende da un `user`) siano eliminate nell'ordine corretto. Un fallimento di teardown è un warning operativo, non un'invalidazione scientifica dell'assessment.

**Tipo di evidenza.** Empirica — dimostrata da test 1.4: il token API creato durante il test è registrato in `TestContext.register_resource_for_teardown()` immediatamente dopo la creazione; il log di Phase 6 mostra la chiamata `DELETE` in ordine LIFO prima della generazione del report.

**Sviluppo futuro.** Il meccanismo di teardown potrebbe essere esteso con retry logic (con backoff esponenziale) per ambienti con rate limiting stringente sull'endpoint di cancellazione.

---

### D4.P7 — Safe HTTP Probing Policy (Three-Outcome Oracle + Tier Segregation)

**Definizione.** Il tool non si limita a classificare una response come PASS/FAIL: applica una politica di probing sicura a tre risultati — ENFORCED (401/403: il gateway blocca correttamente), BYPASSED (2xx senza credenziali: vulnerabilità dimostrabile), INCONCLUSIVE (qualsiasi altro stato: 404, 405, 3xx, 5xx, timeout, rate-limited, DELETE non inviato) — e suddivide gli endpoint in due tier: Tier A (path non-parametrici, responso diretto e interpretabile) e Tier B (path parametrici, il cui responso dipende dalla qualità del path seed). I metodi HTTP distruttivi ricevono trattamento differenziato: DELETE parametrici usano il fallback sicuro `"apiguard-probe"`, DELETE non-parametrici (es. `/api/delete-all`) non vengono mai inviati e vengono classificati come `INCONCLUSIVE_UNPROBED_DESTRUCTIVE`.

**Locus nel codice.**
- `src/tests/domain_1/test_1_1_authentication_required.py` — safety matrix e oracle design documentati nel module docstring; costanti `_OUTCOME_ENFORCED`, `_OUTCOME_BYPASS`, `_OUTCOME_INCONCLUSIVE_PARAMETRIC`, `_OUTCOME_INCONCLUSIVE_UNPROBED_DESTRUCTIVE` e altre `_OUTCOME_INCONCLUSIVE_*`; la classificazione Tier A/B è inline in `_probe_unauthenticated()`
- `src/tests/helpers/path_resolver.py:PATH_PARAM_FALLBACK_SAFE_DELETE = "apiguard-probe"` — fallback sicuro per DELETE parametrici
- `src/core/models/results.py` — campi per riepilogo conteggi per categoria nel `TestResult`

**Conseguenze.** Il tool non causa mai perdita di dati sul target, anche se il gateway è misconfigured e lascia passare richieste non autenticate: un `DELETE /api/users/apiguard-probe` che raggiunge il backend trova un ID inesistente. La distinzione tre-via nell'oracle permette di separare "il gateway non protegge questo endpoint" (BYPASSED: FAIL dimostrabile con evidenza HTTP) da "non sono riuscito a verificarlo" (INCONCLUSIVE: segnalato nel report ma non conteggiato come vulnerabilità). Questo è critico per la credibilità del risultato: un tool che segna FAIL ogni `404` su endpoint parametrici genererebbe falsi positivi inaccettabili per uno strumento con pretese di assurance.

**Tipo di evidenza.** Empirica — dimostrata da test 1.1: il summary output contiene i quattro contatori `enforced_count`, `bypassed_count`, `inconclusive_parametric_count`, `inconclusive_unprobed_destructive_count`; il Tier A/B segregation è osservabile nel log per ogni endpoint sondato.

**Sviluppo futuro.** Il conteggio degli INCONCLUSIVE per categoria potrebbe alimentare un "confidence score" dell'assessment: un assessment con 80% di Tier B endpoint e seed non configurato ha una confidenza inferiore a uno con 80% di Tier A endpoint. Questo score potrebbe essere esposto nel report come metrica di qualità dell'assessment stesso.

---

### D4.P8 — Fail-Fast P0 Escalation Mode

**Definizione.** Quando `config.execution.fail_fast = true`, l'engine interrompe immediatamente la pipeline dopo che qualsiasi test con `priority == 0` restituisce `FAIL` o `ERROR`, senza eseguire i batch successivi. Entrambi gli stati sono trattati come bloccanti: un `ERROR` su un test P0 rappresenta una verifica perimetrale incompleta, altrettanto bloccante in un CI/CD gate di una vulnerabilità confermata.

**Locus nel codice.**
- `src/engine.py:AssessmentEngine._check_fail_fast()` — metodo statico, ritorna bool
- `src/engine.py:AssessmentEngine._phase_5_execute()` — logica di break nei loop batch/test
- `config.yaml:execution.fail_fast` — boolean flag (default: false)

**Conseguenze.** Una pipeline CI/CD può usare `fail_fast: true` per stoppare una build immediatamente alla prima violazione P0 confermata, senza attendere il completamento dell'intero assessment. Questa proprietà è distinta da D6.P1 (exit codes), che descrive il valore di ritorno *dopo* il completamento della pipeline; D4.P8 riguarda se fermarsi in anticipo. La distinzione è rilevante per ambienti dove il wall-clock time dell'assessment è un vincolo: un assessment su un target con 200+ endpoint e 15 test può richiedere diversi minuti; il fail-fast elimina la coda una volta accertato il problema critico.

**Tipo di evidenza.** Empirica — dimostrata eseguendo con `execution.fail_fast: true` contro un target dove test 1.1 produce FAIL: il log di Phase 5 mostra l'interruzione prima dell'esecuzione di test 1.4; il `ResultSet` finale contiene solo il risultato di test 1.1.

**Sviluppo futuro.** Il predicato fail-fast potrebbe essere reso configurabile per dominio o range di priorità (es. fail-fast solo su violazioni del Dominio 1 e Dominio 7).

---

### D4.P9 — Type-Level TestResult Invariant Enforcement

**Definizione.** Tre invarianti su `TestResult` sono enforced al **momento della costruzione** da un `model_validator(mode="after")` di Pydantic, non da check runtime ad hoc distribuiti nei singoli test: (1) `status=FAIL` richiede `findings` non vuoto (l'evidenza è obbligatoria per ogni vulnerabilità dichiarata); (2) `status=SKIP` richiede `skip_reason` non null (ogni SKIP deve essere documentabile); (3) `status=PASS` richiede `findings` vuoto (un PASS non può coesistere con violazioni dichiarate). Violare uno di questi invarianti solleva `pydantic.ValidationError` nel punto in cui `_make_pass()`, `_make_fail()`, o `_make_skip()` costruisce l'oggetto risultato — prima che il risultato raggiunga il report.

**Locus nel codice.**
- `src/core/models/results.py:TestResult.validate_status_finding_consistency()` — `@model_validator(mode="after")`
- `src/tests/base.py:BaseTest._make_fail()` — chiama il costruttore TestResult; il validator si attiva
- `src/external_tests/base.py:ExternalToolTest._make_fail()` — stesso meccanismo

**Conseguenze.** Un test che costruisce `_make_pass(message)` con una lista `findings` accidentalmente popolata solleva al momento della costruzione, non produce silenziosamente un entry di report semanticamente inconsistente. Il contratto è enforced a livello di tipo: il validator è il single point of truth, non una convenzione che i caller devono ricordare di rispettare. Questa proprietà è architetturalmente distinta da D5.P2 (che definisce il *significato semantico* di Finding vs InfoNote) e da D4.P3 (che descrive l'*isolamento delle eccezioni* tra test). D4.P9 riguarda specificamente come il *contratto status-evidenza* è enforced tramite il sistema dei tipi piuttosto che tramite asserzioni distribuite.

**Tipo di evidenza.** Per costruzione — verificabile per ispezione di `src/core/models/results.py` (`model_validator validate_status_finding_consistency`). In operazione corretta il validator è trasparente; è osservabile in sviluppo invocando `_make_fail(message, findings=[])` o `_make_skip(reason=None)`: entrambi sollevano `pydantic.ValidationError` prima che il risultato raggiunga l'engine.

**Sviluppo futuro.** Il pattern validator può essere esteso per enforcare la presenza di `duration_ms` per compliance reporting (ogni test deve registrare quanto ha impiegato), senza modificare i caller.

---

## D5 — Qualità & Osservabilità

### D5.P1 — Methodology Traceability (Tracciabilità alla Metodologia)

**Definizione.** Ogni test porta con sé, come `ClassVar`, i riferimenti normativi della garanzia che verifica: `cwe_id`, `tags` (OWASP, RFC), `test_id` (che corrisponde esattamente all'ID nel documento Metodologia). Ogni `Finding` propaga `references: list[str]`. Il report HTML riporta questi riferimenti a fianco del risultato.

**Locus nel codice.**
- `src/tests/base.py` — `cwe_id: ClassVar[str]`, `tags: ClassVar[list[str]]` obbligatori
- `src/core/models/results.py` — `Finding.references: list[str]`
- `src/report/builder.py` — aggregazione con propagazione dei riferimenti
- `3-Metodologia.md` — ogni garanzia ha ID, riferimenti OWASP, CWE, NIST, RFC

**Conseguenze.** Un analista che legge un `Finding` nel report HTML può risalire direttamente alla sezione della metodologia che descrive il test, all'OWASP category, al CWE, e al RFC applicabile. Il report non è un output opaco ma un documento tracciabile e verificabile. Questa proprietà è essenziale per un tool con pretese accademiche e potenziale enterprise.

**Tipo di evidenza.** Empirica — dimostrata nel report HTML `assessment_report.html` generato da qualsiasi run con FAIL: ogni `Finding` mostra `cwe_id`, `tags` OWASP/RFC e la lista `references` accanto all'esito del test.

**Sviluppo futuro.** La tracciabilità abilita il calcolo automatico di punteggi di conformità rispetto a framework di sicurezza (OWASP ASVS score, NIST SP 800-53 compliance percentage) aggregando i `tags` e `cwe_id` dei test PASS/FAIL.

---

### D5.P2 — Finding/InfoNote Semantic Distinction

**Definizione.** Il modello `TestResult` distingue due tipi di annotazioni: `Finding` (evidenza di una violazione di sicurezza, presente solo in risultati FAIL, contata nel totale, resa in rosso nel report) e `InfoNote` (annotazione informativa contestuale su un risultato PASS, non conta come violazione, non cambia lo status, resa in blu). Un `PASS` non può avere `Finding`; questa invariante è enforced da un `model_validator` Pydantic.

**Locus nel codice.**
- `src/core/models/results.py` — `Finding`, `InfoNote`, `TestResult` con `model_validator`
- `src/tests/domain_4/test_4_3_circuit_breaker_audit.py` — uso pratico: PASS con InfoNote per documentare un compensating control

**Conseguenze.** Il test 4.3 (Circuit Breaker) può passare tramite un "compensating control" (healthcheck passivo anziché circuit breaker attivo) e spiegare la differenza architetturale tramite `InfoNote` senza rilassare il vincolo che "un PASS non ha Finding". L'analista vede il PASS e la nota contestuale senza confusione semantica.

**Tipo di evidenza.** Empirica — dimostrata da test 4.3 (Circuit Breaker su Kong OSS con healthcheck passivo configurato): il risultato è `PASS` con `InfoNote` che documenta il compensating control; osservabile nel report HTML (InfoNote resa in blu accanto al PASS, nessun `Finding` in rosso).

**Sviluppo futuro.** Il pattern InfoNote è riutilizzabile per documentare "partial compliance" (garanzia soddisfatta ma con una nota di miglioramento) senza introdurre un quinto status di test ibrido che complicherebbe la logica di aggregazione nel report.

---

### D5.P3 — DRY Principle con Funzioni Autoritative Centrali

**Definizione.** Operazioni che altrimenti verrebbero duplicate sono centralizzate in un singolo punto autorevole. Esempi: `_relativize_display_path()` in `connectors/base.py` per la sanitizzazione dei path nei command display; costanti `ROLE_ADMIN`, `ROLE_USER_A`, `ROLE_USER_B` in `context.py` per eliminare magic strings nelle chiavi token; `EvidenceStore.pin_artifact()` per la sanitizzazione credenziali; `response_inspector.py` per la logica di ispezione response riusata dai test 2.5, 6.1, 6.2, 6.3.

**Locus nel codice.**
- `src/connectors/base.py:_relativize_display_path()` — docstring: "single authoritative function for path normalization"
- `src/core/context.py` — `ROLE_ADMIN: str = "admin"` etc.
- `src/core/evidence.py` — `pin_artifact()` con sanitizzazione centralizzata
- `src/tests/helpers/response_inspector.py` — analisi response condivisa tra test multipli
- `CLAUDE.md §Path Sanitization` — regola esplicita: "Never duplicate this logic"

**Conseguenze.** Se il formato del display path cambia, la modifica è in un solo posto. Se si aggiunge un nuovo ruolo, la costante è dichiarata una volta e usata ovunque. Se un nuovo pattern di information leakage viene scoperto, viene aggiunto a `inspector_patterns.py` e immediatamente coperto da tutti i test che usano il modulo.

**Tipo di evidenza.** Empirica — dimostrata da test 6.2 e test 6.4 che usano `response_inspector.py` e `inspector_patterns.py` (definiti una sola volta, importati da più test); e da ext.0.1.nuclei e ext.1.5.testssl che chiamano `_relativize_display_path()` dalla funzione unica in `connectors/base.py`. Verifica: `grep -c "def _relativize_display_path" src/connectors/base.py` restituisce 1.

**Sviluppo futuro.** Le costanti di ruolo potrebbero diventare un'enum Pydantic per abilitare la validazione automatica: un `get_token(role="superadmin")` con un ruolo non dichiarato produce errore invece di ritornare silenziosamente `None`.

---

### D5.P4 — Structured Logging con Credential Redaction Obbligatoria

**Definizione.** Tutto il logging usa `structlog` con eventi strutturati a coppie chiave-valore (non stringhe interpolate). `print()` è categoricamente vietato. Ogni log message che potrebbe contenere dati sensibili deve usare `[REDACTED]`. La regola è attiva ed esplicita: non è sufficiente "non loggare" un campo — la struttura dell'oggetto potrebbe essere serializzata automaticamente da layer sottostanti.

**Locus nel codice.**
- `knowledge/RULES_claude.md §5.4` — "No print(), use structlog with structured events (key-value pairs)"
- `knowledge/RULES_claude.md §5.7` — "Credential sanitization: replace with [REDACTED]"
- Ogni modulo: `log: structlog.BoundLogger = structlog.get_logger(__name__)` come prima dichiarazione

**Conseguenze.** Il log prodotto è machine-readable e ingestibile direttamente in sistemi di log aggregation (ELK, Loki) senza parsing custom. La redaction sistematica delle credenziali previene che un log leak esponga token JWT o password nei file di log di un CI/CD runner.

**Tipo di evidenza.** Empirica — dimostrata da qualsiasi run del tool: l'output di log è in formato structlog (coppie chiave-valore) osservabile direttamente nel terminale o piping a `jq`. Per costruzione: `grep -r "print(" src/` restituisce zero risultati.

**Sviluppo futuro.** Con structlog, ogni log event porta il contesto del test corrente (test_id, domain, priority) come campo strutturato: filtrare il log per `test_id=1.1` è triviale in qualsiasi query ELK.

---

### D5.P5 — Report Domain-Centric Split (Native vs External)

**Definizione.** Il `report/builder.py` partiziona i risultati per `domain` × `source` (`"native"` / `"external"`), producendo una struttura `DomainSummary` per ogni dominio. Nel report HTML, per ogni dominio è immediatamente chiaro quali risultati provengono da test Python nativi e quali da tool specializzati. Il campo `source` è un `Literal` nel `TestResult`, propagato dal registry al momento della costruzione.

**Locus nel codice.**
- `src/core/models/results.py` — `TestResult.source: Literal["native", "external"]`
- `src/report/builder.py` — partizionamento per `domain` × `source`
- `4-Implementazione.md §4.10` — "Domain-Centric Split"

**Conseguenze.** Un analista che legge il report sa immediatamente se un `FAIL` nel Dominio 1 è stato rilevato da un test Python (con una request HTTP diretta del tool) o da `testssl.sh` (con analisi TLS specializzata). La distinzione è rilevante per la riproduzione manuale del finding: le evidenze native hanno una request HTTP dimostrabile; quelle esterne hanno il raw output del tool.

**Tipo di evidenza.** Empirica — dimostrata dal report HTML di una run che include test 1.1 (`source="native"`) e ext.0.1.nuclei (`source="external"`): il report mostra le sezioni `native` ed `external` separatamente per il Dominio 0 e il Dominio 1.

**Sviluppo futuro.** Il split per source abilita report differenziati per audience: un report "executive summary" che mostra solo i FAIL nativi (prove dirette), un report "technical deep-dive" che include anche le analisi degli external tool.

---

## D6 — CI/CD & DevEx

### D6.P1 — Semantic Exit Codes per CI/CD Integration

**Definizione.** Il processo termina con exit code che riflette lo stato aggregato del `ResultSet`, calcolato in `report/builder.py`: `0` (clean), `1` (almeno un FAIL), `2` (almeno un ERROR senza FAIL), `10` (errore infrastrutturale bloccante). La priorità `FAIL` prevale su `ERROR`.

**Locus nel codice.**
- `src/engine.py` — costanti `EXIT_CODE_CLEAN`, `EXIT_CODE_FAIL`, `EXIT_CODE_ERROR`, `EXIT_CODE_INFRASTRUCTURE`
- `src/report/builder.py` — calcolo dell'exit code da `ResultSet`
- `4-Implementazione.md §7` — tabella exit code con condizioni esatte

**Conseguenze.** Il tool può essere inserito direttamente in pipeline CI/CD (GitHub Actions, GitLab CI, Jenkins) con un semplice check sul codice di uscita: `apiguard run --config config.yaml && echo "Assessment passed"`. Un exit code `1` blocca il merge di una PR su endpoint che hanno introdotto vulnerabilità. L'exit code `10` è separato per permettere di distinguere "il tool non si è avviato" da "il tool si è avviato e ha trovato problemi".

**Tipo di evidenza.** Empirica — dimostrata da qualsiasi run completo: exit 0 su target correttamente configurato (tutti i test PASS/SKIP), exit 1 su target con autenticazione non enforced (test 1.1 FAIL), exit 10 con `config.yaml` invalido (`ConfigurationError` in Phase 1).

**Sviluppo futuro.** Exit code `3` (riservato) potrebbe indicare "FAIL solo su test P2/P3" per permettere una politica di CI/CD che blocca solo su violazioni P0/P1.

---

### D6.P2 — Dev-Mode Evidence Cache (Acceleratore dello Sviluppo)

**Definizione.** I test `ExternalToolTest` supportano una modalità di sviluppo (`external_tools.<tool>.dev_mode: true` in `config.yaml`) in cui l'output del tool esterno viene letto da un file cache locale invece di invocare il binary. Questo permette di iterare rapidamente sull'oracle `_evaluate()` senza rieseguire tool lenti (testssl.sh richiede 30-60 secondi per un'analisi TLS completa).

**Locus nel codice.**
- `src/external_tests/base.py:ExternalToolTest._load_dev_cache()` — logica di cache lookup; il filename è `{safe_label}_output.json` dove `safe_label` sostituisce i caratteri `./\\ ` con underscore
- `src/external_tests/base.py:ExternalToolTest._is_dev_mode()` — verifica il flag `dev_mode` per tool specifico tramite `TargetContext.external_tools`
- `config.yaml` — `external_tools.testssl.dev_mode: false` e `external_tools.nuclei.dev_mode: false` (default per tutti i tool)
- `docs/pub/ADDING_external_tests.md` — workflow documentato per sviluppatori
- La cache è scritta nella directory `outputs/tools/` (`store.tools_dir`); l'engine Phase 3 imposta questo path. L'envelope ha struttura `{"source_test_id": ..., "label": ..., "record_id": ..., "generated_at_utc": ..., "data": {...}}` con chiavi `_apiguard_meta_*` per il metadata di enrichment

**Conseguenze.** Il ciclo di sviluppo per un nuovo test HYBRID scende da minuti (run completa con tool esterno) a secondi (lettura da cache). La cache è disabilitata per default e deve essere abilitata esplicitamente: zero rischio di dimenticarla attiva in produzione. Una cache hit restituisce un `ConnectorResult` con `tool_version=None` e `execution_time_ms=0`, distinguibile da una vera esecuzione nel log.

**Tipo di evidenza.** Empirica — dimostrata eseguendo ext.0.1.nuclei o ext.1.5.testssl con `external_tools.<tool>.dev_mode: true` dopo una prima run reale (che ha popolato `outputs/tools/`): la seconda run non invoca il binario (nessun subprocess nel log), `execution_time_ms=0` e `tool_version=null` nel `ConnectorResult` sono osservabili.

**Sviluppo futuro.** Il pattern cache potrebbe essere generalizzato a una "snapshot mode" per l'intera pipeline: registra l'output di tutti i tool durante la prima run, riusa le snapshot nelle run successive per CI/CD deterministico (test di regressione sull'oracle senza rete).

---

### D6.P3 — Dual-Layer Type Safety (Mypy Strict + Pydantic v2 Runtime)

**Definizione.** Il codebase applica due strati di type enforcement indipendenti e complementari: (1) **mypy strict** a compile-time (verificato con `mypy src/` — 0 errori su 90 file sorgente, con `strict = true` in `pyproject.toml`); (2) **Pydantic v2 validators** a runtime al momento della costruzione degli oggetti (model_validator, field_validator, Annotated constraints). I due strati coprono scenari diversi: mypy rileva errori di tipo nella logica del codice sorgente prima dell'esecuzione; Pydantic rileva dati invalidi alle *system boundaries* (config YAML caricato da disco, output dei connector, construction dei TestResult). Un `wrong_type` in un helper interno è catturato da mypy; un `timeout_seconds=None` con `enabled=True` nel config YAML è catturato dal validator Pydantic `_timeout_required_when_enabled`. Il combinazione elimina la classe di bug "typecheck verde, runtime crash".

**Locus nel codice.**
- `pyproject.toml:[tool.mypy] strict = true` — abilita l'intero set di flag strict (no-implicit-optional, disallow-untyped-defs, warn-return-any, ecc.)
- `src/config/schema/` — tutti i `BaseModel` con `frozen=True` + validatori specifici per ogni parameter (ge/le, min_length, description)
- `src/core/models/results.py:TestResult.validate_status_finding_consistency()` — model_validator che enforca la coerenza status-evidence
- `src/core/models/external_tools.py:BaseExternalToolConfig._timeout_required_when_enabled()` — field_validator che enforca `timeout_seconds != None` quando `enabled=True`
- `src/core/models/runtime.py` — tutti i `RuntimeTest*Config` con `frozen=True` che rendono `TargetContext` completamente immutabile
- `hatch run dev:lint` — gate CI che esegue `ruff check . && mypy src/` prima di ogni push; "Success: no issues found in 90 source files" è il contratto di release

**Conseguenze.** Aggiungere un parametro con il tipo sbagliato (es. `timeout_seconds: str` invece di `int | None`) viene catturato immediatamente da `mypy` — prima che il codice venga mai eseguito. Passare `timeout_seconds=None` con `enabled=True` in `config.yaml` viene catturato da Pydantic durante il `load_config()` in Phase 1 con messaggio actionable, non durante `_invoke_connector()` alle 3:00 di notte in produzione. Il costo mantenuto di questo sistema è zero per l'autore del test: type hints sono già obbligatori (Hard Rule), `frozen=True` è già obbligatorio per i config models. La safety emerge dalla struttura, non da disciplina manuale.

**Tipo di evidenza.** Per costruzione — verificabile con `mypy src/ --strict` (ritorna exit 0, "no issues in 90 source files"). La coverage runtime Pydantic è verificabile aggiungendo deliberatamente un valore invalido in `config.yaml` (es. `enabled: true` senza `timeout_seconds`) e osservando che `apiguard validate-config` produce `ConfigurationError` con il path del campo violato invece di un crash silenzioso.

**Sviluppo futuro.** L'aggiunta di `py.typed` marker al package (PEP 561) renderebbe i type hints esportati ai downstream consumer: chi scrive test personalizzati come plugin esterno otterrebbe la stessa sicurezza di tipo nell'IDE senza configurazione aggiuntiva.

---

## D7 — Packaging & Deployment

### D7.P1 — Three-Channel Binary Resolution (Deployment Multi-Modale)

**Definizione.** `BaseSubprocessConnector._resolve_binary()` risolve il path del binario esterno tramite una cascata a tre canali, in ordine di priorità crescente di deployment:
1. **Channel 0 — Local bundle** (`./tools/LOCAL_TOOLS_SUBDIR/BINARY_NAME`): usa la copia locale presente nel repo sotto `tools/`, attivo solo se `LOCAL_TOOLS_SUBDIR` è non-vuoto. Garantisce versione pinned senza installazione di sistema.
2. **Channel 1 — System PATH** (`shutil.which(BINARY_NAME)`): binario installato globalmente (`apt`, `brew`, build from source).
3. **Channel 2 — HTTP Microservice** (`os.getenv(SERVICE_ENV_VAR)`): il tool esterno è esposto come servizio HTTP (tipicamente in Docker Compose); il connector invia richieste HTTP invece di invocare un subprocess.

La cascata si arresta al primo canale disponibile. Se nessun canale è attivo, `is_available()` ritorna `False` e il test ottiene `SKIP`.

**Locus nel codice.**
- `src/connectors/base.py:BaseSubprocessConnector._resolve_binary()` — cascata a tre canali
- `src/connectors/base.py:BaseSubprocessConnector.LOCAL_TOOLS_SUBDIR` — `ClassVar[str] = ""` (default disabilitato); `TestsslConnector` lo imposta a `"testssl"`, `NucleiConnector` a `"nuclei"`
- `src/connectors/base.py:BaseSubprocessConnector.SERVICE_ENV_VAR` — `ClassVar[str]` (e.g. `"TESTSSL_SERVICE_URL"`, `"NUCLEI_SERVICE_URL"`)
- `pyproject.toml` — tools bundled nella directory `tools/` (esclusa dal wheel, presente nel repo)

**Conseguenze.** Il medesimo `NucleiConnector` funziona senza modifiche in tre contesti: sviluppo su macOS con `nuclei` installato via `brew` (Channel 1), CI/CD con il binario sotto `./tools/nuclei/` (Channel 0), e deployment containerizzato con nuclei come Docker sidecar (Channel 2). Zero `if DEV_MODE / if DOCKER` nel codice applicativo: la logica di discovery è incapsulata nel connector. L'operatore configura solo l'env var `SERVICE_ENV_VAR` per abilitare il Channel 2; tutto il resto è automatico.

**Tipo di evidenza.** Per costruzione — verificabile per ispezione di `src/connectors/base.py` (metodo `_resolve_binary()` con le tre rami). Channel 0 verificabile con `./tools/testssl/testssl.sh` presente nel repo; Channel 1 verificabile dopo `sudo apt install nuclei`; Channel 2 richiederebbe `docker-compose.yml` con sidecar (non incluso in M1 ma architetturalmente supportato).

**Sviluppo futuro.** Il Channel 2 abilita un'architettura tool-as-microservice in cui tool costosi (nuclei con molti template, testssl con full scan) girano come container persistenti e ricevono richieste dallo stesso run del tool, riducendo drasticamente l'overhead di startup per N run consecutivi.

---

### D7.P2 — License-Gated Optional Dependency (AGPL Isolation)

**Definizione.** Il componente `sslyze` (e la sua dipendenza nativa `nassl`) è rilasciato sotto AGPL v3. Per mantenere il core del tool distribuibile sotto licenza MIT senza obblighi copyleft, `sslyze` è dichiarato esclusivamente in `[project.optional-dependencies.sslyze]` in `pyproject.toml`. Un'installazione standard (`pip install apiguard-assurance`) non installa sslyze. L'utente che vuole abilitare `ext.1.5.sslyze` installa esplicitamente `pip install "apiguard-assurance[sslyze]"` (o `pip install -e ".[sslyze]"` in sviluppo), accettando consapevolmente l'AGPL.

**Locus nel codice.**
- `pyproject.toml:[project.optional-dependencies.sslyze]` — `"sslyze>=6.3,<7"` con commento AGPL esplicito
- `pyproject.toml:[tool.hatch.envs.default]` — `features = ["sslyze"]` incluso per lo sviluppo (il dev env installa sslyze)
- `src/connectors/sslyze.py` — `SslyzeConnector(BaseLibraryConnector)` usa `importlib.util.find_spec("sslyze")` per `is_available()`: se il pacchetto opzionale non è installato, `is_available()` ritorna `False` → `ext.1.5.sslyze` ottiene `SKIP`

**Conseguenze.** Il meccanismo `BaseLibraryConnector.is_available()` (D7.P1/D1.P5) rende il gating completamente trasparente a runtime: se sslyze non è installato, il test è `SKIP` con motivo esplicito. Il core dell'applicazione rimane MIT-clean senza alcun import condizionale. Il wheel distribuibile su PyPI (`apiguard-assurance-X.Y.Z-py3-none-any.whl`) non include sslyze nel proprio `METADATA`'s `Requires-Dist` per default, ma è "PyPI extras-ready".

**Tipo di evidenza.** Per costruzione — verificabile in `pyproject.toml` (assenza di `sslyze` nella sezione `[project] dependencies`, presenza in `[project.optional-dependencies]`). Verificabile a runtime: in un virtualenv senza `pip install ".[sslyze]"`, `SslyzeConnector().is_available()` ritorna `False` e `ext.1.5.sslyze` produce `SKIP ("sslyze library not available")`.

**Sviluppo futuro.** Il pattern extras-gated è replicabile per qualsiasi componente con licenza incompatibile o dipendenza pesante: es. un futuro `[project.optional-dependencies.burp]` per il BurpSuite headless integration o `[project.optional-dependencies.ml]` per feature LLM-assisted che dipendono da PyTorch.

---

### D7.P3 — Deployment-Transparent URL Abstraction (effective_base_url)

**Definizione.** Il tool funziona senza modifiche in due modalità di deployment che differiscono nell'indirizzo di rete del target: *standalone* (il tool gira direttamente sulla macchina host e raggiunge Forgejo su `localhost` o IP pubblico) e *Docker Compose* (il tool gira in un container e raggiunge Forgejo tramite il nome del servizio Compose, es. `http://forgejo:3000`). `TargetContext.effective_base_url` è il campo che astrae questa differenza: in standalone è uguale a `base_url` (letto da `config.yaml`); in Docker Compose viene sovrascritto dal valore di `APIGUARD_TARGET_EFFECTIVE_URL` (env var iniettata dal Compose file), risolto **una sola volta** in Phase 3 e frozen nel `TargetContext`.

**Locus nel codice.**
- `src/core/context.py:TargetContext.effective_base_url` — campo `AnyHttpUrl | None`, popolato da engine Phase 3
- `src/core/context.py:TargetContext.effective_endpoint_base_url()` — metodo usato dai connector per costruire gli URL di target; mai `base_url` direttamente
- `src/engine.py` Phase 3 — `os.getenv("APIGUARD_TARGET_EFFECTIVE_URL")` con fallback a `config.target.base_url`; risultato assegnato al campo `effective_base_url`
- `src/connectors/nuclei.py`, `src/connectors/testssl.py`, `src/connectors/sslyze.py` — usano tutti `target.effective_endpoint_base_url()`, non `target.base_url`

**Conseguenze.** L'operatore che sposta il tool da standalone a Docker Compose modifica solo il Compose file (aggiunge `APIGUARD_TARGET_EFFECTIVE_URL=http://forgejo:3000`) senza toccare `config.yaml` né il codice. I connector non hanno logica condizionale di deployment: non sanno e non devono sapere se stanno girando in un container o sulla macchina host. La risoluzione è effettuata una sola volta e il campo è frozen: zero inconsistenze tra connector diversi che potrebbero leggere l'env var in momenti diversi.

**Tipo di evidenza.** Per costruzione — verificabile con `grep -r "base_url" src/connectors/`: tutti i connector usano `target.effective_endpoint_base_url()` (mai `target.base_url` direttamente). La logica di Phase 3 è verificabile in `src/engine.py` per ispezione.

**Sviluppo futuro.** Il pattern si estende naturalmente a un profilo `config_docker.yaml` che può referenziare `${APIGUARD_TARGET_EFFECTIVE_URL}` come placeholder, con il medesimo meccanismo di interpolazione di `loader.py`. Abilita anche il testing multi-stage: tool che usano indirizzi diversi per il target applicativo vs il Kong Admin API.

---

## Riepilogo Tassonomico

| Dominio | Proprietà |
|---|---|
| **D1 — Architettura & Design** | D1.P1 API-Agnosticism, D1.P2 Unidirectional Dependency Flow, D1.P3 Split State & Immutabilità, D1.P4 Dual Test Hierarchy, D1.P5 Three-Tier Connector Hierarchy, D1.P6 Gateway-Agnostic Adapter |
| **D2 — Estensibilità & Manutenibilità** | D2.P1 Dynamic Test Discovery, D2.P2 DAG Scheduling, D2.P3 Separation Data/Evaluation, D2.P4 Connector Lifecycle DI, D2.P5 Auth Abstraction Layer, D2.P6 Cat A/B Classification, D2.P7 Path Seed System, D2.P8 Test Data Catalog |
| **D3 — Config & Riproducibilità** | D3.P1 Config-Driven Development, D3.P2 Single Source of Truth, D3.P3 Box Gradient, D3.P4 Reproducibility, D3.P5 Zero External State Dependency |
| **D4 — Robustezza & Sicurezza** | D4.P1 Streaming Evidence Store, D4.P2 Evidence Sanitization, D4.P3 Fail-Safe Isolation, D4.P4 Exception Hierarchy, D4.P5 Graceful Degradation, D4.P6 Best-Effort Teardown, D4.P7 Safe HTTP Probing Policy, D4.P8 Fail-Fast P0 Escalation, D4.P9 TestResult Invariant Enforcement |
| **D5 — Qualità & Osservabilità** | D5.P1 Methodology Traceability, D5.P2 Finding/InfoNote Distinction, D5.P3 DRY, D5.P4 Structured Logging, D5.P5 Report Domain-Centric Split |
| **D6 — CI/CD & DevEx** | D6.P1 Semantic Exit Codes, D6.P2 Dev-Mode Cache, D6.P3 Dual-Layer Type Safety |
| **D7 — Packaging & Deployment** | D7.P1 Three-Channel Binary Resolution, D7.P2 License-Gated Optional Dependency, D7.P3 Deployment-Transparent URL |

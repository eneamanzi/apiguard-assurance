# ***Implementazione — Tool Python per API Security Assessment***

- [***1. Il Problema e i Vincoli di Progetto***](#1-il-problema-e-i-vincoli-di-progetto)
- [***2. Struttura del Progetto***](#2-struttura-del-progetto)
- [***3. Principi di Design Fondamentali***](#3-principi-di-design-fondamentali)
  - [***3.1 Filosofia API-Agnostica***](#31-filosofia-api-agnostica)
  - [***3.2 Stato Scisso e Immutabilità***](#32-stato-scisso-e-immutabilità)
- [***4. I Componenti e Come Si Parlano***](#4-i-componenti-e-come-si-parlano)
  - [***4.1 Il Layer di Configurazione (`config/`)***](#41-il-layer-di-configurazione-config)
  - [***4.2 Il Discovery della Superficie d'Attacco (`discovery/`)***](#42-il-discovery-della-superficie-dattacco-discovery)
  - [***4.3 I Due Contesti di Esecuzione: `TargetContext` e `TestContext`***](#43-i-due-contesti-di-esecuzione-targetcontext-e-testcontext)
  - [***4.4 SecurityClient e EvidenceStore — La Coppia HTTP***](#44-securityclient-e-evidencestore--la-coppia-http)
  - [***4.5 TestRegistry e DAGScheduler — Discovery e Ordinamento***](#45-testregistry-e-dagscheduler--discovery-e-ordinamento)
  - [***4.6 Il Layer Connector (`connectors/`)***](#46-il-layer-connector-connectors)
  - [**4.6.1 `BaseGatewayAdapter` — Astrazione del Piano di Configurazione**](#461-basegatewayadapter--astrazione-del-piano-di-configurazione)
  - [***4.7 ExternalToolTest e ExternalTestRegistry***](#47-externaltooltest-e-externaltestregistry)
  - [***4.8 BaseTest — Il Contratto di Ogni Test Nativo***](#48-basetest--il-contratto-di-ogni-test-nativo)
  - [***4.9 Engine — L'Orchestratore***](#49-engine--lorchestratore)
  - [***4.10 Report Layer***](#410-report-layer)
- [***5. La Pipeline di Esecuzione — Flusso Completo***](#5-la-pipeline-di-esecuzione--flusso-completo)
- [***6. Comportamenti Speciali e Casi Limite***](#6-comportamenti-speciali-e-casi-limite)
  - [***6.1 Graceful Degradation per Ambienti DB-less***](#61-graceful-degradation-per-ambienti-db-less)
  - [***6.2 Teardown Best-Effort***](#62-teardown-best-effort)
  - [***6.3 Rate Limit Discovery Empirica (Test 4.1)***](#63-rate-limit-discovery-empirica-test-41)
- [***7. Exit Code e Integrazione CI/CD***](#7-exit-code-e-integrazione-cicd)
- [***8. Gerarchia delle Eccezioni***](#8-gerarchia-delle-eccezioni)

## ***1\. Il Problema e i Vincoli di Progetto***

*La Metodologia (Capitolo 2\) definisce 8 domini di test, garanzie di sicurezza e un gradiente di privilegio Black/Grey/White Box. Eseguire manualmente questa metodologia su ogni target è lento, non riproducibile e non lascia tracce strutturate: il risultato dipende dall'operatore, le evidenze (request/response) vanno raccolte a mano, e ogni applicativo richiede script ad hoc che non funzionano sul prossimo.*

*Il tool risolve questo problema automatizzando l'intera pipeline: dalla lettura del `config.yaml` alla generazione del report PDF. Lo fa rispettando sei vincoli non negoziabili, che governano ogni scelta architetturale descritta in questo documento:*

| *Vincolo* | *Descrizione* |
| ----- | ----- |
| ***Agnosticismo*** | *Funziona su qualsiasi API REST senza toccare il codice sorgente.* |
| ***Tracciabilità*** | *Ogni FAIL è corredato da evidenza HTTP dimostabile.* |
| ***Prioritizzazione*** | *Si può scegliere di eseguire solo P0, o P0+P1, ecc.* |
| ***Solidità*** | *Un test che va in eccezione non blocca gli altri.* |
| ***Pulizia*** | *Le risorse create nei test vengono rimosse a fine esecuzione.* |
| ***Riproducibilità*** | *Lo stesso `config.yaml` sullo stesso target dà sempre gli stessi risultati.* |

***Vincoli tecnici fissi:***

* ***Nessun database esterno** a runtime: tutto lo stato vive in memoria o in file locali.*

## ***2\. Struttura del Progetto***

*La struttura delle directory riflette i confini logici dell'architettura, non il tipo dei file. Ogni directory è un dominio di responsabilità con una sola direzione di dipendenza: il codice in `core/` non sa che i test esistono; i test sanno che `core/` esiste e lo usano.*

*apiguard-assurance/*

 *│*

 *├── config.yaml                 \# Configurazione del target (fornita dall'utente)*

 *├── pyproject.toml              \# Dipendenze, Ruff config, metadati*

 *│*

 *├── src/*

 *│   ├── cli.py                  \# Entry point CLI (Typer)*

 *│   ├── engine.py               \# Orchestratore — l'unico modulo con visibilità totale*

 *│   │*

 *│   ├── core/                   \# Infrastruttura condivisa — zero logica di test*

 *│   │   ├── client.py           \# SecurityClient — wrapper httpx centralizzato*

 *│   │   ├── context.py          \# TargetContext (frozen) \+ TestContext (mutable)*

 *│   │   ├── evidence.py         \# EvidenceStore — streaming JSONL per-test files (v2.0)*

 *│   │   ├── dag.py              \# DAGScheduler — graphlib wrapper*

 *│   │   ├── models/             \# Modelli Pydantic condivisi (package)*

 *│   │   │   \# enums.py, http.py, results.py, runtime.py, surface.py, external\_tools.py*

 *│   │   ├── gateway/            \# Gateway adapter abstraction + implementations*

 *│   │   │   ├── base.py         \# BaseGatewayAdapter ABC \+ GatewayAdapterError*

 *│   │   │   └── kong.py         \# KongGatewayAdapter (Kong DB-less Admin API v3.x)*

 *│   │   └── exceptions.py       \# Gerarchia eccezioni custom del tool*

 *│   │*

 *│   ├── config/                 \# Caricamento e validazione della configurazione*

 *│   │   └── schema/             \# Schema Pydantic (tool\_config.py + domain\_N.py + tests\_config.py)*

 *│   │   └── loader.py           \# Parser YAML \+ interpolazione variabili d'ambiente*

 *│   │*

 *│   ├── discovery/              \# Comprensione del target a runtime*

 *│   │   ├── openapi.py          \# Fetch, dereferenziazione, validazione spec OpenAPI*

 *│   │   └── surface.py          \# AttackSurface — mappa strutturata degli endpoint*

 *│   │*

 *│   ├── connectors/             \# Wrapper verso tool esterni — zero logica di test*

 *│   │   ├── base.py             \# BaseConnector (ABC puro) \+ BaseSubprocessConnector*

 *│   │   │                       \# \+ BaseLibraryConnector \+ ConnectorResult \+ ConnectorRawOutput*

 *│   │   ├── nuclei.py           \# NucleiConnector(BaseSubprocessConnector) — completo*

 *│   │   ├── testssl.py          \# TestsslConnector(BaseSubprocessConnector) — completo*

 *│   │   ├── sslyze.py           \# SslyzeConnector(BaseLibraryConnector) — completo*

 *│   │   └── types/              \# TypedDict shape condivise tra famiglie di connector*

 *│   │       └── tls\_findings.py \# TlsFinding (raw output di testssl \+ sslyze)*

 *│   │*

 *│   ├── external\_tests/         \# External Tool Tests — struttura parallela a tests/*

 *│   │   ├── base.py             \# ExternalToolTest ABC (NON eredita da BaseTest)*

 *│   │   ├── registry.py         \# ExternalTestRegistry — 4 fasi: scan, extract,*

 *│   │   │                       \# filter, inject (DA-2)*

 *│   │   ├── ext\_test\_0\_1\_shadow\_api\_nuclei.py  \# completo*

 *│   │   ├── ext\_test\_1\_5\_tls\_analysis.py       \# completo*

 *│   │   └── ext\_test\_\*.py                      \# futuri test con prefisso obbligatorio*

 *│   │*

 *│   ├── tests/                  \# Implementazioni dei test nativi, per dominio*

 *│   │   ├── base.py             \# BaseTest ABC — contratto comune a tutti i test nativi*

 *│   │   ├── registry.py         \# TestRegistry — discovery dinamico \+ filtro*

 *│   │   ├── strategy.py         \# TestStrategy Enum (BLACK\_BOX / GREY\_BOX / WHITE\_BOX)*

 *│   │   ├── domain\_0/           \# API Discovery & Inventory (3 impl / 3 piani, tutti P0)*

 *│   │   ├── domain\_1/           \# Identità e Autenticazione (4 impl / 6 piani, P0–P3)*

 *│   │   ├── domain\_2/           \# Autorizzazione e Accessi (1 impl / 5 piani, P1–P2)*

 *│   │   ├── domain\_3/           \# Integrità dei Dati (1 impl / 2 piani, P2–P3)*

 *│   │   ├── domain\_4/           \# Disponibilità e Resilienza (3 impl / 3 piani, P0–P1)*

 *│   │   ├── domain\_5/           \# Visibilità e Auditing (0 impl / 2 piani, P1–P2 — tutti Milestone 2)*

 *│   │   ├── domain\_6/           \# Configurazione e Hardening (2 impl / 4 piani, P1–P3)*

 *│   │   └── domain\_7/           \# Business Logic e Flussi (1 impl / 4 piani, P0–P2)*

 *│   │*

 *│   └── report/                 \# Generazione del report finale*

 *│       ├── builder.py          \# Aggregazione ResultSet → statistiche*

 *│       ├── renderer.py         \# Jinja2 → HTML*

 *│       └── templates/*

 *│*

 *└── tests\_e2e/                  \# Suite E2E contro target reale (non unit test)*

     *├── conftest.py*

     *└── test\_full\_pipeline.py*

***La regola di dipendenza è assoluta:** `core/` non importa mai da `tests/`, `connectors/`, o `external_tests/`. `connectors/` importa solo da `core/`. `tests/` e `external_tests/` importano da `core/` e `connectors/`. `engine.py` importa da tutti e li coordina. Le dipendenze fluiscono sempre verso il basso, mai verso l'alto o lateralmente tra domini diversi.*

## ***3\. Principi di Design Fondamentali***

*Prima di descrivere i componenti singolarmente, vale la pena enunciare i due principi architetturali da cui discendono quasi tutte le scelte di design. Tenerli in mente rende il resto del documento più facile da seguire.*

### ***3.1 Filosofia API-Agnostica***

*Il tool non contiene alcun riferimento a path, endpoint o strutture dati di un applicativo specifico. Tutta la conoscenza del target è derivata a runtime da due sole sorgenti: il `config.yaml` (credenziali, URL, parametri di esecuzione) e la specifica OpenAPI del target.*

*Questo agnosticismo non è solo un requisito: è la principale giustificazione accademica del lavoro. Un tool che funziona su un solo applicativo è uno script; un tool che funziona su qualsiasi API REST documentata è un contributo metodologico. Il costo accettato è che il target deve esporre una specifica OpenAPI valida — e che le Shadow API (dominio 0), per definizione fuori dalla spec, costituiscono l'eccezione intenzionale a questa regola.*

### ***3.2 Stato Scisso e Immutabilità***

*Il tool opera su due tipi di stato con caratteristiche opposte: ciò che si sa del target prima di iniziare (immutabile) e ciò che si scopre o si fa durante l'esecuzione (mutabile). Tenere questi due stati separati — in `TargetContext` e `TestContext` — non è un'eleganza stilistica: è la garanzia che un test non possa accidentalmente corrompere le informazioni di base lette da tutti gli altri. La separazione è enforced a livello di tipo: `TargetContext` usa `model_config = {"frozen": True}` di Pydantic.*

## ***4\. I Componenti e Come Si Parlano***

*Questa sezione è il cuore del documento. Ogni sottosezione descrive un componente, la sua responsabilità precisa, e — soprattutto — come riceve input e come passa output agli altri componenti.*

### ***4.1 Il Layer di Configurazione (`config/`)***

***Cosa fa:** è il cancello d'ingresso del tool. Legge il `config.yaml`, lo trasforma in un oggetto Python tipizzato, e blocca l'esecuzione immediatamente se qualcosa non va.*

***Come funziona internamente:** il processo di caricamento avviene in due passaggi sequenziali. Prima, `loader.py` esegue un **pre-processing** del YAML grezzo: sostituisce tutte le occorrenze di `${VAR_NAME}` con il valore della variabile d'ambiente corrispondente. Se una variabile non è impostata nell'ambiente, il loader solleva un errore esplicito prima ancora di chiamare Pydantic. Questo garantisce che le credenziali non vengano mai scritte in chiaro nel `config.yaml` (che potrebbe finire in version control), ma che l'assenza di una credenziale necessaria sia segnalata subito. Poi, il YAML risolto viene passato a `src/config/schema/tool_config.py` (e ai moduli di dominio aggregati da `TestsConfig`), che lo validano tramite schema **Pydantic v2**: URL malformati vengono rifiutati come `AnyHttpUrl` non validi, valori interi vengono verificati contro range accettabili, campi obbligatori mancanti producono messaggi di errore strutturati.*

***Output verso il resto del tool:** `loader.py` produce un oggetto `ToolConfig` (Pydantic, frozen) che viene passato a `engine.py`. Da lì, le parti rilevanti confluiscono nel `TargetContext`. Nessun altro modulo legge direttamente il file YAML: chiunque abbia bisogno di configurazione legge dal `ToolConfig` o dal `TargetContext`.*

### ***4.2 Il Discovery della Superficie d'Attacco (`discovery/`)***

***Cosa fa:** costruisce la mappa completa di ciò che il target espone — endpoint per endpoint — prima che un singolo test venga eseguito.*

***Come funziona internamente:** il modulo `openapi.py` esegue tre operazioni in sequenza. Prima il **fetch**: scarica la specifica OpenAPI dall'URL o dal path locale configurato. Poi la **dereferenziazione**: risolve tutti i `$ref` (inclusi quelli remoti) tramite la libreria `prance`, producendo una specifica completamente inline senza riferimenti circolari. Infine la **validazione** tramite `openapi-spec-validator`: se la spec è malformata, l'errore è segnalato qui, non silenziosamente durante i test. Il risultato pulito viene passato a `surface.py`, che costruisce un oggetto `AttackSurface`: una mappa strutturata degli endpoint, dove ogni entry classifica il path per metodo HTTP, requisiti di autenticazione dichiarati, e tag operazionali.*

***Output verso il resto del tool:** l'`AttackSurface` viene incapsulata nel `TargetContext` e lì rimane per tutta la durata dell'esecuzione. È **l'unica sorgente di verità** sulla topologia del target. Un test che consulta l'`AttackSurface` e non trova endpoint applicabili alle proprie condizioni ritorna `SKIP` — non `ERROR`. La distinzione è semantica: `SKIP` significa "non ho potuto verificarlo per una ragione prevista", `ERROR` significa "ho trovato un problema inatteso nell'eseguire la verifica".*

### ***4.3 I Due Contesti di Esecuzione: `TargetContext` e `TestContext`***

*Questi due oggetti sono gli assi portanti del coordinamento tra i test. Capire la loro differenza è il prerequisito per capire come un test usa i dati prodotti da un altro.*

***`TargetContext` — la conoscenza statica del target.** Viene creato una volta sola durante il bootstrap, incorpora il `ToolConfig` e l'`AttackSurface`, e da quel momento non cambia mai. Un test che lo legge ha la garanzia assoluta che i dati siano identici a quelli che aveva il test precedente. È la risposta alla domanda: "Cos'è il target?"*

***`TestContext` — lo stato dinamico dell'assessment.** Viene creato vuoto al bootstrap ed è mutabile. Accumula tutto ciò che si scopre o si fa durante l'esecuzione: i token JWT acquisiti dai test di autenticazione, le risorse create (utenti, ordini) che dovranno essere rimosse al teardown, e qualsiasi dato condiviso tra test con dipendenze dichiarate. È la risposta alla domanda: "Cosa ho scoperto o fatto sul target finora?"*

***Interfacce tipizzate: tre canali distinti.** La gestione dello stato mutabile nel `TestContext` avviene attraverso tre interfacce esplicite e tipizzate, non tramite dizionari liberi a chiavi arbitrarie:*

*1. **Token channel** — `set_token(role, token)`, `get_token(role) -> str | None`, `has_token(role)`, `stored_roles()`. Le chiavi sono i role constants (`ROLE_ADMIN`, `ROLE_USER_A`, `ROLE_USER_B`), non i test_id. Un `get_token` che ritorna `None` è una condizione gestita esplicitamente, non un `KeyError` silenzioso.*

*2. **Teardown channel** — `register_resource_for_teardown(method, path, headers)`, `drain_resources() -> list[tuple[str, str, dict]]`. LIFO ordering garantisce che risorse con dipendenze di creazione implicite siano eliminate nell'ordine corretto.*

*3. **Shared data channel** — `set_shared(key, value)`, `get_shared(key, default)`, `has_shared(key)`, `shared_keys()`. Canale general-purpose per dati calcolati da un test e consumati da test dipendenti (es. un endpoint scoperto da test 0.1 e riusato da test in Phase C). La convenzione di naming `"{test_id}.{data_name}"` rende esplicito il test produttore.*

***Modello di esecuzione strettamente sequenziale.** Il tool è progettato per operare in modo rigorosamente sequenziale. L'esecuzione parallela è intenzionalmente considerata fuori scope per la Versione 1.0. Questa scelta architetturale mira a garantire la coerenza assoluta dello stato — sia all'interno del `TestContext` che negli oggetti condivisi come l'`EvidenceStore` e il `ResultSet` — senza introdurre l'overhead di meccanismi di sincronizzazione (lock) o il rischio di potenziali race condition, prediligendo la predicibilità totale dell'assessment.*

### ***4.4 SecurityClient e EvidenceStore — La Coppia HTTP***

*Questi due componenti lavorano sempre insieme: il `SecurityClient` esegue le richieste, l'`EvidenceStore` registra quelle rilevanti. Nessun modulo di test nativo chiama `httpx` direttamente.*

***`SecurityClient` (`core/client.py`):** è un wrapper centralizzato attorno a `httpx`. Si occupa di applicare i timeout configurati su ogni request, di ritentare le richieste in caso di errori di rete transitori con backoff esponenziale fino a un massimo configurabile, e di non seguire redirect automaticamente (un redirect inatteso è un'informazione di sicurezza rilevante, non un inconveniente da nascondere). Il client non interpreta mai i codici di risposta HTTP né decide quali header di autenticazione aggiungere: questi sono compiti del singolo test, che compone la request a partire dai token presenti nel `TestContext` e confronta la response con il proprio oracle atteso.*

***`EvidenceStore` (`core/evidence.py`) — v2.0 streaming JSONL:** non mantiene evidenze in RAM. Per ogni test, al momento dell'invocazione `store.begin_test(test_id)`, apre un file JSONL dedicato in `outputs/evidence_tmp/<test_id_safe>.jsonl` e scrive ogni record immediatamente con flush. Al termine del test (`store.end_test()`), il file viene chiuso. In Phase 7, `store.merge_and_finalize()` legge tutti i file JSONL, li ordina cronologicamente, e produce il file `evidence.json` finale con struttura envelope compatibile v1.0. La directory `evidence_tmp/` viene poi rimossa.*

*La distinzione fondamentale rispetto a una registrazione indiscriminata è che l'`EvidenceStore` **non salva automaticamente** tutte le richieste HTTP. Salva esclusivamente:*

* ***Transazioni `FAIL`:** via `add_fail_evidence(record)` — ogni richiesta che produce un esito negativo rispetto all'oracle atteso.*  
* ***Transazioni `pinned`:** via `pin_evidence(record)` — il test marca esplicitamente una transazione come evidenza chiave anche se non ha prodotto un `FAIL` diretto.*

*Questa architettura — rispetto alla precedente v1.0 basata su `collections.deque(maxlen=100)` — elimina il problema delle evidenze silenziosamente espulse quando il buffer si riempiva. Il test 1.1 su un target con 100+ endpoint documentati produceva centinaia di record FAIL; con il bounded deque i primi venivano persi, generando `Finding.evidence_ref` che puntavano a record inesistenti in `evidence.json`. L'architettura JSONL è anche crash-resiliente: i file in `evidence_tmp/` sopravvivono a un crash tra Phase 5 e Phase 7.*

*Gli External Tool Tests persistono l'output dei loro binari tramite `store.pin_artifact(label, data)`. Prima del salvataggio, `pin_artifact()` applica la sanitizzazione ricorsiva: key-pattern matching (11 pattern via regex compilata), JWT-value detection, header-prefix matching. La sanitizzazione è responsabilità esclusiva dell'`EvidenceStore`, non del connector chiamante.*

### ***4.5 TestRegistry e DAGScheduler — Discovery e Ordinamento***

*Questi due componenti si occupano di rispondere a due domande distinte prima che l'esecuzione inizi: "Quali test esistono e possono girare?" e "In quale ordine devono girare?"*

***`TestRegistry` (`tests/registry.py`) — il discovery dinamico dei test nativi.** Non esiste un registro centrale statico dei test disponibili. La `TestRegistry` li scopre a runtime scansionando le directory `tests/domain_*/` con `pkgutil.walk_packages`, trovando tutti i file con il prefisso `test_`, e istanziando tutte le sottoclassi concrete di `BaseTest` tramite `inspect`. Questo significa che aggiungere un nuovo test richiede una sola operazione: creare il file nel dominio corretto con il nome giusto e implementare il contratto. Nessun altro file deve essere modificato.*

*La convenzione di nomenclatura dei file non è opzionale — è la condizione tecnica che abilita il discovery:*

*tests/domain\_X/test\_X\_Y\_description.py*

***`DAGScheduler` (`core/dag.py`) — l'ordinamento per dipendenze.** L'ordine di esecuzione dei test non è fisso né casuale: è determinato da un Directed Acyclic Graph (DAG) costruito a partire dall'attributo `depends_on` dichiarato da ogni test. Il DAG usa `graphlib.TopologicalSorter` della stdlib. Il `DAGScheduler` produce una lista di **batch**: ogni batch contiene i test che non hanno dipendenze reciproche tra loro. I batch sono sequenziali tra loro; all'interno di ciascun batch, i test vengono eseguiti in modo **rigorosamente sequenziale**. Se una dipendenza dichiarata non è presente nel set attivo, viene ignorata con un `WARNING`. Se viene rilevato un ciclo, viene sollevato `DAGCycleError` e l'avvio è bloccato.*

*Il DAG è agnostico rispetto alla natura del test: riceve la lista unificata di test nativi e test esterni dall'engine e li ordina identicamente. Il campo `depends_on` funziona tra test dello stesso tipo e tra i due tipi.*

### ***4.6 Il Layer Connector (`connectors/`)***

*Il layer connector è composto da tre classi in gerarchia, tutte definite in `connectors/base.py`. La motivazione della gerarchia è il principio che una sottoclasse non deve ereditare metodi che non può usare: prima del refactoring DA-1, un ipotetico `SslyzeConnector` avrebbe ereditato `_run_subprocess()`, `BINARY_NAME` e `SERVICE_ENV_VAR` — attributi e metodi del tutto inapplicabili a un tool Python-native. La gerarchia a tre livelli rimuove questo accoppiamento strutturale.*

***`BaseConnector` (tier 1 — ABC puro).** Dichiara un solo ClassVar (`TOOL_NAME: str`) e tre metodi astratti: `is_available() -> bool`, `get_version() -> str | None`, e `run(target_url, timeout_seconds) -> ConnectorResult`. Zero implementazione. È il solo punto del codebase che definisce il contratto universale dei connector — deve restare ignorante di qualsiasi meccanismo di discovery. Il parametro `timeout_seconds` in `run()` non ha valore di default intenzionalmente: ogni chiamante deve fornirlo esplicitamente, letto da `config.yaml`. Renderlo obbligatorio nella firma rende impossibile dimenticarlo. Le sottoclassi concrete possono aggiungere parametri keyword-only con default (LSP-safe); non usano `**kwargs`.*

***`BaseSubprocessConnector` (tier 2 — tool OS).** Eredita da `BaseConnector` e fornisce implementazioni concrete di `is_available()` e `get_version()` basate su subprocess, più i metodi protetti `_run_subprocess()`, `_parse_json_output()`, e `_parse_jsonl_output()`. La discovery avviene su due canali in cascata:*

1. *`shutil.which(BINARY_NAME)` — tool installato localmente nel PATH.*  
2. *`os.getenv(SERVICE_ENV_VAR)` — tool esposto come servizio HTTP in Docker Compose.*

*I connettori concreti (`TestsslConnector`, `FfufConnector`, `NucleiConnector`) ereditano da questo tier e devono solo dichiarare `BINARY_NAME`, `SERVICE_ENV_VAR` e implementare `run()`.*

***`BaseLibraryConnector` (tier 2 — tool Python-native).** Eredita da `BaseConnector` e usa `importlib.util.find_spec(LIBRARY_MODULE)` per la discovery — zero subprocess. Previsto per tool come sslyze, accessibili come librerie Python importabili. `get_version()` legge `module.__version__` con fallback a `importlib.metadata.version()`.*

***`ConnectorResult`.** Modello Pydantic frozen che trasporta l'output strutturato di una singola esecuzione: `tool_name`, `tool_version`, `raw_output: dict[str, Any]`, `exit_code`, `execution_time_ms`, `timed_out`. Il connector non valuta se qualcosa è un FAIL: restituisce dati grezzi, l'`ExternalToolTest` valuta contro il proprio oracle. Il campo `timed_out` permette al test chiamante di distinguere un timeout da un errore organico e produrre un messaggio di errore semanticamente corretto.*

***`ConnectorRawOutput` (TypedDict, in `connectors/base.py`).** Contratto generico per il dict `raw_output` di **qualsiasi** connector: chiavi obbligatorie `command`, `command_json`, `results: list[dict[str, Any]]`, `all_count`. Il tipo `Any` qui è giustificato architetturalmente: connector di famiglie diverse (TLS, nuclei, jwt_tool, …) producono dict con campi diversi, e questo è il contratto astratto che li accomuna.*

***`connectors/types/` — TypedDict condivisi tra famiglie di connector.** Quando due o più connector condividono la stessa shape concreta del finding (es. `testssl` e `sslyze` producono entrambi dict `{id, severity, finding, cve?, cwe?, ip?, port?}`), la shape vive in `connectors/types/<famiglia>_findings.py` come TypedDict (es. `TlsFinding`). Sia i connector produttori che i test esterni consumatori importano questo tipo per ottenere accesso strongly-typed senza Pydantic overhead. La distinzione netta vale: Pydantic per i domain object validati (`Finding`, `TestResult` in `core/models/`), TypedDict per le shape di wire-format raw da tool esterni (qui).*

### **4.6.1 `BaseGatewayAdapter` — Astrazione del Piano di Configurazione**

*Esiste un pattern di accesso all'infrastruttura gateway che non si mappa sui due tier dei connector descritti sopra: i test WHITE_BOX interrogano l'Admin API del gateway tramite chiamate HTTP standard per leggerne la configurazione interna. Il meccanismo di transport è `httpx`, ma la semantica è completamente diversa da `SecurityClient`: non si sta testando il target dall'esterno, si sta leggendo la configurazione dell'infrastruttura di controllo.*

*Questo pattern è gestito da `BaseGatewayAdapter`, ABC che vive in `src/core/gateway/` (non in `connectors/`). La scelta di collocarlo in `core/` riflette la sua natura: è un'astrazione di dominio condivisa tra test, non un wrapper verso tool esterni. Il `ClassVar adapter_name` (proprietà astratta) identifica il tipo di gateway (`"kong"`, `"traefik"`, ecc.). La sottoclasse concreta è selezionata dall'engine Phase 3 sulla base del campo `gateway_adapter` nel `config.yaml`.*

*core/*

*  gateway/*

*    base.py    \# BaseGatewayAdapter(ABC) \+ GatewayAdapterError*

*    kong.py    \# KongGatewayAdapter — Admin API Kong DB-less e DB-mode*

*L'interfaccia read-only esposta da `BaseGatewayAdapter`:*

*  check\_connectivity(self) \-\> bool*

*  get\_routes(self) \-\> list\[dict\[str, Any\]\]*

*  get\_plugins(self) \-\> list\[dict\[str, Any\]\]*

*  get\_services(self) \-\> list\[dict\[str, Any\]\]*

*  get\_upstreams(self) \-\> list\[dict\[str, Any\]\]*

*  get\_plugin\_by\_name(self, plugin\_name: str) \-\> dict\[str, Any\] | None*

*  get\_status(self) \-\> dict\[str, Any\]*

*L'engine Phase 3 chiama `check_connectivity()` per determinare se l'Admin API è raggiungibile. Se lo è, costruisce il `KongGatewayAdapter` e lo inietta in `TargetContext.gateway`. Se `admin_api_url` non è configurato, `target.gateway` resta `None`. I test WHITE_BOX usano `_requires_admin_api(target)` (guard clause in `BaseTest`) che ritorna `SKIP (Admin API not configured)` se `target.gateway is None`. I test accedono all'adapter tramite `target.gateway` — la stessa interfaccia indipendentemente dal tipo di gateway sottostante.*

*I test che usano `BaseGatewayAdapter` sono: **3.3** (HMAC config audit), **4.2** (timeout audit), **4.3** (circuit breaker audit). Gli errori di transport o HTTP inattesi dell'Admin API sollevano `GatewayAdapterError` (definita in `src/core/gateway/base.py` per principio di locality), catturata dai test e ritornata come `TestResult(ERROR)`.*

### ***4.7 ExternalToolTest e ExternalTestRegistry***

***`ExternalToolTest` (`external_tests/base.py`).** ABC parallelo a `BaseTest` — non ne eredita, perché i loro contratti di esecuzione differiscono strutturalmente: `BaseTest.execute()` riceve `(TargetContext, TestContext, SecurityClient, EvidenceStore)` e opera tramite httpx; `ExternalToolTest.execute()` riceve `(TargetContext, TestContext, EvidenceStore)` (nessun `SecurityClient`) e opera tramite connettori. L'engine li tratta identicamente perché entrambi producono `TestResult`.*

*Ogni sottoclasse concreta di `ExternalToolTest` deve dichiarare gli stessi ClassVar di `BaseTest` più `tool_name: ClassVar[str]`, che deve corrispondere alla chiave usata in `ExternalToolsConfig` per consentire il filtraggio per-tool nel registry.*

*Il lifecycle di `execute()` è orchestrato da `_run()`:*

1. *Controlla `_skip_reason_from_registry` — fast-path A (vedi DA-2).*  
2. *Ottiene il connector tramite `_get_connector()`.*  
3. *Chiama `_check_and_skip()` — fast-path B (vedi DA-2).*  
4. *Chiama `_invoke_connector()` — bridge verso il CLI specifico del tool.*  
5. *Chiama `store.pin_artifact()` — persiste il `raw_output` sanitizzato.*  
6. *Chiama `_evaluate()` — oracle evaluation, responsabilità della sottoclasse concreta.*

*Le sottoclassi concrete devono implementare tre metodi: `_build_connector()` (factory del connector, solo object construction, zero I/O), `_invoke_connector()` (bridge che legge parametri da `TargetContext` e chiama `connector.run()`), e `_evaluate()` (oracle evaluation che produce `TestResult`).*

***DA-2 — Connector Lifecycle e Dependency Injection.** Il registry, prima di restituire la lista dei test all'engine, inietta connettori condivisi nelle istanze di test. Due attributi di istanza gestiscono questo ciclo di vita:*

* *`_injected_connector: BaseConnector | None` — valorizzato dal registry quando il tool è disponibile. `_get_connector()` lo restituisce direttamente se non è `None`, bypassando `_build_connector()`. `_check_and_skip()` salta `is_available()` se l'attributo è valorizzato (fast-path B): il registry ha già confermato la disponibilità, una syscall al filesystem ripetuta per ogni test sarebbe spreco puro.*

* *`_skip_reason_from_registry: str | None` — valorizzato dal registry quando il tool è assente. `_run()` lo controlla come prima operazione e ritorna `SKIP` immediatamente (fast-path A): zero costruzione di connector, zero syscall.*

***`ExternalTestRegistry` (`external_tests/registry.py`).** Scansiona i moduli `ext_test_*.py` con la stessa logica di `TestRegistry` (pkgutil.walk\_packages, inspect, filtro per priorità e tool abilitato). Produce test istanziati pronti per il DAG. Aggiunge una **Phase R4** (`_inject_connectors`) eseguita dopo il filtering:*

1. *Raggruppa i test sopravvissuti per `tool_name`.*  
2. *Per ciascun gruppo, chiama `_build_connector()` sul primo test (solo object construction).*  
3. *Chiama `connector.is_available()` **una sola volta** per l'intero gruppo. 4a. Se disponibile: inietta la stessa istanza connector in tutti i test del gruppo. Un solo log `INFO`. 4b. Se non disponibile: scrive `_skip_reason_from_registry` su tutti i test del gruppo. Un solo log `WARNING`.*

*Il risultato concreto: con N test che usano lo stesso tool, il log produce esattamente un entry per tool anziché N entry identiche. In un assessment con 5 test `nuclei` e il binario assente, il log mostra un solo `WARNING "nuclei not found — 5 tests will SKIP"` invece di 5 log separati.*

### ***4.8 BaseTest — Il Contratto di Ogni Test Nativo***

*Ogni test nativo è una classe Python che eredita da `BaseTest` (Abstract Base Class definita in `tests/base.py`). Il contratto ha due parti: gli attributi di classe statici, ispezionati prima dell'esecuzione, e il metodo `execute`, che contiene la logica del test.*

***Attributi di classe obbligatori:***

*class Test\_1\_2\_JWTSignatureValidation(BaseTest):*

    *\# \--- Usati dall'orchestratore per decisioni di esecuzione \---*

    *test\_id: str           \= "1.2"*

    *priority: int          \= 0                           \# 0–3, corrispondente a P0–P3*

    *strategy: TestStrategy \= TestStrategy.BLACK\_BOX      \# BLACK\_BOX / GREY\_BOX / WHITE\_BOX*

    *depends\_on: list\[str\]  \= \[\]                          \# test\_id prerequisiti*

    *\# \--- Usati dal report per classificazione e referenziamento \---*

    *test\_name: str         \= "Le Credenziali Sono Crittograficamente Valide"*

    *domain: int            \= 1*

    *tags: list\[str\]        \= \["authentication", "OWASP-API2"\]*

    *cwe\_id: str            \= "CWE-287"*

***Il metodo `execute`:** riceve i quattro oggetti di infrastruttura come parametri e deve **sempre** ritornare un `TestResult`. Non può propagare eccezioni verso l'engine. Qualsiasi eccezione non gestita deve essere catturata internamente e ritornata come `TestResult(status=ERROR, message=str(e))`.*

*def execute(*

    *self,*

    *target: TargetContext,*

    *context: TestContext,*

    *client: SecurityClient,*

    *store: EvidenceStore,*

*) \-\> TestResult: ...*

***I quattro stati di un `TestResult`:***

| *Status* | *Significato* |
| ----- | ----- |
| *`PASS`* | *Il controllo è stato eseguito e la garanzia di sicurezza è soddisfatta.* |
| *`FAIL`* | *Il controllo è stato eseguito e la garanzia **non** è soddisfatta. Deve avere almeno un `Finding` allegato.* |
| *`SKIP`* | *Il controllo non è stato eseguito per un motivo esplicito e documentato. Richiede `skip_reason` non-None.* |
| *`ERROR`* | *Il test ha incontrato un'eccezione inattesa. Il risultato è incerto. Richiede investigazione manuale.* |

***Relazione tra `TestResult` e `Finding`.** Un `TestResult` non porta un giudizio di gravità: porta una lista di oggetti `Finding`, ciascuno dei quali è un'unità di evidenza tecnica oggettiva. Un singolo test può produrre più `Finding` distinti su endpoint diversi: ciascuno è un'evidenza indipendente che contribuisce al conteggio dei FAIL nel report finale.*

*class Finding(BaseModel):*

    *title: str                  \# Short description of the violated guarantee*

    *detail: str                 \# Technical description of the observed evidence*

    *references: list\[str\]       \# Standard references (CWE, OWASP, RFC)*

    *evidence\_ref: str | None    \# Reference to the transaction ID in EvidenceStore*

*class TestResult(BaseModel):*

    *test\_id: str*

    *status: TestStatus          \# PASS | FAIL | SKIP | ERROR*

    *message: str*

    *skip\_reason: str | None     \# Obbligatorio per status=SKIP (model\_validator)*

    *findings: list\[Finding\] \= \[\]*

*Un `TestResult(status=FAIL)` deve contenere almeno un `Finding`. Un `TestResult(status=SKIP)` deve avere `skip_reason` valorizzato — il `model_validator` di Pydantic lo impone e solleva `ValidationError` se il campo è `None`.*

***Mapping Strategia–Priorità:***

| *Strategia* | *Priorità Corrispondenti* | *Prerequisiti Tipici* |
| ----- | ----- | ----- |
| *`BLACK_BOX`* | *P0* | *Nessuno — zero credenziali richieste* |
| *`GREY_BOX`* | *P1, P2* | *Token utente e/o admin presenti nel `TestContext`* |
| *`WHITE_BOX`* | *P3* | *Admin API raggiungibile (`TargetContext.admin_api_available == True`)* |

### ***4.9 Engine — L'Orchestratore***

*`engine.py` è l'unico modulo che conosce e coordina tutti gli altri. La sua responsabilità è **puramente orchestrativa**: non contiene logica di test, non interpreta risultati, non decide cosa testare. Segue una sequenza fissa di chiamate, passando gli oggetti giusti ai moduli giusti nell'ordine corretto.*

***Fusione delle due popolazioni di test.** Durante la Fase 4, l'engine interroga sia `TestRegistry` (test nativi) che `ExternalTestRegistry` (test esterni) e fonde le due liste prima di passarle al `DAGScheduler`. Il DAG non sa né gli importa se un test è nativo o esterno: vede solo oggetti con attributi `test_id` e `depends_on`. Le dipendenze dichiarate in `depends_on` funzionano sia tra test dello stesso tipo che tra i due tipi.*

***Dispatch differenziato in Fase 5\.** L'engine distingue il tipo di test al momento dell'invocazione:*

* *Test nativi (`BaseTest`): `test.execute(target, context, client, store)`*  
* *Test esterni (`ExternalToolTest`): `test.execute(target, context, store)` (senza `client`)*

*Questa distinzione è localizzata in engine.py con un `isinstance` check — l'unico punto del codebase dove la differenza tra le due gerarchie è visibile.*

***Condizione di fail-fast:** se `config.fail_fast = true`, l'esecuzione viene interrotta immediatamente se un test di priorità P0 restituisce status `FAIL` **oppure** status `ERROR`. Entrambi gli stati su un controllo P0 sono considerati bloccanti. Questo si applica ai test nativi e agli external test indistintamente.*

### ***4.10 Report Layer***

*Il layer di reporting (`report/`) opera interamente dopo che tutti i test sono stati eseguiti e il teardown è completato. Riceve il `ResultSet` e l'`EvidenceStore` dall'engine.*

*`builder.py` aggrega le statistiche iterando su tutti i `TestResult`. Prima del rendering, partiziona i risultati per `domain` e per `source` (`"native"` / `"external"`), producendo una struttura `DomainSummary` per ogni dominio che il template Jinja2 consuma direttamente. Questo **Domain-Centric Split** rende immediatamente evidente al lettore del report cosa è prodotto dal motore Python nativo e cosa è delegato a tool specializzati, senza richiedere sezioni fisicamente separate.*

*Il campo `source: Literal["native", "external"]` nel `TestResult` è la primitiva su cui si basa l'intero split: valorizzato a `"native"` da `TestRegistry` e a `"external"` da `ExternalTestRegistry`, non viene mai modificato dall'engine.*

*`renderer.py` usa Jinja2 per produrre il report HTML. L'`EvidenceStore` viene serializzato separatamente su `evidence.json`. I due output — `assessment_report.html` e `evidence.json` — sono i deliverable finali dell'assessment.*

## ***5\. La Pipeline di Esecuzione — Flusso Completo***

*Le fasi 1, 2 e 4 sono **bloccanti**: un errore interrompe l'avvio prima che un singolo test venga eseguito. Le fasi 5, 6 e 7 non bloccano mai: i fallimenti vengono registrati e l'esecuzione prosegue fino al termine (salvo attivazione del fail-fast).*

*INPUT: config.yaml*

 *│*

 *▼*

 *┌─────────────────────────────────────────────────────────┐*

 *│ FASE 1 — Inizializzazione                               │*

 *│                                                         │*

 *│ config/loader.py legge config.yaml                      │*

 *│ → Pre-processing: interpola ${VAR} da env               │*

 *│ → Valida con schema Pydantic v2 → ToolConfig            │*

 *│ → ConfigurationError se invalido \[BLOCCA\]               │*

 *└───────────────────────────┬─────────────────────────────┘*

                             *│ ToolConfig*

                             *▼*

 *┌─────────────────────────────────────────────────────────┐*

 *│ FASE 2 — OpenAPI Discovery                              │*

 *│                                                         │*

 *│ discovery/openapi.py fetcha la spec dal target          │*

 *│ → Valida (openapi-spec-validator)                       │*

 *│ → Dereferenzia tutti i $ref (prance)                    │*

 *│ → discovery/surface.py costruisce AttackSurface         │*

 *│ → OpenAPILoadError se irraggiungibile/invalida \[BLOCCA\] │*

 *└───────────────────────────┬─────────────────────────────┘*

                             *│ AttackSurface*

                             *▼*

 *┌─────────────────────────────────────────────────────────┐*

 *│ FASE 3 — Costruzione dei Contesti                       │*

 *│                                                         │*

 *│ TargetContext (frozen) ← ToolConfig \+ Surface           │*

 *│ TestContext (mutable, vuoto) ← creato qui               │*

 *│ EvidenceStore (streaming JSONL v2.0) ← creato qui       │*

 *└───────────────────────────┬─────────────────────────────┘*

                             *│ I 3 oggetti pronti (TargetContext, TestContext, EvidenceStore)*

                             *▼*

 *┌─────────────────────────────────────────────────────────┐*

 *│ FASE 4 — Test Discovery e Scheduling                    │*

 *│                                                         │*

 *│ TestRegistry scansiona tests/domain\_\*/test\_\*.py         │*

 *│ → Istanzia BaseTest concrete → filtra per priority      │*

 *│ → filtra per strategy                                   │*

 *│                                                         │*

 *│ ExternalTestRegistry scansiona external\_tests/          │*

 *│   ext\_test\_\*.py                                         │*

 *│ → Istanzia ExternalToolTest concrete                    │*

 *│ → filtra per priority \+ per-tool enabled                │*

 *│ → Phase R4: \_inject\_connectors()                        │*

 *│     · raggruppa per tool\_name                           │*

 *│     · is\_available() UNA SOLA VOLTA per gruppo          │*

 *│     · disponibile → inietta connector condiviso         │*

 *│     · non disponibile → setta \_skip\_reason\_from\_registry│*

 *│     · UN SOLO log WARNING per tool assente              │*

 *│                                                         │*

 *│ merged\_tests \= native\_tests \+ external\_tests            │*

 *│ DAGScheduler legge depends\_on da ogni test              │*

 *│ → Costruisce DAG, verifica assenza cicli                │*

 *│ → Produce lista ordinata di batch                       │*

 *│ → DAGCycleError se ciclo rilevato \[BLOCCA\]              │*

 *└───────────────────────────┬─────────────────────────────┘*

                             *│ Lista di batch ordinati*

                             *▼*

 *┌─────────────────────────────────────────────────────────┐*

 *│ FASE 5 — Esecuzione                                     │*

 *│                                                         │*

 *│ Per ogni batch (sequenziali):                           │*

 *│   Per ogni test nel batch (sequenziale):                │*

 *│     Se BaseTest:                                        │*

 *│       test.execute(target, context, client, store)      │*

 *│     Se ExternalToolTest:                                │*

 *│       test.execute(target, context, store)              │*

 *│     → Ritorna SEMPRE un TestResult                      │*

 *│     → TestResult aggiunto al ResultSet                  │*

 *│     → Se fail\_fast=true e test è P0                     │*

 *│       e status è FAIL oppure ERROR: interrompi          │*

 *└───────────────────────────┬─────────────────────────────┘*

                             *│ ResultSet completo*

                             *▼*

 *┌─────────────────────────────────────────────────────────┐*

 *│ FASE 6 — Teardown (Best-Effort)                         │*

 *│                                                         │*

 *│ TestContext.drain\_resources() → lista risorse create    │*

* │ Per ogni risorsa (ordine inverso di creazione):         │*

 *│   tenta DELETE via SecurityClient                       │*

 *│   Fallimento → WARNING nel log, prosegui               │*

 *└───────────────────────────┬─────────────────────────────┘*

                             *│*

                             *▼*

 *┌─────────────────────────────────────────────────────────┐*

 *│ FASE 7 — Report Generation                              │*

 *│                                                         │*

 *│ report/builder.py aggrega ResultSet → statistiche       │*

 *│ → Partiziona per domain × source (native / external)    │*

 *│ → Produce struttura DomainSummary per ogni dominio      │*

 *│ EvidenceStore serializzato → evidence.json              │*

 *│ report/renderer.py: Jinja2 → HTML                       │*

 *└───────────────────────────┬─────────────────────────────┘*

                             *│*

                             *▼*

 *OUTPUT: evidence.json  report.html*

 *Exit code del processo (0 / 1 / 2 / 10\)*

## ***6\. Comportamenti Speciali e Casi Limite***

### ***6.1 Graceful Degradation per Ambienti DB-less***

*I test `WHITE_BOX` (P3) richiedono accesso all'Admin API del gateway per ispezionarne la configurazione interna. Kong in modalità DB-less — il caso comune in questa tesi — spesso non espone questa API.*

*Se `target.admin_api_url` non è configurato nel `config.yaml`, tutti i test `WHITE_BOX` transitano automaticamente a `SKIP (Admin API not configured)` senza alcun tentativo di connessione. Nel report, questi `SKIP` sono distinguibili dai `SKIP` per prerequisiti funzionali mancanti. La scelta di usare `SKIP` invece di `FAIL` è deliberata: `FAIL` implica che la verifica sia avvenuta con esito negativo; `SKIP` comunica onestamente che la verifica non è stata possibile.*

*Gli External Tool Tests degradano con lo stesso meccanismo: se il master switch `external_tools.enabled = false` è impostato nel `config.yaml`, `ExternalTestRegistry.discover()` ritorna immediatamente una lista vuota senza scansionare il filesystem. Se il master switch è on ma un singolo tool non è installato, la Phase R4 marca i test corrispondenti con `_skip_reason_from_registry` e produce un singolo `WARNING` per tool assente.*

### ***6.2 Teardown Best-Effort***

*I test che creano risorse persistenti (es. `POST /users`) devono registrare l'endpoint di cancellazione nel `TestContext` nel momento stesso in cui le creano. Il teardown avviene nell'ordine inverso di registrazione (LIFO) e continua anche in caso di fallimento di singole cancellazioni. Un fallimento di teardown non invalida i risultati dell'assessment: viene loggato come `WARNING` con tutti i dettagli per una pulizia manuale.*

### ***6.3 Rate Limit Discovery Empirica (Test 4.1)***

*Il test 4.1 non conosce a priori la soglia di rate limiting configurata nel gateway. La verifica è quindi **empirica**: il test invia richieste in loop verso un endpoint protetto, a intervalli regolari, fino a ricevere un `HTTP 429 Too Many Requests` o fino al raggiungimento di `max_requests`. L'**oracle** è binario: se arriva un `429` entro `max_requests` → `PASS`; se non arriva nessun `429` → `FAIL`. I parametri `max_requests` e `request_interval_ms` sono configurabili nel `config.yaml`, con default conservativi di 150 richieste a 50ms di intervallo. Le richieste di sondaggio normale non vengono scritte nell'`EvidenceStore`: solo la transazione che produce il `429` — o l'assenza di quest'ultimo al termine del loop — viene registrata come evidenza.*

## ***7\. Exit Code e Integrazione CI/CD***

*Il processo termina con un exit code che riflette lo **stato aggregato del ResultSet**, calcolato in `report/builder.py`.*

| *Exit Code* | *Condizione* |
| ----- | ----- |
| *`0`* | *Tutti i test `PASS` o `SKIP`. Nessuna violazione dimostrata. Assessment superato.* |
| *`1`* | *Almeno un test `FAIL`. Almeno una garanzia violata con evidenza tecnica dimostrabile.* |
| *`2`* | *Almeno un test `ERROR` (e nessun `FAIL`). Almeno una verifica non completata per causa imprevista.* |
| *`10`* | *Errore infrastrutturale bloccante (config invalida, spec irraggiungibile, ciclo nel DAG). Assessment non avviato.* |

*La priorità degli exit code è ordinata: `FAIL` prevale su `ERROR`. Un assessment con sia `FAIL` che `ERROR` restituisce `1`.*

***Fail-fast e priorità P0.** Quando `config.fail_fast = true`, l'esecuzione viene interrotta se un test di priorità P0 — nativo o esterno — restituisce status `FAIL` oppure `ERROR`.*

## ***8\. Gerarchia delle Eccezioni***

*Tutte le eccezioni custom del tool seguono una gerarchia che permette catch selettivi a diversi livelli della pipeline. Non si solleva mai `Exception` o `RuntimeError` generici nel codice del tool.*

*ToolBaseError                         \# radice — src/core/exceptions.py*

 *├── ConfigurationError    → Fase 1: config invalido o var env mancante \[BLOCCA AVVIO\]*

 *├── OpenAPILoadError      → Fase 2: spec irraggiungibile o malformata \[BLOCCA AVVIO\]*

 *├── DAGCycleError         → Fase 4: dipendenza circolare tra test \[BLOCCA AVVIO\]*

 *├── SecurityClientError   → Fase 5, test nativi: errore HTTP non recuperabile*

 *│                           \[→ TestResult(ERROR), catturata in execute()\]*

 *├── AuthenticationSetupError → helper autenticazione: credenziali invalide*

 *│                              (login endpoint ritorna 4xx). Campi: role, status\_code.*

 *│                              \[→ TestResult(ERROR), catturata in execute()\]*

 *├── ExternalToolError     → Fase 5, test esterni: binario presente ma esecuzione*

 *│                           fallita (exit code non-zero, JSON non parsabile,*

 *│                           timeout subprocess). Campi: tool\_name, exit\_code, timed\_out.*

 *│                           \[→ TestResult(ERROR), catturata in execute()\]*

 *└── TeardownError         → Fase 6: fallimento cancellazione risorsa*

                             *\[WARNING nel log, non propagata\]*

*`GatewayAdapterError` (in `src/core/gateway/base.py`, non nel file centrale) → sollevata da `BaseGatewayAdapter` su transport failure o HTTP status inatteso dall'Admin API. Estende `ToolBaseError`. Campi: `path`, `status_code`. I test WHITE_BOX la catturano e ritornano `TestResult(ERROR)`.*

*Le prime tre sono **fatali**: si verificano prima che qualsiasi test giri. Le restanti sono **recuperate a livello di singolo test**: l'engine non le vede mai. `TeardownError` è **intenzionalmente non propagata**: un fallimento di cleanup non invalida la correttezza dell'assessment.*

*Nota: il tool non implementa `ExternalToolNotFoundError`. Un tool esterno non disponibile non produce un'eccezione — produce un `TestResult(SKIP)` tramite il meccanismo `_skip_reason_from_registry` (Phase R4) o tramite `_check_and_skip()`. Questa scelta è intenzionale: un tool mancante è una condizione operativa attesa, non un errore inaspettato.*

*Fine documento — `4-Implementazione.md` v4.2 Changelog v4.2: corretta struttura §2 (models/ package, gateway/ in core/, connectors implementati rimosso [futuro], ext_test files implementati); aggiornata §4.3 (aggiunto canale shared_data in TestContext); aggiornata §4.4 (EvidenceStore da deque v1.0 a streaming JSONL v2.0); rinominata §4.6.1 (BaseGatewayInspector → BaseGatewayAdapter, path connectors/gateway → core/gateway, interfaccia aggiornata); aggiornata §8 (aggiunte AuthenticationSetupError e GatewayAdapterError alla gerarchia).*


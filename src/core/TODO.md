## `src/core/exceptions.py`

Prima di mostrare il codice, descrivo le scelte progettuali rilevanti per la tesi.

**Ratio architetturale della gerarchia.** Tutte le eccezioni ereditano da un'unica radice `ToolBaseError`. Questo permette a un ipotetico chiamante esterno (ad esempio uno script CI/CD che wrappa il tool) di catturare `except ToolBaseError` per intercettare qualsiasi condizione anomala del tool con un singolo handler, oppure di essere selettivo e catturare solo `ConfigurationError` per distinguere errori di setup da errori di esecuzione. Senza una radice comune, il chiamante dovrebbe elencare ogni tipo concreto, violando il principio Open/Closed.

**Perche' i campi strutturati sulle eccezioni concrete.** Ogni eccezione porta campi tipizzati oltre al messaggio testuale (es. `variable_name` su `ConfigurationError`, `cycle` su `DAGCycleError`). Questo non e' un'eleganza stilistica: e' la differenza tra un log che dice `"Configuration error"` e uno che dice `"Missing environment variable: FORGEJO_ADMIN_TOKEN"`. `structlog` puo' serializzare questi campi come coppie chiave-valore nel JSON di output, rendendo il log machine-readable e direttamente interrogabile in un aggregatore.

**Perche' `TeardownError` non e' propagata.** Come descritto in `Implementazione.md` sezione 8, un fallimento di cleanup non invalida la correttezza dei risultati gia' raccolti. L'eccezione esiste per essere catturata nell'engine, loggata come `WARNING` con tutti i dettagli (metodo, path, status code ricevuto), e poi scartata. Averla come tipo concreto — invece di loggare direttamente una stringa — permette all'engine di distinguere programmaticamente un fallimento di teardown da qualsiasi altra eccezione inattesa.

---

### Cosa aspettarsi dal modulo in esecuzione

Per verifica immediata sulla VM, dopo aver attivato il venv:

```python
from src.core.exceptions import (
    ToolBaseError, ConfigurationError, OpenAPILoadError,
    DAGCycleError, SecurityClientError, TeardownError,
)

# Verifica che la gerarchia sia corretta
assert issubclass(ConfigurationError, ToolBaseError)
assert issubclass(TeardownError, ToolBaseError)

# Verifica che i campi strutturati siano accessibili
exc = ConfigurationError(
    "Missing required environment variable",
    variable_name="FORGEJO_ADMIN_TOKEN",
    config_path="target.admin_token",
)
assert exc.variable_name == "FORGEJO_ADMIN_TOKEN"
assert "Missing" in str(exc)
```

Nessuna dipendenza esterna: il modulo importa solo `from __future__ import annotations` per il forward reference nelle type hints (`list[str] | None` senza quotes). E' il modulo piu' puro dell'intero progetto e non avra' mai bisogno di essere modificato salvo aggiunta di nuove fasi alla pipeline.

Il prossimo step bottom-up e' `src/core/models.py` — i modelli Pydantic v2 condivisi (`Severity`, `TestStatus`, `Finding`, `TestResult`). Attendo il tuo via libera.

---

## Punto 2 — `src/core/models.py`

**Ratio architetturale preliminare.**

`models.py` è il vocabolario condiviso dell'intero tool: ogni modulo lo importa, nessun modulo lo modifica. Per questo motivo ha zero dipendenze interne — importa solo da `pydantic` e dalla stdlib — e deve essere il modulo più stabile dell'intero progetto. Qualsiasi modifica ai modelli qui si propaga a cascata su `BaseTest`, `EvidenceStore`, `builder.py` e il template HTML.

Tre scelte di design meritano spiegazione esplicita per la tesi:

**`Finding.references` come lista di stringhe.** Invece di campi separati `cwe_id`, `owasp_id`, `rfc_id`, una lista unica di reference string è più flessibile: un finding può avere zero, uno o più riferimenti standard (`["CWE-287", "OWASP-API2:2023", "RFC-8725"]`). Il formato stringa è sufficientemente strutturato per essere parsato da un analista o da un sistema terzo, senza richiedere un modello annidato che complicherebbe la serializzazione.

**`EvidenceRecord` come modello separato.** La coppia request/response HTTP che costituisce un'evidenza non è un campo di `Finding`: è un'entità indipendente referenziata tramite `evidence_ref`. Questa separazione replica esattamente l'architettura `EvidenceStore` descritta in `Implementazione.md`: i finding esistono nel `ResultSet`, le evidenze vivono nello store separato, il collegamento avviene tramite ID stringa. Questo permette al report di includere i finding senza duplicare i raw HTTP data nel `ResultSet`.

---

## Cosa aspettarsi dal modulo in esecuzione

Verifica rapida sulla VM dopo aver attivato il venv:

```python
from src.core.models import (
    TestStatus, TestStrategy, Finding, TestResult, ResultSet, EvidenceRecord
)
from datetime import datetime, timezone

# Finding valido
f = Finding(
    title="Accept unsigned JWT tokens (alg:none attack)",
    detail="POST /api/v1/users/tokens returned 200 with alg=none JWT. Expected 401.",
    references=["CWE-287", "OWASP-API2:2023", "RFC-8725"],
    evidence_ref="1.2_001",
)

# TestResult FAIL valido
r = TestResult(test_id="1.2", status=TestStatus.FAIL, message="JWT signature bypass", findings=[f])

# TestResult FAIL senza Finding: deve sollevare ValidationError
from pydantic import ValidationError
try:
    TestResult(test_id="1.2", status=TestStatus.FAIL, message="broken", findings=[])
except ValidationError as exc:
    print(exc)  # atteso: "A TestResult with status=FAIL must contain at least one Finding"

# ResultSet e exit code
rs = ResultSet()
rs.add_result(r)
assert rs.compute_exit_code() == 1
assert rs.fail_count == 1
assert rs.total_finding_count == 1
```

Il prossimo step bottom-up è `src/core/evidence.py` — l'`EvidenceStore` con il buffer FIFO `deque(maxlen=100)` e la logica di salvataggio selettivo. Attendo il tuo via libera.

---

## `src/core/evidence.py`

**Ratio architetturale preliminare.**

`EvidenceStore` è concettualmente un buffer di scrittura selettiva, non un log generale. La distinzione è fondamentale per la tesi: un tool che registra ogni transazione HTTP produce un file di evidenze rumoroso e potenzialmente enorme; uno che registra solo le transazioni significative produce un documento dimostrativo che un analista o una commissione accademica può leggere direttamente.

Tre meccanismi cooperano per realizzare questa selettività:

**Il `deque(maxlen=100)` come struttura dati.** Quando il buffer è pieno, Python espelle automaticamente l'elemento più vecchio (`popleft()` implicito) prima di inserire il nuovo. Questo risolve il problema OOM senza richiedere garbage collection esplicita. Il limite di 100 è giustificato quantitativamente in `Implementazione.md` sezione 4.4: worst-case 26 test, 50% di fail, 2-3 evidenze ciascuno producono circa 40-50 record. Il margine del 100% garantisce che nessuna evidenza rilevante venga espulsa dal rumore.

**Il flag `is_pinned` su `EvidenceRecord`.** Un test può marcare una transazione come chiave anche se non ha prodotto un `FAIL` diretto — ad esempio la risposta di setup che stabilisce il contesto di un attacco successivo. Il pinning è un contratto esplicito tra il test e lo store: il test sa cosa è significativo, lo store preserva quella scelta.

**La serializzazione `to_json_file`.** Il metodo produce `evidence.json` come array JSON di oggetti, ordinati per timestamp UTC. Il formato è deliberatamente human-readable e machine-parseable: un analista può aprirlo in un editor, un sistema SIEM può ingestirlo senza preprocessing.

---

## Cosa aspettarsi dal modulo in esecuzione

Verifica rapida sulla VM dopo aver attivato il venv:

```python
from src.core.evidence import EvidenceStore, EVIDENCE_BUFFER_MAX_SIZE
from src.core.models import EvidenceRecord
from datetime import datetime, timezone
from pathlib import Path

store = EvidenceStore()
assert store.is_empty
assert store.record_count == 0

# Costruzione di un record minimale
record = EvidenceRecord(
    record_id="1.2_001",
    timestamp_utc=datetime.now(timezone.utc),
    request_method="post",          # il validator lo normalizza a "POST"
    request_url="http://localhost:8000/api/v1/users/tokens",
    request_headers={"Authorization": "Bearer abc123"},  # sara' REDACTED
    request_body='{"alg": "none"}',
    response_status_code=200,
    response_headers={"content-type": "application/json"},
    response_body='{"token": "xyz"}',
)

# Verifica redaction automatica dell'header Authorization
assert record.request_headers["authorization"] == "[REDACTED]"
# Verifica normalizzazione metodo
assert record.request_method == "POST"

# Scrittura nello store
store.add_fail_evidence(record)
assert store.record_count == 1

# Recupero per ID
retrieved = store.get_by_id("1.2_001")
assert retrieved is not None
assert retrieved.record_id == "1.2_001"

# Serializzazione su file
written = store.to_json_file(Path("/tmp/test_evidence.json"))
assert written == 1

# Verifica pinning: il record originale non viene mutato (EvidenceRecord e' frozen)
store.pin_evidence(record)
assert store.record_count == 2
pinned = store.get_by_id("1.2_001")
# Il record originale NON e' pinned; quello aggiunto da pin_evidence SI
records = list(store.iter_records())
assert records[1].is_pinned is True
assert records[0].is_pinned is False
```

**Un dettaglio degno di nota per la tesi:** il test di pinning qui sopra mostra un comportamento sottile ma importante. `pin_evidence` non modifica il record originale (impossibile, è frozen), ma aggiunge una nuova istanza con `is_pinned=True`. Questo significa che il buffer può contenere due record con lo stesso `record_id` se un test chiama sia `add_fail_evidence` che `pin_evidence` sullo stesso record. La convenzione da rispettare nei test è che si usa *o* l'uno *o* l'altro, mai entrambi sullo stesso record. Questa è una pre-condizione implicita che documenterò esplicitamente nel contratto di `BaseTest`.

Il prossimo step bottom-up è `src/core/context.py` — i due oggetti di coordinamento `TargetContext` (frozen) e `TestContext` (mutable), con le interfacce tipizzate per token e teardown. Attendo il tuo via libera.

---

## `src/core/context.py`

**Ratio architetturale preliminare.**

Prima di scrivere il codice, c'è una questione di dipendenze da rendere esplicita per la tesi, perché impatta le scelte di typing.

`TargetContext` deve contenere l'`AttackSurface` costruita da `discovery/surface.py`. Ma `core/` non può importare da `discovery/` — violerebbe la regola di monodirezionalità. La soluzione architetturale corretta è che `AttackSurface` venga definita in `core/models.py` (è infrastruttura condivisa, non logica di discovery), e `discovery/surface.py` la importi da lì per popolarla. Questo è esattamente il pattern già usato per `EvidenceRecord`: il modello vive in `core/`, il componente che lo popola lo importa da `core/`.

Poiché `models.py` è già scritto e approvato, uso `Any` per il campo `attack_surface` in questo modulo, con documentazione esplicita che indica il tipo atteso. Quando implementeremo `discovery/surface.py`, aggiungeremo `AttackSurface` a `core/models.py` e sostituiremo `Any` con il tipo corretto — sarà una modifica di una sola riga.

**Perché `TestContext` usa `PrivateAttr` invece di attributi pubblici Pydantic.** Lo stato mutabile di `TestContext` (`_tokens`, `_resources`) non deve essere accessibile direttamente dall'esterno: i test interagiscono solo tramite le interfacce tipizzate (`set_token`, `get_token`, `register_resource_for_teardown`, `drain_resources`). `PrivateAttr` in Pydantic v2 esclude il campo dalla serializzazione, dalla validazione e dall'interfaccia pubblica del modello, realizzando l'incapsulamento senza abbandonare Pydantic.

**Perché `drain_resources` è LIFO.** Le risorse vengono cancellate nell'ordine inverso di creazione perché le dipendenze tra risorse sono spesso ordinate: se il test 2.2 crea prima un utente e poi un repository di quell'utente, il repository deve essere cancellato prima dell'utente. Un `list` usato come stack (`pop()` senza indice) realizza LIFO in O(1).

---

## Cosa aspettarsi dal modulo in esecuzione

```python
from src.core.context import (
    TargetContext, TestContext,
    ROLE_ADMIN, ROLE_USER_A, ROLE_USER_B,
)

# --- TargetContext ---
target = TargetContext(
    base_url="http://localhost:8000",
    openapi_spec_url="http://localhost:8000/api/swagger",
    admin_api_url="http://localhost:8001",
)

# frozen: qualsiasi tentativo di mutazione solleva ValidationError
from pydantic import ValidationError
try:
    target.base_url = "http://evil.com"
except ValidationError as exc:
    print(exc)  # atteso: "Instance is frozen"

# computed_field funziona correttamente
assert target.admin_api_available is True

target_no_admin = TargetContext(
    base_url="http://localhost:8000",
    openapi_spec_url="http://localhost:8000/api/swagger",
)
assert target_no_admin.admin_api_available is False
assert target_no_admin.admin_endpoint_base_url() is None

# endpoint_base_url() restituisce stringa senza trailing slash
assert target.endpoint_base_url() == "http://localhost:8000"

# --- TestContext ---
ctx = TestContext()
assert not ctx.has_token(ROLE_ADMIN)
assert ctx.get_token(ROLE_ADMIN) is None

ctx.set_token(ROLE_ADMIN, "eyJhbGciOiJSUzI1NiJ9.payload.signature")
assert ctx.has_token(ROLE_ADMIN)
assert ctx.get_token(ROLE_ADMIN) is not None
assert ctx.stored_roles() == [ROLE_ADMIN]

# Registrazione risorse e drain LIFO
ctx.register_resource_for_teardown("DELETE", "/api/v1/repos/user-a/repo-first")
ctx.register_resource_for_teardown("DELETE", "/api/v1/repos/user-a/repo-second")
assert ctx.registered_resource_count() == 2

drained = ctx.drain_resources()
assert len(drained) == 2
# LIFO: repo-second (creato dopo) viene cancellato prima
assert drained[0] == ("DELETE", "/api/v1/repos/user-a/repo-second")
assert drained[1] == ("DELETE", "/api/v1/repos/user-a/repo-first")

# Secondo drain: registry e' stato svuotato
assert ctx.drain_resources() == []
assert ctx.registered_resource_count() == 0

# Guardie sui valori invalidi
from pydantic import ValidationError
try:
    ctx.register_resource_for_teardown("DELETE", "no-leading-slash")
except ValueError as exc:
    print(exc)  # atteso: "must start with '/'"
```

---

Un dettaglio rilevante per la tesi: `endpoint_base_url()` e `admin_endpoint_base_url()` esistono perché `AnyHttpUrl` in Pydantic v2 restituisce un oggetto `Url`, non una `str`. Se un test scrive `f"{target.base_url}/api/v1/users"`, ottiene qualcosa come `"http://localhost:8000//api/v1/users"` con doppio slash. I metodi helper centralizzano questa conversione e il `rstrip("/")` difensivo, eliminando una classe intera di bug sottili distribuiti in ogni test.

Il prossimo step bottom-up è `src/core/dag.py` — il `DAGScheduler` basato su `graphlib.TopologicalSorter`. Attendo il tuo via libera.

---

## `src/core/dag.py`

**Ratio architetturale preliminare.**

Il `DAGScheduler` risolve un problema di ordinamento con vincoli: dati N test, ciascuno con una lista di prerequisiti dichiarati (`depends_on: list[str]`), produce una sequenza di esecuzione che rispetta tutti i vincoli. Questo è esattamente il problema del **topological sort** su un grafo diretto aciclico.

Python 3.9 ha introdotto `graphlib.TopologicalSorter` nella stdlib, il che significa zero dipendenze esterne per questo componente. Vale la pena spiegare perché usiamo `graphlib` invece di implementare Kahn's algorithm o DFS manualmente: `TopologicalSorter` è l'unica implementazione nella stdlib che rileva i cicli come condizione di errore esplicita (solleva `CycleError`), che noi intercettiamo e convertiamo nella nostra `DAGCycleError` con informazioni diagnostiche aggiuntive.

**Il concetto di batch e perché esiste.** `TopologicalSorter` produce gruppi di nodi che possono essere processati in parallelo — nodi senza dipendenze reciproche tra loro. Nel nostro caso, i batch sono sequenziali tra loro ma i test dentro un batch potrebbero in futuro girare in parallelo. Produrre esplicitamente i batch invece di una lista piatta è una scelta di design che preserva questa opzione futura senza implementarla ora, in accordo con il principio dichiarato in `Implementazione.md` sezione 4.3: "L'esecuzione parallela è intenzionalmente considerata fuori scope per la Versione 1.0."

**Gestione delle dipendenze mancanti.** Se il test 2.2 dichiara `depends_on=["1.1"]` ma il test 1.1 è stato filtrato fuori dalla `TestRegistry` (perché escluso dalla priorità o dalla strategia), il DAG ha un nodo referenziato ma non presente. La scelta di `Implementazione.md` sezione 4.5 è chiara: dipendenza mancante → `WARNING` e prosecuzione, non errore bloccante. Il rationale è che l'utente potrebbe intenzionalmente eseguire solo i test P2 senza i prerequisiti P0, e bloccare l'esecuzione sarebbe eccessivamente restrittivo.

---

## Cosa aspettarsi dal modulo in esecuzione

```python
from src.core.dag import DAGScheduler, ScheduledBatch
from src.core.exceptions import DAGCycleError

scheduler = DAGScheduler()

# --- Caso base: tre test con dipendenze lineari ---
deps = {
    "1.1": [],
    "1.2": ["1.1"],
    "2.2": ["1.1", "1.2"],
}
active = {"1.1", "1.2", "2.2"}
batches = scheduler.build_schedule(deps, active)

assert len(batches) == 3
assert batches[0].test_ids == ["1.1"]   # nessuna dipendenza
assert batches[1].test_ids == ["1.2"]   # dipende da 1.1
assert batches[2].test_ids == ["2.2"]   # dipende da 1.1 e 1.2

# --- Dipendenze mancanti: WARNING e prosecuzione ---
deps_with_missing = {
    "2.2": ["1.1", "1.2"],  # 1.1 e 1.2 non sono in active
}
active_partial = {"2.2"}
batches_partial = scheduler.build_schedule(deps_with_missing, active_partial)
# 2.2 finisce nel batch 0 perche' le sue dipendenze sono state rimosse
assert len(batches_partial) == 1
assert batches_partial[0].test_ids == ["2.2"]

# --- Ciclo: DAGCycleError fatale ---
deps_cyclic = {
    "1.4": ["2.2"],
    "2.2": ["1.4"],
}
active_cyclic = {"1.4", "2.2"}
try:
    scheduler.build_schedule(deps_cyclic, active_cyclic)
    assert False, "Deve sollevare DAGCycleError"
except DAGCycleError as exc:
    assert "1.4" in exc.cycle or "2.2" in exc.cycle
    print(f"Cycle detected: {exc.cycle}")

# --- Determinismo: stessa input, stesso output ---
import random
shuffled_deps = dict(random.sample(list(deps.items()), len(deps)))
batches_shuffled = scheduler.build_schedule(shuffled_deps, active)
assert [b.test_ids for b in batches_shuffled] == [b.test_ids for b in batches]

# --- ScheduledBatch e' frozen ---
from dataclasses import FrozenInstanceError
try:
    batches[0].batch_index = 99
except FrozenInstanceError:
    print("ScheduledBatch e' correttamente immutabile")
```

---

Due dettagli rilevanti per la tesi che meritano di essere esplicitati:

Il **determinismo** garantito dal `sorted()` dentro `_drain_into_batches` non è un dettaglio estetico: è la realizzazione tecnica del vincolo di **Riproducibilità** enunciato in `Implementazione.md` sezione 1. Due esecuzioni dello stesso `config.yaml` sullo stesso target devono produrre lo stesso ordine di test, e quindi lo stesso `evidence.json` con gli stessi `record_id`. Senza il sort, `graphlib` restituisce i nodi in ordine dipendente dall'implementazione interna del dizionario Python, che è deterministico per insertion order in Python 3.7+ ma non per topological level.

Il **guard sull'infinite loop** in `_drain_into_batches` (il blocco `if not ready_nodes: break`) non è codice difensivo generico: è la conseguenza di una proprietà di `graphlib` che la documentazione ufficiale non garantisce esplicitamente. Se `prepare()` ha avuto successo e non ci sono cicli, `is_active()` e `get_ready()` si comportano correttamente. Ma documentare e gestire il caso degenere trasforma un potenziale freeze della pipeline in un `ERROR` loggato e un assessment parziale, che è sempre preferibile a un processo che non termina.

Il prossimo step bottom-up è `src/core/client.py` — il `SecurityClient`, wrapper centralizzato attorno a `httpx` con retry esponenziale via `tenacity` e notifica all'`EvidenceStore`. Attendo il tuo via libera.

---

## `src/core/client.py`

**Ratio architetturale preliminare.**

Il `SecurityClient` è il punto di confine tra il tool e la rete. Tutto il traffico HTTP dell'assessment passa da qui — nessun test importa `httpx` direttamente. Questo confine centralizzato ha tre conseguenze architetturali che meritano di essere spiegate prima del codice.

**Il client non interpreta, non decide, non autentica.** Il client sa come fare una request HTTP in modo affidabile (timeout, retry, no-redirect). Non sa cosa significa un `401`, non sa quale token aggiungere, non sa se la response è un FAIL o un PASS. Queste sono responsabilità del test. Questo confine netto è ciò che rende il client riutilizzabile su qualsiasi dominio senza modifiche.

**Il pattern di ritorno `(Response, EvidenceRecord)`.** Il client costruisce sempre un `EvidenceRecord` per ogni transazione completata, ma non lo scrive mai nell'`EvidenceStore` autonomamente. Restituisce la coppia `(response, record)` al test, che decide se chiamare `store.add_fail_evidence(record)` o `store.pin_evidence(record)` o semplicemente ignorare il record. Questo realizza il contratto di `Implementazione.md` sezione 4.4: "il logging delle evidenze rilevanti è centralizzato nel client; la selezione di cosa loggare è responsabilità del test."

**Perché `tenacity` e non il retry nativo di `httpx`.** `httpx` non ha retry nativo. `tenacity` permette di definire la condizione di retry con precisione chirurgica: riprova su errori di trasporto (`ConnectError`, `TimeoutException`), mai su risposte HTTP valide inclusi `5xx` — perché un `503` è un'informazione di sicurezza rilevante per il test 4.3 (circuit breaker), non un errore transitorio da nascondere.

---

## Cosa aspettarsi dal modulo in esecuzione

```python
# Questo test richiede che lo stack Docker sia attivo (target reale, no mock).
from src.core.client import SecurityClient
from src.core.models import EvidenceRecord
import httpx

with SecurityClient(base_url="http://localhost:8000") as client:

    # Request normale: risposta + record
    response, record = client.request(
        method="GET",
        path="/api/v1/repos/search",
        test_id="0.1",
    )
    assert isinstance(response, httpx.Response)
    assert isinstance(record, EvidenceRecord)
    assert record.record_id == "0.1_001"
    assert record.request_method == "GET"
    assert record.response_status_code == response.status_code

    # Seconda request dallo stesso test: record_id incrementa
    response2, record2 = client.request(
        method="GET",
        path="/api/v1/repos/search",
        test_id="0.1",
    )
    assert record2.record_id == "0.1_002"

    # Header Authorization: redaction automatica nel record
    response3, record3 = client.request(
        method="GET",
        path="/api/v1/user",
        test_id="1.1",
        headers={"Authorization": "Bearer eyJhbGciOiJSUzI1NiJ9.real.token"},
    )
    assert record3.request_headers["authorization"] == "[REDACTED]"

    # Path senza slash iniziale: ValueError immediato
    try:
        client.request(method="GET", path="api/v1/users", test_id="1.1")
    except ValueError as exc:
        print(exc)  # atteso: "must start with '/'"

# Uso fuori dal context manager: RuntimeError
try:
    client.request(method="GET", path="/api/v1/repos/search", test_id="0.1")
except RuntimeError as exc:
    print(exc)  # atteso: "called outside of a 'with' block"
```

---

Due dettagli rilevanti per la tesi:

Il **non-raise su `HTTPStatusError`** è la scelta più controintuitiva del modulo e la più importante da motivare. La convenzione httpx prevede che `response.raise_for_status()` sollevi un'eccezione su `4xx`/`5xx`. Non chiamarlo mai è deliberato: un `401` su un endpoint che dovrebbe essere protetto è un `PASS` per il test 1.1; un `200` sullo stesso endpoint senza token è un `FAIL`. Il client non ha abbastanza contesto per distinguere i due casi — solo il test lo ha. Qualsiasi tentativo del client di interpretare i codici di stato violerebbe il principio di responsabilità singola e renderebbe impossibile testare scenari in cui un codice di errore è l'esito atteso.

Il **`_next_record_id` con contatore per `test_id`** invece di un UUID globale è una scelta di leggibilità del report. `"1.2_003"` in `evidence.json` comunica immediatamente "terza transazione del test 1.2", mentre `"f47ac10b-58cc-4372-a567-0e02b2c3d479"` non comunica nulla senza una tabella di lookup. Per un documento accademico dimostrativo, la leggibilità dell'evidenza è un requisito non funzionale rilevante.

Il prossimo step bottom-up è `src/config/schema.py` — lo schema Pydantic v2 del `config.yaml`, che definisce `ToolConfig` con tutti i suoi sotto-modelli. Attendo il tuo via libera.

---

## `src/config/schema.py`

**Ratio architetturale preliminare.**

`schema.py` è il contratto formale tra l'utente del tool e il suo comportamento. Ogni campo che appare qui ha una corrispondenza diretta in `config.yaml` e un impatto verificabile sulla pipeline. La responsabilità di questo modulo è esclusivamente **strutturale e validativa**: trasformare un dizionario YAML grezzo in un oggetto Python tipizzato e frozen, rifiutando esplicitamente qualsiasi configurazione ambigua o pericolosa prima che un singolo test venga avviato.

Tre scelte di design meritano spiegazione anticipata.

**La decomposizione in sotto-modelli.** `ToolConfig` non è un modello piatto con venti campi: è una composizione di sotto-modelli (`TargetConfig`, `CredentialsConfig`, `ExecutionConfig`) che raggruppano i campi per dominio semantico. Questo ha due vantaggi: la validazione cross-field (es. "se `strategy` include `WHITE_BOX`, allora `admin_api_url` deve essere presente") può essere espressa come `model_validator` sul sotto-modello corretto invece che su un campo globale; e il `config.yaml` risultante ha una struttura gerarchica leggibile che rispecchia la struttura del codice.

**`ToolConfig` è frozen.** Come `TargetContext`, la configurazione non deve mai essere mutata dopo il caricamento. Un test che potesse modificare `config.execution.min_priority` cambierebbe il comportamento di tutti i test successivi in modo non tracciabile. Il freeze a livello di schema rende questo impossibile a compile-time.

**Validatori espliciti invece di vincoli impliciti.** Pydantic v2 permette di esprimere vincoli tramite `Field(ge=0, le=3)` per gli interi o `AnyHttpUrl` per gli URL. Usiamo entrambi dove applicabile, ma aggiungiamo `field_validator` espliciti per i casi che richiedono messaggi di errore leggibili dall'utente — perché un errore di configurazione deve essere diagnosticabile senza leggere il codice sorgente.

---

## Template `config.yaml` di riferimento

Una volta approvato `schema.py`, il `config.yaml` operativo per il nostro ambiente di laboratorio avrà questa struttura. Lo includo qui perché è la controparte documentale diretta dello schema e serve per la tesi.

```yaml
# config.yaml — APIGuard Assurance configuration template
# Credentials must NEVER be written in plain text here.
# All ${VAR_NAME} placeholders are resolved from environment variables by loader.py.

target:
  base_url: "http://localhost:8000"
  openapi_spec_url: "http://localhost:8000/api/swagger"
  admin_api_url: "http://localhost:8001"

credentials:
  admin_username: "${ADMIN_USERNAME}"
  admin_password: "${ADMIN_PASSWORD}"
  user_a_username: "${USER_A_USERNAME}"
  user_a_password: "${USER_A_PASSWORD}"
  user_b_username: "${USER_B_USERNAME}"
  user_b_password: "${USER_B_PASSWORD}"

execution:
  min_priority: 3
  strategies:
    - BLACK_BOX
    - GREY_BOX
    - WHITE_BOX
  fail_fast: false
  connect_timeout: 5.0
  read_timeout: 30.0
  max_retry_attempts: 3

rate_limit_probe:
  max_requests: 150
  request_interval_ms: 50
```

---

## Cosa aspettarsi dal modulo in esecuzione

```python
from src.config.schema import ToolConfig, CredentialsConfig, ExecutionConfig
from src.core.models import TestStrategy
from pydantic import ValidationError

# Configurazione minima valida (solo target obbligatorio)
config = ToolConfig.model_validate({
    "target": {
        "base_url": "http://localhost:8000",
        "openapi_spec_url": "http://localhost:8000/api/swagger",
    }
})
assert config.execution.min_priority == 3
assert config.execution.fail_fast is False
assert config.rate_limit_probe.max_requests == 150
assert config.rate_limit_probe.request_interval_seconds == 0.05

# Frozen: mutazione impossibile
try:
    config.execution = ExecutionConfig()
except ValidationError as exc:
    print(exc)  # "Instance is frozen"

# URL malformato: ValidationError in Phase 1
try:
    ToolConfig.model_validate({
        "target": {
            "base_url": "not-a-url",
            "openapi_spec_url": "http://localhost:8000/api/swagger",
        }
    })
except ValidationError as exc:
    print(exc)  # URL validation error

# Credential pair incompleta
try:
    ToolConfig.model_validate({
        "target": {
            "base_url": "http://localhost:8000",
            "openapi_spec_url": "http://localhost:8000/api/swagger",
        },
        "credentials": {
            "admin_username": "thesis-admin",
            # admin_password mancante
        }
    })
except ValidationError as exc:
    print(exc)  # "Credential pair incomplete for role 'admin'"

# Strategies lista vuota
try:
    ToolConfig.model_validate({
        "target": {
            "base_url": "http://localhost:8000",
            "openapi_spec_url": "http://localhost:8000/api/swagger",
        },
        "execution": {"strategies": []}
    })
except ValidationError as exc:
    print(exc)  # "must contain at least one strategy"

# WHITE_BOX senza admin_api_url: non fatale, warning property
config_no_admin = ToolConfig.model_validate({
    "target": {
        "base_url": "http://localhost:8000",
        "openapi_spec_url": "http://localhost:8000/api/swagger",
        # admin_api_url assente
    },
    "execution": {"strategies": ["WHITE_BOX"]}
})
assert config_no_admin.white_box_without_admin_api is True
```

---

Il punto da sottolineare per la tesi riguarda l'uso di `object.__setattr__` nel `model_validator` del `ToolConfig` frozen. Un modello frozen in Pydantic v2 solleva `ValidationError` su qualsiasi assegnazione dopo la costruzione — inclusa quella dall'interno di un `model_validator(mode="after")`. L'unico modo per scrivere attributi extra su un modello frozen dopo la validazione è bypassare il meccanismo di Pydantic usando direttamente `object.__setattr__`, che opera sul `__dict__` dell'oggetto senza passare per `__setattr__` di Pydantic. È una tecnica avanzata e deliberatamente ristretta a questo caso specifico: le property `white_box_without_admin_api` e `grey_box_without_credentials` sono flag di diagnostica, non campi di configurazione, e non devono essere dichiarate come `Field` per non inquinare lo schema pubblico del modello.

Il prossimo step è `src/config/loader.py` — il parser YAML con interpolazione delle variabili d'ambiente e produzione del `ToolConfig`. Attendo il tuo via libera.
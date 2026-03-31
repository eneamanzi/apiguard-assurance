## `src/config/loader.py`

**Ratio architetturale preliminare.**

Il loader è il cancello d'ingresso del tool: l'unico modulo che tocca il filesystem per leggere `config.yaml` e l'unico che interagisce con le variabili d'ambiente. Dopo questa fase, il resto della pipeline opera esclusivamente su oggetti Python tipizzati — nessun altro modulo chiama `os.environ` o apre file YAML.

Il processo avviene in tre passaggi sequenziali e distinti, ciascuno con responsabilità non sovrapponibili.

**Passaggio 1 — Lettura raw.** Il file viene letto come stringa grezza. Nessuna interpretazione del contenuto: solo I/O puro con gestione esplicita di `FileNotFoundError` e `PermissionError`.

**Passaggio 2 — Interpolazione.** La stringa grezza viene scansionata con una regex per trovare tutti i pattern `${VAR_NAME}`. Per ogni match, il valore viene cercato in `os.environ`. Se una variabile è assente, il loader solleva `ConfigurationError` immediatamente, con il nome della variabile mancante nel campo strutturato — prima ancora di chiamare Pydantic. Questo è deliberato: un errore di variabile d'ambiente mancante deve essere diagnosticato come problema di ambiente, non come errore di validazione YAML.

**Passaggio 3 — Validazione.** La stringa interpolata viene parsata come YAML e il dizionario risultante viene passato a `ToolConfig.model_validate()`. Gli errori Pydantic vengono catturati e convertiti in `ConfigurationError` con il campo `config_path` popolato dal percorso Pydantic dell'errore (es. `target.base_url`).

---

## Cosa aspettarsi dal modulo in esecuzione

```python
import os
from pathlib import Path
from src.config.loader import load_config
from src.core.exceptions import ConfigurationError

# --- Setup: scrivi un config.yaml temporaneo ---
config_content = """
target:
  base_url: "http://localhost:8000"
  openapi_spec_url: "http://localhost:8000/api/swagger"
  admin_api_url: "http://localhost:8001"

credentials:
  admin_username: "${ADMIN_USERNAME}"
  admin_password: "${ADMIN_PASSWORD}"

execution:
  min_priority: 3
  fail_fast: false
"""

tmp_path = Path("/tmp/test_config.yaml")
tmp_path.write_text(config_content, encoding="utf-8")

# --- Caso 1: variabili d'ambiente mancanti ---
os.environ.pop("ADMIN_USERNAME", None)
os.environ.pop("ADMIN_PASSWORD", None)

try:
    load_config(tmp_path)
except ConfigurationError as exc:
    assert exc.variable_name in ("ADMIN_USERNAME", "ADMIN_PASSWORD")
    print(f"Caught expected error: {exc}")

# --- Caso 2: caricamento corretto ---
os.environ["ADMIN_USERNAME"] = "thesis-admin"
os.environ["ADMIN_PASSWORD"] = "Admin1234!"

config = load_config(tmp_path)
assert str(config.target.base_url).startswith("http://localhost:8000")
assert config.credentials.admin_username == "thesis-admin"
# La password NON compare nei log (structlog non la serializza)
# ma e' accessibile nell'oggetto per i test di autenticazione
assert config.credentials.admin_password == "Admin1234!"
assert config.execution.min_priority == 3

# --- Caso 3: file inesistente ---
try:
    load_config(Path("/tmp/nonexistent.yaml"))
except ConfigurationError as exc:
    assert "not found" in exc.message
    print(f"Caught expected error: {exc}")

# --- Caso 4: YAML malformato ---
bad_yaml = Path("/tmp/bad_config.yaml")
bad_yaml.write_text("target: {base_url: [not, a, url", encoding="utf-8")
try:
    load_config(bad_yaml)
except ConfigurationError as exc:
    assert "YAML syntax error" in exc.message
    print(f"Caught expected error: {exc}")

# --- Caso 5: config.yaml vuoto ---
empty_yaml = Path("/tmp/empty_config.yaml")
empty_yaml.write_text("   ", encoding="utf-8")
try:
    load_config(empty_yaml)
except ConfigurationError as exc:
    assert "empty" in exc.message
    print(f"Caught expected error: {exc}")

# Cleanup
os.environ.pop("ADMIN_USERNAME", None)
os.environ.pop("ADMIN_PASSWORD", None)
```

---

Due dettagli rilevanti per la tesi.

**La scelta di raccogliere tutte le variabili mancanti prima di sollevare l'errore** (invece di fermarsi alla prima) inverte la filosofia del "fail on first" usata da Pydantic. La motivazione è operativa: in un ambiente CI/CD dove le variabili sono configurate come secrets, è comune che ne manchino più di una dopo un refactoring. Ricevere un errore per `ADMIN_USERNAME`, esportarlo, e poi scoprire che manca anche `ADMIN_PASSWORD` raddoppia il ciclo di debug. Un messaggio che lista tutte le variabili mancanti risolve il problema in un'unica iterazione.

**La separazione tra `_read_raw_file`, `_interpolate_env_vars` e `_parse_and_validate`** non è solo organizzativa: è una scelta di diagnosticabilità. Ogni funzione privata solleva `ConfigurationError` con un `message` che inizia con una frase diversa ("Configuration file not found", "Environment variable(s) not set", "YAML syntax error", "Configuration validation failed"). Questo permette a un operatore che legge il log di identificare la fase esatta del fallimento senza analizzare lo stack trace.

Il prossimo step è `src/discovery/openapi.py` — fetch, dereferenziazione e validazione della spec OpenAPI. Attendo il tuo via libera.

---

## `src/discovery/openapi.py`

**Ratio architetturale preliminare.**

Questo modulo esegue le tre operazioni sequenziali descritte in `Implementazione.md` sezione 4.2: fetch, dereferenziazione, validazione. Ogni operazione è implementata come funzione privata separata per la stessa ragione del loader: ogni fase di fallimento produce un messaggio di errore categoricamente distinto, diagnosticabile senza stack trace.

**Perché `prance` per la dereferenziazione e non `jsonschema` o `referencing`.** `prance` è l'unica libreria Python che risolve `$ref` remoti (HTTP e filesystem) producendo una spec completamente inline in un singolo passaggio. `jsonschema` e la libreria `referencing` (il suo successore in v4) gestiscono la risoluzione di riferimenti per la validazione ma non producono una spec dereferenziata come output — restituiscono un resolver, non un documento. `openapi-spec-validator` valida ma non dereferenzia. La sequenza corretta è quindi: `prance` dereferenzia → `openapi-spec-validator` valida il documento dereferenziato.

**Il problema del fetch con `prance`.** `prance` accetta sia URL HTTP che path locali come sorgente della spec. Tuttavia il suo comportamento su errori di rete è eterogeneo tra versioni: alcune versioni sollevano `prance.util.url.ResolutionError`, altre `requests.exceptions.ConnectionError`, altre ancora `FileNotFoundError` a seconda del transport. Il wrapper `_fetch_and_dereference` cattura tutte le eccezioni base e le normalizza in `OpenAPILoadError`, rendendo il comportamento del modulo prevedibile indipendentemente dalla versione di `prance` installata.


---

## Cosa aspettarsi dal modulo in esecuzione

```python
# Questo test richiede che lo stack Docker sia attivo.
from src.discovery.openapi import load_openapi_spec
from src.core.exceptions import OpenAPILoadError

# --- Caso 1: spec reale da Forgejo via Kong ---
spec = load_openapi_spec("http://localhost:8000/api/swagger")

assert isinstance(spec, dict)
assert "openapi" in spec
assert spec["openapi"].startswith("3.")
assert "paths" in spec
assert len(spec["paths"]) > 0

info = spec.get("info", {})
print(f"Spec title: {info.get('title')}")
print(f"Spec version: {info.get('version')}")
print(f"Path count: {len(spec['paths'])}")

# Verifica che non ci siano $ref residui nel primo livello di paths
# (dereferenziazione completa)
first_path = next(iter(spec["paths"].values()))
assert "$ref" not in str(first_path)[:200], "Residual $ref found after deref"

# --- Caso 2: URL irraggiungibile ---
try:
    load_openapi_spec("http://localhost:9999/nonexistent/spec")
except OpenAPILoadError as exc:
    assert exc.source_url == "http://localhost:9999/nonexistent/spec"
    assert exc.underlying_error is not None
    print(f"Caught expected error: {exc.message[:80]}")

# --- Caso 3: spec vuota (Swagger 2.x) ---
# Non testabile direttamente senza un mock server,
# ma il branch e' coperto dalla logica _assert_supported_version.
```

---

Due dettagli per la tesi.

**L'uso di `# noqa: BLE001`** nei due `except Exception` è la soluzione corretta per Ruff in questo contesto. La regola BLE001 ("blind exception") esiste per scoraggiare `except Exception: pass` che nasconde errori. Qui non stiamo nascondendo nulla: stiamo normalizzando eccezioni eterogenee di librerie terze in un tipo controllato. Il commento `noqa` è accompagnato da una docstring che spiega esattamente perché il broad catch è intenzionale — questa è la documentazione che rende il noqa accettabile in una codebase accademica rigorosa.

**La selezione del validatore `OpenAPIV30SpecValidator` vs `OpenAPIV31SpecValidator`** basata sulla stringa di versione è necessaria perché OpenAPI 3.1.x ha introdotto un meta-schema incompatibile con 3.0.x (in particolare, 3.1.x allinea i tipi JSON Schema con la specifica Draft 2020-12). `openapi-spec-validator` espone classi separate per le due versioni; usare quella sbagliata produrrebbe falsi negativi nella validazione. Forgejo espone una spec 3.x ma dobbiamo essere robusti rispetto alla versione minore specifica.

Il prossimo step è `src/discovery/surface.py` — il costruttore di `AttackSurface` che interpreta il dict dereferenziato e produce l'oggetto strutturato che i test consumeranno. Attendo il tuo via libera.

---

## `src/discovery/surface.py`

**Ratio architetturale preliminare.**

`surface.py` è il traduttore tra due rappresentazioni dello stesso dato: il dict Python prodotto da `openapi.py` (formato OpenAPI 3.x, verboso, con semantica implicita) e l'`AttackSurface` (formato del tool, tipizzato, con semantica esplicita). Dopo questo modulo, nessun altro componente del tool tocca il dict grezzo della spec.

Tre aspetti della traduzione meritano spiegazione anticipata.

**La derivazione di `requires_auth`.** OpenAPI 3.x dichiara i requisiti di sicurezza in due posti: a livello globale (`components/securitySchemes` + `security` array globale) e a livello di singola operazione (array `security` dell'operation object). Una operazione può sovrascrivere il global con un array vuoto `security: []` per dichiararsi pubblica. La logica corretta è: se l'operazione ha un `security` array esplicito, usa quello; altrimenti eredita il global. Un array vuoto a qualsiasi livello significa `requires_auth=False`. Questa è la semantica OpenAPI 3.x per la sicurezza, e implementarla correttamente è fondamentale per la correttezza del test 1.1.

**La gestione dei path template.** I path OpenAPI usano parametri template come `{owner}` e `{repo}`. `EndpointRecord.path` li preserva così come sono — non li sostituisce con valori reali. I test che devono fare richieste a endpoint con path parameters usano `_substitute_path_parameters()` nel loro `execute()`, che è responsabilità del test, non della surface.

**Il conteggio delle operazioni vs dei path.** OpenAPI 3.x permette a un singolo path di dichiarare fino a 8 operazioni HTTP distinte. `build_attack_surface` itera su `(path, method)` pairs, non su path, producendo un `EndpointRecord` per coppia. Questo è il livello di granularità corretto perché il controllo di autorizzazione (test 2.1, 2.3) è per-metodo, non per-path.


---

## Cosa aspettarsi dal modulo in esecuzione

```python
# Richiede lo stack Docker attivo.
from src.discovery.openapi import load_openapi_spec
from src.discovery.surface import build_attack_surface
from src.core.models import AttackSurface, EndpointRecord

spec = load_openapi_spec("http://localhost:8000/api/swagger")
surface = build_attack_surface(spec)

assert isinstance(surface, AttackSurface)
assert surface.total_endpoint_count > 0
assert surface.unique_path_count > 0

print(f"Title: {surface.spec_title}")
print(f"Endpoints: {surface.total_endpoint_count}")
print(f"Unique paths: {surface.unique_path_count}")
print(f"Authenticated: {len(surface.get_authenticated_endpoints())}")
print(f"Public: {len(surface.get_public_endpoints())}")
print(f"Deprecated: {surface.deprecated_count}")

# Ogni record ha path che inizia con /
for ep in surface.endpoints[:5]:
    assert ep.path.startswith("/"), f"Bad path: {ep.path}"
    assert ep.method in {
        "GET","POST","PUT","PATCH","DELETE","HEAD","OPTIONS","TRACE"
    }

# Endpoint con path parameters (candidati BOLA)
bola_candidates = surface.get_endpoints_with_path_parameters()
print(f"BOLA candidates (path params): {len(bola_candidates)}")
for ep in bola_candidates[:3]:
    path_params = [p.name for p in ep.parameters if p.location == "path"]
    print(f"  {ep.method} {ep.path} -> params: {path_params}")

# find_endpoint: ricerca esatta
result = surface.find_endpoint("/api/v1/repos/search", "GET")
if result is not None:
    print(f"Found: {result.method} {result.path}")
    print(f"  requires_auth: {result.requires_auth}")
    print(f"  deprecated: {result.is_deprecated}")
    print(f"  parameters: {len(result.parameters)}")

# Surface e' frozen
from pydantic import ValidationError
try:
    surface.spec_title = "mutated"
except ValidationError:
    print("Surface is correctly frozen")

# AttackSurface ora tipizzata correttamente in TargetContext
from src.core.context import TargetContext
target = TargetContext(
    base_url="http://localhost:8000",
    openapi_spec_url="http://localhost:8000/api/swagger",
    attack_surface=surface,
)
assert target.attack_surface is not None
assert target.attack_surface.total_endpoint_count == surface.total_endpoint_count
```

---

Due dettagli per la tesi.

**La gestione del `security` array vuoto a livello di operazione** è il caso più sottile dell'intera surface construction. In OpenAPI 3.x, scrivere `security: []` a livello di operazione non è equivalente ad omettere il campo `security`: significa esplicitamente che questa operazione è pubblica, anche se il global dichiara auth obbligatoria. `_security_array_requires_auth` implementa questa semantica verificando la presenza dell'array come campo (via `isinstance(operation_security_raw, list)`) prima di controllarne il contenuto. Un campo assente cade nel ramo `else` (eredita global); un array vuoto `[]` entra nel ramo `isinstance` e restituisce `False`. La distinzione è cruciale per la correttezza del test 1.1, che non deve tentare bypass di autenticazione su endpoint dichiarati pubblici.

**Il merging dei parametri path-level e operation-level** via dict keyed su `(name, in)` è l'implementazione diretta della regola OpenAPI 3.x Section 4.8.12. Una implementazione naive che concatena le due liste produrrebbe parametri duplicati quando un'operazione ridefinisce un parametro ereditato dal path item — ad esempio, ridefinendo `{owner}` con un pattern più restrittivo. I test di input validation (3.1) che generano payload per ogni parametro dichiarato produrrebbero payload doppi con conseguente rumore nell'evidence store.

Il layer di discovery è ora completo. Il prossimo step è `src/tests/base.py` e `src/tests/strategy.py` — il contratto `BaseTest` e l'enum `TestStrategy` (da spostare in `core/models.py` poiché già definito lì). Attendo il tuo via libera.

---

## `src/tests/strategy.py` e `src/tests/base.py`

**Nota preliminare su `strategy.py`.** `TestStrategy` è già definito in `src/core/models.py` — è la scelta architetturale corretta perché è un tipo condiviso usato da `TargetContext`, `schema.py`, e `TestRegistry`. Il file `src/tests/strategy.py` diventa quindi un modulo di re-export esplicito: documenta dove vive canonicamente il tipo e fornisce un punto di importazione conveniente per chi scrive test senza dover ricordare che `TestStrategy` vive in `core/`.


### `src/tests/base.py`

**Ratio architetturale preliminare.**

`BaseTest` è il contratto che ogni test deve rispettare. Il suo design deve soddisfare due requisiti opposti: essere abbastanza rigido da garantire che l'engine possa trattare ogni test in modo uniforme (stesso metodo da chiamare, stesso tipo di ritorno, stesse garanzie sulle eccezioni), e abbastanza flessibile da non costringere ogni test a duplicare codice boilerplate.

Tre aspetti del design meritano spiegazione anticipata.

**`execute()` è l'unico metodo astratto.** Tutto il resto — gli attributi di classe, i metodi helper, il contratto sulle eccezioni — è infrastruttura opzionale che il test può usare ma non è costretto a override. Il motivo è che un ABC con dieci metodi astratti diventa un obbligo burocratico che scoraggia la scrittura di test nuovi. Un ABC con un solo metodo astratto dice al test: "l'unica cosa che devi fare è implementare `execute()`."

**I metodi helper `_make_skip` e `_make_error`.** Questi metodi costruiscono `TestResult` per i casi più comuni che non richiedono logica di test: prerequisito assente → SKIP, eccezione inattesa → ERROR. Centralizzarli in `BaseTest` serve a tre scopi: evitare che ogni test ripeta la stessa costruzione di `TestResult`, garantire che il `skip_reason` sia sempre popolato per i SKIP (il validatore Pydantic lo richiede), e documentare il pattern corretto che la commissione vede quando legge qualsiasi test.

**Il metodo `_requires_token`.** Il pattern "controlla se il token esiste, altrimenti ritorna SKIP" è così frequente nei test Grey Box che merita un metodo dedicato. Senza di esso, ogni test P1/P2 inizia con lo stesso blocco di quattro righe, che è rumore visivo nel codice e una fonte di errori di copia-incolla.


---

## Cosa aspettarsi dal modulo in esecuzione

```python
from src.tests.base import BaseTest
from src.tests.strategy import TestStrategy
from src.core.models import TestResult, TestStatus
from src.core.context import TargetContext, TestContext, ROLE_USER_A
from src.core.client import SecurityClient
from src.core.evidence import EvidenceStore

# --- Verifica che BaseTest non sia istanziabile direttamente ---
try:
    BaseTest()
except TypeError as exc:
    print(f"Correct: {exc}")

# --- Implementazione minimale per test ---
class TestMinimal(BaseTest):
    test_id = "0.0"
    priority = 0
    strategy = TestStrategy.BLACK_BOX
    depends_on = []
    test_name = "Minimal Test"
    domain = 0
    tags = ["test"]
    cwe_id = "CWE-000"

    def execute(self, target, context, client, store) -> TestResult:
        try:
            return self._make_pass("All good.")
        except Exception as exc:
            return self._make_error(exc)

# --- has_required_metadata ---
assert TestMinimal.has_required_metadata() is True

class TestIncomplete(BaseTest):
    # test_id mancante
    def execute(self, target, context, client, store) -> TestResult:
        return self._make_pass("unreachable")

assert TestIncomplete.has_required_metadata() is False

# --- _make_pass ---
t = TestMinimal()
result = t._make_pass("Verified correctly.")
assert result.status == TestStatus.PASS
assert result.findings == []
assert result.test_id == "0.0"

# --- _make_skip ---
result_skip = t._make_skip("Admin API not configured.")
assert result_skip.status == TestStatus.SKIP
assert result_skip.skip_reason == "Admin API not configured."

# --- _make_error ---
result_error = t._make_error(ValueError("something broke"))
assert result_error.status == TestStatus.ERROR
assert "ValueError" in result_error.message

# --- _requires_token: token assente -> SKIP ---
ctx = TestContext()
skip = t._requires_token(ctx, ROLE_USER_A)
assert skip is not None
assert skip.status == TestStatus.SKIP
assert "user_a" in skip.skip_reason

# --- _requires_token: token presente -> None ---
ctx.set_token(ROLE_USER_A, "eyJhbGciOiJSUzI1NiJ9.payload.sig")
skip_after = t._requires_token(ctx, ROLE_USER_A)
assert skip_after is None

# --- _make_fail ---
result_fail = t._make_fail(
    message="Endpoint accepts unauthenticated requests.",
    detail="GET /api/v1/users/me returned 200 without Authorization. Expected 401.",
    evidence_record_id="0.0_001",
    additional_references=["OWASP-API2:2023"],
)
assert result_fail.status == TestStatus.FAIL
assert len(result_fail.findings) == 1
assert "CWE-000" in result_fail.findings[0].references
assert "OWASP-API2:2023" in result_fail.findings[0].references
assert result_fail.findings[0].evidence_ref == "0.0_001"
```

---

Due dettagli rilevanti per la tesi.

**La scelta di `_make_fail` con un singolo `Finding`** come caso default è una decisione di ergonomia per gli autori di test. La stragrande maggioranza dei test produce al massimo un finding per esecuzione. Avere un helper che costruisce esattamente questo caso riduce il codice di ogni test di circa dieci righe. I test che producono finding multipli (tipicamente 2.2 BOLA, che può rilevare violazioni su endpoint distinti) costruiscono i `Finding` manualmente e chiamano `TestResult()` direttamente — il helper non impedisce questa flessibilità, la affianca.

**Il campo `cwe_id` iniettato automaticamente in `_make_fail`** centralizza un'informazione che altrimenti ogni test dovrebbe ripetere. Dal punto di vista della tesi, questo significa che il mapping tra test e CWE è dichiarato una sola volta (nella ClassVar) e appare automaticamente in ogni finding prodotto da quel test, rendendo il report completamente referenziabile senza sforzo aggiuntivo da parte dell'autore del test.

Il prossimo step è `src/tests/registry.py` — la `TestRegistry` con discovery dinamico via `pkgutil.walk_packages` e filtro per priorità e strategia. Attendo il tuo via libera.

---

## `src/tests/registry.py`

**Ratio architetturale preliminare.**

La `TestRegistry` risolve un problema di accoppiamento: senza discovery dinamico, ogni nuovo test richiederebbe una modifica a un registro centrale — una lista, un dizionario, un import esplicito da qualche parte. Con il discovery via `pkgutil.walk_packages` + `inspect`, aggiungere un test è un'operazione puramente additiva: crei il file nella directory corretta, e il registry lo trova da solo alla prossima esecuzione.

Il processo interno ha tre fasi sequenziali e distinte.

**Fase R1 — Scan dei moduli.** `pkgutil.walk_packages` percorre ricorsivamente il package `src.tests`, trovando tutti i sottomoduli. Solo i moduli il cui nome inizia con `test_` vengono importati: questa convenzione di naming è il meccanismo tecnico di discovery, non una preferenza stilistica. Un file `helpers.py` o `fixtures.py` nella stessa directory non viene toccato.

**Fase R2 — Estrazione delle sottoclassi.** Per ogni modulo importato, `inspect.getmembers` filtra le classi che sono sottoclassi concrete di `BaseTest` — concrete significa che non sono `BaseTest` stessa e non sono ABC con metodi astratti non implementati. Questo esclude automaticamente qualsiasi classe helper che eredita da `BaseTest` senza implementare `execute()`.

**Fase R3 — Filtro.** Le istanze vengono filtrate per `priority <= min_priority` e `strategy in enabled_strategies`. L'ordine dei filtri è deliberato: prima metadati completi, poi priorità, poi strategia. Un test senza metadati è escluso prima ancora di controllare la priorità.

---

## Cosa aspettarsi dal modulo in esecuzione

```python
from src.tests.registry import TestRegistry
from src.core.models import TestStrategy

registry = TestRegistry()

# --- Discovery completa (nessun test implementato ancora: lista vuota) ---
active = registry.discover(
    min_priority=3,
    enabled_strategies={TestStrategy.BLACK_BOX, TestStrategy.GREY_BOX, TestStrategy.WHITE_BOX},
)
# Con zero test implementati, la lista e' vuota ma non si solleva nessun errore.
assert isinstance(active, list)
print(f"Active tests discovered: {len(active)}")

# --- Verifica con un test minimale registrato dinamicamente ---
# (simula cosa accade quando i test di dominio saranno implementati)
from src.tests.base import BaseTest
from src.core.models import TestResult, TestStatus
from src.core.context import TargetContext, TestContext
from src.core.client import SecurityClient
from src.core.evidence import EvidenceStore
import src.tests.domain_0  # il package deve esistere con __init__.py

# Verifica che build_dependency_map funzioni su lista vuota
dep_map = registry.build_dependency_map([])
assert dep_map == {}

# Verifica filtro per priority
# Quando avremo test reali:
# active_p0_only = registry.discover(min_priority=0, enabled_strategies={TestStrategy.BLACK_BOX})
# assert all(t.__class__.priority == 0 for t in active_p0_only)
# assert all(t.__class__.strategy == TestStrategy.BLACK_BOX for t in active_p0_only)

print("TestRegistry instantiation and basic behavior: OK")
```

---

Due dettagli rilevanti per la tesi.

**La condizione `cls.__module__ != module_name` (Guard 3)** è la protezione contro il double-counting più sottile del modulo. Senza di essa, se `test_2_2_bola.py` importa `Test_1_1_AuthRequired` per riutilizzarne un metodo helper, quella classe apparirebbe nell'elenco dei membri di entrambi i moduli e verrebbe istanziata due volte. Il confronto `__module__` garantisce che una classe venga conteggiata solo nel modulo in cui è definita, non in quelli che la importano.

**`build_dependency_map` come metodo separato da `discover`** è una scelta di separazione delle responsabilità verso `engine.py`. L'alternativa sarebbe far restituire a `discover()` una tupla `(tests, dependency_map)`. Ma questo accoppia il formato di ritorno di `discover()` ai requisiti di `DAGScheduler`, che è un dettaglio di implementazione dell'engine. Tenere i due metodi separati significa che l'engine può chiamare `discover()` e decidere autonomamente se e quando costruire la dependency map, senza che il registry debba sapere che esiste un DAGScheduler.

Il prossimo step è `src/engine.py` — l'orchestratore che coordina tutti i componenti implementati finora nelle sette fasi della pipeline. Attendo il tuo via libera.

---

## `src/engine.py`

**Ratio architetturale preliminare.**

L'engine è l'unico modulo con visibilità trasversale su tutti i componenti. La sua responsabilità è **esclusivamente orchestrativa**: chiama i moduli giusti nell'ordine corretto, passa gli oggetti giusti, registra i risultati. Non contiene logica di dominio, non interpreta i risultati dei test, non decide cosa testare.

Il modo più chiaro per garantire questa purezza orchestrativa è strutturare l'engine come una sequenza di metodi privati, uno per fase, ciascuno con una responsabilità precisa e un contratto di input/output esplicito. L'engine non è un `God Object` che contiene tutto: è un direttore d'orchestra che sa chi chiamare e quando, senza sapere cosa suonano.

**La gestione del `SecurityClient` come context manager.** Il client viene aperto all'inizio della Fase 5 e chiuso dopo la Fase 6 (teardown), garantendo che il connection pool sia disponibile per l'intero ciclo di esecuzione + cleanup, e venga rilasciato correttamente anche in caso di eccezioni. Questo è il pattern descritto in `Implementazione.md` sezione 4.4.

**Il `ResultSet.completed_at`** viene impostato dall'engine dopo la Fase 6, non dopo la Fase 5. Questo è intenzionale: il teardown è parte integrante dell'assessment e il suo completamento (o fallimento) deve essere tracciato nel timestamp finale.

---

## Cosa aspettarsi dal modulo in esecuzione

```python
# Test di istanziazione — non richiede stack Docker attivo.
from src.engine import AssessmentEngine, _generate_run_id
from pathlib import Path

# _generate_run_id produce un ID deterministicamente formattato
run_id = _generate_run_id()
assert run_id.startswith("apiguard-")
parts = run_id.split("-")
assert len(parts) == 4
assert len(parts[1]) == 8   # YYYYMMDD
assert len(parts[2]) == 6   # HHMMSS
print(f"Run ID format valid: {run_id}")

# Istanziazione: nessun I/O a construction time
engine = AssessmentEngine(config_path=Path("config.yaml"))

# Esecuzione con config mancante: ritorna EXIT_CODE_INFRASTRUCTURE
engine_bad = AssessmentEngine(config_path=Path("/nonexistent/config.yaml"))
exit_code = engine_bad.run()
assert exit_code == 10
print(f"Infrastructure error exit code: {exit_code}")

# Esecuzione completa (richiede stack Docker + config.yaml + env vars):
# engine_real = AssessmentEngine(config_path=Path("config.yaml"))
# exit_code = engine_real.run()
# assert exit_code in {0, 1, 2, 10}
# assert Path("evidence.json").exists()
# assert Path("assessment_report.html").exists()
```

---

Tre dettagli rilevanti per la tesi.

**`result_set.completed_at` impostato dopo la Fase 6** e non dopo la Fase 5 è una scelta semantica deliberata. Il `ResultSet` rappresenta l'intero assessment, che include la pulizia delle risorse. Il `duration_seconds` calcolato da `started_at` a `completed_at` nel report riflette quindi il tempo totale dell'operazione, non solo il tempo di esecuzione dei test. Questo è il dato corretto per la sezione di performance analysis della tesi.

**`model_copy(update={"duration_ms": ...})`** per iniettare il timing nel `TestResult` è il pattern idiomatico Pydantic v2 per modificare un modello non-frozen producendo una nuova istanza. `TestResult` non è frozen (a differenza di `TargetContext`), quindi l'assegnazione diretta sarebbe tecnicamente possibile, ma `model_copy` è più esplicita nell'intento: "voglio una versione di questo risultato con il campo duration_ms popolato", senza implicare che l'oggetto originale sia stato mutato.

**La separazione tra `_execute_single_test` e `_check_fail_fast`** come metodi statici distinti rispecchia il principio di responsabilità singola a livello di metodo. `_execute_single_test` sa come eseguire un test e misurarne il tempo. `_check_fail_fast` sa quando interrompere la pipeline. Tenerli separati permette di testare la logica fail-fast indipendentemente dalla logica di esecuzione nei test E2E.

Il prossimo step è `src/report/builder.py` — l'aggregatore che trasforma il `ResultSet` in una struttura dati pronta per il rendering Jinja2. Attendo il tuo via libera.

---

## `src/report/builder.py`

**Ratio architetturale preliminare.**

`builder.py` separa due operazioni che potrebbero sembrare la stessa cosa ma non lo sono: **aggregazione** (trasformare un `ResultSet` in statistiche strutturate) e **rendering** (trasformare quelle statistiche in HTML). Questa separazione permette di testare la correttezza delle statistiche indipendentemente da Jinja2, e di cambiare il formato di output (HTML → PDF → JSON) senza toccare la logica di aggregazione.

Il tipo centrale di questo modulo è `ReportData` — un modello Pydantic che rappresenta tutti i dati necessari al template HTML, pre-calcolati e pre-formattati. Il renderer riceve un `ReportData` e non deve calcolare nulla: solo interpolare variabili nel template.

**La distribuzione per dominio** è la struttura più complessa da aggregare. Ogni dominio (0-7) deve mostrare i propri test con i propri risultati. La struttura `DomainSummary` raggruppa i `TestResult` per numero di dominio, calcola i contatori PASS/FAIL/SKIP/ERROR per dominio, e li espone come lista ordinata per il template.

---

**Nota architectturale esplicita per la tesi** — il commento inline in `_build_all_rows` documenta una tensione reale tra il vincolo di dipendenza unidirezionale e la completezza dei dati nel report. `TestResult` non include `test_name`, `priority`, `strategy`, `tags`, `cwe_id` perché questi sono metadati statici della classe, non dell'esecuzione. Il report ne ha bisogno. Le soluzioni sono tre:

1. **Corrente (adottata):** i campi mancanti vengono lasciati vuoti nel `TestResultRow`. Il template gestisce i valori mancanti con filtri Jinja2 (`{{ row.cwe_id or '-' }}`). Nessuna violazione del vincolo di dipendenza.

2. **Futura:** aggiungere a `TestResult` i campi di metadati statici, popolati dal costruttore `_make_pass/_make_fail` di `BaseTest`. Questo sposta il dato al punto di creazione, eliminando il problema.

3. **Scartata:** importare `BaseTest` in `builder.py` per accedere ai ClassVar. Viola il vincolo `report/ must not import from tests/`.

La soluzione 2 è quella corretta per una versione 1.1 del tool. Per la tesi, la soluzione 1 è documentata onestamente e non compromette la correttezza funzionale.

---

## Cosa aspettarsi dal modulo in esecuzione

```python
from src.report.builder import build_report_data, ReportData, ExecutiveSummary
from src.core.models import ResultSet, TestResult, TestStatus, Finding
from src.config.schema import ToolConfig

# --- Setup: ResultSet con risultati misti ---
rs = ResultSet()

rs.add_result(TestResult(
    test_id="0.1", status=TestStatus.PASS,
    message="All documented endpoints verified.",
))
rs.add_result(TestResult(
    test_id="1.1", status=TestStatus.FAIL,
    message="Unauthenticated access accepted.",
    findings=[Finding(
        title="Missing authentication enforcement",
        detail="GET /api/v1/users/me returned 200 without Authorization header.",
        references=["CWE-287", "OWASP-API2:2023"],
    )],
))
rs.add_result(TestResult(
    test_id="1.2", status=TestStatus.SKIP,
    message="No token available.",
    skip_reason="Prerequisite test 1.1 returned FAIL.",
))
rs.add_result(TestResult(
    test_id="6.2", status=TestStatus.ERROR,
    message="Unexpected ConnectionError during Admin API call.",
))

from datetime import datetime, timezone
rs.completed_at = datetime.now(timezone.utc)

# --- Costruzione config minimale ---
config = ToolConfig.model_validate({
    "target": {
        "base_url": "http://localhost:8000",
        "openapi_spec_url": "http://localhost:8000/api/swagger",
    }
})

# --- build_report_data ---
report = build_report_data(result_set=rs, run_id="apiguard-test-001", config=config)

assert isinstance(report, ReportData)
assert report.run_id == "apiguard-test-001"
assert report.executive_summary.fail_count == 1
assert report.executive_summary.pass_count == 1
assert report.executive_summary.skip_count == 1
assert report.executive_summary.error_count == 1
assert report.executive_summary.total_finding_count == 1

# exit_code: c'e' un FAIL -> exit code 1
assert report.executive_summary.exit_code == 1
assert "FAIL" in report.executive_summary.exit_code_label

# Pass rate: 1 PASS su 3 eseguiti (PASS + FAIL + ERROR), SKIP escluso
assert report.executive_summary.pass_rate_pct == round(1/3 * 100, 1)

# Domain summaries: domini 0, 1, 6 (quelli con test attivi)
domain_numbers = [d.domain for d in report.domains]
assert 0 in domain_numbers
assert 1 in domain_numbers
assert 6 in domain_numbers

# Domain 1: 1 FAIL, 1 SKIP
domain_1 = next(d for d in report.domains if d.domain == 1)
assert domain_1.fail_count == 1
assert domain_1.skip_count == 1
assert domain_1.has_failures is True
assert domain_1.total_finding_count == 1

# all_rows ordinati per test_id
assert [r.test_id for r in report.all_rows] == ["0.1", "1.1", "1.2", "6.2"]

# ReportData e' frozen
from pydantic import ValidationError
try:
    report.run_id = "mutated"
except ValidationError:
    print("ReportData is correctly frozen")

print(f"Pass rate: {report.executive_summary.pass_rate_pct}%")
print(f"Exit code: {report.executive_summary.exit_code} — {report.executive_summary.exit_code_label}")
```

---

Il prossimo step è `src/report/renderer.py` — il renderer Jinja2 che trasforma il `ReportData` in HTML. Attendo il tuo via libera.

---
## `src/report/renderer.py` e `src/report/templates/report.html`

**Ratio architetturale preliminare.**

Il renderer ha una responsabilità singola e precisa: prendere un `ReportData` frozen, caricare il template Jinja2, renderizzarlo, e scrivere il file HTML su disco. Non calcola nulla, non interpreta risultati, non formatta dati — tutto questo è già fatto da `builder.py`.

**Perché il template vive in `src/report/templates/` e non come stringa inline nel codice.** Un template HTML inline in una stringa Python è impossibile da mantenere oltre le venti righe. Jinja2's `FileSystemLoader` carica il template dal filesystem, il che permette di modificare l'aspetto del report senza toccare il codice Python — separazione netta tra presentazione e logica.

**La strategia di auto-contenimento del report HTML.** Il report deve essere un singolo file leggibile offline, senza dipendenze da CDN o file esterni. CSS e JavaScript sono quindi inline nel template. Questa scelta è deliberata per il contesto accademico: il report viene allegato alla tesi o consegnato come deliverable, e deve essere apribile in qualsiasi browser senza connettività di rete.

---

### `src/report/renderer.py`


---

## Cosa aspettarsi dal modulo in esecuzione

```python
from pathlib import Path
from src.report.builder import build_report_data
from src.report.renderer import render_html_report
from src.core.models import ResultSet, TestResult, TestStatus, Finding
from src.config.schema import ToolConfig
from datetime import datetime, timezone

# Setup ResultSet di test
rs = ResultSet()
rs.add_result(TestResult(
    test_id="0.2",
    status=TestStatus.PASS,
    message="Gateway correctly returns 404 for unregistered paths.",
))
rs.add_result(TestResult(
    test_id="1.1",
    status=TestStatus.FAIL,
    message="Unauthenticated access to protected endpoint accepted.",
    findings=[Finding(
        title="Missing authentication enforcement on GET /api/v1/user",
        detail=(
            "GET /api/v1/user without Authorization header returned "
            "HTTP 200 with full user object. Expected: HTTP 401 Unauthorized."
        ),
        references=["CWE-287", "OWASP-API2:2023"],
        evidence_ref="1.1_001",
    )],
))
rs.add_result(TestResult(
    test_id="4.1",
    status=TestStatus.SKIP,
    message="Rate limit probe skipped.",
    skip_reason="No authenticated endpoint available for probing.",
))
rs.completed_at = datetime.now(timezone.utc)

config = ToolConfig.model_validate({
    "target": {
        "base_url": "http://localhost:8000",
        "openapi_spec_url": "http://localhost:8000/api/swagger",
    }
})

report_data = build_report_data(rs, "apiguard-test-render-001", config)

output = Path("/tmp/test_report.html")
render_html_report(report_data, output)

assert output.exists()
content = output.read_text(encoding="utf-8")

# Verifica contenuto HTML
assert "APIGuard Assessment Report" in content
assert "apiguard-test-render-001" in content
assert "badge-fail" in content
assert "badge-pass" in content
assert "CWE-287" in content
assert "OWASP-API2:2023" in content
assert "1.1_001" in content
assert "Rate limit probe skipped" in content

print(f"Report generated: {output} ({len(content)} chars)")
print("Open in browser: file:///tmp/test_report.html")
```

---

Due dettagli rilevanti per la tesi.

**`StrictUndefined` come policy di errore Jinja2.** Il default di Jinja2 è `Undefined`, che sostituisce silenziosamente le variabili mancanti con una stringa vuota. In un report di sicurezza, una stringa vuota dove dovrebbe esserci un finding detail è un errore silenzioso potenzialmente grave. `StrictUndefined` trasforma ogni variabile non definita in un `UndefinedError` esplicito durante il rendering, garantendo che il report sia o completamente corretto o non generato affatto — non parzialmente sbagliato.

**`autoescape=select_autoescape(["html"])`** è la protezione XSS del report. I `Finding.detail` documentano payload di attacco: un finding su test 3.1 potrebbe contenere `<script>alert('XSS')</script>` nel campo `detail` perché è esattamente il payload testato. Senza autoescape, questo payload verrebbe eseguito nel browser quando l'analista apre il report. Con autoescape, viene renderizzato come `&lt;script&gt;alert(&#39;XSS&#39;)&lt;/script&gt;` — visibile come testo, non eseguibile.

Il prossimo step è `src/cli.py` — l'entry point Typer che espone il tool come comando CLI. Attendo il tuo via libera.

---

## `src/cli.py`

**Ratio architetturale preliminare.**

`cli.py` è il confine tra il mondo esterno (shell, CI/CD, utente) e il tool. La sua responsabilità è minimale e precisa: parsare gli argomenti della riga di comando, configurare il sistema di logging strutturato, istanziare l'`AssessmentEngine`, e tradurre il suo exit code in una chiamata a `sys.exit()`.

Nessuna logica di business vive qui. Qualsiasi tentazione di aggiungere logica in `cli.py` va resistita: se una funzionalità non riguarda il parsing degli argomenti o la configurazione dell'ambiente di processo, appartiene all'engine o a un modulo specifico.

**Perché Typer e non argparse.** Typer costruisce l'interfaccia CLI da type hints Python standard. Un parametro annotato come `Path` produce automaticamente un argomento CLI che valida l'esistenza del file e lo converte in oggetto `Path`. Questo elimina la boilerplate di argparse e mantiene la CLI type-safe staticamente con mypy.

**La configurazione di `structlog`.** Il logging strutturato deve essere configurato una sola volta, all'avvio del processo, prima di qualsiasi altra operazione. `cli.py` è il punto corretto: è il primo modulo eseguito. La configurazione produce output JSON in modalità machine-readable (`--log-format json`) o output colorato e human-readable in modalità console (default), selezionabile via flag CLI per l'integrazione CI/CD.


---

## Cosa aspettarsi dal modulo in esecuzione

```bash
# Dopo pip install -e . nel venv:

# Help principale
apiguard --help

# Help del comando run
apiguard run --help

# Versione
apiguard version

# Validazione config senza assessment
apiguard validate-config --config config.yaml

# Assessment completo con banner e log console (default)
apiguard run --config config.yaml

# Assessment per CI/CD: JSON log, no banner, exit code leggibile dallo script
apiguard run --config config.yaml --log-format json --no-banner
echo "Exit code: $?"

# Solo test P0 Black Box (esempio di scope ridotto)
# (min_priority e strategies si configurano in config.yaml, non in CLI)
apiguard run --config config.yaml --log-level debug
```

```python
# Test del modulo in Python diretto
from src.cli import LogFormat, LogLevel, _configure_logging, _filter_duration_display

# Configurazione logging: idempotente, chiamabile più volte
_configure_logging(LogFormat.CONSOLE, LogLevel.INFO)
_configure_logging(LogFormat.JSON, LogLevel.DEBUG)
_configure_logging(LogFormat.CONSOLE, LogLevel.WARNING)

# Verifica enum valori
assert LogFormat.CONSOLE.value == "console"
assert LogFormat.JSON.value == "json"
assert LogLevel.DEBUG.value == "debug"
assert LogLevel.INFO.value == "info"
```

---

Tre dettagli rilevanti per la tesi.

**Il ritardo dell'import di `AssessmentEngine`** all'interno della funzione `run_assessment()` invece che al top-level del modulo è intenzionale. `structlog.configure()` deve essere chiamato prima che qualsiasi modulo usi `structlog.get_logger()` per emettere log. Se `engine.py` (e tutti i moduli che importa) venisse importato al top-level di `cli.py`, i loro `structlog.get_logger(__name__)` a livello di modulo verrebbero eseguiti prima di `_configure_logging()`, producendo log con il pipeline di default non configurato. Ritardando l'import a dopo `_configure_logging()`, si garantisce che ogni logger del tool usi il pipeline correttamente configurato.

**`raise typer.Exit(code=exit_code)`** invece di `sys.exit(exit_code)` è la pratica corretta con Typer. `sys.exit()` solleva `SystemExit` che Typer cattura e gestisce internamente, potenzialmente sovrascrivendo il codice con 0. `typer.Exit` è l'eccezione che Typer si aspetta di ricevere dai comandi per impostare il codice di uscita del processo senza interferenze.

**Il comando `validate-config`** come sottocomando separato da `run` segue il principio di responsabilità singola a livello di UX. Un operatore che vuole verificare la configurazione prima di lanciare un assessment in produzione non deve eseguire l'intero pipeline — solo la Phase 1. Questo è particolarmente utile in CI/CD dove la validazione della config può essere un job separato che blocca il deployment se la config è invalida, senza consumare il budget di rate limit del target con un assessment fallito a metà.

---

## Riepilogo dello stato del progetto

Con `cli.py` completato, il **core del tool è architetturalmente completo**. Tutti i layer della pipeline sono implementati:

```
src/
├── cli.py                    ✓ Entry point CLI (Typer)
├── engine.py                 ✓ Orchestratore 7 fasi
├── core/
│   ├── exceptions.py         ✓ Gerarchia eccezioni
│   ├── models.py             ✓ Modelli Pydantic condivisi
│   ├── evidence.py           ✓ EvidenceStore (deque FIFO)
│   ├── context.py            ✓ TargetContext + TestContext
│   ├── dag.py                ✓ DAGScheduler (graphlib)
│   └── client.py             ✓ SecurityClient (httpx + tenacity)
├── config/
│   ├── schema.py             ✓ ToolConfig Pydantic schema
│   └── loader.py             ✓ YAML + env interpolation
├── discovery/
│   ├── openapi.py            ✓ Fetch + deref + validate
│   └── surface.py            ✓ AttackSurface builder
├── tests/
│   ├── base.py               ✓ BaseTest ABC
│   ├── registry.py           ✓ Discovery dinamico
│   └── strategy.py           ✓ Re-export TestStrategy
└── report/
    ├── builder.py             ✓ ReportData aggregator
    ├── renderer.py            ✓ Jinja2 HTML renderer
    └── templates/report.html  ✓ Template self-contained
```

Il prossimo step è l'implementazione dei test di dominio, partendo da `src/tests/domain_0/` (API Discovery, 3 test P0 Black Box). Attendo il tuo via libera.

---

## Domain 0 — API Discovery and Inventory Management

**Nota preliminare.** I tre test del Dominio 0 sono tutti P0 Black Box: non richiedono token, non richiedono Admin API, operano esclusivamente sulle informazioni derivate dall'`AttackSurface` e su richieste HTTP non autenticate. Sono il primo layer di verifica che qualsiasi attaccante esterno eseguirebbe.

Prima di ogni implementazione, descrivo il pattern comune a tutti i test di questo dominio: ogni `execute()` inizia con il guard `_requires_attack_surface()`, poi costruisce la lista di endpoint da testare dall'`AttackSurface`, poi itera sugli endpoint eseguendo richieste via `client.request()`, e infine accumula i `Finding` prima di ritornare un unico `TestResult`.
---

## Cosa aspettarsi dai test in esecuzione

```python
# Verifica strutturale (no stack Docker richiesto)
from src.tests.domain_0.test_0_1_shadow_api_discovery import Test_0_1_ShadowApiDiscovery
from src.tests.domain_0.test_0_2_deny_by_default import Test_0_2_DenyByDefault
from src.tests.domain_0.test_0_3_deprecated_api_enforcement import Test_0_3_DeprecatedApiEnforcement
from src.tests.base import BaseTest
from src.core.models import TestStrategy

for cls in [Test_0_1_ShadowApiDiscovery,
            Test_0_2_DenyByDefault,
            Test_0_3_DeprecatedApiEnforcement]:
    assert issubclass(cls, BaseTest)
    assert cls.has_required_metadata()
    assert cls.priority == 0
    assert cls.strategy == TestStrategy.BLACK_BOX
    assert cls.domain == 0
    assert cls.depends_on == []
    print(f"{cls.test_id}: metadata OK")

# Discovery dinamica: i tre test devono essere trovati dal registry
from src.tests.registry import TestRegistry
from src.core.models import TestStrategy as TS

registry = TestRegistry()
active = registry.discover(
    min_priority=0,
    enabled_strategies={TS.BLACK_BOX},
)
domain_0_ids = {t.__class__.test_id for t in active if t.__class__.domain == 0}
assert "0.1" in domain_0_ids
assert "0.2" in domain_0_ids
assert "0.3" in domain_0_ids
print(f"Domain 0 tests discovered: {sorted(domain_0_ids)}")
```

---

Tre dettagli rilevanti per la tesi.

**Il trattamento dei path con template parameters in 0.3.** Un path come `/api/v1/repos/{owner}/{repo}` non può essere sondato in Black Box senza conoscere valori validi di `{owner}` e `{repo}`. Invece di omettere silenziosamente questi endpoint dal risultato (il che produrrebbe un PASS parzialmente falso), il test genera un `Finding` informativo che documenta la lacuna di coverage per l'analista. Questa trasparenza è più corretta accademicamente di un PASS che nasconde endpoint non verificati.

**Il `store.pin_evidence(record)` per le risposte 410** in 0.3 è un esempio del secondo meccanismo di storage dell'`EvidenceStore`. Una risposta `410 Gone` è un successo — non produce un FAIL — ma è un'evidenza interessante da conservare nel report perché dimostra che il Gateway sta effettivamente applicando il sunset enforcement. Il `pin` la rende visibile in `evidence.json` senza che il test debba classificarla come FAIL.

**La wordlist di 0.1 è intenzionalmente conservativa.** SecLists `API-endpoints.txt` contiene oltre 10.000 entry. Usarla integralmente produrrebbe centinaia di richieste HTTP per ogni assessment run, saturando i log del target e rischiando di innescare alert di sicurezza. I 33 path selezionati coprono le categorie più critiche (actuator, debug, admin, swagger, internal) mantenendo il test responsabile verso l'ambiente.

Il prossimo step è `src/tests/domain_1/` — i test di Identity e Authentication (6 test, P0-P3). Attendo il tuo via libera.
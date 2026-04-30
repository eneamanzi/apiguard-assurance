
---

# ADR-001 — Integrazione del Layer External Tool Testing

**Documento:** Architectural Decision Record
**Versione:** 1.1
**Stato:** Approvato
**Changelog v1.1:** Integrate le osservazioni di revisione: timeout obbligatorio su `BaseConnector.run()` (§3.2), sanitizzazione del `raw_output` prima del pin in `EvidenceStore` (§4.3), nota implementativa sul Docker network mapping (§6).
**Impatto su:** `Implementazione.md` §2, §4.5, §4.6, §4.7, §5, §6, §8

---

## 1. Contesto e Motivazione

`Implementazione.md` v4.0 definisce un tool composto esclusivamente da **Native Tests**: test Python che operano via `SecurityClient` (httpx) e producono `TestResult` con evidenze HTTP strutturate. Questa architettura copre correttamente la maggior parte dei 26 test della metodologia.

Esiste però una categoria di controlli di sicurezza per cui tool specializzati dell'ecosistema open source (es. `testssl.sh` per l'analisi TLS, `nuclei` per template di vulnerabilità note, `ffuf` per fuzzing di path) offrono una profondità di analisi non replicabile efficientemente in Python puro. Reimplementare queste capacità sarebbe un lavoro ingegneristico scorretto e metodologicamente discutibile.

La modifica introduce un secondo tipo di test — **External Tool Tests** — che wrappa esecuzioni di binari esterni traducendo il loro output nel formato `TestResult` già definito. Il sistema esistente non viene alterato: i due tipi di test coesistono, vengono scoperti e ordinati dallo stesso DAG, appaiono nel medesimo report.

**Vincolo non negoziabile:** il tool deve funzionare integralmente anche in assenza di qualsiasi binario esterno. Gli External Tool Tests degradano gracefully a `SKIP` se il tool richiesto non è rilevabile a runtime.

---

## 2. Modifiche alla Struttura del Progetto

### 2.1 Nuove Directory

La struttura radice acquisisce due nuove directory sotto `src/`:

```
src/
├── connectors/                  ← NUOVO — wrapper sottili verso binari esterni
│   ├── base.py                  ← BaseConnector ABC + ConnectorResult model
│   ├── testssl.py               ← wrapper testssl.sh
│   ├── nuclei.py                ← wrapper nuclei
│   └── ffuf.py                  ← wrapper ffuf
│
├── external_tests/              ← NUOVO — External Tool Tests, struttura parallela a tests/
│   ├── base.py                  ← ExternalToolTest ABC (estende BaseTest)
│   ├── registry.py              ← ExternalTestRegistry
│   ├── tls/
│   │   └── ext_test_tls_analysis.py
│   ├── fuzzing/
│   │   └── ext_test_shadow_api_fuzzing.py
│   └── vuln_scan/
│       └── ext_test_nuclei_api.py
│
└── [tutto il resto invariato]
```

**Motivazione della separazione `external_tests/` da `tests/`:** le due popolazioni hanno dipendenze strutturalmente diverse. I Native Tests dipendono da `SecurityClient`. Gli External Tool Tests dipendono da binari di sistema. Tenerli separati rende immediatamente visibile la natura della dipendenza, semplifica il filtraggio per chi vuole eseguire solo i test nativi, e permette al registry di gestirli con logiche di discovery distinte pur unificandoli nel DAG.

**Convenzione di naming obbligatoria per External Tool Tests:**

```
external_tests/<categoria>/ext_test_<descrizione>.py
```

Il prefisso `ext_test_` (anziché `test_`) è la condizione tecnica che permette al registry di distinguere i due tipi durante il discovery.

---

## 3. Nuovi Componenti

### 3.1 `ConnectorResult` — Il Dato Grezzo del Tool Esterno

Vive in `connectors/base.py`. È un modello Pydantic che rappresenta l'output strutturato di un binario esterno **prima** di qualsiasi valutazione di oracle. Il connector non decide se qualcosa è un FAIL: restituisce dati, il test valuta.

```
ConnectorResult
├── tool_name: str            ← nome del binario (es. "testssl.sh")
├── tool_version: str | None  ← versione rilevata a runtime se disponibile
├── raw_output: dict          ← output JSON del tool, già parsato
├── exit_code: int            ← exit code del processo
├── execution_time_ms: int    ← durata dell'esecuzione in millisecondi
└── timed_out: bool           ← True se il processo è stato terminato per timeout
```

Il campo `raw_output` è tipizzato `dict` con `Any` esplicitamente giustificato: la struttura varia per tool e viene poi discriminata dal test specifico che conosce lo schema atteso. Il campo `timed_out` permette al test chiamante di distinguere un timeout da un errore organico del tool e produrre un messaggio di `SKIP` o `ERROR` semanticamente corretto.

### 3.2 `BaseConnector` — Il Contratto di Ogni Connector

Vive in `connectors/base.py`. ABC con tre responsabilità: verificare la disponibilità del binario, scoprire la sua versione, eseguirlo con un timeout esplicito e restituire un `ConnectorResult`.

```python
class BaseConnector(ABC):
    BINARY_NAME: ClassVar[str]        # nome del binario nel PATH
    SERVICE_ENV_VAR: ClassVar[str]    # var env per discovery via container/servizio HTTP
    DEFAULT_TIMEOUT_SECONDS: ClassVar[int]  # timeout di default, override via config.yaml

    def is_available(self) -> bool    # shutil.which() o os.getenv() — mai solleva eccezioni
    def get_version(self) -> str | None

    @abstractmethod
    def run(
        self,
        target_url: str,
        timeout_seconds: int,         # OBBLIGATORIO — non ha valore di default nel metodo
        **kwargs: Any,
    ) -> ConnectorResult
    # implementata dalla sottoclasse; solleva ExternalToolError se il processo fallisce
    # se il timeout viene superato: termina il processo, ritorna ConnectorResult con timed_out=True
```

**Motivazione del timeout obbligatorio nella firma:** i tool esterni girano fuori dal controllo del GIL Python. Un `testssl.sh` bloccato su un endpoint che non risponde o un `ffuf` incastrato su una route con redirect infiniti paralizzerebbero l'intera pipeline senza possibilità di recupero. Il timeout non è un parametro opzionale di convenienza: è un requisito di solidità equivalente al timeout del `SecurityClient` sui Native Tests. Renderlo obbligatorio nella firma — senza valore di default — forza ogni sottoclasse a gestirlo esplicitamente tramite `subprocess.run(timeout=timeout_seconds)`, sollevando `ExternalToolError` in caso di `subprocess.TimeoutExpired`. Il valore concreto del timeout viene letto dal `config.yaml` e passato dall'external test al momento della chiamata a `run()`.

**Meccanismo di discovery a runtime** — due canali in cascata:

1. `shutil.which(BINARY_NAME)` → tool installato localmente nel PATH
2. `os.getenv(SERVICE_ENV_VAR)` → tool esposto come servizio HTTP (caso Docker Compose con container dedicati)

Se entrambi restituiscono `None`, `is_available()` ritorna `False`. Il test produce `SKIP` senza nemmeno istanziare il connector.

### 3.3 `ExternalToolTest` — Il Contratto degli External Test

Vive in `external_tests/base.py`. Estende `BaseTest` aggiungendo gli attributi e il comportamento specifici della dipendenza esterna. Eredita integralmente il contratto di `BaseTest` (attributi obbligatori, firma di `execute()`, gestione eccezioni): il DAG e il report lo trattano in modo identico a un Native Test.

```python
class ExternalToolTest(BaseTest, ABC):
    # Attributi aggiuntivi obbligatori (oltre agli 8 di BaseTest)
    required_connector: ClassVar[type[BaseConnector]]  # classe connector da usare

    # Metodo di convenienza — non abstractmethod, implementazione default
    def _check_and_skip(self) -> TestResult | None:
        """
        Ritorna TestResult(SKIP) se il connector non è disponibile,
        None se il connector è disponibile e si può procedere.
        Chiamato all'inizio di execute() da ogni sottoclasse concreta.
        """

    @abstractmethod
    def execute(
        self,
        target: TargetContext,
        context: TestContext,
        client: SecurityClient,   # ricevuto per compatibilità; usato opzionalmente
        store: EvidenceStore,
    ) -> TestResult: ...
```

**Nota sul parametro `client`:** gli External Tool Tests ricevono `SecurityClient` nella firma di `execute()` per mantenere la compatibilità totale con l'engine. Alcuni test potrebbero usarlo per richieste di setup preliminari; altri lo ignoreranno. Non è un problema architetturale.

### 3.4 `ExternalTestRegistry` — Discovery degli External Test

Vive in `external_tests/registry.py`. Replica la logica di `TestRegistry` ma scansiona `external_tests/` cercando file con prefisso `ext_test_` e istanziando sottoclassi concrete di `ExternalToolTest`. Applica gli stessi filtri per `priority` e `strategy`. Produce una lista di test compatibile con il DAG.

---

## 4. Modifiche ai Componenti Esistenti

### 4.1 `engine.py` — Fusione delle Due Popolazioni

L'engine acquisisce una singola modifica: nella Fase 4, dopo il discovery dei Native Tests via `TestRegistry`, interroga `ExternalTestRegistry` e fonde le due liste prima di passarle al `DAGScheduler`. Il DAG non sa né gli importa se un test è native o external: vede solo `BaseTest` e relazioni `depends_on`.

```
FASE 4 — Test Discovery e Scheduling (modifica)

TestRegistry().discover()         → lista Native Tests
ExternalTestRegistry().discover() → lista External Tests
merged_tests = native_tests + external_tests   ← NUOVO
DAGScheduler(merged_tests).build()             → lista batch ordinati
```

Nessuna altra modifica all'engine. La solidità dell'esecuzione (un test che crasha non ferma gli altri) si applica identicamente agli external test: `ExternalToolError` viene catturata dentro `execute()` e trasformata in `TestResult(ERROR)` prima che l'engine la veda.

### 4.2 `config/schema.py` — Nuova Sezione `external_tools`

Il `config.yaml` acquisisce una sezione opzionale `external_tools`. Se la sezione è assente, il comportamento di default è: esegui se disponibile, SKIP altrimenti.

```yaml
# Aggiunta opzionale al config.yaml
external_tools:
  enabled: true                    # master switch — false disabilita tutti gli external test
  testssl:
    enabled: true
    timeout_seconds: 120           # timeout esplicito passato a BaseConnector.run()
    extra_flags: "--quiet"
  nuclei:
    enabled: true
    timeout_seconds: 300
    template_tags: ["api", "token"]
  ffuf:
    enabled: false
    timeout_seconds: 180
```

Il campo `timeout_seconds` per ogni tool è obbligatorio nel schema Pydantic se il tool è `enabled: true`. Un tool abilitato senza timeout esplicito produce `ConfigurationError` al bootstrap (Fase 1, bloccante) — esattamente come una credenziale mancante. Questo garantisce che nessun external test possa essere eseguito senza un timeout configurato, rendendo impossibile dimenticare accidentalmente questa protezione.

### 4.3 `EvidenceStore` — Evidenze da Tool Esterni con Sanitizzazione

Gli External Tool Tests non producono transazioni HTTP classiche ma devono allegare evidenze ai loro `Finding`. Il meccanismo di `pinned` già esistente viene esteso con un nuovo metodo:

```python
def pin_artifact(self, label: str, data: dict) -> str:
    """
    Serializza e salva un artefatto arbitrario (es. ConnectorResult.raw_output)
    come evidenza allegabile a un Finding. Ritorna l'evidence_ref da usare in Finding.
    Il payload viene sanitizzato prima del salvataggio.
    """
```

**Sanitizzazione obbligatoria del `raw_output`:** tool come `ffuf` o `nuclei` includono nei loro output JSON frammenti di response HTTP del target, che possono contenere token JWT, cookie di sessione, o header `Authorization` catturati durante la scansione. Prima che `raw_output` venga scritto nell'`EvidenceStore`, la funzione di sanitizzazione già definita nelle best practice del progetto viene applicata al dizionario ricorsivamente: ogni valore stringa che corrisponde a pattern noti di credenziali (`Bearer `, `token`, `password`, `api_key`, `Authorization`) viene sostituito con `[REDACTED]`. Questa sanitizzazione avviene all'interno di `pin_artifact()` — non è responsabilità del test chiamante applicarla, ma dell'`EvidenceStore` garantirla su tutto ciò che entra nel buffer.

### 4.4 `EvidenceStore.maxlen` — Revisione del Limite

Con l'aggiunta degli External Tool Tests, la stima originale di 100 elementi va aggiornata. Un report `testssl.sh` completo può avere 200+ campi JSON; un output `nuclei` può contenere decine di finding per template. Il limite viene portato a `200` mantenendo invariata la logica FIFO di scarto automatico.

---

## 5. Nuove Eccezioni

La gerarchia in `core/exceptions.py` acquisisce due nuovi tipi:

```
ToolBaseError
├── [eccezioni esistenti invariate]
├── ExternalToolNotFoundError  → is_available() == False
│                                 usata internamente prima di produrre SKIP
│                                 non propagata all'engine
└── ExternalToolError          → il binario è presente ma l'esecuzione fallisce:
                                  exit code non-zero, output non parsabile,
                                  timeout superato (subprocess.TimeoutExpired)
                                  → catturata in execute() → TestResult(ERROR)
```

`ExternalToolError` segue lo stesso pattern di `SecurityClientError`: viene catturata dentro `execute()` e trasformata in `TestResult(ERROR, message=str(e))`. Il messaggio di errore include il nome del tool, l'exit code, e se il processo è stato terminato per timeout — informazioni sufficienti per il debugging senza esporre output potenzialmente sensibili nei log.

---

## 6. Deployment e Discovery Runtime

Il tool supporta tre configurazioni di deployment senza modifiche al codice:

| Configurazione | Meccanismo di discovery | Chi la usa |
|---|---|---|
| **Standalone senza external tools** | `is_available()` → False per tutti → tutti gli external test SKIP | Utente base, CI pipeline minimale |
| **Standalone con binari locali** | `shutil.which()` trova i binari nel PATH dell'host o del container | Utente che installa i tool sul proprio sistema |
| **Docker Compose potenziato** | Variabili d'ambiente `TESTSSL_SERVICE_URL`, `NUCLEI_SERVICE_URL` puntano a container dedicati; il connector fa HTTP invece di subprocess | Setup avanzato con compose opzionale |

Il `docker-compose.external-tools.yml` viene distribuito con il repository come file separato dal compose principale dell'ambiente di test Forgejo/Kong ed è documentato come componente opzionale.

**Nota implementativa critica sul Docker network addressing:** quando un tool esterno gira nel proprio container Docker, la stringa `localhost` o `127.0.0.1` risolve all'interno del container del tool, non al Forgejo/Kong target. Il `TargetContext` fornito agli external test deve quindi esporre l'indirizzo del target nella forma corretta per il contesto di esecuzione. La soluzione è un campo `effective_base_url: AnyHttpUrl` nel `TargetContext` che l'engine popola al bootstrap leggendo la variabile d'ambiente `APIGUARD_TARGET_EFFECTIVE_URL` se presente, altrimenti usando il `base_url` del `config.yaml`. In un setup Docker Compose, questa variabile viene impostata nel `docker-compose.external-tools.yml` con il nome del servizio Compose (es. `http://kong-gateway:8000`). In tutti gli altri setup, il campo coincide con `base_url` e il comportamento è identico all'attuale. Nessuna logica condizionale nell'engine: la distinzione è interamente nel valore di configurazione.

---

## 7. Invarianti che Non Cambiano

Per chiarezza esplicita, questi aspetti dell'architettura rimangono **intatti**:

- La regola di dipendenza monodirezionale (`core/` non importa da nessun test o connector)
- Il modello di esecuzione sequenziale — nessun threading introdotto
- Il contratto `BaseTest.execute()` — firma identica, return type identico
- Il meccanismo di fail-fast su P0 — si applica anche agli external test
- La separazione `TargetContext` (frozen) / `TestContext` (mutable)
- Il principio No Placeholder: ogni connector implementato è completo e funzionante

---

## 8. Impatto sul Report — Pattern Domain-Centric Split

### 8.1 Principio di Presentazione

Il report adotta il pattern **Domain-Centric Split**: i risultati sono organizzati per Dominio (come nella metodologia), ma all'interno di ciascun Dominio i risultati vengono separati visivamente in due blocchi distinti — Controlli Nativi e Analisi Tool Esterni. Questo risolve simultaneamente due requisiti che soluzioni alternative soddisfano solo parzialmente:

- **Distinzione netta dell'origine:** rende immediatamente evidente al lettore (e al relatore di tesi) cosa è prodotto dal motore Python nativo e cosa è delegato a tool specializzati. Non c'è ambiguità su dove finisce il contributo dell'autore e dove inizia quello dell'ecosistema esterno.
- **Coerenza della navigazione:** chi vuole la panoramica completa del Dominio 0 trova tutto in un unico punto del documento, senza saltare tra una Parte 1 e una Parte 2 fisicamente separate.

Il pattern è graficamente analogo alla struttura dei Penetration Test report professionali, dove le scoperte manuali e quelle degli scanner automatici appaiono sotto la stessa intestazione di vulnerabilità ma con label di provenienza distinti.

### 8.2 Struttura Visiva per Dominio

Ogni sezione del report segue questo schema ricorrente:

```
DOMINIO N: <Nome Dominio>
│
├── CONTROLLI NATIVI (APIGuard Engine)
│   ├── Test N.X — <Nome Test>    [ PASS / FAIL / SKIP / ERROR ]
│   ├── Test N.Y — <Nome Test>    [ PASS ]
│   └── Test N.Z — <Nome Test>    [ DELEGATO A TOOL ESTERNO ]
│                                    ↑ placeholder esplicito quando il controllo
│                                      non ha un native test corrispondente
│
└── ANALISI TOOL ESTERNI (External Scanners)
    ├── Tool: ffuf — WordList: SecLists API-endpoints.txt
    │   ├── FINDING: Path non documentato rilevato: /api/v2/admin
    │   └── FINDING: Path non documentato rilevato: /health
    └── [oppure: "Nessun tool esterno configurato per questo dominio"]
```

La sezione "ANALISI TOOL ESTERNI" appare sotto ogni Dominio indipendentemente dal fatto che un external test sia configurato: se nessun tool copre quel dominio, il blocco mostra esplicitamente `Nessun tool esterno configurato per questo dominio` — informazione utile perché comunica intenzionalità, non assenza accidentale.

Il placeholder `DELEGATO A TOOL ESTERNO` nella sezione nativa appare quando la metodologia prevede un controllo per quel test ID ma nessun Native Test lo implementa. Questo placeholder è generato dal `ReportBuilder` confrontando la lista dei `test_id` attesi dalla metodologia con quelli presenti nel `ResultSet` — non è hardcoded nel template.

### 8.3 Implementazione HTML — Pattern Accordion

Il template HTML (`report/templates/report.html`) implementa il Domain-Centric Split tramite l'elemento nativo HTML `<details>/<summary>`, senza dipendenze JavaScript esterne. Questo garantisce che il report sia navigabile in qualsiasi browser, funzioni offline, e si degradi gracefully in PDF (dove i `<details>` si espandono tutti per default nella stampa CSS via `@media print { details { display: block; } }`).

La struttura HTML generata da Jinja2 per ogni dominio è:

```html
<section class="domain" id="domain-{{ domain.id }}">
  <h2>Dominio {{ domain.id }}: {{ domain.name }}</h2>

  <details open>  <!-- aperto di default per i FAIL, chiuso per i PASS -->
    <summary class="section-native">
      Controlli Nativi (APIGuard Engine)
      <span class="badge-summary">
        {{ domain.native_pass }} PASS /
        {{ domain.native_fail }} FAIL /
        {{ domain.native_skip }} SKIP
      </span>
    </summary>
    <div class="results-native">
      {% for result in domain.native_results %}
        {# rendering del singolo TestResult nativo #}
      {% endfor %}
    </div>
  </details>

  <details>
    <summary class="section-external">
      Analisi Tool Esterni (External Scanners)
      <span class="badge-summary">
        {{ domain.external_findings }} finding
      </span>
    </summary>
    <div class="results-external">
      {% if domain.external_results %}
        {% for result in domain.external_results %}
          {# rendering del singolo TestResult esterno con tool_name in evidenza #}
        {% endfor %}
      {% else %}
        <p class="no-external">
          Nessun tool esterno configurato per questo dominio.
        </p>
      {% endif %}
    </div>
  </details>

</section>
```

Il blocco nativo è `open` di default solo se contiene almeno un `FAIL` o `ERROR` — logica gestita da Jinja2 nel template. Il blocco esterno è sempre collassato di default: i finding degli scanner tendono ad essere verbosi e l'utente li esplora intenzionalmente.

### 8.4 Modifiche a `report/builder.py`

Il `ReportBuilder` acquisisce una nuova fase di aggregazione prima del rendering: dopo aver raccolto tutti i `TestResult` dal `ResultSet`, li partiziona per `domain` e per `source`, producendo una struttura `DomainReport` che il template consuma direttamente.

```
ResultSet (lista flat di TestResult)
    │
    ▼
ReportBuilder.build()
    │
    ├── Partiziona per domain (0–7)
    │   └── Per ogni domain, partiziona per source ("native" / "external")
    │
    ├── Genera placeholder "DELEGATO" per test_id metodologia senza native result
    │
    └── Produce lista DomainReport → passata a renderer.py → Jinja2
```

Il modello `DomainReport` è un Pydantic model (non frozen, costruito durante l'aggregazione):

```
DomainReport
├── domain_id: int
├── domain_name: str
├── native_results: list[TestResult]      ← source == "native"
├── external_results: list[TestResult]    ← source == "external"
├── delegated_test_ids: list[str]         ← test_id senza native result
├── native_pass: int                      ← conteggi pre-calcolati per il template
├── native_fail: int
├── native_skip: int
├── native_error: int
└── external_findings: int               ← totale Finding negli external results
```

Questa struttura tiene tutta la logica di aggregazione in `builder.py`, mantenendo il template Jinja2 puramente presentazionale — nessuna logica condizionale complessa nel template, solo iterazione su dati già strutturati.

### 8.5 Il Campo `source` come Primitiva Architetturale

Il campo `source: Literal["native", "external"]` nel `TestResult` — già introdotto nell'ADR v1.0 come "scelta di presentazione non bloccante" — viene qui promosso a **primitiva architetturale del report layer**. Tutta la logica del Domain-Centric Split dipende da esso. Questo campo deve essere valorizzato correttamente alla creazione di ogni `TestResult`:

- `TestRegistry` imposta `source="native"` su tutti i test che istanzia
- `ExternalTestRegistry` imposta `source="external"` su tutti i test che istanzia

L'engine non tocca questo campo: lo riceve già valorizzato nel `TestResult` restituito da `execute()`.

---

## 9. Cosa NON è incluso in questa modifica

- Implementazione concreta dei connector (`testssl.py`, `nuclei.py`, `ffuf.py`)
- Implementazione concreta dei singoli external test
- Il `docker-compose.external-tools.yml`
- La funzione di sanitizzazione ricorsiva del `raw_output` (riuso della logica già definita nelle security best practice del progetto)

Questi vengono sviluppati in step successivi. Il prossimo step immediato è aggiornare `Implementazione.md` incorporando questo ADR, poi iniziare dallo scheletro di `connectors/base.py`.
[English version](README.en.md) | **Versione Italiana**

# APIGuard Assurance

**Automated Security Assessment Tool for REST APIs in Cloud Environments**

APIGuard Assurance is a CLI tool for security auditing of REST APIs protected by an API Gateway. It executes the APIGuard methodology — 8 domains, up to 29 verifiable security guarantees — against any target documented with an OpenAPI 3.x or Swagger 2.0 specification, producing an interactive HTML report and a formal, reproducible evidence archive.

> **Sei un contributor o sviluppatore?**
> Questo documento è rivolto a chi *usa* il tool. Se vuoi capire l'architettura interna, il modello dei dati, o come aggiungere un nuovo test, leggi **[`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md)**.

---

## Indice

1. [Valore aggiunto e casi d'uso](#1-valore-aggiunto-e-casi-duso)
2. [Requisiti e installazione](#2-requisiti-e-installazione)
3. [Configurazione](#3-configurazione)
4. [Utilizzo pratico](#4-utilizzo-pratico)
5. [Output dell'assessment](#5-output-dellassessment)
6. [Come funziona — Pipeline ad alto livello](#6-come-funziona--pipeline-ad-alto-livello)
7. [Domini e priorità dei test](#7-domini-e-priorità-dei-test)
8. [Codici di uscita](#8-codici-di-uscita)
9. [Struttura della repository](#9-struttura-della-repository)

---

## 1. Valore aggiunto e casi d'uso

L'auditing manuale di un API Gateway è lento, difficile da riprodurre e soggetto a omissioni sistematiche. APIGuard Assurance risolve questi problemi con un approccio formale, deterministico e documentato.

**Per i Security Auditors:**
- Esecuzione riproducibile dello stesso set di garanzie su qualsiasi target compatibile: stessi test, stesso ordine, stesso output.
- Tre livelli di privilegio — Black Box (nessuna credenziale), Grey Box (JWT validi per più ruoli), White Box (accesso Admin API) — configurabili indipendentemente per adattarsi al perimetro dell'engagement.
- Evidenza formale raccolta automaticamente: ogni violazione è corredata di request completa, response completa e un `record_id` che consente all'analista di riprodurre l'attacco senza alcun contesto aggiuntivo.
- Report HTML interattivo con audit trail completo di ogni transazione HTTP eseguita, incluse quelle PASS, come prova di copertura.

**Per i team di sviluppo e DevSecOps:**
- Integrazione nativa in pipeline CI/CD tramite output JSON strutturato (`apiguard_report.json`) e codici di uscita semantici.
- Logging strutturato in formato JSON (`--log-format json`) compatibile con Elasticsearch, Splunk, Datadog e aggregatori analoghi.
- Architettura zero-secret: le credenziali non compaiono mai in chiaro nei file di configurazione versionati.

---

## 2. Requisiti e installazione

**Requisiti di sistema:**
- Python 3.11 o superiore
- Accesso di rete al target API (proxy Gateway + eventuale Admin API)

**Installazione in modalità sviluppo (consigliata):**

```bash
git clone <url-repository>
cd apiguard-assurance

# Crea e attiva un virtual environment
python -m venv .venv
source .venv/bin/activate   # Linux/macOS
# .venv\Scripts\activate    # Windows

# Installa il pacchetto con tutte le dipendenze runtime
pip install -e .

# Verifica l'installazione
apiguard version
```

**Installazione con dipendenze di sviluppo (per contributor):**

```bash
pip install hatch
hatch env create dev
hatch run dev:pytest tests_e2e/ -v
```

**Strumenti di analisi statica:**

```bash
# Linting e formatting (ruff — sostituisce flake8 + isort + black)
hatch run dev:ruff check src/
hatch run dev:ruff format src/

# Type checking in modalità strict (mypy)
hatch run dev:mypy src/
```

---

## 3. Configurazione

La configurazione è separata in due strati distinti e deliberatamente disaccoppiati: parametri strutturali versionabili e segreti da ambiente.

### 3.1 `config.yaml` — parametri strutturali (versionabile)

```yaml
target:
  base_url: "http://localhost:8000"           # URL del proxy Gateway
  openapi_spec_url: "http://localhost:3000/swagger.v1.json"
  admin_api_url: "http://localhost:8001"      # Ometti per disabilitare test WHITE_BOX

credentials:
  # Le credenziali NON compaiono mai in chiaro qui.
  # I placeholder ${VAR} vengono risolti da variabili d'ambiente a runtime.
  admin_username: "${ADMIN_USERNAME}"
  admin_password: "${ADMIN_PASSWORD}"
  user_a_username: "${USER_A_USERNAME}"
  user_a_password: "${USER_A_PASSWORD}"
  user_b_username: "${USER_B_USERNAME}"
  user_b_password: "${USER_B_PASSWORD}"

execution:
  min_priority: 3        # 0 = solo P0 | 1 = P0+P1 | 2 = P0-P2 | 3 = tutti (default)
  strategies:
    - BLACK_BOX
    - GREY_BOX
    - WHITE_BOX
  fail_fast: false       # Se true, interrompe l'esecuzione al primo FAIL su test P0
  connect_timeout: 5.0
  read_timeout: 30.0
  max_retry_attempts: 3
  openapi_fetch_timeout_seconds: 60.0

output:
  directory: "outputs"   # Accetta percorsi relativi o assoluti; creata se non esiste

rate_limit_probe:
  max_requests: 150      # Massimo richieste per il probe empirico di rate limiting
  request_interval_ms: 50

tests:
  domain_1:
    max_endpoints_cap: 0 # 0 = testa tutti gli endpoint protetti (raccomandato)
```

### 3.2 File `.env` — segreti (non versionare)

```bash
# Copia il template e valorizza i campi
cp .env.example .env
```

```bash
# .env — variabili d'ambiente locali
ADMIN_USERNAME=thesis-admin
ADMIN_PASSWORD=<password-admin>
USER_A_USERNAME=user-a
USER_A_PASSWORD=<password-user-a>
USER_B_USERNAME=user-b
USER_B_PASSWORD=<password-user-b>
```

Il loader (`src/config/loader.py`) esegue l'interpolazione delle variabili d'ambiente **prima** del parsing YAML. Un placeholder non risolto (`${MISSING_VAR}`) produce un `ConfigurationError` che nomina esplicitamente la variabile mancante, rendendo la diagnosi immediata. Le variabili già presenti nell'ambiente del processo hanno la precedenza sul file `.env` (comportamento `override=False` di `load_dotenv`), il che rende il tool corretto per ambienti CI/CD che iniettano segreti tramite orchestratore.

### 3.3 Validazione della configurazione (senza avviare l'assessment)

```bash
apiguard validate-config --config config.yaml
```

Esegue esclusivamente la Fase 1 (caricamento e validazione) e ritorna exit code 0 se la configurazione è valida, 10 in caso contrario.

---

## 4. Utilizzo pratico

### Avvio dell'assessment

```bash
# Esecuzione standard (config.yaml nella working directory corrente)
apiguard run

# Config in percorso esplicito
apiguard run --config /etc/apiguard/config.yaml

# Output JSON per CI/CD — log machine-readable, nessun banner
apiguard run --log-format json --no-banner

# Debug verboso: ogni transazione HTTP viene loggata individualmente
apiguard run --log-level debug

# Sopprime il banner mantenendo log human-readable (utile in script)
apiguard run --no-banner
```

### Selezionare un sottoinsieme di test

La selezione avviene tramite `config.yaml`, non tramite argomenti CLI. Modifica i parametri `execution` per restringere il perimetro:

```yaml
# Solo test Black Box — nessuna credenziale richiesta
execution:
  min_priority: 0
  strategies:
    - BLACK_BOX

# Solo test critici P0 di tutte le strategie
execution:
  min_priority: 0
  strategies:
    - BLACK_BOX
    - GREY_BOX
    - WHITE_BOX
```

### Integrazione in pipeline CI/CD

```bash
#!/bin/bash
set -e

apiguard run \
  --config config.yaml \
  --log-format json \
  --no-banner

EXIT_CODE=$?

case $EXIT_CODE in
  0)  echo "CLEAN: nessuna violazione rilevata"; exit 0 ;;
  1)  echo "FAIL: almeno una garanzia di sicurezza e violata"; exit 1 ;;
  2)  echo "ERROR: almeno una verifica non e stata completata"; exit 2 ;;
  10) echo "INFRA: errore di infrastruttura, assessment non completato"; exit 10 ;;
esac
```

---

## 5. Output dell'assessment

Al termine di ogni run vengono prodotti tre file nella directory configurata (`output.directory`):

| File | Formato | Scopo |
|---|---|---|
| `assessment_report.html` | HTML interattivo | Report leggibile dall'analista con audit trail completo per transazione |
| `evidence.json` | JSON | Archivio forense delle evidenze FAIL (payload completi, riproducibili) |
| `apiguard_report.json` | JSON | Report strutturato per CI/CD, SIEM e integrazioni machine-to-machine |

### `evidence.json` — Archivio forense

Contiene un array di `EvidenceRecord` ordinato cronologicamente, uno per ogni transazione HTTP che ha prodotto un FAIL o che e stata esplicitamente "pinned" dal test come contesto chiave. Ogni record include:

- Request completa (method, URL, headers con `Authorization: [REDACTED]`, body)
- Response completa (status code, headers, body troncato a 10.000 char)
- `record_id` nel formato `{test_id}_{sequence}` (es. `1.1_005`) — chiave di cross-referencing con il report HTML

Un singolo `EvidenceRecord` e sufficiente per riprodurre la richiesta esatta che ha scatenato la vulnerabilita senza alcun contesto aggiuntivo. Questo e il suo scopo progettuale: **ogni record e autosufficiente**.

### `assessment_report.html` — Report interattivo

Il report HTML include:

- Executive summary con statistiche aggregate (PASS/FAIL/SKIP/ERROR, totale richieste HTTP inviate, durata dell'assessment)
- Tabella dei risultati per test con dominio, priorita, strategia, CWE e messaggio di esito
- Per ogni test FAIL: il `Finding` con descrizione tecnica specifica e riferimenti standard (CWE, OWASP)
- Audit trail espandibile per ogni test: tabella di tutte le transazioni HTTP con oracle state (`ENFORCED`, `BYPASS`, `RATE_LIMIT_HIT`, ecc.) e preview del body
- Cross-referencing bidirezionale: le entry con `is_fail_evidence=true` riportano il `record_id` corrispondente in `evidence.json`

---

## 6. Come funziona — Pipeline ad alto livello

Il tool esegue sette fasi sequenziali per ogni assessment. Le fasi 1, 2 e 4 sono **bloccanti**: un errore produce exit code 10 senza eseguire alcun test. Le fasi 5, 6 e 7 non sono bloccanti.

```
config.yaml + .env
      |
      v
  Fase 1: Initialization       — Legge e valida config.yaml, interpola segreti da env
      |
      v
  Fase 2: OpenAPI Discovery    — Scarica la spec, derefenzia $ref, costruisce la mappa endpoint
      |
      v
  Fase 3: Context Construction — Crea i quattro oggetti di runtime
      |
      v
  Fase 4: Test Discovery       — Scopre i test dinamicamente, ordina per dipendenze (DAG),
      |                          applica i filtri di priorita e strategia
      v
  Fase 5: Execution            — Esegue ogni test in ordine topologico, raccoglie i TestResult
      |
      v
  Fase 6: Teardown             — Rimuove (best-effort) le risorse create durante i test
      |
      v
  Fase 7: Report Generation    — Serializza evidence.json, genera HTML e JSON di report
      |
      v
  Outputs: assessment_report.html  evidence.json  apiguard_report.json
```

> Per una descrizione dettagliata di ogni fase, inclusi edge case, modello dei dati in memoria e protocollo di `BaseTest.execute()`, consulta [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md).

---

## 7. Domini e priorita dei test

La metodologia APIGuard struttura la copertura di sicurezza in 8 domini tematici e 4 livelli di priorita:

| Dominio | Nome | Test attualmente implementati |
|---|---|---|
| 0 | API Discovery and Inventory Management | 0.1 Shadow API, 0.2 Deny by Default, 0.3 Deprecated API Enforcement |
| 1 | Identity and Authentication | 1.1 Authentication Required |
| 2 | Authorization and Access Control | — |
| 3 | Data Integrity | — |
| 4 | Availability and Resilience | — |
| 5 | Visibility and Auditing | — |
| 6 | Configuration and Hardening | — |
| 7 | Business Logic and Sensitive Flows | — |

| Priorita | Label | Strategia tipica | Descrizione |
|---|---|---|---|
| P0 | Critical | BLACK_BOX | Controlli perimetrali fondamentali. Un FAIL su P0 con `fail_fast: true` interrompe l'intero assessment |
| P1 | High | GREY_BOX | Garanzie di autenticazione e autorizzazione con credenziali valide |
| P2 | Medium | GREY_BOX | Logica applicativa, integrita dei dati, visibilita |
| P3 | Low | WHITE_BOX | Audit di configurazione tramite Admin API del Gateway |

**Mappatura `min_priority` -> test inclusi:**

| `min_priority` | Test inclusi |
|---|---|
| `0` | Solo P0 (Black Box puro) |
| `1` | P0 + P1 |
| `2` | P0 + P1 + P2 |
| `3` | Tutti — P0 + P1 + P2 + P3 (default raccomandato) |

**Markers pytest per filtri selettivi nei test E2E:**

```bash
pytest tests_e2e/ -m "p0 and domain_0" -v
pytest tests_e2e/ -m "black_box" -v
```

---

## 8. Codici di uscita

| Codice | Significato | Condizione |
|---|---|---|
| `0` | CLEAN — Nessuna violazione rilevata | Tutti i test hanno prodotto PASS o SKIP |
| `1` | FAIL — Almeno una garanzia di sicurezza e violata | Almeno un `TestResult(status=FAIL)` nel `ResultSet` |
| `2` | ERROR — Almeno una verifica non e stata completata | Nessun FAIL, ma almeno un `TestResult(status=ERROR)` |
| `10` | INFRA — Errore di infrastruttura | `ConfigurationError`, `OpenAPILoadError`, `DAGCycleError` |

La priorita e: **FAIL (1) > ERROR (2) > CLEAN (0)**. Un singolo FAIL sovrascrive qualsiasi numero di ERROR. Exit code 10 indica che l'assessment non ha avuto inizio e il `ResultSet` non e una base affidabile per alcun giudizio di sicurezza.

---

## 9. Struttura della repository

```
apiguard-assurance/
|-- config.yaml                  # Template di configurazione (versionabile)
|-- .env.example                 # Template variabili d'ambiente (non versionare .env)
|-- pyproject.toml               # Metadati progetto, dipendenze, configurazione tool
|
|-- src/
|   |-- cli.py                   # Entry point CLI (Typer)
|   |-- engine.py                # Orchestratore pipeline — 7 fasi sequenziali
|   |
|   |-- config/                  # Fase 1: caricamento e validazione configurazione
|   |-- core/                    # Layer fondamentale — vocabolario e infrastruttura condivisa
|   |-- discovery/               # Fase 2: parsing OpenAPI e costruzione AttackSurface
|   |-- tests/                   # Fase 5: implementazioni dei test per dominio
|   `-- report/                  # Fase 7: generazione HTML, JSON e aggregazione statistiche
|
|-- test-environments/
|   `-- forgejo-kong/            # Docker Compose per l'ambiente di test locale
|
|-- tests_e2e/                   # Suite E2E contro il target reale (richiede Docker stack)
`-- tests_integration/           # Suite di integrazione per i layer interni
```

> La mappa completa con ogni singolo file commentato si trova in [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md#repository-structure).

---

*APIGuard Assurance v1.0.0 — MIT License*
### Fase 3: Il Grande Refactoring (Smembrare Schema e Models)
**Questo DEVE essere l'ultimo passo assoluto.** Lo si fa solo quando il codice è stabile e funziona tutto (il cosiddetto "Code Freeze").
1. Vai nella chat del refactoring.
2. Incollagli i tuoi `schema.py` e `models.py` completi e definitivi (che ora conterranno le InfoNotes e i parametri dell'Evidence).
3. Fagli eseguire il lavoro di chirurgia: dividere tutto in cartelle (`src/config/schema/domain_1.py`, ecc.) e aggiornare il `config.yaml` mettendo `test_1_1` al posto giusto.
4. Fai girare l'engine. Se tutto parte senza errori di importazione, hai vinto. Hai un'architettura Enterprise pulitissima.




Ora voglio eseguire un refactoring architetturale (Domain-Driven Design) per risolvere il problema dei 'God File'. Iniziamo con `src/config/schema.py`.
> 
> Voglio trasformare il singolo file `schema.py` in un package Python `src/config/schema/`. 
> L'obiettivo è dividere le responsabilità senza rompere la retrocompatibilità degli import nel resto dell'app (come in `loader.py` o `engine.py`).
> 
> Con una struttura tipo questa:
> 1. `src/config/schema/base.py`: Conterrà le configurazioni globali (TargetConfig, OutputConfig, GlobalCredentials, ToolConfig, ecc.).
> 2. `src/config/schema/domain_0.py`: Conterrà le configurazioni specifiche dei test 0.x (TestDomain0Config, Test01Config, ecc.).
> 3. `src/config/schema/domain_1.py`: Conterrà le configurazioni per i test 1.x.
> 4. `src/config/schema/domain_4.py`: Conterrà le configurazioni per i test 4.x (incluso il Test43AuditConfig).
> 5. `src/config/schema/__init__.py`: Il file Facade. Dovrà importare tutto dai sottomoduli (es. `from .base import ToolConfig`, `from .domain_4 import Test43AuditConfig`) ed esporli. In questo modo chi fa `from src.config.schema import ToolConfig` non si accorgerà del refactoring.
> 
> Generami il codice per questi 5 file basandoti sul contenuto attuale del mio `schema.py`."

---
Secondo 'God File': `src/core/models.py`. 
> 
> Voglio trasformarlo nel package `src/core/models/`, seguendo la stessa logica Facade per mantenere intatti gli import in `engine.py`, `evidence.py` e nei test.
> 
> Con una struttura tipo questa:
> 1. `src/core/models/base.py`: I modelli fondamentali e universali (TestStatus, Finding, InfoNote, TestResult con la sua logica di validazione).
> 2. `src/core/models/http.py`: I modelli legati al traffico di rete e alle prove (EvidenceRecord, TransactionSummary).
> 3. `src/core/models/openapi.py`: I modelli legati alla specifica (EndpointRecord, AttackSurface, ecc.).
> 4. `src/core/models/runtime.py`: Le configurazioni di runtime che i test si passano a vicenda (RuntimeTest11Config, RuntimeTest43Config, ecc.).
> 5. `src/core/models/__init__.py`: Il file Facade che importa ed espone tutto dai sottomoduli.
> 
> Fai attenzione a mantenere corretti gli import interni tra questi sottomoduli (es. se `http.py` ha bisogno di qualcosa da `base.py`).

**Il riassunto dell'obiettivo:**
L'idea alla base è sfruttare il pattern **Facade** (creando i file `__init__.py`). In questo modo distruggiamo due file giganti e ingestibili, dividendoli in moduli più piccoli e specializzati (Domain-Driven Design), ma senza dover andare a modificare i percorsi di importazione in tutti gli altri file del progetto. 






## Analisi del problema

### Cosa c'è effettivamente in questi file

**`schema.py`** oggi contiene due responsabilità distinte che convivono nello stesso file:

1. **Config "di infrastruttura"** — `TargetConfig`, `CredentialsConfig`, `ExecutionConfig`, `OutputConfig`, `ToolConfig`: queste descrivono il tool, non i test.
2. **Config "per test"** — `RateLimitProbeConfig`, `TestDomain1Config`, `Test42AuditConfig`, `Test43AuditConfig`, `TestDomain4Config`, `TestsConfig`: queste descrivono i parametri di ogni singolo test.

**`models.py`** oggi contiene tre responsabilità distinte:

1. **Enum e modelli "fondazionali"** — `TestStatus`, `TestStrategy`, `SpecDialect`, `Finding`, `InfoNote`, `TestResult`, `ResultSet`: il vocabolario condiviso di tutto il tool.
2. **Modelli HTTP** — `EvidenceRecord`, `TransactionSummary`: il traffico di rete e le prove.
3. **Modelli di surface** — `ParameterInfo`, `EndpointRecord`, `AttackSurface`: la mappa dell'OpenAPI.
4. **RuntimeConfig** — `RuntimeTest11Config`, `RuntimeTest41Config`, ecc.: i parametri che i test leggono a runtime.

Il problema del **`rate_limit_probe`** che citi è reale e si duplica in tre posti: è una sezione a radice in `config.yaml`, rispecchiata in `RateLimitProbeConfig` in `schema.py`, e poi rispecchiata ancora in `RuntimeTest41Config` in `models.py`. Questo è l'unico posto dove c'è una vera incoerenza da risolvere insieme al refactoring.


### Piano definitivo che ti propongo

**Package `config/schema/`**:
- `__init__.py` — Facade: ri-esporta tutto, zero breaking change negli import
- `tool_config.py` — `TargetConfig`, `CredentialsConfig`, `ExecutionConfig`, `OutputConfig`, `ToolConfig` + relative costanti
- `domain_1.py` — `TestDomain1Config`
- `domain_4.py` — `Test41ProbeConfig` (ex `RateLimitProbeConfig`), `Test42AuditConfig`, `Test43AuditConfig`, `TestDomain4Config`
- `tests_config.py` — `TestsConfig` (aggrega `domain_1` e `domain_4`)

**Package `core/models/`**:
- `__init__.py` — Facade
- `enums.py` — `TestStatus`, `TestStrategy`, `SpecDialect` (separati perché usati in molti moduli distinti)
- `http.py` — `EvidenceRecord`, `TransactionSummary` + costanti airbag
- `surface.py` — `ParameterInfo`, `EndpointRecord`, `AttackSurface`
- `results.py` — `Finding`, `InfoNote`, `TestResult`, `ResultSet`
- `runtime.py` — `RuntimeCredentials`, `RuntimeTest11Config`, `RuntimeTest41Config`, `RuntimeTest42Config`, `RuntimeTest43Config`, `RuntimeTestsConfig`

**`config.yaml`**: spostare `rate_limit_probe` dentro `tests.domain_4.test_4_1`.

**`engine.py`**: aggiornare il punto dove popola `RuntimeTest41Config` (da `config.rate_limit_probe` a `config.tests.domain_4.test_4_1`).

---

Alcune domande prima di procedere:

La suddivisione che propongo per `models/` separa gli enum in un file dedicato (`enums.py`) invece di tenerli in `base.py` come nella tua bozza. Il motivo è che `TestStrategy` è importato sia da `schema.py` che dai test — avere un file `enums.py` minimo riduce il rischio di import circolari quando `base.py` cresce. Sei d'accordo, o preferisci tenerli in `base.py` per semplicità? Va bene spsotarli

E per `TestsConfig` — nella tua bozza non era un file separato, era aggregata in `base.py` o in un domain file. La propongo come file separato (`tests_config.py`) perché è il punto di aggregazione che importa da tutti i domain files, e tenerla separata rende il DAG di dipendenze tra file chiarissimo. Sei d'accordo? Si, va bene separato
# **Linee Guida di Sviluppo — APIGuard Assurance**

## **Manuale di Istruzioni — Tool Python per API Security Assessment**

**Nota:** Questo documento è un estratto operativo del manuale di progettazione completo. Le sezioni sono numerate in continuità con il documento originale da cui sono state estratte; le sezioni intermedie (5–8) appartengono ad altri estratti e non sono incluse qui.

**Scopo:** Definire come devi lavorare su questo progetto. Non descrive l'architettura — quella è in `4-Implementazione.md`, che è la tua fonte di verità primaria. Questo documento descrive la roadmap da seguire, gli anti-pattern da non riprodurre, le regole che governano ogni tua generazione di codice, e la checklist da soddisfare prima di considerare un output pronto.

---

## **0\. Fonte di Verità Architetturale**

`4-Implementazione.md` è la fonte di verità unica sull'architettura del progetto. Se una richiesta che ricevi è in conflitto con quanto definito in `4-Implementazione.md` — sui confini di responsabilità dei moduli, sull'interfaccia di un componente, sul flusso di esecuzione — non procedere silenziosamente. Segnala il conflitto esplicitamente, indica la sezione rilevante del documento, e chiedi conferma prima di generare codice. La richiesta potrebbe riflettere un'evoluzione del design: in quel caso la risposta corretta è aggiornare `4-Implementazione.md` prima di implementare, non aggirare il documento.

Se una richiesta viola uno dei principi fondamentali del progetto — agnosticismo API, separazione `TargetContext`/`TestContext`, monodirezionalità delle dipendenze — segnalalo esplicitamente prima di procedere. Non produrre codice che viola questi principi anche se la richiesta è formulata in modo diretto.

---

## **1\. Roadmap Implementativa**

Segui queste fasi in ordine sequenziale. Non passare alla fase successiva prima che il deliverable critico della fase corrente sia verificato.

| Fase | Durata Stimata | Deliverable Critico |
| ----- | ----- | ----- |
| 0 — Setup | 2 giorni | Repo \+ CI/CD \+ Dockerfile \+ `pyproject.toml` con dipendenze pinnate FLOOR-NEXT_MAJOR |
| 1 — Foundation | 1 settimana | Pydantic models \+ SecurityClient \+ BaseTest \+ TestResult models |
| 2 — Connectors | 1 settimana | OpenAPI parser \+ Target auth \+ Kong admin \+ testssl wrapper (output JSON via `--jsonfile`) |
| 3 — Orchestrator | 1 settimana | Factory \+ DAG (graphlib) \+ Strategy validation \+ Execution loop |
| 4 — Domain 0 | 1 settimana | Test 0.1, 0.2, 0.3 funzionanti contro target reale |
| 5 — Domain 1 | 1 settimana | Test 1.1–1.4 (valida dependency chain \+ strategy pattern) |
| 6 — Reporting | 3 giorni | JSON reporter \+ HTML base \+ exit code corretto |
| 7 — Extension | Variabile | Altri domini \+ polish \+ documentazione finale |

**Milestone gate obbligatorio:** al termine della Fase 3, l'orchestratore deve essere in grado di eseguire almeno 2 test dummy end-to-end con output `TestResult` corretto. Se questo gate non è superato, non iniziare la Fase 4\. Segnala esplicitamente se il gate non è stato superato invece di procedere.

---

## **2\. Anti-Pattern da Non Riprodurre**

Se durante l'implementazione ti trovi a scrivere codice che riproduce uno di questi pattern, fermati: è un segnale che stai deviando dal design. Segnala la situazione invece di procedere.

| Anti-Pattern | Dove Potrebbe Apparire | Come Prevenirlo |
| ----- | ----- | ----- |
| **God Object** | `engine.py` | `engine.py` deve solo orchestrare: delega tutta la logica a Strategy validator, TestFactory, Reporter. Il segnale di un God Object non è la lunghezza del file, ma la presenza di `if/else` che interpretano i risultati dei test, o di logica che appartiene a un singolo componente. Se stai scrivendo decisioni di dominio in `engine.py`, fermati. |
| **Circular Dependencies** | Connectors ↔ Tests | I test dipendono dai connectors, mai il contrario. Il flusso di dipendenza è monodirezionale: `tests/` importa da `core/` e `connectors/`, mai viceversa. Non introdurre import in direzione opposta. |
| **Singleton** | `SecurityClient` | Il client deve essere un'istanza per contesto di esecuzione, non un singleton globale di modulo. Non usare variabili di modulo per mantenere un'istanza condivisa del client. |
| **Magic Numbers** | Timeout, retry, limiti di evidenza | Non scrivere literal numerici nel codice senza una costante nominata. Ogni valore numerico che governa il comportamento del tool deve provenire da `config.yaml` o da una costante esplicitamente nominata. |

---

## **3\. Regole per la Generazione di Codice**

Queste regole si applicano a ogni output di codice che produci, indipendentemente dal contesto della richiesta.

### **3.1 Prima di Generare**

* Se hai dubbi sui requisiti, chiedi chiarimenti prima di generare. Non fare assunzioni su comportamenti ambigui e procedere silenziosamente.  
* Se mancano informazioni su un edge case, chiedi come deve comportarsi il sistema in quel caso specifico. Un edge case non gestito è un bug futuro.  
* Se ci sono trade-off reali tra due approcci, presenta entrambe le opzioni con pro e contro e chiedi quale direzione prendere. Non scegliere autonomamente senza avvisare.

### **3.2 Durante la Generazione**

* **Nessuna implementazione parziale.** Genera codice completo e funzionante. Se un modulo richiede 5 funzioni, implementale tutte e 5\. Non restituire scheletri con `pass` o `...` dove dovrebbe esserci logica reale.  
* **Nessun placeholder.** Non scrivere `# TODO: implement this`, `# FIXME`, o commenti che ammettono che il codice non è pronto. Se una funzionalità non è ancora implementabile, non creare il file: dillo esplicitamente.  
* **Nessun `print()`.** Usa `structlog` per tutto il logging. `print()` non è mai accettabile nel codice che produci, nemmeno come soluzione temporanea.  
* **Granularità dei moduli.** Genera un modulo completo per volta, non funzioni isolate estratte dal contesto. Se la richiesta riguarda una singola funzione, genera il modulo che la contiene con tutte le sue dipendenze interne risolte.

### **3.3 Convenzioni Obbligatorie**

* **Nomenclatura file test:** usa sempre la convenzione `tests/domain_X/test_X_Y_description.py`. Non creare file con nomi arbitrari nelle directory di dominio.  
* **Attributi obbligatori `BaseTest`:** ogni nuova classe di test deve dichiarare tutti e otto gli attributi di classe: `test_id`, `test_name`, `priority`, `domain`, `strategy`, `depends_on`, `tags`, `cwe_id`. Non omettere nessuno.  
* **Unicità del `test_id`:** prima di dichiarare un `test_id` in un nuovo test, verifica che non sia già usato da un test esistente nel registry. Un `test_id` duplicato causa comportamento silenziosamente errato nel DAG e nel report.  
* **Sanitizzazione credenziali:** ogni log message che potrebbe contenere dati sensibili deve usare `[REDACTED]`. Non fare affidamento sul fatto che un campo "di solito non viene loggato".

---

## **4\. Checklist Pre-Output**

Prima di considerare un output pronto, verifica ogni punto. Tutti i punti devono essere soddisfatti.

* \[ \] Type hints presenti su tutte le funzioni e i metodi (parametri e return type)  
* \[ \] Docstring su tutte le funzioni e classi pubbliche (stile Google/NumPy)  
* \[ \] Logging con `structlog` — nessun `print()` presente  
* \[ \] Exception handling esplicito: nessun `except Exception: pass`, nessun bare `except:`  
* \[ \] Nessun magic number: tutti i valori numerici significativi sono costanti nominate o provengono dalla configurazione  
* \[ \] Codice formattato secondo le regole Ruff definite in sezione 9.3  
* \[ \] Nessun `TODO`, `FIXME`, `HACK` nel codice  
* \[ \] Tutto il codice in inglese (variabili, funzioni, classi, docstring, log, eccezioni, commenti)  
* \[ \] Nessuna emoji nel codice sorgente  
* \[ \] Credenziali e token sanitizzati con `[REDACTED]` nei log  
* \[ \] Nessun import wildcard (`from module import *`)  
* \[ \] Dipendenze aggiunte con versione pinnata in `pyproject.toml` secondo la policy `FLOOR-NEXT_MAJOR` (lower bound = versione testata, upper bound = prossimo major)  
* \[ \] Nessun secret hardcoded nel codice (usare variabili d'ambiente via `${VAR}` in config)  
* \[ \] Tutti gli attributi obbligatori di `BaseTest` presenti nei nuovi test  
* \[ \] `test_id` del nuovo test verificato come univoco rispetto a tutti i test esistenti nel registry

---

## **5\. Coding Standards — Regole Tassative**

Queste regole si applicano a ogni riga di codice che produci. Non sono raccomandazioni: sono requisiti. Se una richiesta ti porterebbe a violarle, segnalalo prima di generare.

### **5.1 Lingua**

Tutto il codice che produci è in inglese senza eccezioni: nomi di variabili, funzioni, classi, moduli, argomenti, docstring, messaggi di log, messaggi di eccezione, commenti tecnici. L'unica eccezione ammessa riguarda valori letterali che rappresentano nomi propri del dominio non traducibili (es. il nome esatto di un endpoint del target).

### **5.2 Type Hints e Pydantic**

Inserisci type hints su ogni firma di funzione e metodo, incluso il return type. Usa `Any` solo se tecnicamente inevitabile (es. payload JSON a struttura arbitraria) e accompagnalo con un commento inline che ne giustifichi l'uso. Usa Pydantic v2 come unico strumento per modellare strutture dati validate a runtime: non usare `TypedDict` o plain dataclasses per dati che transitano da fonti esterne (config, response HTTP). I modelli immutabili usano `model_config = {"frozen": True}`. Eccezione: `TypedDict` è ammesso esclusivamente per le shape di wire-format raw provenienti da tool esterni (`connectors/types/`), dove la validazione Pydantic non è necessaria perché il dato viene immediatamente proiettato in strutture validate da `_evaluate()`.

### **5.3 Code Quality — Ruff**

Ruff è il solo tool di formatting e linting del progetto. Non usare Black, isort separato, o flake8. La configurazione in `pyproject.toml` attiva i ruleset `E, W, F, I, N, UP, B, S, ANN` con `line-length = 100` e `target-version = "py311"`. Il codice che produci deve superare `ruff check .` e `ruff format --check .` senza errori.

### **5.4 Error Handling**

Usa esclusivamente la gerarchia di eccezioni definita in `src/core/exceptions.py`. Non sollevare `Exception` o `RuntimeError` generici. Non usare `print()`: tutto il logging passa per `structlog` con eventi strutturati (coppie chiave-valore esplicite, non stringhe interpolate libere). Non scrivere `except Exception: pass`. Ogni `except` deve loggare l'errore con contesto sufficiente per il debugging e/o propagare un'eccezione tipizzata. Non usare bare `except:` senza tipo specificato.

### **5.5 No Placeholder Policy**

Non scrivere `# TODO`, `# FIXME`, `# HACK` nel codice. I commenti spiegano il *perché* di una scelta non ovvia, non il *cosa* fa il codice. Non inserire emoji nel codice sorgente. Se una funzionalità non è ancora implementabile, non creare il file: comunicalo esplicitamente. L'unica eccezione è il letterale `...` (Ellipsis) come body di un `@abstractmethod` (idiomatico Python ABC, equivalente a `pass`): è un contratto, non un placeholder. `...` non deve mai apparire altrove nel codice.

### **5.6 Testing Strategy — E2E Only**

Non scrivere unit test con mock. La scelta è deliberata: i test di sicurezza del tool verificano comportamenti HTTP reali contro un target reale — mockare `httpx` non fornirebbe garanzie sulla correttezza delle verifiche di sicurezza, solo sulla correttezza del codice Python. Scrivi test esclusivamente nella suite E2E in `tests_e2e/`, che gira contro un'istanza reale del target (Docker Compose con l'applicazione bersaglio e il gateway API). Il `conftest.py` verifica la raggiungibilità del target prima di ogni esecuzione. Un test E2E che fallisce per irraggiungibilità del target è un `ERROR` di infrastruttura, non un fallimento del tool.

### **5.7 Security Best Practices**

**Sanitizzazione dei log.** Sostituisci con `[REDACTED]` qualsiasi credenziale presente nel `ToolConfig` (password, token, API key) prima che compaia in qualsiasi log message o struttura loggata da `structlog`. Non è sufficiente non loggare quel campo: la struttura dell'oggetto potrebbe essere serializzata automaticamente da layer sottostanti. La sanitizzazione deve essere attiva ed esplicita.

**Generazione di valori casuali.** Usa esclusivamente il modulo `secrets` della stdlib Python per qualsiasi generazione di token, nonce o identificatori casuali a uso sicuro. Non usare il modulo `random` per questi scopi: non è crittograficamente sicuro.

**Dipendenze pinnate.** Tutte le dipendenze sono dichiarate in `pyproject.toml` (sezione `[project] dependencies` + `[project.optional-dependencies]`) secondo la policy `FLOOR-NEXT_MAJOR`: `name>=FLOOR,<NEXT_MAJOR` dove `FLOOR` è la versione effettivamente testata in Milestone 1 e `NEXT_MAJOR` blocca il prossimo major (es. `pydantic>=2.12,<3`). Unica eccezione: `prance==25.4.8.0` pinnata esattamente perché il tool accede a un attributo interno via name-mangling. Per un progetto nel dominio della sicurezza, il pip-audit nelle scripts hatch (`hatch run dev:deps`) verifica le CVE attive contro il PyPI advisory DB e l'OSV ad ogni release.

---

*Fine documento — `RULES_claude.md` v1.2*


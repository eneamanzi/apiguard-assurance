Leggo prima il codice esistente per capire lo stato reale del progetto.Adesso ho una visione chiara. Ti spiego tutto e poi definiamo il piano.

---

## Prima: chiarezza sulla questione dell'autenticazione

Il problema in parole semplici:

Il tool, per fare i test GREY_BOX (quelli che richiedono un utente loggato), deve prima ottenere un token di autenticazione. Oggi lo fa così: chiama `POST /api/v1/users/{username}/tokens` con username e password — questo è un endpoint **specifico di Forgejo/Gitea**. Nessun'altra applicazione al mondo espone quell'endpoint.

Su crAPI, per loggare, si chiama `POST /identity/api/auth/login` con email e password nel body JSON, e il token torna nella risposta come `{"token": "eyJ..."}`. Meccanismo completamente diverso.

Quindi il problema concreto è: **il codice che acquisisce il token è hardcoded per Forgejo, e non funzionerà su crAPI**. L'Intervento C del TODO risolve esattamente questo, aggiungendo un "dispatcher" che legge dal `config.yaml` che tipo di autenticazione usare e chiama il codice giusto.

---

## Piano di Azione — Versione Pulita

Ecco lo stato attuale e cosa fare, in ordine di esecuzione.

---

### Stato Attuale (cosa funziona oggi)

Test implementati e funzionanti su Forgejo+Kong:
- Domain 0: 0.1, 0.2, 0.3
- Domain 1: 1.1
- Domain 4: 4.1, 4.2, 4.3
- Domain 6: 6.2, 6.4
- Domain 7: 7.2

Test non ancora implementati: tutto il Domain 2 (BOLA, RBAC), Domain 3, Domain 5, e i restanti di Domain 1 (1.2–1.6).

---

### Fase 1 — Pulizie rapide (zero rischio, fai ora)

**1a. Fix dipendenza semanticamente vuota in test 7.2**
In `test_7_2_ssrf_prevention.py`, `depends_on` è già `[]` (ho verificato). Nulla da fare.

**1b. Aggiungere `shared_data` a `TestContext`**
Aggiungere tre metodi (`set_shared`, `get_shared`, `has_shared`) con un dizionario privato in `context.py`. Serve per quando i test di Domain 2 dovranno passarsi dati (es. l'ID di una risorsa creata). Non rompe nulla di esistente.

---

### Fase 2 — Auth dispatcher (rende il tool agnostico sull'autenticazione)

Questo è il refactoring principale per supportare crAPI.

**Cosa si modifica:**

`config/schema/tool_config.py` — aggiungere `auth_type` a `CredentialsConfig` con default `"forgejo_token"` (backward compatible: chi non mette `auth_type` nel config.yaml continua a funzionare esattamente come prima).

`core/models/runtime.py` — aggiungere `auth_type` e i campi JWT (`login_endpoint`, `username_body_field`, `password_body_field`, `token_response_path`) a `RuntimeCredentials`.

**Cosa si crea:**

`src/tests/helpers/auth.py` — dispatcher pubblico: legge `auth_type` e chiama l'implementazione giusta. Questo diventa l'unico import che i test usano.

`src/tests/helpers/auth_jwt_login.py` — implementazione generica per qualsiasi API che fa login con POST + JSON body e ritorna un JWT. Copre crAPI e la maggioranza delle API moderne.

**Cosa NON si tocca:**

`auth_forgejo.py` — rimane invariato internamente. Diventa un'implementazione privata chiamata dal dispatcher.

`auth_api_key.py` — lo saltiamo per ora. Il caso d'uso non esiste ancora e ha complessità irrisolte sul `SecurityClient`.

**Gate di completamento:** il tool gira su Forgejo con config.yaml invariato e produce output identico a prima.

---

### Fase 3 — Installare e configurare crAPI

crAPI si installa con Docker Compose da `https://github.com/OWASP/crAPI`. Richiede:
- Docker e Docker Compose
- Scaricare il repo
- `docker compose up` nella directory

Poi serve:
- Registrare 3 account (admin, user_a, user_b) via interfaccia web o API
- Ottenere una specifica OpenAPI (crAPI la espone o va presa dal repository)
- Scrivere il `config.yaml` per crAPI con `auth_type: jwt_login`

Questo passaggio è **pratico e manuale** — nessun codice. Prima di scrivere il config crAPI, devi avere crAPI in piedi e sapere esattamente quali endpoint usa per il login e come risponde.

---

### Fase 4 — Verifica agnosticismo su crAPI (Black Box prima)

Con crAPI in piedi e l'auth dispatcher pronto, si eseguono prima i test **BLACK_BOX** (P0 senza credenziali): 0.1, 0.2, 0.3, 4.1. Questi non richiedono login e girano già oggi senza modifiche. Se funzionano su crAPI, hai già una dimostrazione parziale di agnosticismo.

Poi si testano i **GREY_BOX** con l'auth dispatcher: 1.1, 7.2 in `fixed_path` mode.

---

### Fase 5 — Domain 2 (BOLA, RBAC) — dopo tutto il resto

Il Domain 2 richiede creare risorse sul target. Su Forgejo esiste già `forgejo_resources.py`. Per crAPI serve un equivalente. La soluzione config-driven del TODO (Intervento D) è **opzionale per la tesi**: puoi dimostrare l'agnosticismo del tool sui test già implementati e documentare Domain 2 come "richiede un adapter leggero per tipo di risorsa del target", che è onesto e accademicamente difendibile.

Se vuoi implementare Domain 2, lo facciamo dopo che tutto il resto è stabile.

---

### Ordine pratico di esecuzione

```
[1b] shared_data in TestContext
    ↓
[2]  Auth dispatcher (auth.py + auth_jwt_login.py + modifiche config/runtime)
    ↓
[Gate] Tool gira su Forgejo senza regressioni
    ↓
[3]  Installazione crAPI + setup manuale account + config.yaml crAPI
    ↓
[4a] Test BLACK_BOX su crAPI (0.1, 0.2, 0.3, 4.1)
    ↓
[4b] Test GREY_BOX su crAPI (1.1, 7.2 fixed_path)
    ↓
[Decisione] Domain 2 su crAPI: config-driven vs adapter vs fuori scope
```

---

Vuoi che iniziamo dalla Fase 1b (`shared_data` in `TestContext`) o preferisci prima discutere qualcosa che non è chiaro?
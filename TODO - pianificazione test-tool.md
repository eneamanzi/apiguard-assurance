# APIGuard — Mappa Strategica: Native vs Hybrid vs External

**Documento:** Piano di Sviluppo e Integrazione Tool
**Versione:** 2.0
**Riferimento:** `3_TOP_metodologia.md`, `ADR-001`, struttura corrente `src/tests/`
**Stato attuale del codebase:** 13 test implementati su 26 totali

---

## Premesse Architetturali (Decisioni Chiuse)

Prima del catalogo, si fissano quattro decisioni di scope che influenzano la classificazione di ogni test. Sono decisioni chiuse — documentate qui come riferimento per la tesi e per future iterazioni.

### P1 — Scope OpenAPI (obbligatorio, modalità senza spec come TODO futuro)

Il tool richiede che il target esponga una specifica OpenAPI valida. Questa non è una limitazione: è la condizione tecnica che permette al tool di essere API-agnostico senza conoscere il dominio applicativo. Come scritto in `Implementazione.md`: "un tool che funziona su qualsiasi API REST documentata è un contributo metodologico". Un target senza specifica espone una superficie d'attacco non strutturata che richiederebbe riscrivere `discovery/` da zero. La modalità pure black-box (discovery da zero via fuzzing senza spec, con tool come Arjun, ParamSpider, APIClarity, mitmproxy2swagger) è una direzione legittima catalogata come **Sviluppo Futuro v2.0**.

> **Implicazione per il catalogo tool:** Arjun, ParamSpider, APIClarity, mitmproxy2swagger non vengono scartati per ragioni tecniche — vengono rimandati perché il loro caso d'uso primario (discovery su target senza spec) è fuori scope nella versione corrente. Restano documentati nella sezione "Tool per sviluppi futuri".

### P2 — Schemi di Autenticazione (multipli, config-driven)

Un tool enterprise-grade non può assumere che ogni target usi JWT Bearer. Gli schemi reali includono API Key (header o query param), OAuth2 client_credentials, HTTP Basic Auth, HMAC request signing (AWS Signature V4), e mTLS. La soluzione è un **Auth Abstraction Layer** nel `config.yaml`:

```yaml
auth:
  scheme: jwt_bearer           # jwt_bearer | api_key | oauth2_cc | http_basic | hmac_aws_v4
  # Parametri specifici per schema — validati da discriminated union Pydantic v2
  jwt_bearer:
    login_endpoint: /api/v1/users/signin
    username_field: source_id
    password_field: password
  api_key:
    header_name: X-API-Key
    value: ${API_KEY}
  oauth2_cc:
    token_endpoint: https://auth.example.com/oauth/token
    client_id: ${CLIENT_ID}
    client_secret: ${CLIENT_SECRET}
    scope: read:api write:api
  http_basic:
    username: ${HTTP_USER}
    password: ${HTTP_PASS}
  hmac_aws_v4:
    access_key: ${AWS_ACCESS_KEY}
    secret_key: ${AWS_SECRET_KEY}
    region: eu-west-1
    service: execute-api
```

`tests/helpers/auth.py` espone un'interfaccia unificata `acquire_token(config: AuthConfig) -> str | dict` che seleziona l'implementazione corretta in base a `auth.scheme`. I test del Dominio 1 testano i meccanismi di sicurezza dello schema configurato — non sempre JWT. Questo cambia la natura di test come 1.2 e 1.3 (che hanno senso solo per JWT) e il modo in cui gli altri test acquisiscono credenziali.

> **Implicazione per il catalogo:** i test 1.2 (JWT Signature) e 1.3 (JWT Expiry) producono `SKIP` se `auth.scheme != jwt_bearer`. I test 1.1, 1.4, 2.x, 3.x, etc. usano lo schema configurato indifferentemente — l'astrazione è trasparente.

### P3 — Gateway Abstraction Layer (interfaccia astratta, non Kong-specific)

I test White Box che ispezionano la configurazione del gateway (4.2, 4.3, 6.3) non devono essere accoppiati a Kong. La soluzione è un `BaseGatewayInspector` con implementazioni concrete per ogni gateway supportato:

```
core/
└── gateway/
    ├── base.py          ← BaseGatewayInspector ABC
    ├── kong.py          ← KongInspector (usa Admin API /upstreams, /plugins)
    ├── aws_apigw.py     ← AwsApiGatewayInspector (usa boto3 / REST API)
    ├── traefik.py       ← TraefikInspector (usa Traefik API /api/http/routers)
    └── nginx.py         ← NginxInspector (legge nginx.conf da path configurato)
```

Il `TargetContext` espone `gateway_inspector: BaseGatewayInspector | None`. I test White Box lo ricevono già istanziato e chiamano metodi astratti come `get_timeout_config()`, `get_circuit_breaker_config()`, `get_plugin_list()` — senza sapere se stanno parlando con Kong o AWS. Se `gateway_inspector is None` (gateway non configurato o tipo non riconosciuto): `SKIP (Gateway inspector not available)`.

```yaml
# Configurazione gateway in config.yaml
gateway:
  type: kong          # kong | aws_apigw | traefik | nginx | none
  kong:
    admin_url: http://localhost:8001
  aws_apigw:
    rest_api_id: abc123
    region: eu-west-1
  traefik:
    api_url: http://localhost:8080
  nginx:
    config_path: /etc/nginx/nginx.conf
```

> **Implicazione per il catalogo:** i test 4.2, 4.3, 6.3 sono classificati `[NATIVE]` anche in contesto multi-gateway perché la logica di ispezione rimane Python — cambia solo l'implementazione dell'inspector, non il test.

### P4 — REST only (GraphQL, gRPC, WebSocket come Sviluppi Futuri v2.0)

Aggiungere GraphQL richiederebbe riscrivere `surface.py` (il sistema di tipi GraphQL è categoricamente diverso da OpenAPI), gestire introspection queries come discovery alternativo, e adattare tool come Schemathesis in modalità GraphQL. Per una tesi con delivery definito, il confine è REST + OpenAPI. GraphQL, gRPC, WebSocket sono documentati come direzioni future.

---

## Legenda e Criteri Decisionali

| Etichetta | Significato | Criterio Primario |
|---|---|---|
| `[NATIVE]` | Implementato interamente in Python via `SecurityClient` (httpx) | La logica è stateful, richiede `TestContext`, oppure Python raggiunge già la profondità di analisi sufficiente |
| `[HYBRID]` | Python orchestra; uno o più tool esterni eseguono la parte tecnica specializzata | Il tool esterno copre una superficie (fuzzing wordlist, protocollo raw, generazione statistica) non replicabile efficientemente in Python puro a parità di qualità metodologica |
| `[EXTERNAL]` | Delegato interamente a tool esterni tramite connector | Non applicabile: ogni test richiede sempre logica Python per oracle evaluation, `Finding` strutturati, e integrazione nel DAG. L'etichetta non esiste in questo progetto. |

**Principio guida per HYBRID:** la domanda non è "Python può farlo?" (la risposta è quasi sempre sì), ma "aggiungere un tool esterno porta una dimensione di analisi genuinamente diversa che un target enterprise si aspetterebbe da uno strumento serio?". Se la risposta è sì, il test è `[HYBRID]`. Questo include casi dove più tool coprono *angolazioni diverse dello stesso controllo*, sommandosi invece di sovrapporsi.

**Sul multi-tool:** per un singolo test `[HYBRID]` possono essere configurati più tool in parallelo o in cascata. Esempio: test 0.1 usa Kiterunner per la route discovery RESTful E ffuf per il fuzzing di parametri E Nuclei per template di vulnerabilità sui path trovati. I finding di tutti i tool confluiscono nello stesso `TestResult` con `source="external"` e `tool_name` distinto per ciascuno.

---

## Sintesi Esecutiva

| Etichetta | Numero di Test | % sul Totale |
|---|---|---|
| `[NATIVE]` | 18 | 69% |
| `[HYBRID]` | 8 | 31% |
| `[EXTERNAL]` | 0 | 0% |
| **Totale metodologia** | **26** | **100%** |

I test `[HYBRID]` sono aumentati da 4 a 8 rispetto alla prima versione del documento: la revisione del criterio (non "serve per Forgejo?" ma "aggiunge valore in contesti enterprise generici?") ha promosso 4 test che nella prima versione erano classificati `[NATIVE]` per bias di contesto.

---

## DOMINIO 0 — API Discovery & Inventory Management

### Test 0.1 — Shadow API Discovery `[P0]` `[Black Box]`

**Classificazione: `[HYBRID]` — Multi-Tool**
**Stato:** `[ TODO ]`

**Struttura del test:** tre layer sovrapposti che coprono angolazioni diverse della stessa garanzia.

**Layer 1 — Python (NATIVE component):** confronto spec vs endpoint attivi usando l'`AttackSurface`. Ogni endpoint che risponde `2xx/401/403` ma non è presente nella specifica OpenAPI è un shadow endpoint. Questo layer non può essere delegato: nessun tool conosce la specifica nel formato strutturato già disponibile nel `TargetContext`.

**Layer 2 — Route Bruteforcing (Tool 1):** fuzzing wordlist-based per trovare path non documentati e non raggiungibili dalla spec. Un fuzzer con corpus da 100k+ path costruito da traffico reale copre una superficie statisticamente superiore a qualsiasi lista hardcoded.

**Layer 3 — Parameter Discovery (Tool 2, opzionale):** per gli endpoint trovati dai layer precedenti, discovery dei parametri nascosti (query param, header, body field). Rilevante in contesti dove la spec è incompleta.

**Layer 4 — Vulnerability Scan sui Path Trovati (Tool 3, opzionale):** dopo la discovery, scan con template di vulnerabilità noti sui path rilevati. Chiude il loop tra "ho trovato un endpoint non documentato" e "questo endpoint è sfruttabile".

**Tool raccomandati:**

| Ruolo | Tool Primario | Tool Alternativo | Note |
|---|---|---|---|
| Route bruteforcing | **Kiterunner** (`assetnote/kiterunner`) | **ffuf** (`ffuf/ffuf`) | Kiterunner è progettato per API REST: negozia route con metodi HTTP multipli, usa wordlist costruite da traffico reale di API commerciali. ffuf è il fallback universale. |
| Parameter discovery | **Arjun** (`s0md3v/Arjun`) | **x8** (`Sh1Yo/x8`) | Scopre parametri nascosti via anomaly detection sulle response. Utile quando la spec è parziale o gli endpoint trovati hanno parametri non documentati. |
| Vuln scan post-discovery | **Nuclei** (`projectdiscovery/nuclei`) | — | Template `http/exposures/` e `http/misconfiguration/` per endpoint appena trovati. Scala il test da "ho trovato shadow endpoint" a "ho trovato shadow endpoint vulnerabili". |

**Divisione del lavoro:**

```
Python (native component)               Tool esterni
──────────────────────────────          ────────────────────────────────────────
Legge AttackSurface da TargetContext → Kiterunner: wordlist route bruteforce
Confronta hit tool vs spec             ffuf: fuzzing parametri e header
Genera Finding per shadow endpoint     Arjun: parameter discovery su hit
Consolida Finding da tutti i tool      Nuclei: template scan sui path trovati
Produce TestResult unificato
```

---

### Test 0.2 — Deny-by-Default `[P0]` `[Black Box]`

**Classificazione: `[NATIVE]`**
**Stato:** `[ TODO ]` (refactoring in corso)

La logica è interamente nella costruzione programmatica di path arbitrari e varianti normalizzate, invio HTTP, e verifica dei codici di risposta e header di backend. Nessuna dimensione tecnica specializzata da aggiungere. ffuf potrebbe generare varianti più velocemente, ma la velocità non è il vincolo qui: il vincolo è la correttezza dell'oracle, che è logica Python.

---

### Test 0.3 — Deprecated API Enforcement `[P0]` `[Black Box]`

**Classificazione: `[NATIVE]`**
**Stato:** `[ TODO ]` (refactoring in corso)

Richiede accesso alla specifica OpenAPI (endpoint con `deprecated: true`), verifica degli header `Sunset`, confronto rate limit, e accesso all'`AttackSurface`. Logica applicativa con accesso a strutture dati del `TargetContext`. Non delegabile.

---

## DOMINIO 1 — Identità e Autenticazione

**Nota di dominio:** tutti i test che testano credenziali JWT (1.2, 1.3) producono `SKIP` automatico se `config.auth.scheme != jwt_bearer`. I test che verificano comportamenti generali di autenticazione (1.1, 1.4, 1.5, 1.6) funzionano con qualsiasi schema configurato usando l'Auth Abstraction Layer.

### Test 1.1 — Solo Richieste Autenticate `[P0]` `[Black Box]`

**Classificazione: `[NATIVE]`**
**Stato:** `[  OK  ]`

Comportamento invariante rispetto allo schema di autenticazione: invia richieste senza credenziali e con credenziali malformate, verifica `401`. Compatibile con tutti gli schemi dell'Auth Abstraction Layer.

---

### Test 1.2 — Credenziali Crittograficamente Valide `[P0]` `[Grey Box]`

**Classificazione: `[NATIVE]`**
**Stato:** `[ TODO ]` (`jwt_forge.py` già disponibile)

Specifico per JWT Bearer. `jwt_forge.py` implementa `alg:none`, payload tampered, algorithm confusion, signature stripping, `kid` mismatch. Produce `SKIP` se `auth.scheme != jwt_bearer`. Nessun tool esterno esegue questo tipo di forgiatura JWT con la flessibilità richiesta dall'oracle specifico del target.

---

### Test 1.3 — Credenziali Non Scadute `[P0]` `[Black Box]`

**Classificazione: `[NATIVE]`**
**Stato:** `[ TODO ]`

Specifico per JWT Bearer (manipolazione del claim `exp`). Produce `SKIP` se `auth.scheme != jwt_bearer`. Per schemi diversi (API Key, HTTP Basic), la scadenza è gestita server-side e non manipolabile lato client — il controllo non è applicabile.

---

### Test 1.4 — Credenziali Non Revocate `[P1]` `[Grey Box]`

**Classificazione: `[NATIVE]`**
**Stato:** `[ TODO ]`

Test intrinsecamente stateful: acquisisce credenziali → triggera revoca (logout, password change) → riusa credenziali → verifica rifiuto. Compatibile con qualsiasi schema: per JWT Bearer verifica token blacklist, per API Key verifica revoca della chiave, per OAuth2 verifica token introspection endpoint. La logica di sequenza è Python puro con `TestContext`.

---

### Test 1.5 — Credenziali Non su Canali Insicuri `[P2]` `[White Box]`

**Classificazione: `[HYBRID]`**
**Stato:** `[ TODO ]` (file presente)

**Layer Python (NATIVE component):** test empirico del redirect HTTP→HTTPS (una request con httpx), verifica header HSTS, verifica che le credenziali non appaiano in query string o URL.

**Layer tool esterno:** analisi completa del protocollo TLS — versioni supportate, cipher suite, forward secrecy, certificate transparency, vulnerabilità note (BEAST, POODLE, ROBOT, DROWN, Heartbleed, LUCKY13, SWEET32, ecc.). Replicare questa analisi in Python richiederebbe implementare centinaia di handshake TLS personalizzati a livello socket raw. `testssl.sh` è lo standard de facto per questo tipo di analisi, battle-tested e attivamente mantenuto.

**Tool raccomandati:**

| Tool | Note |
|---|---|
| **testssl.sh 3.2** (`testssl/testssl.sh`) | Primario. Output `--jsonfile <path>` produce array JSON con `{id, severity, finding, cve, cwe}` per finding. Versione 3.2 stabile (giugno 2025); 3.0.x EOL. Disponibile come Docker image (`drwetter/testssl.sh`, `ghcr.io/testssl/testssl.sh`). |
| **sslyze** (`nabla-c0d3/sslyze`) | Alternativa Python-native — può essere importata come libreria (`from sslyze import ...`) invece di subprocess. Meno completa di testssl.sh per vulnerability scanning ma più semplice da integrare senza binary dependencies. Utile come fallback quando testssl.sh non è disponibile. |

**Note di parsing testssl.sh:** il campo `severity` nel JSON output classifica ogni finding come `INFO`, `LOW`, `MEDIUM`, `HIGH`, `CRITICAL`, `WARN`. Il connector deve filtrare per `severity in {MEDIUM, HIGH, CRITICAL, WARN}` per produrre Finding rilevanti. I finding `INFO` (es. "TLS session tickets are offered") sono informativi e non costituiscono vulnerabilità — includerli genererebbe rumore nel report.

---

### Test 1.6 — Session Management in Architetture Distribuite `[P3]` `[White Box]`

**Classificazione: `[NATIVE]`**
**Stato:** `[ TODO ]` (file presente)

Audit configurazione cookie (attributi `HttpOnly`, `Secure`, `SameSite`) + ispezione session store TTL via Admin API + test empirico session fixation. Tutto gestibile via httpx e `BaseGatewayInspector`. Nessuna dimensione tecnica specializzata.

---

## DOMINIO 2 — Autorizzazione e Controllo Accessi

Tutti i test del Dominio 2 sono `[NATIVE]`. Il denominatore comune è che operano su **stato autenticato multi-utente** con logica di ownership applicativa — una dimensione dove il `TestContext` e il DAG sono il punto di forza, non i tool esterni che operano stateless e senza conoscenza del dominio.

### Test 2.1 — RBAC Endpoint Privilege `[P1]` `[Grey Box]`

**Classificazione: `[NATIVE]`**
**Stato:** `[ TODO ]`

Richiede token per ruoli distinti (`TestContext`), iterazione sistematica su endpoint privilegiati dell'`AttackSurface`, verifica `403` da token con ruolo insufficiente. La matrice ruolo→endpoint è derivata dalla specifica OpenAPI (tag di sicurezza, scope OAuth2 dichiarati). Python puro.

---

### Test 2.2 — BOLA Prevention `[P1]` `[Grey Box]`

**Classificazione: `[NATIVE]`**
**Stato:** `[ TODO ]`

Richiede due account con risorse distinte. Il meccanismo di ownership check è per definizione specifico al dominio applicativo: nessun tool conosce "questa risorsa appartiene a questo utente" senza configurazione manuale equivalente a scrivere il test. Logica stateful Python.

---

### Test 2.3 — Operazioni Distruttive e Least Privilege `[P1]` `[Grey Box]`

**Classificazione: `[NATIVE]`**
**Stato:** `[ TODO ]`

Token con scope granulari, test DELETE/PUT da non-owner e da token read-only. Logica applicativa, nessuna complessità di protocollo.

---

### Test 2.4 — Consistenza Policy Across Endpoint `[P1]` `[Grey Box]`

**Classificazione: `[NATIVE]`**
**Stato:** `[ TODO ]`

Confronto sistematico delle policy di autenticazione tra versioni API e endpoint equivalenti usando l'`AttackSurface` come mappa. Python puro con logica di confronto strutturata.

---

### Test 2.5 — Excessive Data Exposure `[P2]` `[Grey Box]`

**Classificazione: `[NATIVE]`**
**Stato:** `[ TODO ]`

Ispezione della response JSON per field sensibili non documentati, confronto field-by-field tra ruoli. `response_inspector.py` è l'helper dedicato. Python puro.

---

## DOMINIO 3 — Integrità dei Dati

### Test 3.1 — Input Validation `[P2]` `[Grey Box]`

**Classificazione: `[HYBRID]` — Multi-Tool**
**Stato:** `[ TODO ]` (`injection_payloads.py` già presente)

**Layer Python (NATIVE component):** invio di payload di injection classici da `injection_payloads.py` (SQL, NoSQL, command injection, CRLF, path traversal, type confusion, boundary values). Oracle: codice di risposta `400` o assenza di esecuzione. `response_inspector.py` per l'analisi dell'output.

**Layer tool esterno — Schema-aware fuzzing:** Schemathesis genera automaticamente centinaia di input per ogni parametro di ogni endpoint, basandosi sulla specifica OpenAPI. Trova edge case statistici (Unicode anomalo, tipi confusi, combinazioni di parametri) che nessuna lista manuale può coprire sistematicamente. La differenza qualitativa rispetto al layer Python è che Schemathesis esplora lo spazio degli input in modo *esaustivo rispetto allo schema*, non *selettivo rispetto ai pattern noti*.

**Layer tool esterno — Vulnerability templates:** Nuclei con template `http/vulnerabilities/` può rilevare pattern di injection specifici per tecnologie note (Spring Boot, Django, Laravel) che `injection_payloads.py` non copre senza aggiornamento manuale continuo.

**Tool raccomandati:**

| Ruolo | Tool | Note |
|---|---|---|
| Schema fuzzing | **Schemathesis** (`schemathesis/schemathesis`) | **Unico tool integrabile come libreria Python** (`from schemathesis import from_uri`). OpenAPI 3.1 nativo. Property-based testing con Hypothesis engine. Nessun subprocess: la dipendenza è in `pyproject.toml`. |
| Injection templates | **Nuclei** (`projectdiscovery/nuclei`) | Template `http/vulnerabilities/` coprono injection specifiche per framework. JSON output. Usato anche in 0.1 e 7.2: un solo connector per tre test. |
| Negative fuzzing | **CATS** (`Endava/cats`) | Java — alternativa a Schemathesis se si preferisce evitare dipendenze Python aggiuntive. Genera automaticamente casi negativi da spec. Meno integrabile come libreria. |

**Nota architetturale su Schemathesis:** l'integrazione come libreria Python — invece di subprocess — significa che il "SchemathesisConnector" non estende `BaseConnector` (che è progettato per subprocess) ma implementa un'interfaccia separata. Questo è l'unico caso nel catalogo dove la distinzione "libreria vs binario" cambia la gerarchia delle classi. Vale la pena esplicitarlo nell'ADR.

---

### Test 3.3 — HMAC Config Audit `[P3]` `[White Box]`

**Classificazione: `[NATIVE]`**
**Stato:** `[  OK  ]`

Audit architetturale della presenza/assenza e parametri del meccanismo di firma. Python puro.

---

## DOMINIO 4 — Disponibilità e Resilienza

### Test 4.1 — Rate Limiting `[P0]` `[Black Box]`

**Classificazione: `[NATIVE]`**
**Stato:** `[  OK  ]`

Loop empirico con discovery automatica della soglia via richieste progressive. Il valore del test è il comportamento dell'oracle (`429` con `Retry-After`), non la velocità di generazione del traffico. Python è sufficiente. Tool come ffuf potrebbero saturare un endpoint più velocemente, ma un tool che genera traffico troppo veloce su un sistema di produzione è un rischio che il tool non deve introdurre per default.

---

### Test 4.2 — Timeout Config Audit `[P1]` `[White Box]`

**Classificazione: `[NATIVE]`**
**Stato:** `[  OK  ]`

Usa `BaseGatewayInspector.get_timeout_config()`. Python puro, compatibile con tutti i gateway supportati.

---

### Test 4.3 — Circuit Breaker `[P1]` `[White Box]`

**Classificazione: `[NATIVE]`**
**Stato:** `[  OK  ]`

Usa `BaseGatewayInspector.get_circuit_breaker_config()` e `.get_health_metrics()`. Python puro.

---

## DOMINIO 5 — Visibilità e Auditing

### Test 5.1 — Audit Logging `[P1]` `[Grey Box]`

**Classificazione: `[NATIVE]`**
**Stato:** `[ TODO ]`

Esegue richieste HTTP, poi interroga il log aggregator via API (Elasticsearch `_search`, Splunk HEC, CloudWatch Logs Insights, Datadog Logs API) per verificare presenza e contenuto dei log generati. Entrambe le operazioni sono HTTP request via httpx. La logica di verifica (presenza campi, redazione sensibile) è applicativa.

**Requisito di configurazione:** `logging.aggregator_url` e credenziali nel `config.yaml`. Analogamente a `admin_api_url`, il test produce `SKIP` se non configurato.

---

### Test 5.2 — Alert Real-Time `[P2]` `[Grey Box]`

**Classificazione: `[NATIVE]`**
**Stato:** `[ TODO ]`

Genera eventi anomali (brute-force simulato), poi verifica via SIEM API o webhook receiver che l'alert sia stato emesso entro la latenza attesa. Logica di orchestrazione stateful — non delegabile.

---

## DOMINIO 6 — Configurazione e Hardening

### Test 6.1 — Error Handling e Information Disclosure `[P2]` `[Grey Box]`

**Classificazione: `[NATIVE]`**
**Stato:** `[ TODO ]`

Input anomali deliberati + ispezione response per keyword tecnici (stack trace, query SQL, version strings). `response_inspector.py` contiene già la logica di pattern matching. Python puro.

---

### Test 6.2 — Security Headers `[P3]` `[White Box]`

**Classificazione: `[HYBRID]`**
**Stato:** `[  OK  ]` (native component implementato)

**Revisione rispetto a v1:** la prima versione classificava questo test come `[NATIVE]` con bias di contesto (ambiente locale). In un contesto enterprise generico, l'ispezione dei security header può beneficiare di strumenti dedicati che forniscono un benchmark qualitativo più ricco, grading su scala, e tracking delle best practice aggiornate.

**Layer Python (NATIVE component):** verifica presenza e valore degli header HSTS, X-Frame-Options, X-Content-Type-Options, CSP, Permissions-Policy. Già implementato in `test_6_2_security_headers_audit.py`.

**Layer tool esterno:** analisi più approfondita della Content-Security-Policy (parsing e valutazione di policy complesse, rilevamento di wildcard pericolosi in CSP), CORS misconfiguration, e confronto contro un database di best practice aggiornato.

**Tool raccomandati:**

| Tool | Note |
|---|---|
| **shcheck** (`santoru/shcheck`) | Python — analisi security header con grading. Importabile come libreria o subprocess. Output strutturato. Copre header meno comuni (Cross-Origin-Opener-Policy, Cross-Origin-Embedder-Policy). |
| **csp-evaluator** (Google, API pubblica) | Valutazione CSP via API REST. Utile quando il target ha policy CSP complesse da analizzare. Non richiede binario locale. |

**Nota:** l'implementazione corrente di `test_6_2_security_headers_audit.py` costituisce il layer native completo. L'aggiunta del layer tool esterno è un enhancement, non un requisito bloccante.

---

### Test 6.3 — Gateway Layer-7 Hardening `[P1]` `[Grey Box]`

**Classificazione: `[HYBRID]`**
**Stato:** `[ TODO ]`

**Layer Python (NATIVE component):**
- Test CORS enforcement (header inspection con httpx)
- Path normalization e method override (richieste HTTP standard)
- Plugin audit via `BaseGatewayInspector.get_plugin_list()`
- Timeout Layer-7 audit via `BaseGatewayInspector.get_timeout_config()`

**Layer tool esterno — HTTP Request Smuggling:** il test CL.TE/TE.CL richiede la costruzione di request con header HTTP ambigui non RFC-compliant che `httpx` rifiuta per design (è RFC-compliant). Questo richiede l'invio di byte TCP raw, per cui esistono tool dedicati.

**Layer tool esterno — WAF bypass:** in contesti enterprise con WAF o API Gateway con regole di filtering, tool specializzati testano tecniche di evasion Layer-7 (encoding bypass, HTTP method override, path traversal) su un corpus più ampio di quello gestibile manualmente.

**Tool raccomandati:**

| Ruolo | Tool | Note |
|---|---|---|
| HTTP Smuggling | **smuggler** (`defparam/smuggler`) | Python — può essere importato come libreria. Copre CL.TE, TE.CL, TE.TE desync. Stesso vantaggio architetturale di Schemathesis: nessun subprocess. |
| WAF bypass / Layer-7 | **gotestwaf** (`wallarm/gotestwaf`) | Go binario. JSON output. Copre bypass WAF, evasion techniques, e HTTP desync in modo più completo. Eccessivo se lo scope è solo smuggling; ottimo se si vuole coprire l'intero spazio Layer-7. |

---

### Test 6.4 — Hardcoded Credentials `[P2]` `[White Box]`

**Classificazione: `[NATIVE]`**
**Stato:** `[  OK  ]`

Regex scan su file di configurazione, check debug endpoint. Python puro.

---

## DOMINIO 7 — Business Logic e Flussi Sensibili

### Test 7.1 — Anti-Automation su Flussi Sensibili `[P2]` `[Grey Box]`

**Classificazione: `[NATIVE]`**
**Stato:** `[ TODO ]`

Verifica CAPTCHA enforcement e rate limit applicativo su endpoint specifici (payment, register). Logica di oracle applicativa — verifica se una request senza CAPTCHA token viene rifiutata, se N request consecutive triggerano blocco. Python puro.

---

### Test 7.2 — SSRF Prevention `[P0]` `[Black Box]`

**Classificazione: `[HYBRID]`**
**Stato:** `[  OK  ]` (native component con `ssrf_payloads.py`)

**Layer Python (NATIVE component, già implementato):** `ssrf_payloads.py` copre cloud metadata endpoints (AWS, GCP, Azure), private IP ranges, encoding bypass (decimal, hex, IPv6), protocol whitelist. Questo layer non viene rimosso né modificato.

**Layer tool esterno — Template SSRF avanzati:** Nuclei mantiene template aggiornati con bypass specifici per tecnologie e configurazioni cloud emergenti — una dimensione che `ssrf_payloads.py` non può avere senza aggiornamento manuale continuo. I finding Nuclei *si sommano* a quelli del layer Python: non c'è sovrapposizione, ci sono angolazioni diverse.

**Strategia di integrazione:** Nuclei viene invocato con la lista degli endpoint che accettano parametri URL (estratta dall'`AttackSurface`), non sull'intera API. Il `NucleiConnector` — che serve anche test 0.1 e 3.1 — viene istanziato una volta e riusato.

**Tool raccomandati:**

| Tool | Note |
|---|---|
| **Nuclei** (`projectdiscovery/nuclei`) | Template `http/vulnerabilities/generic/ssrf*`. JSON output (`-json`). Connector condiviso con 0.1 e 3.1 — one connector, multiple tests. |

---

### Test 7.3 — Race Condition e Idempotency `[P2]` `[Grey Box]`

**Classificazione: `[NATIVE]`**
**Stato:** `[ TODO ]`

Invio di richieste concorrenti con `concurrent.futures` Python, verifica dei codici di risposta, controllo stato risorse post-execution. Le richieste sono I/O-bound (httpx rilascia il GIL durante l'attesa): il threading Python è sufficiente per testare race condition a livello applicativo. La logica di Idempotency Key (generazione `uuid`, verifica `200 OK` cached vs `201 Created`) è applicativa e non delegabile.

---

### Test 7.4 — Consumo Sicuro di Servizi Esterni `[P2]` `[Grey Box]`

**Classificazione: `[NATIVE]`**
**Stato:** `[ TODO ]`

Webhook forgiati con HMAC valido e invalido, verifica comportamento del target. Richiede un mock server controllabile (configurabile nel `config.yaml`). Logica applicativa stateful, non delegabile.

---

## Riepilogo Completo per Dominio

| Test ID | Nome | P | Strategy | Class. | Stato | Tool (se HYBRID) |
|---|---|---|---|---|---|---|
| **0.1** | Shadow API Discovery | P0 | Black Box | `HYBRID` | TODO | Kiterunner, ffuf, Arjun, Nuclei |
| **0.2** | Deny-by-Default | P0 | Black Box | `NATIVE` | TODO | — |
| **0.3** | Deprecated API Enforcement | P0 | Black Box | `NATIVE` | TODO | — |
| **1.1** | Auth Required | P0 | Black Box | `NATIVE` | OK | — |
| **1.2** | JWT Cryptographic Validity | P0 | Grey Box | `NATIVE` | TODO | — |
| **1.3** | Credentials Not Expired | P0 | Black Box | `NATIVE` | TODO | — |
| **1.4** | Token Revocation | P1 | Grey Box | `NATIVE` | TODO | — |
| **1.5** | Insecure Transport (TLS) | P2 | White Box | `HYBRID` | TODO | testssl.sh, sslyze |
| **1.6** | Session Management | P3 | White Box | `NATIVE` | TODO | — |
| **2.1** | RBAC Endpoint Privilege | P1 | Grey Box | `NATIVE` | TODO | — |
| **2.2** | BOLA Prevention | P1 | Grey Box | `NATIVE` | TODO | — |
| **2.3** | Destructive Ops Privilege | P1 | Grey Box | `NATIVE` | TODO | — |
| **2.4** | Auth Policy Consistency | P1 | Grey Box | `NATIVE` | TODO | — |
| **2.5** | Excessive Data Exposure | P2 | Grey Box | `NATIVE` | TODO | — |
| **3.1** | Input Validation | P2 | Grey Box | `HYBRID` | TODO | Schemathesis, Nuclei, CATS |
| **3.3** | HMAC Config Audit | P3 | White Box | `NATIVE` | OK | — |
| **4.1** | Rate Limiting | P0 | Black Box | `NATIVE` | OK | — |
| **4.2** | Timeout Config Audit | P1 | White Box | `NATIVE` | OK | — |
| **4.3** | Circuit Breaker | P1 | White Box | `NATIVE` | OK | — |
| **5.1** | Audit Logging | P1 | Grey Box | `NATIVE` | TODO | — |
| **5.2** | Real-Time Alerts | P2 | Grey Box | `NATIVE` | TODO | — |
| **6.1** | Error Handling & Info Disclosure | P2 | Grey Box | `NATIVE` | TODO | — |
| **6.2** | Security Headers | P3 | White Box | `HYBRID` | OK (native) | shcheck, csp-evaluator |
| **6.3** | Gateway Layer-7 Hardening | P1 | Grey Box | `HYBRID` | TODO | smuggler, gotestwaf |
| **6.4** | Hardcoded Credentials | P2 | White Box | `NATIVE` | OK | — |
| **7.1** | Anti-Automation Business Flows | P2 | Grey Box | `NATIVE` | TODO | — |
| **7.2** | SSRF Prevention | P0 | Black Box | `HYBRID` | OK (native) | Nuclei |
| **7.3** | Race Condition & Idempotency | P2 | Grey Box | `NATIVE` | TODO | — |
| **7.4** | Unsafe External Consumption | P2 | Grey Box | `NATIVE` | TODO | — |

---

## Catalogo Consolidato dei Tool Esterni

### Tool Selezionati per l'Implementazione

| Tool | Repository | Tipo | Connector | Test che lo usano | Priorità impl. |
|---|---|---|---|---|---|
| **Kiterunner** | `assetnote/kiterunner` | Binario Go | `KiterunnnerConnector` | 0.1 | Alta (P0) |
| **ffuf** | `ffuf/ffuf` | Binario Go | `FfufConnector` | 0.1 (fallback) | Alta (P0) |
| **Nuclei** | `projectdiscovery/nuclei` | Binario Go | `NucleiConnector` | 0.1, 3.1, 7.2 | Alta (P0) |
| **testssl.sh 3.2** | `testssl/testssl.sh` | Script Bash | `TestsslConnector` | 1.5 | Media (P2) |
| **sslyze** | `nabla-c0d3/sslyze` | Libreria Python | `SslyzeConnector` | 1.5 (fallback) | Media (P2) |
| **Schemathesis** | `schemathesis/schemathesis` | Libreria Python | — (import diretto) | 3.1 | Media (P2) |
| **smuggler** | `defparam/smuggler` | Libreria Python | — (import diretto) | 6.3 | Media (P1) |
| **gotestwaf** | `wallarm/gotestwaf` | Binario Go | `GotestwafConnector` | 6.3 (alternativa) | Bassa (P1) |
| **Arjun** | `s0md3v/Arjun` | Binario Python | `ArjunConnector` | 0.1 | Bassa (P0) |
| **shcheck** | `santoru/shcheck` | Libreria Python | — (import diretto) | 6.2 | Bassa (P3) |

**Nota sull'ordine di implementazione dei connector:** l'ordine rispecchia la priorità del test che li usa, non la complessità del connector. Un connector semplice che serve un P0 ha precedenza su un connector complesso che serve un P2.

**Pattern "Libreria Python vs Binario":** tre tool (Schemathesis, smuggler, sslyze, shcheck) sono integrabili come librerie Python — nessun subprocess, dipendenza in `pyproject.toml`, nessun `shutil.which()`. Questi non estendono `BaseConnector` (progettato per subprocess) ma implementano un'interfaccia parallela `BasePythonLibraryIntegration`. Questo è un dettaglio architetturale che merita chiarimento nell'ADR prima dell'implementazione.

**Connector condivisi (NucleiConnector):** Nuclei serve tre test diversi (0.1, 3.1, 7.2) con template diversi. Il `NucleiConnector` viene istanziato una volta ed espone un metodo `run(template_tags: list[str])` che permette a ogni test di specificare i template rilevanti. Il connector non viene reinstanziato per ogni test — viene passato come dipendenza condivisa dal `ExternalTestRegistry`.

---

### Tool per Sviluppi Futuri (Fuori Scope v1.0)

Documentati per completezza. Entrano in scope quando si implementano le estensioni indicate.

| Tool | Estensione | Motivazione |
|---|---|---|
| **Arjun** / **x8** | Pure black-box mode (P1 — v2.0) | Discovery parametri su target senza OpenAPI spec |
| **ParamSpider** | Pure black-box mode (P1 — v2.0) | Mining parametri da archivi web (Wayback Machine) |
| **mitmproxy2swagger** | Pure black-box mode (P1 — v2.0) | Reverse-engineering spec da traffico catturato |
| **APIClarity** | Pure black-box mode (P1 — v2.0) | Ricostruzione spec da traffico runtime |
| **feroxbuster** | Alternative fuzzer (bassa priorità) | Directory bruteforcing — inferiore a Kiterunner per API REST, superiore per web server tradizionali |
| **CATS** | Schema fuzzing alternativo | Java — alternativa a Schemathesis se si vuole evitare dipendenze Python extra |
| **OWASP OFFAT** | Coverage OWASP API Top 10 | Copre garanzie con overlap sulla metodologia nativa — valore aggiunto limitato |
| **Dredd** | Contract testing | Scope diverso (conformance spec vs impl) — non security testing |

---

## Decisioni Architetturali Aperte

Queste decisioni non bloccano il piano attuale ma devono essere risolte prima di iniziare l'implementazione dei connector.

**DA-1 — Pattern per librerie Python:** come si classifica architetturalmente un tool che è una libreria Python (Schemathesis, smuggler, sslyze) nell'architettura connector/external-test definita nell'ADR-001? L'ADR assume subprocess per tutti i connector. Servono: (a) un'interfaccia `BasePythonLibraryIntegration` separata da `BaseConnector`, (b) chiarimento se questi tool vanno in `connectors/` o direttamente in `external_tests/`, (c) aggiornamento dell'ADR.

**DA-2 — Shared connector lifecycle:** `NucleiConnector` serve tre test. Chi gestisce il suo ciclo di vita? L'`ExternalTestRegistry` lo istanzia una volta e lo inietta nei test che lo richiedono, oppure ogni test lo istanzia indipendentemente? La prima opzione è più efficiente (un solo check `is_available()`); la seconda è più semplice da implementare. La scelta ha impatto su come il `ExternalTestRegistry` e l'engine coordinano i connector condivisi.

**DA-3 — Auth Abstraction Layer scope:** l'Auth Abstraction Layer descritto in P2 è un'estensione non banale di `tests/helpers/auth.py`. Prima di implementare i test Dominio 1 rimanenti, vale la pena definire lo schema Pydantic completo per `auth` nel `config.yaml` e l'interfaccia `acquire_token()`. Questa è una dipendenza di tutti i test Grey Box.

---

*Versione 2.0 — aggiornata incorporando le decisioni di scope P1–P4 e il principio di valutazione enterprise-agnostica.*
*Sostituisce integralmente la versione 1.0.*
*Riferimenti: `3_TOP_metodologia.md`, `ADR-001`, `Implementazione.md` v4.0, `TODO - tool shadow api.md`, struttura `src/tests/` al 30 aprile 2026.*
# Metodologia di Security Assurance per API REST — Tool di Testing

- [**Nota Metodologica: Gradiente Black Box / Grey Box / White Box**](#nota-metodologica-gradiente-black-box--grey-box--white-box)
- [**Matrice di Priorità (Riepilogo)**](#matrice-di-priorità-riepilogo)
- [**DOMINIO 0: API DISCOVERY E INVENTORY MANAGEMENT**](#dominio-0-api-discovery-e-inventory-management)
  - [**0.1 Tutti gli Endpoint Esposti Sono Documentati e Autorizzati `[P0]`**](#01-tutti-gli-endpoint-esposti-sono-documentati-e-autorizzati-p0)
  - [**0.2 Il Gateway Rifiuta Richieste a Path Non Registrati (Deny-by-Default) `[P0]`**](#02-il-gateway-rifiuta-richieste-a-path-non-registrati-deny-by-default-p0)
  - [**0.3 Le API Deprecate Sono Disabilitate o Sottoposte a Monitoraggio Rafforzato `[P0]`**](#03-le-api-deprecate-sono-disabilitate-o-sottoposte-a-monitoraggio-rafforzato-p0)
- [**DOMINIO 1: IDENTITÀ E AUTENTICAZIONE**](#dominio-1-identità-e-autenticazione)
  - [**1.1 Solo Richieste Autenticate Accedono a Risorse Protette `[P0]`**](#11-solo-richieste-autenticate-accedono-a-risorse-protette-p0)
  - [**1.2 Le Credenziali Sono Crittograficamente Valide `[P0]`**](#12-le-credenziali-sono-crittograficamente-valide-p0)
  - [**1.3 Le Credenziali Non Sono Scadute `[P0]`**](#13-le-credenziali-non-sono-scadute-p0)
  - [**1.4 Le Credenziali Non Sono State Revocate `[P2]`**](#14-le-credenziali-non-sono-state-revocate-p2)
  - [**1.5 Le Credenziali Non Sono Trasmesse via Canali Insicuri `[P2]`**](#15-le-credenziali-non-sono-trasmesse-via-canali-insicuri-p2)
  - [**1.6 Le Sessioni Sono Gestite in Modo Sicuro in Architetture Distribuite `[P3]`**](#16-le-sessioni-sono-gestite-in-modo-sicuro-in-architetture-distribuite-p3)
- [**DOMINIO 2: AUTORIZZAZIONE E CONTROLLO ACCESSI**](#dominio-2-autorizzazione-e-controllo-accessi)
  - [**2.1 Solo Utenti Autorizzati Accedono a Endpoint Privilegiati `[P2]`**](#21-solo-utenti-autorizzati-accedono-a-endpoint-privilegiati-p2)
  - [**2.2 Gli Utenti Accedono Solo ai Propri Dati (BOLA Prevention) `[P1]`**](#22-gli-utenti-accedono-solo-ai-propri-dati-bola-prevention-p1)
  - [**2.3 Le Operazioni Distruttive Richiedono Privilegi Appropriati `[P1]`**](#23-le-operazioni-distruttive-richiedono-privilegi-appropriati-p1)
  - [**2.4 Le Policy di Autorizzazione Sono Consistenti Across Endpoint `[P1]`**](#24-le-policy-di-autorizzazione-sono-consistenti-across-endpoint-p1)
  - [**2.5 L'API Non Espone Dati Eccessivi `[P2]`**](#25-lapi-non-espone-dati-eccessivi-p2)
- [**DOMINIO 3: INTEGRITÀ DEI DATI**](#dominio-3-integrità-dei-dati)
  - [**3.1 Tutti gli Input Sono Validati Secondo Schema e Constraints `[P2]`**](#31-tutti-gli-input-sono-validati-secondo-schema-e-constraints-p2)
  - [**3.2 → Fusa in Garanzia 6.1**](#32--fusa-in-garanzia-61)
  - [**3.3 I Dati in Transit Sono Protetti da Manipolazione (Beyond TLS) `[P3]`**](#33-i-dati-in-transit-sono-protetti-da-manipolazione-beyond-tls-p3)
- [**DOMINIO 4: DISPONIBILITÀ E RESILIENZA**](#dominio-4-disponibilità-e-resilienza)
  - [**4.1 Il Sistema Previene Resource Exhaustion via Rate Limiting `[P0]`**](#41-il-sistema-previene-resource-exhaustion-via-rate-limiting-p0)
  - [**4.2 Il Sistema Implementa Timeout per Prevenire Resource Lock `[P1]`**](#42-il-sistema-implementa-timeout-per-prevenire-resource-lock-p1)
  - [**4.3 Il Sistema Degrada Gracefully con Circuit Breaker `[P1]`**](#43-il-sistema-degrada-gracefully-con-circuit-breaker-p1)
- [**DOMINIO 5: VISIBILITÀ E AUDITING**](#dominio-5-visibilità-e-auditing)
  - [**5.1 Ogni Richiesta È Logged con Metadata Essenziali `[P1]`**](#51-ogni-richiesta-è-logged-con-metadata-essenziali-p1)
  - [**5.2 Eventi Security Anomali Triggerano Alert Real-Time `[P2]`**](#52-eventi-security-anomali-triggerano-alert-real-time-p2)
- [**DOMINIO 6: CONFIGURAZIONE E HARDENING**](#dominio-6-configurazione-e-hardening)
  - [**6.1 Error Handling e Information Disclosure `[P2]`**](#61-error-handling-e-information-disclosure-p2)
  - [**6.2 Security Header Configurati Appropriatamente `[P3]`**](#62-security-header-configurati-appropriatamente-p3)
  - [**6.3 La Configurazione del Gateway È Hardenata Contro Exploit Layer-7 `[P1]`**](#63-la-configurazione-del-gateway-è-hardenata-contro-exploit-layer-7-p1)
  - [**6.4 Le Credenziali di Servizio Non Sono Hardcoded o Esposte `[P2]`**](#64-le-credenziali-di-servizio-non-sono-hardcoded-o-esposte-p2)
- [**DOMINIO 7: BUSINESS LOGIC E FLUSSI SENSIBILI**](#dominio-7-business-logic-e-flussi-sensibili)
  - [**7.1 I Flussi Business Sensibili Sono Protetti da Abuse Automatizzato `[P2]`**](#71-i-flussi-business-sensibili-sono-protetti-da-abuse-automatizzato-p2)
  - [**7.2 Il Sistema Previene Server-Side Request Forgery (SSRF) `[P0]`**](#72-il-sistema-previene-server-side-request-forgery-ssrf-p0)
  - [**7.3 Le Operazioni Critiche Sono Idempotent o Protette da Race Condition `[P2]`**](#73-le-operazioni-critiche-sono-idempotent-o-protette-da-race-condition-p2)
  - [**7.4 L'API Consuma Servizi Esterni in Modo Sicuro `[P2]`**](#74-lapi-consuma-servizi-esterni-in-modo-sicuro-p2)
- [**MATRICE DI PRIORITIZZAZIONE RISK-BASED (RIVISTA)**](#matrice-di-prioritizzazione-risk-based-rivista)
  - [**Priority P0 — Critico: Gateway Core + OWASP Top Risk**](#priority-p0--critico-gateway-core--owasp-top-risk)
  - [**Priority P1 — Alto: Business Critical + Gateway Feature Avanzate**](#priority-p1--alto-business-critical--gateway-feature-avanzate)
  - [**Priority P2 — Medio: Application Logic + Defense in Depth**](#priority-p2--medio-application-logic--defense-in-depth)
  - [**Priority P3 — Basso: Compliance e Best Practice Statiche**](#priority-p3--basso-compliance-e-best-practice-statiche)


## **Nota Metodologica: Gradiente Black Box / Grey Box / White Box**

La presente metodologia non adotta un approccio di testing monolitico, bensì si muove lungo un **gradiente continuo di conoscenza e privilegio** dell'attore di test. Tale gradiente — ispirato alla classificazione internazionale Black Box / Grey Box / White Box — determina concretamente quali informazioni il tester deve possedere prima di avviare le verifiche di ciascun dominio, e con quale tecnica le esegue. Questo approccio riflette la realtà operativa degli assessment di sicurezza: applicare la tecnica sbagliata al controllo sbagliato produce sia falsi negativi (vulnerabilità non rilevate) che effort sprecato (test costosi su controlli verificabili in pochi secondi di ispezione configurazionale).

**Black Box — Esternalità Totale (Controlli Perimetrali P0).** Per i controlli classificati con priorità P0, il tester assume una posizione di completa esternalità: zero conoscenza dell'infrastruttura interna, zero privilegi pre-acquisiti, accesso esclusivamente tramite endpoint pubblici. Questo approccio è appropriato per le garanzie che il Gateway deve per definizione applicare verso qualsiasi interlocutore non autenticato. Test di questa categoria includono: accesso senza token, path fuzzing per Shadow API discovery, test di deny-by-default, verifica del rate limiting. L'obiettivo è simulare un attaccante anonimo che sonda il perimetro.

**Grey Box — Conoscenza e Privilegi Parziali (Controlli Logico-Applicativi P1, P2).** Per i controlli di priorità P1 e P2, il tester dispone di un set minimo di risorse: token JWT validi per almeno due utenti con ruoli distinti, conoscenza della struttura degli endpoint principali (tipicamente ottenuta dall'OpenAPI spec), e talvolta accesso in lettura a un ambiente di staging. Questo approccio è necessario per verificare logiche che presuppongono uno stato autenticato: autorizzazione RBAC, BOLA, revoca token, validazione input semantica. Si simula un attaccante che ha già compromesso credenziali legittime o un utente interno malintenzionato.

**White Box / Configuration Audit — Accesso Interno (Controlli Infrastrutturali P3 e P2 Complessi).** Per i controlli dove il test empirico esterno è macchinoso, indiretto o richiederebbe simulazioni di attacco elaborate per ottenere evidenza di qualcosa verificabile in pochi secondi di lettura della configurazione — versioni TLS supportate, header di sicurezza, gestione dei secret, timeout del Gateway, circuit breaker — la metodologia adotta un approccio di **Configuration Audit**. Il tester accede in lettura alle configurazioni del Gateway tramite Admin API, file di configurazione, o documentazione dell'infrastruttura. L'audit produce una checklist di conformità verificabile in modo deterministico, riproducibile e documentabile, senza ricorrere a test empirici time-consuming con esito incerto dall'esterno.

La tabella seguente sintetizza il mapping tra livello di priorità, approccio metodologico e prerequisiti tipici:

| Priorità | Approccio | Prerequisiti Tipici | Razionale |
| ----- | ----- | ----- | ----- |
| **P0 — Critico** | Black Box | Nessuno — solo accesso rete pubblica | Controlli perimetrali applicati dal Gateway prima di qualsiasi autenticazione |
| **P1 — Alto** | Grey Box | Token per ≥2 ruoli, OpenAPI spec, staging env | Verifiche che richiedono stato autenticato ma non accesso infrastrutturale |
| **P2 — Medio** | Grey Box / White Box | Variabile per garanzia — specificato in ogni sezione | Mix di test empirici (BOLA, input validation) e audit (TLS, headers) |
| **P3 — Basso** | White Box — Config Audit | Accesso in lettura a configurazioni Gateway, session store, TLS config | Logica applicativa profonda o configurazione statica, non testabile efficacemente dall'esterno |

---

## **Matrice di Priorità (Riepilogo)**

| Priorità | Garanzie | Criterio |
| ----- | ----- | ----- |
| **P0 — Critico** | 0.1, 0.2, 0.3, 1.1, 1.2, 1.3, 4.1, 7.2 | Funzione nativa Gateway, automatizzabile al 100%, OWASP Top 3 |
| **P1 — Alto** | 2.3, 2.4, 4.2, 4.3, 5.1, 6.3 | Parzialmente Gateway, automatizzabile con setup, business critical |
| **P2 — Medio** | 1.4, 1.5, 2.1, 2.2, 2.5, 3.1, 5.2, 6.1+3.2, 6.4, 7.1, 7.3, 7.4 | Applicativo o complesso, automazione parziale |
| **P3 — Basso** | 1.6, 3.3, 6.2 | Configurazione statica, best practice, logica backend profonda |

---

## **DOMINIO 0: API DISCOVERY E INVENTORY MANAGEMENT**

### **0.1 Tutti gli Endpoint Esposti Sono Documentati e Autorizzati `[P0]`**

**\[Riferimenti: OWASP API9:2023 Improper Inventory Management, NIST SP 800-204 Section 3.1, OWASP ASVS v5.0.0 V4.1.1\]**

**Concetto.** Questo controllo verifica che ogni endpoint attivo sul Gateway corrisponda a una voce nella specifica OpenAPI ufficiale. Endpoint attivi ma non documentati — detti Shadow API — costituiscono superficie d'attacco sconosciuta: non sono soggetti a security review, rate limiting, né policy di autenticazione sistematiche. La difesa è un inventory authoritative mantenuto nel Management Plane del Gateway.

**Scenari di Failure.**

* **Endpoint Legacy Non Rimosso:** Durante la migrazione da API v1 a v2, il team disabilita la documentazione Swagger per `/api/v1/users` ma omette di rimuovere la route dal Gateway. L'endpoint rimane raggiungibile, privo di rate limiting, e viene scoperto tramite fuzzing o cache Google di repository interni.  
* **Path Non Documentato con Wildcard Route:** Il Gateway usa una route catch-all `/*` che inoltra tutto il traffico al backend. Percorsi come `/api/internal/config` o `/api/debug/users` non sono in OpenAPI ma rispondono con `200 OK`, restituendo configurazioni sensibili perché il backend assume che il Gateway filtrasse a monte.  
* **Versioning Inconsistente:** Il Gateway espone `/api/v1/`, `/api/v2/`, `/api/v3/` ma OpenAPI documenta solo v3. Le versioni precedenti mancano di controlli introdotti successivamente (es. autenticazione 3D-Secure) e passano inosservate nel ciclo di security review.

**Assunzioni e Prerequisiti:** Approccio **Black Box**. Il tester dispone unicamente dell'URL base dell'API e, se pubblicamente disponibile, della specifica OpenAPI. Nessun token autenticato è necessario per questa fase. Per il solo sotto-test "Documentation Drift via Admin API", è richiesto accesso in lettura alla Admin API del Gateway (approccio Grey Box addizionale, da eseguire se disponibile).

**Logica di Test.**

* **Path Enumeration via Fuzzing:** Eseguire scansione con wordlist standard (SecLists `API-endpoints.txt`: `/api/admin`, `/api/internal`, `/swagger.json`, `/openapi.yaml`, ecc.). Confrontare i path che restituiscono `2xx`, `401`, o `403` con la lista degli endpoint documentati in OpenAPI. Ogni path attivo non presente nella specifica è una Shadow API. Includere varianti case e trailing slash per verificare la normalizzazione.  
* **HTTP Method Discovery:** Per ogni endpoint documentato, inviare una `OPTIONS` request e confrontare i metodi nell'header `Allow` con quelli dichiarati in OpenAPI. Se `Allow: GET, POST, DELETE` ma la spec dichiara solo `GET, POST`, il metodo `DELETE` non documentato deve essere verificato: se processato (status ≠ `405`), è esposizione non autorizzata.  
* **Versioning Completeness:** Generare combinazioni plausibili di versioni (`v1`, `v2`, `v3`, `v1.0`, `version1`) per ogni endpoint documentato e inviare le request. Oracle: versioni che rispondono con `2xx` o `401/403` sono versioni attive. Confrontare con le versioni dichiarate; verificare la parità delle policy di sicurezza tra versioni.  
* **Documentation Drift via Admin API:** Scaricare la route table effettiva del Gateway tramite Admin API (Kong: `GET /routes`; AWS API Gateway: `aws apigateway get-resources`; Traefik: `/api/http/routers`) e confrontarla programmaticamente con l'OpenAPI spec. Ogni route presente nel Gateway senza corrispondenza nella spec è drift di configurazione.

---

### **0.2 Il Gateway Rifiuta Richieste a Path Non Registrati (Deny-by-Default) `[P0]`**

**\[Riferimenti: NIST SP 800-204 Section 4.1, OWASP ASVS v5.0.0 V4.1.1, CIS Benchmark API Gateway Controls 2.3\]**

**Concetto.** Il principio di Deny-by-Default impone che il Gateway blocchi qualsiasi richiesta il cui path non corrisponda esattamente a una route esplicitamente registrata, anziché inoltrarla a un backend di default o a un servizio catch-all. Il Gateway deve operare come security enforcement point primario: restituire `404 Not Found` o `403 Forbidden` per path non registrati, senza rivelare informazioni sulla topologia interna.

**Scenari di Failure.**

* **Wildcard Catch-All Permissiva:** Il Gateway usa `/*` che inoltra tutto al backend. Path come `/actuator/heapdump` (Spring Boot), `/debug/pprof` (Go), o `/api/internal/reset-db` vengono raggiunti dall'esterno perché il backend assume che il Gateway filtri le richieste non legittime.  
* **Path Normalization Bypass:** Il Gateway esegue un match esatto su `/api/users` ma il backend normalizza percorsi. Un attaccante invia `/api/%75sers` (URL-encoding) o `/api//users` (doppio slash): il Gateway non riconosce il path come registrato e lo inoltra; il backend lo normalizza e lo processa, bypassando i controlli.  
* **Case Sensitivity Mismatch:** Il Gateway registra la route `/api/users` (lowercase). Il backend (es. Windows IIS) è case-insensitive. Una richiesta a `/API/USERS` non trova match nel Gateway e viene inoltrata al default backend senza autenticazione.

**Assunzioni e Prerequisiti:** Approccio **Black Box**. Nessun token, nessuna conoscenza dell'infrastruttura interna. Il tester invia request arbitrarie a path inventati e a varianti di path noti, osservando il comportamento del Gateway. Non è richiesto alcun privilegio pre-acquisito.

**Logica di Test.**

* **Unregistered Path Rejection:** Inviare `GET` a path garantiti inesistenti (`/nonexistent-xyz-123`, `/api/fake/route`). Oracle: risposta `404` o `403`. Il body non deve contenere stack trace, routing logic, o identificativi del backend server.  
* **Path Normalization Consistency:** Per ogni endpoint documentato (es. `/api/users`), generare varianti: URL-encoded (`%75sers`), double-encoded (`%2575sers`), path traversal (`/api/users/../admin`), doppio slash (`/api//users`), trailing slash, varianti uppercase. Oracle: se il path è legittimo, tutte le varianti normalizzate devono applicare le stesse policy di autenticazione e rate limiting. Se una variante bypassa l'autenticazione o riceve una risposta diversa, è vulnerabilità. Se il path non esiste, tutte le varianti devono restituire `404/403`.  
* **Default Backend Fallback Detection:** Inviare request a path arbitrari e osservare i response header: la presenza di header backend-specifici (`X-Backend-Server`, `X-Application-Context`) indica che la richiesta ha raggiunto il backend, violando il deny-by-default.

---

### **0.3 Le API Deprecate Sono Disabilitate o Sottoposte a Monitoraggio Rafforzato `[P0]`**

**\[Riferimenti: OWASP API9:2023 Improper Inventory Management, NIST SP 800-204 Section 3.1.3, OWASP ASVS v5.0.0 V4.1.1\]**

**Concetto.** Questo controllo verifica che gli endpoint marcati come `deprecated` nel ciclo di vita API siano o completamente disabilitati (risposta `410 Gone`) oppure sottoposti a rate limiting rafforzato e logging verboso durante il periodo di transizione. Endpoint deprecati ricevono meno attenzione in termini di patching e monitoring pur rimanendo esposti, creando una finestra temporale critica.

**Scenari di Failure.**

* **Vulnerabilità Non Backportata:** API v1 deprecata contiene una SQL injection risolta in v2 ma non corretta retroattivamente perché "in via di dismissione". Il team non monitora v1 attivamente; l'endpoint rimane sfruttabile per l'intera durata del periodo di deprecazione.  
* **Sunset Header Senza Enforcement:** Il Gateway restituisce `Sunset: Wed, 01 Jan 2026 00:00:00 GMT` ma non implementa alcun controllo alla data indicata. Dopo il sunset pianificato, l'endpoint continua a funzionare indefinitamente come "zombie API".

**Assunzioni e Prerequisiti:** Approccio **Black Box** per i sotto-test di accessibilità (Milestone 1 implementato): zero credenziali, solo spec OpenAPI per identificare endpoint con `deprecated: true`. I sotto-test di rate limiting differenziale e logging verbosity richiedono **Grey Box** (token JWT per utente standard + accesso in lettura al log aggregator o alla Admin API del Gateway): pianificati per Milestone 2.

**Logica di Test.**

* **Deprecated Endpoint Accessibility:** Estrarre da OpenAPI tutti gli endpoint con `deprecated: true`. Verificare la presenza dell'header `Sunset` con `HEAD` request. Se la data sunset è trascorsa, inviare `GET`: oracle è `410 Gone` (RFC 9110). Se l'endpoint risponde `200 OK` post-sunset, indica mancato enforcement del ciclo di vita.  
* **Rate Limiting Differenziale:** Per endpoint deprecati ancora attivi (pre-sunset), eseguire burst test di 100 request in 60 secondi. Oracle: il rate limit applicato deve essere più stringente rispetto all'endpoint equivalente non deprecato (es. 10 req/min vs 100 req/min). Parità di rate limit indica trattamento equivalente e assenza di misure compensative.  
* **Logging Verbosity Differenziale:** Verificare tramite Admin API o sistema di log aggregation che gli endpoint deprecati generino log con verbosità maggiore (source IP, user identity, request body) rispetto agli endpoint standard. Un endpoint deprecato senza logging rinforzato non è monitorabile per pattern di abuse.

---

## **DOMINIO 1: IDENTITÀ E AUTENTICAZIONE**

### **1.1 Solo Richieste Autenticate Accedono a Risorse Protette `[P0]`**

**\[Riferimenti: OWASP API2:2023 Broken Authentication, NIST SP 800-63B-4 Section 4.3.1, OWASP ASVS v5.0.0 Chapter V6.3\]**

**Concetto.** Questo controllo verifica che ogni endpoint che espone dati sensibili o operazioni privilegiate rifiuti richieste prive di credenziali valide prima di raggiungere la business logic. L'enforcement — tramite token bearer JWT o opachi OAuth2 nell'header `Authorization` — deve avvenire a livello di Gateway o middleware con logica deny-by-default: assenza o invalidità del token producono immediatamente `401 Unauthorized`.

**Scenari di Failure.**

* **Bypass Completo:** L'endpoint non verifica la presenza dell'header `Authorization`. Una `GET /api/users/profile` senza token riceve `200 OK` con i dati dell'utente.  
* **Accettazione di Token Vuoti o Malformati:** L'API verifica la presenza dell'header ma non il contenuto. `Authorization: Bearer` (senza token) o `Authorization: invalid-garbage` vengono processati come autenticati.  
* **Path Normalization Non Protetto:** L'API protegge `/api/users` ma non la variante `/api/Users` (uppercase) o `/api/users/` (trailing slash), perché il routing non normalizza i path prima di applicare le policy.

**Assunzioni e Prerequisiti:** Approccio **Black Box**. Nessun token JWT, nessuna conoscenza dell'infrastruttura. Il tester opera esclusivamente con richieste non autenticate o con token deliberatamente malformati verso tutti gli endpoint protetti documentati nell'OpenAPI spec.

**Logica di Test.**

* **Accesso Senza Token:** `GET /api/users/me` senza header `Authorization`. Oracle: `401 Unauthorized`. Il body non deve contenere dati sensibili (es. `{"error": "Authentication required"}`, non l'oggetto user). Il test va eseguito su tutti gli endpoint protetti documentati, non su un solo campione.  
* **Token Vuoto e Malformato:** Inviare `Authorization: Bearer` (stringa vuota), `Authorization: Bearer null`, `Authorization: invalid`. Oracle: `401` in tutti i casi, comportamento identico all'assenza dell'header.  
* **Header Case Variations:** Inviare la request con header in varianti `authorization`, `AUTHORIZATION`, `AuThOrIzAtIoN`. Oracle: senza token valido, `401` in tutti i casi (verifica conformità allo standard HTTP case-insensitivity, RFC 9110).  
* **Path Normalization:** Testare `/api/Users`, `/api/users/`, `/api//users`, `/api/users/../users`. Oracle: tutte le varianti devono richiedere autenticazione.

---

### **1.2 Le Credenziali Sono Crittograficamente Valide `[P0]`**

**\[Riferimenti: OWASP API2:2023 Broken Authentication, RFC 8725 Section 3.2, OWASP ASVS v5.0.0 V9.1.1 \+ V11.5.1, NIST SP 800-63B-4 Section 4.3.1\]**

**Concetto.** Questo controllo verifica che il Gateway o il middleware di autenticazione eseguano la validazione crittografica completa dei JWT: estrazione della firma, ricalcolo tramite la chiave pubblica dell'issuer (per RS256/RS384/RS512) o il secret condiviso (per HS256/HS384/HS512), e confronto byte-by-byte. Token con algoritmo `none`, payload manomesso, o firmati con chiave errata devono essere rifiutati con `401`. Algoritmi deboli o deprecati (DES, export-grade) sono esplicitamente esclusi da NIST SP 800-131A.

**Scenari di Failure.**

* **Accettazione di `alg: none`:** Alcune librerie JWT legacy accettano token con header `{"alg":"none","typ":"JWT"}` e firma vuota, bypassando completamente la verifica crittografica (CVE-2015-9235).  
* **Payload Non Verificato:** L'API decodifica il JWT ed estrae i claim senza verificare la firma. Un attaccante modifica `"userId": "1"` in `"userId": "2"`, mantenendo la firma originale: l'API accetta il token perché è sintatticamente valido.  
* **Key Confusion Attack (RS256 → HS256):** L'issuer firma con RS256 (chiave privata RSA), il server valida con la chiave pubblica. Un attaccante crea un token firmato con HS256 usando la chiave pubblica come HMAC secret. Se l'API accetta entrambi gli algoritmi senza vincoli, il token forgiato supera la validazione.

**Assunzioni e Prerequisiti:** Approccio **Grey Box**. Il tester deve possedere almeno un token JWT valido (ottenuto tramite login regolare) da cui estrarre la struttura header/payload. Per il test di Key Confusion, è necessario accedere al JWKS endpoint pubblico (`/.well-known/jwks.json`) per recuperare la chiave pubblica dell'issuer. Nessun accesso amministrativo richiesto.

**Logica di Test.**

* **Test `alg: none` Rejection:** Creare JWT con header `{"alg":"none","typ":"JWT"}`, payload valido, firma vuota (`header.payload.`). Oracle: `401 Unauthorized`.  
* **Test Tampered Payload:** Prendere un JWT valido, modificare un claim nel payload (es. estendere `exp` di un anno), ri-encodare in base64url, ricomporre con la firma originale immutata. Oracle: `401`, la firma non corrisponde al nuovo payload.  
* **Test Algorithm Confusion:** Ottenere la chiave pubblica dell'issuer da `/.well-known/jwks.json`. Creare un token HS256 firmato con quella chiave pubblica come secret. Oracle: `401`, il server non accetta switch arbitrari di algoritmo (RFC 8725).  
* **Test Signature Stripping:** Rimuovere la firma da un JWT valido (`header.payload.` con nulla dopo il secondo punto). Oracle: `401`, non deve essere interpretato come `alg:none` implicito.  
* **Test Key Rotation Resilience:** Con JWKS endpoint che espone due chiavi (old e new) durante grace period di 24h: JWT firmato con chiave old deve restituire `200 OK` entro la finestra; JWT con chiave old dopo scadenza grace period deve restituire `401`. Verificare nei log che il Gateway usi il `kid` header per selezione chiave. Verificare che il cache TTL del JWKS endpoint sia ≤ 300 secondi (`Cache-Control: max-age=300`).  
* **Test Key ID Mismatch:** Generare JWT valido firmato con chiave old, modificare il campo `kid` nell'header per dichiarare la chiave new. Oracle: `401`, il Gateway deve verificare che la firma corrisponda effettivamente alla chiave indicata dal `kid`.

---

### **1.3 Le Credenziali Non Sono Scadute `[P0]`**

**\[Riferimenti: OWASP API2:2023 Broken Authentication, RFC 7519 Section 4.1.4, OWASP ASVS v5.0.0 V9.2.1, NIST SP 800-63B-4 Section 4.2\]**

**Concetto.** Questo controllo verifica che il Gateway confronti il claim `exp` (Unix timestamp) con l'orario corrente e rifiuti token con `now >= exp`. Un margine di tolleranza (leeway) di ±60 secondi è accettabile per compensare il clock skew tra issuer e validatore. Le best practice NIST SP 800-63B-4 raccomandano access token con lifetime di 5–15 minuti, rinnovati tramite refresh token.

**Scenari di Failure.**

* **Claim `exp` Ignorato:** L'API decodifica il token ma non verifica la scadenza. Un token rubato mesi prima rimane utilizzabile indefinitamente.  
* **Clock Skew Exploit:** Issuer e validatore hanno orologi desincronizzati di 10 minuti. Token validi vengono rifiutati (orologio avanti) o token scaduti accettati (orologio indietro).

**Assunzioni e Prerequisiti:** Approccio **Grey Box**. Il tester deve poter generare o manipolare JWT con claim `exp` arbitrari. È sufficiente avere la chiave di firma (o un token valido da cui derivare un token modificato) e un endpoint autenticato su cui testare. Non è richiesto accesso amministrativo.

**Logica di Test.**

* **Test Token Scaduto:** JWT valido con `exp = now - 3600` (scaduto 1 ora fa). Oracle: `401 Unauthorized`.  
* **Test Token Valido:** JWT con `exp = now + 31536000` (+1 anno). Oracle: `200 OK`.  
* **Test Clock Skew:** Con leeway dichiarato di 60s: `exp = now - 30` (scaduto 30s fa) → Oracle `200 OK`. `exp = now - 90` (scaduto 90s fa) → Oracle `401`.  
* **Test Expiry Negativo:** JWT con `exp = -1` o `exp = 0`. Oracle: `401`, senza crash o comportamento indefinito.

---

### **1.4 Le Credenziali Non Sono State Revocate `[P2]`**

**\[Riferimenti: OWASP API2:2023 Broken Authentication, RFC 7009 (OAuth 2.0 Token Revocation), RFC 7519 Section 4.1.7, OWASP ASVS v5.0.0 V7.4 \+ V9, NIST SP 800-63B-4 Section 5.1\]**

**Concetto.** Questo controllo verifica che token crittograficamente validi e non scaduti, ma esplicitamente revocati (logout, cambio password, compromissione segnalata), siano rifiutati. Le strategie implementative — blacklist centralizzata su Redis con `jti` claim, versioning claim su database, o token short-lived con refresh rotation — sono scelte architetturali; il test verifica il comportamento risultante, non l'implementazione interna.

**Scenari di Failure.**

* **Pure Stateless JWT Senza Revoca:** L'API valida solo firma ed expiry. Dopo logout, il token rimane valido per l'intera durata del claim `exp` (es. 15 minuti). In caso di compromissione, l'attaccante mantiene accesso fino a scadenza naturale.  
* **Race Condition nella Replica:** Il token viene inserito nella blacklist Redis nel nodo primario, ma la replica asincrona introduce un delay di 500ms. Nella finestra di propagazione, una request a un nodo replica non ancora aggiornato viene accettata.

**Assunzioni e Prerequisiti:** Approccio **Grey Box**. Il tester deve possedere credenziali valide per effettuare login, ottenere token JWT, e accedere agli endpoint di logout e cambio password. Sono necessari almeno due account distinti per i test di concorrenza. Nessun accesso al session store interno è richiesto: il test verifica esclusivamente il comportamento comportamentale esterno.

**Logica di Test.**

* **Test Token Dopo Logout:** Login → ottenere token → `POST /api/auth/logout` → riusare immediatamente il token su `GET /api/users/me`. Oracle: `401 Unauthorized`.  
* **Test Token Dopo Password Change:** Login → ottenere token → `POST /api/users/password` (cambio password, deve incrementare `tokenVersion` nel DB) → riusare il vecchio token. Oracle: `401`.  
* **Test Logout Idempotente:** Simulare 10 logout simultanei dello stesso token (threading). Oracle: tutti `200 OK`, il token appare in blacklist esattamente una volta senza duplicazioni.

---

### **1.5 Le Credenziali Non Sono Trasmesse via Canali Insicuri `[P2]`**

**\[Riferimenti: OWASP API2:2023, RFC 9110 Section 4.2.2, NIST SP 800-52 Rev. 2, OWASP ASVS v5.0.0 V12.1.1 \+ V12.1.2 \+ V14.2.1\]**

**Concetto.** Questo controllo verifica che le credenziali siano trasmesse esclusivamente su canale TLS 1.2+ e che il Gateway applichi HTTPS enforcement (redirect 301/308) e HSTS. I cipher suite devono garantire forward secrecy (ECDHE) e authenticated encryption (AES-GCM). La parte configurativa (HSTS, header) è verificabile staticamente; la parte protocollo richiede scan attivo.

**Scenari di Failure.**

* **HTTP Plaintext Accettato:** L'API risponde sia su `:80` (HTTP) che `:443` (HTTPS) senza redirect. Un attaccante MitM downgrade connection a HTTP; l'utente invia `Authorization: Bearer token` in chiaro.  
* **TLS 1.0/1.1 Supportato:** Il server accetta protocolli deprecati. Un attaccante forza downgrade a TLS 1.0 e decifra traffico offline sfruttando vulnerabilità note (BEAST, POODLE).

**Assunzioni e Prerequisiti:** Approccio **White Box — Audit di Configurazione** (con singolo test empirico per HTTP redirect). Il tester ha accesso alla configurazione TLS del server (file nginx.conf, httpd.conf, o equivalente nel Gateway), oppure può richiedere i parametri al team di infrastruttura. Lo scan con `testssl.sh` richiede solo connettività di rete verso il target.

**Audit di Configurazione (Checklist).**

* **\[AUDIT\]** Verificare nel file di configurazione del server (es. `nginx.conf`, Kong `proxy_listen`, AWS API GW TLS policy) che i protocolli abilitati siano esclusivamente TLS 1.2 e TLS 1.3. Oracle: le direttive `ssl_protocols` (Nginx) o equivalenti non devono includere `TLSv1`, `TLSv1.1`, `SSLv3`. Documentare il parametro esatto e il suo valore.  
* **\[AUDIT\]** Verificare la cipher suite configurata. Oracle (NIST SP 800-52 Rev. 2): per TLS 1.3 solo suite AEAD (`TLS_AES_256_GCM_SHA384`, `TLS_CHACHA20_POLY1305_SHA256`); per TLS 1.2 solo suite con ECDHE e GCM (`ECDHE-RSA-AES256-GCM-SHA384`). Nessuna cipher con RSA key exchange statico (no forward secrecy).  
* **\[AUDIT\]** Verificare che il certificato TLS abbia una data di scadenza futura, provenga da CA fidata nell'elenco Mozilla, e che il CN/SAN corrisponda all'hostname del servizio. Strumento: `openssl s_client -connect host:443 -showcerts`.  
* **\[AUDIT\]** Verificare la presenza di almeno 2 SCT (Signed Certificate Timestamp) da Certificate Transparency log distinti, inclusi nei certificati o nell'handshake TLS (RFC 6962).  
* **\[TEST EMPIRICO\]** Inviare `GET http://api.example.com/users/me` (HTTP plaintext) con token valido. Oracle: connessione rifiutata (porta 80 chiusa) o redirect `301/308` a HTTPS senza processare la request. Questo è l'unico test attivo necessario: il comportamento di redirect è non deducibile dalla sola configurazione.  
* **\[AUDIT\]** Verificare nella risposta HTTPS la presenza dell'header `Strict-Transport-Security: max-age=31536000; includeSubDomains` (ASVS V12.1.1). Verificabile con una singola `curl -I https://api.example.com`.

---

### **1.6 Le Sessioni Sono Gestite in Modo Sicuro in Architetture Distribuite `[P3]`**

**\[Riferimenti: OWASP API2:2023, OWASP ASVS v5.0.0 V3.2.1 \+ V3.2.3 \+ V3.2.4, NIST SP 800-63B-4 Section 4.2, NIST SP 800-204A Section 4.3\]**

**Concetto.** Questo controllo riguarda la gestione di sessioni ibride (cookie \+ refresh token) in deployment multi-region, dove la consistenza del session store (Redis Cluster, DynamoDB Global Tables) è critica per revoca cross-node e prevenzione di session fixation. Essendo fortemente dipendente dall'architettura interna del session store, questo controllo è parzialmente verificabile dall'esterno e viene trattato come best practice architetturale.

**Scenario di Failure.**

* **Session Fixation:** Attaccante ottiene session cookie pre-autenticazione tramite endpoint pubblico. Vittima fa login con stesso browser; Gateway non rigenera session ID. Attaccante con cookie pre-auth è ora autenticato come vittima.

**Assunzioni e Prerequisiti:** Approccio **White Box — Audit di Configurazione**. Il tester ha accesso in lettura alla configurazione del session store (Redis TTL policy, replica mode) e ai parametri di configurazione dei cookie nel Gateway o middleware applicativo. L'unico test empirico (session fixation) richiede un browser e un account valido, ma la maggior parte delle verifiche è configurazionale.

**Audit di Configurazione (Checklist).**

* **\[AUDIT\]** Verificare nella configurazione del Gateway o del middleware applicativo che i session cookie siano emessi con gli attributi `HttpOnly`, `Secure`, e `SameSite=Strict` (ASVS V3.2.3). Strumento: analisi del `Set-Cookie` header in una risposta di login.  
* **\[AUDIT\]** Verificare nella configurazione del session store (Redis: comando `CONFIG GET maxmemory-policy`, DynamoDB: TTL attribute abilitato) che il TTL della session key sia allineato con il lifetime del JWT (`exp`). Oracle: TTL Redis ≤ valore `exp` del JWT associato. Una session key con TTL maggiore del JWT consente riuso post-scadenza.  
* **\[AUDIT\]** Verificare che la modalità di replica del session store sia sincrona o che la finestra di propagazione asincrona sia documentata e accettata come rischio. In Redis Cluster con replica asincrona, la finestra di inconsistenza deve essere ≤ 100ms per essere accettabile in contesti ad alto rischio.  
* **\[TEST EMPIRICO\]** Session Fixation: catturare il cookie pre-autenticazione → effettuare login → verificare che il valore del cookie sia diverso post-autenticazione (ASVS V3.2.1). Questo test è necessariamente empirico perché verifica comportamento a runtime, non configurazione.  
* **\[AUDIT\]** Verificare tramite codice sorgente o documentazione tecnica che il server generi session token con entropia sufficiente: minimo 128 bit di randomness da CSPRNG (ASVS V3.2.4). Non è necessario generare 1000 token: è sufficiente verificare che la libreria usata (es. `uuid.v4()`, `secrets.token_hex(32)`) produca tale entropia per definizione.

---

## **DOMINIO 2: AUTORIZZAZIONE E CONTROLLO ACCESSI**

### **2.1 Solo Utenti Autorizzati Accedono a Endpoint Privilegiati `[P2]`**

**\[Riferimenti: OWASP API5:2023 Broken Function Level Authorization, OWASP ASVS v5.0.0 V8.3.1 \+ V8.2.2, NIST SP 800-53 Rev. 5 AC-3\]**

**Concetto.** Questo controllo verifica che, dopo l'autenticazione, il Gateway o il middleware applicativo esegua un controllo di autorizzazione basato su ruoli (RBAC, NIST SP 800-162): ogni endpoint privilegiato deve rifiutare con `403 Forbidden` le richieste di utenti autenticati ma privi del ruolo o scope richiesto. L'autenticazione prova "chi sei"; l'autorizzazione prova "cosa puoi fare".

**Scenari di Failure.**

* **Controllo Lato Client:** L'interfaccia nasconde il bottone "Delete User" per utenti non-admin, ma l'API non verifica il ruolo. Una request diretta via curl a `DELETE /api/users/123` ha successo.  
* **Inconsistenza tra Metodi HTTP:** `GET /api/users/{id}` e `DELETE /api/users/{id}` richiedono rispettivamente autenticazione e ruolo admin, ma `PATCH /api/users/{id}` dimentica il controllo. Un utente normale può modificare dati tramite PATCH.

**Assunzioni e Prerequisiti:** Approccio **Grey Box**. Il tester deve possedere token JWT validi per almeno due ruoli distinti (es. `user` e `admin`), conoscenza degli endpoint privilegiati documentati in OpenAPI (inclusi i metodi HTTP e i ruoli richiesti per ciascuno), e un ambiente di staging o produzione su cui eseguire le chiamate.

**Logica di Test.**

* **Accesso Admin con Token User:** Login come utente normale → `DELETE /api/users/999`. Oracle: `403 Forbidden` (non `401`, perché autenticato; non `200`). Ripetere per tutti gli endpoint privilegiati documentati.  
* **HTTP Method Confusion:** Per ogni risorsa (es. `/api/users/{id}`), testare tutti i metodi HTTP (GET, POST, PUT, PATCH, DELETE, HEAD, OPTIONS). Oracle: ogni metodo deve avere il controllo di authorization appropriato.  
* **Gerarchia Ruoli:** Con gerarchia `superadmin > admin > moderator > user` (NIST SP 800-162), verificare che `moderator` acceda agli endpoint `moderator` ma NON a quelli `admin`.

---

### **2.2 Gli Utenti Accedono Solo ai Propri Dati (BOLA Prevention) `[P1]`**

**\[Riferimenti: OWASP API1:2023 Broken Object Level Authorization, CWE-639, OWASP ASVS v5.0.0 V8.2.2, NIST SP 800-162 Section 2.2\]**

**Concetto.** Questo controllo verifica che il sistema applichi ownership check a livello di oggetto: un utente può accedere solo alle risorse di cui è proprietario. BOLA (\#1 OWASP) si manifesta quando l'API usa un identificatore controllato dal client (ID nell'URL o nel body) senza verificare che corrisponda all'utente autenticato. Il controllo tipico lato backend è `WHERE id = {resourceId} AND userId = {tokenUserId}`.

**Scenari di Failure.**

* **Enumerazione Sequenziale:** Con ID incrementali (1, 2, 3...), un utente autenticato chiama `GET /api/orders/1` → `GET /api/orders/1000` in loop, scaricando tutti gli ordini del sistema.  
* **Modifica di Oggetti Altrui:** `PATCH /api/orders/100 {"status": "cancelled"}` da un utente che non è owner dell'ordine 100\.

**Assunzioni e Prerequisiti:** Approccio **Grey Box**. Il tester deve possedere token JWT validi per almeno due account distinti (userA e userB), con almeno una risorsa creata e identificata per ciascun account. È necessario conoscere gli ID delle risorse appartenenti a ciascun utente, ottenibili tramite chiamate GET precedenti al login.

**Logica di Test.**

* **Cross-User Data Access:** Login come userA → ottenere ordine (es. `orderId=100`) → login come userB → `GET /api/orders/100`. Oracle: `403 Forbidden` o `404 Not Found` (per non rivelare l'esistenza, CWE-639).  
* **Enumerazione ID Sequenziali:** Login → verificare ID del proprio ordine (es. `orderId=500`) → testare `GET /api/orders/499`, `GET /api/orders/501`. Oracle: `403/404`. Ripetere su almeno 10 ID consecutivi.  
* **Modifica Oggetti Altrui:** userA ha order 100, userB ha order 200\. userB esegue `PATCH /api/orders/100 {"status": "cancelled"}`. Oracle: `403`. Verificare con GET successiva come userA che l'ordine 100 non sia stato modificato.  
* **Mass Assignment Protection:** `POST /api/orders {"userId": 999, "productId": 456}`. Oracle: ordine creato con `userId = tokenUserId` (dal token), ignorando il valore nel body.  
* **UUID Entropy (Se Applicabile):** Creare 10 risorse, estrarre UUID. Oracle: versione UUID 4 (random) o 7 (time-ordered, preferred 2026). Generare 1000 UUID consecutivi e calcolare Hamming distance media tra coppie (Oracle: ≥ 64 bit). L'uso di UUID non elimina la necessità di ownership check.

---

### **2.3 Le Operazioni Distruttive Richiedono Privilegi Appropriati `[P1]`**

**\[Riferimenti: OWASP API5:2023, OWASP ASVS v5.0.0 V8.2.1 \+ V8.1.1, NIST SP 800-53 Rev. 5 AC-6 Least Privilege\]**

**Concetto.** Questo controllo verifica che operazioni con effetti permanenti (DELETE, PUT su risorse critiche, operazioni finanziarie) richiedano scope OAuth2 o ruoli più elevati rispetto alle corrispondenti operazioni di lettura. Il principio di Least Privilege (NIST SP 800-53 AC-6) si traduce in scope granulari: `read:posts` permette GET, `delete:posts` permette DELETE.

**Scenari di Failure.**

* **Delete da Non-Owner:** userA ha il post 100\. userB chiama `DELETE /api/posts/100` e l'operazione ha successo perché l'API verifica solo l'autenticazione, non l'ownership.  
* **Scope Escalation:** Un'app ottiene token OAuth con `scope: read:profile`. Usa lo stesso token per chiamare `DELETE /api/profile` che dovrebbe richiedere `scope: delete:profile`.

**Assunzioni e Prerequisiti:** Approccio **Grey Box**. Il tester deve disporre di token OAuth2 con scope granulari differenziati (es. `read:posts` vs `delete:posts`), di almeno due account per i test di cross-ownership, e della documentazione degli scope richiesti per ciascun endpoint (da OpenAPI o documentazione API).

**Logica di Test.**

* **Delete da Non-Owner:** userA ha il post 100\. userB chiama `DELETE /api/posts/100`. Oracle: `403 Forbidden`.  
* **Operazione con Token Read-Only:** Ottenere token OAuth con scope `read:posts`. Chiamare `DELETE /api/posts/123`. Oracle: `403` con messaggio "Insufficient scope".  
* **Batch Delete Authorization:** `DELETE /api/posts?ids=1,2,3` dove l'ID 2 appartiene a un altro utente. Oracle: l'intera operazione deve fallire (`403`) senza cancellare nessuno degli ID (comportamento transazionale).

---

### **2.4 Le Policy di Autorizzazione Sono Consistenti Across Endpoint `[P1]`**

**\[Riferimenti: OWASP API8:2023 Security Misconfiguration, OWASP ASVS v5.0.0 V8.1, NIST SP 800-53 Rev. 5 AC-3\]**

**Concetto.** Questo controllo verifica che endpoint equivalenti — per versione API, formato risposta, o rappresentazione alternativa — applichino policy di autorizzazione identiche. La consistenza è una proprietà configurazionale del Gateway e la sua violazione spesso emerge da route duplicate o versioni non allineate, verificabili sistematicamente tramite confronto automatizzato.

**Scenari di Failure.**

* **Versioning Inconsistency:** `GET /api/v1/users/{id}` richiede ruolo admin, la nuova versione `GET /api/v2/users/{id}` dimentica il controllo.  
* **GraphQL vs REST:** Il REST endpoint `GET /api/users` richiede auth; il GraphQL endpoint `POST /graphql query {users{...}}` non la richiede, esponendo gli stessi dati.

**Assunzioni e Prerequisiti:** Approccio **Grey Box**. Il tester deve disporre della specifica OpenAPI completa per tutte le versioni dell'API, di token JWT validi per utenti con ruoli distinti, e di conoscenza degli endpoint alternativi (versioni precedenti, format alternativi, alias di convenienza) anche non documentati nella versione corrente.

**Logica di Test.**

* **Versioned Endpoint Parity:** Per ogni endpoint in v1 che richiede auth, testare v2/v3 senza token. Oracle: `401`.  
* **Alternate Format Parity:** Se esistono `/api/users.json` e `/api/users.xml`, entrambi devono richiedere stessa autenticazione.  
* **Alias/Convenience Endpoint:** Identificare endpoint che restituiscono dati simili per naming pattern. Se `/api/me` è protetto, `/api/current-user` deve esserlo ugualmente.

---

### **2.5 L'API Non Espone Dati Eccessivi `[P2]`**

**\[Riferimenti: OWASP API3:2023 Broken Object Property Level Authorization, OWASP ASVS v5.0.0 V8.2.3 \+ V14.2.6, NIST SP 800-53 Rev. 5 SC-4\]**

**Concetto.** Questo controllo verifica che le response API contengano solo i campi che l'utente autenticato ha diritto di vedere, anziché l'intero oggetto database. Il filtraggio deve avvenire lato server, non lato client (security by obscurity). Un attaccante legge la raw HTTP response e accede a campi nascosti dall'UI.

**Scenario di Failure.**

* **Password Hash in Response:** `GET /api/users/me` restituisce `{"id": 1, "name": "Alice", "passwordHash": "$2b$10$..."}`. Anche se hash, non dovrebbe essere esposto; l'attaccante può tentare crack offline.

**Assunzioni e Prerequisiti:** Approccio **Grey Box**. Il tester deve possedere token JWT validi per almeno due ruoli distinti (utente standard e admin), per verificare il filtraggio differenziale dei campi. È necessaria la specifica OpenAPI o la documentazione del modello dati per identificare i campi sensibili che non dovrebbero essere esposti.

**Logica di Test.**

* **Sensitive Field Presence:** `GET /api/users/me`. Oracle: la response NON deve contenere `password`, `passwordHash`, `ssn`, `creditCard`, `apiKey` (ASVS V14.2.6).  
* **Role-Based Field Filtering:** Login come admin → `GET /api/users/123` → salvare response (include SSN). Login come user → stessa request. Oracle: la response user NON contiene SSN (confronto field-by-field, ASVS V8.2.3).  
* **Nested Object Filtering:** `GET /api/orders/123` — se include un oggetto `user`, deve contenere solo campi pubblici (id, name), non email/phone.

---

## **DOMINIO 3: INTEGRITÀ DEI DATI**

### **3.1 Tutti gli Input Sono Validati Secondo Schema e Constraints `[P2]`**

**\[Riferimenti: OWASP API10:2023, CWE-20, OWASP ASVS v5.0.0 V2.2.1 \+ V1.2, NIST SP 800-53 Rev. 5 SI-10\]**

**Concetto.** Questo controllo verifica che ogni input (body, query param, path param, header) sia validato contro tipo, formato, range, lunghezza e pattern attesi prima di raggiungere la business logic. L'approccio whitelist — accettare solo valori noti-buoni — previene SQL injection, NoSQL injection, command injection, type confusion, e DoS via payload anomali. Il Gateway può applicare validazione schema superficiale (conformità OpenAPI); la validazione semantica profonda rimane applicativa.

**Scenari di Failure (Critici).**

* **SQL Injection:** `GET /api/users?name=' OR '1'='1--` restituisce tutti gli utenti.  
* **NoSQL Injection:** `POST /api/login {"username": {"$ne": null}, "password": {"$ne": null}}` bypassa autenticazione in MongoDB.  
* **Buffer Overflow / OOM:** `POST /api/upload` con file 10GB; server alloca l'intera memoria e crasha.

**Assunzioni e Prerequisiti:** Approccio **Grey Box**. Il tester deve disporre di un token JWT valido per utente standard (per testare endpoint autenticati), della specifica OpenAPI per identificare i tipi attesi di ciascun campo, e di un ambiente di test su cui inviare payload potenzialmente anomali senza impatto su dati di produzione.

**Logica di Test.**

* **Injection Payloads:** Testare `' OR '1'='1--` (SQL), `{"$ne": null}` (NoSQL), `8.8.8.8; whoami` (command). Oracle: `400 Bad Request` con messaggio generico; nessuna esecuzione dell'injection.  
* **Type Confusion:** Inviare tipo errato per ogni field (string invece di int, array invece di string, object invece di boolean). Oracle: `400` con indicazione del tipo atteso.  
* **Boundary e Size Limits:** Inviare payload \>100MB, valori numerici oltre max int32 (es. `99999999999999999999`), stringhe oltre lunghezza massima dichiarata, path con `../../etc/passwd`. Oracle: `400` o `413 Payload Too Large`; nessun crash o allocazione incontrollata.  
* **Encoding e Injection in Header:** Inviare query param con `\r\n` (CRLF injection), emoji in campo alphanumeric-only (`user😀123`), caratteri Unicode in campo strict. Oracle: `400` o sanitizzazione; response header non deve contenere entry iniettate.

---

### **3.2 → Fusa in Garanzia 6.1**

*(I contenuti sulla prevenzione di information leakage via error message e debug data sono stati integrati nella Garanzia 6.1 "Error Handling e Information Disclosure". La sezione è stata eliminata per evitare ridondanza strutturale.)*

---

### **3.3 I Dati in Transit Sono Protetti da Manipolazione (Beyond TLS) `[P3]`**

**\[Riferimenti: OWASP ASVS v5.0.0 V4.1.5, NIST SP 800-175B Rev. 1, NIST SP 800-107 Rev. 1\]**

**Concetto.** Questo controllo riguarda meccanismi di integrità applicativa oltre TLS (HMAC request signature, JWT signed response, content hash) per prevenire manipolazione da proxy intermediari fidati o replay attack. È un controllo avanzato di architettura applicativa, non una funzione Gateway standard.

**Scenario di Failure.**

* **Manipolazione da Proxy Fidato:** Corporate proxy modifica il body di `POST /api/transfer {"amount": 100}` in `{"amount": 1000}`. Senza HMAC, la modifica non viene rilevata.

**Assunzioni e Prerequisiti:** Approccio **White Box — Audit di Configurazione**. Il tester ha accesso alla documentazione dell'architettura applicativa per verificare se il meccanismo di firma è implementato, e ai file di configurazione o al codice sorgente del middleware per verificarne i parametri. Il test empirico è indicato solo se il meccanismo è già implementato e deve essere validato.

**Audit di Configurazione (Checklist).**

* **\[AUDIT\]** Verificare nella documentazione tecnica o nel codice del middleware se è implementato un meccanismo di HMAC request signature (es. AWS Signature V4, custom `X-Signature` header con SHA-256). Se non implementato, documentare l'assenza come gap architetturale e valutare il rischio in base al modello di threat (presenza di proxy interni fidati nel percorso).  
* **\[AUDIT\]** Se il meccanismo è implementato: verificare nella configurazione che l'algoritmo usato sia SHA-256 o superiore (NIST SP 800-107 Rev. 1\) e che la chiave condivisa abbia entropia ≥ 256 bit. Algoritmi MD5 o SHA-1 per HMAC devono essere documentati come non conformi.  
* **\[AUDIT\]** Verificare che il meccanismo includa protezione da replay attack tramite: timestamp nel payload con finestra di validità ≤ 5 minuti, oppure nonce monouso con verifica di unicità su Redis. L'assenza di entrambi rende il meccanismo HMAC vulnerabile a replay indipendentemente dalla robustezza dell'algoritmo.  
* **\[TEST EMPIRICO — Solo se il meccanismo è implementato\]** Request Tampering: generare request con HMAC signature valida → modificare il body mantenendo la signature originale → Oracle: `400` o `403` per "Signature mismatch". Replay: re-inviare request con timestamp → Oracle: `400 "Request expired"` dopo la finestra configurata.

---

## **DOMINIO 4: DISPONIBILITÀ E RESILIENZA**

### **4.1 Il Sistema Previene Resource Exhaustion via Rate Limiting `[P0]`**

**\[Riferimenti: OWASP API4:2023 Unrestricted Resource Consumption, OWASP ASVS v5.0.0 V2.4.1, NIST SP 800-204 Section 4.5\]**

**Concetto.** Questo controllo verifica che il Gateway applichi rate limiting per prevenire abuse automatizzato (DoS, brute-force, scraping). Le strategie — Fixed Window, Sliding Window, Token Bucket, Leaky Bucket — sono funzioni native di ogni API Gateway di produzione. I limiti si applicano per IP, User ID (post-auth), e API Key. Il superamento del limite produce `429 Too Many Requests` con header `Retry-After`. Questa garanzia è separata dalla 7.1 (protezione business flow) perché riguarda la disponibilità infrastrutturale, non la logica applicativa.

**Scenari di Failure.**

* **Assenza su Endpoint CPU-Intensive:** `GET /api/reports/export` genera report PDF. Senza rate limit, un loop infinito porta il server a saturazione CPU.  
* **Assenza su Login Endpoint:** `POST /api/auth/login` senza limite consente brute-force password illimitato.  
* **Rate Limit In-Memory (Single Instance):** Il contatore è per-istanza; con load balancer round-robin, ogni istanza vede solo una frazione delle richieste e non raggiunge mai il limite.

**Assunzioni e Prerequisiti:** Approccio **Black Box** (per test di enforcement) e **Grey Box** (per test per-user). Il tester non richiede conoscenza dell'architettura interna per verificare il comportamento del rate limiting. Per il test "Rate Limit per User vs per IP" è necessario disporre di token JWT per due utenti distinti. Il limite configurato deve essere noto o ricavabile dalla documentazione API o dagli header di risposta (`X-RateLimit-Limit`).

**Logica di Test.**

* **Enforcement del Limite:** Identificare il limite documentato (es. 100 req/min). Eseguire script che invia 101 request in \<60s. Oracle: le prime 100 ricevono `200 OK`, la 101ª riceve `429 Too Many Requests` (ASVS V2.4.1).  
* **Retry-After Header:** Dopo `429`, verificare presenza di `Retry-After: {seconds}` o `X-RateLimit-Reset: {timestamp}`. Attendere il periodo indicato e inviare nuova request. Oracle: `200 OK` (limite resettato).  
* **Rate Limit per User vs per IP:** Login userA → 101 request → `429`. Logout → login userB dallo stesso IP → inviare request. Oracle: se limite per USER, userB riceve `200 OK` (counter separato); se per IP, `429` (counter condiviso). Il comportamento deve corrispondere alla policy dichiarata.  
* **Burst Behavior (Token Bucket):** Se il limite permette burst (es. 20 request istantanee): inviare 20 request simultanee in threading → Oracle: tutte `200 OK`. Inviare la 21ª istantaneamente → Oracle: `429`.  
* **Header Spoofing Resistance:** Inviare request con `X-Forwarded-For` randomizzato a ogni call. Oracle: il Gateway deve usare l'IP reale dalla connessione TCP (non il valore dell'header) per il rate limiting; il bypass non deve avere successo.

---

### **4.2 Il Sistema Implementa Timeout per Prevenire Resource Lock `[P1]`**

**\[Riferimenti: OWASP API4:2023, CWE-400, NIST SP 800-204A Section 4.3\]**

**Concetto.** Questo controllo verifica che ogni operazione I/O (query DB, chiamata HTTP esterna, file read) abbia un timeout configurato. Senza timeout, un thread rimane bloccato indefinitamente se la risorsa non risponde; l'accumulo di thread bloccati esaurisce il pool e rende il server incapace di accettare nuove richieste.

**Scenari di Failure.**

* **No Timeout su DB Query:** `GET /api/users` esegue `SELECT * FROM users`. DB ha lock contention, query pende indefinitamente. 100 request simultanee → 100 thread bloccati → thread pool exhausted.  
* **External API Call Senza Timeout:** `GET /api/weather` chiama servizio esterno down che non risponde. Default timeout potrebbe essere 60s+; user aspetta 60s per vedere errore.

**Assunzioni e Prerequisiti:** Approccio **White Box — Audit di Configurazione**. Il tester ha accesso in lettura ai file di configurazione del Gateway e dei servizi applicativi, oppure può interrogare l'Admin API per estrarre i parametri di timeout configurati. Il test empirico con mock service è indicato opzionalmente in ambienti di staging per validare che il timeout configurato si traduca nel comportamento atteso.

**Audit di Configurazione (Checklist).**

* **\[AUDIT\]** Verificare nella configurazione del Gateway (Kong: `upstream.connect_timeout`, `upstream.read_timeout`, `upstream.write_timeout`; Nginx: `proxy_connect_timeout`, `proxy_read_timeout`, `proxy_send_timeout`; AWS API GW: Integration Timeout) che i timeout siano configurati e inferiori a 30 secondi. Oracle: `connect_timeout` ≤ 5s, `read_timeout` ≤ 30s. Valori non configurati implicano il default del runtime (spesso 60s o illimitato), che deve essere documentato come gap.  
* **\[AUDIT\]** Verificare nella configurazione del connection pool applicativo (HikariCP: `connectionTimeout`, `idleTimeout`; PgBouncer: `server_connect_timeout`, `query_timeout`) che siano presenti timeout espliciti. Oracle: `connectionTimeout` ≤ 10s, `query_timeout` ≤ 30s per query standard.  
* **\[AUDIT\]** Verificare che le chiamate a servizi esterni nel codice applicativo (HTTP client: Apache HttpClient `setConnectTimeout`, Python requests `timeout`, Node.js axios `timeout`) abbiano timeout configurati esplicitamente e non affidarsi al default del client. Oracle: timeout configurato ≤ 15s per chiamate sincrone.  
* **\[TEST EMPIRICO OPZIONALE — Solo in ambiente staging\]** Configurare un mock service con delay programmato (30s). Inviare richiesta all'endpoint che lo chiama. Oracle: risposta ricevuta entro il timeout configurato (es. 10s) con `503` o `504 Gateway Timeout`, non dopo il delay completo del mock.

---

### **4.3 Il Sistema Degrada Gracefully con Circuit Breaker `[P1]`**

**\[Riferimenti: OWASP API4:2023, OWASP ASVS v5.0.0 V16.5.2, NIST SP 800-204 Section 4.5.1, Martin Fowler — Circuit Breaker Pattern (2014)\]**

**Concetto.** Il Circuit Breaker previene il cascading failure quando un servizio downstream fallisce, implementando tre stati: **Closed** (normale), **Open** (downstream failing — request bloccate immediatamente con risposta cached o errore, senza attendere timeout), **Half-Open** (dopo timeout, singola request probe per verificare il recovery). Trigger tipico: N failure consecutive (es. 5\) o percentuale di failure in una finestra temporale. È una funzione nativa di Gateway avanzati (Istio `outlierDetection`, Kong Enterprise, AWS API GW integration).

**Scenario di Failure.**

* **Circuit Breaker Assente:** Durante un incident (DB overload), ogni request attende il timeout (30s default). Con 100 req/sec, in 30s il Gateway accumula 3000 request pending, satura il thread pool (Tomcat: 200 thread di default), e il fallimento di un singolo servizio dipendente causa cascading failure sull'intero Gateway.

**Assunzioni e Prerequisiti:** Approccio **White Box — Audit di Configurazione** con test comportamentale opzionale in staging. Il tester ha accesso in lettura alla configurazione del Gateway (Admin API o file di configurazione) per verificare i parametri del circuit breaker. Il test di graceful degradation, se necessario, richiede coordinamento con il team per disabilitare un servizio dipendente in ambiente non-produttivo.

**Audit di Configurazione (Checklist).**

* **\[AUDIT\]** Verificare via Admin API o file di configurazione la presenza di direttive circuit breaker: Kong plugin `circuit-breaker` o `response-ratelimiting`; Traefik middleware `circuitbreaker`; Istio `DestinationRule.trafficPolicy.outlierDetection`; AWS API GW integration con retry policy e timeout. L'assenza totale di qualsiasi direttiva equivalente deve essere documentata come gap architetturale critico (ASVS V16.5.2).  
* **\[AUDIT\]** Estrarre e verificare i parametri configurati. Oracle per ciascuno: `failure_threshold` (numero di failure consecutive che aprono il circuito): valore atteso 3–10; `timeout_duration` (durata dello stato Open prima del Half-Open): valore atteso 30s–120s; `trigger_codes` (codici HTTP che contano come failure): deve includere sia 5xx che timeout/connessioni rifiutate, non solo 500\.  
* **\[AUDIT\]** Verificare se il Gateway espone endpoint di health che riportano lo stato dei circuit breaker (Kong Admin `/status`; Spring Boot Actuator `/actuator/health`; Istio Pilot metrics). Oracle: presenza di campi `circuit_name`, `state` (CLOSED/OPEN/HALF\_OPEN), `failure_count`. Un sistema senza observability sul circuit breaker non è gestibile durante un incident.  
* **\[AUDIT\]** Analizzare le metriche storiche del sistema di monitoring (Grafana, CloudWatch, Datadog) in read-only per gli ultimi 30 giorni. Cercare eventi `circuit_breaker_state_change`, `circuit_breaker_trip_count`, `rejected_requests_count`. L'assenza totale di questi eventi in 30 giorni può indicare threshold troppo alto o circuit breaker disabilitato — non necessariamente stabilità del sistema.  
* **\[TEST COMPORTAMENTALE OPZIONALE — Solo in ambiente staging, coordinato con il team\]** Disabilitare temporaneamente un servizio dipendente non-critico. Inviare request all'endpoint che lo chiama. Oracle: risposta immediata (\<1s) con fallback graceful o `503` con `Retry-After`. Una risposta che blocca per la durata del timeout configurato prima di fallire indica che il circuit breaker non è attivo o non è in stato Open.

---

## **DOMINIO 5: VISIBILITÀ E AUDITING**

### **5.1 Ogni Richiesta È Logged con Metadata Essenziali `[P1]`**

**\[Riferimenti: NIST SP 800-92, NIST SP 800-53 Rev. 5 AU-2, OWASP ASVS v5.0.0 V16.2.1, GDPR Article 30\]**

**Concetto.** Questo controllo verifica che il Gateway generi log strutturati (JSON) per ogni request, contenenti i metadata minimi richiesti da NIST SP 800-92 per incident response e audit: timestamp UTC, Request ID, HTTP method \+ path, source IP reale (non proxy), User ID (se autenticato), status code, response time. I dati sensibili (password, token, SSN) devono essere redatti per conformità GDPR Art. 30\.

**Scenari di Failure.**

* **Missing Logs su Security Events:** Login failure e authorization denial non loggati — il brute-force passa inosservato.  
* **Dati Sensibili in Log Chiaro:** `POST /api/login {"password": "secret123"}` registrato in chiaro — se i log sono compromessi, le credenziali sono esposte (GDPR violation).  
* **Log Injection:** Username `"admin\n[CRITICAL] System breached"` inietta una falsa entry nel log che nasconde l'attacco reale o genera false alarm.

**Assunzioni e Prerequisiti:** Approccio **Grey Box**. Il tester deve disporre di un token JWT valido per effettuare richieste autenticate, e di accesso in lettura al log aggregator (Elasticsearch/Kibana, Splunk, CloudWatch Logs, Datadog) per verificare le entry generate. Senza accesso ai log, questo controllo non è verificabile empiricamente dall'esterno.

**Logica di Test.**

* **Log Entry Presence:** Eseguire `GET /api/users/me` autenticato → verificare nel log aggregator la presenza di: timestamp, request ID, `method=GET`, `path=/api/users/me`, `userId={authenticatedUserId}`, `statusCode=200`, `responseTime>0ms` (ASVS V16.2.1).  
* **Sensitive Data Redaction:** `POST /api/login {"username": "test", "password": "secret"}`. Oracle: log non contiene `"password": "secret"` (GDPR). Deve essere `"password": "[REDACTED]"` o omesso.  
* **Security Event Logging:** `GET /api/admin/users` senza token. Oracle: entry log con `statusCode=401`, `path=/admin/users`, `userId=null`, `reason="Missing token"`.  
* **Log Injection Prevention:** `POST /api/users {"username": "alice\nFAKE LOG ENTRY"}`. Oracle: username escapato (`alice\\nFAKE LOG ENTRY`) o sanitizzato nel log. Nessuna entry log separata generata.  
* **Real IP Logging:** Inviare request con `X-Forwarded-For: 1.2.3.4`. Oracle: IP loggato è `1.2.3.4` (IP client reale), non l'IP del proxy o load balancer.

---

### **5.2 Eventi Security Anomali Triggerano Alert Real-Time `[P2]`**

**\[Riferimenti: NIST SP 800-61 Rev. 3 Section 2.3, OWASP ASVS v5.0.0 V7.1.1, GDPR Article 33\]**

**Concetto.** Questo controllo verifica che eventi security-critical (brute-force, BOLA enumeration, rate limit hit, spike traffico anomalo) triggerino alert attivi verso SIEM o canali di notifica (PagerDuty, Slack) in tempo reale secondo NIST SP 800-61 Rev. 3\. L'efficacia del sistema dipende dall'infrastruttura di monitoring e dalla definizione delle correlation rules — parzialmente verificabile dall'esterno.

**Scenari di Failure.**

* **Brute-Force Undetected:** 10.000 tentativi password in 10 minuti. Log esistono ma nessun alert; security team scopre breach settimane dopo.  
* **Alert Fatigue:** Sistema genera alert per ogni singolo `401` error; 1000 alert/giorno (mostly false positive). Team ignora alert, miss eventi reali.

**Assunzioni e Prerequisiti:** Approccio **Grey Box** con componente di Configuration Audit. Il tester deve avere accesso in lettura alla configurazione delle alert rules (SIEM, Grafana Alert Manager, CloudWatch Alarms) per verificare threshold e logica di correlazione. Per i test comportamentali, è necessario un endpoint webhook o canale di notifica in ambiente di test su cui ricevere gli alert generati, per verificarne la latenza e il contenuto.

**Logica di Test.**

* **Brute-Force Alert:** Eseguire 20 login failure in 60s. Oracle: entro 10s dall'ultima failure, alert generato (verifica via webhook receiver o pattern `ALERT.*brute_force` nei log, ASVS V16.3).  
* **Alert Deduplication:** Triggerare lo stesso evento 10 volte. Oracle: alert inviato una sola volta con counter aggregato (non 10 alert separati — previene spam).  
* **Alert Threshold Verification:** Con threshold configurata a 5 failure: inviare 4 failure → Oracle: nessun alert. 5 failure → Oracle: alert triggered. Questo test verifica che la threshold dichiarata nella configurazione corrisponda al comportamento reale.

---

## **DOMINIO 6: CONFIGURAZIONE E HARDENING**

### **6.1 Error Handling e Information Disclosure `[P2]`**

**\[Riferimenti: OWASP API8:2023 Security Misconfiguration, OWASP ASVS v5.0.0 V13.4.2 \+ V13.4.6 \+ V16.5.1, CWE-209, NIST SP 800-53 Rev. 5 SI-11 \+ SC-7\]**

**Concetto.** Questo controllo verifica che le response dell'API — sia in condizioni di errore che in condizioni normali — non espongano informazioni tecniche interne. I vettori sono due: **(1) Error Messages Dettagliati** contenenti stack trace, query SQL, path filesystem, o versioni librerie che abilitano il fingerprinting del backend e l'identificazione di CVE applicabili; **(2) Debug Data Residuo** in produzione (campi `_debug`, `_sql_query`, versioni framework in header `X-Powered-By`) che espongono architettura interna. Il principio è fail-secure: messaggi generici al client, dettagli tecnici nei log server-side.

**Scenari di Failure.**

* **Stack Trace in Response:** `POST /api/orders {"productId": "invalid-uuid"}` → risposta `500` con `Caused by: java.lang.IllegalArgumentException at com.example.OrderController:47` — rivela framework (Spring Boot), versione, path dei file.  
* **SQL Error Leak:** `GET /api/users?id=1'` → risposta con `ERROR: syntax error at or near "'"` — conferma SQL injection e rivela nomi tabelle.  
* **Debug Mode in Produzione:** Flag `DEBUG=True` dimenticato dopo deployment; ogni errore include environment variables, potenzialmente contenenti API key e credenziali database.  
* **Informazioni Differenziali negli Errori Auth:** Risposta diversa per "user non trovato" vs "password errata" abilita username enumeration.

**Assunzioni e Prerequisiti:** Approccio **Grey Box**. Il tester deve disporre di un token JWT valido (per testare endpoint autenticati) e accesso alle response HTTP raw. Non è richiesto accesso a configurazioni interne: tutti i test si basano sull'osservazione delle response restituite dal server a fronte di input anomali deliberatamente costruiti.

**Logica di Test.**

* **Stack Trace Detection su Errori Provocati:** Inviare request progettate per triggerare eccezioni backend: type mismatch (`{"age": "not-a-number"}`), field obbligatorio mancante, JSON malformato (`{"malformed": }`), payload oversized (\>10MB). Oracle: response NON deve contenere keyword `Exception`, `at com.`, `Caused by`, path filesystem (`/opt/`, `/var/`), nomi di classe Java/Python, o versioni framework (ASVS V13.4.2).  
* **Debug Field Detection in Response Normale:** Inviare request valida a endpoint CRUD (es. `GET /api/products/123`). Analizzare response JSON per field non documentati in OpenAPI: pattern `_debug`, `_sql`, `_trace`, `_internal`, `databaseId`, `shardKey`, `cacheHit`. Oracle: nessun field con naming tecnico o informazioni architetturali.  
* **Header Information Leakage:** Analizzare response header. Oracle: `X-Powered-By` assente o generico; `Server` generico (`nginx`, non `nginx/1.18.0 (Ubuntu)`); header `X-*` interni rimossi dal Gateway (ASVS V13.4.6).  
* **Error Verbosity Consistency:** Testare quattro condizioni di errore: JSON malformato, business rule violation, autenticazione fallita, autorizzazione negata. Oracle: tutti i messaggi devono avere lo stesso livello di astrazione. In particolare, l'errore di autenticazione non deve distinguere "user not found" vs "wrong password" (abilitazione di username enumeration).  
* **Correlation ID in Error Response:** Oracle: ogni risposta di errore deve contenere un correlation ID (`{"error": "Internal Server Error", "requestId": "uuid-123"}`), consentendo al supporto di recuperare i dettagli tecnici nei log interni tramite quell'ID senza esporre informazioni al client.

---

### **6.2 Security Header Configurati Appropriatamente `[P3]`**

**\[Riferimenti: OWASP API8:2023, OWASP ASVS v5.0.0 V3.4 (3.4.1–3.4.7), RFC 9110, Mozilla Observatory Security Headers Best Practices\]**

**Concetto.** Questo controllo verifica la presenza e correttezza degli HTTP security header che costituiscono defense-in-depth contro attacchi client-side: HSTS (forza HTTPS), X-Content-Type-Options (previene MIME sniffing), X-Frame-Options (previene clickjacking), Content-Security-Policy (previene XSS), Permissions-Policy (disabilita feature browser rischiose). Sono configurazioni statiche del Gateway, verificabili con una singola request.

**Scenario di Failure.**

* **Missing HSTS:** User digita `http://api.example.com` → browser fa request HTTP → attacker MitM intercetta (SSL stripping). HSTS previene questo dopo prima visita HTTPS.

**Assunzioni e Prerequisiti:** Approccio **White Box — Audit di Configurazione**. Tutte le verifiche sono eseguibili con una singola `curl -I https://api.example.com` o tramite ispezione del file di configurazione del Gateway. Non è richiesto alcun token autenticato né accesso privilegiato: gli header di sicurezza devono essere presenti su ogni risposta, incluse quelle a endpoint pubblici.

**Audit di Configurazione (Checklist).**

* **\[AUDIT\]** Verificare la presenza e il valore dell'header `Strict-Transport-Security`. Oracle: `Strict-Transport-Security: max-age=31536000; includeSubDomains` (ASVS V3.4.1). Un valore `max-age` inferiore a 31536000 (1 anno) è subottimale; l'assenza dell'header è non conforme.  
* **\[AUDIT\]** Verificare la presenza dell'header `X-Frame-Options`. Oracle: valore `DENY` o `SAMEORIGIN` (ASVS V3.4.6). Il valore `ALLOW-FROM` è deprecato in RFC 9110 e non deve essere usato.  
* **\[AUDIT\]** Verificare la presenza dell'header `X-Content-Type-Options`. Oracle: `nosniff` (ASVS V3.4.4). L'assenza consente MIME-type sniffing nei browser meno recenti.  
* **\[AUDIT\]** Verificare la presenza e il valore dell'header `Content-Security-Policy`. Oracle: deve essere presente e non deve contenere `default-src *`. Il valore minimo accettabile è `default-src 'self'` (ASVS V3.4.3). Una policy permissiva con wildcard è equivalente all'assenza della policy.  
* **\[AUDIT\]** Verificare la presenza dell'header `Permissions-Policy`. Oracle: le funzionalità browser non utilizzate dall'applicazione devono essere esplicitamente disabilitate: `geolocation=(), camera=(), microphone=()`.  
* **\[AUDIT\]** Verificare la consistenza degli header su tutti gli endpoint (pubblici, autenticati, admin). La presenza degli header su un endpoint e l'assenza su un altro indica misconfiguration selettiva nel Gateway. Strumento: confronto automatizzato delle response header su un campione rappresentativo di endpoint.

---

### **6.3 La Configurazione del Gateway È Hardenata Contro Exploit Layer-7 `[P1]`**

**\[Riferimenti: OWASP API8:2023, OWASP ASVS v5.0.0 V14.2.1 \+ V14.5.3, RFC 9110 Section 9.3, CWE-444 (HTTP Request Smuggling), NIST SP 800-204 Section 4.5.1\]**

**Concetto.** Il Gateway introduce un layer di parsing HTTP che, se configurato debolmente, diventa attack surface per HTTP Request Smuggling (CWE-444) e Slowloris DoS. Request smuggling sfrutta discrepanze tra il parsing del Gateway (frontend) e quello del backend: header `Content-Length` e `Transfer-Encoding: chunked` presenti simultaneamente violano RFC 9110, ma parser diversi danno precedenza a uno o all'altro, permettendo a un attaccante di "contrabbandare" una request che bypassa i controlli del Gateway. Un Gateway hardenato deve: rifiutare header ambigui, normalizzare i path prima di applicare le policy, applicare timeout Layer-7 aggressivi (header timeout ≤ 10s, body timeout ≤ 30s) per prevenire Slowloris.

**Scenari di Failure.**

* **CL.TE Desync:** Il Gateway usa `Content-Length`, il backend usa `Transfer-Encoding`. L'attaccante costruisce una request che il Gateway interpreta come una sola (valida e autenticata) ma il backend come due: la seconda request "contrabbandabile" non è passata per il Gateway e bypassa i controlli di autenticazione.  
* **Slowloris via Long Header Parsing:** Con header timeout a 60s (default insicuro), 10.000 connessioni con header parziali saturano il connection pool per 60s ciascuna.  
* **CORS Wildcard con Credentials:** `Access-Control-Allow-Origin: *` combinato con `Access-Control-Allow-Credentials: true` viola la spec CORS e può abilitare esfiltrazione cross-origin su browser legacy.

**Assunzioni e Prerequisiti:** Approccio **misto Grey Box / White Box**. I test di HTTP Smuggling e CORS richiedono solo connettività di rete (Grey Box). I test di timeout e plugin richiedono accesso in lettura alla configurazione del Gateway via Admin API o file di configurazione (White Box). Il test CORS con browser automation richiede un ambiente di test controllato.

**Logica di Test.**

* **HTTP Request Smuggling (CL.TE) — Test Empirico:** Costruire request con `Content-Length` e `Transfer-Encoding: chunked` simultaneamente. Oracle: `400 Bad Request` per "ambiguous headers" (RFC 9110, ASVS V14.5.3). Il Gateway non deve inoltrarla al backend.  
* **\[AUDIT\] Timeout Layer-7:** Verificare nella configurazione del Gateway i parametri di timeout HTTP: Nginx `client_header_timeout` e `client_body_timeout`; Kong `client_header_timeout`; HAProxy `timeout http-request`. Oracle: `header_timeout` ≤ 10s, `body_timeout` ≤ 30s. Valori di default superiori (spesso 60s) devono essere ridotti esplicitamente.  
* **\[AUDIT\] Plugin Source e Versioning:** Elencare i plugin Gateway installati via Admin API (Kong: `GET /plugins`). Per ogni plugin: verificare la provenienza da repository ufficiale, la presenza di version pinning nel file di configurazione, e l'assenza di CVE ad alta severità nel security advisory del vendor (ASVS V14.2.1).  
* **CORS Strict Enforcement — Test Empirico:** Verificare che l'header `Access-Control-Allow-Origin` nella risposta sia una whitelist specifica di domini autorizzati, non il wildcard `*`. Se `Access-Control-Allow-Credentials: true` è presente, il wildcard è una violazione della spec CORS RFC 6454 e deve essere segnalata come critica.  
* **Path Normalization e Method Override — Test Empirico:** Inviare varianti di path (doppio slash, path traversal, URL encoding) su endpoint protetto senza token. Oracle: tutte le varianti restituiscono `403` — policy applicata dopo normalizzazione. Se il Gateway supporta `X-HTTP-Method-Override`, verificare che il metodo effettivo riconosciuto sia coerente tra Gateway e backend.

---

### **6.4 Le Credenziali di Servizio Non Sono Hardcoded o Esposte `[P2]`**

**\[Riferimenti: OWASP API8:2023, OWASP ASVS v5.0.0 V13.3.1 \+ V13.3.4 \+ V13.4.1, CWE-798, NIST SP 800-53 Rev. 5 IA-5(1), NIST SP 800-204 Section 5.4\]**

**Concetto.** Questo controllo verifica che le credenziali usate dal Gateway (password database, API key, private key TLS) siano gestite tramite Secret Manager dedicato (AWS Secrets Manager, HashiCorp Vault, Azure Key Vault) e non hardcoded in file di configurazione o immagini Docker. Credenziali statiche non possono essere ruotate senza redeploy e, se esposte via path traversal o repository leak, forniscono accesso diretto al backend bypassando il Gateway.

**Scenari di Failure.**

* **Database Password in Config File:** `/etc/kong/kong.conf` contiene `pg_password = SuperSecret123!` in chiaro. Un attaccante con accesso read-only al filesystem la estrae e si connette direttamente al database.  
* **API Key in Dockerfile:** `ENV STRIPE_API_KEY=sk_live_xxx` in un'immagine Docker pushata su registry pubblico. Bot automatizzati scansionano Docker Hub per pattern `sk_live_*` in minuti.  
* **Nessuna Rotation Policy:** Credenziali gestite da secret manager ma senza rotation. Stesso secret in uso da 3 anni; ex-dipendente con accesso storico può ancora accedere post-terminazione (ASVS V13.3.4).

**Assunzioni e Prerequisiti:** Approccio **White Box — Audit di Configurazione**. Il tester ha accesso in lettura ai file di configurazione del Gateway, alle immagini Docker (tramite registry o `docker history`), e all'audit trail del secret manager. L'unico test parzialmente empirico (debug endpoint exposure) richiede connettività di rete verso l'ambiente target.

**Audit di Configurazione (Checklist).**

* **\[AUDIT\]** Eseguire regex scan sui file di configurazione Gateway accessibili per pattern noti di credenziali: `password\s*=\s*['"]\S+['"]`, `api_key\s*=`, `AKIA[A-Z0-9]{16}` (AWS Access Key), `sk_live_` (Stripe). Oracle: nessun match con valore ad alta entropia (\>20 caratteri non-placeholder). Valori come `CHANGE_ME` o `xxx` sono accettabili come placeholder; valori realistici sono CRITICAL (ASVS V13.3.1).  
* **\[TEST EMPIRICO\]** Debug Endpoint Exposure: verificare che endpoint di debug non espongano variabili d'ambiente (`/actuator/env`, `/debug/vars`, `/api/config`). Oracle: se l'endpoint è raggiungibile e restituisce `DATABASE_PASSWORD`, `API_KEY`, o `AWS_SECRET_ACCESS_KEY` in chiaro, è una direct leak critica. Le env vars devono contenere reference al secret store (es. `arn:aws:secretsmanager:...`), non il valore diretto.  
* **\[AUDIT\]** Se disponibile l'accesso al container registry, eseguire `docker history <image>` e cercare nei layer storici comandi `ENV` o `RUN echo` contenenti credenziali. Oracle: nessuna credenziale in nessun layer. I secret devono essere iniettati a runtime tramite orchestrator (Kubernetes Secrets montati come volume, Docker Swarm secrets) e non inclusi nell'immagine.  
* **\[AUDIT\]** Verificare nell'audit trail del secret manager (AWS CloudTrail per Secrets Manager, Vault audit log) che le credenziali critiche (database password, payment API key) siano state ruotate almeno negli ultimi 90 giorni (NIST SP 800-53 IA-5(1), ASVS V13.3.4). L'assenza di eventi di rotazione negli ultimi 90 giorni deve essere segnalata come non conformità.

---

## **DOMINIO 7: BUSINESS LOGIC E FLUSSI SENSIBILI**

### **7.1 I Flussi Business Sensibili Sono Protetti da Abuse Automatizzato `[P2]`**

**\[Riferimenti: OWASP API6:2023 Unrestricted Access to Sensitive Business Flows, OWASP Automated Threats OAT-001–OAT-021, OWASP ASVS v5.0.0 V2.4.1 \+ V2.4.2, NIST SP 800-63B-4 Section 5.2.5\]**

**Concetto.** Questa garanzia è distinta dalla 4.1 (Rate Limiting infrastrutturale) perché affronta la protezione della logica di business da abuse automatizzato, non la disponibilità del servizio. Mentre il rate limiting generico limita il volume di richieste, la protezione dei flussi sensibili riguarda endpoint specifici ad alto valore (payment, account creation, password reset, coupon redemption) che richiedono meccanismi anti-bot dedicati: CAPTCHA, OTP, behavioral analysis, device fingerprinting. Un bot può rimanere entro i limiti di rate e comunque causare frode (es. card testing con 1 request/minuto per 10.000 carte rubate).

**Scenari di Failure.**

* **Card Testing:** `POST /api/payment` senza CAPTCHA e con rate limit generoso (100 req/min). Un attaccante testa 10.000 carte rubate in meno di 2 ore, trovando quelle valide.  
* **Account Creation Bot:** Assenza di CAPTCHA su `POST /api/register` consente creazione di 10.000 account/ora per spam o vote manipulation.

**Assunzioni e Prerequisiti:** Approccio **Grey Box**. Il tester deve disporre di un token JWT valido (per endpoint di pagamento che richiedono autenticazione), di un ambiente di test con account reale (per i test su registrazione e verifica email), e di conoscenza degli endpoint business-critical da testare. Non è richiesto accesso a configurazioni interne.

**Logica di Test.**

* **CAPTCHA su Endpoint Sensibile:** `POST /api/payment {"amount": 100}` senza CAPTCHA token. Oracle: `400 Bad Request` "CAPTCHA required" (ASVS V2.4.1). Con token invalido: `400` "Invalid CAPTCHA".  
* **Rate Limiting Applicativo Aggressivo:** Su endpoint payment/register, eseguire 5 request in 60s (se limite è 1/min). Oracle: request 2–5 ricevono `429`.  
* **Email Verification Enforcement:** Creare account → non confermare email → tentare login. Oracle: `403 "Email not verified"` o accesso limitato fino a conferma.  
* **Device Fingerprint Tracking:** 10 registration dallo stesso device fingerprint in 10 minuti. Oracle: dopo N tentativi, CAPTCHA challenge aumentato o blocco temporaneo (ASVS V2.4.2).

---

### **7.2 Il Sistema Previene Server-Side Request Forgery (SSRF) `[P0]`**

**\[Riferimenti: OWASP API7:2023 Server Side Request Forgery, CWE-918, OWASP ASVS v5.0.0 V1.3.6, NIST SP 800-204 Section 3.2.2\]**

**Concetto.** Questo controllo verifica che il sistema blocchi SSRF: quando l'API accetta un URL fornito dall'utente ed esegue una richiesta HTTP lato server verso quell'URL, un attaccante può accedere a risorse interne (metadati cloud `169.254.169.254`, servizi su `localhost`, subnet private `10.0.0.0/8`) bypassando il firewall perimetrale. Il rischio è amplificato in Cloud, dove il metadata endpoint AWS/Azure/GCP espone IAM credentials temporanee. Le mitigazioni richiedono URL whitelist, IP blacklist su range privati/link-local, e risoluzione DNS pre-validata.

**Scenari di Failure.**

* **Accesso Cloud Metadata:** `POST /api/fetch {"url": "http://169.254.169.254/latest/meta-data/iam/security-credentials/"}` → il server restituisce AWS credentials temporanee.  
* **Internal Service Enumeration:** `POST /api/fetch {"url": "http://10.0.0.5:8080/admin"}` → il server interno non è raggiungibile da internet, ma il server API può accedervi.  
* **Bypass Blacklist via Encoding:** La blacklist blocca `127.0.0.1` ma non `127.1` (notazione abbreviata), `0x7f000001` (hex), o `2130706433` (decimal) — formati equivalenti non coperti da regex semplici.

**Assunzioni e Prerequisiti:** Approccio **Black Box** (per gli endpoint SSRF pubblici) o **Grey Box** (se l'endpoint richiede autenticazione). Il tester non ha bisogno di conoscenza dell'infrastruttura interna: i payload di test sono standard e pubblicamente documentati. Per gli endpoint autenticati, è necessario un token JWT valido per utente standard.

**Logica di Test.**

* **Cloud Metadata Access:** `POST /api/fetch {"url": "http://169.254.169.254/latest/meta-data/"}` (AWS), `http://169.254.169.254/computeMetadata/v1/` (GCP), `http://169.254.169.254/metadata/instance` (Azure). Oracle: `400 Bad Request` "Forbidden IP range" o timeout (ASVS V1.3.6).  
* **Private IP Range Blocking:** Testare `http://127.0.0.1:8080`, `http://localhost`, `http://10.0.0.5`, `http://192.168.1.1`, `http://172.16.0.1`. Oracle: tutte bloccate.  
* **Encoding Bypass:** `http://127.1`, `http://0x7f000001`, `http://2130706433`, `http://[::1]` (IPv6 localhost). Oracle: tutte bloccate (validazione robusta, non solo regex su stringa).  
* **Protocol Whitelist:** `file:///etc/passwd`, `gopher://internal.server`, `dict://`, `ftp://`. Oracle: `400` "Unsupported protocol".  
* **Redirect Following Validation:** Configurare server pubblico che risponde con `302 Redirect` verso `http://127.0.0.1`. Inviare `POST /api/fetch {"url": "http://public-redirect-server.com"}`. Oracle: il sistema deve re-validare il target URL dopo il redirect e bloccarlo se è un IP privato.  
* **Domain Whitelist Enforcement:** Se implementata whitelist di domini (es. `["api.partner.com"]`): `http://api.partner.com` → Oracle `200 OK`; `http://evil.com` → Oracle `400 Forbidden`.

---

### **7.3 Le Operazioni Critiche Sono Idempotent o Protette da Race Condition `[P2]`**

**\[Riferimenti: CWE-362 (Race Condition), OWASP ASVS v5.0.0 V2.3.3 \+ V2.3.4, RFC 7231 Section 4.2.2\]**

**Concetto.** Operazioni business-critical (payment, fund transfer, inventory deduction) devono essere idempotenti — eseguire la stessa request N volte ha lo stesso effetto di una sola esecuzione — e protette da race condition. I meccanismi implementativi sono applicativi (Idempotency Key su Redis, database transaction SERIALIZABLE, optimistic locking) e non direttamente controllabili dal Gateway; i test verificano il comportamento risultante dall'esterno.

**Scenari di Failure.**

* **Double Payment Charge:** User clicca "Pay", request timeout (network slow), user riclicca. Due request: entrambe processate → user charged $200 invece di $100.  
* **Race Condition su Inventory:** Product stock=1, due user acquistano simultaneamente. Senza sincronizzazione: entrambi leggono stock=1, entrambi deducono → stock=-1 (oversold).

**Assunzioni e Prerequisiti:** Approccio **Grey Box**. Il tester deve disporre di token JWT validi per almeno due utenti distinti, di un ambiente di staging su cui creare ordini e transazioni di test reali (il test di idempotenza richiede un endpoint di pagamento funzionante), e della capacità di inviare request concorrenti tramite threading (per i test di race condition). Nessun accesso al database è richiesto: il test verifica il comportamento comportamentale osservabile tramite API.

**Logica di Test.**

* **Duplicate Request con Idempotency Key:** `POST /api/payment Idempotency-Key: uuid-12345 {"amount": 100}` → risposta `201 Created`. Stessa request identica ripetuta. Oracle: `200 OK` (cached result, non `201`), nessun secondo addebito. Verifica DB (se accessibile): singola transazione.  
* **Race Condition su Inventory:** Setup: prodotto stock=1. Due user inviano `POST /api/orders {"productId": 123}` simultaneamente (threading). Oracle: uno successo, uno fallisce per "insufficient stock". Vulnerabilità: entrambi successo con stock=-1.  
* **Withdrawal Race Condition:** Account balance=$100. Due `POST /api/withdraw {"amount": 100}` concorrenti. Oracle: uno successo (balance=0), uno fallisce. Vulnerabilità: entrambi successo (balance=-100).

---

### **7.4 L'API Consuma Servizi Esterni in Modo Sicuro `[P2]`**

**\[Riferimenti: OWASP API10:2023 Unsafe Consumption of APIs, NIST SP 800-161 Rev. 1, OWASP ASVS v5.0.0 V13.2.4 \+ V4, NIST SP 800-204 Section 4.3\]**

**Concetto.** Quando l'API riceve webhook da provider esterni (payment provider, CI/CD, CRM) o chiama API partner, deve verificare crittograficamente l'autenticità dei dati ricevuti prima di processarli. Un webhook non verificato può essere forgiato da un attaccante per triggerare operazioni privilegiate (es. marcare un ordine come pagato senza transazione reale). NIST SP 800-161 Rev. 1 raccomanda l'approccio zero-trust verso tutti i servizi esterni, inclusi quelli fidati.

**Scenari di Failure.**

* **Webhook Senza Signature Verification:** Payment provider webhook `POST /api/webhooks/stripe {"event": "payment.success", "orderId": "123"}`. Backend estrae event, marca ordine come pagato. Nessun HMAC check. Attaccante forgia HTTP request, specifica `orderId` arbitrario → ordine marcato paid senza payment reale.  
* **XSS via Webhook Data:** Webhook riceve issue notification con title `"<script>alert('XSS')</script>"`. Backend store in DB senza sanitizzazione. Admin visualizza issue list → script eseguito.

**Assunzioni e Prerequisiti:** Approccio **Grey Box**. Il tester deve conoscere il meccanismo di firma usato dal provider esterno (tipicamente HMAC-SHA256 con secret condiviso, documentato nel developer portal del provider), avere la capacità di inviare request HTTP verso l'endpoint webhook dell'API, e disporre di un ambiente di test in cui verificare lo stato degli ordini/risorse dopo il webhook. Per il test XSS, è necessario un browser e accesso all'interfaccia admin.

**Logica di Test.**

* **Webhook Signature Verification:** Inviare webhook con HMAC valido → Oracle `200 OK`. Stesso payload con HMAC invalido → Oracle `400/403` "Signature verification failed" (ASVS V4).  
* **Replay Attack Protection:** Catturare webhook con signature valida → re-inviarlo identico dopo 10 minuti. Oracle: `400 "Request expired"` (timestamp check) o `400 "Nonce already used"`.  
* **External API Response Validation:** Configurare mock server che restituisce risposta malformata (tipo errato, field mancante). Oracle: errore gestito gracefully con type validation; il sistema non crasha e non propaga dati malformati.  
* **External API Timeout:** Mock server con delay 60s. Oracle: risposta entro timeout configurato (≤10–15s) con errore graceful; nessun hang indefinito.  
* **XSS Payload Injection via Webhook:** Webhook con payload `{"title": "<img src=x onerror=alert('XSS')>"}` con HMAC valido. Recuperare dati via API. Oracle: payload HTML-encoded o rimosso; test browser non deve triggerare `alert()`.

---

## **MATRICE DI PRIORITIZZAZIONE RISK-BASED (RIVISTA)**

La seguente matrice riflette una doppia prioritizzazione: **rilevanza per il testing Gateway-centrico** (automatizzabilità, locus di enforcement) e **severità intrinseca** (impatto se la garanzia fallisce).

### **Priority P0 — Critico: Gateway Core \+ OWASP Top Risk**

Controlli che il Gateway **deve** applicare per definizione, automatizzabili al 100% senza dipendenze applicative profonde. Il tool deve coprire queste garanzie con test eseguibili su qualsiasi API Gateway conforme.

| ID | Garanzia |
| ----- | ----- |
| **0.1** | Tutti gli Endpoint Esposti Sono Documentati (Shadow API Discovery) |
| **0.2** | Gateway Deny-by-Default su Path Non Registrati |
| **0.3** | API Deprecate Disabilitate o con Monitoring Rafforzato |
| **1.1** | Solo Richieste Autenticate Accedono a Risorse Protette |
| **1.2** | Credenziali Crittograficamente Valide (JWT Signature Validation) |
| **1.3** | Credenziali Non Scadute (Expiry Check) |
| **4.1** | Rate Limiting (Resource Exhaustion Prevention) |
| **7.2** | SSRF Prevention (Cloud Metadata Protection) |

### **Priority P1 — Alto: Business Critical \+ Gateway Feature Avanzate**

Controlli parzialmente Gateway-side o configurabili via Gateway, con impatto business-critical. Richiedono setup più elaborato (token multipli, mock service) ma rimangono automatizzabili.

| ID | Garanzia |
| ----- | ----- |
| **1.4** | Credenziali Non Revocate (Token Revocation) |
| **2.1** | Solo Utenti Autorizzati ad Endpoint Privilegiati (RBAC) |
| **2.3** | Operazioni Distruttive Richiedono Privilegi Appropriati |
| **2.4** | Policy di Autorizzazione Consistenti Across Endpoint e Versioni |
| **4.2** | Timeout per Prevenire Resource Lock |
| **4.3** | Circuit Breaker per Graceful Degradation |
| **5.1** | Audit Logging con Metadata Essenziali |
| **6.3** | Gateway Hardenato Contro Exploit Layer-7 (HTTP Smuggling, Slowloris) |

### **Priority P2 — Medio: Application Logic \+ Defense in Depth**

Controlli principalmente applicativi o che richiedono conoscenza della business logic interna. Il tool può includerli come moduli ausiliari (delegando a tool specializzati come OWASP ZAP) o come checklist guidate.

| ID | Garanzia |
| ----- | ----- |
| **1.5** | Credenziali Non su Canali Insicuri (TLS Enforcement) |
| **2.2** | BOLA Prevention (Object-Level Authorization) |
| **2.5** | Excessive Data Exposure Prevention |
| **3.1** | Input Validation Secondo Schema e Constraints |
| **5.2** | Alert Real-Time su Anomalie Security |
| **6.1** | Error Handling e Information Disclosure (ex 3.2 \+ 6.1) |
| **6.4** | Credenziali di Servizio Non Hardcoded |
| **7.1** | Flussi Business Sensibili Protetti da Abuse Automatizzato |
| **7.3** | Operazioni Critiche Idempotent (Race Condition) |
| **7.4** | Consumo Sicuro di Servizi Esterni (Webhook Verification) |

### **Priority P3 — Basso: Compliance e Best Practice Statiche**

Configurazioni statiche o logica applicativa profonda non testabile dall'esterno. Documentate come requisiti architetturali e raccomandazioni di compliance, non come test automatici nel tool.

| ID | Garanzia |
| ----- | ----- |
| **1.6** | Sessioni Sicure in Architetture Distribuite (Session Store Consistency) |
| **3.3** | Integrità Dati Beyond TLS (HMAC Request Signing) |
| **6.2** | Security Header Configurati (HSTS, CSP, X-Frame-Options) |

*Basato su: OWASP API Security Top 10 2023, OWASP ASVS v5.0.0, NIST SP 800-204/204A, NIST SP 800-63B-4, RFC 7519/8725/9110.*


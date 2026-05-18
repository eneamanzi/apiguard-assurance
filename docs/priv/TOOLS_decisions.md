# APIGuard — Tool Decisions per Test

- [Documento Operativo Consolidato](#documento-operativo-consolidato)
- [DOMINIO 0 — API Discovery \& Inventory Management](#dominio-0--api-discovery--inventory-management)
  - [0.1 Shadow API Discovery `[P0]` `[HYBRID]`](#01-shadow-api-discovery-p0-hybrid)
  - [0.2 Deny-by-Default `[P0]` `[NATIVE + opzionale]`](#02-deny-by-default-p0-native--opzionale)
  - [0.3 Deprecated API Enforcement `[P0]` `[NATIVE + opzionale]`](#03-deprecated-api-enforcement-p0-native--opzionale)
- [DOMINIO 1 — Identità e Autenticazione](#dominio-1--identità-e-autenticazione)
  - [1.1 Solo Richieste Autenticate `[P0]` `[NATIVE]`](#11-solo-richieste-autenticate-p0-native)
  - [1.2 Credenziali Crittograficamente Valide `[P0]` `[HYBRID]`](#12-credenziali-crittograficamente-valide-p0-hybrid)
  - [1.3 Credenziali Non Scadute `[P0]` `[HYBRID]`](#13-credenziali-non-scadute-p0-hybrid)
  - [1.4 Credenziali Non Revocate `[P1]` `[NATIVE]`](#14-credenziali-non-revocate-p1-native)
  - [1.5 Credenziali su Canali Insicuri `[P2]` `[HYBRID]`](#15-credenziali-su-canali-insicuri-p2-hybrid)
  - [1.6 Session Management `[P3]` `[NATIVE]`](#16-session-management-p3-native)
- [DOMINIO 2 — Autorizzazione e Controllo Accessi](#dominio-2--autorizzazione-e-controllo-accessi)
  - [2.1 RBAC Endpoint Privilege `[P1]` `[NATIVE]`](#21-rbac-endpoint-privilege-p1-native)
  - [2.2 BOLA Prevention `[P1]` `[NATIVE + opzionale]`](#22-bola-prevention-p1-native--opzionale)
  - [2.3 Operazioni Distruttive `[P1]` `[NATIVE + opzionale]`](#23-operazioni-distruttive-p1-native--opzionale)
  - [2.4 Consistenza Policy `[P1]` `[NATIVE]`](#24-consistenza-policy-p1-native)
  - [2.5 Excessive Data Exposure `[P2]` `[NATIVE]`](#25-excessive-data-exposure-p2-native)
- [DOMINIO 3 — Integrità dei Dati](#dominio-3--integrità-dei-dati)
  - [3.1 Input Validation `[P2]` `[HYBRID]`](#31-input-validation-p2-hybrid)
  - [3.3 HMAC Config Audit `[P3]` `[NATIVE]`](#33-hmac-config-audit-p3-native)
- [DOMINIO 4 — Disponibilità e Resilienza](#dominio-4--disponibilità-e-resilienza)
  - [4.1 Rate Limiting `[P0]` `[HYBRID]`](#41-rate-limiting-p0-hybrid)
  - [4.2 Timeout Config Audit `[P1]` `[NATIVE]`](#42-timeout-config-audit-p1-native)
  - [4.3 Circuit Breaker `[P1]` `[NATIVE]`](#43-circuit-breaker-p1-native)
- [DOMINIO 5 — Visibilità e Auditing](#dominio-5--visibilità-e-auditing)
  - [5.1 Audit Logging `[P1]` `[NATIVE]`](#51-audit-logging-p1-native)
  - [5.2 Alert Real-Time `[P2]` `[NATIVE]`](#52-alert-real-time-p2-native)
- [DOMINIO 6 — Configurazione e Hardening](#dominio-6--configurazione-e-hardening)
  - [6.1 Error Handling e Information Disclosure `[P2]` `[NATIVE]`](#61-error-handling-e-information-disclosure-p2-native)
  - [6.2 Security Headers `[P3]` `[NATIVE]`](#62-security-headers-p3-native)
  - [6.3 Gateway Layer-7 Hardening `[P1]` `[HYBRID]`](#63-gateway-layer-7-hardening-p1-hybrid)
  - [6.4 Hardcoded Credentials `[P2]` `[NATIVE + opzionale]`](#64-hardcoded-credentials-p2-native--opzionale)
- [DOMINIO 7 — Business Logic e Flussi Sensibili](#dominio-7--business-logic-e-flussi-sensibili)
  - [7.1 Anti-Automation `[P2]` `[NATIVE]`](#71-anti-automation-p2-native)
  - [7.2 SSRF Prevention `[P0]` `[HYBRID]`](#72-ssrf-prevention-p0-hybrid)
  - [7.3 Race Condition `[P2]` `[HYBRID]`](#73-race-condition-p2-hybrid)
  - [7.4 Consumo Sicuro Servizi Esterni `[P2]` `[HYBRID]`](#74-consumo-sicuro-servizi-esterni-p2-hybrid)
- [Riepilogo Connector Condivisi](#riepilogo-connector-condivisi)
- [Riepilogo Classificazione](#riepilogo-classificazione)

## Documento Operativo Consolidato

**Versione:** 3.0 — Maggio 2026
**Sostituisce:** v2.0

**Criteri di inclusione applicati (v1.0):**
- Esclusi tutti i tool `DEPRECATED` (ultimo commit 2+ anni fa)
- Esclusi tutti i tool `DA VERIFICARE` (nessun repository verificabile)
- Esclusi tool per protocolli fuori scope v1.0 (GraphQL, gRPC, WebSocket, HTTP/3)
- Esclusi tool IaC/cloud-specific salvo deck (già rimosso in v2.0)
- Escluse appendici enciclopediche

**Criteri aggiuntivi applicati in v2.0 — Tripartizione A/B/C:**
La classificazione completa è in `TOOLS_catalog.md`. Questo documento riporta
solo le Categorie A (connector obbligatori) e B (connector facoltativi con fallback nativo).
I tool Categoria C non compaiono nelle tabelle operative. Le quattro ragioni di scarto sono:
- **C.1 Ridondanza / Deprecazione:** sostituito da un tool A o B già presente, oppure abbandonato
- **C.2 Platform-specific:** rompe l'agnosticismo dell'architettura (4-Implementazione.md §3.1)
- **C.3 Scope diverso:** contract testing, SAST, IaC — dominio adiacente non security assessment API
- **C.4 Valore solo documentale:** Python nativo produce risultato equivalente senza dipendenze

**Changelog v3.0 rispetto a v2.0:**
- `kiterunner` rimosso da Cat A (abbandonato) → `ffuf` promosso da Cat B a Cat A per il test 0.1
- `CRLFuzz` rimosso da Cat A (inattivo dal 2021) → copertura CRLF delegata a template Nuclei `crlf-injection`
- `smuggler` rimosso da Cat A (nessuna release ufficiale) → connector Python raw sockets per CL.TE/TE.CL
- `race-the-web` rimosso da Cat A (abbandonato) → `vegeta` copre sia 4.1 che 7.3
- `jwtXploiter` rimosso da Cat B (5 anni senza manutenzione) → `jwt_tool` copre già le stesse varianti
- `Gopherus` rimosso da Cat B (4 anni senza commit, nessuna release) → Nuclei templates `ssrf-via-gopher-*`
- `http2smugl` aggiunto come Cat B per test 6.3 (estensione H2 opzionale)

---

## DOMINIO 0 — API Discovery & Inventory Management

### 0.1 Shadow API Discovery `[P0]` `[HYBRID]`

| Tool | Cat. | Ruolo | Motivazione |
|---|---|---|---|
| **ffuf** | A | Primario bruteforce | Wordlist API 30k+ path da SecLists (`API-endpoints.txt`, `common-api-endpoints-mazen160.txt`). Output JSON nativo (`-of json`). Supporta negoziazione metodi HTTP, recursion, filtri su status code e dimensione risposta. Attivamente mantenuto. **Promosso da Cat B** in sostituzione di kiterunner (abbandonato). |
| **katana** | A | Layer JS/SPA | Crawler headless con parsing AST di bundle JavaScript. Indispensabile per SPA dove gli endpoint sono definiti nel codice client-side. |
| **Nuclei** | A | Post-discovery vuln scan | Dopo aver trovato shadow endpoints, scala il test da "endpoint non documentato esiste" a "endpoint sfruttabile". Connector condiviso con 3.1 e 7.2. |
| **gau** | B | Layer storico passivo | Aggrega endpoint da Wayback Machine, CommonCrawl, OTX, URLScan. Trova versioni API obsolete senza inviare traffico al target. Angolazione completamente passiva. |
| **cherrybomb** | B | Analisi statica spec | Analizza la spec OpenAPI per rilevare endpoint non protetti e parameter tampering vectors. Angolazione SAST complementare al DAST. |

**Scartati (Categoria C):** kiterunner (C.1 — abbandonato, nessun commit recente; ffuf promosso a Cat A copre la stessa funzione con wordlist SecLists), feroxbuster (C.1 — inferiore a ffuf per REST puro), gobuster (C.1 — inferiore a ffuf e kiterunner), OWASP Noir (C.3 — SAST su codice sorgente, richiede accesso al source), APIClarity / akto / metlo / mitmproxy2swagger (C.3 — scope v2.0, richiedono target senza spec OpenAPI), Arjun / x8 / ParamSpider (C.3 — parameter discovery senza spec, scope v2.0), getJS+LinkFinder (C.1 — katana copre lo stesso scenario in modo più moderno).

---

### 0.2 Deny-by-Default `[P0]` `[NATIVE + opzionale]`

| Tool | Cat. | Ruolo | Motivazione |
|---|---|---|---|
| **cherrybomb** | B | Complementare statico | Connector già presente per 0.1. Rileva staticamente dalla spec i path che potrebbero non avere policy deny-by-default configurata. Costo zero in termini di nuove dipendenze. |

**Scartati (Categoria C):** feroxbuster e gobuster (C.1 — il test è NATIVE, Python costruisce path arbitrari; non serve fuzzer esterno), dredd e prism (C.3 — contract testing, scope diverso), Spectral e vacuum (C.3 — linter statici, angolazione coperta da cherrybomb), OWASP Noir (C.3).

---

### 0.3 Deprecated API Enforcement `[P0]` `[NATIVE + opzionale]`

| Tool | Cat. | Ruolo | Motivazione |
|---|---|---|---|
| **oasdiff** | B | Complementare spec diff | Confronta versioni di OpenAPI spec, rileva deprecation e sunset header compliance. Gestisce edge case del diff (nested `$ref`, `allOf`/`anyOf`) che Python nativo produce false negative su spec complesse. |

**Scartati (Categoria C):** apidiff (C.1 — alternativa meno matura a oasdiff, stessa funzione), dredd (C.3 — contract testing), Spectral e vacuum (C.3 — linter statici senza diff tra versioni), OWASP Noir (C.3).

---

## DOMINIO 1 — Identità e Autenticazione

### 1.1 Solo Richieste Autenticate `[P0]` `[NATIVE]`

Nessun tool esterno. La logica è semplice — invia richiesta senza token, verifica 401 — e Python la copre completamente. Hurl aggiunge solo leggibilità documentale senza valore tecnico (C.4).

---

### 1.2 Credenziali Crittograficamente Valide `[P0]` `[HYBRID]`

| Tool | Cat. | Ruolo | Motivazione |
|---|---|---|---|
| **jwt_tool** | A | Primario | 20+ attacchi JWT automatizzati: `alg:none` (CVE-2015-9235), key confusion RS256→HS256, `kid` injection (path traversal + SQL injection), Psychic Signature ECDSA (CVE-2022-21449), payload tampering. Mantenere questo catalogo aggiornato richiederebbe manutenzione continua di crittografia applicativa. Copre il perimetro di ex-jwtXploiter. |

**Scartati (Categoria C):** jwtXploiter (C.1 — 5 anni senza manutenzione; jwt_tool copre già le stesse varianti di `kid` injection), jose-cli (C.4 — Python può parsare JWT; il guadagno di velocità Go non giustifica una dipendenza aggiuntiva per questo scope), jwt-cracker Node.js (C.1 — sostituito da jwt_tool), jwt-crack Rust (C.4 — brute-force HMAC weak secret, scenario troppo specifico fuori dall'oracle principale).

---

### 1.3 Credenziali Non Scadute `[P0]` `[HYBRID]`

| Tool | Cat. | Ruolo | Motivazione |
|---|---|---|---|
| **jwt_tool** | A | Primario | Connector già presente per 1.2. Permette di costruire JWT con claim `exp` arbitrari tramite flag dedicate. Zero costo aggiuntivo di dipendenze — stesso processo subprocess già orchestrato per 1.2. |

**Nota:** `jwt_forge.py` copre gli stessi scenari base (`forge_expired()`), ma condividere il connector con 1.2 è architetturalmente corretto: un singolo processo jwt_tool gestisce entrambi i test senza overhead. Il confine è: jwt_forge.py per attacchi context-aware che richiedono il TargetContext (key confusion, JWKS); jwt_tool per manipolazioni standardizzate di claim incluso `exp`.

**Scartati (Categoria C):** jose-cli (C.4 — parsing JWT è triviale in Python; jwt_tool shared da 1.2 copre lo stesso), jwt-crack Rust (C.4 — brute-force HMAC, scenario fuori scope per il test di expiry).

---

### 1.4 Credenziali Non Revocate `[P1]` `[NATIVE]`

Nessun tool esterno. La sequenza login → usa token → logout → replay token → verifica 401 è pura logica Python stateful sul `TestContext`.

**Scartati (Categoria C):** Hurl (C.4 — DSL che aggiunge solo leggibilità documentale, zero valore tecnico rispetto a Python), mitmproxy (C.3 — scenario eccessivamente complesso per il caso baseline), keycloak-admin-client / auth0-cli / aws-cognito-idp (C.2 — IDP-specific, il tool è agnostico per design).

---

### 1.5 Credenziali su Canali Insicuri `[P2]` `[HYBRID]`

| Tool | Cat. | Ruolo | Motivazione |
|---|---|---|---|
| **testssl.sh** | A | Primario CLI | Standard de facto per TLS analysis. Copre versioni protocollo, cipher suite, forward secrecy, certificate transparency, 20+ vulnerabilità CVE-based (BEAST, POODLE, ROBOT, Heartbleed). Replicare in Python richiederebbe centinaia di handshake personalizzati a livello socket raw. Output JSON strutturato (`--jsonfile`). |
| **sslyze** | A | Primario libreria | Implementato come connector parallelo a testssl.sh in Milestone 1. Importabile come libreria Python (`BaseLibraryConnector`) — zero binary dependencies, utilizzabile in ambienti dove testssl.sh non è installabile. Copre cipher suite, forward secrecy, certificate validation, vulnerabilità CVE-based (Heartbleed, ROBOT, CCS injection). Output strutturato via `ScanCommandsResultsObserver` di sslyze. Genera evidenza indipendente da testssl.sh tramite `ext.1.5.sslyze` (test classe parallela a `ext.1.5.testssl`). |

**Scartati (Categoria C):** tlsx (C.4 — più veloce per multi-target ma meno profondo per singolo target; il nostro caso è sempre singolo target), sslscan2 (C.1 — alternativa a sslyze senza vantaggi su sslyze), tls-scan (C.4 — ottimizzato per bulk scan, non per analisi profonda), h2spec (C.3 — HTTP/2 conformance testing, scope diverso), quiche+curl (C.3 — HTTP/3, fuori scope v1.0).

---

### 1.6 Session Management `[P3]` `[NATIVE]`

Nessun tool esterno essenziale. Il test è P3 e l'audit di configurazione (cookie attributes, TTL Redis) è verificabile con Python + httpx.

**Scartati (Categoria C):** mitmproxy (C.3 — proxy richiede interposizione nella connessione; per session fixation l'unico test empirico è Python + httpx), Hurl (C.4 — DSL documentale).

---

## DOMINIO 2 — Autorizzazione e Controllo Accessi

### 2.1 RBAC Endpoint Privilege `[P1]` `[NATIVE]`

Nessun tool esterno. La logica di test (token per ruoli distinti, iterazione endpoint) è pura orchestrazione Python sul `TestContext`.

**Scartati (Categoria C):** opa+conftest (C.2 — richiede che il target usi OPA come policy engine, assunzione non agnostica), Spectral (C.3 — solo analisi statica della spec, già coperta da cherrybomb).

---

### 2.2 BOLA Prevention `[P1]` `[NATIVE + opzionale]`

| Tool | Cat. | Ruolo | Motivazione |
|---|---|---|---|
| **OFFAT** | B | Primario | Parser OpenAPI → generazione automatica test IDOR sostituendo ID utente su tutti gli endpoint con path parameters. Copre sistematicamente l'intera superficie senza configurazione manuale. |
| **cherrybomb** | B | Complementare statico | Connector già presente. Rileva pattern BOLA nella spec (endpoint con ID path param senza ownership check dichiarato) prima del test dinamico. |

**Scartati (Categoria C):** akto (C.3 — piattaforma Java troppo pesante), susanoo (C.1 — alternativa a OFFAT meno matura), AuthMatrix (C.3 — richiede configurazione manuale della matrice, non agnostica), astra (C.1 — abbandonato, ultimo commit 2020).

---

### 2.3 Operazioni Distruttive `[P1]` `[NATIVE + opzionale]`

| Tool | Cat. | Ruolo | Motivazione |
|---|---|---|---|
| **OFFAT** | B | Complementare | Connector già presente per 2.2. Genera automaticamente test su operazioni DELETE/PUT dalla spec OpenAPI. |

**Scartati (Categoria C):** Hurl (C.4 — DSL documentale senza valore tecnico aggiuntivo).

---

### 2.4 Consistenza Policy `[P1]` `[NATIVE]`

Nessun tool esterno essenziale. Il confronto sistematico tra versioni API è logica Python sull'`AttackSurface`.

**Scartati (Categoria C):** dredd e prism (C.3 — contract testing, scope più ampio e diverso), Spectral e vacuum (C.3 — linter statici senza angolazione dinamica).

---

### 2.5 Excessive Data Exposure `[P2]` `[NATIVE]`

Nessun tool esterno essenziale. L'ispezione field-by-field delle response JSON è logica Python tramite `response_inspector.py`.

**Scartati (Categoria C):** APIClarity (C.3 — richiede traffic capture, scope v2.0), akto (C.3 — piattaforma troppo pesante), graphql-cop (C.3 — GraphQL-only, fuori scope).

---

## DOMINIO 3 — Integrità dei Dati

### 3.1 Input Validation `[P2]` `[HYBRID]`

I tool qui sono complementari per tipo di injection — non si sovrappongono, coprono angolazioni genuinamente distinte.

| Tool | Cat. | Tipo Injection | Motivazione |
|---|---|---|---|
| **Schemathesis** | A | Schema-aware fuzzing | Unico tool integrabile come libreria Python nativa (`from schemathesis import from_uri`). Property-based testing con Hypothesis engine: esplora lo spazio degli input in modo esaustivo rispetto allo schema OpenAPI. Paradigma di testing diverso da una lista di payload. |
| **Nuclei** | A | Template framework-specific | Template `http/vulnerabilities/` per injection specifiche per framework. Connector condiviso con 0.1 e 7.2. Copre anche CRLF injection tramite template `crlf-injection` (vedi nota). |
| **sqlmap** | B | SQL injection | Standard de facto, insostituibile per coverage completa. Payload grammar context-aware che supera qualsiasi lista manuale. |
| **NoSQLMap** | B | NoSQL injection | Copre MongoDB/CouchDB injection. Angolazione completamente separata da sqlmap — critico per API moderne. |
| **Dalfox** | B | XSS | Context-aware con DOM analysis. Motore di payload generation basato su grammar context-aware, non lista statica. |
| **commix** | B | Command injection | Unico tool maturo per OS command injection automatizzato. Rileva blind injection via time-based, error-based, output-based. |
| **SSTImap** | B | Template injection SSTI | Fork attivo di tplmap. Copre Jinja2, Twig, Smarty, Velocity, FreeMarker, Pebble. Rileva engine automaticamente. |

**Nota copertura CRLF:** CRLFuzz rimosso da Cat A (inattivo dal 2021). La ragione tecnica della sua presenza era che operava su raw socket per bypassare la normalizzazione RFC 7230 applicata da `httpx`. I template Nuclei `crlf-injection` nel bundle `nuclei-templates 10.4.3` usano lo stesso approccio raw TCP. Pre-requisito: verificare la presenza del tag `crlf-injection` nel bundle pinned prima di dichiarare la copertura CRLF soddisfatta.

**Scartati (Categoria C):** CRLFuzz (C.1 — abbandonato, inattivo dal 2021; copertura delegata a template Nuclei `crlf-injection`), ghauri (C.1 — alternativa a sqlmap, sqlmap è sufficiente), nosqli (C.1 — alternativa a NoSQLMap, meno matura), XSStrike (C.1 — alternativa a Dalfox, Dalfox è superiore), tplmap (C.1 — SSTImap è il fork attivo), crlfmap e headi (C.1 — alternative a CRLFuzz, ora anche CRLFuzz è rimosso; Nuclei templates coprono questo vettore), dotdotpwn (C.1 — path traversal coperto da ffuf con wordlist), CATS (C.3 — alternativa Java a Schemathesis, preferiamo Python library), APIFuzzer (C.1 — coperto da Schemathesis).

---

### 3.3 HMAC Config Audit `[P3]` `[NATIVE]`

Nessun tool esterno. Questo controllo è un Configuration Audit (White Box): verifica documentazione tecnica e codice sorgente del middleware. Python può interrogare la configurazione e verificare i parametri.

**Scartati (Categoria C):** step-cli (C.4 — `step crypto key inspect` è un singolo comando CLI ma `openssl` o sslyze già presente coprono lo stesso; non giustifica dipendenza aggiuntiva per un test P3), jwt_tool (C.4 — uso marginale su HMAC, il connector è per 1.2 esclusivamente), Vault API (C.2 — HashiCorp-specific), mitmproxy (C.3 — approccio a proxy incompatibile con black-box), Checkov (C.2 — IaC scanner).

---

## DOMINIO 4 — Disponibilità e Resilienza

### 4.1 Rate Limiting `[P0]` `[HYBRID]`

| Tool | Cat. | Ruolo | Motivazione |
|---|---|---|---|
| **vegeta** | A | Primario | Rate control preciso con goroutine Go — elimina il jitter del GIL Python che renderebbe inaffidabile la soglia osservata. Istogrammi latenza (p50/p90/p99). Per verificare che il rate limit scatti esattamente a N req/s, il load generator deve essere preciso al millisecondo. Connector condiviso con 7.3. |

**Scartati (Categoria C):** hey (C.1 — fallback esplicito di vegeta; stessa funzione, meno feature), slowloris (C.4 — testa slow HTTP attacks su connessioni lente, angolazione orthogonale al rate limiting su frequenza; il test 4.2 sui timeout indirizza il caso slow-connection), bombardier (C.4 — HTTP/2 specifico, scenario marginale per il test principale), graphql-cop (C.3 — GraphQL-only).

---

### 4.2 Timeout Config Audit `[P1]` `[NATIVE]`

Nessun tool esterno. Il test è un Configuration Audit (White Box): legge parametri da file di configurazione del Gateway e del connection pool. Python + Admin API del Gateway sono sufficienti.

**Scartati (Categoria C):** httpstat (C.4 — timing breakdown visivo, Python può misurare TTFB; non aggiunge evidenze strutturate al report), deck (C.2 — Kong-specific, rompe l'agnosticismo; la logica di lettura configurazione è nel `BaseGatewayAdapter`), vegeta (C.4 — utile come test comportamentale opzionale in staging ma il test è principalmente config audit), prowler (C.2 — AWS-specific), kubescape (C.2 — Kubernetes-specific).

---

### 4.3 Circuit Breaker `[P1]` `[NATIVE]`

Nessun tool esterno. Il test è un Configuration Audit (White Box): verifica la presenza di direttive circuit breaker via Admin API o file di configurazione. Il `BaseGatewayAdapter` astrae questo layer.

**Scartati (Categoria C):** deck (C.2 — Kong-specific), istioctl (C.2 — Istio-specific), kuma-cp (C.2 — Kuma-specific), linkerd viz (C.2 — Linkerd-specific), aws appmesh (C.2 — AWS-specific), envoy-tools (C.2 — Envoy-specific), kubescape (C.2 — Kubernetes-specific), vegeta (C.4 — test comportamentale opzionale in staging, non parte dell'oracle principale).

---

## DOMINIO 5 — Visibilità e Auditing

### 5.1 Audit Logging `[P1]` `[NATIVE]`

Nessun tool esterno. Il test interroga il log aggregator via API (Elasticsearch, Splunk, CloudWatch, Loki) tramite Python httpx. La logica di query è specifica per lo stack del target e viene configurata in `config.yaml`.

**Scartati (Categoria C):** vector+jq (C.4 — pipeline di log processing stack-specific, non un tool di security assessment), loki-cli (C.4 — Grafana/Loki-specific; Python via httpx interroga qualsiasi log aggregator tramite la loro REST API), Prowler (C.2 — AWS-specific), metlo (C.3 — traffic capture, scope diverso).

---

### 5.2 Alert Real-Time `[P2]` `[NATIVE]`

Nessun tool esterno. Il test genera la condizione anomala con Python, poi interroga il sistema di alerting via API per verificare la delivery e la latenza.

**Scartati (Categoria C):** alertmanager mock (C.4 — richiede setup infrastruttura Prometheus locale, dipendenza pesante per un test P2), webhook.site API (C.4 — servizio esterno; introduce dipendenza da connettività esterna e da un servizio terzo non controllato), Prowler (C.2 — AWS-specific).

---

## DOMINIO 6 — Configurazione e Hardening

### 6.1 Error Handling e Information Disclosure `[P2]` `[NATIVE]`

Nessun tool esterno. Inviare payload anomali e analizzare le response per stack trace, version disclosure, e debug data è logica Python su `httpx`. Il test itera su tutti gli endpoint dell'`AttackSurface`.

**Scartati (Categoria C):** httpx ProjectDiscovery (C.4 — diverso dalla libreria Python httpx che già usiamo; la velocità Go è irrilevante per il nostro scope di singolo target; "tech-detect" aggiunge fingerprinting ma non evidenze strutturate di vulnerabilità), whatweb (C.4 — fingerprinting tecnologico Ruby; utile per contestualizzare finding in manuale, non produce evidenze di vulnerabilità dirette automatizzabili), hakrawler (C.4 — crawler generico usato come pipeline grep, non tool di security analysis), Spectral (C.3 — linter statico).

---

### 6.2 Security Headers `[P3]` `[NATIVE]`

Nessun tool esterno. Python può verificare la presenza e il valore di 6-8 header HTTP con una lista di pattern attesi — non giustifica dipendenze aggiuntive per un test P3.

**Scartati (Categoria C):** shcheck (C.4 — Python può fare la stessa cosa con una lista di 8 valori attesi; il vantaggio di coprire header meno comuni come COOP/COEP non giustifica una dipendenza per un test P3), csp-evaluator (C.4 — API REST Google; Python con httpx fa la stessa chiamata in 3 righe, non è un tool da integrare come connector), securityheaders.com API (C.4 — servizio esterno di scoring, non aggiunge evidenze automatizzate), treblle (C.4 — poco mantenuto come tool standalone), Checkov (C.2 — IaC scanner).

---

### 6.3 Gateway Layer-7 Hardening `[P1]` `[HYBRID]`

> **Nota architetturale:** smuggler rimosso da Cat A per assenza di release ufficiale. I pattern **CL.TE** e **TE.CL** (RFC 9110 §9.3.3) sono implementati direttamente nel connector `ext_test_6_3_smuggling.py` tramite `socket` della stdlib Python. Python `httpx` rifiuta per design gli header ambigui `Content-Length` + `Transfer-Encoding: chunked` simultaneamente — il raw socket bypassa questo enforcement. Il vantaggio accademico è che il codice del connector rende leggibile il meccanismo dell'attacco nella tesi senza dipendere da un binary black-box.

| Tool | Cat. | Ruolo | Motivazione |
|---|---|---|---|
| **http2smugl** | B | Estensione H2 opzionale | Copre HTTP/2 downgrade smuggling — angolazione distinta dai pattern CL.TE/TE.CL. Promovibile a Cat A se il target espone HTTP/2. Attivamente mantenuto in Go. |

**Scartati (Categoria C):** smuggler (C.1 — nessuna release ufficiale taggata; i pattern CL.TE/TE.CL sono implementati direttamente con socket Python stdlib), gotestwaf (C.3 — overkill per il solo test di smuggling), h2csmuggler (C.4 — HTTP/2 cleartext upgrade smuggling, scenario molto specifico che richiede target con HTTP/2 upgrade non cifrato), deck (C.2 — Kong-specific, il `BaseGatewayAdapter` astrae questa logica), tutto il gruppo IaC/K8s/cloud (prowler, checkov, tfsec, kics, cfn-lint, steampipe, inspec-aws, kubescape, kube-linter, istioctl, kubeaudit — tutti C.2, tool infrastrutturali non di assessment API).

---

### 6.4 Hardcoded Credentials `[P2]` `[NATIVE + opzionale]`

| Tool | Cat. | Ruolo | Motivazione |
|---|---|---|---|
| **trufflehog** | B | Primario | 800+ detector per pattern API key mantenuti dalla community (AWS AKIA, Stripe sk_live_, GitHub tokens, ecc.). Mantenere questi regex aggiornati in Python richiederebbe un team dedicato. Scansiona filesystem, response body, spec files, JS bundles. |
| **gitleaks** | B | Complementare git | Scansione commit history del repository dove risiede la spec OpenAPI o i file di configurazione. Angolazione distinta da trufflehog: runtime vs versionamento. |
| **detect-secrets** | B | Complementare CI | Importabile come libreria Python. Plugin architecture per custom detectors. Utile per integrare il tool nella CI del progetto stesso, oltre che per testare il target. |

**Scartati (Categoria C):** secretlint (C.1 — Node.js; detect-secrets Python library copre lo stesso), kube-linter (C.2 — Kubernetes-specific), prowler (C.2 — AWS-specific).

---

## DOMINIO 7 — Business Logic e Flussi Sensibili

### 7.1 Anti-Automation `[P2]` `[NATIVE]`

Nessun tool esterno. Il test verifica che endpoint sensibili richiedano CAPTCHA e applichino rate limiting applicativo aggressivo. Python + httpx è sufficiente per osservare il comportamento dei controlli.

**Scartati (Categoria C):** playwright (C.4 — browser automation per CAPTCHA testing è un test P2 molto specifico; il connector aggiungerebbe una dipendenza browser completo per un singolo test secondario; la verifica che il CAPTCHA *esista* è osservabile nella response HTTP), puppeteer (C.1 — Node.js, playwright copre lo stesso con binding Python), puppeteer-extra-stealth (C.4 — device fingerprinting avanzato, scenario specifico non nel core del test), curl-impersonate (C.4 — TLS fingerprint impersonation, scenario avanzato non nel core del test), akto (C.3 — piattaforma pesante).

---

### 7.2 SSRF Prevention `[P0]` `[HYBRID]`

| Tool | Cat. | Ruolo | Motivazione |
|---|---|---|---|
| **Nuclei** | A | Complementare template | Connector già presente. Template `http/vulnerabilities/generic/ssrf*` con bypass emergenti aggiornati dalla community. Angolazione distinta da `ssrf_payloads.py` nativo: Python copre i payload standard, Nuclei copre bypass specifici per tecnologia. Copre anche payload Gopher per SSRF verso servizi interni tramite template `ssrf-via-gopher-*` (vedi nota). |
| **interactsh** | A | OOB/Blind SSRF | Fondamentale — senza OOB, le SSRF blind non sono rilevabili. Il server registra DNS/HTTP callbacks che confermano exploitation. Angolazione tecnicamente non sostituibile con Python puro. |

**Nota tecnica:** SSRFmap è implementato come layer nativo (`ssrf_payloads.py`) — non è un connector esterno ma logica Python integrata nel test.

**Nota copertura Gopher:** Gopherus rimosso da Cat B (4 anni senza commit, nessuna release). I template Nuclei nella categoria `ssrf` e `network` coprono SSRF verso Redis, MySQL e SMTP tramite payload Gopher. Pre-requisito: verificare la presenza di template `ssrf-via-gopher-*` nel bundle `nuclei-templates 10.4.3` prima di dichiarare la copertura Gopher soddisfatta.

**Scartati (Categoria C):** Gopherus (C.1 — abbandonato, 4 anni senza commit, nessuna release; copertura Gopher delegata a template Nuclei), nimbostratus (C.2 — AWS metadata exploitation, platform-specific), singularity (C.4 — DNS rebinding framework, scenario molto avanzato coperto dalla logica di test nativa con payload standard), SSRFfire (già DEPRECATED, sostituito da SSRFmap).

---

### 7.3 Race Condition `[P2]` `[HYBRID]`

| Tool | Cat. | Ruolo | Motivazione |
|---|---|---|---|
| **vegeta** | A | Primario | Connector già presente per 4.1. Flag `-rate=0 -max-workers=N` lancia N goroutine Go in parallelo con sincronizzazione last-byte — equivalente funzionale a race-the-web (abbandonato). Python asyncio introduce jitter di scheduling che sfasa la sincronizzazione sub-millisecondo necessaria per TOCTOU. Output JSON con `status_codes` e `latencies` per rilevare response anomale da race condition. |

**Scartati (Categoria C):** race-the-web (C.1 — abbandonato, poche stelle, nessuna release recente; vegeta copre il caso comune con last-byte sync via `-rate=0 -max-workers=N`), racepwn (C.4 — dipendenza `librace` C richiede compilazione non triviale in ambienti Docker; il vettore HTTP/2 concurrent streams è raro su target gateway-standard come Kong), turbo-intruder (C.4 — Java/Jython, setup complesso), h2csmuggler (C.4 — HTTP/2 smuggling, non race condition), http2smugl (C.1 — smuggling HTTP/2, non race condition), h2spec (C.3 — conformance testing, non race), ffuf -rate 0 (C.1 — baseline grossolana; vegeta è il tier entry-level corretto).

---

### 7.4 Consumo Sicuro Servizi Esterni `[P2]` `[HYBRID]`

| Tool | Cat. | Ruolo | Motivazione |
|---|---|---|---|
| **interactsh** | A | Complementare OOB | Connector già presente per 7.2. Usato per verificare webhook callback URL malevoli — il sistema chiama l'URL iniettato e interactsh registra il callback, confermando la vulnerabilità. |

**Scartati (Categoria C):** httpx ProjectDiscovery (C.4 — redirect chain analysis è 3 righe con Python httpx nativo), confused (C.3 — dependency confusion, scope supply chain non API security), nuclei usage qui (C.4 — troppo indiretto come layer aggiuntivo su un test già P2).

---

## Riepilogo Connector Condivisi

Tool che compaiono in più test — l'`ExternalTestRegistry` li istanzia una sola volta.

| Connector | Cat. | Test che lo usano |
|---|---|---|
| **Nuclei** | A | 0.1, 3.1, 7.2 |
| **cherrybomb** | B | 0.1, 0.2, 2.2 |
| **OFFAT** | B | 2.2, 2.3 |
| **jwt_tool** | A | 1.2, 1.3 |
| **vegeta** | A | 4.1, 7.3 |
| **interactsh** | A | 7.2, 7.4 |

---

## Riepilogo Classificazione

| Classificazione | Test |
|---|---|
| `[NATIVE]` | 0.2, 0.3, 1.1, 1.4, 1.6, 2.1, 2.2, 2.3, 2.4, 2.5, 3.3, 4.2, 4.3, 5.1, 5.2, 6.1, 6.2, 6.4, 7.1 |
| `[HYBRID]` | 0.1, 1.2, 1.3, 1.5, 3.1, 4.1, 6.3, 7.2, 7.3, 7.4 |

**Nota:** la categoria TOOL non si applica a nessun test del catalogo. Per design architetturale, Python contribuisce sempre logica di sicurezza indipendente in ogni test che usa connector esterni. I test `[NATIVE]` con tool Cat B opzionali sono elencati nella colonna NATIVE — il Cat B non cambia la classificazione del test, ne estende la copertura.

**Connector definitivi (Categoria A — obbligatori):**
ffuf (ex-kiterunner), katana, Nuclei, jwt_tool, testssl.sh, sslyze, Schemathesis, vegeta, interactsh

**Connector definitivi (Categoria B — facoltativi con fallback nativo):**
gau, cherrybomb, OFFAT, sqlmap, NoSQLMap, Dalfox, commix, SSTImap, trufflehog, gitleaks, detect-secrets, oasdiff, http2smugl

**Totale:** 9 connector Categoria A + 13 connector Categoria B = 22 connector operativi.
Categoria C: ~77 tool — documentati in `TOOLS_catalog.md`, non entrano nel codice.
*(Rispetto a v2.0: -4 Cat A rimossi per abbandono/nessuna release, +1 Cat B promosso ad A, -3 Cat B rimossi per abbandono, +1 Cat B aggiunto. Netto: -5 connector operativi.)*
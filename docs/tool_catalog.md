# APIGuard — Catalogo Completo dei Tool di Security Assessment
## Raccolta Integrale dalle Ricerche (use.ai × 4 sessioni + Gemini Deep Search + Analisi Claude)

**Versione:** 1.3 — Maggio 2026
**Scopo:** Documento di riferimento unico per la ricerca. Ogni tool menzionato in qualsiasi fonte verificabile è incluso.

**Changelog v1.3 rispetto a v1.2:**
- Test 0.1: kiterunner spostato in Cat C (abbandonato); ffuf promosso da Cat B a Cat A
- Test 1.2: jwtXploiter spostato in Cat C (5 anni senza manutenzione)
- Test 3.1: CRLFuzz spostato in Cat C (inattivo dal 2021); copertura CRLF delegata a template Nuclei
- Test 6.3: smuggler spostato in Cat C (nessuna release); Cat A ora usa Python raw sockets stdlib; http2smugl aggiunto come Cat B
- Test 7.2: Gopherus spostato in Cat C (4 anni senza commit); copertura Gopher delegata a template Nuclei
- Test 7.3: race-the-web spostato in Cat C (abbandonato); vegeta promosso a Cat A condiviso con 4.1; racepwn confermato C.4
- Appendice A aggiornata: ffuf, vegeta
- Appendice C aggiornata: aggiunti kiterunner, CRLFuzz, smuggler, race-the-web, jwtXploiter, Gopherus
- Appendice E aggiornata a v1.4: matrice di confidenza allineata alle nuove decisioni

**Novità v1.2 — Tripartizione A/B/C:**
Ogni sezione di test è organizzata in tre sotto-sezioni nell'ordine di priorità operativa:
- **Categoria A** — Da implementare come connector obbligatorio (Python strutturalmente non può)
- **Categoria B** — Connector facoltativo con fallback nativo (Python può, il tool aggiunge copertura genuina)
- **Categoria C — Scartato** — Non entra nel codice; motivazione sintetizzata in nota

La classificazione completa con motivazioni estese è in `TODO-decisioni-tool.md`.

---

## Legenda Colonne

| Colonna | Significato |
|---|---|
| **Tool** | Nome dello strumento |
| **Repository / Sorgente** | GitHub o identificativo |
| **Linguaggio/Tipo** | Linguaggio di implementazione o tipo (CLI, Libreria, API, Script) |
| **Valore Architetturale** | Perché è utile vs Python nativo puro |
| **Output** | Formato di output rilevante per l'integrazione |
| **Fonte** | Da quale sessione/documento proviene la segnalazione |
| **Note** | Avvertenze, stato manutenzione, dipendenze |

---

## DOMINIO 0 — API Discovery & Inventory Management

---

### Test 0.1 — Tutti gli Endpoint Esposti Sono Documentati (Shadow API Discovery) `[P0]`

**Obiettivo del test:** verificare che non esistano endpoint attivi sul Gateway non presenti nella specifica OpenAPI ufficiale (Shadow API).

#### Categoria A — Da implementare come connector

| Tool | Repository | Linguaggio/Tipo | Valore Architetturale vs Python Nativo | Output | Fonte | Note |
|---|---|---|---|---|---|---|
| **ffuf** | `ffuf/ffuf` | Go — CLI binario | Fuzzer ultrarapido per path enumeration con wordlist API. Supporta wordlist SecLists (`API-endpoints.txt`, `common-api-endpoints-mazen160.txt`, 30k+ path). Output JSON nativo con `-of json`. Negoziazione metodi HTTP multipli, recursion, filtri avanzati su status code e dimensione risposta. Attivamente mantenuto. **Promosso da Cat B** in sostituzione di kiterunner (abbandonato). | JSON (`-of json -o result.json`) | use.ai-1, use.ai-2, Claude Analysis | Strumento primario per shadow API discovery. Connector condiviso con fallback 0.2. |
| **katana** | `projectdiscovery/katana` | Go — CLI binario | Crawler headless con estrazione JavaScript, scopre endpoint non documentati tramite parsing AST di bundle JS. Indispensabile per SPA moderne dove gli endpoint sono definiti nel routing client-side, non server-side. | JSON | use.ai-2, use.ai-3 v3 | Copre scenari JS-heavy che ffuf non gestisce |
| **Nuclei** | `projectdiscovery/nuclei` | Go — CLI binario | Scanner template-based con libreria di template `http/api/` per vulnerabilità API specifiche. Dopo shadow discovery, scala il test da "endpoint non documentato esiste" a "endpoint sfruttabile". Template aggiornati dalla community. | JSON (`-json`), SARIF | use.ai-2, use.ai-3 v3, Claude Analysis | **Connector condiviso** con test 3.1 e 7.2 |

#### Categoria B — Connector facoltativo (fallback nativo disponibile)

| Tool | Repository | Linguaggio/Tipo | Valore Architetturale vs Python Nativo | Output | Fonte | Note |
|---|---|---|---|---|---|---|
| **gau** (GetAllURLs) | `lc/gau` | Go — CLI binario | Aggrega URL da Wayback Machine, CommonCrawl, OTX, URLScan. Pipeline: `gau domain \| grep api` produce endpoint storici mai rimossi. Trova versioni API obsolete ancora raggiungibili. Angolazione completamente diversa: passiva. | Text (pipe-friendly) | use.ai-1, use.ai-2, use.ai-3 v3 | Strumento di mining passivo; complementare ai fuzzer attivi |
| **cherrybomb** | GitHub open source | Rust — CLI binario | Analisi statica OpenAPI spec: rileva endpoint non protetti, parameter tampering vectors, BOLA patterns. Approccio SAST complementare al DAST dei tool sopra. | JSON | use.ai-3 v2 | Copre anche 0.2, 2.2; multi-test tool |

#### Categoria C — Scartato

| Tool | Motivo Scarto | Alternativa |
|---|---|---|
| **Kiterunner** | C.1 — DEPRECATED: abbandonato, nessun commit recente. ffuf promosso a Cat A copre path enumeration REST con wordlist SecLists. | ffuf (Cat A) |
| **feroxbuster** | C.1 — Redundanza: inferiore a ffuf per REST puro; utile per web server tradizionali non nel nostro scope | ffuf |
| **gobuster** | C.1 — Redundanza: più semplice di feroxbuster senza vantaggi distinti | ffuf |
| **OWASP Noir** | C.3 — Scope diverso: SAST su AST del codice sorgente, richiede accesso al source code; incompatibile con approccio black/grey box | — |
| **APIClarity** | C.3 — Scope v2.0: richiede target senza spec OpenAPI e traffic capture | — |
| **akto** | C.3 — Scope diverso: piattaforma Java pesante, non tool di assessment API | — |
| **metlo** | C.3 — Scope diverso: traffic-based discovery, richiede sidecar | — |
| **mitmproxy2swagger** | C.3 — Scope v2.0: reverse-engineering spec da traffico catturato | — |
| **Arjun** | C.3 — Scope v2.0: parameter discovery senza spec OpenAPI | — |
| **x8** | C.3 — Scope v2.0: alternativa Rust ad Arjun | — |
| **ParamSpider** | C.3 — Scope v2.0: mining parametri da Wayback, nessuna spec | — |
| **getJS + LinkFinder** | C.1 — Redundanza: katana copre lo stesso scenario in modo più moderno e integrato | katana |
| **waymore** | C.1 — Redundanza rispetto a gau senza vantaggi tecnici determinanti nel nostro scope | gau |
| **Astra** | C.1 — DEPRECATED: ultimo commit 2020 | OFFAT, cherrybomb |

---

### Test 0.2 — Il Gateway Rifiuta Richieste a Path Non Registrati (Deny-by-Default) `[P0]`

**Obiettivo del test:** verificare che il Gateway restituisca `404/403` per qualsiasi path non registrato esplicitamente.

#### Categoria A — Da implementare come connector

*(Nessun tool Categoria A — il test è NATIVE)*

#### Categoria B — Connector facoltativo (fallback nativo disponibile)

| Tool | Repository | Linguaggio/Tipo | Valore Architetturale vs Python Nativo | Output | Fonte | Note |
|---|---|---|---|---|---|---|
| **cherrybomb** | GitHub open source | Rust — CLI binario | Analisi statica OpenAPI: identifica endpoint non protetti e path senza policy deny-by-default configurata. Connector già presente per 0.1 — zero costo aggiuntivo. | JSON | use.ai-3 v2 | Approccio statico complementare ai test dinamici |

#### Categoria C — Scartato

| Tool | Motivo Scarto | Alternativa |
|---|---|---|
| **feroxbuster** | C.1 — Redundanza: il test è NATIVE; Python costruisce path arbitrari e varianti; non serve fuzzer esterno per la logica del test | cherrybomb (SAST) |
| **gobuster** | C.1 — Redundanza: idem | cherrybomb |
| **dredd** | C.3 — Scope diverso: contract testing, non security assessment | — |
| **prism** | C.3 — Scope diverso: mock server e validation proxy, strumento di sviluppo | — |
| **Spectral** | C.3 — Scope diverso: OpenAPI linter statico, cherrybomb copre l'angolazione security | cherrybomb |
| **vacuum** | C.3 — Scope diverso: alternativa Go a Spectral, stessa limitazione | cherrybomb |
| **OWASP Noir** | C.3 — Scope diverso: SAST su codice sorgente | — |
| **ffuf** | C.1 — Connector già presente per 0.1; la logica deny-by-default è più accurata con path costruiti dal test NATIVE | ffuf già in 0.1 |

---

### Test 0.3 — Le API Deprecate Sono Disabilitate o con Monitoraggio Rafforzato `[P0]`

**Obiettivo del test:** verificare che endpoint `deprecated: true` siano disabilitati (`410 Gone`) o abbiano rate limiting rafforzato e logging verboso.

#### Categoria A — Da implementare come connector

*(Nessun tool Categoria A — il test è NATIVE + opzionale)*

#### Categoria B — Connector facoltativo (fallback nativo disponibile)

| Tool | Repository | Linguaggio/Tipo | Valore Architetturale vs Python Nativo | Output | Fonte | Note |
|---|---|---|---|---|---|---|
| **oasdiff** | `tufin/oasdiff` | Go — CLI binario | Confronta due OpenAPI spec e identifica breaking changes, deprecation, sunset header compliance (RFC 9110). Gestisce edge case del diff (nested `$ref`, `allOf`/`anyOf`) che Python nativo produce false negative su spec complesse. | JSON, YAML | use.ai-2, use.ai-3 v3 | Strumento primario per diff tra versioni spec |

#### Categoria C — Scartato

| Tool | Motivo Scarto | Alternativa |
|---|---|---|
| **apidiff** | C.1 — Redundanza: alternativa meno matura a oasdiff, stessa funzione senza vantaggi | oasdiff |
| **dredd** | C.3 — Scope diverso: contract testing, non sunset enforcement | — |
| **Spectral** | C.3 — Scope diverso: linter statico senza diff tra versioni | oasdiff |
| **vacuum** | C.3 — Scope diverso: alternativa Go a Spectral, stessa limitazione | oasdiff |
| **OWASP Noir** | C.3 — Scope diverso: SAST su codice sorgente | — |

---

## DOMINIO 1 — Identità e Autenticazione

---

### Test 1.1 — Solo Richieste Autenticate Accedono a Risorse Protette `[P0]`

**Obiettivo del test:** verificare che ogni endpoint protetto rifiuti richieste senza credenziali valide con `401 Unauthorized`.

#### Categoria A / B — Da implementare come connector

*(Nessun tool — test NATIVE puro)*

#### Categoria C — Scartato

| Tool | Motivo Scarto | Alternativa |
|---|---|---|
| **Hurl** | C.4 — Valore solo documentale: DSL per leggibilità, zero valore tecnico aggiuntivo rispetto a Python; la logica è semplice e coperta completamente da httpx | Python nativo |

---

### Test 1.2 — Le Credenziali Sono Crittograficamente Valide (JWT Signature) `[P0]`

**Obiettivo del test:** verificare che il Gateway rifiuti JWT con `alg:none`, payload manomesso, algorithm confusion (RS256→HS256), signature stripping, `kid` mismatch.

#### Categoria A — Da implementare come connector

| Tool | Repository | Linguaggio/Tipo | Valore Architetturale vs Python Nativo | Output | Fonte | Note |
|---|---|---|---|---|---|---|
| **jwt_tool** (alias jwttool) | `ticarpi/jwt_tool` | Python — CLI / libreria | Implementa **20+ attacchi JWT automatizzati**: `alg:none` bypass (CVE-2015-9235), key confusion RS256→HS256, claim injection, payload tampering, `kid` header injection (path traversal, SQL injection nel kid), Psychic Signature ECDSA (CVE-2022-21449), iniezioni JWKS. Flag `-M at` per all-tests mode. Copre il perimetro di ex-jwtXploiter. | JSON (con `-op`), text | use.ai-1, use.ai-2, use.ai-3 v2, use.ai-3 v3, Gemini Deep Search | **Strumento primario per JWT security**. Nonostante sia Python, incapsula logica crittografica complessa aggiornata |

#### Categoria B — Connector facoltativo (fallback nativo disponibile)

*(Nessun tool Categoria B — jwtXploiter rimosso, vedi Cat C)*

#### Categoria C — Scartato

| Tool | Motivo Scarto | Alternativa |
|---|---|---|
| **jwtXploiter** | C.1 — DEPRECATED: 5 anni senza manutenzione. jwt_tool copre già le stesse varianti di `kid` header injection (path traversal + SQLi). Nessuna copertura differenziale giustificabile. | jwt_tool (Cat A) |
| **jose-cli** | C.4 — Il guadagno di velocità Go per parsing JWT non giustifica una dipendenza aggiuntiva nel nostro scope di singolo-target | jwt_tool |
| **jwt-cracker (Node.js)** | C.1 — Redundanza: jwt_tool copre weak secret detection | jwt_tool |
| **jwt-crack (Rust)** | C.4 — Brute-force HMAC weak secret, scenario troppo specifico; l'oracle principale del test non richiede questo | jwt_tool |

---

### Test 1.3 — Le Credenziali Non Sono Scadute (Expiry Check) `[P0]`

**Obiettivo del test:** verificare che il Gateway rifiuti JWT con claim `exp` nel passato.

#### Categoria A — Da implementare come connector

| Tool | Repository | Linguaggio/Tipo | Valore Architetturale vs Python Nativo | Output | Fonte | Note |
|---|---|---|---|---|---|---|
| **jwt_tool** | `ticarpi/jwt_tool` | Python — CLI / libreria | Connector già presente per 1.2. Permette di costruire JWT con claim `exp` arbitrari per testare il comportamento del server (scaduto, valido, negativo, leeway). Stesso tool, parametri diversi. | JSON, text | use.ai-2, use.ai-3 v3 | Condiviso con 1.2; zero costo aggiuntivo di dipendenze |

#### Categoria B / C

| Tool | Motivo Scarto | Alternativa |
|---|---|---|
| **jose-cli** | C.4 — Parsing exp su larga scala non necessario per singolo-target; jwt_tool già copre | jwt_tool |

---

### Test 1.4 — Le Credenziali Non Sono State Revocate (Token Revocation) `[P1]`

**Obiettivo del test:** verificare che token validi ma esplicitamente revocati (post-logout, post-password-change) vengano rifiutati.

#### Categoria A / B — Da implementare come connector

*(Nessun tool — test NATIVE puro)*

#### Categoria C — Scartato

| Tool | Motivo Scarto | Alternativa |
|---|---|---|
| **Hurl** | C.4 — DSL che aggiunge solo leggibilità documentale; la sequenza login → logout → replay è logica Python stateful sul TestContext | Python nativo |
| **mitmproxy** | C.3 — Approccio a proxy richiede interposizione nella connessione; per revoca il test è diretto via httpx | Python nativo |
| **keycloak-admin-client** | C.2 — Platform-specific Keycloak; il tool è agnostico per design | — |
| **auth0-cli** | C.2 — Platform-specific Auth0 | — |
| **aws-cognito-idp** | C.2 — Platform-specific AWS Cognito | — |
| **jose-cli** | C.4 — Uso marginale per verifica struttura crittografica post-revoca | — |

---

### Test 1.5 — Le Credenziali Non Sono Trasmesse via Canali Insicuri (TLS) `[P2]`

**Obiettivo del test:** verificare TLS 1.2+ enforced, cipher suite sicure (ECDHE + AEAD), HSTS, redirect HTTP→HTTPS.

#### Categoria A — Da implementare come connector

| Tool | Repository | Linguaggio/Tipo | Valore Architetturale vs Python Nativo | Output | Fonte | Note |
|---|---|---|---|---|---|---|
| **testssl.sh 3.2** | `testssl/testssl.sh` | Bash script (dipendenze: OpenSSL) | **Standard de facto per TLS security assessment.** Copre: versioni protocollo (SSLv2–TLS 1.3), cipher suite, forward secrecy, certificate transparency (SCT count), vulnerabilità CVE-based (BEAST, POODLE, ROBOT, DROWN, Heartbleed, LUCKY13, SWEET32, FREAK, LOGJAM, CRIME, BREACH, RENEGOTIATION, TICKETBLEED). Replicare in Python richiederebbe centinaia di handshake TLS a livello socket raw. | JSON (`--jsonfile <path>`) con `{id, severity, finding, cve, cwe}` | Claude Analysis, use.ai-3 v3 | **Tool primario.** Versione 3.2 stabile. Docker: `drwetter/testssl.sh`. Filtrare `severity in {MEDIUM, HIGH, CRITICAL, WARN}`. |

#### Categoria B — Connector facoltativo (fallback nativo disponibile)

| Tool | Repository | Linguaggio/Tipo | Valore Architetturale vs Python Nativo | Output | Fonte | Note |
|---|---|---|---|---|---|---|
| **sslyze** | `nabla-c0d3/sslyze` | Python — libreria / CLI | Alternativa Python-native importabile come libreria (`from sslyze import ...`) invece di subprocess. Meno completa di testssl.sh per vulnerability scanning ma zero binary dependencies. Fallback quando testssl.sh non è disponibile nell'ambiente. | JSON | Claude Analysis, use.ai-3 v2 | **Libreria Python** → `BaseLibraryConnector`, non `BaseSubprocessConnector` |

#### Categoria C — Scartato

| Tool | Motivo Scarto | Alternativa |
|---|---|---|
| **tlsx** | C.4 — Più veloce per multi-target ma meno profondo per singolo target; il nostro caso è sempre singolo target | testssl.sh |
| **sslscan2** | C.1 — Alternativa a sslyze senza vantaggi su sslyze; dipendenza C aggiuntiva | sslyze |
| **tls-scan** | C.4 — Ottimizzato per bulk scan su migliaia di host; non per analisi profonda su singolo target | testssl.sh |
| **h2spec** | C.3 — HTTP/2 conformance testing; scope diverso da TLS vulnerability detection | — |
| **quiche + curl --http3** | C.3 — HTTP/3/QUIC, fuori scope v1.0 | — |
| **jwt_tool (-cv)** | C.4 — Uso terziario per verifica canale TLS; testssl.sh copre questo in modo specifico e completo | testssl.sh |

---

### Test 1.6 — Le Sessioni Sono Gestite in Modo Sicuro in Architetture Distribuite `[P3]`

**Obiettivo del test:** audit cookie attributes (HttpOnly, Secure, SameSite), session store TTL, session fixation.

#### Categoria A / B — Da implementare come connector

*(Nessun tool — test NATIVE puro)*

#### Categoria C — Scartato

| Tool | Motivo Scarto | Alternativa |
|---|---|---|
| **mitmproxy** | C.3 — Approccio proxy richiede interposizione nella connessione; incompatibile con black-box; per session fixation il test empirico è Python + httpx | Python nativo |
| **Hurl** | C.4 — DSL documentale senza valore tecnico | Python nativo |
| **jwt_tool** | C.4 — Uso terziario su session management; mapping marginale | — |

---

## DOMINIO 2 — Autorizzazione e Controllo Accessi

---

### Test 2.1 — Solo Utenti Autorizzati Accedono a Endpoint Privilegiati (RBAC) `[P1]`

**Obiettivo del test:** verificare che endpoint privilegiati rifiutino con `403` utenti autenticati ma con ruolo insufficiente.

#### Categoria A / B — Da implementare come connector

*(Nessun tool — test NATIVE puro)*

#### Categoria C — Scartato

| Tool | Motivo Scarto | Alternativa |
|---|---|---|
| **opa + conftest** | C.2 — Richiede che il target usi OPA come policy engine; assunzione non agnostica; viola il principio di agnosticismo dell'architettura | Python nativo |
| **Spectral** | C.3 — Solo analisi statica della spec, già coperta da cherrybomb presente per 0.1/0.2 | cherrybomb |

---

### Test 2.2 — Gli Utenti Accedono Solo ai Propri Dati (BOLA Prevention) `[P1]`

**Obiettivo del test:** verificare che un utente non possa accedere a risorse di un altro utente (IDOR, BOLA).

#### Categoria A — Da implementare come connector

*(Nessun tool Categoria A — il test è HYBRID con tool B)*

#### Categoria B — Connector facoltativo (fallback nativo disponibile)

| Tool | Repository | Linguaggio/Tipo | Valore Architetturale vs Python Nativo | Output | Fonte | Note |
|---|---|---|---|---|---|---|
| **OWASP OFFAT** | `OWASP/OFFAT` | Python — CLI / libreria | Parser OpenAPI → generazione automatica test IDOR sostituendo ID utente su tutti gli endpoint con path parameters. Copre sistematicamente l'intera superficie senza configurazione manuale per endpoint. | JSON | use.ai-1, use.ai-2, use.ai-3 v2, use.ai-3 v3 | Strumento primario per BOLA; copre anche mass assignment |
| **cherrybomb** | GitHub open source | Rust — CLI binario | Analisi statica OpenAPI: identifica pattern BOLA nella spec (endpoint con ID path param senza ownership check dichiarato) prima del test dinamico. Connector già presente. | JSON | use.ai-3 v2, use.ai-3 v3 | Approccio SAST complementare al DAST |

#### Categoria C — Scartato

| Tool | Motivo Scarto | Alternativa |
|---|---|---|
| **akto** | C.3 — Piattaforma Java pesante; non tool di assessment API integrabile come connector | OFFAT |
| **susanoo** | C.1 — Alternativa a OFFAT meno matura e meno mantenuta | OFFAT |
| **AuthMatrix** | C.3 — Richiede configurazione manuale della matrice ruoli×endpoint; non agnostica; non automatable senza knowledge a priori | OFFAT |
| **astra** | C.1 — DEPRECATED: ultimo commit 2020 | OFFAT, cherrybomb |

---

### Test 2.3 — Le Operazioni Distruttive Richiedono Privilegi Appropriati `[P1]`

**Obiettivo del test:** verificare che DELETE/PUT/operazioni finanziarie richiedano scope OAuth2 o ruoli elevati (Least Privilege).

#### Categoria A — Da implementare come connector

*(Nessun tool Categoria A — il test è NATIVE + opzionale)*

#### Categoria B — Connector facoltativo (fallback nativo disponibile)

| Tool | Repository | Linguaggio/Tipo | Valore Architetturale vs Python Nativo | Output | Fonte | Note |
|---|---|---|---|---|---|---|
| **OWASP OFFAT** | `OWASP/OFFAT` | Python — CLI | Genera automaticamente test di authorization su operazioni distruttive dalla spec OpenAPI. Connector già presente per 2.2. | JSON | use.ai-3 v3 | Condiviso con 2.2 |

#### Categoria C — Scartato

| Tool | Motivo Scarto | Alternativa |
|---|---|---|
| **Hurl** | C.4 — DSL documentale per sequenza least privilege testing; la logica stateful è Python sul TestContext | Python nativo |

---

### Test 2.4 — Le Policy di Autorizzazione Sono Consistenti Across Endpoint `[P1]`

**Obiettivo del test:** verificare che endpoint equivalenti (versioni diverse, format alternativi) applichino policy di autenticazione identiche.

#### Categoria A / B — Da implementare come connector

*(Nessun tool — test NATIVE puro)*

#### Categoria C — Scartato

| Tool | Motivo Scarto | Alternativa |
|---|---|---|
| **dredd** | C.3 — Contract testing OpenAPI; scope più ampio e diverso da security policy consistency | Python nativo |
| **prism** | C.3 — Mock server e validation proxy; strumento di sviluppo, non security testing | Python nativo |
| **Spectral** | C.3 — Linter statico; l'analisi dinamica del comportamento è più rilevante per questo test | Python nativo |
| **vacuum** | C.3 — Alternativa Go a Spectral, stessa limitazione di scope | Python nativo |

---

### Test 2.5 — L'API Non Espone Dati Eccessivi `[P2]`

**Obiettivo del test:** verificare che le response non contengano campi sensibili non documentati (password hash, SSN, API key).

#### Categoria A / B — Da implementare come connector

*(Nessun tool — test NATIVE puro)*

#### Categoria C — Scartato

| Tool | Motivo Scarto | Alternativa |
|---|---|---|
| **graphql-cop** | C.3 — GraphQL-only; fuori scope v1.0 (REST only) | — |
| **APIClarity** | C.3 — Richiede traffic capture; scope v2.0 | — |
| **akto** | C.3 — Piattaforma Java pesante | — |
| **jwttool -pd** | C.4 — Uso specifico per claim JWT eccessivi; caso molto marginale; jwt_tool già presente per 1.2 | jwt_tool |

---

## DOMINIO 3 — Integrità dei Dati

---

### Test 3.1 — Tutti gli Input Sono Validati Secondo Schema e Constraints `[P2]`

**Obiettivo del test:** verificare che injection (SQL, NoSQL, command, template, CRLF), type confusion, e payload anomali siano rifiutati con `400`.

> **Nota copertura CRLF (v1.3):** CRLFuzz rimosso da Cat A (inattivo dal 2021). La ragione tecnica della sua presenza era che operava su raw socket bypassando la normalizzazione RFC 7230 applicata da `httpx`. I template Nuclei `crlf-injection` nel bundle pinned `nuclei-templates 10.4.3` usano lo stesso approccio raw TCP e producono evidenza equivalente. **Pre-requisito:** verificare la presenza del tag `crlf-injection` nel bundle prima di dichiarare la copertura CRLF soddisfatta nel test 3.1.

#### Categoria A — Da implementare come connector

| Tool | Repository | Linguaggio/Tipo | Valore Architetturale vs Python Nativo | Output | Fonte | Note |
|---|---|---|---|---|---|---|
| **Schemathesis** | `schemathesis/schemathesis` | Python — libreria / CLI | **Unico tool integrabile come libreria Python nativa** (`from schemathesis import from_uri`). Property-based testing con Hypothesis engine: genera centinaia di input per ogni parametro di ogni endpoint basandosi sulla spec OpenAPI. Esplora lo spazio degli input in modo esaustivo rispetto allo schema — paradigma di testing diverso da una lista di payload. OpenAPI 3.1 nativo. | JUnit XML, JSON | Claude Analysis, use.ai-3 v2 | **Nota architetturale**: `BaseLibraryConnector`, non `BaseSubprocessConnector` |
| **Nuclei** | `projectdiscovery/nuclei` | Go — CLI binario | Template `http/vulnerabilities/` per injection specifiche per framework noti (Spring Boot, Django, Laravel, Rails). Aggiornati dalla community senza intervento manuale. Copre anche CRLF injection tramite template `crlf-injection` (sostituisce ex-CRLFuzz). | JSON (`-json`), SARIF | Claude Analysis, use.ai-3 v2 | Connector condiviso con 0.1 e 7.2 |

#### Categoria B — Connector facoltativo (fallback nativo disponibile)

| Tool | Repository | Linguaggio/Tipo | Valore Architetturale vs Python Nativo | Output | Fonte | Note |
|---|---|---|---|---|---|---|
| **sqlmap** | `sqlmapproject/sqlmap` | Python — CLI | Standard de facto per SQLi. Motore di payload generation basato su grammar context-aware che supera qualsiasi lista manuale. Flag `--batch --forms --risk=3 --level=5`. | JSON (`--output-dir`) | use.ai-2, use.ai-3 v2, use.ai-3 v3 | Standard de facto per SQL injection |
| **NoSQLMap** | `codingo/NoSQLMap` | Python — CLI | Specifico per MongoDB/CouchDB injection. Critico per API moderne. Unico tool maturo per NoSQL injection. | Strutturato | use.ai-2, use.ai-3 v2, use.ai-3 v3 | Angolazione completamente separata da sqlmap |
| **Dalfox** | `hahwul/dalfox` | Go — CLI binario | XSS context-aware con DOM analysis e blind detection. Motore di payload generation basato su grammar context-aware. Supera liste statiche di payload per falsi negativi. | JSON (`--format json`) | use.ai-1, use.ai-2, use.ai-3 v2, use.ai-3 v3 | Strumento primario per XSS; molto attivo |
| **commix** | `commixproject/commix` | Python — CLI | Unico tool maturo per OS command injection automatizzato. Rileva blind injection via time-based, error-based, output-based. Copre header injection, path injection, varianti OS. | Strutturato | use.ai-2, use.ai-3 v2, use.ai-3 v3 | Nessuna alternativa equivalente per command injection |
| **SSTImap** | Repository pubblico | Python — CLI | Fork attivo di tplmap. Copre Jinja2, Twig, Smarty, Velocity, FreeMarker, Pebble. Rileva engine automaticamente e adatta i payload. | Strutturato | use.ai-3 v3 | **Preferire SSTImap** come fork attivo di tplmap |

#### Categoria C — Scartato

| Tool | Motivo Scarto | Alternativa |
|---|---|---|
| **CRLFuzz** | C.1 — DEPRECATED: inattivo dal 2021. Copertura CRLF delegata a template Nuclei `crlf-injection` (stesso approccio raw TCP). | Nuclei templates `crlf-injection` |
| **ghauri** | C.1 — Alternativa a sqlmap senza vantaggi determinanti; sqlmap è sufficiente e standard de facto | sqlmap |
| **nosqli** | C.1 — Alternativa Go a NoSQLMap, meno matura | NoSQLMap |
| **XSStrike** | C.1 — Alternativa a Dalfox; Dalfox è superiore per context-aware XSS | Dalfox |
| **tplmap** | C.1 — SSTImap è il fork attivo di tplmap con motori aggiuntivi | SSTImap |
| **crlfmap** | C.1 — Alternativa a CRLFuzz; CRLFuzz stesso rimosso → Nuclei templates | Nuclei templates |
| **headi** | C.1 — Copre header injection ma CRLFuzz già lo faceva; CRLFuzz rimosso → Nuclei templates | Nuclei templates |
| **dotdotpwn** | C.1 — Path traversal testing coperto da ffuf con wordlist dedicate | ffuf + wordlist |
| **CATS** | C.3 — Alternativa Java a Schemathesis; preferiamo la libreria Python nativa | Schemathesis |
| **APIFuzzer** | C.1 — Coperto completamente da Schemathesis | Schemathesis |
| **cherrybomb** | C.4 — Analisi statica per injection points; Nuclei copre l'angolazione dinamica con più coverage | Nuclei |

---

### Test 3.3 — I Dati in Transit Sono Protetti da Manipolazione (HMAC Config Audit) `[P3]`

**Obiettivo del test:** audit dell'architettura di HMAC request signing — presenza/assenza, algoritmo, protezione da replay.

#### Categoria A / B — Da implementare come connector

*(Nessun tool — test NATIVE puro: Configuration Audit via lettura documentazione e codice)*

#### Categoria C — Scartato

| Tool | Motivo Scarto | Alternativa |
|---|---|---|
| **step-cli** | C.4 — `step crypto key inspect` è un singolo comando CLI; `openssl` o sslyze già presenti coprono la stessa analisi; non giustifica dipendenza per test P3 | openssl CLI o sslyze |
| **jwt_tool** | C.4 — Uso marginale su HMAC; il connector è per 1.2/1.3 | — |
| **Vault API** | C.2 — HashiCorp Vault-specific; rompe l'agnosticismo | — |
| **mitmproxy** | C.3 — Approccio proxy incompatibile con black-box; per test empirico P3 il rischio/beneficio è sfavorevole | — |
| **Checkov** | C.2 — IaC scanner Terraform/CF/K8s; scope completamente diverso | — |

---

## DOMINIO 4 — Disponibilità e Resilienza

---

### Test 4.1 — Il Sistema Previene Resource Exhaustion via Rate Limiting `[P0]`

**Obiettivo del test:** verificare che il Gateway applichi rate limiting e risponda con `429 Too Many Requests` con `Retry-After`.

#### Categoria A — Da implementare come connector

| Tool | Repository | Linguaggio/Tipo | Valore Architetturale vs Python Nativo | Output | Fonte | Note |
|---|---|---|---|---|---|---|
| **vegeta** | `tsenart/vegeta` | Go — CLI binario | Rate control preciso con goroutine Go. Il GIL Python e il garbage collector introducono jitter che rende inaffidabile la soglia osservata. Per verificare che il rate limit scatti esattamente a N req/s, il load generator deve essere preciso al millisecondo. Istogrammi latenza (p50/p90/p99). | JSON (`vegeta attack \| vegeta report --type=json`) | use.ai-2, use.ai-3 v2, use.ai-3 v3 | **Connector condiviso con 7.3.** `-rate=0 -max-workers=N` per race condition. |

#### Categoria B / C

*(Nessun tool Categoria B per questo test)*

#### Categoria C — Scartato

| Tool | Motivo Scarto | Alternativa |
|---|---|---|
| **hey** | C.1 — Redundanza esplicita di vegeta: stessa funzione, meno feature | vegeta |
| **slowloris** | C.4 — Testa slow HTTP attacks su connessioni lente; angolazione orthogonale al rate limiting su frequenza richiesta; il test 4.2 sui timeout indirizza il caso slow-connection | vegeta per frequenza |
| **bombardier** | C.4 — HTTP/2 specifico; scenario marginale per il test principale; vegeta copre il caso generale | vegeta |
| **graphql-cop** | C.3 — GraphQL-only; fuori scope v1.0 | — |

---

### Test 4.2 — Il Sistema Implementa Timeout per Prevenire Resource Lock `[P1]`

**Obiettivo del test:** audit dei timeout configurati su Gateway (connect/read/write), connection pool, e chiamate HTTP esterne.

#### Categoria A / B — Da implementare come connector

*(Nessun tool — test NATIVE puro: Configuration Audit)*

#### Categoria C — Scartato

| Tool | Motivo Scarto | Alternativa |
|---|---|---|
| **httpstat** | C.4 — Timing breakdown visivo; Python può misurare TTFB e tempi di connessione; non aggiunge evidenze strutturate al report | Python nativo |
| **deck** | C.2 — Kong-specific; viola l'agnosticismo; la logica di lettura configurazione è nel `BaseGatewayAdapter` | BaseGatewayAdapter |
| **vegeta** | C.4 — Utile come test comportamentale opzionale in staging ma il test è Configuration Audit, non load test | — |
| **prowler** | C.2 — AWS-specific | — |
| **kubescape** | C.2 — Kubernetes-specific | — |

---

### Test 4.3 — Il Sistema Degrada Gracefully con Circuit Breaker `[P1]`

**Obiettivo del test:** audit della configurazione circuit breaker (threshold, timeout, trigger codes, observability).

#### Categoria A / B — Da implementare come connector

*(Nessun tool — test NATIVE puro: Configuration Audit)*

#### Categoria C — Scartato

| Tool | Motivo Scarto | Alternativa |
|---|---|---|
| **deck** | C.2 — Kong-specific; viola l'agnosticismo | BaseGatewayAdapter |
| **inso** | C.2 — Kong ecosystem-specific | BaseGatewayAdapter |
| **kuma-cp inspect** | C.2 — Kuma service mesh-specific | — |
| **istioctl analyze** | C.2 — Istio service mesh-specific | — |
| **kubescape** | C.2 — Kubernetes-specific | — |
| **linkerd viz** | C.2 — Linkerd service mesh-specific | — |
| **aws appmesh** | C.2 — AWS App Mesh-specific | — |
| **envoy-tools** | C.2 — Envoy standalone-specific | — |
| **vegeta** | C.4 — Test comportamentale opzionale in staging; non parte dell'oracle principale del Configuration Audit | — |

---

## DOMINIO 5 — Visibilità e Auditing

---

### Test 5.1 — Ogni Richiesta È Logged con Metadata Essenziali `[P1]`

**Obiettivo del test:** verificare che ogni request generi log strutturati con timestamp, Request ID, source IP, User ID, status code, response time.

#### Categoria A / B — Da implementare come connector

*(Nessun tool — test NATIVE puro)*

#### Categoria C — Scartato

| Tool | Motivo Scarto | Alternativa |
|---|---|---|
| **vector + jq** | C.4 — Pipeline di log processing stack-specific; non un tool di security assessment; Python httpx interroga qualsiasi log aggregator tramite REST API | Python nativo |
| **loki-cli** (logcli) | C.4 — Grafana/Loki-specific; Python via httpx può interrogare Loki via REST API (`/loki/api/v1/query`) senza dipendenze aggiuntive | Python nativo |
| **nuclei** | C.4 — Uso indiretto per trigger condizioni di log; la logica è più pulita come Python diretto | Python nativo |
| **Prowler** | C.2 — AWS-specific (CloudWatch, GuardDuty) | — |
| **metlo** | C.3 — Traffic capture; scope diverso | — |

---

### Test 5.2 — Eventi Security Anomali Triggerano Alert Real-Time `[P2]`

**Obiettivo del test:** verificare che brute-force, BOLA enumeration, rate limit hit triggerino alert verso SIEM/notifiche entro SLA.

#### Categoria A / B — Da implementare come connector

*(Nessun tool — test NATIVE puro)*

#### Categoria C — Scartato

| Tool | Motivo Scarto | Alternativa |
|---|---|---|
| **alertmanager webhook receiver mock** | C.4 — Richiede setup infrastruttura Prometheus locale; dipendenza pesante per un test P2 | Python nativo con endpoint webhook locale |
| **webhook.site API** | C.4 — Servizio esterno non controllato; introduce dipendenza da connettività esterna; il test deve essere riproducibile in ambienti air-gapped | Python nativo con endpoint locale |
| **nuclei** | C.4 — Uso troppo indiretto come layer aggiuntivo su alert testing | Python nativo |
| **Prowler** | C.2 — AWS-specific | — |

---

## DOMINIO 6 — Configurazione e Hardening

---

### Test 6.1 — Error Handling e Information Disclosure `[P2]`

**Obiettivo del test:** verificare che le response non contengano stack trace, versioni framework, SQL errors, debug data.

#### Categoria A / B — Da implementare come connector

*(Nessun tool — test NATIVE puro)*

#### Categoria C — Scartato

| Tool | Motivo Scarto | Alternativa |
|---|---|---|
| **httpx (ProjectDiscovery)** | C.4 — La velocità Go per probing massivo su centinaia di endpoint è irrilevante per singolo target; la libreria Python httpx già usata copre lo stesso; il flag `-tech-detect` aggiunge fingerprinting ma non evidenze di vulnerabilità strutturate automatizzabili | Python httpx nativo |
| **whatweb** | C.4 — Fingerprinting tecnologico Ruby; utile per contestualizzare finding in manuale ma non produce evidenze di vulnerabilità dirette; richiede runtime Ruby | Python nativo |
| **hakrawler** | C.4 — Crawler generico usato come pipeline grep; non tool di security analysis; la logica è più pulita come iterazione Python su `AttackSurface` | Python nativo |
| **Spectral** | C.3 — Linter statico; l'analisi dinamica delle response è più rilevante per information disclosure | Python nativo |

---

### Test 6.2 — Security Header Configurati Appropriatamente `[P3]`

**Obiettivo del test:** verificare presenza e valore di HSTS, X-Frame-Options, X-Content-Type-Options, CSP, Permissions-Policy.

#### Categoria A / B — Da implementare come connector

*(Nessun tool — test NATIVE puro)*

#### Categoria C — Scartato

| Tool | Motivo Scarto | Alternativa |
|---|---|---|
| **shcheck** | C.4 — Python può verificare la presenza di 6-8 header con una lista di valori attesi in ~20 righe; il vantaggio di coprire header meno comuni (COOP, COEP) non giustifica una dipendenza per un test P3 | Python nativo |
| **csp-evaluator** | C.4 — API REST pubblica Google; Python con httpx fa la stessa chiamata in 3 righe; non è un tool da integrare come connector | Python nativo con httpx |
| **securityheaders.com API** | C.4 — Servizio esterno di scoring; non aggiunge evidenze automatizzate; dipendenza da connettività esterna | Python nativo |
| **treblle** | C.4 — Poco mantenuto come tool standalone; non aggiunge valore rispetto a Python nativo | Python nativo |
| **Checkov** | C.2 — IaC scanner; scope completamente diverso | — |

---

### Test 6.3 — La Configurazione del Gateway È Hardenata Contro Exploit Layer-7 `[P1]`

**Obiettivo del test:** HTTP Request Smuggling (CL.TE, TE.CL), Slowloris timeout, CORS enforcement, path normalization, plugin security.

> **Nota architetturale v1.3:** smuggler rimosso da Cat A per assenza di release ufficiale. Il connector `ext_test_6_3_smuggling.py` implementa i pattern **CL.TE** e **TE.CL** (RFC 9110 §9.3.3) direttamente tramite `socket` della stdlib Python. Python `httpx` rifiuta per design gli header ambigui `Content-Length` + `Transfer-Encoding: chunked` simultaneamente per conformità RFC — il raw socket bypassa questo enforcement a livello TCP. Il vantaggio accademico è che il codice del connector è leggibile nella tesi e documenta il meccanismo dell'attacco senza dipendere da un binary black-box.

#### Categoria A — Da implementare come connector

*(Nessun tool Cat A — il connector usa Python raw sockets stdlib per CL.TE/TE.CL)*

#### Categoria B — Connector facoltativo (fallback nativo disponibile)

| Tool | Repository | Linguaggio/Tipo | Valore Architetturale vs Python Nativo | Output | Fonte | Note |
|---|---|---|---|---|---|---|
| **http2smugl** | Repository Go pubblico | Go — CLI binario | Copre HTTP/2 downgrade smuggling — angolazione distinta dai pattern CL.TE/TE.CL implementati nel connector nativo. Promovibile a Cat A se il target espone HTTP/2. Attivamente mantenuto. | Strutturato | use.ai-3 v3 | **Cat B opzionale.** Candidato a Cat A se il target usa H2. |

#### Categoria B / C precedente

*(Nessun tool Categoria B aggiuntivo per questo test)*

#### Categoria C — Scartato

| Tool | Motivo Scarto | Alternativa |
|---|---|---|
| **smuggler** | C.1 — Nessuna release ufficiale taggata; i pattern CL.TE/TE.CL sono implementati direttamente con socket Python stdlib nel connector. | Python raw sockets (stdlib) |
| **gotestwaf** | C.3 — Overkill: copre l'intero spazio Layer-7 WAF bypass; per il solo smuggling il perimetro è il connector nativo | Python raw sockets |
| **h2csmuggler** | C.4 — HTTP/2 cleartext upgrade smuggling; scenario molto specifico che richiede target con HTTP/2 upgrade non cifrato; la maggioranza dei target non lo espone | http2smugl (Cat B) |
| **deck** | C.2 — Kong-specific; viola l'agnosticismo; `BaseGatewayAdapter` astrae questa logica | BaseGatewayAdapter |
| **inso** | C.2 — Kong ecosystem-specific | BaseGatewayAdapter |
| **kong-plugin-validator** | C.2 — Kong-specific | BaseGatewayAdapter |
| **prowler** | C.2 — AWS-specific | — |
| **checkov** | C.2 — IaC scanner | — |
| **inspec-aws** | C.2 — AWS + Ruby InSpec | — |
| **steampipe** | C.2 — Cloud SQL query; cloud-specific | — |
| **cfn-lint** | C.2 — AWS CloudFormation-specific | — |
| **tfsec** | C.2 — Terraform-specific | — |
| **kics** | C.2 — Multi-IaC scanner | — |
| **kubescape** | C.2 — Kubernetes-specific | — |
| **kube-linter** | C.2 — Kubernetes-specific | — |
| **kubeaudit** | C.2 — Kubernetes Ingress-specific | — |
| **istioctl** | C.2 — Istio service mesh-specific | — |

---

### Test 6.4 — Le Credenziali di Servizio Non Sono Hardcoded o Esposte `[P2]`

**Obiettivo del test:** verificare che le credenziali siano in Secret Manager, non hardcoded in file di config, immagini Docker, o esposte via debug endpoint.

#### Categoria A — Da implementare come connector

*(Nessun tool Categoria A — il test è HYBRID con tool B)*

#### Categoria B — Connector facoltativo (fallback nativo disponibile)

| Tool | Repository | Linguaggio/Tipo | Valore Architetturale vs Python Nativo | Output | Fonte | Note |
|---|---|---|---|---|---|---|
| **trufflehog** | `trufflesecurity/trufflehog` | Go — CLI binario | **800+ detector per API keys, tokens, secrets** (AWS, Stripe, GitHub, Slack, ecc.). Scansiona response body, spec files, JS bundles, git history. Mantenere questi regex aggiornati in Python sarebbe un incubo di manutenzione continua. | JSON | use.ai-1, use.ai-2, use.ai-3 v2, use.ai-3 v3 | **Strumento primario** |
| **gitleaks** | `gitleaks/gitleaks` | Go — CLI binario | Scansiona commit history del repository dove risiede la spec OpenAPI o i file di configurazione. Angolazione distinta da trufflehog: runtime vs versionamento git. | JSON | use.ai-2, use.ai-3 v2 | Complementare a trufflehog |
| **detect-secrets** | `Yelp/detect-secrets` | Python — CLI / libreria | Plugin architecture per custom detectors. Importabile come libreria Python. Pre-commit hook nativo. Utile sia per testare il target che per la CI del progetto stesso. | JSON | use.ai-2, use.ai-3 v2, use.ai-3 v3 | Importabile come libreria Python |

#### Categoria C — Scartato

| Tool | Motivo Scarto | Alternativa |
|---|---|---|
| **secretlint** | C.1 — Node.js; detect-secrets Python library copre lo stesso | detect-secrets |
| **kube-linter** | C.2 — Kubernetes-specific | — |
| **prowler** | C.2 — AWS-specific | — |

---

## DOMINIO 7 — Business Logic e Flussi Sensibili

---

### Test 7.1 — I Flussi Business Sensibili Sono Protetti da Abuse Automatizzato `[P2]`

**Obiettivo del test:** verificare CAPTCHA enforcement, rate limiting applicativo aggressivo, device fingerprinting su endpoint payment/register.

#### Categoria A / B — Da implementare come connector

*(Nessun tool — test NATIVE puro)*

#### Categoria C — Scartato

| Tool | Motivo Scarto | Alternativa |
|---|---|---|
| **playwright** | C.4 — Browser automation per CAPTCHA testing è un test P2 secondario; il connector aggiungerebbe una dipendenza browser completo per un singolo scenario; la verifica che il CAPTCHA *esista* nella response HTTP è osservabile con Python httpx | Python nativo |
| **puppeteer** | C.1 — Node.js; playwright copre lo stesso con binding Python | playwright (già C.4) |
| **puppeteer-extra-stealth** | C.4 — Device fingerprinting avanzato; scenario specifico non nel core del test | — |
| **vegeta** | C.4 — Connector già presente per 4.1; l'uso per burst test su endpoint business è marginale rispetto alla logica nativa | vegeta già in 4.1 |
| **curl-impersonate** | C.4 — TLS fingerprint impersonation; scenario molto avanzato e specifico non nel core del test | — |
| **akto** | C.3 — Piattaforma Java pesante | — |

---

### Test 7.2 — Il Sistema Previene Server-Side Request Forgery (SSRF) `[P0]`

**Obiettivo del test:** verificare che il sistema blocchi SSRF verso cloud metadata (169.254.169.254), indirizzi privati, e bypass via encoding.

**Nota tecnica:** SSRFmap è implementato come layer nativo (`ssrf_payloads.py`) — non è un connector esterno ma logica Python integrata nel test. I payload standard (cloud metadata, private IP, encoding bypass, protocol whitelist) sono codice Python nativo. I connector qui estendono il coverage con angolazioni non replicabili in Python.

> **Nota copertura Gopher (v1.3):** Gopherus rimosso da Cat B (4 anni senza commit, nessuna release). I template Nuclei nella categoria `ssrf` e `network` del bundle pinned `nuclei-templates 10.4.3` coprono SSRF verso Redis, MySQL, FastCGI, Memcached e SMTP tramite payload Gopher. **Pre-requisito:** verificare la presenza di template `ssrf-via-gopher-*` prima di dichiarare la copertura Gopher soddisfatta.

#### Categoria A — Da implementare come connector

| Tool | Repository | Linguaggio/Tipo | Valore Architetturale vs Python Nativo | Output | Fonte | Note |
|---|---|---|---|---|---|---|
| **Nuclei** | `projectdiscovery/nuclei` | Go — CLI binario | Template `http/vulnerabilities/generic/ssrf*` con bypass specifici per tecnologie e configurazioni cloud emergenti. Aggiornati dalla community. Angolazione distinta da `ssrf_payloads.py` nativo. Copre anche payload Gopher tramite template `ssrf-via-gopher-*` (sostituisce ex-Gopherus). | JSON | Claude Analysis | Connector condiviso con 0.1 e 3.1 |
| **interactsh** | `projectdiscovery/interactsh` | Go — server / client | **OOB (Out-of-Band) callback server** per confermare SSRF blind. Senza OOB, le SSRF blind non sono rilevabili. interactsh registra DNS/HTTP callbacks che confermano l'exploitation. Angolazione non sostituibile con Python puro. | JSON | use.ai-2, use.ai-3 v2, use.ai-3 v3 | **Indispensabile per Blind SSRF**. Condiviso con 7.4 |

#### Categoria B — Connector facoltativo (fallback nativo disponibile)

*(Nessun tool Categoria B — Gopherus rimosso, vedi Cat C)*

#### Categoria C — Scartato

| Tool | Motivo Scarto | Alternativa |
|---|---|---|
| **Gopherus** | C.1 — DEPRECATED: 4 anni senza commit, nessuna release. I template Nuclei `ssrf-via-gopher-*` coprono gli stessi payload (Redis, MySQL, FastCGI, Memcached, SMTP). | Nuclei templates `ssrf-via-gopher-*` |
| **SSRFmap** | Note: integrato come codice nativo (`ssrf_payloads.py`), non connector | — |
| **nimbostratus** | C.2 — AWS metadata exploitation specifico; platform-specific | ssrf_payloads.py nativo |
| **singularity** | C.4 — DNS rebinding framework; scenario avanzato coperto dalla logica nativa con payload standard | ssrf_payloads.py nativo |
| **SSRFfire** | C.1 — DEPRECATED (ultimo commit 2021); sostituito da SSRFmap integrato come nativo | ssrf_payloads.py nativo |

---

### Test 7.3 — Le Operazioni Critiche Sono Idempotent o Protette da Race Condition `[P2]`

**Obiettivo del test:** verificare che operazioni critiche (payment, inventory deduction) siano protette da race condition e che l'Idempotency Key funzioni.

#### Categoria A — Da implementare come connector

| Tool | Repository | Linguaggio/Tipo | Valore Architetturale vs Python Nativo | Output | Fonte | Note |
|---|---|---|---|---|---|---|
| **vegeta** | `tsenart/vegeta` | Go — CLI binario | Connector già presente per 4.1. Flag `-rate=0 -max-workers=N` lancia N goroutine Go in parallelo con sincronizzazione last-byte — equivalente funzionale del ex-race-the-web. Python asyncio introduce jitter di scheduling che sfasa la sincronizzazione sub-millisecondo necessaria per TOCTOU. Output JSON con `status_codes` e `latencies` per rilevare response anomale (es. doppio 200 su operazione idempotente). | JSON (`vegeta attack \| vegeta report --type=json`) | use.ai-2, use.ai-3 v2, use.ai-3 v3 | **Connector condiviso con 4.1.** `-rate=0 -max-workers=N` per last-byte sync. |

#### Categoria B / C

*(Nessun tool Categoria B per questo test)*

#### Categoria C — Scartato

| Tool | Motivo Scarto | Alternativa |
|---|---|---|
| **race-the-web** | C.1 — DEPRECATED: abbandonato, poche stelle, nessuna release recente. vegeta con `-rate=0 -max-workers=N` copre il requisito di last-byte sync senza dipendenze aggiuntive. | vegeta (Cat A) |
| **racepwn** | C.4 — Dipendenza `librace` C richiede compilazione non triviale in ambienti Docker; il vettore HTTP/2 concurrent streams è raro su target gateway-standard come Kong; vegeta copre il caso comune | vegeta |
| **turbo-intruder** | C.4 — Java/Jython, setup molto complesso; vegeta copre la stessa precisione con architettura più semplice | vegeta |
| **h2csmuggler** | C.4 — HTTP/2 cleartext upgrade smuggling, non race condition | smuggler (già C.1) / http2smugl |
| **http2smugl** | C.1 — Smuggling HTTP/2; non race condition | http2smugl Cat B in 6.3 |
| **h2spec** | C.3 — Conformance testing HTTP/2; scope diverso da race condition | — |
| **ffuf -rate 0** | C.1 — Baseline grossolana per race detection; vegeta è il tier entry-level corretto | vegeta |

---

### Test 7.4 — L'API Consuma Servizi Esterni in Modo Sicuro (Webhook Verification) `[P2]`

**Obiettivo del test:** verificare HMAC signature su webhook, replay attack protection, sanitizzazione payload webhook.

#### Categoria A — Da implementare come connector

| Tool | Repository | Linguaggio/Tipo | Valore Architetturale vs Python Nativo | Output | Fonte | Note |
|---|---|---|---|---|---|---|
| **interactsh** | `projectdiscovery/interactsh` | Go — server / client | Connector già presente per 7.2. Registra webhook URL malevolo che punta a interactsh, verifica che il sistema lo chiami e riceva il callback. Fondamentale per verificare che webhook callback URL malevoli vengano rilevati — senza OOB server non c'è evidenza diretta. | JSON | use.ai-3 v3 | Condiviso con 7.2 |

#### Categoria B / C

*(Nessun tool Categoria B per questo test)*

#### Categoria C — Scartato

| Tool | Motivo Scarto | Alternativa |
|---|---|---|
| **httpx (ProjectDiscovery)** | C.4 — Redirect chain analysis con `-follow-redirects` è 3 righe con Python httpx nativo | Python nativo |
| **nuclei** | C.4 — Uso troppo indiretto per webhook testing; la logica è più chiara come Python diretto | Python nativo |
| **confused** | C.3 — Dependency confusion testing; supply chain attack, non API security in senso stretto | — |

---

## APPENDICE A — Tool Cross-Cutting (Multi-Dominio) — v1.3

Tool che coprono aspetti di più test o domini.

| Tool | Cat. | Domini/Test | Motivo Multi-Copertura |
|---|---|---|---|
| **Nuclei** | A | 0.1, 3.1, 7.2 | Template per shadow API, injection (incluso CRLF), SSRF (incluso Gopher) — un solo connector, tre test |
| **jwt_tool** | A | 1.2, 1.3 | JWT security testing multipurpose |
| **vegeta** | A | 4.1, 7.3 | Load testing per rate limiting (4.1); last-byte sync per race condition (7.3) |
| **interactsh** | A | 7.2, 7.4 | OOB server per SSRF blind e webhook callback testing |
| **cherrybomb** | B | 0.1, 0.2, 2.2 | Rust static analyzer multi-test |
| **OWASP OFFAT** | B | 2.2, 2.3 | BOLA e destructive operations authorization |
| **ffuf** | A | 0.1 (e fallback 0.2) | Go fuzzer — **promosso a Cat A** per 0.1; fallback per 0.2 |
| **oasdiff** | B | 0.3 | Spec diff tool |
| **trufflehog** | B | 6.4 | Secret scanning runtime |
| **gitleaks** | B | 6.4 | Secret scanning git history |
| **detect-secrets** | B | 6.4 | Secret scanning Python library |
| **sslyze** | B | 1.5 (fallback testssl.sh) | TLS analysis Python library |

Tool Categoria C con copertura multi-dominio (documentati per completezza storica):

| Tool | Cat. | Motivo Esclusione |
|---|---|---|
| **deck** | C.2 | Kong-specific → presente in catalogo sotto 4.2, 4.3, 6.3 |
| **prowler** | C.2 | AWS-specific → presente in catalogo sotto 4.2, 5.1, 5.2, 6.3, 6.4 |
| **kubescape** | C.2 | Kubernetes-specific → presente in catalogo sotto 4.2, 4.3, 6.3 |
| **istioctl** | C.2 | Istio-specific → presente in catalogo sotto 4.3, 6.3 |
| **checkov** | C.2 | IaC scanner → presente in catalogo sotto 3.3, 6.2, 6.3 |
| **Spectral** | C.3 | OpenAPI linter → presente in catalogo sotto 0.2, 0.3, 2.1, 2.4, 6.1 |
| **vacuum** | C.3 | Alternativa Go a Spectral → presente in catalogo sotto 0.2, 0.3, 2.4 |
| **dredd** | C.3 | Contract testing → presente in catalogo sotto 0.2, 0.3, 2.4 |
| **prism** | C.3 | Mock server → presente in catalogo sotto 0.2, 2.4 |
| **Hurl** | C.4 | DSL documentale → presente in catalogo sotto 1.1, 1.4, 2.3 |
| **httpx (PD)** | C.4 | Probing massivo → presente in catalogo sotto 6.1, 7.4 |
| **h2csmuggler** | C.4 | HTTP/2 smuggling → presente in catalogo sotto 6.3, 7.3 |
| **akto** | C.3 | Piattaforma Java → presente in catalogo sotto 0.1, 2.2, 2.5, 7.1 |

---

## APPENDICE B — Tool per Protocolli Non-REST (Fuori Scope v1.0, Documentati per Completezza)

### GraphQL

| Tool | Repository | Linguaggio | Test Equivalente | Funzione |
|---|---|---|---|---|
| **graphw00f** | Repository pubblico | Python | 0.1 | Fingerprint GraphQL engine, rileva introspection enabled |
| **clairvoyance** | Repository pubblico | Python | 2.2 | Ricostruisce schema GraphQL anche senza introspection |
| **graphql-cop** | Repository pubblico | Python | 2.5, 4.1 | 40+ security test automatici su endpoint GraphQL |
| **graphql-path-enum** | Repository pubblico | Python | 3.1 | Enumera path e rileva injection points GraphQL |
| **BatchQL** | Repository pubblico | Python | 7.1 | Test batching abuse per bypass rate limiting GraphQL |

### gRPC

| Tool | Repository | Linguaggio | Test Equivalente | Funzione |
|---|---|---|---|---|
| **grpcurl** | `fullstorydev/grpcurl` | Go | 0.1 | Reflection enumeration, output JSON |
| **grpc-client-cli** | Repository pubblico | Go | 3.1 | Fuzzing parametri gRPC |
| **ghz** | `bojand/ghz` | Go | 4.1 | Load testing gRPC, equivalente di vegeta |

### WebSocket

| Tool | Repository | Linguaggio | Test Equivalente | Funzione |
|---|---|---|---|---|
| **websocat** | `vi/websocat` | Rust | 1.1, 7.3 | CLI WebSocket, test auth su upgrade e race condition |
| **STEWS** | Repository pubblico | Python | 3.1 | WebSocket security testing framework |

---

## APPENDICE C — Tool Segnalati come Datati o Abbandonati

Documentati per completezza storica e per tracciabilità delle fonti. **Non raccomandati** per implementazione.

| Tool | Motivo | Alternativa Raccomandata | Fonte della Segnalazione |
|---|---|---|---|
| **astra** (`flipkart-incubator/Astra`) | Ultimo commit 2020 | OFFAT, cherrybomb | use.ai-3 v2, use.ai-3 v3 |
| **GAP-Burp-Extension** | Dipende da Burp Suite | katana + LinkFinder standalone | use.ai-3 v3 |
| **recaptcha-cracker** | Non mantenuto | Test manuale o Python nativo | use.ai-3 v3 |
| **SSRFfire** | Ultimo commit 2021 | SSRFmap integrato come nativo | use.ai-3 v3 |
| **kiterunner** (`assetnote/kiterunner`) | Abbandonato, nessun commit recente | ffuf (Cat A, promosso in v1.3) | Claude Analysis v1.3 |
| **CRLFuzz** (`dwisiswant0/crlfuzz`) | Inattivo dal 2021 | Nuclei templates `crlf-injection` | Claude Analysis v1.3 |
| **smuggler** (`defparam/smuggler`) | Nessuna release ufficiale taggata | Python raw sockets stdlib (connector 6.3) | Claude Analysis v1.3 |
| **race-the-web** (`TheHackerDev/race-the-web`) | Abbandonato, poche stelle, nessuna release recente | vegeta (Cat A, last-byte sync con `-rate=0 -max-workers=N`) | Claude Analysis v1.3 |
| **jwtXploiter** (`DontPanicO/jwtXploiter`) | Ultimo commit 5 anni fa, nessuna release recente | jwt_tool (Cat A, copre le stesse varianti kid injection) | Claude Analysis v1.3 |
| **Gopherus** (`tarunkant/Gopherus`) | Ultimo commit 4 anni fa, nessuna release | Nuclei templates `ssrf-via-gopher-*` | Claude Analysis v1.3 |

---

## APPENDICE D — Tool per Sviluppi Futuri (Fuori Scope v1.0)

Tool validi ma esclusi dallo scope v1.0 per le ragioni indicate. Candidati per v2.0.

| Tool | Condizione per Inclusione | Dominio | Note |
|---|---|---|---|
| **APIClarity** | Modalità pure black-box (target senza spec OpenAPI) | 0.1, 2.5 | Runtime traffic analysis |
| **mitmproxy2swagger** | Modalità pure black-box | 0.1 | Reverse-engineering spec |
| **Arjun** / **x8** | Modalità pure black-box | 0.1 | Parameter discovery senza spec |
| **ParamSpider** | Modalità pure black-box | 0.1 | Mining parametri da Wayback |
| **metlo** | Integrazione come sidecar | 0.1, 5.1 | Traffic-based discovery |
| **OWASP Noir** | Se si vuole includere approccio SAST con accesso al source | 0.1, 0.2, 0.3 | Richiede codice sorgente |
| **playwright** | Se il test 7.1 viene esteso per CAPTCHA simulation | 7.1 | Dipendenza browser completo |
| **graphql-cop** | Target GraphQL | 2.5, 4.1 | Fuori scope v1.0 (REST only) |
| **graphw00f**, **clairvoyance**, **BatchQL** | Target GraphQL | Domini vari | Fuori scope v1.0 |
| **grpcurl**, **ghz** | Target gRPC | Domini vari | Fuori scope v1.0 |
| **websocat**, **STEWS** | Target WebSocket | Domini vari | Fuori scope v1.0 |
| **RESTler-fuzzer** | Stateful fuzzing engine per BOLA complessi | 2.2, 7.1, 7.4 | Richiede C# runtime; troppo pesante per v1.0 |
| **http2smugl** | Target che espone HTTP/2 (promovibile da Cat B 6.3 a Cat A) | 6.3 | Già presente come Cat B; promozione condizionale |

---

## APPENDICE E — Matrice di Confidenza

Tool primari operativi per ogni test, ordinati per categoria.
**Versione 1.4** — allineata a `test_tool_decisions.md` v3.0.

Cambiamenti rispetto a v1.3:
- 0.1: kiterunner → ffuf (Cat A), rimosso da Cat B
- 1.2: jwtXploiter rimosso da Cat B
- 3.1: CRLFuzz rimosso da Cat A
- 6.3: smuggler rimosso da Cat A; Cat A ora usa Python raw sockets; http2smugl aggiunto Cat B
- 7.2: Gopherus rimosso da Cat B
- 7.3: race-the-web rimosso da Cat A; vegeta promosso a Cat A condiviso

| Test | Cat. A (Obbligatorio) | Cat. B (Facoltativo) | Classificazione Test |
|---|---|---|---|
| 0.1 | ffuf, katana, Nuclei | gau, cherrybomb | HYBRID |
| 0.2 | — | cherrybomb | NATIVE |
| 0.3 | — | oasdiff | NATIVE |
| 1.1 | — | — | NATIVE |
| 1.2 | jwt_tool | — | HYBRID |
| 1.3 | jwt_tool | — | HYBRID |
| 1.4 | — | — | NATIVE |
| 1.5 | testssl.sh | sslyze | HYBRID |
| 1.6 | — | — | NATIVE |
| 2.1 | — | — | NATIVE |
| 2.2 | — | OFFAT, cherrybomb | NATIVE |
| 2.3 | — | OFFAT | NATIVE |
| 2.4 | — | — | NATIVE |
| 2.5 | — | — | NATIVE |
| 3.1 | Schemathesis, Nuclei | sqlmap, NoSQLMap, Dalfox, commix, SSTImap | HYBRID |
| 3.3 | — | — | NATIVE |
| 4.1 | vegeta | — | HYBRID |
| 4.2 | — | — | NATIVE |
| 4.3 | — | — | NATIVE |
| 5.1 | — | — | NATIVE |
| 5.2 | — | — | NATIVE |
| 6.1 | — | — | NATIVE |
| 6.2 | — | — | NATIVE |
| 6.3 | — (Python raw sockets stdlib) | http2smugl | HYBRID |
| 6.4 | — | trufflehog, gitleaks, detect-secrets | NATIVE |
| 7.1 | — | — | NATIVE |
| 7.2 | Nuclei, interactsh | — | HYBRID |
| 7.3 | vegeta | — | HYBRID |
| 7.4 | interactsh | — | HYBRID |

---

## APPENDICE F — Fonti di Riferimento

| Fonte | Descrizione |
|---|---|
| **use.ai Sessione 1** | Prima analisi tool specializzati — identificazione gap Python |
| **use.ai Sessione 2** | Analisi estesa per dominio — multi-tool coverage |
| **use.ai Sessione 3 v2** | Tool 2024-2025, gap colmati, GraphQL/gRPC/WebSocket |
| **use.ai Sessione 3 v3** | Analisi definitiva maggio 2026 — tool emergenti, HTTP/2, K8s |
| **Gemini Deep Search** | Analisi architetturale approfondita — paradigmi DevSecOps |
| **Claude Analysis** | Mappa strategica Native vs Hybrid, decisioni architetturali |
| **Altri Tool** | Ricerca complementare su GitHub — endpoint discovery, schema fuzzing |

---

*Fine documento — Catalogo Tool APIGuard v1.3*
*Revisione v1.1: rimossi tool non verificabili (SSRFHunter Elite v3.0, Ice-Tea, Lonkero, QitOps CLI, openapi-security-scanner).*
*Revisione v1.2: tripartizione A/B/C applicata a ogni sezione di test. Tool Categoria C spostati in sotto-sezioni dedicate con motivazione esplicita dello scarto. Appendice A aggiornata con classificazione. Appendice E riscritta come matrice operativa post-tripartizione.*
*Revisione v1.3: 6 tool rimossi per abbandono/nessuna release (kiterunner, CRLFuzz, smuggler, race-the-web, jwtXploiter, Gopherus). ffuf e vegeta aggiornati a Cat A con copertura estesa. http2smugl aggiunto Cat B per 6.3. Appendice C aggiornata. Appendice E portata a v1.4.*
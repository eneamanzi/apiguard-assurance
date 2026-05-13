# APIGuard — Checklist Stato Implementazione

## Legenda Stati

| Simbolo | Significato |
|---------|-------------|
| `[TODO]` | Non ancora iniziato. |
| `[WIP]`  | In corso. |
| `[OK·C]` | Python **completo**, manca il Connector Cat A obbligatorio (test HYBRID non chiudibile senza). |
| `[OK]`   | Completato al 100%. |

**Legenda checkbox milestone:**

| Checkbox | Significato |
|----------|-------------|
| `[ ]` | Test non ancora avviato o incompleto. |
| `[~]` | Python completo. Test **NATIVE+OPT**: funziona già, il Cat B aggiungerebbe copertura ma non è bloccante. Può essere consegnato così. |
| `[x]` | Test **NATIVE** al 100%, oppure **HYBRID** con tutti i connector Cat A pronti. |

---

## MILESTONE 1 — Infrastruttura & No-Auth
*Test eseguibili senza autenticazione. Validano la pipeline end-to-end.*

- [ ] **0.1** `[HYBRID]` Shadow API Discovery `[OK·C]`
- [x] **1.1** `[NATIVE]` Auth Required `[OK]`
- [ ] **1.5** `[HYBRID]` Insecure Transport (TLS) `[OK·C]`
- [ ] **4.1** `[HYBRID]` Rate Limiting `[OK·C]`
- [ ] **7.2** `[HYBRID]` SSRF Prevention `[OK·C]`

## MILESTONE 2 — Identità & Hybrid Tooling
*Auth Abstraction Layer e integrazione tool specialistici.*

- [ ] **1.2** `[HYBRID]` JWT Cryptographic Validity `[TODO]`
- [ ] **1.3** `[HYBRID]` Credentials Not Expired `[TODO]`
- [ ] **3.1** `[HYBRID]` Input Validation (Injection) `[TODO]`
- [ ] **6.3** `[HYBRID]` Gateway Layer-7 Hardening `[TODO]`
- [ ] **7.3** `[HYBRID]` Race Condition `[TODO]`
- [ ] **7.4** `[HYBRID]` Unsafe Ext. Consumption `[TODO]`

## MILESTONE 3 — Business Logic, White Box & Hardening
*Audit configurazione Gateway e flussi applicativi complessi.*

- [~] **0.2** `[NATIVE+OPT]` Deny-by-Default `[OK]` *(cherrybomb Cat B disponibile)*
- [~] **0.3** `[NATIVE+OPT]` Deprecated API Enforcement `[OK]` *(oasdiff Cat B disponibile)*
- [ ] **1.4** `[NATIVE]` Token Revocation `[TODO]`
- [x] **1.6** `[NATIVE]` Session Management `[OK]`
- [ ] **2.1** `[NATIVE]` RBAC Endpoint Privilege `[TODO]`
- [ ] **2.2** `[NATIVE+OPT]` BOLA Prevention `[TODO]`
- [ ] **2.3** `[NATIVE+OPT]` Destructive Ops Privilege `[TODO]`
- [ ] **2.4** `[NATIVE]` Auth Policy Consistency `[TODO]`
- [ ] **2.5** `[NATIVE]` Excessive Data Exposure `[TODO]`
- [x] **3.3** `[NATIVE]` HMAC Config Audit `[OK]`
- [x] **4.2** `[NATIVE]` Timeout Config `[OK]`
- [x] **4.3** `[NATIVE]` Circuit Breaker `[OK]`
- [ ] **5.1** `[NATIVE]` Audit Logging `[TODO]` *(⚠ richiede log aggregator nel Docker setup)*
- [ ] **5.2** `[NATIVE]` Real-Time Alerts `[TODO]` *(⚠ richiede sistema di alerting configurato)*
- [ ] **6.1** `[NATIVE]` Error Handling `[TODO]`
- [x] **6.2** `[NATIVE]` Security Headers `[OK]`
- [~] **6.4** `[NATIVE+OPT]` Hardcoded Credentials `[OK]` *(trufflehog/gitleaks Cat B disponibili)*
- [ ] **7.1** `[NATIVE]` Anti-Automation `[TODO]`

---

## Riepilogo Connettori

### Categoria A — HYBRID (Bloccanti e Obbligatori)
*Senza di essi il test associato non produce evidenza valida.*

> **Changelog decisioni v2:**
> `kiterunner` rimosso (abbandonato) → `ffuf` promosso da Cat B.
> `crlfuzz` rimosso (abbandonato, inattivo dal 2021) → copertura CRLF delegata a template Nuclei `crlf-injection`.
> `smuggler` rimosso (nessuna release ufficiale) → sostituito da connector Python `raw sockets` per pattern CL.TE / TE.CL.
> `race-the-web` rimosso (abbandonato) → `vegeta` copre sia 4.1 (volume) che 7.3 (last-byte sync).
> `jwtXploiter` rimosso (5 anni senza manutenzione) → `jwt_tool` copre già le stesse varianti.
> `Gopherus` rimosso (abbandonato) → copertura payload Gopher delegata a template Nuclei categoria `ssrf`.

| Connector | Versione Pinnata | Tipo | Test Impattati | Motivazione presenza in Cat A |
|---|---|---|---|---|
| **nuclei** | `3.8.0` | Subprocess | 0.1, 3.1, 7.2 | Template vulnerability engine, aggiornamenti community. Copre anche CRLF (ex-crlfuzz) e payload Gopher SSRF (ex-Gopherus). |
| **interactsh** | `1.3.1` | Subprocess | 7.2, 7.4 | Server OOB per SSRF blind — non sostituibile con Python puro. |
| **jwt_tool** | `2.3.0` | Subprocess | 1.2, 1.3 | 15+ attacchi CVE-specific (kid SQL, Psychic Sig ECDSA, alg:none); flag `--exp` per claim arbitrari su 1.3. Copre il perimetro di ex-jwtXploiter. |
| **ffuf** | `2.1.0` | Subprocess | 0.1 | Wordlist API 30k+ path (SecLists `API-endpoints.txt`); output JSON nativo `-of json`; negoziazione metodi REST. **Promosso da Cat B** in sostituzione di kiterunner. |
| **katana** | `1.6.1` | Subprocess | 0.1 | Crawling headless e parsing AST bundle JavaScript; scopre endpoint dinamici non raggiungibili da wordlist statiche. |
| **testssl.sh** | `3.2.3` | Subprocess | 1.5 | Analisi TLS completa (20+ CVE, cipher suite, Certificate Transparency). Output JSON strutturato via `--jsonfile`. |
| **schemathesis** | `4.18.1` | Library | 3.1 | Property-based fuzzing da schema OpenAPI (Hypothesis engine). Genera automaticamente casi limite da vincoli di schema. |
| **vegeta** | `12.13.0` | Subprocess | 4.1, 7.3 | Rate generation preciso in Go; elimina il GIL jitter di Python sotto carico. `--max-connections` + `-rate=0` abilita last-byte sync per race condition (7.3). **Sostituisce race-the-web**. |

> **Nota connector 3.1 — copertura CRLF:** crlfuzz operava a livello raw socket bypassando la normalizzazione RFC 7230 applicata da `httpx`. I template Nuclei `crlf-injection` usano lo stesso approccio raw TCP e producono evidenza equivalente. **Pre-requisito:** verificare la presenza del tag `crlf-injection` nel bundle `nuclei-templates 10.4.3` prima dell'esecuzione del test 3.1.

> **Nota connector 6.3 — HTTP Request Smuggling:** il connector per il test 6.3 è implementato interamente in Python con `socket` della stdlib per i pattern **CL.TE** e **TE.CL** classici (RFC 9110 §9.3.3). Non dipende da binari esterni. Questo approccio ha valore dimostrativo diretto nella tesi: il codice del connector rende leggibile il meccanismo dell'attacco. `http2smugl` è disponibile in Cat B come estensione per coprire i pattern H2 downgrade smuggling qualora il target esponga HTTP/2.

> **Nota connector 7.2 — copertura Gopher SSRF:** i template Nuclei nella categoria `ssrf` e `network` della versione pinnata coprono SSRF verso Redis, MySQL e SMTP tramite payload Gopher. **Pre-requisito:** verificare la presenza di template `ssrf-via-gopher-*` nel bundle `nuclei-templates 10.4.3` prima dell'esecuzione del test 7.2.

> **Nota connector 7.3 — race condition con vegeta:** `vegeta` con flag `-rate=0 -max-workers=N` lancia N goroutine in parallelo con sincronizzazione last-byte. L'output JSON include `status_codes`, `latencies` e `bytes_in`; il connector analizza le response anomale (es. doppio 200 su operazione che dovrebbe consentirne uno solo) per rilevare race condition su inventory e withdrawal.

---

### Categoria B — Opzionali (Estensioni per Test NATIVE)
*Il test funziona già. Il connector espande la superficie di rilevamento.*

| Connector | Versione | Stato | Tipo | Test Impattati | Valore aggiunto |
|---|---|---|---|---|---|
| **cherrybomb** | `1.0.1` | `[TODO]` | Subprocess | 0.2, 2.2 | SAST su OpenAPI spec (analisi statica pre-fuzzing). Ultimo commit 2 anni fa: valutare stabilità prima dell'integrazione. |
| **OFFAT** | `0.19.4` | `[TODO]` | Subprocess | 2.2, 2.3 | Generazione automatica test IDOR/DELETE da spec OpenAPI. Preferibile a cherrybomb per i test di autorizzazione. |
| **oasdiff** | `1.15.3` | `[TODO]` | Subprocess | 0.3 | Diff semantico tra versioni spec; gestisce edge case `$ref` / `allOf` non coperti dal parser interno. |
| **trufflehog** | `3.95.2` | `[TODO]` | Subprocess | 6.4 | 800+ regex secret pattern mantenute dalla community. |
| **gitleaks** | `8.30.1` | `[TODO]` | Subprocess | 6.4 | Scansione commit history — angolazione versionamento. |
| **detect-secrets** | `1.5.0` | `[TODO]` | Library | 6.4 | Plugin architecture; integrabile come pre-commit hook. |
| **gau** | `2.2.4` | `[TODO]` | Subprocess | 0.1 | Mining storico passivo di URL (Wayback Machine, Common Crawl). Complementare a ffuf per endpoint non più in produzione ma ancora raggiungibili. |
| **sslyze** | `6.3.1` | `[TODO]` | Library | 1.5 | Fallback Python puro a testssl.sh; zero dipendenze binarie. Utile in ambienti dove testssl.sh non è installabile. |
| **http2smugl** | latest stable | `[TODO]` | Subprocess | 6.3 | Copertura HTTP/2 downgrade smuggling. Promovibile a Cat A se il target espone H2. |

---

## DAG di Esecuzione a Runtime

| Fase | Test |
|------|------|
| **A — No Dipendenze** | 0.1, 0.2, 0.3, 1.1, 1.5, 1.6, 3.3, 4.1, 4.2, 4.3, 6.2, 6.4, 7.2 |
| **B — Auth (requires 1.1)** | 1.2, 1.3, 1.4, 5.2, 6.3 |
| **C — Multi-Stato (requires 1.2)** | 2.1, 2.2, 2.3, 2.4, 2.5, 3.1, 5.1, 6.1, 7.1, 7.3, 7.4 |

---

## Dettaglio per Dominio

### DOMINIO 0 — API Discovery
| ID | Strategy | Test Name | Milestone | Task Attivi |
|---|---|---|---|---|
| 0.1 | HYBRID | Shadow API Discovery | **1** | `test_0_1_shadow_api.py` → Connector Cat A: `ffuf` (ex-kiterunner), `katana`, `nuclei` |
| 0.2 | NATIVE+OPT | Deny-by-Default | **3** | `test_0_2_deny_by_default.py` → Connector Cat B: `cherrybomb` |
| 0.3 | NATIVE+OPT | Deprecated API Enforcement | **3** | `test_0_3_deprecated_api.py` → Connector Cat B: `oasdiff` |

### DOMINIO 1 — Identità e Autenticazione
| ID | Strategy | Test Name | Milestone | Task Attivi |
|---|---|---|---|---|
| 1.1 | NATIVE | Auth Required | **1** | `test_1_1_auth_required.py` |
| 1.2 | HYBRID | JWT Cryptographic Validity | **2** | `ext_test_1_2_jwt_validity.py` → Connector Cat A: `jwt_tool` |
| 1.3 | HYBRID | Credentials Not Expired | **2** | `ext_test_1_3_jwt_expiry.py` → Connector Cat A: `jwt_tool` (istanza condivisa con 1.2) |
| 1.4 | NATIVE | Token Revocation | **3** | `test_1_4_token_revocation.py` |
| 1.5 | HYBRID | Insecure Transport (TLS) | **1** | `ext_test_1_5_tls_analysis.py` → Connector Cat A: `testssl.sh`; Cat B fallback: `sslyze` |
| 1.6 | NATIVE | Session Management | **3** | `test_1_6_session_mgmt.py` |

### DOMINIO 2 — Autorizzazione e Controllo Accessi
| ID | Strategy | Test Name | Milestone | Task Attivi |
|---|---|---|---|---|
| 2.1 | NATIVE | RBAC Endpoint Privilege | **3** | `test_2_1_rbac_privilege.py` |
| 2.2 | NATIVE+OPT | BOLA Prevention | **3** | `test_2_2_bola_prevention.py` → Connector Cat B: `OFFAT`, `cherrybomb` |
| 2.3 | NATIVE+OPT | Destructive Ops Privilege | **3** | `test_2_3_destructive_ops.py` → Connector Cat B: `OFFAT` |
| 2.4 | NATIVE | Auth Policy Consistency | **3** | `test_2_4_policy_consistency.py` |
| 2.5 | NATIVE | Excessive Data Exposure | **3** | `test_2_5_data_exposure.py` |

### DOMINIO 3 — Integrità dei Dati
| ID | Strategy | Test Name | Milestone | Task Attivi |
|---|---|---|---|---|
| 3.1 | HYBRID | Input Validation (Injection) | **2** | `ext_test_3_1_injection.py` → Connector Cat A: `schemathesis`, `nuclei` (CRLF via template `crlf-injection`; crlfuzz rimosso — vedi nota) |
| 3.3 | NATIVE | HMAC Config Audit | **3** | `test_3_3_hmac_config.py` |

### DOMINIO 4 — Disponibilità e Resilienza
| ID | Strategy | Test Name | Milestone | Task Attivi |
|---|---|---|---|---|
| 4.1 | HYBRID | Rate Limiting | **1** | `test_4_1_rate_limiting.py` → Connector Cat A: `vegeta` |
| 4.2 | NATIVE | Timeout Config | **3** | `test_4_2_timeout_config.py` → usa `target.gateway` (`BaseGatewayAdapter`) |
| 4.3 | NATIVE | Circuit Breaker | **3** | `test_4_3_circuit_breaker.py` → usa `target.gateway` (`BaseGatewayAdapter`) |

### DOMINIO 5 — Visibilità e Auditing
| ID | Strategy | Test Name | Milestone | Task Attivi |
|---|---|---|---|---|
| 5.1 | NATIVE | Audit Logging | **3** | `test_5_1_audit_logging.py` ⚠ richiede log aggregator nel Docker setup |
| 5.2 | NATIVE | Real-Time Alerts | **3** | `test_5_2_alerts.py` ⚠ richiede sistema di alerting configurato |

### DOMINIO 6 — Configurazione e Hardening
| ID | Strategy | Test Name | Milestone | Task Attivi |
|---|---|---|---|---|
| 6.1 | NATIVE | Error Handling | **3** | `test_6_1_error_handling.py` |
| 6.2 | NATIVE | Security Headers | **3** | `test_6_2_security_headers.py` |
| 6.3 | HYBRID | Gateway Layer-7 Hardening | **2** | `ext_test_6_3_smuggling.py` → Connector: Python `raw sockets` stdlib (CL.TE / TE.CL); Cat B: `http2smugl` per H2 |
| 6.4 | NATIVE+OPT | Hardcoded Credentials | **3** | `test_6_4_hardcoded_creds.py` → Connector Cat B: `trufflehog`, `gitleaks`, `detect-secrets` |

### DOMINIO 7 — Business Logic e Flussi Sensibili
| ID | Strategy | Test Name | Milestone | Task Attivi |
|---|---|---|---|---|
| 7.1 | NATIVE | Anti-Automation | **3** | `test_7_1_anti_automation.py` |
| 7.2 | HYBRID | SSRF Prevention | **1** | `test_7_2_ssrf_prevention.py` → Connector Cat A: `nuclei` (incl. Gopher via template; Gopherus rimosso), `interactsh` |
| 7.3 | HYBRID | Race Condition | **2** | `ext_test_7_3_race_condition.py` → Connector Cat A: `vegeta` (istanza condivisa con 4.1; race-the-web rimosso) |
| 7.4 | HYBRID | Unsafe Ext. Consumption | **2** | `ext_test_7_4_unsafe_consumption.py` → Connector Cat A: `interactsh` |
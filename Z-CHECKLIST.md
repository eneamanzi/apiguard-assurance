# APIGuard — Checklist Stato Implementazione

## Legenda Stati

| Simbolo | Significato |
|---------|-------------|
| `[TODO]` | Non ancora iniziato. |
| `[WIP]`  | In corso (es. refactor `BaseGatewayInspector` pendente). |
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
- [x] **4.2** `[NATIVE]` Timeout Config `[OK]` *(WIP: refactor a `BaseGatewayInspector`)*
- [x] **4.3** `[NATIVE]` Circuit Breaker `[OK]` *(WIP: refactor a `BaseGatewayInspector`)*
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

| Connector | Stato | Tipo | Test Impattati | Limite Python superato |
|---|---|---|---|---|
| **nuclei** | `[TODO]` | Subprocess | 0.1, 3.1, 7.2 | Template vulnerability engine, aggiornamenti community. |
| **interactsh** | `[TODO]` | Subprocess | 7.2, 7.4 | Server OOB per SSRF blind — non sostituibile con Python. |
| **jwt_tool** | `[TODO]` | Subprocess | 1.2, 1.3 | 15+ attacchi CVE-specific (kid SQL, Psychic Sig ECDSA); flag `--exp` per claim arbitrari su 1.3. |
| **kiterunner** | `[TODO]` | Subprocess | 0.1 | Wordlist 30k+ path API reali; negoziazione metodi RESTful. |
| **katana** | `[TODO]` | Subprocess | 0.1 | Crawling headless e parsing AST bundle JavaScript. |
| **testssl.sh** | `[TODO]` | Subprocess | 1.5 | Analisi TLS completa (20+ CVE, cipher suite, CT). |
| **schemathesis** | `[TODO]` | Library | 3.1 | Property-based fuzzing da schema OpenAPI (Hypothesis engine). |
| **crlfuzz** | `[TODO]` | Subprocess | 3.1 | CRLF injection via socket raw — `httpx` sanitizza gli header per RFC. |
| **vegeta** | `[TODO]` | Subprocess | 4.1 | Rate generation preciso Go; elimina GIL jitter Python. |
| **smuggler** | `[TODO]` | Library | 6.3 | HTTP Request Smuggling — `httpx` forza conformità RFC 9110. |
| **race-the-web** | `[TODO]` | Subprocess | 7.3 | Last-byte synchronization Go goroutine vs jitter asyncio. |

### Categoria B — Opzionali (Estensioni per Test NATIVE)
*Il test funziona già. Il connector espande la superficie di rilevamento.*

| Connector | Stato | Tipo | Test Impattati | Valore aggiunto |
|---|---|---|---|---|
| **cherrybomb** | `[TODO]` | Subprocess | 0.2, 2.2 | SAST su OpenAPI spec (analisi statica pre-fuzzing). |
| **OFFAT** | `[TODO]` | Subprocess | 2.2, 2.3 | Generazione automatica test IDOR/DELETE da spec OpenAPI. |
| **oasdiff** | `[TODO]` | Subprocess | 0.3 | Diff tra versioni spec, edge case `$ref` / `allOf`. |
| **trufflehog** | `[TODO]` | Subprocess | 6.4 | 800+ regex secret pattern mantenute dalla community. |
| **gitleaks** | `[TODO]` | Subprocess | 6.4 | Scansione commit history — angolazione versionamento. |
| **detect-secrets** | `[TODO]` | Library | 6.4 | Plugin architecture, integrabile come pre-commit. |
| **ffuf / gau** | `[TODO]` | Subprocess | 0.1 | Fallback discovery generico e mining storico passivo. |
| **sslyze** | `[TODO]` | Library | 1.5 | Fallback Python puro a testssl.sh, zero binary deps. |
| **jwtXploiter** | `[TODO]` | Subprocess | 1.2 | Varianti kid injection non coperte da jwt_tool. |
| **Gopherus** | `[TODO]` | Subprocess | 7.2 | Payload Gopher per servizi interni (Redis, MySQL, SMTP). |

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
| 0.1 | HYBRID | Shadow API Discovery | **1** | `test_0_1_shadow_api.py` → Connector: `kiterunner`, `katana`, `nuclei` |
| 0.2 | NATIVE+OPT | Deny-by-Default | **3** | `test_0_2_deny_by_default.py` → Connector: `cherrybomb` (OPT) |
| 0.3 | NATIVE+OPT | Deprecated API Enforcement | **3** | `test_0_3_deprecated_api.py` → Connector: `oasdiff` (OPT) |

### DOMINIO 1 — Identità e Autenticazione
| ID | Strategy | Test Name | Milestone | Task Attivi |
|---|---|---|---|---|
| 1.1 | NATIVE | Auth Required | **1** | `test_1_1_auth_required.py` |
| 1.2 | HYBRID | JWT Cryptographic Validity | **2** | `ext_test_1_2_jwt_validity.py` → Connector: `jwt_tool` |
| 1.3 | HYBRID | Credentials Not Expired | **2** | `ext_test_1_3_jwt_expiry.py` → Connector: `jwt_tool` (shared) |
| 1.4 | NATIVE | Token Revocation | **3** | `test_1_4_token_revocation.py` |
| 1.5 | HYBRID | Insecure Transport (TLS) | **1** | `ext_test_1_5_tls_analysis.py` → Connector: `testssl.sh` |
| 1.6 | NATIVE | Session Management | **3** | `test_1_6_session_mgmt.py` |

### DOMINIO 2 — Autorizzazione e Controllo Accessi
| ID | Strategy | Test Name | Milestone | Task Attivi |
|---|---|---|---|---|
| 2.1 | NATIVE | RBAC Endpoint Privilege | **3** | `test_2_1_rbac_privilege.py` |
| 2.2 | NATIVE+OPT | BOLA Prevention | **3** | `test_2_2_bola_prevention.py` → Connector: `OFFAT`, `cherrybomb` (OPT) |
| 2.3 | NATIVE+OPT | Destructive Ops Privilege | **3** | `test_2_3_destructive_ops.py` → Connector: `OFFAT` (OPT) |
| 2.4 | NATIVE | Auth Policy Consistency | **3** | `test_2_4_policy_consistency.py` |
| 2.5 | NATIVE | Excessive Data Exposure | **3** | `test_2_5_data_exposure.py` |

### DOMINIO 3 — Integrità dei Dati
| ID | Strategy | Test Name | Milestone | Task Attivi |
|---|---|---|---|---|
| 3.1 | HYBRID | Input Validation (Injection) | **2** | `ext_test_3_1_injection.py` → Connector: `schemathesis`, `crlfuzz`, `nuclei` |
| 3.3 | NATIVE | HMAC Config Audit | **3** | `test_3_3_hmac_config.py` |

### DOMINIO 4 — Disponibilità e Resilienza
| ID | Strategy | Test Name | Milestone | Task Attivi |
|---|---|---|---|---|
| 4.1 | HYBRID | Rate Limiting | **1** | `test_4_1_rate_limiting.py` → Connector: `vegeta` |
| 4.2 | NATIVE | Timeout Config | **3** | `test_4_2_timeout_config.py` → Pendente: refactor `BaseGatewayInspector` |
| 4.3 | NATIVE | Circuit Breaker | **3** | `test_4_3_circuit_breaker.py` → Pendente: refactor `BaseGatewayInspector` |

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
| 6.3 | HYBRID | Gateway Layer-7 Hardening | **2** | `ext_test_6_3_smuggling.py` → Connector: `smuggler` |
| 6.4 | NATIVE+OPT | Hardcoded Credentials | **3** | `test_6_4_hardcoded_creds.py` → Connector: `trufflehog`, `gitleaks` (OPT) |

### DOMINIO 7 — Business Logic e Flussi Sensibili
| ID | Strategy | Test Name | Milestone | Task Attivi |
|---|---|---|---|---|
| 7.1 | NATIVE | Anti-Automation | **3** | `test_7_1_anti_automation.py` |
| 7.2 | HYBRID | SSRF Prevention | **1** | `test_7_2_ssrf_prevention.py` → Connector: `nuclei`, `interactsh` |
| 7.3 | HYBRID | Race Condition | **2** | `ext_test_7_3_race_condition.py` → Connector: `race_the_web` |
| 7.4 | HYBRID | Unsafe Ext. Consumption | **2** | `ext_test_7_4_unsafe_consumption.py` → Connector: `interactsh` |
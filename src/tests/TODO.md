ATTUALMENTE TEST 1.1

In qualche mododo aggigunere alal config un paraemtro che permette di passare gli id dei test che si vogloo eseguire, se quel parametro è attivo si eseguono solo quelli (forse ha senso?)


**Domain 1 — Identity & Authentication (6 test)**

- `test_1_1_authentication_required.py` — P0, BLACK_BOX. Verifica che ogni endpoint protetto restituisca 401 senza token. Nessun prerequisito. È il test che popola la base del `TestContext` confermando che l'autenticazione esiste.
- `test_1_2_jwt_signature_validation.py` — P0, GREY_BOX. Attacchi `alg:none`, payload manomesso, key confusion RS256→HS256, signature stripping. Richiede un JWT valido ottenuto via Forgejo `/api/v1/users/token` con Basic Auth.
- `test_1_3_token_expiry.py` — P0, GREY_BOX. Token con `exp` nel passato deve restituire 401. Richiede capacità di costruire JWT con claim arbitrari.
- `test_1_4_token_revocation.py` — P1, GREY_BOX. Login → logout (`DELETE /api/v1/user/keys/{id}` o equivalente) → riuso del token deve dare 401.
- `test_1_5_tls_enforcement.py` — P2, WHITE_BOX. Verifica redirect HTTP→HTTPS e header HSTS. Nel nostro ambiente HTTP-only, questo test è un SKIP documentato.
- `test_1_6_session_management.py` — P3, WHITE_BOX. Audit configurazione session store via Kong Admin API.

**Domain 2 — Authorization (5 test)**

- `test_2_1_rbac_enforcement.py` — P1, GREY_BOX. Token user tenta endpoint admin. Dipende da `1.1` e `1.2`.
- `test_2_2_bola_prevention.py` — P1, GREY_BOX. user_a accede a risorse di user_b tramite ID. Richiede risorse create su entrambi gli account.
- `test_2_3_destructive_operations_privilege.py` — P1, GREY_BOX.
- `test_2_4_authorization_consistency.py` — P1, GREY_BOX.
- `test_2_5_excessive_data_exposure.py` — P2, GREY_BOX.

**Domain 3 — Data Integrity (2 test)**

- `test_3_1_input_validation.py` — P2, GREY_BOX. SQL injection, NoSQL injection, type confusion, oversized payloads.
- `test_3_3_data_in_transit.py` — P3, WHITE_BOX. HMAC/signing audit.

**Domain 4 — Availability (3 test)**

- `test_4_1_rate_limiting.py` — P0, BLACK_BOX. Loop empirico fino a 429. Usa `config.rate_limit_probe.*`.
- `test_4_2_timeout_enforcement.py` — P1, WHITE_BOX. Audit `kong.yml` valori timeout.
- `test_4_3_circuit_breaker.py` — P1, WHITE_BOX. Audit Kong Admin API per plugin circuit-breaker.

**Domain 5 — Visibility (2 test)**

- `test_5_1_audit_logging.py` — P1, GREY_BOX. Verifica che le richieste compaiano nei log Kong (`/dev/stdout`).
- `test_5_2_security_alerting.py` — P2, GREY_BOX. Brute-force simulato e verifica alert.

**Domain 6 — Hardening (4 test)**

- `test_6_1_error_handling.py` — P2, GREY_BOX. Stack trace assenti nelle risposte di errore.
- `test_6_2_security_headers.py` — P3, WHITE_BOX. HSTS, CSP, X-Frame-Options.
- `test_6_3_layer7_hardening.py` — P1, GREY_BOX + WHITE_BOX. HTTP smuggling CL.TE, CORS wildcard.
- `test_6_4_hardcoded_credentials.py` — P2, WHITE_BOX. Audit `kong.yml` e env vars.

**Domain 7 — Business Logic (4 test)**

- `test_7_1_business_flow_abuse.py` — P2, GREY_BOX.
- `test_7_2_ssrf_prevention.py` — P0, BLACK_BOX. Payload `169.254.169.254`, IPv6, encoding bypass.
- `test_7_3_idempotency.py` — P2, GREY_BOX. Race condition su operazioni critiche.
- `test_7_4_external_api_consumption.py` — P2, GREY_BOX. Webhook signature verification.

### Infrastruttura di Test

- **Helper di autenticazione** — Funzione condivisa (probabilmente in `BaseTest` o in un modulo `src/tests/helpers/auth.py`) che esegue il login Forgejo via `/api/v1/users/search` + Basic Auth e popola `TestContext` con i token JWT. Tutti i test GREY_BOX dipenderanno da questo.
- **Forgejo test data setup** — Script `scripts/setup_test_data.py` che crea repository e contenuti su user_a e user_b prima dell'assessment, necessari per i test BOLA (Domain 2).
- **Suite E2E per i domain test** — `tests_e2e/test_02_domain_0_full.py`, `tests_e2e/test_03_domain_1_auth.py` ecc. che eseguono i test reali contro Forgejo/Kong verificando sia il risultato (`PASS`/`FAIL`) sia la struttura dell'evidenza.


### Report
- **Integrazione test di regressione per basePath** — Aggiungere al `REFERENCE_SPEC` di `tests_integration/conftest.py` un fixture Swagger 2.0 con `basePath` per coprire con test di integrazione la funzione `_resolve_absolute_path`.



| Test | `depends_on` |
|------|-------------|
| `0.1` | `[]` |
| `0.2` | `[]` |
| `0.3` | `[]` |
| `1.1` | `[]` |
| `1.2` | `["1.1"]` |
| `1.3` | `["1.1", "1.2"]` |
| `1.4` | `["1.1", "1.2"]` |
| `1.5` | `[]` |
| `1.6` | `[]` |
| `2.1` | `["1.1", "1.2"]` |
| `2.2` | `["1.1", "1.2"]` |
| `2.3` | `["1.1", "1.2", "2.1"]` |
| `2.4` | `["1.1", "1.2", "2.1"]` |
| `2.5` | `["1.1", "1.2"]` |
| `3.1` | `["1.1", "1.2"]` |
| `3.3` | `[]` |
| `4.1` | `[]` |
| `4.2` | `[]` |
| `4.3` | `[]` |
| `5.1` | `["1.1", "1.2"]` |
| `5.2` | `["1.1", "5.1"]` |
| `6.1` | `["1.1", "1.2"]` |
| `6.2` | `[]` |
| `6.3` | `["1.1"]` |
| `6.4` | `[]` |
| `7.1` | `["1.1", "1.2"]` |
| `7.2` | `[]` |
| `7.3` | `["1.1", "1.2"]` |
| `7.4` | `["1.1", "1.2"]` |




Bene. Ora possiamo fare questa analisi con precisione, perché sappiamo esattamente quali test usano cosa e in che ordine.

---

## Approccio: seguiamo l'ordine di esecuzione

Anziché proporre helper in astratto, percorriamo i batch del DAG e annodiamo cosa serve dove.

---

### Batch 1 — nessuna dipendenza

`0.1`, `0.2`, `0.3` lavorano sulla spec OpenAPI e fanno fuzzing su path — tutto inline, nessun helper condiviso necessario.

`1.1` manda richieste senza token — inline, zero stato.

`4.1` fa un loop empirico fino al `429` — inline, è un semplice ciclo `for` con `time.sleep`.

`7.2` manda payload SSRF — ha bisogno di un catalogo di URL. Usato da **un solo test**. La domanda è se vale un file separato.

`1.5`, `1.6`, `3.3`, `4.2`, `4.3`, `6.2`, `6.4` sono WHITE_BOX audit. `4.2`, `4.3`, `6.4` interrogano la Kong Admin API. Usati da **tre/quattro test**. Vale sicuramente un helper.

---

### Batch 2 — dipende da `1.1`

`1.2` è il test più complesso del progetto. Fa due cose:

1. Acquisisce i token tramite login su Forgejo e li scrive nel `TestContext` — logica non banale, usata **una sola volta** ma sufficientemente complessa da meritare separazione.
2. Forgia JWT malformati (`alg:none`, payload manomesso, signature stripping) — usato anche da `1.3`.

`5.2` simula brute-force sull'endpoint di login — inline, è un loop sequenziale.

`6.3` testa HTTP smuggling e CORS — inline, le request sono costruite ad hoc.

---

### Batch 3 — dipende da `1.1` + `1.2`

`2.2`, `2.3`, `7.3` creano risorse Forgejo (repository, issue) dentro `execute()` e le registrano per il teardown. Stesso pattern ripetuto tre volte — helper condiviso.

`2.5`, `6.1`, `6.2` analizzano i campi della response o gli header cercando pattern specifici (stack trace, campi sensibili, header di sicurezza). Pattern ripetuto — helper condiviso.

`3.1` costruisce payload di injection (SQL, NoSQL, type confusion) — usato da **un solo test**.

`1.3` forgia JWT con `exp` nel passato — riusa la logica di forge di `1.2`.

---

## Mappa definitiva degli helper

| Helper | Usato da | Giustificazione |
|--------|----------|-----------------|
| `helpers/auth.py` | `1.2` | Logica di login Forgejo, gestione token opachi vs JWT, scrittura nel `TestContext` — troppo complessa per stare inline |
| `helpers/jwt_forge.py` | `1.2`, `1.3` | Condiviso tra due test dello stesso dominio |
| `helpers/forgejo_resources.py` | `2.2`, `2.3`, `7.3` | Stesso pattern CRUD + teardown ripetuto in tre test di domini diversi |
| `helpers/kong_admin.py` | `4.2`, `4.3`, `6.4`, (1.6) | Stesso client HTTP verso Admin API usato da quattro test |
| `helpers/response_inspector.py` | `2.5`, `6.1`, `6.2` | Pattern di analisi body/header ripetuto in tre test di domini diversi |

## I due casi dubbi: payload catalogues

`ssrf_payloads.py` → usato solo da `7.2`.
`injection_payloads.py` → usato solo da `3.1`.

**Argomento per tenerli separati:** i payload sono dati di test, non logica. Separarli tiene il file del test focalizzato sul flusso e rende i payload facili da estendere senza toccare la logica. È lo stesso principio per cui le wordlist di `0.1` sono una costante nel file del test, non inline nel loop.



### Roadmap implementativa basata sul DAG

Partendo dalla tabella delle dipendenze, i test si sviluppano in questo ordine naturale:

**Fase A — Batch 1 completo (tutti i test senza dipendenze)**

```
0.1 → 0.2 → 0.3   # Domain 0, già presenti nel repo
1.1               # primo test da implementare nel Domain 1
4.1               # rate limiting, BLACK_BOX
7.2               # SSRF, BLACK_BOX — usa data/ssrf_payloads.py
1.5, 1.6          # WHITE_BOX audit TLS e session store
3.3               # WHITE_BOX HMAC audit
4.2, 4.3          # WHITE_BOX Kong timeout e circuit breaker — usa kong_admin.py
6.2, 6.4          # WHITE_BOX header e hardcoded credentials
```

**Fase B — Sblocca il resto (dipende da `1.1` e `1.2`)**

```
1.2               # GREY_BOX — usa auth.py + jwt_forge.py, pivot dell'intero DAG
1.3, 1.4          # completamento Domain 1 — usa jwt_forge.py
5.2, 6.3          # dipendono solo da 1.1
```

**Fase C — Domain 2 e il resto dei GREY_BOX (dipendono da `1.2`)**

```
2.1               # RBAC base
2.2, 2.3, 2.4, 2.5  # BOLA, destructive ops, consistency, exposure — usano forgejo_resources.py
3.1               # injection — usa data/injection_payloads.py
5.1               # audit logging
6.1               # error handling — usa response_inspector.py
7.1, 7.3, 7.4     # business logic, race condition, webhook
```

L'ordine all'interno di ogni fase non è vincolato dal DAG — possiamo scegliere il test più semplice da fare come primo in ogni fase per validare l'infrastruttura prima di affrontare quelli complessi. Suggerisco di iniziare con `1.1` e `4.1` (i più diretti) per confermare che l'intera pipeline test→result→evidence funziona end-to-end prima di affrontare `1.2` che è il test pivot.

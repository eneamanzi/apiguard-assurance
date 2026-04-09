## Lista TODO — Lavori Restanti

### Implementazione Sicurezza (il corpo della tesi)

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

### Modello Dati

- **`Finding.severity`** — Campo da aggiungere al modello `Finding` in `models.py` (`CRITICAL | HIGH | MEDIUM | LOW | INFO`). Attualmente assente nonostante `Implementazione.md` Section 7 lo preveda per il calcolo dell'exit code basato su severity. Exit code attuale: basato su FAIL/ERROR. Exit code spec: basato su severity massima dei finding (CRITICAL→1, HIGH→2, MEDIUM→3).
- **`ResultSet.compute_exit_code()`** — Aggiornare per usare la severity dei Finding quando il campo sarà presente.

### Report

- **Sezione severity nel report HTML** — Aggiornare `report/builder.py` e il template per mostrare la distribuzione di severity dei finding (non solo PASS/FAIL/SKIP/ERROR).
- **Integrazione test di regressione per basePath** — Aggiungere al `REFERENCE_SPEC` di `tests_integration/conftest.py` un fixture Swagger 2.0 con `basePath` per coprire con test di integrazione la funzione `_resolve_absolute_path`.
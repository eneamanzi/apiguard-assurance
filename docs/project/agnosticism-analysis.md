# Agnosticism Analysis

> **Audience:** project owner, Claude Code · **Status:** step 1 of block 7+8 (analysis, no code), written
> 2026-10-10 · **Source of truth:** the code at the lines cited; the only run on a second target is the cRAPI run of
> 2026-10-06 (no gateway, recorded in Q-18) · Working file: decisions go to `OPEN_QUESTIONS.md` (Q-43, Q-38, Q-34,
> Q-18) and `plan.md`.

Goal: an integrator points the tool at **their** API behind **their** gateway with an OpenAPI specification and
`config.yaml`, and every test either gives a correct verdict or says why it cannot (SKIP with the reason). This page
lists everything that stands in the way today: what is tied to Forgejo or Kong, and the hidden assumptions about how
any target behaves. It decides nothing; step 2 decides one point at a time.

**Method.** Every test module, helper, the gateway adapter, the engine and the configuration schema were read, not
only searched for the words Forgejo and Kong. Each item states its source and what happens on another target.
"Observed" means seen in the cRAPI run of 2026-10-06; "from the code" means read in the code, not yet run.

What can happen on another target, from best to worst:

| Outcome | Meaning |
|---|---|
| works | the test gives a correct verdict |
| configurable | works after setting a parameter the integrator must know about |
| SKIP / ERROR | the test says it cannot run; no false verdict, but nothing is verified |
| **false verdict** | a PASS or FAIL that does not reflect the target: the worst case, it is silent |

## 1. Tool infrastructure

| # | Item | Source | Tie | On another target |
|---|---|---|---|---|
| I-1 | Only one gateway adapter, chosen by a fixed `if` | `src/engine.py:576`; schema accepts only `"kong"` (`src/config/schema/tool_config.py:329`) | Kong, code | another gateway: no adapter, the configuration audits SKIP |
| I-2 | The adapter interface is shaped on Kong concepts and returns Kong's raw objects: `get_routes`, `get_plugins`, `get_services`, `get_upstreams`, `get_status`, `get_plugin_by_name` (Q-38) | `src/core/gateway/base.py:137-217` | Kong, design | a second adapter would have to imitate Kong's JSON for the tests to understand it |
| I-3 | The Admin API is called without credentials and with certificate verification always on (Q-34) | `src/core/gateway/kong.py:305` | gateway setup | a protected Admin API: the audits return ERROR |
| I-4 | `credentials.auth_type` defaults to `forgejo_token` (Forgejo token API with Basic Auth) | `src/config/schema/tool_config.py:387`; again in `src/core/models/runtime.py:44` (a second definition of the same field) | Forgejo, default | a target without the setting: every login fails, the tests that log in return ERROR |
| I-5 | Login implementations: `forgejo_token` and `jwt_login` (generic: POST of username and password as JSON, token read at a dotted path) | `src/tests/helpers/auth.py:93`, `auth_jwt_login.py` | generic option exists | APIs that log in differently (form body, OAuth2 client credentials, API keys issued out of band, cookies) are not covered |
| I-6 | Forgejo resource helpers (repository, issue, current user) used by 1.4 and 7.2 | `src/tests/helpers/forgejo_resources.py:68-73` | Forgejo, code | not usable elsewhere |
| I-7 | the configuration files are the labs' (`path_seed` names, `http_probe_url`, Admin API URL) | `test-environments/forgejo-kong/config.yaml`, `test-environments/crapi-kong/config.yaml` (moved there on 2026-10-10, were `config.yaml` and `config_crapi.yaml` at the root) | lab values | expected: an integrator writes their own; a neutral template is planned |

Already neutral: the teardown (each test registers method, path and headers of its own DELETE, `src/engine.py`
Phase 6), the OpenAPI discovery (Swagger 2.0 and OpenAPI 3), redaction, reports, external tools (nuclei and testssl
read only the base URL).

## 2. Assumptions about how any target behaves

These are not Forgejo or Kong names: they are ideas built into the tests about how an API answers. They are the
most dangerous, because they produce **false verdicts** without any error.

| # | Assumption | Where | When it is false |
|---|---|---|---|
| A-1 | A path that does not exist answers 404 | 0.1 counts as "active" anything in `_ACTIVE_STATUS_CODES` (`test_0_1_shadow_api_discovery.py:66`, includes 401, 403, 200); 2.1 counts 404 as "protected" (`test_2_1_rbac_enforcement.py:73`); 0.2 expects 403/404/410 (`test_0_2_deny_by_default.py:104`) | gateways with an authentication plugin applied before routing answer 401 to every path; single-page applications answer 200 to every path. 0.1: every wordlist entry becomes a finding; 0.2: every probe a finding; 2.1: **PASS on a path that does not exist (observed on cRAPI)** |
| A-2 | A credential travels as `Authorization: Bearer <token>` | `test_2_1_rbac_enforcement.py:243`, `test_7_2_ssrf_prevention.py:545`, `forgejo_resources.py:474`, `src/core/client.py:138`; 1.4 uses `token <value>` (`test_1_4_token_revocation.py:412`) | APIs using an API-key header (`X-API-Key`), a cookie, or another scheme |
| A-3 | `path_seed` maps a parameter **name** to one value for the whole API | `src/tests/helpers/path_resolver.py:93` | APIs that reuse a name for different resources (`/users/{id}`, `/orders/{id}`): one value cannot be right for both; a missing name becomes `"1"` (`path_resolver.py:74`) |
| A-4 | Roles are three fixed accounts: `admin`, `user_a`, `user_b` | `src/core/context.py` (ROLE_* constants), `CredentialsConfig` | APIs with more roles or tenants; holds for most targets, recorded only to be explicit |
| A-5 | The rate limit is below `max_requests` (150) per run of 4.1 | `src/test_config/domain_4.py:37` | an API allowing more: 4.1 reports "rate limiting absent" (FAIL) while a limit exists; configurable, but only if the integrator knows the limit |
| A-6 | The specification says which endpoints are protected | 1.1 uses `requires_auth` from the security declarations (`src/discovery/surface.py:507-515`) | a specification without `security` declarations: 1.1 SKIPs (correct, but nothing verified); one declaring everything protected (Forgejo) turns public reads into findings (decided correct in Q-47) |

## 3. Test by test

| Test | Forgejo or Kong ties | Assumptions (section 2) | On another target |
|---|---|---|---|
| 0.1 | none | A-1 | false findings where unknown paths do not answer 404 (from the code) |
| 0.2 | default `gateway_server_identifiers` includes kong among 7 gateways (`src/test_config/domain_0.py:58`), configurable | A-1 | false findings where unknown paths answer 401 (from the code); ran on cRAPI (observed) |
| 0.3 | none (uses `deprecated` from the specification) | - | works; SKIP without deprecated endpoints |
| 1.1 | none (specification, `path_seed`) | A-3, A-6 | works (observed on cRAPI) |
| 1.4 | **all of it**: token API paths (`test_1_4_token_revocation.py:72-73`), Basic Auth for creation, `sha1` field, `token` scheme, re-probe on `/api/v1/user` (`:78`), Forgejo user lookup | A-2 | **ERROR** (observed on cRAPI: `GET /api/v1/user returned HTTP 404`). Also, regardless of the target: the token is never tried before revocation, and any non-2xx answer after revocation is a PASS (`:89`), 404 and 500 included |
| 1.5 | none (derives the HTTP URL from the HTTPS one, or `http_probe_url`) | - | works |
| 1.6 | none (cookie names list, probe paths `/`) | - | works; finds nothing if the session cookie has a name outside the list |
| 2.1 | default `admin_endpoint_paths: ["/api/v1/admin/users"]` (`src/test_config/domain_2.py:32`) | A-1, A-2 | **false PASS** with the default path on an API without it (observed on cRAPI); no check that the configured path exists |
| 3.3 | Kong `hmac-auth` plugin and field names, as configurable defaults (`src/test_config/domain_3.py:41`); plugin scope global / service / route; needs I-2 | - | SKIP without the adapter (observed); another gateway's HMAC configuration has another shape |
| 4.1 | none (endpoint chosen from the specification) | A-5 | works if the limit is below `max_requests` |
| 4.2 | Kong service fields `connect_timeout`, `read_timeout`, `write_timeout` in milliseconds (`test_4_2_timeout_config_audit.py:83-85`); needs I-2 | - | SKIP without the adapter (observed) |
| 4.3 | built for Kong OSS: circuit-breaker plugin, then upstream passive health checks (`healthchecks.passive.unhealthy.*`), then `/status` metrics; needs I-2 | - | SKIP without the adapter (observed); other gateways implement circuit breaking differently |
| 6.2 | none (response headers) | - | works |
| 6.4 | sub-test A none (debug paths list); sub-test B scans Kong services (`url`) and plugins (`config`); `gateway_block_body_fragment` default is Kong's message (`src/test_config/domain_6.py:205`), used only for an oracle state label | A-1 | A works; B needs I-2 |
| 7.2 | default `injection_mode: forgejo_webhook` (`src/test_config/domain_7.py:144`), Forgejo repository and webhook body; `fixed_path` mode is generic | A-2 | works with `fixed_path` (observed on cRAPI, 73 payloads rejected); the oracle "2xx = URL accepted" does not show that the server fetched the URL |
| `ext.*` | none (base URL only) | - | works |

Summary:

- **Generic today:** 0.3, 1.1, 1.5, 1.6, 4.1 (with A-5), 6.2, the external tests, 6.4 sub-test A, 7.2 in
  `fixed_path`.
- **Tied to Forgejo:** 1.4 (entirely), the `forgejo_token` login and its default, 2.1 and 7.2 defaults.
- **Tied to Kong:** the adapter design (I-1, I-2) and the four audits that use it (3.3, 4.2, 4.3, 6.4 B).
- **False verdicts possible on any target:** 0.1, 0.2, 2.1 (A-1); 1.4 (no positive control); 4.1 (A-5).

## 4. Scope (owner, 2026-10-10)

Block 7+8 makes the tool **run and be configurable** on an API and a gateway other than Forgejo and Kong, with
nothing of either wired into the code. Whether a verdict is **correct** belongs to the test review (block 6). The
items above split as follows.

**In this block** (they stop the tool from running, or tie it to Forgejo or Kong):

| Item | Why |
|---|---|
| I-1, I-2: neutral gateway adapter (Q-38), second gateway | with a gateway other than Kong the audits cannot run at all |
| I-3: Admin API protection (Q-34) | a protected Admin API makes the audits return ERROR |
| I-4: `forgejo_token` default login | on another API without the setting every login fails |
| Forgejo defaults of 2.1 (`admin_endpoint_paths`) and 7.2 (`injection_mode`) | Forgejo paths wired as defaults |
| 1.4, entirely Forgejo | ERROR on another API: configurable, or "not applicable" instead of an error |
| A-2: credential always sent as `Bearer` | an API using another scheme cannot be tested at all; only if a lab needs it |
| I-5: login types beyond `jwt_login` | only if a lab needs one |
| I-7: cRAPI lab, its specification and configuration | the proof (Q-52) |

**Moved to the test review** (the test runs, the verdict may be wrong): A-1 calibration against unknown paths (0.1,
0.2, 2.1); positive controls (2.1 admin path exists, 1.4 token tried before revocation, 1.4 non-2xx counted as
PASS); A-3 `path_seed` per parameter name; A-5 4.1 threshold; A-6 specification without security declarations; the
7.2 oracle (2xx does not show the URL was fetched).

**Questions for step 2** (this block only; none decided):

1. What do the audits need from a gateway, in neutral terms (e.g. "timeouts of each upstream service", "is request
   signing enabled, with which algorithms and replay window", "is there a circuit breaker or health check")?
   Should the adapter return those answers instead of Kong's objects (Q-38)?
2. When a gateway has no equivalent of a control (no Admin API, no circuit breaker), how does the test say "not
   applicable to this gateway"?
3. Admin API protection (Q-34): token, private certificate authority; per adapter or common.
4. Login (I-4): no Forgejo default (`auth_type` required, or a neutral default)?
5. 1.4 and 7.2: the target-specific operation a test needs (create and revoke a credential; an endpoint that makes
   the server fetch a URL) configured by the integrator as requests, as 7.2 `fixed_path` already does, or "not
   applicable" when not configured?
6. 2.1 default admin path: no default (SKIP "not configured") or kept?
7. Credential scheme (A-2) and other login types (I-5): only when a lab requires them?

**Decisions on these questions** (owner, 2026-10-11): question 1 in `gateway-concepts.md`; question 2 (reported as
SKIP with the reason, InfoNote for a partial test) in `gateway-concepts.md`; question 3 (Q-34, `admin_api_headers`)
in `gateway-concepts.md` and Q-34; questions 4 and 7 in `auth-survey.md` section 5; question 6: test 2.1 has **no
default admin path**, without `admin_endpoint_paths` it returns SKIP ("no admin endpoint configured"); the
specification cannot say which endpoints are for administrators (OpenAPI has no such marker) and guessing from names
is unreliable. The Forgejo lab configuration already lists the path (result unchanged); on cRAPI 2.1 goes from a
false PASS to SKIP until its admin endpoints are chosen in the test review. Question 5, test 7.2: **no default injection endpoint**:
without an injection configuration 7.2 returns SKIP ("no SSRF injection endpoint configured"); `forgejo_webhook`
stays as a mode chosen explicitly; both lab configurations already set 7.2 explicitly (results unchanged).

## 5. What the labs will show

- **cRAPI behind Kong** (only the API changes): expected from this analysis, before any change: 1.4 ERROR, 2.1 false
  PASS with the default path, 7.2 SKIP in the default mode (`test_7_2_ssrf_prevention.py:317-345`), audits running against the same Kong
  configuration as the Forgejo lab; 0.1 and 0.2 depend on how cRAPI and Kong answer unknown paths (A-1).
- **Second gateway** (only the gateway changes): the gateway must have an interface from which its configuration
  can be read, otherwise 3.3, 4.2, 4.3 and 6.4 B can only be "not applicable"; which gateway is chosen after the
  answers to questions 1 and 2.

### Observed on the cRAPI lab (2026-10-10, native tests, `test-environments/crapi-kong/config.yaml`, before any change)

Two runs on a lab reset in between gave identical results: 7 PASS, 5 FAIL, 2 SKIP, 1 ERROR, 58 findings, exit 1.

| Test | Result | Reading |
|---|---|---|
| 0.1 | FAIL, 49 findings (37 shadow paths, 12 undeclared methods) | the 37 shadow paths come from Q-65: every unknown path answers 301 (A-1) |
| 0.2 | FAIL, 4 findings | same cause (Q-65); the Forgejo lab behaves the same way |
| 0.3 | SKIP | the specification declares no deprecated endpoint |
| 1.1 | FAIL, 2 findings | `GET /workshop/api/shop/orders/1` and `/workshop/api/shop/return_qr_code` answer 200 without credentials: a real crAPI vulnerability (its challenge 14, unauthenticated access) |
| 1.4 | ERROR | as expected: `GET /api/v1/user returned HTTP 301` (Forgejo path, I-6) |
| 1.5 | PASS | redirect on port 9000 |
| 1.6 | SKIP | no session cookie with a listed name (crAPI uses JWTs) |
| 2.1 | PASS | **false PASS**, as expected: the default Forgejo path answers 301, classified inconclusive, yet the message says "correctly rejected" |
| 3.3, 4.2, 4.3 | PASS | same Kong configuration as the Forgejo lab |
| 4.1 | FAIL, 2 findings | no rate limiting in either lab |
| 6.2 | FAIL, 1 finding | header inconsistency: the community service sends neither `X-Content-Type-Options` nor `X-Frame-Options`, and the lab's Kong configuration only *replaces* them (Forgejo sends them itself); the workshop service also leaks `Server: gunicorn` |
| 6.4 | PASS | |
| 7.2 | PASS, 90.8 s | **probably a false PASS**: all 73 payloads answer 503 or 504, counted as "blocked"; on crAPI that endpoint is a documented SSRF (its challenge 11), so 503/504 more likely mean the server tried to fetch the URL. The message also says "webhook" (Forgejo wording) |

After Q-65 (2026-10-11, Kong's own HTTP-to-HTTPS redirect): 0.1 FAIL 12 findings (the 12 undeclared methods), 0.2
PASS, 1.5 FAIL (Kong's 404 carries no HSTS), 2.1 PASS with the default path answering 404; the rest unchanged.

For the test review: 1.1 finding a real vulnerability is the kind of check cRAPI's documented vulnerabilities allow
(`docs/challenges.md` upstream: 18 challenges).

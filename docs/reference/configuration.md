# Configuration Reference (`config.yaml`)

> **Audience:** users, integrators · **Status:** stable · **Source of truth:** `src/config/schema/tool_config.py`,
> `src/test_config/domain_*.py`, `src/core/models/external_tools.py`, `src/core/models/resources.py`,
> `src/config/loader.py` · **Verified:** 2026-10-14 (credentials, resources), 2026-10-12 (gateway keys), 2026-10-05, v0.1.0 (field list extracted from the Pydantic models; behaviours tested with
> `apiguard validate-config`)

Every field, type, default and constraint below comes from the Pydantic models. For a guided setup see
[`guides/usage/configure-a-target.md`](../guides/usage/configure-a-target.md); the complete example in the repository, with every key, its description and its default, is
[`config.example.yaml`](../../config.example.yaml) (`hatch run dev:check` verifies that it lists every key); the lab
configurations hold only their own values.

## Loading rules

1. **File.** Default `config.yaml` in the working directory; override with `--config`.
2. **Secrets via environment.** Every `${VAR}` placeholder is replaced with the environment variable `VAR`
   **before** the YAML is parsed (`src/config/loader.py`).
   - Only uppercase names are recognised: `${[A-Z][A-Z0-9_]*}`. Other forms are left as literal text.
   - `${VAR:-default}` is **not** supported.
   - An unset variable stops the tool with `ConfigurationError` naming the variable (exit `10`). This applies
     to placeholders **inside YAML comments too**, because interpolation happens on the raw text.
   - `.env` is loaded first: the one in the working directory, or the file given with `--env-file`
     ([details](cli.md#environment-and-env)); variables already in the environment win.
3. **Relative paths** (`openapi_spec_path`, `output.directory`, `external_tools.nuclei.template_dir`) are
   resolved against the **working directory**, not the location of `config.yaml`.
4. **Unknown keys are rejected.** Every section with a schema forbids keys it does not declare: a misspelled key
   (e.g. `min_prioriti`) stops the tool at Phase 1 with exit `10`. The message lists every error with its
   dotted path and, when a declared key is similar enough, suggests it:
   `execution.min_prioriti: unknown key (did you mean 'min_priority'?)`. Free-form mappings such as
   `target.path_seed` (keys chosen by the user) are not checked. A configuration written for a newer version of
   the tool, with keys this version does not know, is rejected the same way.
5. The loaded configuration is immutable for the whole run.

## Minimal configuration

Only `target.base_url` and one OpenAPI source are required:

```yaml
target:
  base_url: "https://gateway.example.com"
  openapi_spec_path: "./specs/openapi.json"
```

With this configuration the tests that log in to the API return SKIP (no `credentials`), tests that read the gateway
configuration return SKIP or skip that part (no `admin_api_url` / `gateway_adapter`), and external tools are
not scheduled (disabled by default). Which tests are affected is stated on each test page ([`tests/`](../tests/README.md)). Phase 1 logs a
`config_coherence_warning` for the missing credentials and Admin API; they are warnings, not errors.

---

## `target`

Connection to the API under test and to the gateway admin plane.

| Key | Type | Default | Constraints | Description |
|---|---|---|---|---|
| `base_url` | URL | **required** | - | Base URL of the API as exposed through the gateway proxy. |
| `openapi_spec_url` | URL \| null | `null` | exactly one of `openapi_spec_url` / `openapi_spec_path` | URL fetched at runtime (Phase 2). |
| `openapi_spec_path` | path \| null | `null` | see above | Local spec file (JSON or YAML). Existence is checked in Phase 2, not by `validate-config`. |
| `admin_api_url` | URL \| null | `null` | required if `gateway_adapter` is set | Gateway Admin API. Without it, WHITE_BOX tests that read gateway configuration return SKIP. Called with the headers of `admin_api_headers` and with certificate verification on: an Admin API with a certificate not publicly trusted is not accessible, and those tests SKIP with "Not verifiable: no access to ..." ([security model](../architecture/security-model.md)). |
| `admin_api_headers` | map string → string | `{}` | names and values not empty | Headers sent on every Admin API request, for a gateway that protects it: e.g. `X-API-KEY` (APISIX; a key of role `viewer`, GET only, is enough), `Kong-Admin-Token` (Kong Enterprise). Never sent to `health_api_url`. Write the values as `${VAR}`: they are registered as secrets and masked in logs and reports. |
| `health_api_url` | URL \| null | `null` | - | Interface reporting the live health of the backends, for a gateway that keeps it outside the Admin API: the APISIX Control API (e.g. `http://127.0.0.1:9090`). Read by test 4.3 (observability), without the `admin_api_headers`. Not used by Kong. Absent on APISIX: the live health is reported as not accessible, the rest of the audits still run. |
| `gateway_adapter` | string \| null | `null` | `kong`, `apisix` (the adapters listed in `src/core/gateway/__init__.py`) | Adapter used by WHITE_BOX configuration-audit tests. `null` → those tests SKIP even if `admin_api_url` is set. |
| `admin_connect_timeout_seconds` | float | `5.0` | 1-30 | TCP connect timeout for Admin API (and `health_api_url`) calls. |
| `admin_read_timeout_seconds` | float | `10.0` | 1-60 | Read timeout for Admin API (and `health_api_url`) calls. |
| `path_seed` | map string→string | `{}` | - | Real values for OpenAPI path parameters (`{owner}` → `"alice"`). Unlisted parameters fall back to the test's placeholder (typically `1`). Generate with [`apiguard generate-seed`](cli.md#generate-seed). **Use only test resources you can lose:** the values are used for every request, including `DELETE` and writes sent without credentials (test 1.1); on an API without protection on those endpoints they are deleted or changed. |
| `verify_tls` | bool | `true` | - | Verify the TLS certificate of `base_url`. Set `false` only for lab gateways with self-signed certificates. Also applied to the HTTP-redirect probe of test 1.5. |

## `credentials`

Accounts used by the tests that log in to the API: `user_a` (a normal user) by the GREY_BOX tests, `admin` (the
API's administrator account) by the WHITE_BOX test 1.4. Always provide values through `${VAR}` placeholders.

| Key | Type | Default | Description |
|---|---|---|---|
| `auth_type` | string \| null | `null` | How a credential is obtained. **Required** when an account or a token is configured. `basic` (HTTP Basic with username and password, RFC 7617), `static_token` (the `<role>_token` values), `login` (the [prepared resource](#resources) `login_resource` is created for each role: its value `credential` is the token; its delete request, if any, deletes the token at the end of the run and lets test 1.4 revoke one). `forgejo_token` and `jwt_login` (v0.1.0) are rejected with a message showing the `login` form. |
| `admin_username`, `admin_password` | string \| null | `null` | Administrator role (`basic`, `login`). |
| `user_a_username`, `user_a_password` | string \| null | `null` | First non-privileged role. |
| `user_b_username`, `user_b_password` | string \| null | `null` | Second non-privileged role. |
| `admin_token`, `user_a_token`, `user_b_token` | string \| null | `null` | `static_token` only: the token of each role. |
| `login_resource` | string \| null | `null` | `login` only, **required** there: the name of a resource of [`resources`](#resources) whose create request logs in for a role (`auth: basic` or `none`) and whose values include `credential`, the dotted path of the token in the response. The v0.1.0 keys `login_endpoint`, `username_body_field`, `password_body_field`, `token_response_path` are rejected with a message showing this form. |
| `security_scheme` | string \| null | `null` | Name of the specification's security scheme the credential is sent with. **Required** when the specification declares more than one scheme that can carry a token (e.g. Forgejo: `AuthorizationHeaderToken`). Not with `basic`. |
| `send_as` | map \| null | `null` | Where and how the credential is sent: `in` (`header`, `query`, `cookie`), `name`, `prefix` (written before the credential, spaces included). Every field left out comes from the specification's scheme; with no usable scheme `in` and `name` are required. With a declared `apiKey` scheme only `prefix` may be set (Forgejo: `prefix: "token "`). Not with `basic`. |

Each method takes its own kind of credential: `static_token` the `<role>_token` keys only, the other methods username
and password, set together or not at all.

Examples of `login` resources, from the labs: crAPI's JSON login (`test-environments/crapi-kong/config.yaml`,
`crapi-login`: `POST /identity/api/auth/login` with `auth: none` and the body `email: "{username}"`,
`password: "{password}"`, value `credential: token`); Forgejo's token API (`test-environments/forgejo-kong/config.yaml`,
`forgejo-token`: `POST /api/v1/users/{username}/tokens` with `auth: basic`, value `credential: sha1`, and a delete
request, so tokens are deleted at the end of the run and 1.4 can revoke one). Every value comes from a `${VAR}` placeholder; passwords and tokens are
registered as secrets and masked in every output.

**How the credential is sent** (resolved once per run, after the specification is read; `src/core/auth_placement.py`):

| Situation | Result |
|---|---|
| `auth_type: basic` | `Authorization: Basic <base64(username:password)>` |
| one scheme that can carry a token | that scheme |
| several such schemes | the one named in `security_scheme` (error otherwise, listing the names) |
| no such scheme | `send_as` with `in` and `name` (error otherwise) |
| `http` bearer, `oauth2`, `openIdConnect` scheme | `Authorization: Bearer <token>`; a `send_as.prefix` is an error |
| `apiKey` scheme | its location and name, after `send_as.prefix` if set |

Schemes that can carry a token: `apiKey`, `http` bearer, `oauth2`, `openIdConnect` (not `http` basic, not
`mutualTLS`). A configuration that does not determine the placement stops the run with exit `10` before any test;
`validate-config` checks it too, reading the specification (download or local file) only when credentials are
configured, and prints where the credentials will be sent.

## `resources`

Prepared resources: what the tool creates on the target and deletes at the end of the run, by name (letters, digits,
`_`, `-`). Used by `credentials.login_resource` and by `tests.domain_7.test_7_2.injection_resource`; the test or the
login chooses the role a resource is created for. None by default. Design: `docs/project/resources-design.md`.

| Key | Type | Default | Description |
|---|---|---|---|
| `<name>.create.method` | `GET` `POST` `PUT` `PATCH` `DELETE` | `POST` | Method of the create request. |
| `<name>.create.path` | string | **required** | Path, starting with `/`; may use `{username}`, `{password}`, `{random}`. |
| `<name>.create.auth` | `credential` \| `basic` \| `none` | `credential` | `credential`: the role's credential, sent as `credentials` says; `basic`: HTTP Basic with the role's username and password; `none`: nothing. |
| `<name>.create.body` | JSON \| null | `null` | JSON body; strings may use the same placeholders. |
| `<name>.values` | map name → dotted path | `{}` | Values read from the JSON response, e.g. `owner: owner.login`. A login resource needs `credential` (always masked as a secret); other values are not secrets. No array indexes. |
| `<name>.delete.method` | as `create.method` | `DELETE` | Method of the delete request, sent at teardown with the same role. |
| `<name>.delete.path` | string | none | Path; may also use the names of `values`. No `delete`: nothing is deleted. A delete request has no body. |
| `<name>.delete.auth` | as `create.auth` | `credential` | How the delete request authenticates. |

**Placeholders** (`{...}`, one syntax for every value the tool fills): `{username}` and `{password}` are the account of
the role the resource is created for, `{random}` is 8 hexadecimal characters (the same in the create and delete
request of one resource), and in `delete` the names of `values`. Literal braces are written `{{` and `}}`. In YAML a
value that starts with `{` must be quoted (`email: "{username}"`): unquoted, YAML reads it as a mapping, and the
configuration is rejected. `${VAR}` is different: an environment variable, filled by the loader.

At run time: a create request answered with a non-`2xx` status, or a configured value missing from the response, gives
an error naming the resource (the test returns ERROR). The teardown entry is registered as soon as the create request
succeeds; teardown runs in reverse creation order, so a resource created with a credential is deleted before the
credential. `validate-config` lists the resources and who uses them.

## `execution`

| Key | Type | Default | Constraints | Description |
|---|---|---|---|---|
| `min_priority` | int | `3` | 0-3 | **Highest** priority level included (the name is historical): `0` = P0 only, `3` = all. |
| `strategies` | list | all three | non-empty; `BLACK_BOX`, `GREY_BOX`, `WHITE_BOX` | Tests, native and external, whose strategy is not listed are excluded (ignored when `test_ids` is set). |
| `test_ids` | list of strings | `[]` | `X.Y` or `ext.X.Y.tool` | Non-empty: run **only** the listed tests, native or external. Replaces the `min_priority` filter (and `strategies` for native tests). It chooses only among available tests: an ID that does not exist, or an external test whose tool is disabled (`external_tools`), stops the tool at startup (exit `10`) with the reason and, for an unknown ID, the closest existing ID. |
| `fail_fast` | bool | `false` | - | Stop after the first P0 test returning FAIL or ERROR ([`exit-codes.md`](exit-codes.md)). |
| `connect_timeout` | float | `5.0` | 1-30 | TCP connect timeout (s) for requests to the target. |
| `read_timeout` | float | `30.0` | 5-120 | Read timeout (s) for requests to the target. |
| `max_retry_attempts` | int | `3` | 1-10 | Total attempts (initial + retries). Only transport errors are retried, never HTTP status codes. |
| `openapi_fetch_timeout_seconds` | float | `60.0` | 10-300 | Wall-clock limit for fetching and dereferencing the spec in Phase 2. When it expires the run stops with `OpenAPILoadError` (exit `10`), also if the server accepts the connection and never answers. |

## `output`

| Key | Type | Default | Description |
|---|---|---|---|
| `directory` | path | `outputs` | Destination of `evidence.json`, `assessment_report.html`, `apiguard_report.json`, `tools/` and the temporary `evidence_tmp/`. Created if missing. |

## `tests`

Per-test tuning. Defaults produce a complete assessment; set only what you need to change. Structure:
`tests.domain_<D>.test_<D>_<N>.<key>`. Every native test has a section; 0.3 has no parameters.
Schema per domain: `src/test_config/domain_<D>.py`.

### `tests.domain_0.test_0_1` - Shadow API discovery

| Key | Type | Default | Description |
|---|---|---|---|
| `method_probe_sample_size` | int 1-100 | `10` | Number of documented endpoints, in spec order, taken by the undeclared-method sub-check; the parametric ones among them are skipped. Each receives up to about five undeclared methods. |

### `tests.domain_0.test_0_2` - Deny-by-default

| Key | Type | Default | Description |
|---|---|---|---|
| `gateway_server_identifiers` | list (≥1) | `kong, nginx, openresty, apache, caddy, traefik, envoy` | Case-insensitive substrings of the `Server` header that identify a response generated by the gateway rather than the backend. APISIX answers `Server: APISIX`: add `apisix`. |

### `tests.domain_1.test_1_1` - Authentication required

| Key | Type | Default | Description |
|---|---|---|---|
| `max_endpoints_cap` | int ≥0 | `0` | Maximum protected endpoints probed. `0` = all. Set a positive cap only if the target's rate limiting would interfere or a time bound is needed. |

### `tests.domain_1.test_1_4` - Token revocation

| Key | Type | Default | Description |
|---|---|---|---|
| `verify_request.method` | `GET` `POST` `PUT` `PATCH` `DELETE` | `GET` | Method of the request sent with the revoked credential. |
| `verify_request.path` | string | none | Path of an endpoint that requires authentication and answers `2xx` to a valid credential (Forgejo: `/api/v1/user`). No `verify_request`: the test returns SKIP. |

The temporary credential is a new instance of the login resource for the `admin` role, revoked by its delete request;
1.4 runs only with `auth_type: login` and a login resource that has a delete request (otherwise SKIP "Not
applicable"). `token_name` (v0.1.0) is rejected: names now come from the resource (`apiguard-{random}` on the labs).

### `tests.domain_1.test_1_5` - Credentials over insecure channels

| Key | Type | Default | Description |
|---|---|---|---|
| `hsts_min_max_age_seconds` | int ≥86400 | `31536000` | Minimum acceptable `Strict-Transport-Security` max-age. |
| `http_probe_enabled` | bool | `true` | Probe the HTTP URL for HTTP→HTTPS redirect. |
| `http_probe_url` | string | `""` | Explicit HTTP URL to probe. Empty → derived from `base_url`. Needed when HTTPS uses a non-standard port (e.g. `https://localhost:8443` → set `http://localhost:8000/api/v1/version`, a path the gateway routes). |
| `http_probe_timeout_seconds` | float ≥1 | `5.0` | Timeout for the redirect probe. |
| `expected_redirect_status_codes` | list of int | `301, 308` | Status codes accepted as a valid redirect. |

### `tests.domain_1.test_1_6` - Session management

| Key | Type | Default | Description |
|---|---|---|---|
| `cookie_probe_paths` | list | `/` | Paths requested to collect `Set-Cookie` headers. |
| `session_cookie_names` | list (non-empty) | `session, sid, PHPSESSID, JSESSIONID, connect.sid, _session, auth_session, user_session` | Case-insensitive names treated as session cookies. |
| `check_samesite` | bool | `true` | Validate the `SameSite` attribute. |
| `expected_samesite_value` | string | `Strict` | Expected `SameSite` value (case-insensitive). |

### `tests.domain_2.test_2_1` - RBAC

| Key | Type | Default | Description |
|---|---|---|---|
| `admin_endpoint_paths` | list | empty | Admin-only paths of the target probed with a non-privileged token. No default (a path the target does not have answers `404`, counted as enforced): empty, the test returns SKIP. Forgejo: `/api/v1/admin/users`. |
| `admin_endpoint_method` | string | `GET` | HTTP method used for the probes. |

### `tests.domain_3.test_3_3` - HMAC configuration audit

| Key | Type | Default | Description |
|---|---|---|---|
| `max_clock_skew_seconds` | int ≥1 | `300` | Maximum acceptable `clock_skew` of the HMAC plugin. |
| `forbidden_algorithms` | list | `hmac-sha1, hmac-md5` | Algorithms whose presence is a finding. |
| `plugin_names` | list | `hmac-auth` | Gateway plugin names implementing HMAC authentication. Read by the Kong adapter; the APISIX adapter reads its own `hmac-auth` plugin. |
| `field_clock_skew` | string | `clock_skew` | Plugin config field holding the replay window. |
| `field_algorithms` | string | `algorithms` | Plugin config field listing allowed algorithms. |
| `field_validate_body` | string | `validate_request_body` | Plugin config field enabling body signing. The three `field_*` keys: Kong adapter only. |
| `clock_skew_unconfigured_value` | int | `0` | Value meaning "no limit configured". |

### `tests.domain_4.test_4_1` - Rate limiting

| Key | Type | Default | Description |
|---|---|---|---|
| `max_requests` | int 10-500 | `150` | Requests sent before concluding that rate limiting is absent. |
| `request_interval_ms` | int 10-5000 | `50` | Interval between probe requests. |

### `tests.domain_4.test_4_2` - Timeout configuration audit

| Key | Type | Default | Description |
|---|---|---|---|
| `max_connect_timeout_ms` | int ≥1 | `5000` | Maximum acceptable gateway service `connect_timeout`. |
| `max_read_timeout_ms` | int ≥1 | `30000` | Maximum acceptable `read_timeout`. |
| `max_write_timeout_ms` | int ≥1 | `30000` | Maximum acceptable `write_timeout`. |

### `tests.domain_4.test_4_3` - Circuit breaker audit

| Key | Type | Default | Description |
|---|---|---|---|
| `accepted_cb_plugin_names` | list | `circuit-breaker` | Plugin names accepted as a circuit breaker. Read by the Kong adapter; the APISIX adapter reads its own `api-breaker` plugin. |
| `failure_threshold_min` / `failure_threshold_max` | int ≥1 | `3` / `10` | Acceptable failure-threshold range (min ≤ max enforced). |
| `timeout_duration_min_seconds` / `timeout_duration_max_seconds` | int ≥1 | `30` / `120` | Acceptable open-state duration range (min ≤ max enforced). |
| `passive_hc_max_http_failures` | int ≥1 | `10` | Maximum acceptable `unhealthy.http_failures` in upstream passive health checks. |
| `passive_hc_max_tcp_failures` | int ≥1 | `10` | Maximum acceptable `unhealthy.tcp_failures`. |
| `passive_hc_max_timeouts` | int ≥1 | `10` | Maximum acceptable `unhealthy.timeouts`. |

### `tests.domain_6.test_6_2` - Security headers audit

| Key | Type | Default | Description |
|---|---|---|---|
| `hsts_min_max_age_seconds` | int ≥1 | `31536000` | Minimum acceptable HSTS max-age. |
| `endpoint_sample_size` | int ≥0 | `5` | Endpoints sampled for the cross-endpoint consistency check. `0` = all. |

### `tests.domain_6.test_6_4` - Hardcoded credentials audit

| Key | Type | Default | Description |
|---|---|---|---|
| `debug_endpoint_paths` | list | 10 paths (`/actuator/env`, `/debug/vars`, `/api/config`, …; full list in `src/test_config/domain_6.py`) | Paths probed for exposed debug/actuator endpoints. |
| `gateway_block_body_fragment` | string | `no Route matched with those values` | Body substring identifying a deny-by-default reply generated by the gateway (the default is Kong's message; APISIX: `404 Route Not Found`). |

### `tests.domain_7.test_7_2` - SSRF prevention

| Key | Type | Default | Description |
|---|---|---|---|
| `payload_categories` | list | `cloud_metadata, private_ip, encoding_bypass, forbidden_protocol, dns_bypass, url_parser_confusion` | Payload families sent. |
| `injection_path_template` | string \| null | `null` | Endpoint receiving the injected URL (`POST`). No default: unset (with the body), the test returns SKIP. With `injection_resource` it may use the resource's values (Forgejo: `/api/v1/repos/{owner}/{repo}/hooks`). |
| `injection_body_template` | object \| null | `null` | Request body; **required** with the path. Must contain `"{ssrf_url}"` exactly once (each payload URL); may contain `"{random_secret}"` (32 random hexadecimal characters, masked as a secret) and the resource's values. Checked at startup. Forgejo webhook body: `test-environments/forgejo-kong/config.yaml`. |
| `injection_resource` | string \| null | `null` | A [prepared resource](#resources) created for `user_a` before the probes (once per run), whose values fill the path and the body; deleted at teardown (Forgejo: `repository`). Without it the path is used as written (crAPI). A resource that cannot be created gives ERROR. |

`injection_mode` and `injection_url_field` (v0.1.0) are rejected with a message showing the new form; `$SSRF_URL$`
and `$RANDOM_SECRET$` are now `{ssrf_url}` and `{random_secret}`.
| `ssrf_redirect_server_url` | string | `""` | Operator-controlled server answering `302` to an internal address. Empty → the redirect sub-test is skipped and documented with an InfoNote. |
| `ssrf_block_response_keywords` | list | 11 keywords | Body substrings identifying an explicit SSRF block. |
| `ssrf_malformed_url_keywords` | list | 8 keywords | Body substrings identifying a URL rejected as syntactically invalid. |
| `ssrf_unsupported_scheme_keywords` | list | 8 keywords | Body substrings identifying a rejected URL scheme. |
| `ssrf_request_timeout_ms` | int ≥1000 | `10000` | **No effect in v0.1.0** - reserved; `execution.read_timeout` applies (Q-24). |

Keyword defaults: `src/test_config/domain_7.py`.

## `external_tools`

External-tool tests (`ext.*`) are scheduled only when the master switch **and** the tool's own `enabled` are
true (`src/external_tests/registry.py`):

| Situation | Result |
|---|---|
| Section absent, master switch `false`, or tool `enabled: false` | The tool's tests are **not scheduled** (not a SKIP): they are listed in the report's `not_run` with reason `tool_disabled`. |
| Tool enabled but binary/library not found | The tool's tests return **SKIP** with the reason. |
| Tool enabled and available | The tests run; a tool failure or timeout returns **ERROR**. |

`execution.test_ids` cannot force a disabled tool to run: listing a test of a disabled tool stops the tool at startup
(exit `10`, e.g. `'ext.1.5.sslyze' cannot run: external_tools.sslyze.enabled is false`).

| Key | Type | Default | Description |
|---|---|---|---|
| `enabled` | bool | `true` | Master switch. `false` removes all external tests from the run. |

Common keys for each tool (`testssl`, `nuclei`, `sslyze`):

| Key | Type | Default | Description |
|---|---|---|---|
| `enabled` | bool | **`false`** | Enable the tool. |
| `timeout_seconds` | int \| null | `null` | **Required when `enabled: true`** (Phase 1 error otherwise). Ranges: testssl 30-600, nuclei 60-600, sslyze 30-300. For testssl and nuclei: wall-clock limit of one execution. For sslyze: timeout of each TLS connection, not of the whole scan. |
| `extra_flags` | string | testssl: `--quiet --color 0`; nuclei: `""` | **testssl and nuclei only** (command-line tools). Flags appended verbatim to the command line. Must not contain secrets. sslyze is a library and has no such key. |
| `expected_version` | string \| null | `null` | Expected tool version; a mismatch logs a WARNING and the test still runs. |
| `dev_mode` | bool | `false` | Development only: reuse `outputs/tools/<label>_output.json` instead of running the tool. Never enable in a real assessment. |

nuclei-specific keys:

| Key | Type | Default | Description |
|---|---|---|---|
| `template_dir` | string | `./tools/nuclei-templates` | Template directory (relative to the working directory). |
| `tags` | list | `api, exposure, misconfig, panel` | Template tags selected (`-tags`). |
| `per_request_timeout` | int 5-60 | `10` | Per-request timeout passed as `-timeout`. |
| `rate_limit_rps` | int 1-150 | `30` | Requests per second passed as `-rl`. |

Binary installation: `install_tools.sh` (testssl.sh 3.2.3, nuclei 3.8.0). sslyze is a Python extra:
`pip install "apiguard-assurance[sslyze]"`.

---

## Validation rules

Phase 1 rejects the configuration (exit `10`) when:

| Rule | Fields |
|---|---|
| Exactly one OpenAPI source | `target.openapi_spec_url`, `target.openapi_spec_path` |
| Adapter needs the Admin API URL; `kong` or `apisix` | `target.gateway_adapter`, `target.admin_api_url` |
| `auth_type` set when credentials are configured, supported value (`forgejo_token`, `jwt_login`, `json_login` and the v0.1.0 login keys rejected with the `login` form); `login` needs `login_resource`, only `login` takes it; each method's own credential keys only; `basic` without `security_scheme` / `send_as` | `credentials.*` |
| The login resource exists, has the value `credential`, and its create request does not use `auth: credential` | `credentials.login_resource`, `resources` |
| Resource names (letters, digits, `_`, `-`); paths start with `/`; methods `GET` `POST` `PUT` `PATCH` `DELETE`; placeholders well formed, known where used (no response value in `create`), quoted in YAML; value names not `username` / `password` / `random` | `resources.*` |
| 7.2: path and body together; `injection_resource` defined; path and body placeholders known; `{ssrf_url}` exactly once | `tests.domain_7.test_7_2` |
| 1.4: `verify_request` path starts with `/`, supported method | `tests.domain_1.test_1_4` |
| Username and password set together per role | `credentials.*` |
| The credentials determine where they are sent (`security_scheme`, `send_as` against the specification's schemes; checked after the specification is read) | `credentials.security_scheme`, `credentials.send_as` |
| `strategies` not empty | `execution.strategies` |
| `test_ids` format `X.Y` or `ext.X.Y.tool` | `execution.test_ids` |
| `test_ids` entries exist and their tool is enabled (checked right after Phase 1, also by `validate-config`) | `execution.test_ids` |
| Enabled tool has `timeout_seconds` | `external_tools.<tool>.*` |
| `session_cookie_names` not empty | `tests.domain_1.test_1_6` |
| min ≤ max ranges | `tests.domain_4.test_4_3` |
| Numeric ranges and types in the tables above | all |

Phase 1 **warns** (does not fail) when a selected strategy has tests that will SKIP for lack of access: WHITE_BOX
without `gateway_adapter` (gateway configuration audits), WHITE_BOX without the `admin` credentials (1.4), GREY_BOX
without the `user_a` credentials (2.1, 7.2). Log event `config_coherence_warning`, field `condition`.

## See also

- [`cli.md`](cli.md) - `validate-config`, `generate-seed`
- [`exit-codes.md`](exit-codes.md)
- [`config.example.yaml`](../../config.example.yaml) - every key, with description and default
- [`test-environments/forgejo-kong/config.yaml`](../../test-environments/forgejo-kong/config.yaml) - configuration of the Forgejo + Kong lab
- [`test-environments/crapi-kong/config.yaml`](../../test-environments/crapi-kong/config.yaml) - configuration of the crAPI + Kong lab
- [`test-environments/forgejo-apisix/config.yaml`](../../test-environments/forgejo-apisix/config.yaml) - configuration of the Forgejo + APISIX lab (Admin API key, Control API)

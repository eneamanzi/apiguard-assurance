# Configuration Reference (`config.yaml`)

> **Audience:** users, integrators · **Status:** stable · **Source of truth:** `src/config/schema/tool_config.py`,
> `src/config/schema/domain_*.py`, `src/core/models/external_tools.py`, `src/config/loader.py` ·
> **Verified:** 2026-10-05, v0.1.0 (field list extracted from the Pydantic models; behaviours tested with
> `apiguard validate-config`)

Every field, type, default and constraint below comes from the Pydantic models. For a guided setup see
[`guides/usage/configure-a-target.md`](../guides/usage/configure-a-target.md); the annotated example in the repository is
[`config.yaml`](../../config.yaml).

## Loading rules

1. **File.** Default `config.yaml` in the working directory; override with `--config`.
2. **Secrets via environment.** Every `${VAR}` placeholder is replaced with the environment variable `VAR`
   **before** the YAML is parsed (`src/config/loader.py`).
   - Only uppercase names are recognised: `${[A-Z][A-Z0-9_]*}`. Other forms are left as literal text.
   - `${VAR:-default}` is **not** supported.
   - An unset variable stops the tool with `ConfigurationError` naming the variable (exit `10`). This applies
     to placeholders **inside YAML comments too**, because interpolation happens on the raw text.
   - `.env` is loaded first (with Hatch: the repository's `.env`; with a `pip` install it is not found, see
     [where `.env` is searched](cli.md#environment-and-env)); variables already in the environment win.
3. **Relative paths** (`openapi_spec_path`, `output.directory`, `external_tools.nuclei.template_dir`) are
   resolved against the **working directory**, not the location of `config.yaml`.
4. **Unknown keys are ignored.** A misspelled key (e.g. `min_prioriti`) passes validation and the default
   applies (Q-22). Check spelling against this page.
5. The loaded configuration is immutable for the whole run.

## Minimal configuration

Only `target.base_url` and one OpenAPI source are required:

```yaml
target:
  base_url: "https://gateway.example.com"
  openapi_spec_path: "./specs/openapi.json"
```

With this configuration GREY_BOX tests return SKIP (no `credentials`), tests that read the gateway
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
| `admin_api_url` | URL \| null | `null` | required if `gateway_adapter` is set | Gateway Admin API. Without it, WHITE_BOX tests that read gateway configuration return SKIP. |
| `gateway_adapter` | string \| null | `null` | `kong` only | Adapter used by WHITE_BOX configuration-audit tests. `null` → those tests SKIP even if `admin_api_url` is set. |
| `admin_connect_timeout_seconds` | float | `5.0` | 1-30 | TCP connect timeout for Admin API calls. |
| `admin_read_timeout_seconds` | float | `10.0` | 1-60 | Read timeout for Admin API calls. |
| `path_seed` | map string→string | `{}` | - | Real values for OpenAPI path parameters (`{owner}` → `"alice"`). Unlisted parameters fall back to the test's placeholder (typically `1`). Generate with [`apiguard generate-seed`](cli.md#generate-seed). **Use only test resources you can lose:** the values are used for every request, including `DELETE` and writes sent without credentials (test 1.1); on an API without protection on those endpoints they are deleted or changed. |
| `verify_tls` | bool | `true` | - | Verify the TLS certificate of `base_url`. Set `false` only for lab gateways with self-signed certificates. Also applied to the HTTP-redirect probe of test 1.5. |

## `credentials`

Accounts used by GREY_BOX tests. Always provide values through `${VAR}` placeholders.

| Key | Type | Default | Description |
|---|---|---|---|
| `auth_type` | string | `forgejo_token` | Token acquisition strategy: `forgejo_token` (Forgejo/Gitea token API, `POST /users/{username}/tokens` with Basic Auth) or `jwt_login` (generic JSON login endpoint). |
| `admin_username`, `admin_password` | string \| null | `null` | Administrator role. |
| `user_a_username`, `user_a_password` | string \| null | `null` | First non-privileged role. |
| `user_b_username`, `user_b_password` | string \| null | `null` | Second non-privileged role. |
| `login_endpoint` | string \| null | `null` | `jwt_login` only, **required** there. Path relative to `base_url`. |
| `username_body_field` | string | `username` | `jwt_login`: JSON field carrying the username (e.g. `email`). |
| `password_body_field` | string | `password` | `jwt_login`: JSON field carrying the password. |
| `token_response_path` | string | `access_token` | `jwt_login`: dot-path to the token in the login response (`data.token`). No array indexing. |

Each role's username and password must be set together or not at all.

## `execution`

| Key | Type | Default | Constraints | Description |
|---|---|---|---|---|
| `min_priority` | int | `3` | 0-3 | **Highest** priority level included (the name is historical): `0` = P0 only, `3` = all. |
| `strategies` | list | all three | non-empty; `BLACK_BOX`, `GREY_BOX`, `WHITE_BOX` | Native tests whose strategy is not listed are excluded. **External tests are not filtered by strategy** (Q-10). |
| `test_ids` | list of strings | `[]` | `X.Y` or `ext.X.Y.tool` | Non-empty: run only the listed tests, with one exception: if the list has **only native IDs**, every enabled external test runs as well (Q-45). A list with only `ext.*` IDs, or a mixed list, runs exactly the listed tests. Replaces the `min_priority` filter (and `strategies` for native tests). To run only native tests, also set `external_tools.enabled: false`. |
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
`tests.domain_<D>.test_<D>_<N>.<key>`. Tests without tunable parameters (0.1, 0.3) have no section.
Schema per domain: `src/config/schema/domain_<D>.py`.

### `tests.domain_0.test_0_2` - Deny-by-default

| Key | Type | Default | Description |
|---|---|---|---|
| `gateway_server_identifiers` | list (≥1) | `kong, nginx, openresty, apache, caddy, traefik, envoy` | Case-insensitive substrings of the `Server` header that identify a response generated by the gateway rather than the backend. |

### `tests.domain_1.test_1_1` - Authentication required

| Key | Type | Default | Description |
|---|---|---|---|
| `max_endpoints_cap` | int ≥0 | `0` | Maximum protected endpoints probed. `0` = all. Set a positive cap only if the target's rate limiting would interfere or a time bound is needed. |

### `tests.domain_1.test_1_4` - Token revocation

| Key | Type | Default | Description |
|---|---|---|---|
| `token_name` | string (1-40) | `apiguard-token-revocation-test` | Name of the temporary API token created and revoked during the probe. |

### `tests.domain_1.test_1_5` - Credentials over insecure channels

| Key | Type | Default | Description |
|---|---|---|---|
| `hsts_min_max_age_seconds` | int ≥86400 | `31536000` | Minimum acceptable `Strict-Transport-Security` max-age. |
| `http_probe_enabled` | bool | `true` | Probe the HTTP URL for HTTP→HTTPS redirect. |
| `http_probe_url` | string | `""` | Explicit HTTP URL to probe. Empty → derived from `base_url`. Needed when HTTPS uses a non-standard port (e.g. `https://localhost:8443` → set `http://localhost:8000/`). |
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
| `admin_endpoint_paths` | list (≥1) | `/api/v1/admin/users` | Admin-only paths probed with a non-privileged token. The default is a Forgejo path: set it for other targets. |
| `admin_endpoint_method` | string | `GET` | HTTP method used for the probes. |

### `tests.domain_3.test_3_3` - HMAC configuration audit

| Key | Type | Default | Description |
|---|---|---|---|
| `max_clock_skew_seconds` | int ≥1 | `300` | Maximum acceptable `clock_skew` of the HMAC plugin. |
| `forbidden_algorithms` | list | `hmac-sha1, hmac-md5` | Algorithms whose presence is a finding. |
| `plugin_names` | list | `hmac-auth` | Gateway plugin names implementing HMAC authentication. |
| `field_clock_skew` | string | `clock_skew` | Plugin config field holding the replay window. |
| `field_algorithms` | string | `algorithms` | Plugin config field listing allowed algorithms. |
| `field_validate_body` | string | `validate_request_body` | Plugin config field enabling body signing. |
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
| `accepted_cb_plugin_names` | list | `circuit-breaker` | Plugin names accepted as a circuit breaker. |
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
| `debug_endpoint_paths` | list | 10 paths (`/actuator/env`, `/debug/vars`, `/api/config`, …; full list in `src/config/schema/domain_6.py`) | Paths probed for exposed debug/actuator endpoints. |
| `gateway_block_body_fragment` | string | `no Route matched with those values` | Body substring identifying a deny-by-default reply generated by the gateway (the default is Kong's message). |

### `tests.domain_7.test_7_2` - SSRF prevention

| Key | Type | Default | Description |
|---|---|---|---|
| `payload_categories` | list | `cloud_metadata, private_ip, encoding_bypass, forbidden_protocol, dns_bypass, url_parser_confusion` | Payload families sent. |
| `injection_mode` | `forgejo_webhook` \| `fixed_path` | `forgejo_webhook` | `forgejo_webhook`: create a temporary repository and inject through its webhook endpoint (Forgejo only; removed in teardown). `fixed_path`: post directly to `injection_path_template`; use for any other target. |
| `injection_path_template` | string | `/api/v1/repos/{owner}/{repo}/hooks` | Endpoint receiving the injected URL. |
| `injection_url_field` | string | `config.url` | Dot-path inside `injection_body_template` where the SSRF URL is placed. |
| `injection_body_template` | object | Forgejo webhook body | Request body; `$SSRF_URL$` and `$RANDOM_SECRET$` are substituted at runtime. |
| `ssrf_redirect_server_url` | string | `""` | Operator-controlled server answering `302` to an internal address. Empty → the redirect sub-test is skipped and documented with an InfoNote. |
| `ssrf_block_response_keywords` | list | 11 keywords | Body substrings identifying an explicit SSRF block. |
| `ssrf_malformed_url_keywords` | list | 8 keywords | Body substrings identifying a URL rejected as syntactically invalid. |
| `ssrf_unsupported_scheme_keywords` | list | 8 keywords | Body substrings identifying a rejected URL scheme. |
| `ssrf_request_timeout_ms` | int ≥1000 | `10000` | **No effect in v0.1.0** - reserved; `execution.read_timeout` applies (Q-24). |

Keyword defaults: `src/config/schema/domain_7.py`.

## `external_tools`

External-tool tests (`ext.*`) are scheduled only when the master switch **and** the tool's own `enabled` are
true (`src/external_tests/registry.py`):

| Situation | Result |
|---|---|
| Section absent, master switch `false`, or tool `enabled: false` | The tool's tests are **not scheduled**: they do not appear in the report at all (not even as SKIP). |
| Tool enabled but binary/library not found | The tool's tests return **SKIP** with the reason. |
| Tool enabled and available | The tests run; a tool failure or timeout returns **ERROR**. |

`execution.test_ids` cannot force a disabled tool to run.

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
| Adapter needs the Admin API URL; only `kong` supported | `target.gateway_adapter`, `target.admin_api_url` |
| Supported `auth_type`; `jwt_login` needs `login_endpoint` | `credentials.*` |
| Username and password set together per role | `credentials.*` |
| `strategies` not empty | `execution.strategies` |
| `test_ids` format `X.Y` or `ext.X.Y.tool` | `execution.test_ids` |
| Enabled tool has `timeout_seconds` | `external_tools.<tool>.*` |
| `session_cookie_names` not empty | `tests.domain_1.test_1_6` |
| min ≤ max ranges | `tests.domain_4.test_4_3` |
| Numeric ranges and types in the tables above | all |

Phase 1 **warns** (does not fail) when WHITE_BOX is selected without `admin_api_url`, or GREY_BOX without any
credential pair.

## See also

- [`cli.md`](cli.md) - `validate-config`, `generate-seed`
- [`exit-codes.md`](exit-codes.md)
- [`../../config.yaml`](../../config.yaml) - annotated example used for the Forgejo + Kong lab

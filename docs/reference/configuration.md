# Configuration Reference (`config.yaml`)

> **Audience:** users, integrators · **Status:** stable · **Source of truth:** `src/config/schema/tool_config.py`,
> the parameter models in the test modules (`src/tests/domain_*/test_*.py`, `src/config/tests_section.py`),
> `src/core/models/external_tools.py`, `src/core/models/resources.py`,
> `src/config/loader.py`, `src/core/models/tls.py` · **Verified:** 2026-10-15 (connections: `target`, `specification`,
> `gateway`, `tls`), 2026-10-14 (credentials, resources), 2026-10-12 (gateway keys), 2026-10-05, v0.1.0 (field list extracted from the Pydantic models; behaviours tested with
> `apiguard validate-config`)

Every field, type, default and constraint below comes from the Pydantic models. For a guided setup see
[`guides/usage/configure-a-target.md`](../guides/usage/configure-a-target.md); the complete example in the repository, with every key, its description and its default, is
[`config.example.yaml`](../../config.example.yaml) (`hatch run dev:check` verifies that it lists every key and loads as written); the lab
configurations hold only their own values.

## Loading rules

1. **File.** Default `config.yaml` in the working directory; override with `--config`.
2. **Secrets via environment.** Every `${VAR}` placeholder is replaced with the environment variable `VAR`
   **after** the YAML is parsed, inside the string values (`src/config/loader.py`), as Docker Compose does.
   - A placeholder is a whole value or part of one (`"Bearer ${TOKEN}"`); in a key it is not replaced, and in
     a YAML comment it is ignored.
   - The value from the environment is never read as YAML structure: any character (`#`, `:`, `"`, `\`, `[`)
     is kept, and a YAML error quotes the file as written, never the value.
   - Quotes decide the type, as for a value written by hand. Quoted (`"${VAR}"`), the value is always text.
     Unquoted and alone (`count: ${VAR}`), it takes the type of a number, a boolean or an empty value, as if
     written in its place (`VAR=5` gives `5`, `true` gives `true`, empty gives `null`); any other value stays the
     exact text. It matters in free data such as a resource `body`; a configuration field converts the text
     itself (`timeout_seconds: "${NUCLEI_TIMEOUT}"` is 600). Write passwords and tokens quoted: an unquoted
     `12345678` is a number, and a password field rejects it.
   - In a mapping written on one line (`body: {count: ${VAR}}`) the placeholder must be quoted, or the braces
     are a YAML error; for a number there, write the mapping on several lines.
   - Only uppercase names are recognised: `${[A-Z][A-Z0-9_]*}`. Other forms are left as literal text.
   - `${VAR:-default}` is **not** supported.
   - An unset variable stops the tool with `ConfigurationError` naming every unset variable (exit `10`).
   - `.env` is loaded first: the one in the working directory, or the file given with `--env-file`
     ([details](cli.md#environment-and-env)); variables already in the environment win.
3. **Relative paths** (`specification.path`, the files of the `tls` blocks, `output.directory`,
   `external_tools.nuclei.template_dir`) are resolved against the **working directory**, not the location of
   `config.yaml`.
4. **Unknown keys are rejected.** Every section with a schema forbids keys it does not declare: a misspelled key
   (e.g. `min_prioriti`) stops the tool at Phase 1 with exit `10`. The message lists every error with its
   dotted path and, when a declared key is similar enough, suggests it:
   `execution.min_prioriti: unknown key (did you mean 'min_priority'?)`. Free-form mappings such as
   `target.path_seed` (keys chosen by the user) are not checked. A configuration written for a newer version of
   the tool, with keys this version does not know, is rejected the same way.
5. **A key written twice in the same mapping is rejected** (exit `10`), naming the key and both lines:
   `key 'path' written twice in the same mapping (lines 129 and 130 of config.yaml): keep one.` YAML alone would
   keep the last value without a message. Each mapping is checked on its own: the same key under different parents
   (`path` in two resources) or in different items of a list is not a repetition, and a key that overrides a YAML
   merge (`<<: *anchor`) is allowed.
6. **A block written empty takes its defaults**, as if it were not written: a block the schema declares (a
   section, a tool, a `domain_X`, a `test_X_Y`, `headers`, `path_seed`) with every line under it commented,
   which YAML reads as `null`. A required block written empty (`target`, `specification`, `gateway.admin`) is
   still an error, and so is a single value written empty (`fail_fast:`); free data (a `body`, the values of
   `headers` and `path_seed`) is kept as written, `null` included.
7. The loaded configuration is immutable for the whole run.

## Minimal configuration

Only `target.base_url` and one specification source are required:

```yaml
target:
  base_url: "https://gateway.example.com"
specification:
  path: "./specs/openapi.json"
```

With this configuration the tests that log in to the API return SKIP (no `credentials`), tests that read the gateway
configuration return SKIP or skip that part (no `gateway`), and external tools are not scheduled (disabled by
default). Which tests are affected is stated on each test page ([`tests/`](../tests/README.md)); `validate-config` lists the
selected tests that will SKIP and why, and the run logs one `test_will_skip_unmet_needs` warning per test. Every certificate
is checked against the system's authorities ([`tls`](#tls-certificates-of-a-connection)).

The configuration is organised by **connection**: each place the tool connects to has its own section with its address,
its timeouts and its certificate settings.

| Connection | Section | Used for |
|---|---|---|
| the API under test | [`target`](#target) | every test request |
| the OpenAPI specification | [`specification`](#specification) | Phase 2 (and `validate-config` and `generate-seed`) |
| the gateway's Admin API | [`gateway.admin`](#gateway) | the WHITE_BOX configuration audits |
| the gateway's health interface | [`gateway.health`](#gateway) | test 4.3, on a gateway that keeps it apart (APISIX) |

---

## `target`

The API under test, as exposed through the gateway proxy, and how the tool connects to it.

| Key | Type | Default | Constraints | Description |
|---|---|---|---|---|
| `base_url` | URL | **required** | - | Base URL of the API as exposed through the gateway proxy. |
| `tls` | [tls block](#tls-certificates-of-a-connection) | none | - | Certificate settings of the API connection, also used by the HTTP-redirect probe of test 1.5 and given to the external TLS tests (`ca_bundle`). |
| `connect_timeout` | float | `5.0` | 1-30 | TCP connect timeout (s) for requests to the API. |
| `read_timeout` | float | `30.0` | 5-120 | Read timeout (s) for requests to the API. |
| `max_retry_attempts` | int | `3` | 1-10 | Total attempts (initial + retries). Only transport errors are retried, never HTTP status codes and never a TLS failure. |
| `path_seed` | map string→string | `{}` | - | Real values for OpenAPI path parameters (`{owner}` → `"alice"`). Unlisted parameters fall back to the test's placeholder (typically `1`). Generate with [`apiguard generate-seed`](cli.md#generate-seed). **Use only test resources you can lose:** the values are used for every request, including `DELETE` and writes sent without credentials (test 1.1); on an API without protection on those endpoints they are deleted or changed. |

Before any test the tool sends one request to `base_url` (`GET /`, recorded in the evidence as test `preflight`). A TLS
failure, or a TLS problem the server reports with an HTTP answer (see [TLS errors](#tls-errors)), stops the run with
exit `10` and the key to set; any other answer, of any status, lets the run go on.

## `specification`

Where the OpenAPI specification is read from: exactly one of `url` and `path`.

| Key | Type | Default | Constraints | Description |
|---|---|---|---|---|
| `url` | URL \| null | `null` | exactly one of `url` / `path` | Downloaded by the tool at runtime (Phase 2), redirects followed, with the settings of `tls`. |
| `path` | path \| null | `null` | see above | Local file (JSON or YAML). Its existence is checked in Phase 2, not by `validate-config`. |
| `timeout` | float | `60.0` | 10-300 | Wall-clock limit for loading the specification (download and `$ref` dereferencing). When it expires the run stops with `OpenAPILoadError` (exit `10`), also if the server accepts the connection and never answers. |
| `tls` | [tls block](#tls-certificates-of-a-connection) | none | - | Certificate settings of the download; ignored (with a warning) for an `http://` URL, unused for `path`. |

Relative `$ref` in a specification read from `url` are not supported (the dereferencing library resolves them only
for files): save the specification and its referenced files locally and use `path`.

## `gateway`

The API gateway in front of the API, for the WHITE_BOX configuration audits (3.3, 4.2, 4.3, 6.4 sub-test B).
Optional: without it those audits return SKIP. With it, `adapter` and `admin.url` are required.

| Key | Type | Default | Constraints | Description |
|---|---|---|---|---|
| `adapter` | string | **required** | `kong`, `apisix` (the adapters listed in `src/core/gateway/__init__.py`) | How the gateway's configuration is read. |
| `admin.url` | URL | **required** | - | The gateway's Admin API. Read with GET requests only. |
| `admin.headers` | map string → string | `{}` | names and values not empty | Headers sent on every Admin API request, for a gateway that protects it: e.g. `X-API-KEY` (APISIX; a key of role `viewer`, GET only, is enough), `Kong-Admin-Token` (Kong Enterprise). Never sent to `health.url`. Write the values as `${VAR}`: they are registered as secrets and masked in logs and reports. |
| `admin.connect_timeout` | float | `5.0` | 1-30 | TCP connect timeout (s) for the Admin API and the health interface. |
| `admin.read_timeout` | float | `10.0` | 1-60 | Read timeout (s) for the Admin API and the health interface. |
| `admin.tls` | [tls block](#tls-certificates-of-a-connection) | none | - | Certificate settings of the Admin API connection (e.g. the client certificate APISIX's `admin_api_mtls` requires). |
| `health.url` | URL | **required** with `health` | - | Interface reporting the live health of the backends, for a gateway that keeps it outside the Admin API: the APISIX Control API (e.g. `http://127.0.0.1:9090`). Read by test 4.3 (observability), without the `admin.headers`. Not used by Kong. Absent on APISIX: the live health is reported as not accessible, the rest of the audits still run. |
| `health.tls` | [tls block](#tls-certificates-of-a-connection) | none | - | Certificate settings of the health interface (APISIX's Control API has no TLS: leave it out). |

An Admin API the tool cannot read (refused, wrong address, certificate not trusted, client certificate missing) is
"not accessible": the audits return SKIP with "Not verifiable: no access to ..." and the reason, which names the key to
set ([security model](../architecture/security-model.md)).

## `tls`: certificates of a connection

Each of `target`, `specification`, `gateway.admin` and `gateway.health` takes an optional `tls` block of this shape
(`src/core/models/tls.py`). Guide, with how to obtain the files: [configure a target, TLS and
certificates](../guides/usage/configure-a-target.md#2-tls-and-certificates).

| Key | Type | Default | Constraints | Description |
|---|---|---|---|---|
| `verify` | bool | `true` | not `false` with `ca_bundle` | Check the server's certificate. `false` accepts any certificate (an impostor too): the report shows the connection as **not verified**. |
| `ca_bundle` | path \| null | `null` | existing file, PEM | The certificate authorities to trust for this connection, **instead of** the default ones (as `curl --cacert`). |
| `client_cert` | path \| null | `null` | existing file, PEM; with `client_key` | The tool's certificate, for a server that asks for mutual TLS. Allowed with `verify: false`. |
| `client_key` | path \| null | `null` | existing file, PEM, not encrypted; with `client_cert` | The private key of `client_cert`. Only the path is configuration: the content is read by the TLS library and never logged. |

**Trust.** Without `tls`, or without `ca_bundle`, a connection trusts the operating system's store (through
`truststore`: a company authority installed by IT, or a proxy inspecting HTTPS, is trusted) plus certifi's list.
`SSL_CERT_FILE` and `SSL_CERT_DIR` do not change it: the configuration does.

**Checked before any test** (exit `10`, also by `validate-config`): the files exist; `client_cert` and `client_key`
together; `verify: false` with `ca_bundle`; the files are PEM, the key belongs to the certificate, the key is not
encrypted (the tool never asks for a password: decrypt it with `openssl pkey -in key.pem -out plain.pem`).
**Warnings** (the run goes on): a `client_key` readable by other users of the machine (`chmod 600`); a `tls` block on
an `http://` URL (ignored).

### TLS errors

A TLS failure is never retried. The message names the problem and the key to set:

| Problem | Where it is detected | What to set |
|---|---|---|
| certificate not trusted | handshake | `<connection>.tls.ca_bundle` (or install the authority in the system's store) |
| name in the URL not in the certificate | handshake | a URL with a name the certificate was issued for |
| certificate expired or not yet valid | handshake | the server's certificate |
| client certificate refused | handshake (alert) | `<connection>.tls.client_cert`, `client_key` |
| client certificate missing / not accepted | HTTP 400 page of nginx (`No required SSL certificate was sent`, `The SSL certificate error`) | `<connection>.tls.client_cert`, `client_key` |
| plain HTTP to an HTTPS port | HTTP 400 page of nginx (`The plain HTTP request was sent to HTTPS port`) | `https://` in the URL |
| HTTPS to a port that does not speak TLS | handshake (`WRONG_VERSION_NUMBER`) | `http://` in the URL, or the right port |

On `target` and `specification` the run stops (exit `10`); on `gateway.admin` and `gateway.health` the audits return
SKIP with the message. nginx, and the gateways built on it (APISIX), complete the handshake without a client
certificate and answer with these pages ([nginx: error processing](https://nginx.org/en/docs/http/ngx_http_ssl_module.html#errors)).

The report states how each connection was trusted (`connections` in the [JSON report](report-schema.md), "Certificate
checks" in the HTML report): `verified_system`, `verified_ca_bundle`, `not_verified`, `plain_http`, `local_file`, and
whether a client certificate was used.

## `credentials`

Accounts used by the tests that log in to the API: `user_a` (a normal user) by the GREY_BOX tests, `admin` (the
API's administrator account) by the WHITE_BOX test 1.4. Always provide values through `${VAR}` placeholders.

| Key | Type | Default | Description |
|---|---|---|---|
| `auth_type` | string \| null | `null` | How a credential is obtained. **Required** when an account or a token is configured. `basic` (HTTP Basic with username and password, RFC 7617), `static_token` (the `<role>_token` values), `login` (the [prepared resource](#resources) `login_resource` is created for each role: its value `credential` is the token; its delete request, if any, deletes the token at the end of the run and lets test 1.4 revoke one). |
| `admin_username`, `admin_password` | string \| null | `null` | Administrator role (`basic`, `login`). |
| `user_a_username`, `user_a_password` | string \| null | `null` | First non-privileged role. |
| `user_b_username`, `user_b_password` | string \| null | `null` | Second non-privileged role. |
| `admin_token`, `user_a_token`, `user_b_token` | string \| null | `null` | `static_token` only: the token of each role. |
| `login_resource` | string \| null | `null` | `login` only, **required** there: the name of a resource of [`resources`](#resources) whose create request logs in for a role (`auth: basic` or `none`) and whose values include `credential`, the dotted path of the token in the response. |
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
`_`, `-`). Used by `credentials.login_resource` and by `tests.domain_7.test_7_2.url_accepting_endpoint.resource`; the test or the
login chooses the role a resource is created for. None by default. Design: [D6](../architecture/design-decisions.md#d6-prepared-resources).

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

The timeouts and retries of the API connection are in [`target`](#target), the specification's timeout in
[`specification`](#specification).

## `output`

| Key | Type | Default | Description |
|---|---|---|---|
| `directory` | path | `outputs` | Destination of `evidence.json`, `assessment_report.html`, `apiguard_report.json`, `config_used.yaml`, `tools/` and the temporary `evidence_tmp/`. Created if missing. |

### The configuration a run used (`config_used.yaml`)

Every run writes `config_used.yaml` in `output.directory` before contacting the target, so it exists also when the
run stops later (`src/config/config_used.py`; `apiguard validate-config --show-config` prints the same text). It
holds every key of the schema, the parameters of every test included, each marked `# specified` (written in your
file) or `# default`. Passed back with `apiguard run --config config_used.yaml`, with the same environment, it runs
the same assessment (verified on the Forgejo + Kong lab: same tests, statuses, findings, oracle states, exit code).

- A value written with a `${VAR}` placeholder is written as you wrote it, quoted or not, never resolved: the tool
  cannot know whether a variable holds a secret, and the re-run resolves it from the same environment.
- A secret written in clear (the usernames, passwords and tokens of `credentials`, the values of
  `gateway.admin.headers`) becomes a placeholder named after its key, e.g. `${APIGUARD_CREDENTIALS_ADMIN_PASSWORD}`,
  with the note `written in clear in your config.yaml: export APIGUARD_CREDENTIALS_ADMIN_PASSWORD to re-run`; the
  re-run stops (exit `10`) naming every such variable until it is exported.
- Any other value is the one the run used, as validated: a relative TLS file becomes an absolute path, a URL may
  gain a final `/`.

## `tests`

Per-test tuning. Defaults produce a complete assessment; set only what you need to change. Structure:
`tests.domain_<D>.test_<D>_<N>.<key>`, derived from the test ID. Each test declares its parameter model in its own
module (`src/tests/domain_<D>/test_<D>_<N>_*.py`, the class `Test<D><N>Params`); 0.3 and the external tests have
none. The section is checked right after the rest of the configuration, once the tests are discovered (also by
`validate-config`): an unknown test or parameter is reported like any unknown key, with the closest name.

The tables below are generated from the parameter models (`scripts/generate_docs.py`); the full default lists
are in [`config.example.yaml`](../../config.example.yaml).

<!-- [[[cog import generate_docs as g; cog.out(g.configuration_tests()) ]]] -->

### `tests.domain_0.test_0_1`

Test [0.1](../tests/domain-0/0-1-shadow-api-discovery.md), All Exposed Endpoints Are Documented and Authorized.

| Key | Type | Default | Description |
|---|---|---|---|
| `method_probe_sample_size` | int 1-100 | `10` | Number of documented endpoints (in spec order) used by the undeclared-method sub-check; parametric ones among them are skipped. Each receives up to about five undeclared methods. Range 1-100, default 10. |

### `tests.domain_0.test_0_2`

Test [0.2](../tests/domain-0/0-2-deny-by-default.md), Gateway Deny-by-Default on Unregistered Paths.

| Key | Type | Default | Description |
|---|---|---|---|
| `gateway_server_identifiers` | list | 7 values (`kong`, `nginx`, …) | Substrings matched case-insensitively against the 'Server' response header to classify a response as generated by the API Gateway layer (not the backend). A response whose Server header does NOT contain any of these substrings is flagged as a deny-by-default violation: the request reached the backend. Default: ['kong', 'nginx', 'openresty', 'apache', 'caddy', 'traefik', 'envoy']. Extend when deploying gateways not in this list (HAProxy, Tyk, APISIX). Never add application server names (Gunicorn, uWSGI): that defeats the check. |

### `tests.domain_1.test_1_1`

Test [1.1](../tests/domain-1/1-1-authentication-required.md), Only Authenticated Requests Access Protected Resources.

| Key | Type | Default | Description |
|---|---|---|---|
| `max_endpoints_cap` | int ≥0 | `0` | Maximum number of protected endpoints that Test 1.1 will probe. 0 means test ALL protected endpoints declared in the OpenAPI spec (recommended for complete academic coverage). Set to a positive integer only when the target API enforces strict rate limiting that would cause 429 responses during a full scan, or when the operator requires a time-bounded assessment. |

### `tests.domain_1.test_1_4`

Test [1.4](../tests/domain-1/1-4-token-revocation.md), Revoked Token Rejected After Deletion.

| Key | Type | Default | Description |
|---|---|---|---|
| `protected_endpoint` | object \| null | none, **needed to run** | An endpoint of the API that requires authentication: method (default GET) and path. The test sends the revoked credential to it, which must be rejected. No default: unset, the test returns SKIP. |
| `protected_endpoint.method` | string | `GET` | HTTP method. Default GET. |
| `protected_endpoint.path` | string | required | Path of an endpoint that requires authentication and answers 2xx to a valid credential, e.g. '/api/v1/user'. |

### `tests.domain_1.test_1_5`

Test [1.5](../tests/domain-1/1-5-insecure-credential-transport.md), Credentials Not Transmitted via Insecure Channels.

| Key | Type | Default | Description |
|---|---|---|---|
| `hsts_min_max_age_seconds` | int ≥86400 | `31536000` | Minimum acceptable max-age value (seconds) in the Strict-Transport-Security header. NIST SP 800-52 Rev.2, OWASP ASVS v5.0.0 V12.1.1. Default: 31536000 (1 year). |
| `http_probe_enabled` | bool | `true` | If True, probe the HTTP base URL for redirect enforcement (sub-test 1). Set False only if port 80 is filtered at the network level and any connection attempt would block for the full timeout. Default: True. |
| `http_url` | string | `""` | A URL of the API in plain HTTP, checked for a redirect to HTTPS (sub-test 1). When non-empty, this URL is used directly instead of deriving the HTTP counterpart from the HTTPS base URL. Use in non-standard port lab setups where the HTTPS base URL uses a port other than 443 (e.g. https://localhost:8443 -> derive produces http://localhost:8443/ which hits the gateway's TLS listener and returns 400). Example: 'http://localhost:8000/' to probe the gateway's HTTP listener. Empty string (default) falls back to the derived URL. |
| `http_probe_timeout_seconds` | number ≥1.0 | `5.0` | Connect + read timeout (seconds) for the HTTP redirect probe. Keep short: a TCP RST is returned immediately for refused connections. Default: 5.0. |
| `expected_redirect_status_codes` | list | `301`, `308` | HTTP status codes that satisfy the redirect oracle in sub-test 1. RFC 9110 permanent redirects: 301 (Moved Permanently) and 308 (Permanent Redirect). Temporary redirects 302/307 are NOT accepted: they allow MITM-driven downgrade attacks. Default: [301, 308]. |

### `tests.domain_1.test_1_6`

Test [1.6](../tests/domain-1/1-6-secure-session-management.md), Secure Session Management in Distributed Architectures.

| Key | Type | Default | Description |
|---|---|---|---|
| `session_cookie_paths` | list | `/` | Paths of the API that set session cookies, read with a GET to collect them. The test sends a GET to each path (unauthenticated) and collects all Set-Cookie headers. Extend this list to cover login pages or API roots that issue cookies. Default: ['/']. |
| `session_cookie_names` | list | 8 values (`session`, `sid`, …) | Case-insensitive cookie names treated as session identifiers. Cookies whose name appears in this list are subject to the HttpOnly / Secure / SameSite attribute audit. Default: well-known session cookie names across common web frameworks. |
| `check_samesite` | bool | `true` | If True, validate the SameSite attribute on session cookies. OWASP ASVS v5.0.0 V3.2.3 requires SameSite to prevent CSRF. Set False only when the application legitimately requires cross-site cookies and the risk is documented and accepted. Default: True. |
| `expected_samesite_value` | string | `Strict` | Expected value for the SameSite cookie attribute (case-insensitive). Accepted: 'Strict' (recommended, ASVS V3.2.3), 'Lax' (acceptable for applications that require cross-origin GET requests). 'None' is never acceptable for a session cookie. Default: 'Strict'. |

### `tests.domain_2.test_2_1`

Test [2.1](../tests/domain-2/2-1-rbac-enforcement.md), Only Authorized Users Access Privileged Endpoints.

| Key | Type | Default | Description |
|---|---|---|---|
| `admin_endpoint_paths` | list | empty, **needed to run** | Admin-only endpoint paths of the target to probe with a non-privileged token (OWASP ASVS v5.0.0 V8.3.1), each starting with '/'. No default: the admin paths depend on the API, and a path the API does not have would answer 404 and pass. Empty: the test returns SKIP. Example (Forgejo): ['/api/v1/admin/users']. |
| `admin_endpoint_method` | string | `GET` | HTTP method to use when probing each admin endpoint. Default: 'GET'. |

### `tests.domain_3.test_3_3`

Test [3.3](../tests/domain-3/3-3-hmac-config-audit.md), HMAC Authentication Configuration Does Not Allow Replay or Weak Algorithms.

| Key | Type | Default | Description |
|---|---|---|---|
| `max_clock_skew_seconds` | int ≥1 | `300` | Maximum acceptable replay window (in seconds) of a signing policy (the allowed difference between the request's date and the gateway's clock). A larger window increases the replay-attack surface: an attacker who captures a signed request can replay it until the window expires. NIST SP 800-107 Rev. 1 Section 5.3.2 recommends <= 300 s (5 minutes). Default: 300. |
| `forbidden_algorithms` | list | `hmac-sha1`, `hmac-md5` | HMAC algorithms whose presence in a signing policy's allowed list constitutes a security finding. 'hmac-md5': cryptographically broken (RFC 6151); must never be used. 'hmac-sha1': deprecated per NIST SP 800-131A Rev. 2 and PCI-DSS v4 Requirement 12.3.3; acceptable to remove from this list only if the deployment has a documented exception. Default: ['hmac-sha1', 'hmac-md5']. |

### `tests.domain_4.test_4_1`

Test [4.1](../tests/domain-4/4-1-rate-limiting.md), Rate Limiting -- Resource Exhaustion Prevention.

| Key | Type | Default | Description |
|---|---|---|---|
| `max_requests` | int 10-500 | `150` | Maximum probe requests sent before concluding rate limiting is absent. Range: [10, 500]. Default: 150. |
| `request_interval_ms` | int 10-5000 | `50` | Interval in milliseconds between consecutive probe requests. Range: [10, 5000]. Default: 50 ms. |

### `tests.domain_4.test_4_2`

Test [4.2](../tests/domain-4/4-2-timeout-config-audit.md), Timeout Configuration Audit -- Prevention of Resource Lock.

| Key | Type | Default | Description |
|---|---|---|---|
| `max_connect_timeout_ms` | int ≥1 | `5000` | Maximum acceptable backend connect timeout of a gateway service, in milliseconds. Methodology oracle: connect_timeout <= 5 000 ms (NIST SP 800-204A Section 4.3). Services with a higher value will produce a FAIL finding. |
| `max_read_timeout_ms` | int ≥1 | `30000` | Maximum acceptable backend read timeout of a gateway service, in milliseconds. Methodology oracle: read_timeout <= 30 000 ms (NIST SP 800-204A Section 4.3). Services with a higher value will produce a FAIL finding. |
| `max_write_timeout_ms` | int ≥1 | `30000` | Maximum acceptable backend write (send) timeout of a gateway service, in milliseconds. Methodology oracle: write_timeout <= 30 000 ms. Services with a higher value will produce a FAIL finding. |

### `tests.domain_4.test_4_3`

Test [4.3](../tests/domain-4/4-3-circuit-breaker-audit.md), Circuit Breaker Audit -- Dual-Check a 3 Livelli.

| Key | Type | Default | Description |
|---|---|---|---|
| `failure_threshold_min` | int ≥1 | `3` | Minimum acceptable failure threshold to open the circuit. Methodology range: [3, 10] consecutive failures. A threshold below this minimum is too sensitive (alert fatigue). |
| `failure_threshold_max` | int ≥1 | `10` | Maximum acceptable failure threshold to open the circuit. Methodology range: [3, 10] consecutive failures. A threshold above this maximum leaves the system exposed too long. |
| `timeout_duration_min_seconds` | int ≥1 | `30` | Minimum acceptable Open-state duration in seconds before Half-Open probe. Methodology range: [30, 120] s (Martin Fowler Circuit Breaker Pattern). A shorter window may not allow the downstream service to recover. |
| `timeout_duration_max_seconds` | int ≥1 | `120` | Maximum acceptable Open-state duration in seconds before Half-Open probe. Methodology range: [30, 120] s. A longer window unnecessarily degrades availability. |
| `passive_hc_max_http_failures` | int ≥1 | `10` | Maximum acceptable value for unhealthy.http_failures in an upstream's passive healthcheck. A passive HC is considered active when this counter is > 0 (0 disables it). Acceptable range: [1, this value]. Values above the maximum indicate an overly permissive threshold. |
| `passive_hc_max_tcp_failures` | int ≥1 | `10` | Maximum acceptable value for unhealthy.tcp_failures in an upstream's passive healthcheck. Same semantics as passive_hc_max_http_failures but for TCP-level connection failures. |
| `passive_hc_max_timeouts` | int ≥1 | `10` | Maximum acceptable value for unhealthy.timeouts in an upstream's passive healthcheck. Same semantics as passive_hc_max_http_failures but for upstream response timeouts. |

### `tests.domain_6.test_6_2`

Test [6.2](../tests/domain-6/6-2-security-headers-audit.md), Security Headers Configured Appropriately.

| Key | Type | Default | Description |
|---|---|---|---|
| `hsts_min_max_age_seconds` | int ≥1 | `31536000` | Minimum acceptable max-age value in the Strict-Transport-Security header. ASVS V3.4.1 requires max-age >= 31 536 000 (one year). An HSTS header present but with a lower max-age is flagged as a FAIL. Default: 31536000 seconds (1 year). |
| `endpoint_sample_size` | int ≥0 | `5` | Number of endpoints to sample for cross-endpoint header consistency check. 0 = all endpoints in the AttackSurface (complete coverage). Any positive integer caps the sample at that count, using the first N endpoints returned by the AttackSurface iterator. The consistency check compares each sampled endpoint's security headers against the reference set obtained from the first endpoint. Default: 5. |

### `tests.domain_6.test_6_4`

Test [6.4](../tests/domain-6/6-4-hardcoded-credentials-audit.md), Service Credentials Not Hardcoded or Exposed.

| Key | Type | Default | Description |
|---|---|---|---|
| `debug_endpoint_paths` | list | 10 values (`/actuator/env`, `/actuator/configprops`, …) | List of paths to probe for debug / actuator endpoint exposure. Each path is probed with an unauthenticated GET request. A 2xx response whose body contains credential-like patterns is a FAIL. Extend this list with stack-specific debug paths in config.yaml (e.g. Laravel Telescope: '/_ignition/health-check', Django Silk: '/silk/summary/'). Removing paths from the default list narrows coverage. Default: ['/actuator/env', '/actuator/configprops', '/actuator/health', '/debug/vars', '/debug/pprof', '/api/config', '/admin/config', '/_debug', '/api/debug/users', '/api/debug/config']. |
| `gateway_block_body_fragment` | string | `no Route matched with those values` | A substring present in the response body of a non-2xx reply produced by the Gateway itself (deny-by-default), as opposed to a reply forwarded to and rejected by the upstream application. Used to distinguish oracle states ENDPOINT_BLOCKED (Gateway) from ENDPOINT_BLOCKED_BY_APP (application) in the audit trail. Default is specific to Kong DB-less 3.x. Override for other gateways: Traefik: '404 page not found' AWS API Gateway: 'Missing Authentication Token' Nginx: '<title>404 Not Found</title>' HAProxy: '503 Service Unavailable'. Set to an empty string to disable the distinction entirely (all non-2xx responses will be classified as ENDPOINT_BLOCKED). |

### `tests.domain_7.test_7_2`

Test [7.2](../tests/domain-7/7-2-ssrf-prevention.md), Server-Side Request Forgery (SSRF) Prevention.

| Key | Type | Default | Description |
|---|---|---|---|
| `payload_categories` | list | 6 values (`cloud_metadata`, `private_ip`, …) | Payload categories to include in the SSRF probe. Valid values: 'cloud_metadata', 'private_ip', 'encoding_bypass', 'forbidden_protocol', 'dns_bypass', 'url_parser_confusion'. Removing a category reduces coverage; the omitted sub-test is not reported as SKIP -- the category is simply not probed. Default: all six categories ['cloud_metadata', 'private_ip', 'encoding_bypass', 'forbidden_protocol', 'dns_bypass', 'url_parser_confusion']. |
| `url_accepting_endpoint` | object \| null | none, **needed to run** | An endpoint of the API that accepts a URL from the client and makes the server call it (a webhook, an import from a URL): path, body and, optionally, a prepared resource. The test sends the SSRF payload URLs to it. No default: unset, the test returns SKIP. |
| `url_accepting_endpoint.path` | string | required | Path of the endpoint (POST). With resource it may hold the resource's values, e.g. '/api/v1/repos/{owner}/{repo}/hooks'. |
| `url_accepting_endpoint.body` | object | required | JSON body of the request. Must contain "{ssrf_url}" exactly once, replaced by each payload URL; may contain "{random_secret}" (32 random hexadecimal characters) and, with resource, the resource's values. Placeholders in quotes. |
| `url_accepting_endpoint.resource` | string \| null | none | Name of a prepared resource (resources: in config.yaml) created for user A before probing; its values fill the placeholders of path and body, and it is deleted at teardown. Optional: without it the path is used as written. |
| `ssrf_redirect_server_url` | string | `""` | URL of an operator-controlled public server that responds with 302 Location pointing to an internal SSRF target (e.g. http://169.254.169.254/...). When non-empty, sub-test G (redirect following) is executed: the injection URL is set to this server and the oracle checks whether the application re-validates the redirected target URL. When empty (default), sub-test G is SKIPPED with an InfoNote documenting the gap. This server must be reachable from the test runner's network and must be under your control. Default: '' (empty -- redirect sub-test skipped). |
| `ssrf_block_response_keywords` | list | 11 values (`invalid host`, `not allowed`, …) | Case-insensitive substrings checked against the response body of non-2xx SSRF probe responses. A match classifies the oracle state as SSRF_BLOCKED_BY_VALIDATION (explicit URL rejection). No match produces SSRF_BLOCKED_UNKNOWN (URL rejected for an unspecified reason). Both states produce no Finding. Override with gateway- or application-specific error message fragments for more precise Audit Trail classification. Default: ['invalid host', 'not allowed', 'forbidden', 'scheme not supported', 'scheme not allowed', 'host not allowed', 'private', 'loopback', 'blocked', 'disallowed', 'restricted']. |
| `ssrf_malformed_url_keywords` | list | 8 values (`invalid character`, `invalid url`, …) | Case-insensitive substrings that, when found in a non-2xx SSRF probe response body, indicate the URL was rejected because it is syntactically invalid to the HTTP parser -- NOT because of an explicit SSRF defence and NOT because the scheme is unsupported. Checked FIRST (Level 1). A match produces oracle state SSRF_BLOCKED_AS_MALFORMED_URL. No Finding is generated; the distinction only affects the Audit Trail column of the HTML report. Example: Go's net/url rejects 'http://%31%32%37...' with 'invalid character'; this is a parser side-effect, not an SSRF-aware block. Default: ['invalid character', 'invalid url', 'url malformed', 'malformed url', 'parse error', 'url parse', 'could not parse', 'bad url']. |
| `ssrf_unsupported_scheme_keywords` | list | 8 values (`scheme not supported`, `scheme not allowed`, …) | Case-insensitive substrings that, when found in a non-2xx SSRF probe response body, indicate the URL was rejected because its scheme (protocol) is not accepted by the application -- NOT because the URL is syntactically malformed and NOT because of an explicit SSRF IP/range defence. Checked SECOND (Level 2), after ssrf_malformed_url_keywords. A match produces oracle state SSRF_BLOCKED_UNSUPPORTED_SCHEME. No Finding is generated. Important: in Forgejo/Go, 'file://', 'gopher://', 'dict://' etc. are rejected with the same 'Invalid url' message as malformed URLs. The test therefore also checks the injected URL's scheme directly when the response body gives no clear signal -- these keywords serve as a fallback for application stacks with more descriptive error messages. Default: ['scheme not supported', 'scheme not allowed', 'unsupported scheme', 'unsupported protocol', 'invalid scheme', 'only http', 'only https', 'protocol not allowed']. |
| `ssrf_request_timeout_ms` | int ≥1000 | `10000` | Intended timeout in milliseconds for individual SSRF probe requests. Reserved for future per-request timeout override support in SecurityClient. Currently the global target.read_timeout governs all requests; this field documents the operator's intent and will be honoured automatically once SecurityClient supports per-request timeout overrides. NIST SP 800-204 Section 3.2.2 recommends tight timeouts on outbound connections from API servers. Default: 10000 ms (10 s). Minimum: 1000 ms. |

<!-- [[[end]]] -->

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
| `timeout_seconds` | int \| null | `null` | **Required when `enabled: true`** (Phase 1 error otherwise). Ranges: testssl ≥30, nuclei ≥60 (no upper bound), sslyze 30-300. For testssl and nuclei: wall-clock limit of one execution, which only stops a tool that hangs: set it to 2-3 times the duration seen on your target; a tool that ends after more than 70% of it logs the warning `external_tool_near_time_limit` with the value to raise. For sslyze: timeout of each TLS connection, not of the whole scan. |
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
| Exactly one specification source | `specification.url`, `specification.path` |
| With `gateway`: `adapter` (`kong` or `apisix`) and `admin.url`; with `health`: `health.url` | `gateway.*` |
| `tls` blocks: files exist; `client_cert` with `client_key`; not `verify: false` with `ca_bundle`; PEM files, key matching the certificate, key not encrypted | `*.tls` |
| `auth_type` set when credentials are configured, supported value; `login` needs `login_resource`, only `login` takes it; each method's own credential keys only; `basic` without `security_scheme` / `send_as` | `credentials.*` |
| The login resource exists, has the value `credential`, and its create request does not use `auth: credential` | `credentials.login_resource`, `resources` |
| Resource names (letters, digits, `_`, `-`); paths start with `/`; methods `GET` `POST` `PUT` `PATCH` `DELETE`; placeholders well formed, known where used (no response value in `create`), quoted in YAML; value names not `username` / `password` / `random` | `resources.*` |
| 7.2: `url_accepting_endpoint` has `path` and `body`; its `resource` is defined; path and body placeholders known; `{ssrf_url}` exactly once (checked with the tests section, against `resources`) | `tests.domain_7.test_7_2.url_accepting_endpoint` |
| 1.4: `protected_endpoint` path starts with `/`, supported method | `tests.domain_1.test_1_4.protected_endpoint` |
| Username and password set together per role | `credentials.*` |
| The credentials determine where they are sent (`security_scheme`, `send_as` against the specification's schemes; checked after the specification is read) | `credentials.security_scheme`, `credentials.send_as` |
| `strategies` not empty | `execution.strategies` |
| `test_ids` format `X.Y` or `ext.X.Y.tool` | `execution.test_ids` |
| `test_ids` entries exist and their tool is enabled (checked right after Phase 1, also by `validate-config`) | `execution.test_ids` |
| Enabled tool has `timeout_seconds` | `external_tools.<tool>.*` |
| `session_cookie_names` not empty | `tests.domain_1.test_1_6` |
| min ≤ max ranges | `tests.domain_4.test_4_3` |
| Numeric ranges and types in the tables above | all |

A test that needs something the configuration does not give (`Needs` in the [test catalogue](../tests/README.md):
the credentials of a role, a gateway, a login that can revoke a credential, or a parameter marked **needed to run**
in the tables above) is not an error: the engine records it as SKIP without running it, naming what is missing
("Needs USER_ACCOUNT: the credentials of the user_a role are not configured (credentials.user_a_*)."). The run
**warns** before the first test (log event `test_will_skip_unmet_needs`, fields `test_id` and `reason`);
`validate-config` and `list-tests --config` say the same without contacting the target.

## See also

- [`cli.md`](cli.md) - `validate-config`, `list-tests`, `generate-seed`
- [`exit-codes.md`](exit-codes.md)
- [`config.example.yaml`](../../config.example.yaml) - every key, with description and default
- [`test-environments/forgejo-kong/config.yaml`](../../test-environments/forgejo-kong/config.yaml) - configuration of the Forgejo + Kong lab
- [`test-environments/crapi-kong/config.yaml`](../../test-environments/crapi-kong/config.yaml) - configuration of the crAPI + Kong lab
- [`test-environments/forgejo-apisix/config.yaml`](../../test-environments/forgejo-apisix/config.yaml) - configuration of the Forgejo + APISIX lab (Admin API key and client certificate, Control API)

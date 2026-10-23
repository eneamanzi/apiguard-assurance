# Configuration Reference (`config.yaml`)

> **Audience:** users, integrators · **Status:** stable · **Source of truth:** `src/config/schema/tool_config.py`,
> the parameter models in the test modules (`src/tests/domain_*/test_*.py`, `src/config/tests_section.py`),
> `src/core/models/external_tools.py`, `src/core/models/resources.py`,
> `src/config/loader.py`, `src/core/models/tls.py` · **Verified:** 2026-10-15 (connections: `target`, `specification`,
> `gateway`, `tls`), 2026-10-14 (credentials, resources), 2026-10-12 (gateway keys), 2026-10-05, v0.1.0 (field list extracted from the Pydantic models; behaviours tested with
> `apiguard validate-config`)

Every field, type, default and constraint below comes from the Pydantic models. For a guided setup see
[`guides/usage/configure-a-target.md`](../02-guides/01-usage/01-configure-a-target.md); the complete example in the repository, with every key, its description and its default, is
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
     ([details](02-cli.md#environment-and-env)); variables already in the environment win.
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
default). Which tests are affected is stated on each test page ([`tests/`](../05-tests/README.md)); `validate-config` lists the
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

<!-- [[[cog import generate_docs as g; cog.out(g.configuration_table("target")) ]]] -->

| Key | Type | Default | Description |
|---|---|---|---|
| `base_url` | URL | **required** | Base URL of the API as exposed through the gateway proxy, e.g. https://api.example.com. |
| `connect_timeout` | number 1-30 | `5.0` | TCP connect timeout (s) for requests to the API. |
| `read_timeout` | number 5-120 | `30.0` | Read timeout (s) for requests to the API. |
| `max_retry_attempts` | int 1-10 | `3` | Total attempts (initial + retries). Only transport errors are retried, never HTTP status codes and never a TLS failure. |
| `tls` | [tls block](#tls-certificates-of-a-connection) | none | Certificate settings of the API connection, also used by the HTTP-redirect probe of test 1.5 and given to the external TLS tests (`ca_bundle`). |
| `path_seed` | map string → string | `{}` | Real values for OpenAPI path parameters (`{owner}` → `"alice"`). Unlisted parameters fall back to the test's placeholder (typically `1`; `apiguard-probe` in a DELETE, so that it matches no real resource). Generate with `apiguard generate-seed`. **Use only test resources you can lose:** the values are used for every request, including `DELETE` and writes sent without credentials (test 1.1); on an API without protection on those endpoints they are deleted or changed. |

<!-- [[[end]]] -->

Before any test the tool sends one request to `base_url` (`GET /`, recorded in the evidence as test `preflight`). A TLS
failure, or a TLS problem the server reports with an HTTP answer (see [TLS errors](#tls-errors)), stops the run with
exit `10` and the key to set; any other answer, of any status, lets the run go on.

## `specification`

Where the OpenAPI specification is read from: exactly one of `url` and `path`.

<!-- [[[cog import generate_docs as g; cog.out(g.configuration_table("specification")) ]]] -->

| Key | Type | Default | Description |
|---|---|---|---|
| `url` | URL \| null | none | Downloaded by the tool at runtime (Phase 2), redirects followed, with the settings of `tls`. Exactly one of `url` and `path`. |
| `path` | path \| null | none | Local file (JSON or YAML), relative to the working directory. Exactly one of `url` and `path`. Its existence is checked when the specification is loaded (Phase 2; `validate-config` only when credentials are configured). Remote `$ref` entries inside it still need network access. |
| `timeout` | number 10-300 | `60.0` | Timeout (s) of the download (the connection and each read), and, separately, the limit of the `$ref` dereferencing as a whole. When one expires the run stops with exit `10`, also if the server accepts the connection and never answers. |
| `tls` | [tls block](#tls-certificates-of-a-connection) | none | Certificate settings of the download; ignored (with a warning) for an `http://` URL, unused for `path`. |

<!-- [[[end]]] -->

Relative `$ref` in a specification read from `url` are not supported (the dereferencing library resolves them only
for files): save the specification and its referenced files locally and use `path`.

## `gateway`

The API gateway in front of the API, for the WHITE_BOX configuration audits (3.3, 4.2, 4.3, 6.4 sub-test B).
Optional: without it those audits return SKIP. With it, `adapter` and `admin.url` are required.

<!-- [[[cog import generate_docs as g; cog.out(g.configuration_table("gateway")) ]]] -->

| Key | Type | Default | Description |
|---|---|---|---|
| `adapter` | string | **required** | How the gateway's configuration is read: `kong`, `apisix`. |
| `admin.url` | URL | **required** | The gateway's Admin API, read with GET requests only by the configuration audits (3.3, 4.2, 4.3, 6.4 sub-test B). |
| `admin.headers` | map string → string | `{}` | Headers sent on every Admin API request, for a gateway that protects it: e.g. `X-API-KEY` (APISIX; a key of role `viewer`, GET only, is enough), `Kong-Admin-Token` (Kong Enterprise). Names and values not empty. Never sent to `health.url`. Write the values as `${VAR}`: they are registered as secrets and masked in logs and reports. |
| `admin.connect_timeout` | number 1-30 | `5.0` | TCP connect timeout (s) for the Admin API and the health interface. |
| `admin.read_timeout` | number 1-60 | `10.0` | Read timeout (s) for the Admin API and the health interface. |
| `admin.tls` | [tls block](#tls-certificates-of-a-connection) | none | Certificate settings of the Admin API connection (e.g. the client certificate APISIX's `admin_api_mtls` requires). |
| `health` | object \| null | none | The gateway's health interface, when separate from the Admin API (APISIX). |
| `health.url` | URL | required with `health` | Interface reporting the live health of the backends, for a gateway that keeps it outside the Admin API: the APISIX Control API (e.g. `http://127.0.0.1:9090`). Read by test 4.3 (observability), without the `admin.headers`. Not used by Kong. Absent on APISIX: the live health is reported as not accessible, the rest of the audits still run. |
| `health.tls` | [tls block](#tls-certificates-of-a-connection) | none | Certificate settings of the health interface (APISIX's Control API has no TLS: leave it out). |

<!-- [[[end]]] -->

An Admin API the tool cannot read (refused, wrong address, certificate not trusted, client certificate missing) is
"not accessible": the audits return SKIP with "Not verifiable: no access to ..." and the reason, which names the key to
set ([security model](../04-architecture/04-security-model.md)).

## `tls`: certificates of a connection

Each of `target`, `specification`, `gateway.admin` and `gateway.health` takes an optional `tls` block of this shape
(`src/core/models/tls.py`). Guide, with how to obtain the files: [configure a target, TLS and
certificates](../02-guides/01-usage/01-configure-a-target.md#2-tls-and-certificates).

<!-- [[[cog import generate_docs as g; cog.out(g.tls_block_table()) ]]] -->

| Key | Type | Default | Description |
|---|---|---|---|
| `verify` | bool | `true` | Check the server's certificate. `false` accepts any certificate (an impostor too): the report shows the connection as **not verified**. Not `false` with `ca_bundle`. |
| `ca_bundle` | path \| null | none | The certificate authorities to trust for this connection (an existing PEM file), **instead of** the default ones (as `curl --cacert`). |
| `client_cert` | path \| null | none | The tool's certificate (an existing PEM file, with `client_key`), for a server that asks for mutual TLS. Allowed with `verify: false`. |
| `client_key` | path \| null | none | The private key of `client_cert` (an existing PEM file, not encrypted, with `client_cert`). Only the path is configuration: the content is read by the TLS library and never logged. |

<!-- [[[end]]] -->

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

The report states how each connection was trusted (`connections` in the [JSON report](04-report-schema.md), "Certificate
checks" in the HTML report): `verified_system`, `verified_ca_bundle`, `not_verified`, `plain_http`, `local_file`, and
whether a client certificate was used.

## `credentials`

Accounts used by the tests that log in to the API: `user_a` (a normal user) by the GREY_BOX tests, `admin` (the
API's administrator account) by the WHITE_BOX test 1.4. Always provide values through `${VAR}` placeholders.

<!-- [[[cog import generate_docs as g; cog.out(g.configuration_table("credentials")) ]]] -->

| Key | Type | Default | Description |
|---|---|---|---|
| `auth_type` | `basic` \| `static_token` \| `login` \| null | none | How a credential is obtained. **Required** when an account or a token is configured. `basic` (HTTP Basic with username and password, RFC 7617), `static_token` (the `<role>_token` values), `login` (the prepared resource `login_resource` is created for each role: its value `credential` is the token; its delete request, if any, deletes the token at the end of the run and lets test 1.4 revoke one). |
| `admin_username` | string \| null | none | Username of the administrator role (`basic`, `login`). Not a secret: it may appear in the outputs (e.g. in a path). |
| `admin_password` | string \| null | none | Password of the administrator role (`basic`, `login`). Write it as a `${VAR}` placeholder: never logged, and masked in every output when it has 8 characters or more. |
| `user_a_username` | string \| null | none | Username of the first non-privileged role (`basic`, `login`). Not a secret: it may appear in the outputs (e.g. in a path). |
| `user_a_password` | string \| null | none | Password of the first non-privileged role (`basic`, `login`). Write it as a `${VAR}` placeholder: never logged, and masked in every output when it has 8 characters or more. |
| `user_b_username` | string \| null | none | Username of the second non-privileged role (`basic`, `login`). Not a secret: it may appear in the outputs (e.g. in a path). |
| `user_b_password` | string \| null | none | Password of the second non-privileged role (`basic`, `login`). Write it as a `${VAR}` placeholder: never logged, and masked in every output when it has 8 characters or more. |
| `admin_token` | string \| null | none | `static_token` only: the token of the administrator role. Write it as a `${VAR}` placeholder: never logged, and masked in every output when it has 8 characters or more. |
| `user_a_token` | string \| null | none | `static_token` only: the token of the first non-privileged role. Write it as a `${VAR}` placeholder: never logged, and masked in every output when it has 8 characters or more. |
| `user_b_token` | string \| null | none | `static_token` only: the token of the second non-privileged role. Write it as a `${VAR}` placeholder: never logged, and masked in every output when it has 8 characters or more. |
| `login_resource` | string \| null | none | `login` only, **required** there: the name of a prepared resource (`resources`) whose create request logs in for a role (`auth: basic` or `none`) and whose values include `credential`, the dotted path of the token in the response. |
| `security_scheme` | string \| null | none | Name of the specification's security scheme the credential is sent with. **Required** when the specification declares more than one scheme that can carry a token (e.g. Forgejo: `AuthorizationHeaderToken`). Not with `basic`. |
| `send_as` | object \| null | none | Where and how the credential is sent. Every field left out comes from the specification's scheme; with no usable scheme `in` and `name` are required. With a declared scheme `in` and `name` may only repeat the scheme's, and a `prefix` is allowed only for an `apiKey` scheme (Forgejo: `prefix: "token "`). Not with `basic`. |
| `send_as.in` | `header` \| `query` \| `cookie` \| null | none | Where the credential is sent: `header`, `query` or `cookie`. |
| `send_as.name` | string \| null | none | Name of the header, query parameter or cookie. |
| `send_as.prefix` | string \| null | none | Text written before the credential, spaces included (Forgejo: `"token "`). |

<!-- [[[end]]] -->

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
login chooses the role a resource is created for. None by default. Design: [D6](../04-architecture/05-design-decisions.md#d6-prepared-resources).

<!-- [[[cog import generate_docs as g; cog.out(g.configuration_table("resources")) ]]] -->

| Key | Type | Default | Description |
|---|---|---|---|
| `<name>.create.path` | string | **required** | Path, starting with `/`; may use `{username}`, `{password}`, `{random}` and, in a delete request, the names of `values`. |
| `<name>.create.auth` | `credential` \| `basic` \| `none` | `credential` | How the request authenticates: `credential` (the role's credential, sent as `credentials` says), `basic` (HTTP Basic with the role's username and password), `none` (nothing). |
| `<name>.create.method` | string | `POST` | Method of the create request: `GET`, `POST`, `PUT`, `PATCH` or `DELETE`. |
| `<name>.create.body` | JSON | none | JSON body; strings may use the same placeholders as the path, in quotes. |
| `<name>.values` | map string → string | `{}` | Values read from the JSON response, name → dotted path through objects (no array indexes), e.g. `owner: owner.login`; the value found must be a string or a number. A login resource needs `credential` (always masked as a secret); other values are not secrets. |
| `<name>.delete` | object \| null | none | The request that deletes the resource at teardown; without it nothing is deleted. |
| `<name>.delete.path` | string | required with `delete` | Path, starting with `/`; may use `{username}`, `{password}`, `{random}` and, in a delete request, the names of `values`. |
| `<name>.delete.auth` | `credential` \| `basic` \| `none` | `credential` | How the request authenticates: `credential` (the role's credential, sent as `credentials` says), `basic` (HTTP Basic with the role's username and password), `none` (nothing). |
| `<name>.delete.method` | string | `DELETE` | Method of the delete request, sent at teardown with the same role: `GET`, `POST`, `PUT`, `PATCH` or `DELETE`. A delete request has no body. |

<!-- [[[end]]] -->

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

<!-- [[[cog import generate_docs as g; cog.out(g.configuration_table("execution")) ]]] -->

| Key | Type | Default | Description |
|---|---|---|---|
| `min_priority` | int 0-3 | `3` | **Highest** priority level included (the name is historical): `0` = P0 only, `3` = all. |
| `strategies` | list of `BLACK_BOX` \| `GREY_BOX` \| `WHITE_BOX` | `BLACK_BOX`, `GREY_BOX`, `WHITE_BOX` | Tests, native and external, whose strategy is not listed are excluded (ignored when `test_ids` is set). Not empty. |
| `fail_fast` | bool | `false` | Stop after the first P0 test returning FAIL, ERROR or INCONCLUSIVE. |
| `test_ids` | list | empty | Not empty: run **only** the listed tests, native (`X.Y`) or external (`ext.X.Y.tool`); `min_priority` and `strategies` are then ignored. It chooses only among available tests: an ID that does not exist, or an external test whose tool is disabled (`external_tools`), stops the tool at startup (exit `10`) with the reason and, for an unknown ID, the closest existing ID. |

<!-- [[[end]]] -->

The timeouts and retries of the API connection are in [`target`](#target), the specification's timeout in
[`specification`](#specification).

## `output`

<!-- [[[cog import generate_docs as g; cog.out(g.configuration_table("output")) ]]] -->

| Key | Type | Default | Description |
|---|---|---|---|
| `directory` | path | `outputs` | Destination of `evidence.json`, `assessment_report.html`, `apiguard_report.json`, `config_used.yaml`, `tools/` and the temporary `evidence_tmp/`, relative to the working directory. Created if missing. |

<!-- [[[end]]] -->

### The configuration a run used (`config_used.yaml`)

Every run writes `config_used.yaml` in `output.directory` before contacting the target, so it exists also when the
run stops later (`src/config/config_used.py`; `apiguard validate-config --show-config` prints the same text). It
holds every key of the schema, the parameters of every test included, each marked `# specified` (written in your
file) or `# default`. Passed back with `apiguard run --config config_used.yaml`, with the same environment, it runs
the same assessment (verified on the Forgejo + Kong lab: same tests, statuses, findings, oracle states, exit code).

- A value written with a `${VAR}` placeholder is written as you wrote it, quoted or not, never resolved: the tool
  cannot know whether a variable holds a secret, and the re-run resolves it from the same environment.
- A secret written in clear (the passwords and tokens of `credentials`, the values of
  `gateway.admin.headers`; the usernames are not secrets) becomes a placeholder named after its key, e.g. `${APIGUARD_CREDENTIALS_ADMIN_PASSWORD}`,
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

### `tests.domain_1.test_1_5`

Test [1.5](../05-tests/domain-1/1-5-credentials-over-an-insecure-channel.md), Credentials Over an Insecure Channel.

| Key | Type | Default | Description |
|---|---|---|---|
| `hsts_min_max_age_seconds` | int ≥86400 | `31536000` | Lowest acceptable max-age (seconds) in the Strict-Transport-Security header. NIST SP 800-52 Rev.2, OWASP ASVS v5.0.0-3.4.1 ask for at least one year. Default: 31536000 (one year). |
| `http_url` | string | `""` | The API in plain HTTP, when its HTTP listener is on a non-standard port: only the origin (scheme://host[:port]) is used, the path is derived from the specification. Empty (default) derives the origin from base_url (scheme to http, port 443 dropped). |

### `tests.domain_2.test_2_2`

Test [2.2](../05-tests/domain-2/2-2-object-level-authorization.md), Object-Level Authorization.

| Key | Type | Default | Description |
|---|---|---|---|
| `owned_object_resources` | list | empty, **needed to run** | The config.yaml `resources:` resources that each create a disposable object owned by user_a, whose identifiers (its `values`) name the path parameters of the object's by-id operations. Each is tested in turn, so several object types are covered. Without any the test cannot run (BOLA needs an owned object). |

### `tests.domain_2.test_2_5`

Test [2.5](../05-tests/domain-2/2-5-object-property-authorization.md), Object Property-Level Authorization.

| Key | Type | Default | Description |
|---|---|---|---|
| `owned_object_resources` | list | empty, **needed to run** | The config.yaml `resources:` resources that each create a disposable object owned by user_a (the same as test 2.2); each is checked in turn. Without any the test cannot run. |

### `tests.domain_4.test_4_1`

Test [4.1](../05-tests/domain-4/4-1-rate-limiting.md), Rate Limiting.

| Key | Type | Default | Description |
|---|---|---|---|
| `max_burst` | int ≥2 | `150` | The largest burst the test sends before concluding there is no rate limit, when the gateway's configured limit cannot be read. The burst stops at the first 429. |
| `probe_path` | string | `""` | The documented path to flood; empty derives the shortest documented GET. A read path, so the flood changes nothing. |

### `tests.domain_4.test_4_2`

Test [4.2](../05-tests/domain-4/4-2-timeout-config-audit.md), Timeout Configuration Audit -- Prevention of Resource Lock.

| Key | Type | Default | Description |
|---|---|---|---|
| `max_connect_timeout_ms` | int ≥1 | `5000` | Maximum acceptable backend connect timeout of a gateway service, in milliseconds. Methodology oracle: connect_timeout <= 5 000 ms (NIST SP 800-204A Section 4.3). Services with a higher value will produce a FAIL finding. |
| `max_read_timeout_ms` | int ≥1 | `30000` | Maximum acceptable backend read timeout of a gateway service, in milliseconds. Methodology oracle: read_timeout <= 30 000 ms (NIST SP 800-204A Section 4.3). Services with a higher value will produce a FAIL finding. |
| `max_write_timeout_ms` | int ≥1 | `30000` | Maximum acceptable backend write (send) timeout of a gateway service, in milliseconds. Methodology oracle: write_timeout <= 30 000 ms. Services with a higher value will produce a FAIL finding. |

### `tests.domain_4.test_4_4`

Test [4.4](../05-tests/domain-4/4-4-request-size-limits.md), Request Size Limits.

| Key | Type | Default | Description |
|---|---|---|---|
| `body_size_bytes` | int ≥1024 | `2000000` | The size of the body sent when the gateway's configured limit cannot be read. A body above a sane API limit (default 2 MB); a gateway that accepts it has no small body-size limit. |
| `probe_path` | string | `""` | The documented write path to probe; empty derives the shortest documented write. |

### `tests.domain_6.test_6_4`

Test [6.4](../05-tests/domain-6/6-4-hardcoded-credentials-audit.md), Hardcoded Credentials Audit.

| Key | Type | Default | Description |
|---|---|---|---|
| `debug_endpoint_paths` | list | empty | Paths of debug or actuator endpoints to probe unauthenticated for exposed credentials (e.g. /actuator/env, /debug/vars). Empty: the debug sub-test is not applicable. |

### `tests.domain_0.ext_0_1_ffuf`

Test [ext.0.1.ffuf](../05-tests/external/domain-0/ext-0-1-ffuf.md), Undocumented Paths Answer (ffuf path search, re-verified).

| Key | Type | Default | Description |
|---|---|---|---|
| `wordlist` | string \| null | none | A list of the user's (one word or path per line), tried under every base path besides the default lists, e.g. Assetnote's `httparchive_apiroutes` for a deep search (364,056 paths: at 30 requests per second about 3.4 hours per base path). Relative to the working directory. |

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

<!-- [[[cog import generate_docs as g; cog.out(g.configuration_table("external_tools")) ]]] -->

| Key | Type | Default | Description |
|---|---|---|---|
| `enabled` | bool | `true` | Master switch: `false` removes all external tests from the run, whatever the settings of each tool. |
| `testssl.enabled` | bool | `false` | Enable testssl.sh; `timeout_seconds` is then required. |
| `testssl.timeout_seconds` | int ≥30 \| null | none | **Required with `enabled: true`.** Wall-clock limit (s) of one execution, which only stops a tool that hangs: set it to 2-3 times the duration seen on your target; a run that ends after more than 70% of it logs the warning `external_tool_near_time_limit` with the value to raise. |
| `testssl.expected_version` | string \| null | none | Expected tool version; a mismatch logs a WARNING and the test still runs. |
| `testssl.dev_mode` | bool | `false` | Development only: reuse the output a previous run saved (`<output.directory>/tools/<label>_output.json`) instead of running the tool; without that file the tool runs and saves it. Never enable in a real assessment. |
| `testssl.extra_flags` | string | `--quiet --color 0` | Flags appended verbatim to the testssl.sh command line. Must not contain secrets. |
| `nuclei.enabled` | bool | `false` | Enable nuclei; `timeout_seconds` is then required. |
| `nuclei.timeout_seconds` | int ≥60 \| null | none | **Required with `enabled: true`.** Wall-clock limit (s) of one execution, which only stops a tool that hangs: set it to 2-3 times the duration seen on your target (it grows with the templates, the endpoints and the request rate); a run that ends after more than 70% of it logs the warning `external_tool_near_time_limit` with the value to raise. |
| `nuclei.expected_version` | string \| null | none | Expected tool version; a mismatch logs a WARNING and the test still runs. |
| `nuclei.dev_mode` | bool | `false` | Development only: reuse the output a previous run saved (`<output.directory>/tools/<label>_output.json`) instead of running the tool; without that file the tool runs and saves it. Never enable in a real assessment. |
| `nuclei.extra_flags` | string | `""` | Flags appended verbatim to the nuclei command line. Must not contain secrets. |
| `nuclei.template_dir` | string | `./tools/nuclei-templates` | Template directory, relative to the working directory (`install_tools.sh` fills the default one). |
| `nuclei.tags` | list | 4 values (`api`, `exposure`, …) | Template tags selected (`-tags`). |
| `nuclei.per_request_timeout` | int 5-60 | `10` | Timeout (s) of each request, passed as `-timeout`. |
| `nuclei.rate_limit_rps` | int 1-150 | `30` | Requests per second, passed as `-rl`. |
| `sslyze.enabled` | bool | `false` | Enable sslyze; `timeout_seconds` is then required. Needs the `sslyze` extra (`pip install "apiguard-assurance[sslyze]"`). |
| `sslyze.timeout_seconds` | int 30-300 \| null | none | **Required with `enabled: true`.** Today it has no effect: each TLS connection sslyze opens times out after 20 s whatever the value (`src/connectors/sslyze.py`; Q-24). |
| `sslyze.expected_version` | string \| null | none | Expected tool version; a mismatch logs a WARNING and the test still runs. |
| `sslyze.dev_mode` | bool | `false` | Development only: reuse the output a previous run saved (`<output.directory>/tools/<label>_output.json`) instead of running the tool; without that file the tool runs and saves it. Never enable in a real assessment. |
| `ffuf.enabled` | bool | `false` | Enable ffuf; `timeout_seconds` is then required. |
| `ffuf.timeout_seconds` | int ≥60 \| null | none | **Required with `enabled: true`.** Wall-clock limit (s) of the whole search (one ffuf run per base path), which only stops a tool that hangs: set it to 2-3 times the duration seen on your target (it grows with the base paths, the lists and the request rate); a search that ends after more than 70% of it logs the warning `external_tool_near_time_limit` with the value to raise. |
| `ffuf.expected_version` | string \| null | none | Expected tool version; a mismatch logs a WARNING and the test still runs. |
| `ffuf.dev_mode` | bool | `false` | Development only: reuse the output a previous run saved (`<output.directory>/tools/<label>_output.json`) instead of running the tool; without that file the tool runs and saves it. Never enable in a real assessment. |
| `ffuf.wordlist_dir` | string | `./tools/seclists` | Directory of the pinned SecLists wordlists, relative to the working directory (`install_tools.sh` fills the default one). |
| `ffuf.per_request_timeout` | int 1-60 | `10` | Timeout (s) of each request, passed as `-timeout`. |
| `ffuf.rate_limit_rps` | int 1-150 | `30` | Requests per second, passed as `-rate`. |

<!-- [[[end]]] -->

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

A test that needs something the configuration does not give (`Needs` in the [test catalogue](../05-tests/README.md):
the credentials of a role, a gateway, a login that can revoke a credential, or a parameter marked **needed to run**
in the tables above) is not an error: the engine records it as SKIP without running it, naming what is missing
("Needs USER_ACCOUNT: the credentials of the user_a role are not configured (credentials.user_a_*)."). The run
**warns** before the first test (log event `test_will_skip_unmet_needs`, fields `test_id` and `reason`);
`validate-config` and `list-tests --config` say the same without contacting the target.

## See also

- [`cli.md`](02-cli.md) - `validate-config`, `list-tests`, `generate-seed`
- [`exit-codes.md`](03-exit-codes.md)
- [`config.example.yaml`](../../config.example.yaml) - every key, with description and default
- [`test-environments/forgejo-kong/config.yaml`](../../test-environments/forgejo-kong/config.yaml) - configuration of the Forgejo + Kong lab
- [`test-environments/crapi-kong/config.yaml`](../../test-environments/crapi-kong/config.yaml) - configuration of the crAPI + Kong lab
- [`test-environments/forgejo-apisix/config.yaml`](../../test-environments/forgejo-apisix/config.yaml) - configuration of the Forgejo + APISIX lab (Admin API key and client certificate, Control API)

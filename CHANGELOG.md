# Changelog

Notable changes to APIGuard Assurance. Format based on [Keep a Changelog](https://keepachangelog.com/); versions
follow [Semantic Versioning](https://semver.org/). What is a contract, and how changes are versioned, is in
[compatibility](docs/reference/compatibility.md#interface-stability): a change that breaks a contract is marked
**Breaking:**; a change of test oracles, coverage or effects on the target is listed under **Changed results**.
Before 1.0.0 a breaking change raises the minor version.

## [Unreleased]

The test logic is unchanged since 0.1.0. Results on the lab differ only because the lab changed (below): with
the new `path_seed` resources, test 1.1 reports 78 findings instead of 56.

### Added

- `config_used.yaml` among the outputs of every run (Q-70): every key of the configuration, the parameters of every
  test included, each marked `# specified` or `# default`; `apiguard run --config config_used.yaml` repeats the run
  (verified on the lab: identical report). Placeholders stay as written; a credential or Admin API header written in
  clear becomes a placeholder named after its key, so the file holds no secret. `apiguard validate-config
  --show-config` prints it on stdout. Fields that hold secrets are declared in the schema
  (`Field(json_schema_extra=SECRET_VALUE)`, `src/core/models/runtime.py`).

- An external tool that ends after more than 70% of its time limit is warned about (`external_tool_near_time_limit`,
  with the duration, the limit and the key to raise), for the tools run as a process (testssl.sh, nuclei); the limit
  only stops a tool that hangs (Q-67).

- What a test needs from the configuration is declared (block 10b, `docs/architecture/design-decisions.md`, D8): `TestInfo.needs`
  (`ADMIN_ACCOUNT`, `USER_ACCOUNT`, `GATEWAY`, `REVOCABLE_LOGIN`; `src/core/test_needs.py`, where a new need is one
  entry) and the parameters a test cannot run without (`Field(json_schema_extra=NEEDED_TO_RUN)`). `validate-config`
  lists the selected tests that will SKIP and why; the run warns before the first test (`test_will_skip_unmet_needs`);
  the catalogue has a generated "Needs" column, the test pages a "Needs" row, the parameter tables "needed to run".
- `apiguard list-tests [--config PATH] [--json]`: every test with its declaration, needs and the JSON Schema of its
  parameters; with a configuration, whether the run selects it and why it would SKIP (block 10b, 6.7;
  `docs/reference/cli.md`).

- Generated documentation (block 10b, `docs/architecture/design-decisions.md`, D8): what repeats the tests' declarations is
  built from them by `scripts/generate_docs.py` and written by Cog between markers in the files: the test catalogue
  (`docs/tests/README.md`), the header of each test page, the tests by strategy and priority
  (`docs/architecture/assessment-model.md`), the tests chapter of `docs/reference/configuration.md` (one table per
  test, every parameter with type, range, default and description) and the `tests` section of
  `config.example.yaml` (every parameter with its default and the first sentence of its description; example values
  from the models). `hatch run dev:gen` writes them; `hatch run dev:check` fails when one is out of date, or when a
  test has no page. Development dependency: `cogapp`. The catalogue's "Needs" column is replaced by a link to "Test
  portability"; the headings of the tests chapter of `configuration.md` are the keys alone (anchors such as
  `#testsdomain_2test_2_1`).

- Certificate settings for every connection of the tool (`docs/architecture/design-decisions.md`, D2): an optional `tls`
  block on `target`, `specification`, `gateway.admin` and `gateway.health` with `verify`, `ca_bundle` (the authorities
  to trust, instead of the default ones, as `curl --cacert`), `client_cert` and `client_key` (mutual TLS). A private
  authority, an Admin API over HTTPS with a company certificate and an Admin API that requires a client certificate
  (APISIX `admin_api_mtls`) now work. The files are checked before any test (exit `10`): they exist, are PEM, the key
  matches the certificate and is not encrypted (the tool never prompts for a password); a key readable by other users
  and a `tls` block on an `http://` URL give a warning. Guide: `configure-a-target.md`, "TLS and certificates".
- A TLS problem is explained with the key to set and never retried: certificate not trusted, wrong name, expired,
  client certificate refused or missing (also when nginx-based servers, such as APISIX, answer with an HTTP 400
  page instead of refusing the connection), plain HTTP to an HTTPS port, HTTPS to a plain port. Before the first
  test the tool sends one request to the API (`preflight` in `evidence.json`): a TLS problem stops the run there
  (exit `10`) instead of failing every test.
- A run that stops with exit `10` prints the reason in full on a `Reason` line below the exit code (the log lines
  cut values at 160 characters, so the key to set was often lost).
- `apiguard_report.json` has `connections`: how the certificate of each connection was checked
  (`verified_system`, `verified_ca_bundle`, `not_verified`, `plain_http`, `local_file`) and whether a client
  certificate was used; the HTML report shows them under "Certificate checks", a not verified connection in red.
- The external TLS tests receive `target.tls.ca_bundle` (testssl.sh `--add-ca`, sslyze `custom_ca_file`), so a
  certificate from a private authority is judged on its properties, with an InfoNote saying that trust came from the
  configured authority.
- `apiguard generate-seed` takes `-c/--config` (and `--env-file`): the specification and its certificate settings
  come from the configuration; the `SPEC` argument is optional with it.
- The labs' certificate authority (`test-environments/pki/gen-pki.sh`): generated at the first start of any lab by a
  one-shot `pki` service, shared by the three labs, never committed; certificates of 180 days with the RFC 5280
  extensions, renewed automatically. Every connection of the labs is verified with it; Kong labs have an HTTPS Admin
  API (8444, 9444), the APISIX lab an Admin API over HTTPS with a mandatory client certificate; the Admin APIs listen
  on `127.0.0.1` only.

- Second test lab, `test-environments/crapi-kong/`: OWASP crAPI 1.1.6 behind Kong 3.9.3, with the same gateway
  configuration as the Forgejo lab, on ports 9000/9443/9001 (both labs can run together); users created by a setup
  container from `.env`; the crAPI specification is stored in the lab. Its configuration is
  `test-environments/crapi-kong/config.yaml` (it was `config_crapi.yaml`, which pointed to a crAPI without gateway and to a
  specification not in the repository).
- Integration guide: `docs/guides/integration/integrate-apiguard.md` (install with pip, credentials, one output
  directory per run, exit-code handling, reading the reports with `jq`, stopping a run, versions).
- Every test of the tool is accounted for: `apiguard_report.json` has a `not_run` section (and
  `executive_summary.not_run_count`) listing each test not executed, with a `reason` (`priority`, `strategy`,
  `not_in_test_ids`, `tool_disabled`, `fail_fast`) and a `detail`; the HTML report a "Not Run" section and card; the
  log `pipeline_tests_not_run` the counts. Before, a test excluded by the selection or stopped by fail-fast was
  absent without trace. With the external tools master switch off, their tests are now scanned and listed as
  `tool_disabled`.
- Progress during a run: each test's start line shows its position (`progress=5/18`) and, for an external test,
  the tool's `timeout_seconds`; nuclei and testssl.sh log `external_tool_still_running` every 10 seconds.
- `--env-file PATH` for `run` and `validate-config`: load the environment variables from that file instead of `.env`
  in the working directory.
- `tests.domain_0.test_0_1.method_probe_sample_size` (1-100, default 10): how many documented endpoints test 0.1
  takes for the undeclared-method sub-check (it was a fixed 10). Every native test now has a configuration model.
- `gateway.admin.headers`: headers sent on every read of the gateway's Admin API (e.g. an APISIX key or a Kong
  Enterprise RBAC token), for a gateway that protects it; the values are registered as secrets and masked in logs
  and reports (Q-34).
- `config.example.yaml` in the repository root: every configuration key with its description and default, neutral
  values; included in the source archive. `hatch run dev:check` runs `scripts/check_config_keys.py`, which fails
  when a key of the schema is missing from it or it has a key the schema does not know (alternatives that cannot
  be active together are listed commented out).
- Apache APISIX gateway adapter, `gateway.adapter: apisix` (tested with APISIX 3.19.0 and etcd): the
  configuration audits (3.3, 4.2, 4.3, 6.4 sub-test B) read the APISIX Admin API (a key of role `viewer`, GET only,
  is enough) and fill the fields left out with the defaults of the running APISIX (its plugin and upstream schemas),
  so that, for example, `hmac-auth` without `allowed_algorithms` is seen to allow `hmac-sha1`.
- `gateway.health.url`: address of the interface reporting the live health of the backends when the gateway keeps
  it outside the Admin API (APISIX Control API), read by test 4.3 without the Admin API headers; not used by Kong.
- Third test lab, `test-environments/forgejo-apisix/`: the Forgejo lab's API behind Apache APISIX 3.19.0 (etcd 3.5.34),
  with a gateway configuration of the same intent as the Kong labs, on ports 10000/10443/10001 (Control API 10002);
  Admin API keys from `.env` (`APISIX_ADMIN_KEY` for the setup, `APISIX_VIEWER_KEY` for the tool).
  Native results identical to the Forgejo + Kong lab.

### Fixed

- `config.example.yaml` did not load as written (exit `10`, `tests.domain_1.test_1_4: Input should be a valid
  dictionary`) since it was created: a block with every line commented is `null` for YAML, and a block rejected
  `null` (Q-70). A declared block written empty now takes its defaults, as if it were not written (sections, tools,
  domains and tests of the `tests` section, `headers`, `path_seed`); a required block or a single value written
  empty is still an error. `dev:check` now loads the example as written (`scripts/check_config_keys.py`, with the
  tests section check and no contact with the target).

- A value from the environment could change `config.yaml`: `${VAR}` was replaced in the raw text, then the text
  was parsed as YAML (Q-69). A password `ab #cd` arrived as `ab` without a message, `C:\new` in quotes arrived with a
  newline, `x: y` or `p"w` stopped the tool, and the YAML error printed the password in clear. The placeholders
  are now replaced after parsing, inside the string values: any value arrives exactly as set, a YAML error shows
  the file as written, and a placeholder in a comment is ignored (it used to stop the tool when unset). Quoted, a
  placeholder is text; unquoted and alone, it takes the type of a number, a boolean or an empty value, as before
  (`count: ${N}` with `N=5` sends `5`). An unquoted placeholder inside a mapping written on one line
  (`{count: ${N}}`) is now a YAML error: quote it, or write the mapping on several lines. The lab
  configurations and `config.example.yaml` load the same data as before. The commented examples of
  `config.example.yaml` show `${...}` placeholders instead of `<placeholder>`.

- `--log-format json`: the sslyze library wrote plain-text INFO lines into the JSON log stream (5 per run);
  they now appear only at `--log-level debug`.
- SIGTERM (`kill`, `docker stop`, CI timeouts) is handled like Ctrl+C: teardown runs, so the resources the tests
  created on the target are removed (before, the process died at once and left them, e.g. a repository and a
  token); a running external tool is stopped too. For both signals the tool says on stderr that it is cleaning up,
  a repeated Ctrl+C or SIGTERM no longer interrupts the cleanup (it only says to wait), and the process still ends
  by the first signal (exit `130` or `143`, as before).
- `.env` is loaded from the working directory (where the command is run). It was searched from the tool's own
  code folder, so a `pip`-installed tool never found it, and a Hatch run found the repository's `.env` from any
  folder. Only `run` and `validate-config` load it.
- `apiguard run --help` listed exit code `2` as ERROR; it lists `2` (invalid invocation) and `3` (ERROR).
- `execution.test_ids` with only native IDs no longer runs every enabled external test as well: a non-empty
  `test_ids` now runs exactly the listed tests (a listed test of a disabled tool still does not run).
- Lab setup: if issue 1 or comment 1 was deleted (they are `path_seed` resources), the setup stops and asks for a
  full reset instead of reporting "Issue 1 created" for a resource Forgejo created under a new number.
- The `config_coherence_warning` messages no longer link priorities and strategies and no longer quote skip
  reasons that did not exist.
- `apiguard generate-seed SPEC > seed.yaml` writes a valid YAML file: stdout carries only the template, the panel,
  logs and messages go to stderr.
- A spec URL that accepts the connection and never answers no longer hangs the run: after
  `specification.timeout` the run stops with exit `10`.

### Removed

- The lab's committed self-signed certificate and private key (`test-environments/forgejo-kong/certs/`) and
  `gen-certs.sh`: no private key is in the repository; the labs generate their certificates (see Added).
- `TargetContext.effective_base_url` and the `<TOOL>_SERVICE_URL` tool discovery: both were never functional.
  External tools are found in `./tools/` or `PATH`; a missing tool gives SKIP (with `<TOOL>_SERVICE_URL` set it
  used to give ERROR).

### Changed

- **Breaking:** a key written twice in the same mapping of `config.yaml` stops the tool (exit `10`, naming the
  key and both lines); before, the last one was kept silently and the first value was lost (Q-68). The same key under
  different parents, in different list items or overriding a YAML merge (`<<:`) is accepted.

- `external_tools.testssl.timeout_seconds` and `external_tools.nuclei.timeout_seconds` have no upper bound (they were
  at most 600): the user sizes them to 2-3 times the duration seen on the target. The example and the lab
  configurations set nuclei to 600 (was 240: a lab scan takes 173-194 s, and a loaded machine went over 240, Q-67).

- **Breaking:** parameters a user gives about the target are named by what they are, not by what the test does
  (block 10b, owner): 1.4 `verify_request` is `protected_endpoint` (an endpoint that requires authentication: method
  and path); 1.5 `http_probe_url` is `http_url`; 1.6 `cookie_probe_paths` is `session_cookie_paths`; 7.2
  `injection_path_template`, `injection_body_template` and `injection_resource` are one key, `url_accepting_endpoint`,
  with `path`, `body` and `resource` (an endpoint of the API that accepts a URL and makes the server call it; `path`
  and `body` required inside it). The former keys are unknown keys.

- **Changed results**, SKIP reasons (statuses unchanged): a test whose needs the configuration does not meet is
  recorded as SKIP by the engine, before it runs, with one reason per unmet need, e.g. "Needs USER_ACCOUNT: the
  credentials of the user_a role are not configured (credentials.user_a_*)." or "Needs
  tests.domain_2.test_2_1.admin_endpoint_paths: not set (the test cannot run without it)."; the tests no longer
  check these themselves (`_requires_credentials`, `_requires_token`, `_requires_admin_api` removed from
  `BaseTest`). The startup warnings per strategy (`config_coherence_warning`) are replaced by one warning per test
  that will SKIP.

- **Breaking** (for tests written outside the tool): a test declares its parameters in its own module and names the
  model in its class, `class Test21...(BaseTest[Test21Params])`, and reads them with `self.params(target)` (typed:
  mypy checks every name); a test without parameters writes `BaseTest` alone (block 10b,
  `docs/architecture/design-decisions.md`, D8). `src/test_config/` (the per-domain models, their containers and
  `RuntimeTestsConfig`) and `src/config/schema/tests_config.py` are removed; `TargetContext.tests_config` is
  `TargetContext.test_params` (by test ID). The user's keys are unchanged (`tests.domain_<D>.test_<D>_<N>.<param>`).
  The `tests` section is checked right after the rest of the configuration, once the tests are discovered (also by
  `validate-config`), with the same messages as any key (an unknown test or parameter, with the closest name); test
  7.2's checks against `resources` moved into its own model.
- A key of an earlier configuration structure (the keys moved by the configuration by connection, the `auth_type`
  values `jwt_login`, `json_login`, `forgejo_token` and their keys, 1.4 `token_name`, 7.2 `injection_mode`,
  `injection_url_field`, the `$SSRF_URL$` placeholder) is now an unknown key or value like any other: the messages
  naming its replacement are removed (the tool has no users of those versions).
- `typing-extensions` is a declared dependency (it was already required by pydantic): a test without parameters
  writes `BaseTest` alone thanks to a type variable with a default (PEP 696), in `typing` only from Python 3.13.

- **Breaking:** the gateway adapters know their gateway's plugins: six test keys that described Kong's plugins are
  removed (block 10b, `docs/architecture/design-decisions.md`, D8): `tests.domain_3.test_3_3.plugin_names`, `field_clock_skew`,
  `field_algorithms`, `field_validate_body`, `clock_skew_unconfigured_value` and
  `tests.domain_4.test_4_3.accepted_cb_plugin_names`. The Kong adapter reads `hmac-auth` with the fields of Kong's schema and recognises the third-party
  `circuit-breaker` plugin; the APISIX adapter reports `clock_skew: 0` (no date check) as no replay window
  (`SigningPolicy.replay_unlimited`), the case the removed `clock_skew_unconfigured_value` described (Kong itself
  rejects `clock_skew: 0`). No test parameter reaches the adapters any more.
- **Changed results**, report texts of 3.3 and 4.3 (statuses and finding counts unchanged on the three labs): they
  no longer name Kong's fields or the removed keys, e.g. `HMAC 'clock_skew' Field Absent` is now
  `HMAC Replay Window Not Stated`, `HMAC 'algorithms' Field Absent` is `HMAC Allowed Algorithms Not Stated`, the
  body note is `HMAC Body Signed` / `HMAC Body Not Signed`; 3.3 no longer has the SKIP for an empty `plugin_names`.

- **Breaking** (for tests written outside the tool): a test declares who it is in one object,
  `info = TestInfo(id=..., name=..., priority=..., strategy=..., cwe=..., tags=..., depends_on=..., requires_pass=...)`
  (external tests also `tool=...`), instead of nine class attributes (`test_id`, `test_name`, `domain`, `priority`,
  `strategy`, `depends_on`, `requires_pass`, `tags`, `cwe_id`, and `tool_name`); the domain is taken from the ID
  (block 10b, `docs/architecture/design-decisions.md`, D8). The declaration is a Pydantic model, checked when the module is
  imported (also the CWE form `CWE-<number>`). Native and external tests share one base (`src/core/assessment_test.py`)
  with the same result helpers: an external test's FAIL with a list of findings is `_make_fail_multi` (it was
  `_make_fail`), `_make_error(exc, message=...)` replaces `message_override`. Results and reports keep their field
  names (`test_id`, `test_name`, `domain`, `cwe_id`, `tool_name`).
- A test is never left out of a run silently: a test module that cannot be imported (an invalid declaration
  included), or a test module in a folder without `__init__.py`, stops the tool right after loading the
  configuration (exit `10`, also in `validate-config`), naming the file and the error. Before, the module was skipped
  with a warning and the run went on without its tests. An external test's ERROR message for a tool failure is
  `External tool '<tool>' failed: ...` (it was `[ExternalToolError] ...`); an unexpected exception in an external test
  gives the same message as in a native one (`Unexpected <type> during test execution: ...`, cut at 500 characters).

- **Breaking:** the configuration is organised by connection (`docs/architecture/design-decisions.md`, D1): `target` is
  the API (address, `tls`, `connect_timeout`, `read_timeout`, `max_retry_attempts`, `path_seed`), `specification` the
  OpenAPI document (`url` or `path`, `timeout`, `tls`), `gateway` the gateway (`adapter`, `admin` with `url`,
  `headers`, `connect_timeout`, `read_timeout`, `tls`, and `health` with `url`, `tls`). The previous keys moved:
  `target.openapi_spec_url` / `openapi_spec_path` → `specification.url` / `path`,
  `execution.openapi_fetch_timeout_seconds` → `specification.timeout`, `target.gateway_adapter` →
  `gateway.adapter`, `target.admin_api_url` → `gateway.admin.url`, `target.admin_connect_timeout_seconds` /
  `admin_read_timeout_seconds` → `gateway.admin.connect_timeout` / `read_timeout`, `execution.connect_timeout` /
  `read_timeout` / `max_retry_attempts` → `target.*`. Table: `docs/reference/configuration.md`, "Keys moved".
- **Breaking:** `target.verify_tls` is replaced by `target.tls.verify`; the Admin API, which was always verified
  against the public authorities only, now follows `gateway.admin.tls`.
- **Breaking:** by default every connection trusts the operating system's certificate store (through `truststore`)
  plus certifi's list; before, only certifi's list (httpx's default). A company authority installed in the system
  is now trusted without configuration; `SSL_CERT_FILE` / `SSL_CERT_DIR` no longer change what the tool trusts.
- The specification is downloaded by the tool (with the settings of `specification`), no longer by prance; relative
  `$ref` in a specification read from a URL were never resolved (prance resolves them only for files) and now give a
  message saying to use a local copy.
- **Changed results**, connections and TLS: on the three labs, with the labs' authority, the external TLS tests no
  longer report an untrusted chain: `ext.1.5.sslyze` FAIL → PASS (`cert_chain_not_trusted` gone), `ext.1.5.testssl`
  keeps only `cert_revocation` (`cert_chain_of_trust` and `overall_grade` gone; the lab certificates declare no CRL or
  OCSP address). The native tests give the same results. The Forgejo labs serve the specification through the gateway
  (`/swagger.v1.json`, test 0.1 excludes it as before), Forgejo publishes no port and its `ROOT_URL` is the gateway's
  address.
- **Breaking:** authentication is configured in two parts (block 7+8 phase C, `docs/architecture/design-decisions.md` D5).
  `credentials.auth_type` has no default and is required when an account or a token is configured (it was
  `forgejo_token` by default); values `basic` (new, HTTP Basic), `static_token` (new, `admin_token` /
  `user_a_token` / `user_b_token`), `login` (new, replaces `forgejo_token` and `jwt_login`: the request that logs
  in is a prepared resource named in `credentials.login_resource`, see the next entry). `forgejo_token`, `jwt_login`
  and the `jwt_login` keys `login_endpoint`, `username_body_field`, `password_body_field`, `token_response_path`
  are removed. How the credential is sent comes from the security schemes the
  specification declares: one scheme is used as is, several need `credentials.security_scheme`, none needs
  `credentials.send_as` (`in`, `name`, `prefix`); `send_as.prefix` also completes a declared `apiKey` scheme whose
  prefix is described only in words (Forgejo: `security_scheme: AuthorizationHeaderToken`, `send_as: {prefix:
  "token "}`). A configuration that does not determine it stops the run before any test (exit `10`);
  `validate-config` checks it too, reading the specification only when credentials are configured, and prints
  where the credentials are sent. Each method accepts only its own kind of credential (tokens or username and
  password). Passwords and configured tokens are registered as secrets.
- **Breaking:** prepared resources (block 7+8 phase E, `docs/architecture/design-decisions.md` D6): what the tool creates on
  the target and how it logs in are configuration, in the new top-level section `resources` (a create request,
  values read from its JSON response, an optional delete request sent at teardown; placeholders `{username}`,
  `{password}`, `{random}` and the values, checked at startup). The last Forgejo code is gone
  (`src/tests/helpers/auth_forgejo.py`, `auth_json_login.py`, `forgejo_resources.py`); the Forgejo labs declare the
  resources `forgejo-token` (login) and `repository` (7.2), crAPI `crapi-login`. Test 7.2: the `resource` of its
  `url_accepting_endpoint` names a resource created for `user_a` whose values fill the path and the body; `injection_mode` and
  `injection_url_field` are removed; the body placeholders `$SSRF_URL$` and
  `$RANDOM_SECRET$` are now `{ssrf_url}` and `{random_secret}`. Test 1.4: the temporary credential comes from the
  login resource and is revoked by its delete request; `protected_endpoint` (method and path, no default: SKIP) replaces
  the `/api/v1/user` path written in the test; `token_name` is removed. `validate-config` shows the login
  resource and who uses each resource. `config.example.yaml` documents every field of a resource, checked by
  `scripts/check_config_keys.py`.
- **Breaking:** tests 2.1 and 7.2 have no Forgejo defaults (block 7+8 phase D). 2.1 `admin_endpoint_paths` is empty
  by default (was `/api/v1/admin/users`); 7.2 `url_accepting_endpoint` (path and body) is unset by
  default (were the Forgejo webhook ones). Unconfigured, the tests return SKIP naming the keys to set; a path without
  a body, or a body without `{ssrf_url}` exactly once, stops the run at startup. The Forgejo labs set the previous
  values explicitly.
- **Changed results**, 2.1 and 7.2 without configuration (block 7+8 phase D): SKIP instead of probing Forgejo paths;
  on crAPI 2.1 PASS -> SKIP (the PASS came from a `404` on the Forgejo path, which crAPI does not have).
- **Changed results**, authentication (block 7+8 phase C): the tests send the credential as the specification
  declares instead of always `Authorization: Bearer`: on Forgejo `Authorization: token <value>` (results
  unchanged). Test 1.4 uses the revocation capability of the authentication method (`login` with a login resource
  that has a delete request): otherwise it returns SKIP "Not applicable: the authentication method '<auth_type>'
  cannot revoke a credential ..." (crAPI: was ERROR). The SKIP reason for missing credentials no longer mentions
  Forgejo.
- **Changed results**, prepared resources (block 7+8 phase E): the three labs give the same results. Test 7.2 returns
  ERROR, naming the resource, the request and the status, when the resource of its endpoint cannot be created (was SKIP
  "not applicable" for the Forgejo mode). The temporary token of 1.4 has the scopes of the login token (it was
  `read:user` only), and the cleanup of a token left with the fixed name by an interrupted run is gone (names are
  random). Report texts of 4.3 (circuit breaker notes and finding), 6.4 (configuration audit notes) and 7.2 (accepted
  URL finding) no longer name Kong or Forgejo as the only gateway or application.
- The Forgejo + Kong lab configuration holds only the lab's values, like the other labs (774 -> 175 lines); the
  complete reference is `config.example.yaml`. Its effective configuration is identical (all values compared).
- Config key suggestions use the names written in `config.yaml` (e.g. `credentials.send_as.inn` suggests `in`).
- **Changed results**, gateway audits (block 7+8): tests 4.2, 4.3, 3.3 and 6.4 (sub-test B) read the gateway
  through neutral concepts.
  When the Admin API cannot be read they return SKIP "Not verifiable: no access to <concept>: ..." (was ERROR);
  their findings point to the stored concept (`evidence_ref`, was empty). 4.3: the observability check reads the
  live health of the backend targets (Kong `/upstreams/<name>/health`) instead of looking for circuit-breaker
  fields in Kong's `/status`, which never has them: the note "Observability Gap: CB Metrics Absent from Kong
  /status" is gone on Kong (on a FAIL it was an extra finding); a circuit-breaker parameter that is not a number
  is reported as "Not Found" (was "Non-Numeric"). 3.3: findings name the policy by its reference (on Kong
  `plugin hmac-auth (id: ...)`, was the plugin id alone); the coverage note lists backends and routes by name.
  6.4: sub-test B finding titles say "Gateway" instead of "Kong"; when the configuration cannot be read, a note
  says that sub-test B was not verified (sub-test A stands).
  Same statuses and findings on both labs.
- Test labs: Kong active health checks re-enable a backend excluded by the passive checks (Q-66): on the crAPI lab a
  run no longer leaves the workshop service excluded, so consecutive runs give the same results without a reset.
  Results unchanged.
- Test labs: HTTP-to-HTTPS redirect done with Kong's own mechanism (API routes HTTPS-only with
  `https_redirect_status_code: 301`) instead of a catch-all redirect route, which also answered 301 over HTTPS to
  every unknown path (Q-65); `tests.domain_1.test_1_5.http_url` of the lab configurations points to an API path. **Changed results**
  on the labs (tool unchanged): Forgejo 0.1 16 -> 2 findings, 0.2 FAIL -> PASS, 1.5 PASS -> FAIL (Kong's own 404
  carries no HSTS; the earlier PASS came from the removed route); crAPI 0.1 49 -> 12, 0.2 FAIL -> PASS, 1.5 PASS ->
  FAIL.
- The lab configurations moved into their labs: `config.yaml` → `test-environments/forgejo-kong/config.yaml` (reports in
  `outputs/forgejo/`), `config_crapi.yaml` → `test-environments/crapi-kong/config.yaml` (reports in `outputs/crapi/`). Run the tool
  from the repository root with `-c <file>`; without `-c` it still reads `config.yaml` in the working directory,
  which the repository no longer has. The source archive (sdist) no longer contains a configuration file. Path
  rule unchanged: relative paths in a configuration file are resolved against the working directory.
- **Breaking:** the console output of `apiguard run` is an interface for people: a header (target, specification,
  selection), one line per test with its status, findings grouped by kind, the reason of a SKIP or ERROR, and a
  summary (cleanup, counts, exit code, paths of the reports); on a terminal the test in progress updates in place
  with its elapsed time. Before, about 270 lines of technical log for 15 tests, over 700 characters wide; now about
  35. The default `--log-level` is `warning` (was `info`): the technical log, shown below the interface, has only
  problems unless `--log-level info` or `debug` is given, and in JSON format the default logs only problems (use
  `--log-level info` for the event stream). Test results (bypasses, accepted URLs, missing headers, ...) are logged
  at `info` (were `warning`). Library warnings appear only at `debug`. `validate-config` logs at `warning`.
- **Breaking:** `output_schema_version` removed from `apiguard_report.json` (it was `"1.0"`, set arbitrarily):
  `tool_version` is the only version of the output formats. `evidence.json` now has `tool_version` too. The
  interface contract (what is stable, what is announced, what is free) is in
  `docs/reference/compatibility.md`.
- Secrets are redacted in every output with typed placeholders that keep the meaning: `authorization` says whose
  credential it was (`[REDACTED: user_a token]`, was a bare `[REDACTED]`); the token created by test 1.4 and the
  webhook secrets generated by test 7.2, which were in clear, are replaced (the 1.4 token keeps its last 8
  characters to correlate create, revoke and reuse); cookie values are hidden, names and attributes kept. Response
  bodies are unchanged (often the proof). The fixed probe values test 1.1 sends as `Authorization` (malformed tokens)
  are shown as `[public probe] <value>`, and "copy as cURL" in the HTML report now rebuilds those requests exactly.
  Findings, evidence references and statuses are unchanged.
- A test class declared incorrectly stops the tool right after loading the configuration (exit `10`, also in
  `validate-config`), listing every problem with class and module: a missing or invalid class attribute (e.g.
  `priority` outside 0-3, `strategy` not a `TestStrategy`, a `test_id` not matching `domain`), a duplicate `test_id`,
  a class that cannot be instantiated. Before, a native test was dropped and an external one ran with defaults,
  with only a warning. The same rules for native and external tests (`src/core/test_metadata.py`); classes whose
  name starts with `_` are helpers, not tests.
- Prerequisites between tests are applied, not only used for ordering. A test declares `depends_on` (it uses data
  that another test produces: it runs if that test ended PASS or FAIL) and `requires_pass` (it is meaningful only if
  another test passes: it runs if that test ended PASS); otherwise it returns SKIP with a reason naming the
  prerequisite, also when the selection left the prerequisite out (before, the dependency was dropped with a warning
  and the test ran anyway). A prerequisite that names no test, or the test itself, stops the tool at startup (exit
  `10`). Tests 1.4 and 2.1 no longer depend on 1.1: they take no data from it, and a FAIL of 1.1 does not make them
  meaningless; same results on the lab.
- **Breaking:** strategies say what the tester has (BLACK_BOX: network only; GREY_BOX: an ordinary account;
  WHITE_BOX: the API's administrator account or internal access) and `execution.strategies` filters external tests
  too. Relabelled: 1.5, 1.6, 6.2, `ext.1.5.testssl`, `ext.1.5.sslyze` WHITE_BOX → BLACK_BOX (network access only);
  1.4 GREY_BOX → WHITE_BOX (administrator account). With all three strategies (the default) the same tests run; the
  `strategy` field of these tests changes in the report. Phase 1 warnings follow the exact SKIP conditions: WHITE_BOX
  without `gateway` (was: without `admin_api_url`, which missed an URL without adapter), WHITE_BOX without
  the `admin` credentials (new), GREY_BOX without the `user_a` credentials (was: without any credentials).
- **Breaking:** a run that would check nothing no longer ends with exit `0` (CLEAN). An `execution.test_ids`
  entry that does not exist (with a suggestion of the closest ID) or that belongs to a disabled tool stops the tool
  right after loading the configuration, also in `validate-config`; a filter combination that selects no test stops
  the run at Phase 4. Both exit `10`. Before, the run produced an empty report and exit `0`.
- **Breaking:** `generated_at_utc` in `apiguard_report.json` is UTC (`+00:00`), as its name says; it was written in
  `Europe/Rome` time (same instant, different offset). The HTML report shows it in the reader's local time zone,
  with the UTC value in the tooltip.
- **Breaking:** unknown keys in `config.yaml` are rejected at startup (exit `10`) instead of being silently
  ignored, so a misspelled key no longer applies a default unnoticed. The error lists every validation error (it
  showed only the first), and for an unknown key suggests the closest declared key. Free-form mappings such as
  `target.path_seed` are not affected. The lab configurations are unchanged and valid.
- **Breaking:** exit code `3` now means ERROR (at least one test could not complete, no FAIL); it was `2`. `2`
  now means only an invalid invocation (unknown option or command), so a wrapper can tell "nothing ran" from "the
  run completed with errors". The same value is in `executive_summary.exit_code` of `apiguard_report.json`.
- Test lab (`test-environments/forgejo-kong/`): every credential and secret comes from `.env` (new variables
  `LAB_DB_PASSWORD`, `LAB_FORGEJO_SECRET_KEY`, `LAB_TEST_REPO`, `LAB_TEST_ORG`, `LAB_TEST_TAG` in `.env.example`);
  the setup container creates users that can call the API immediately, plus the repository, organization, tag,
  issue and comment that `path_seed` points to.
- Supported Python range set to the versions verified on the lab: `>=3.11,<3.15` (3.11, 3.12, 3.13, 3.14);
  previously `>=3.11` with only 3.12 tested.
- Test lab: Docker images pinned to exact versions (Forgejo 14.0.5, Kong 3.9.3, PostgreSQL 15.19), listed in
  `docs/reference/compatibility.md`.
- `config.yaml`: `path_seed` reads the lab names from `.env`; `sha` is `main` instead of a commit hash that
  changed on every new lab.
- `external_tools.sslyze.extra_flags` removed: it never had an effect (sslyze is a library, not a command line);
  `extra_flags` remains for testssl and nuclei.
- Test 7.2: the redirect sub-test is called "Sub-test G" in the report texts (was "Sub-test E", which is the DNS
  bypass sub-test).
- Internal: the gateway adapter interface is made of neutral concepts (`src/core/gateway/concepts.py`, one
  reader per concept, read once per run); the Kong-shaped methods (`get_services`, `get_plugins`, ...) are gone;
  adapters are registered in `GATEWAY_ADAPTERS`. Guide: `docs/guides/extending/add-a-gateway-adapter.md`.
  The constructor, the HTTP reads and the collection of configuration text values are shared by every adapter
  (`BaseGatewayAdapter`); an interface answering with a body that is not JSON is reported as not accessible (it was
  an unhandled error); error messages name the interface and its configuration key.
- Internal: every test parameter is defined once, in `src/test_config/` (one model per test, the same model
  validates `config.yaml` and reaches the test); the runtime copies and the field-by-field copy in the engine were
  removed; the engine collects them automatically, and a model missing on one side stops the run at
  Phase 3. No change to existing configuration keys, defaults or results.
- Internal: list-valued test parameters (13) are tuples, so no test can change them during a run (YAML lists in
  `config.yaml` are unchanged). No change to defaults or results.
- Development checks: `hatch run dev:check` also runs `ruff format --check` and `lint-imports` (dependency rules
  between packages); code formatted; one import fixed to respect the dependency rule.
- Documentation rewritten in English and reorganised under `docs/` (getting started, usage guides, reference,
  test catalogue, architecture, contributor guides). `README.en.md` removed; `README.md` is the single README.

## [0.1.0] - 2026-05-18

First release (Milestone 1).

### Added

- Assessment pipeline in 7 phases: configuration, OpenAPI discovery (Swagger 2.0, OpenAPI 3.x), context, scheduling
  with dependencies, execution, teardown, reports.
- 15 native tests: 0.1, 0.2, 0.3, 1.1, 1.4, 1.5, 1.6, 2.1, 3.3, 4.1, 4.2, 4.3, 6.2, 6.4, 7.2
  ([catalogue](docs/tests/README.md)).
- 3 external-tool tests: `ext.0.1.nuclei`, `ext.1.5.testssl`, `ext.1.5.sslyze`; `install_tools.sh` for the binaries.
- Kong gateway adapter (DB-less Admin API) for configuration-audit tests.
- Reports: `assessment_report.html`, `apiguard_report.json` (`output_schema_version` 1.0), `evidence.json`.
- CLI: `run`, `validate-config`, `generate-seed`, `version`; exit codes 0, 1, 2, 10.

[Unreleased]: https://github.com/eneamanzi/apiguard-assurance/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/eneamanzi/apiguard-assurance/releases/tag/v0.1.0

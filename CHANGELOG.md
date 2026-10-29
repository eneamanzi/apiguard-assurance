# Changelog

Notable changes to APIGuard Assurance. Format based on [Keep a Changelog](https://keepachangelog.com/); versions
follow [Semantic Versioning](https://semver.org/). What is a contract, and how changes are versioned, is in
[compatibility](docs/03-reference/06-compatibility.md#interface-stability): a change that breaks a contract is marked
**Breaking:**; a change of test oracles, coverage or effects on the target is listed under **Changed results**.
Before 1.0.0 a breaking change raises the minor version.

## [Unreleased]

Since 0.1.0 the infrastructure for production and integration landed first (blocks 1-5d, 7-10, below), and then the
**block-6 test review** rewrote the test suite on a new assessment model and extended it. Lab results therefore
differ from 0.1.0 by the tests' own logic, not only by the lab's data. The full list of tests now implemented is the
generated catalogue [`docs/05-tests/README.md`](docs/05-tests/README.md); `apiguard list-tests` is the ground truth.

### Added

- **What the tool detects of crAPI's declared vulnerabilities, measured** (`06-compatibility.md`, 2026-10-29). crAPI
  publishes the 18 weaknesses it was built to contain, so the measure is not ours: on a reset lab, with the full
  32-test assessment, the tool caught four outright (an unprotected password reset, no rate limit on the very
  feature the challenge names, two endpoints served without a credential, a JWT with `alg: none` that crAPI does not
  even list among its four JWT flaws), caught the class of a fifth on another endpoint, **named the endpoint of a
  sixth and refused to exploit it** because the operation is destructive, attempted a seventh without being able to
  conclude, missed four, and four more are outside its scope by decisions already recorded while three are absent
  from this deployment. The row for each challenge says which, and why.
- **Block-6 test review: the test suite was reviewed and extended.** New guarantees: 0.4 (a backend answers only
  through the gateway), 1.2 and 1.3 (JWT cryptographic validity and expiry), 1.7 (authentication endpoints resist
  guessing), 2.2 (object-level authorization, BOLA), 2.4 and 2.5 (authorization consistency and object-property
  level), 4.4 (request size limits), 5.1 and 5.2 (request-logging and security-alerting audits), 6.1 (error and
  information disclosure), 7.1, 7.3 and 7.4 (sensitive-flow anti-automation, race conditions, webhook verification);
  `ext.0.1.ffuf` and `ext.3.1.schemathesis` as new external tests. The full set, with each test's strategy and
  priority, is in the generated catalogue `docs/05-tests/README.md`.
- **A new assessment model under every test** (block 6): each judged response carries an `outcome` (`VIOLATION`,
  `ENFORCED`, `NOT_VERIFIABLE`, `NOT_APPLICABLE`) and a test-specific `detail`; each finding carries a `confidence`
  (`CERTAIN`, `FIRM`, `TENTATIVE`); a test's status is computed from its sub-tests' outcomes, with a new
  `INCONCLUSIVE` status (exit `3`, shared with ERROR) when a run verified nothing. Oracles rest on calibration and
  positive controls, so a test reports honestly when it cannot verify instead of a false PASS. New needs
  (`Need.SECOND_USER_ACCOUNT`, `Need.GATEWAY`, ...) let the engine acquire accounts and SKIP a test whose
  prerequisites are missing.
- Continuous integration on GitHub (`.github/workflows/check.yml`, Q-16): on every push and pull request,
  `hatch run dev:check` on Python 3.11 and 3.14, and the built wheel installed in an empty environment runs
  `apiguard version` and `apiguard list-tests`.
- `config_used.yaml` among the outputs of every run (Q-70): every key of the configuration, the parameters of every
  test included, each marked `# specified` or `# default`; `apiguard run --config config_used.yaml` repeats the run
  (verified on the lab: identical report). Placeholders stay as written; a credential or Admin API header written in
  clear becomes a placeholder named after its key, so the file holds no secret. `apiguard validate-config
  --show-config` prints it on stdout. Fields that hold secrets are declared in the schema
  (`Field(json_schema_extra=SECRET_VALUE)`, `src/core/models/runtime.py`).

- An external tool that ends after more than 70% of its time limit is warned about (`external_tool_near_time_limit`,
  with the duration, the limit and the key to raise), for the tools run as a process (testssl.sh, nuclei); the limit
  only stops a tool that hangs (Q-67).

- What a test needs from the configuration is declared (block 10b, `docs/04-architecture/05-design-decisions.md`, D8): `TestInfo.needs`
  (`ADMIN_ACCOUNT`, `USER_ACCOUNT`, `GATEWAY`, `REVOCABLE_LOGIN`; `src/core/test_needs.py`, where a new need is one
  entry) and the parameters a test cannot run without (`Field(json_schema_extra=NEEDED_TO_RUN)`). `validate-config`
  lists the selected tests that will SKIP and why; the run warns before the first test (`test_will_skip_unmet_needs`);
  the catalogue has a generated "Needs" column, the test pages a "Needs" row, the parameter tables "needed to run".
- `apiguard list-tests [--config PATH] [--json]`: every test with its declaration, needs and the JSON Schema of its
  parameters; with a configuration, whether the run selects it and why it would SKIP (block 10b, 6.7;
  `docs/03-reference/02-cli.md`).

- Generated documentation (block 10b, `docs/04-architecture/05-design-decisions.md`, D8): what repeats the tests' declarations is
  built from them by `scripts/generate_docs.py` and written by Cog between markers in the files: the test catalogue
  (`docs/05-tests/README.md`), the header of each test page, the tests by strategy and priority
  (`docs/04-architecture/03-assessment-model.md`), the tests chapter of `docs/03-reference/01-configuration.md` (one table per
  test, every parameter with type, range, default and description) and the `tests` section of
  `config.example.yaml` (every parameter with its default and the first sentence of its description; example values
  from the models). `hatch run dev:gen` writes them; `hatch run dev:check` fails when one is out of date, or when a
  test has no page. Development dependency: `cogapp`. The catalogue's "Needs" column is replaced by a link to "Test
  portability"; the headings of the tests chapter of `configuration.md` are the keys alone (anchors such as
  `#testsdomain_2test_2_1`).

- Certificate settings for every connection of the tool (`docs/04-architecture/05-design-decisions.md`, D2): an optional `tls`
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
- Integration guide: `docs/02-guides/02-integration/01-integrate-apiguard.md` (install with pip, credentials, one output
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

- **The crAPI lab wears out, and `maintainer-commands.md` said it needed no reset** (pass C of the test-by-test
  review, 2026-10-29). Tests 2.2 and 2.5 create a shop order and each order spends 10 of user A's 100 starting
  credit, which crAPI never gives back: after about ten runs the creation answers `400 Insufficient Balance`, both
  tests report `OBJECT_NOT_CREATED`, and a full assessment shows 9 FAIL where a reset lab shows 15, losing the two
  authorization findings crAPI exists to expose (a BOLA on an order, `card_number` in its response). The tool stays
  honest throughout, reporting INCONCLUSIVE and never a PASS. The maintainer commands now say to reset about every
  ten runs, with the measurement and how to read the balance.
- **One version of each standard, and every citation verified on its source** (pass B of the test-by-test review,
  2026-10-28). The tool cited a mixture: the NIST identifiers omitted the revision (`800-53`, `800-63B`, `800-61`,
  `800-52`, `800-107`) while the pages named it, so the report printed a reference a reader could not check, and the
  section numbering of a NIST publication changes between revisions. Every identifier now carries its revision, and
  `StandardFormat` holds the one version of each standard the tool cites (ASVS v5.0.0, OWASP API Top 10 2023, OWASP
  Top 10 2025, WSTG v4.2, CWE 4.20), pinned in the pattern so a reference on another version is refused when it is
  built; `report-schema.md` states each version and how it was established. All 141 citations (106 distinct) were
  then checked against the sources: the 40 ASVS requirements exist in v5.0.0 (indexed from the 17 chapters of the
  OWASP repository), the 37 CWEs exist with the titles of release 4.20, the 11 RFCs are none of them obsolete and
  every cited section carries the title the test uses it for, the 4 WSTG identifiers resolve on the v4.2 tag, and
  the NIST sections were read from the publications themselves.
- **The TLS scan was filed under Broken Authentication.** `ext.1.5.testssl` cited OWASP API2:2023, and the test
  carries no credential: it judges the gateway's TLS stack (protocol versions, cipher suites, forward secrecy, the
  certificate chain). Read on the source, API8:2023 lists "Transport Layer Security (TLS) is missing" and
  "appropriate security hardening is missing across any part of the API stack", while API2's own list says nothing
  about the handshake, its "weak encryption keys" and "plain text passwords" being about the credentials themselves.
  The external test now cites API8:2023; the native test 1.5 cites **both**, API2:2023 for the credential it exposes
  and API8:2023 for the configuration that exposes it.
- **Two more citations named a section whose content is about something else**, found by reading the body of each
  NIST section instead of its title (2026-10-28): test 7.2 cited `NIST SP 800-204 §3.2.2` as a source of its SSRF
  payload catalogue, and that section is "Internet-based Attacks", about the inbound surface of a microservices
  application, while the publication never mentions SSRF, server-side request forgery or an outbound call (the
  reference is dropped; the catalogue's real sources, PayloadsAllTheThings and WSTG-v42-INPV-19, are the ones its own
  module names). Test 2.2 cited `800-162 §2.2`, a survey of ABAC definitions that never mentions object attributes,
  where §2.3 "Basic ABAC Concepts" evaluates "attributes of the object", `Owner` among them, which is the ownership
  the test checks.
- **Eight citations named the wrong thing**, each replaced by one verified on the source: test 6.4 cited
  `NIST SP 800-53 §5.4` and its page `800-204 §5.4`, and **neither publication has a §5.4** (now 800-53r5 §3.7,
  control IA-5(7), "no embedded unencrypted static authenticators", which is the test's guarantee verbatim); tests
  2.1, 2.4, 2.5 and 5.1 carried a control identifier in the `section` field, so the report printed "Section 3" where
  the pages meant AC-3 and AU-2 (now §3.1 Access Control and §3.3 Audit and Accountability, the families those
  controls belong to); test 1.7's `800-63B §3.2.2` exists only in revision 4 (now `800-63B-4`, whose §3.2.2 is "Rate
  Limiting (Throttling)"; in the base SP 800-63-4 that number is "Identify Potential Impact Levels"); test 5.1 cited
  ASVS 16.2.1, per-entry log metadata, the one thing it cannot see (now 16.3.3 and 16.4.3, which describe what a
  gateway logging plugin does); test 2.5 cited ASVS 8.2.2, data-specific access, where 8.2.3 is written for broken
  object property level authorization, and gains CWE-915 for mass assignment; test 2.1 gains ASVS 8.2.1, the
  function-level requirement it verifies; `ext.3.1.schemathesis` loses API10:2023, which is the API's trust in data
  it consumes from third parties, and rests on CWE-20, ASVS 2.2.1 and SI-10; test 5.2's `800-61 §2.3` is
  "Incident Response Policies, Processes, and Procedures", not alerting (now §3.2, CSF outcome DE.AE-06); and test
  6.2 declares CWE-1021, which its own page already cited and which CWE 4.20 allows for mapping. **Changed
  results**: the `references` of those tests in the report and the catalogue; no status, coverage or finding count
  changes.
- **A `POST` or `PATCH` that timed out was sent again, so one request could be applied several times** (found
  reviewing the client's retry policy, 2026-10-28). Every transport failure was retried for every method: measured
  against a server that counts what it receives and answers too late, a `POST` was sent **three times** and applied
  three times. On a target whose create endpoint is slow, `create_resource` would leave two objects behind that the
  tool never learned of, with no teardown registered for them, and the retry is not theoretical: on crAPI a run
  retried `POST /workshop/api/shop/orders` twice. A method that is not idempotent (`POST`, `PATCH`, RFC 9110
  section 9.2.2) is now retried only when the failure proves the request never reached the application (connection
  refused, connect or pool timeout); after a read or write timeout or a protocol error it is reported as a failure
  whose message says the request may already have been applied. Verified against the same server: `POST` and
  `PATCH` one attempt, `PUT`, `DELETE` and `GET` three, and with the connection refused all of them three.
- **Every cookie the target set was replayed on every later request of the run** (found reviewing the authentication
  helpers, 2026-10-28). `SecurityClient` wraps an `httpx.Client`, which keeps a cookie jar and sends it to the host
  on each request: measured on the reference lab, Forgejo answers a probe with `Set-Cookie: i_like_gitea=...` and
  from then on every request carried it, absent from the evidence (the record holds the headers the test set, not
  the ones the transport adds). A cookie is never a credential for this tool (`credentials.auth_type` has no cookie
  method, and the compatibility table says session cookies are not implemented), so a session cookie on a target
  that sets one at login would have authenticated the probes the tests send **without** a credential (1.1, 1.2,
  1.3) and could have carried one role's session into another role's request (2.2). The jar is now cleared after
  each response; the `Set-Cookie` of the response is still recorded as evidence, which is what test 1.6 judges.
  No change on the three labs (29, 29 and 28 native tests: identical statuses, coverages and finding counts).
- **Ctrl+C or SIGTERM arriving during the teardown left resources on the target, while the tool reported the
  cleanup had run** (found reviewing the resource helper, 2026-10-28). The CLI's stop handler raises wherever the
  main thread is, so a first signal delivered inside the Phase 6 loop aborted the deletions still pending: measured
  on the reference lab by signalling the instant Phase 6 started, 3 of 8 resources were left behind, 3 Forgejo API
  tokens among them, and the run still logged `assessment_interrupted detail='Teardown ran'`. The engine now defers
  both signals for the duration of Phase 6 (`_stop_signals_deferred`, `signal.pthread_sigmask`): the same
  experiment now logs `teardown_completed success_count=8 failure_count=0` and leaves nothing on the target, with
  the exit code unchanged (`143`) and the same message. The exit-code reference promised this behaviour already.
- **The configuration values concept came back in a different order on every read.** Both gateways answer a plugin
  configuration as a serialised Lua table, whose key order is not stable, so the pinned evidence of the concept and
  the order of test 6.4's findings changed between two runs against an unchanged target. The order is now defined
  once, in `sorted_config_values` (by location, then key), and both adapters return their values through it. Checked
  by reading all seven concepts three times on the three labs: every concept now identical, byte for byte.
- **The Kong circuit-breaker concept looked for field names the plugin it recognises does not use.** The adapter
  recognises `circuit-breaker` (dream11/kong-circuit-breaker) by name, but read its threshold and open-state from
  `failure_threshold` / `consecutive_errors` / `timeout` / `sleep_time`, while that plugin states
  `failure_percent_threshold` and `wait_duration_in_open_state`: the concept answered "not stated" for values the
  gateway does state, and the note of test 4.3 printed "threshold None". The plugin's own names come first now,
  checked against its README (read 2026-10-28). Proven by reading the reference Kong through a proxy that adds such
  a plugin with its documented configuration: "threshold 51".
- **The gateway configuration scan of test 6.4 read nothing at all on Kong** (found reviewing the adapters,
  2026-10-28), so its PASS rested on an empty scan. Two causes, both in the shared code. The Kong reader collected
  `service["url"]`, a field Kong's Service object does not have (`GET /schemas/services` holds `protocol`, `host`,
  `port`, `path`): the address is now rebuilt from those fields. And `collect_text_values` descended into arrays
  only for items that are objects, skipping a string that is an item of an array, which is exactly how a gateway
  plugin states a header (`config.add.headers[0] = "Authorization: Bearer ..."`): such strings are now collected,
  with an indexed key. The values the scan reads went from 0 to 11 on Forgejo + Kong, 0 to 25 on crAPI + Kong and
  11 to 15 on Forgejo + APISIX. Proven by planting a GitHub-PAT-shaped token in a plugin header list of the
  reference lab: **FAIL**, `VIOLATION/CONFIG_SECRET` naming `config.add.headers[3]`, where the old reader collected
  0 values and saw nothing. The lab change was undone and verified. **Changed results**: none on the labs as
  configured (6.4 still PASS on all three, no false positive from the newly read values).
- **A PASS could claim `complete` coverage while part of the test never ran** (found reviewing the verdict
  arithmetic, 2026-10-28). `coverage` became `partial` only when cases were not verifiable, so a declared sub-test
  that verified nothing did not lower it: on the reference lab, 6.2 passed `complete` with its CORS sub-test judged
  `NOT_APPLICABLE` and 6.4 passed `complete` with its debug-endpoint sub-test never made. A `PASS` is now `complete`
  only when every declared sub-test verified something, so both report `partial`. **Changed results**: coverage of
  6.2 and 6.4 (statuses, finding counts and exit codes unchanged, verified by re-running the 29 native tests on all
  three labs).
- **The report did not honour its own schema for `sub_tests`.** `report-schema.md` states that the array holds every
  declared sub-test, but a test that skipped before judging (1.6, 5.2, 7.1, 7.3, 7.4 on the reference lab) returned
  it empty, while a test that ran and applied to nothing (1.2, 1.3, 2.4) returned its sub-tests as SKIP: the same
  situation in two shapes, which an integrator cannot rely on. `_skip()` now reports the declared sub-tests at zero
  counters, so the shape no longer depends on the outcome. A caller that had already judged something keeps the
  result it had.
- **Test 4.3 passed a Kong gateway with no health check at all** (found in the test-by-test review, 2026-10-27).
  The oracle accepted a backend as protected when its `active` health-check record existed, but Kong answers
  `GET /upstreams` with its defaults filled in, so a backend with nothing configured comes back with a complete
  `active` record whose intervals are zero, which means it is never probed. Any Kong gateway with at least one
  upstream was therefore reported `ENFORCED/HEALTH_CHECK`, CERTAIN, with a note claiming a failing backend was taken
  out of rotation, and the `VIOLATION` branch was unreachable. A health check now counts only when it can notice a
  failure: a passive threshold above zero, or an active probe on healthy targets. Proven on the lab by removing the
  upstream's `healthchecks` block (**FAIL**, where the old oracle said PASS).
- **Test 4.3 could report a violation it had not established.** The SKIP needed *both* gateway concepts to be
  unreadable, so a gateway that answered `/upstreams` but refused `/plugins` fell through to
  `VIOLATION/NO_CIRCUIT_BREAKER` with CERTAIN confidence, stating the gateway had no breaker without having read the
  breakers. The test now distinguishes the two answers the adapter already separated: a concept the gateway does not
  have (`NOT_SUPPORTED`) counts as absent, while a concept that could not be read (`NOT_ACCESSIBLE`) gives
  `NOT_VERIFIABLE/GATEWAY_READ_FAILED` and an INCONCLUSIVE status. The SKIP reason now names both concepts, not only
  the breakers.
- **Test 4.3's note stated a Kong fact on every gateway:** "Kong has no breaker plugin, this is its mechanism" was
  printed on an APISIX run, where `api-breaker` exists. The note is now gateway-neutral and says instead which
  backends are not re-enabled by themselves (`HealthCheck.recovers_automatically`), which the oracle computed and
  never reported.
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

- **Two data modules and six symbols nothing referenced**, found by a sweep over every module-level symbol of
  `src/` and `scripts/` (126 modules, 1,250 symbols) at the close of the infrastructure review, 2026-10-28:
  `src/tests/data/auth_payloads.py` (57 lines, only `MALFORMED_TOKENS`, which test 1.1 replaced with its own
  `_MALFORMED_VALUES`), `src/tests/data/shadow_wordlists.py` (119 lines: tests 0.1 and 0.2 derive their paths from
  the specification and the gateway's routes, and ffuf uses SecLists with `src/core/sensitive_paths.py`),
  `REDIRECT_SSRF_SENTINEL` (the redirect-chain SSRF that test 7.2 leaves out), `references.confidence_of`,
  `cli.DEFAULT_LOG_LEVEL`, `loader.DEFAULT_CONFIG_FILENAME`, and `evidence.EVIDENCE_OUTPUT_FILENAME` with
  `evidence.RESPONSE_BODY_MAX_CHARS` — the latter a second copy of the live truncation limit
  (`_EVIDENCE_RECORD_BODY_MAX_CHARS` in `core/models/http.py`, same value), so editing it changed nothing. Three
  stale claims went with them: two docstrings named `injection_payloads.py`, which never existed, and the design
  property D2.P8 and the extending guide listed four payload modules of which two were dead. The 29 native tests
  give identical statuses, coverages and finding counts after the deletions.
- **`PATH_PARAM_FALLBACK_SAFE_DELETE`, a safety constant no caller ever passed** (2026-10-28). The resolver declared
  `"apiguard-probe"` as the fallback for a parametric DELETE probe, and the design properties described it as a
  protection in force ("a request that slips past the gateway finds nothing to delete"), but no test ever passed it:
  the claim described a protection that did not exist. What does keep a write off a real object was already there
  and is stronger: test 1.1 sends every write method to `random_sibling_path`, which fills each parameter with a
  random value. The design property and the helper list say that instead now.
- **Five functions of `response_inspector.py` and one data list, none of them called by any test** (found reviewing
  the shared helpers, 2026-10-28): `check_security_headers`, `find_missing_security_headers`,
  `find_invalid_security_headers`, `contains_sensitive_fields`, `auth_errors_are_uniform`, with
  `SECURITY_HEADER_DEFINITIONS`, `_NORMALIZED_SENSITIVE_FIELD_NAMES`, `_scan_dict_for_sensitive_fields` and
  `SENSITIVE_FIELD_NAMES` in `src/tests/data/inspector_patterns.py`. They were written before the block-6 test
  review and left behind by it, so the repository held two definitions of "a sensitive field" and two of "the
  security headers the tool checks", the dead ones wider than the live ones. Each job is done elsewhere: the header
  policy by test 6.2, whose scope was decided in the review (HSTS moved to 1.5, which checks `max-age` against a
  bound; Permissions-Policy dropped as outside ASVS 3.4) and whose framing check already refuses the deprecated
  `allow-from`; the sensitive field names by test 2.5's own list; the uniformity of authentication errors by test
  1.7, which compares a fingerprint of the body and the response times rather than the bodies as they are. The
  module keeps the three detectors test 6.1 uses: 411 lines to 195, and 127 to 82 in the data module. The 29 native
  tests give identical statuses, coverages and finding counts on the reference lab.

- The sslyze connector and the `[sslyze]` optional extra (Q-11, Q-24): `SslyzeConnector`, `SslyzeConfig`, the
  `external_tools.sslyze` configuration, the `ext.1.5.sslyze` external test and the Hatch default-environment
  feature. sslyze (with its transitive `nassl`) is AGPL v3 and was imported in-process; on the labs it found no TLS
  weakness testssl.sh did not already report, so guarantee 1.5 stays covered by `ext.1.5.testssl` alone. The
  `BaseLibraryConnector` tier is kept as the documented extension point for a future Python-library tool.
- `hatch run dev:docs` and the `pydoc-markdown` development dependency (Q-13): its output, `docs/API_REFERENCE.md`
  (the docstrings of a fixed list of modules), was not kept in the repository nor used; the docstrings stay in the code.
- The lab's committed self-signed certificate and private key (`test-environments/forgejo-kong/certs/`) and
  `gen-certs.sh`: no private key is in the repository; the labs generate their certificates (see Added).
- `TargetContext.effective_base_url` and the `<TOOL>_SERVICE_URL` tool discovery: both were never functional.
  External tools are found in `./tools/` or `PATH`; a missing tool gives SKIP (with `<TOOL>_SERVICE_URL` set it
  used to give ERROR).

### Changed

- **Block-6 test review: the test logic was rewritten** (it is not unchanged since 0.1.0). Every test's oracle was
  rebuilt on the new assessment model; several tests changed the strategy and priority they declare (read them with
  `apiguard list-tests`). Existing tests of 0.1.0 were reworked (e.g. 1.1 records `5xx` as `NOT_VERIFIABLE` instead
  of a silent PASS; 2.1 counts a `404` as enforced only when a positive control proves the operation exists; 1.5's
  HTTP/HSTS checks are native and the TLS handshake is testssl). 3.2 is covered by 6.1; `ext.0.1.nuclei` was
  replaced by `ext.0.1.ffuf`.
- Test 2.2 (Object-Level Authorization, BOLA) is now priority **P0** (was P1), applying the methodology's
  importance criterion to the OWASP API Top 10, where BOLA is API1:2023, the top risk (Q-33). It now runs under
  `min_priority: 0` (P0 only); the other authorization tests (2.1, 2.4, 2.5) stay P1.
- The usage guides state a fact once and link to its page (Q-04): the exit codes are explained in `exit-codes.md`
  (`read-the-report.md` keeps the two warnings for a reader, `integrate-apiguard.md` only what a program should
  do); the output files in `read-the-report.md`. Fixed on the way: an interrupted run keeps `config_used.yaml` and,
  when the tests had started, `evidence_tmp/` (verified with Ctrl+C on the lab; the guides said only
  `evidence_tmp/`); the integration guide said exit `3` means "no violation found" (an ERROR result may carry
  findings); `evidence.json` redacts more than `Authorization` (cookies, the known secrets); the first assessment
  showed nuclei's old 240 s limit (600); `configure-a-target.md` now says what 1.4, 2.1 and 7.2 need besides the
  accounts, and points to `apiguard list-tests -c`.

- The developer tables are generated from the code (Q-04): the result helpers and the evidence calls
  (`add-a-native-test.md`), the connector bases, their helpers and the methods an external test implements
  (`add-an-external-test.md`), the gateway concepts with the tests that use them (`add-a-gateway-adapter.md`), the
  exceptions (`docs/04-architecture/01-overview.md`): signatures from `inspect`, the text from the first paragraph of each
  docstring, rewritten for the guides and checked against the code. Fixed on the way: the native test guide still
  said to guard with `_requires_admin_api` (removed: a test declares `Need.GATEWAY`); the connector attributes
  `DEFAULT_TIMEOUT_SECONDS` and `LOCAL_TOOLS_SUBDIR` have defaults (the guide listed them as required);
  `SecurityClientError` never comes from an HTTP status, and its `status_code` is always `None` (its docstring said
  503 is retried and 502 is reported); `AuthenticationSetupError` follows any login status that is not 2xx (not only
  401/403); `GatewayAdapterError` is caught by the concept readers, not by the tests; `generate-seed` exits with a
  named constant.

- Every description generated into the reference was checked against the code that does what it says (Q-04),
  and corrected where it did not match: the usernames are not secrets (never registered: they appear in the
  outputs, e.g. in a path) and no longer carry `SECRET_VALUE`, so `config_used.yaml` writes a username as given;
  passwords and tokens are masked only with 8 characters or more; `execution.test_ids` sets aside both
  `min_priority` and `strategies`, for native and external tests (the page said strategies only for native ones);
  `specification.timeout` is the download's timeout and, separately, the limit of the `$ref` dereferencing;
  `path_seed` falls back to `apiguard-probe` in a DELETE; with a declared security scheme `send_as.in` and `name`
  may repeat the scheme's; `list-tests --config` does not read the certificates nor the specification;
  `tool_artifact_label` is the external test's ID; `all_rows` and `not_run` are ordered by `test_id` as text.

- **Breaking:** the text of an exit code has one definition (`EXIT_CODES`, `src/core/models/enums.py`), used by the
  report (`executive_summary.exit_code_label`), the console summary, `apiguard run --help` and
  `docs/03-reference/03-exit-codes.md` (generated); before, five places described the codes with different words. The
  label in the JSON report changes, e.g. `FAIL — At least one security guarantee violated` becomes `FAIL - at least
  one security guarantee is violated`; `exit_code` is unchanged. Each meaning checked against the code: exit `3`
  may come with findings (an ERROR result may carry some), exit `10` also follows an unexpected error after the
  tests ran.
- `docs/03-reference/05-evidence-format.md`: the tables of the file and of `EvidenceRecord` are generated (`evidence_table`,
  Q-04); the top level of `evidence.json` has a model (`EvidenceFile`, `src/core/models/http.py`) instead of a
  dictionary built by hand, and the file written is the same, character by character. Fixed on the way: the code
  said the request body is not sanitized (the registered secrets are replaced); a tool output stored in
  `evidence.json` is truncated like any body, the full output being in `tools/<label>_output.json`.

- `docs/03-reference/04-report-schema.md`: the table of every model of `apiguard_report.json` (`ReportData`,
  `ConnectionTrust`, `ExecutiveSummary`, `NotRunEntry`, `DomainSummary`, `TestResultRow`, `Finding`, `InfoNote`,
  `TransactionSummary`) and the domain names are generated from the models (`report_table`, `domain_names_table`,
  Q-04); the field descriptions in the code now carry the page's wording (checked against a real report: the JSON has
  exactly the models' fields). The labels and the truncation limits come from their constants. Fixed on the way:
  `total_finding_count` counts the findings of every result (the page said FAIL only); the code's descriptions of
  `request_headers`, `findings` and `notes` were outdated (typed placeholders, findings on ERROR, notes on any status).

- `docs/03-reference/02-cli.md`: the syntax line and the options table of every command are generated from the CLI
  (`scripts/generate_docs.py`, `cli_synopsis` and `cli_options`, from Typer's command objects, Q-04); the help texts
  in `src/cli.py` now carry the page's wording, so `apiguard <command> --help` says the same. Fixed on the way: the
  syntax of `run` lacked `--env-file`, the syntax of `generate-seed` lacked `--config` and `--env-file`, and its
  `SPEC` argument was given as required (it is optional: `--config` is the alternative). `--env-file` and `--output`
  show their real default in `--help` ("'.env' in the working directory", "stdout").

- The tables of `docs/03-reference/01-configuration.md` outside `tests` (`target`, `specification`, `gateway`, `tls`,
  `credentials`, `resources`, `execution`, `output`, `external_tools`) are generated from the configuration schema
  (`scripts/generate_docs.py`, `configuration_table`, Q-04): key, type with its range, default, description; the
  descriptions in the code now carry the page's wording (60 fields). Fixed on the way: `dev_mode` reads
  `<output.directory>/tools/<label>_output.json` (the page said `outputs/tools/`) and, without it, runs the tool and
  saves the file; `resources.<name>.delete.path` is required in a `delete` block (the page said "none"). The
  `external_tools` keys are one table, with each tool's own defaults and ranges.

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
  `docs/04-architecture/05-design-decisions.md`, D8). `src/test_config/` (the per-domain models, their containers and
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
  removed (block 10b, `docs/04-architecture/05-design-decisions.md`, D8): `tests.domain_3.test_3_3.plugin_names`, `field_clock_skew`,
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
  (block 10b, `docs/04-architecture/05-design-decisions.md`, D8). The declaration is a Pydantic model, checked when the module is
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

- **Breaking:** the configuration is organised by connection (`docs/04-architecture/05-design-decisions.md`, D1): `target` is
  the API (address, `tls`, `connect_timeout`, `read_timeout`, `max_retry_attempts`, `path_seed`), `specification` the
  OpenAPI document (`url` or `path`, `timeout`, `tls`), `gateway` the gateway (`adapter`, `admin` with `url`,
  `headers`, `connect_timeout`, `read_timeout`, `tls`, and `health` with `url`, `tls`). The previous keys moved:
  `target.openapi_spec_url` / `openapi_spec_path` → `specification.url` / `path`,
  `execution.openapi_fetch_timeout_seconds` → `specification.timeout`, `target.gateway_adapter` →
  `gateway.adapter`, `target.admin_api_url` → `gateway.admin.url`, `target.admin_connect_timeout_seconds` /
  `admin_read_timeout_seconds` → `gateway.admin.connect_timeout` / `read_timeout`, `execution.connect_timeout` /
  `read_timeout` / `max_retry_attempts` → `target.*`. Table: `docs/03-reference/01-configuration.md`, "Keys moved".
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
- **Breaking:** authentication is configured in two parts (block 7+8 phase C, `docs/04-architecture/05-design-decisions.md` D5).
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
- **Breaking:** prepared resources (block 7+8 phase E, `docs/04-architecture/05-design-decisions.md` D6): what the tool creates on
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
  `docs/03-reference/06-compatibility.md`.
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
  `docs/03-reference/06-compatibility.md`.
- `config.yaml`: `path_seed` reads the lab names from `.env`; `sha` is `main` instead of a commit hash that
  changed on every new lab.
- `external_tools.sslyze.extra_flags` removed: it never had an effect (sslyze is a library, not a command line);
  `extra_flags` remains for testssl and nuclei.
- Test 7.2: the redirect sub-test is called "Sub-test G" in the report texts (was "Sub-test E", which is the DNS
  bypass sub-test).
- Internal: the gateway adapter interface is made of neutral concepts (`src/core/gateway/concepts.py`, one
  reader per concept, read once per run); the Kong-shaped methods (`get_services`, `get_plugins`, ...) are gone;
  adapters are registered in `GATEWAY_ADAPTERS`. Guide: `docs/02-guides/03-extending/04-add-a-gateway-adapter.md`.
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
  ([catalogue](docs/05-tests/README.md)).
- 3 external-tool tests: `ext.0.1.nuclei`, `ext.1.5.testssl`, `ext.1.5.sslyze`; `install_tools.sh` for the binaries.
- Kong gateway adapter (DB-less Admin API) for configuration-audit tests.
- Reports: `assessment_report.html`, `apiguard_report.json` (`output_schema_version` 1.0), `evidence.json`.
- CLI: `run`, `validate-config`, `generate-seed`, `version`; exit codes 0, 1, 2, 10.

[Unreleased]: https://github.com/eneamanzi/apiguard-assurance/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/eneamanzi/apiguard-assurance/releases/tag/v0.1.0

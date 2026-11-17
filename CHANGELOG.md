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

- **Every test page says which branches of its oracle have been seen (2026-11-14).** The 17 native pages that did
  not have it got the paragraph "What each branch has been seen doing" (rule 9) at the end of their Validation
  section, written only from what that section records: proven on a lab, seen off the labs (a scratch server, a
  stand-in Admin API, a proxy), still unproven, and, where the page is ambiguous, to re-verify with the reason. The
  11 native pages that had it and the 3 external pages were checked the same way: branches they did not name were
  added, and nine claims their own section or the code does not support were moved to "to re-verify". The sixteen
  items to re-verify were then run on the labs, one test at a time, every lab change undone and checked: fifteen
  are settled in their pages, one (1.7's timing branch) is the owner's decision. The runs also produced the two
  sides of 2.4 (a version that drops the check, one that keeps it) and the "backend unavailable" branches of eight
  tests, and showed six behaviours written on their pages for the owner to judge (2.4's absence rule, 0.4 and 6.2
  with a stopped backend, a timeout reported by Schemathesis as a server error, 1.1's note, 1.7's timing branch).
  Test 1.2's page named its details `ACCEPTED_TAMPERED` and `ACCEPTED_STRIPPED`: the code's are
  `ACCEPTED_TAMPERED_PAYLOAD` and `ACCEPTED_STRIPPED_SIGNATURE`.
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

- **Test pages that had fallen behind their code (2026-11-16).** Read against each module (the sub-tests it
  declares, the details it writes, its finding titles), eight pages lacked something: finding titles never documented
  (0.1, 1.1, 6.2) or documented with an old wording (0.2, 1.5 "Credential-bearing request ...", 1.6 "Session cookie
  without ..."), details not listed (1.1's `CREDENTIAL_REFUSED`, `NOT_SERVED` and its five malformed cases, 2.2's
  three `NO_*_OPERATION`, 7.2's four `SSRF_BLOCKED_*`). All aligned to the code.
- **A test's oracle is declared in its code, and its page's tables are generated (2026-11-16).** Each case is one
  line of `TestInfo.oracle` (`OracleCase`: when, outcome, detail, confidence); `dev:gen` writes section 6 of the
  page from it (`oracle_table`) and section 8 from the titles of the test's findings (`finding_titles`), and a test
  that records a judgement its oracle does not declare ends in ERROR (`AssessmentTest._record`), as one with an
  undeclared sub-test did already. A test without a declared oracle is not checked; the tests move to it one at a
  time, with their review. First: 4.4.
- **4.4 reviewed (2026-11-16).** It sent a POST whatever the documented method of the write it probed: on an
  operation documented only as PUT or PATCH a gateway may refuse the method before any size check (Kong's `404`
  "no Route matched"), which read as a forwarded body; it now sends the documented method, and its finding names it.
  ASVS v5.0.0-2.4.1 is no longer cited: it is about excessive calls (test 4.1), and ASVS 5.0.0 has no requirement on
  the size of a request body; OWASP API4:2023 asks for it ("define and enforce a maximum size of data on all
  incoming parameters and payloads"). A second sub-test, `chunked_body_rejected`, sends the same body in chunks
  (`Transfer-Encoding: chunked`, no `Content-Length`; `SecurityClient` takes a tuple of chunks): a gateway that
  weighs only the declared length lets it through. Kong's `request-size-limiting` and APISIX's `client-control`
  refuse it with `413` (measured with a 1 MB limit on each). **Changed results**: on the three labs as configured
  (no size limit), one more 4.4 finding, "Oversized body not rejected: <probe> (chunked)"; the probe is the same
  documented POST. The guarantee said the gateway refuses the body, but a `413` from the gateway and one from the
  application are the same answer, told apart only by signals of one gateway (rule 10): it now says the body is
  refused before it is processed, by the gateway (where the limit belongs) or else by the application, and the
  page's Limitations say which of the two answered is not told (catalogue heading "Request body size is limited at
  the boundary").
- **4.1 reviewed (2026-11-16).** Its oracle is declared in code; the review found these, each verified on a lab
  variant (test page, section 12). A burst refused by a `401` or `403` was judged as it was: on a gateway that
  authenticates before its limit (Kong and APISIX run authentication, ACL and IP restriction first: plugin priorities
  read in the labs' gateways) a configured limit was reported "not enforced". Such a burst is now sent again with
  user_a's credential (optional need), and refused again it is `NOT_VERIFIABLE/REFUSED_BEFORE_LIMIT`, without user_a
  `NO_CREDENTIAL_TO_RETRY`. A limit's own refusal status is read (`RateLimit.refusal_status`: Kong `error_code`,
  default `429`; APISIX `rejected_code`, default `503`): APISIX's default refusal ended as `LIMIT_OR_UNAVAILABLE`, now
  `RATE_LIMITED`. The burst no longer has a size fixed in advance (twice the largest count plus one, which assumed a
  burst shorter than the window): it goes on until every limit read is provably exceeded, or `max_burst`. The FIRM
  finding without a limit read said "no limit at or below" the burst, while a burst may straddle two windows: it now
  names the limits surely absent (fewer than half the burst per window as long as it). `ip_spoofing_resisted`
  recorded `NOT_APPLICABLE/NO_LIMIT_TO_BYPASS` also when a limit may exist (`limit_enforced` not verifiable): now
  `NOT_VERIFIABLE/NO_LIMIT_SEEN`; and `IP_SPOOF_BYPASS` is CERTAIN only when a plain request after the spoofed burst
  is still refused, FIRM otherwise (shown for the first time on a real gateway: Kong trusting `X-Forwarded-For`).
  The probe prefers a GET without a security requirement; a run of `503` reads as a possible limit after any answer
  that says something, not only a served one; a request without an answer no longer counts as reaching the gateway.
  **Changed results**: on crAPI the probe is `/workshop/api/mechanic/receive_report` (was `/workshop/api/mechanic/`),
  still FAIL FIRM; the Forgejo labs unchanged.
- **4.2 reviewed (2026-11-16).** ASVS v5.0.0-16.5.2 is no longer cited (it names circuit breakers and graceful
  degradation, test 4.3); 13.2.6 is, the requirement that names connection timeouts to separate services. A timeout of
  `0` now means "no bound" in the concept (`BackendTimeout`), and its detail `NOT_CONFIGURED` is `UNBOUNDED`: an unset
  timeout is judged at its default, so "not configured" named the wrong case (neither gateway accepts `0`). The page
  listed a finding title the code no longer wrote; sections 6 and 8 are now generated. No result changes.
- **4.3 reviewed (2026-11-16).** A gateway whose Admin API answered neither read (circuit breakers, health checks)
  was SKIP, against the rule of 2026-11-04 (a concept the gateway has and that could not be read makes the test
  INCONCLUSIVE): now `NOT_VERIFIABLE/CONCEPT_NOT_ACCESSIBLE`, the shared detail, which also replaces its own
  `GATEWAY_READ_FAILED`; SKIP only for a gateway that has neither concept. No result changes on the labs.
- **A gateway concept that could not be read is a shared case (2026-11-16).** `CONCEPT_NOT_ACCESSIBLE`, recorded by
  `BaseTest._unread_concept`, is in core with the answers that say nothing: a test whose oracle is declared may
  record it without declaring it (otherwise test 4.2, with its oracle declared, would have ended in ERROR on an
  unreadable Admin API), and the oracle table of every test that reads a concept shows it.
- **An optional account whose login fails no longer makes the test ERROR (2026-11-16).** The engine logs in before a
  test for every account it declares; a failed login of an optional one (`optional_needs`) made the test ERROR, seen
  on APISIX when a rate limit refused user_a's login with `503`. The test now runs without it (a warning,
  `test_optional_account_not_available`); a required one still makes it ERROR. Tests 0.3, 4.1 and 4.4 read the
  optional account through one helper, `optional_role_parts()`, which no longer logs in by itself.
- **Domain 6 reviewed (2026-11-16)**, oracles declared in code, each fix verified on the labs (test pages,
  section 12). **6.1**: `no_debug_field` passed without looking at anything when the sampled answer was a JSON array
  (Forgejo's `/api/v1/orgs`), a refusal or a HEAD: it now walks objects and arrays of served bodies, and records
  `NOT_VERIFIABLE/NO_JSON_OBJECT` when none was looked at; debug names are exact or `_`-prefixed (a substring flagged
  `search_query`); the error probe tries up to five writes until one is parsed (Forgejo's first is refused by scope,
  so no error was ever provoked there: now `NO_STACK_TRACE` via `POST /api/v1/markup`); the request's own path is
  taken out of the error body before scanning; a leaky header is CERTAIN only with a version, and `Via` naming a
  version is judged; each finding cites its own ASVS requirement (the stack trace 16.5.1, not 13.4.2). **6.2**: a
  header sent twice (`nosniff, nosniff`) read as missing, CERTAIN: now read as browsers do; `frame-ancestors
  https://*` passed; X-Frame-Options alone is `XFO_ONLY` with a note (ASVS 3.4.6 asks for `frame-ancestors`); a refusal
  without CORS headers was `ORIGIN_NOT_ALLOWED`, now only a served answer counts (`PROBE_NOT_SERVED` otherwise).
  **6.4**: the credential found on a served debug path was copied in clear into `evidence.json` and the report: it is
  now registered as a secret and redacted; a served `.env` or actuator body is read for credential-named keys
  (`DB_PASSWORD=...`), not only token patterns; a header in Kong's header lists is keyed by its name; a redirect is
  `NOT_VERIFIABLE/NOT_INTERPRETED`, not blocked; an unreadable configuration follows the shared rule
  (`CONFIG_NOT_READABLE` is gone); five more credential patterns; the debug finding cites CWE-215 and ASVS
  13.4.2/13.4.5. **Changed results**: 6.2 on the three labs records `XFO_ONLY` with a note; 6.1's `no_stack_trace` is
  now proven on the Forgejo labs.
- **Domain 7 reviewed (2026-11-16)**, oracles declared in code, each fix seen on a lab (test pages, section 12).
  **7.2**: an endpoint that fetches the URL and answers a failed fetch with a `4xx` passed: crAPI's `contact_mechanic`
  (SSRF-vulnerable, it returns the fetched page) answered its loopback payloads `400` "Could not connect" and they
  read as blocked, one run away from a PASS on an essential class. An unreachable control (a random `.invalid` host)
  now shows what a failed fetch looks like (`REJECTED_LIKE_UNREACHABLE`); the benign control is sent again after the
  series and each ENFORCED waits for it; a payload's `2xx` carrying a cloud-metadata marker on an endpoint that returns
  what it fetches is a proven `VIOLATION/SSRF_CONTENT_REFLECTED` (CERTAIN), the one exception to the listener
  boundary; loopback payloads go before the cloud-metadata ones (which hang off-cloud); only an invalid or forbidden
  answer is a rejection; ASVS v5.0.0-1.3.6 cited. **7.1**: `NO_ANTI_AUTOMATION` is FIRM (an acceptance is not an
  effect); AWS WAF's and Cloudflare's challenge headers count; weak words count only after a served submission.
  **7.3**: ASVS 2.3.4 cited; a resource not created is `NOT_VERIFIABLE/OBJECT_NOT_CREATED` (7.2 too), not ERROR.
  **7.4**: the validly signed delivery goes last (an event-ID cache made the first order a false PASS or FAIL); a
  forged delivery accepted is FIRM. **Changed results**: crAPI 7.2's `private_ip` is `REJECTED_LIKE_UNREACHABLE`
  (INCONCLUSIVE, as the test was); crAPI 7.1 FIRM.
- **Domain 0 reviewed (2026-11-16)**, oracles declared in code (test pages, sections 6, 8, 12). **0.4**: the adapters
  report every target their gateway routes to, not only the health-checked ones (a Kong Service pointing straight at
  a host, an APISIX upstream without `checks`, `UNKNOWN`), so the most common Kong setup is now tried (a checked APISIX
  upstream's nodes were also added again by name, as unchecked, until the final regression run of 2026-11-17 showed it); a declared
  loopback address is `GATEWAY_LOCAL_ADDRESS`, not asked on the tool's machine; a derived address answering while
  the gateway refused the probe itself is `GATEWAY_REFUSED_PROBE`, not `ANOTHER_SERVICE`; the probe path prefers a
  public GET. **0.1**: a `401`/`403` unlike the siblings is `REFUSED_BEFORE_METHOD`, not a FIRM
  `UNDECLARED_METHOD_KNOWN` (an authentication runs before dispatch); TRACE refused likewise is not "not served"; an
  undocumented version is calibrated against a random version, and a `404` unlike it is `VERSION_UNCLEAR`; the route
  comparison prefixes the base URL's path; the Kong adapter anchors route regexes and writes PCRE's `(?<name>` as
  Python's, and reports the routes of a disabled Service disabled; a regex that does not compile is `ROUTE_NOT_READ`,
  not a CERTAIN finding; the TRACE finding cites ASVS 13.4.4. **0.2**: without a gateway `near_route_paths` is `NO_GATEWAY`; the over-match finding no longer says the route's policies
  are skipped. **0.3**: a `404` unlike the siblings is not "still served"; a parametric path answering like a random
  object is `OBJECT_OR_OPERATION_ABSENT` (NOT_VERIFIABLE). Unreadable concepts follow the shared rule
  (`ROUTES_NOT_READABLE`, `ADDRESSES_NOT_READABLE` gone). The catalogue's references for 0.1 to 0.4 are the code's
  (it cited ASVS V4.1.1, the Content-Type requirement). **Changed results**: crAPI 0.1 loses its
  `UNDECLARED_METHOD_KNOWN` finding (now `REFUSED_BEFORE_METHOD`); crAPI 0.4 adds two FIRM findings (the identity and
  community backends' declared addresses answer directly).
- **Domain 1 reviewed (2026-11-16)**, oracles declared in code (test pages, sections 6, 8, 12). **1.1**: a write
  without path parameters was probed on a random sibling of its path, so it never reached the operation (crAPI's
  identity writes read `CREDENTIAL_REQUIRED` from a nonexistent path): it now goes to its own path; a `2xx` is compared
  with a random path (`SERVED_LIKE_UNKNOWN`, `VARIANT_LIKE_UNKNOWN`: a catch-all no longer makes every path a
  violation); a malformed credential not served is `CREDENTIAL_REFUSED` (a `400` was NOT_VERIFIABLE); an empty
  `OPTIONS` answer is `OPTIONS_ANSWERED`; the variants cite CWE-288, not ASVS 6.3.4. **1.2, 1.4**: only `400`, `401`,
  `403` are refusals (`NOT_A_REFUSAL` otherwise); a forged or revoked token served is CERTAIN only with the genuine
  answer's shape. **1.4**: a credential creation the target did not evaluate is NOT_VERIFIABLE, not ERROR
  (`ResourceSetupError` carries the answer); RFC 7519 4.1.7 dropped. **1.3**: `NO_EXP_CLAIM` is TENTATIVE; without
  `iat` the lifetime is measured from the login. **1.5**: the plain-HTTP probe keeps the base URL's path; HSTS is not
  judged on an answer that says nothing; NIST SP 800-52r2, which says nothing of HSTS, is no longer cited (RFC 6797);
  findings cite their own references. **1.6**: findings are FIRM (whether a cookie carries the session is not
  proven); the `__Host-`/`__Secure-` name prefix (ASVS 3.3.1) is checked; CWE-384 dropped. **1.7**: both account
  names are masked in both bodies (a fixed text holding one name was a false CERTAIN); the attempts run even when the
  comparison's bodies are unstable; durations are compared on unstable bodies too, and a 40 ms gap between every
  reading counts; a stable `500` against a `401` is a disclosure (FIRM); a gateway limit's stated refusal status
  (APISIX's `503`) counts as the limit; the brute-force finding cites CWE-307. The catalogue's references for 1.1 to
  1.5 are the code's (it cited NIST SP 800-63B-4 sections that do not exist, ASVS 11.5.1, and a "5-15 minutes"
  NIST does not state). **Results**: the same verdicts on the three labs.
- **Domain 2 reviewed (2026-11-16)**, oracles declared in code (test pages, sections 6, 8, 12). **2.1**: a refusal of
  user_a while the admin account is refused too is `ADMIN_REFUSED_TOO` (not verifiable), not `REFUSED` (the Forgejo
  labs passed so while the admin token lacked `read:admin`); an operation the specification does not protect but
  that refuses an anonymous request counts as protected; ASVS 8.1.1 dropped. **2.2**: `BOLA_READ` is CERTAIN only
  with the owner's answer; `BOLA_DELETE` CERTAIN only served-then-gone, `DELETE_NOT_APPLIED` when the owner still
  reads the object; an unavailable owner read is not `OWNER_NOT_SERVED_HERE`; a creation without an answer is not
  ERROR. **2.4**: a sibling served like a random path under its version is `SERVED_LIKE_UNKNOWN` (a catch-all was a
  CERTAIN violation); calibration per method; every safe operation is compared, not only those the specification
  protects; ASVS 6.3.4 and CWE-288 replace 8.1.1. **2.5**: a sensitive-named boolean, object or count is not
  exposure; `MASS_ASSIGNMENT` is FIRM and skips the keys the configured body sets; a create refused for the injected
  fields is `INJECTED_CREATE_REFUSED` (not verifiable: rejected unknown fields and a wrong-typed bound field look alike); ASVS 15.3.1 and 15.3.3 replace 14.2.6. The catalogue's references follow
  the code, and RBAC is attributed to ANSI INCITS 359, not NIST SP 800-162 (the ABAC guide). **Changed results**:
  one Forgejo 2.1 operation is `ADMIN_REFUSED_TOO`; verdicts unchanged on the three labs.
- **A login that answers only with a session cookie can be used (owner, 2026-11-16).** A resource value can read a
  cookie the response sets, `cookie:<name>` (validated as a cookie name), and the JSON body is required only for a
  value read from it, so a login answering `204` with `Set-Cookie` works; the credential is sent back as configured
  (`send_as: {in: cookie}`), never through the client's cookie jar, which stays empty. Test 1.6 judges the cookie the
  credential is read from CERTAIN, the others FIRM. Until then such a target could not be logged into and every test
  needing an account ended in ERROR. Existing configurations are unchanged (verified: the account tests of domains 1
  and 2 give the same results on the labs). Verified with a simulated login route on Forgejo + Kong; no lab has a
  cookie-session API, so sending that cookie to a backend that accepts it is not exercised (1.6 Limitations). 1.6's
  page no longer says the name prefixes are unchecked (`COOKIE_WITHOUT_PREFIX` checks them).
- **5.1: a log shipper that ships the credential fails (owner, 2026-11-17).** New sub-test `secrets_not_shipped`:
  per enabled shipper, whether the record it builds carries a request part where the target's credential travels
  (the configured placement and the specification's security schemes), not removed (`CREDENTIAL_SHIPPED`, FIRM;
  ASVS v5.0.0-16.2.5, CWE-532). The adapters state what each record carries (`LogShipper.request`,
  `ShippedRequest`), read on the gateways' sources: Kong redacts only `authorization` and `proxy-authorization`
  and ships the URI as received, `key-auth` `hide_credentials` clears its headers, `custom_fields_by_lua` on the
  request leaves the record not stated; APISIX ships every header and the URI unless a `log_format` or a
  `data-mask` (on the logger's route, or global) removes them, a route's `data-mask` running after a global logger.
  Checked on variants of the three labs and against the records the gateways write (`file-log` on stdout, dummy
  credentials). An independent review against the gateways' sources found five defects and three edge cases
  before release (kafka `origin`, `jwt-auth`'s cookie, Kong's most specific `key-auth`, a plugin in two APISIX global
  rules, Kong's shared custom fields; cached variables, `_meta`, routes by id), all fixed and run again. The labs ship no logs, so their results are unchanged (`NO_SHIPPER`). The page's sources and
  remediation no longer cite ASVS 16.3.3 and NIST AU-2, which the code dropped on 2026-11-16.
- **1.5: a protocol refusal is not cleartext processing (owner, 2026-11-16).** Kong answers plain HTTP on an
  HTTPS-only route with `426 Please use HTTPS protocol`, which read as `HTTP_PROCESSED_CLEARTEXT` (CERTAIN), although
  ASVS v5.0.0-4.1.2 forbids only the transparent redirect and the finding itself recommended answering an error. A
  `426`, or a `4xx` the path does not get over HTTPS, is `ENFORCED/HTTP_REFUSED`; the same `4xx` as over HTTPS, a
  `5xx`, a `2xx` and a redirect are judged as before; a `4xx` with no HTTPS answer that says something to compare is
  `HTTPS_ANSWER_UNKNOWN` (not verifiable). Verified on Forgejo + Kong without the redirect: PASS.
- **3.3, 5.1 and the external tests reviewed (2026-11-16)**; with them every test declares its oracle in code
  (`TestInfo.oracle`), and every page's sections 6 and 8 are generated. **3.3**: a bounded replay window checked on a
  date the signature need not cover is `REPLAY_DATE_NOT_SIGNED` (FIRM): Kong accepts `X-Date` or `Date` and
  requires neither in the signature unless `enforce_headers` lists both (`SigningPolicy.date_signed`); a policy with
  an anonymous fallback is `SIGNATURE_OPTIONAL` (`SigningPolicy.optional`); a new sub-test `content_signed` judges
  whether the signature must cover the body digest and the method and path (`BODY_NOT_SIGNED`, `TARGET_NOT_SIGNED`,
  FIRM; `SigningPolicy.body_signed` now means the body is signed, not only validated, and `target_signed` is new),
  so all three labs now FAIL (Forgejo + APISIX validates the body but does not sign `digest`); a Kong variant with
  `enforce_headers: [date, x-date, digest, request-line]` is PASS; ASVS 4.1.5 and 11.4.1 cited; the Kong lab's
  comments on `hmac-auth` corrected (a NIST claim for the 300 s bound, md5 Kong does not accept, a body "in the
  signature"). **5.1**: a Kong log shipper bound to one consumer no longer counts as logging every request; the
  shippers are read before the configuration values; ASVS 16.3.3 dropped, NIST AU-4(1)/AU-9(2) named. **ext.1.5**:
  an offered TLS 1.0/1.1 (testssl.sh rates it LOW) passed: now `DEPRECATED_PROTOCOL` (CERTAIN), with RFC 8996 and
  ASVS 12.1.2, 12.2.2; a plain-HTTP base URL is SKIP, not ERROR. **ext.0.1**: the time limit no longer throws away
  the base paths already searched (`SEARCH_INCOMPLETE` for the rest); a base path redirecting every unknown path is
  `SEARCH_BLIND`. **ext.3.1**: a case quoting only `501` is `NOT_IMPLEMENTED`, not a finding; ASVS 16.5.3 cited.
  **Changed results**: 3.3 FAIL on both Kong labs (their `hmac-auth` signs no date; until that day PASS).
- **Every dependency is pinned to an exact version (2026-11-16).** The runtime dependencies used
  `>=FLOOR,<NEXT_MAJOR` ranges and the development tools floors only, so a clean checkout, the CI's included, took
  the newest releases: Typer 0.29 broke the checks with no change in the repository (below). `pyproject.toml` now
  pins each one to the version verified that day (`typer==0.29.1`, `ruff==0.17.5`, ...): users, developers and the
  CI install the same versions, and a release changes nothing until its pin is changed. Indirect dependencies are
  not pinned. Hatch's own lockfiles (1.17+) were tried and left out: syncing from the lock removed the project's
  development install, and `hatch env lock --check` fails as soon as a newer compatible release appears
  ([pypa/hatch#2406](https://github.com/pypa/hatch/issues/2406), open).
- **The CI failed since 2026-11-15 on a new Typer (2026-11-16).** Typer 0.29 carries its own copy of Click, and the
  objects it builds for a command no longer have `type`, `make_metavar` or `human_readable_name`: the generator of
  the CLI reference read them, so mypy, and then the generation itself, failed on every clean checkout (Python
  3.11 and 3.14, the runs of `polishing docs` and of the next commit; the last green run had Typer 0.27). The tool
  itself was not affected (the package job passed). The generator now reads the commands' declarations
  (`typer.Option`, `typer.Argument` in `src/cli.py`), the same with either Typer: the CLI reference is unchanged, and
  `dev:check` passes on a clean checkout with Python 3.11 and 3.14 and the latest dependencies.
- **One rule for the answers that say nothing about a guarantee (2026-11-16).** Each test wrote for itself which
  answers to record `NOT_VERIFIABLE` (the gateway unable to reach the backend, a `429`, a `500`, no answer), 24
  times, and the copies differed: test 4.4 read a `429` as a forwarded body (`VIOLATION/NO_SIZE_LIMIT`, produced on
  Forgejo + Kong with a rate limit of 1 per minute), and several tests named a timeout, a `500` or a mix of them
  `UPSTREAM_UNAVAILABLE`, `FLOW_UNAVAILABLE`, `OBJECT_NOT_READABLE` or `NO_USABLE_RESPONSE`. The list is now written
  once (`UNINFORMATIVE_CATEGORIES`, `src/core/response_category.py`), applied by one method
  (`AssessmentTest._uninformative`), and a sub-test whose question is one of those answers declares it with the
  reason (`TestInfo.decisive_answers`: the `429` of 4.1 and 7.1, the `500` of 6.1, ffuf and Schemathesis, the
  timeout of 7.2's payloads). `dev:gen` writes the rule as it applies to each test at the end of its page's
  section 6, and the categories with their HTTP statuses in the assessment model; a test that applies the rule
  without the block on its page stops the generation. Three tests read a `429` as a real answer, and no longer do
  (owner, 2026-11-16): 4.4 (a forwarded body), 1.7's `account_enumeration` (readings all throttled alike read as
  answers that agree, `ENFORCED/TIMING_TOO_SMALL`, produced on Forgejo + Kong with the login answering `429`; its
  `repeated_attempts` keeps the `429` as its verdict) and 0.4 (the gateway's `429` taken as the backend's answer to
  compare a direct one with; a `500` stays the comparison, and no answer is `NO_RESPONSE`, `TARGET_NOT_ANSWERING`
  before). **Changed results**: the three cases above become `NOT_VERIFIABLE/RATE_LIMITED`; the names above become
  the category's (`SERVER_ERROR`, `NO_RESPONSE`, ...); on the three labs as configured, none (measured 2026-11-16: a
  full assessment of each compared with the one before the change, no difference on the two Forgejo labs; on crAPI
  three differences of its own, 4.4's race, 7.2's outbound call cut by Kong's `504` or by the client's timeout, and
  7.3's coupon already claimed in the earlier run; 0.4, 1.7 and 7.3 run again after a reset gave the earlier
  results). Verified on Forgejo + Kong with every test run under a gateway
  answering `503`, then `429`, then `500` (a temporary `pre-function`, undone): each test records the category's
  name, and the declared ones judge it themselves.
- **`6.4` reported one credential twice (2026-11-15).** Kong's Admin API answers a `rate-limiting` plugin's Redis
  password under `config.redis.password` and the older `config.redis_password`, and each key gave a finding. The
  findings of the configuration scan are now one per value per object, the strongest kept and naming the other
  keys. **Changed results**: none on the three labs (no credential in their configuration); the variant with a
  fictitious password gives 1 finding instead of 2.
- **The client sends a path as the test wrote it (2026-11-15).** httpx removes dot segments and reads a leading
  `//` as an authority, so test 1.1's `DOT_SEGMENT`, `DOT_DOT_SEGMENT` and `DOUBLE_SLASH` variants left as the
  canonical path (or as `/v1/user`) while their record showed the variant: they were judged on another path's
  answer. `SecurityClient` now hands such a path to its transport as the request target, keeping the Host header,
  the query, the evidence and the redaction (`src/core/client.py`); every other path goes as before. The
  `path_variants` docstring no longer says test 2.1 uses the variants (it does not import them). **Changed
  results**: none on the three labs (measured: Kong normalises the three, APISIX forwards the dot segments to
  Forgejo's `404`); the three `SERVED_AS_*` branches were produced on Forgejo + Kong (test 1.1's page).
- **`4.1` and `4.4` read the gateway's limits (2026-11-15).** They looked for their limit among the configuration
  text values, which hold strings, while Kong and APISIX state a rate and a body size as numbers: the limit was
  never read, the CERTAIN branch of both was unreachable, and the code took the smallest number anywhere in a
  matching plugin, from any route. Two neutral concepts replace that scan (D7): `rate_limits()`, requests per
  window of seconds (Kong `rate-limiting` `second` to `year`; APISIX `limit-count`, and `limit-req` as a limit not
  counted per window), with whether every node shares the counter; `body_size_limits()`, in bytes (Kong
  `request-size-limiting` times its `size_unit`; APISIX `client-control`). A limit counts only for the routes that
  may serve the probe (`src/tests/helpers/route_limits.py`). Test 4.1's budget is twice the largest window count
  plus one (a burst may straddle two fixed windows), and its CERTAIN needs every limit that may apply exceeded
  within one window and a counter shared by every node (both gateways' default `local` policy counts per node:
  FIRM); its `LIMIT_ABOVE_BUDGET` is now `LIMIT_NOT_REACHED`, with a note. Test 4.4 sends the largest such limit
  plus 1024 bytes. **Changed results**: on the three labs, as configured, none (no limit configured: FIRM as
  before, the finding now naming the route); on a gateway with APISIX `limit-req` 4.1 is INCONCLUSIVE instead of a
  FIRM FAIL (the leaky bucket delays the burst rather than refusing it). Six variants on the labs produced every
  branch (the pages, section 12).
- **`0.2` reported a PASS complete behind a regex catch-all route (2026-11-15).** With a Kong route `~/.*$`, every
  path without a route of its own reached the backend, the backend's `404` was taken for the gateway's refusal and
  the forwarded neighbours looked refused. A regex route path that matches a random path at the root (the shape of
  the refusal's probes, tried with Python's `re` as test 0.1 tries one) now counts as a catch-all:
  `NOT_VERIFIABLE/CATCH_ALL_ROUTE`. **Changed results**: none on the three labs as configured (measured).
- **The Forgejo labs' login token can read the admin operations (2026-11-15).** Its scopes lacked `read:admin`, so
  Forgejo refused the `/api/v1/admin` operations to the admin's token too and test 2.1's admin positive control
  could never confirm one. Both Forgejo labs' `forgejo-token` now add `read:admin`
  ([Forgejo, Access Token Scope](https://forgejo.org/docs/latest/user/token-scope/)), and so does the configuration
  guide's example. **Changed results**: none (2.1 PASS partial; its 6 controls are quota reads that answer `404` to
  the admin as well).
- **The branch campaign on the labs (2026-11-15).** Every branch of every test page is now seen on a lab, seen off
  the labs, or stated unreachable or not producible with its reason, each with the change that produced it. Pages
  corrected on the way: 1.3's five claim branches are produced (a fictitious token from the login), 1.7's
  `LOGIN_NOT_ANSWERING` and 4.4's `NO_RESPONSE` are guards the code cannot reach (their table rows now say what the
  case gives), 1.1's three variants `DOT_SEGMENT`, `DOT_DOT_SEGMENT`, `DOUBLE_SLASH` are not sent as written by the
  HTTP client (owner decision pending), 3.3's policy on a disabled route is judged as configured (owner, 2026-11-15).
- **Six oracle behaviours found by the branch verification on the labs (2026-11-15).** Each was produced on a
  lab, fixed, and produced again (the pages say how):
  - `0.4` reported a PASS when the backend was down: the gateway's `502`/`503`/`504` on the probe path now stops
    the test with `NOT_VERIFIABLE/UPSTREAM_UNAVAILABLE`, since a refused connection cannot tell a down backend from
    an isolated one;
  - `6.2` judged the headers of the gateway's own `503`: an answer that is no response, a `429` or a `5xx` is no
    longer judged by the header sub-tests, as it already was not by the CORS one (`NO_RESPONSE`);
  - `ext.3.1.schemathesis` reported a request that got no answer in time ("Response timeout") as a server error:
    such a case is no longer judged, and an operation left with no other case is `NOT_VERIFIABLE/NO_RESPONSE`;
  - `2.4` took an existing version for an absent one when the first pairs' documented operations answered `404`
    as well: such a pair no longer counts towards `VERSION_ABSENT`;
  - `1.1`'s note said every operation inherits a global `security` when the specification declares none: a third
    note says the specification declares no security requirement;
  - `1.7` recorded `NO_DISCREPANCY` or `TIMING_TOO_SMALL` after `EXISTENCE_DISCLOSED_BY_ANSWER`: they are now
    recorded only when the bodies agree; the timing channel is still judged in both cases (owner decision), and
    section 6 of the page says so.

  **Changed results**: on the three labs, as configured, none (measured 2026-11-15 on the six tests): the changes
  act only where the backend is down, an operation times out, a version is mirrored, a specification declares no
  security, or a login answer differs with comparable durations (`1.7`'s enforced counter).
- **Two statements of the methodology documents, checked against the code (2026-11-14).** `03-guarantees.md` said
  that thirty guarantees have a test and that only 2.3 and 6.3 have none: the code has 28 native and 3 external
  tests, which cover twenty-nine guarantees, and 5.2 has no test either (removed 2026-11-03). Guarantee 0.2 cited a
  "CIS Benchmark API Gateway Controls 2.3" that no test cites and that could not be found; the reference is gone.
  `02-methodology.md` said that every test uses only what its strategy grants: since the owner decision of
  2026-11-04 the strategy is the least access a test needs (`NEED_MINIMUM_STRATEGY`, `src/core/test_metadata.py`),
  and five BLACK_BOX tests also read the gateway when one is configured.
- **The Kong labs' security headers (2026-11-05).** Both `kong.yml` set `X-Content-Type-Options` and
  `X-Frame-Options` with `response-transformer` `replace` only. In Kong, `replace` rewrites a header the backend
  already sent and does nothing otherwise (`header_transformer.lua`, Kong 3.9.3), so crAPI's community service,
  which sends neither, answered without them, and test 6.2 reported a FAIL that was the lab's, not crAPI's. The
  headers are now under `add` as well. 6.2 is PASS on crAPI, and its page keeps the earlier FAIL with its cause.
  `LAB_FINDINGS.md` (new) says, for each finding of the three labs, whether it comes from the application, the lab's
  setup or the specification.
- **Final consistency pass on the code and the test pages (2026-11-05).**
  - Every verdict detail the code can record is now in its test page's oracle table, and every detail a page lists is
    one the code records: added 0.4 `NO_GATEWAY`, 2.4 `CALIBRATION_UNSTABLE`, 6.1 `NO_READ_ENDPOINT`, `NO_ENDPOINT`
    and `NO_ERROR_PROBE`, 6.4 `NO_GATEWAY` and `CONFIG_NOT_READABLE`.
  - Comments and pages no longer cite the identifiers of the external audit's working report, which is not kept in
    the repository: the reason and the date of each change stay, and this file keeps the history.
  - The coding-rules guide, the maintainer commands, a docstring and a `pyproject.toml` comment name the documents
    that hold the coding and dependency rules (this guide, the architecture overview).
  - The Schemathesis page explains `ONLY_4XX` for the run with a credential as well.
- **A test-by-test review of the oracles (2026-11-05): one verdict with a wrong reason, four checks made more
  complete, one that checked nothing by default.** Each change is on its test page, with what the labs showed.
  - **4.2:** an APISIX timeout the configuration does not set was a CERTAIN violation claiming "no bound". APISIX then
    sets no timeout and nginx's default of 60 s applies (read in `apisix/balancer.lua` and on nginx.org). The adapter
    now states that default (`BackendTimeout.defaulted`), and the test judges it: still above the threshold, at FIRM.
    A value neither set nor stated as a default is `NOT_VERIFIABLE/NOT_STATED`, no longer a violation.
  - **0.1:** `TRACE` is asked once per service and judged on its echo (`TRACE_ECHOED`, CERTAIN): 405 on the three
    labs, the violation shown on a scratch server.
  - **1.2:** `alg: none` is also tried as `None`, `NONE` and `nOnE`, until one is accepted.
  - **2.2:** every documented read of the object is asked, its sub-resources included, once the object's own read
    refused user_b. A served sub-resource is `BOLA_READ_SUBRESOURCE`, FIRM, citing that refusal. On Forgejo, 35
    sub-resources were refused.
  - **4.1:** the spoofed burst carries the random address in `X-Forwarded-For`, `X-Real-IP`, `X-Client-IP`,
    `True-Client-IP` and `Forwarded`. A limit keyed to `X-Real-IP` was bypassed on a scratch server and reported,
    where the old burst would have passed it.
  - **6.4:** without `debug_endpoint_paths`, the debug sub-test asks the tool's six configuration-exposing paths under
    the root and each service prefix, where it was `NOT_APPLICABLE` (crAPI: 24 requests, nothing exposed). A 404 is
    `DEBUG_NOT_FOUND`.
  - **Pages:**
    - 0.1 and 1.5 had limitations describing behaviour removed on 2026-11-04.
    - 7.4 said replay needs an out-of-band listener. That is true of the blind callback; an inbound replay is
      simply not judgeable from the answer.
- **The Low findings of the external audit of 2026-11-03: verdicts claimed beyond their evidence, and records
  missing from the transaction log.** Each change is stated on its test page.
  - **Core** (CORE-9 to CORE-12): a SKIP after a judgement raises (the test's ERROR keeps the findings; it
    would have hidden a VIOLATION and exited 0), and a SKIP result with findings is refused by the model. A request
    logged as a step and then judged keeps one entry (7.3 logged one twice); a request two sub-tests judge keeps one
    per judgement, as the report schema now says, and `total_transaction_count` counts distinct requests. Docstrings
    of the client, the transaction log and the DAG corrected.
  - **1.x** (D1-17 to D1-23, D1-25 to D1-27):
    - 1.7: a 429 on any reading, not only the last, is reported as such; the unlimited-attempts finding points to the
      101st attempt and cites the first; every attempt is in the transaction log (the first one and the last reading
      were missing). The finding no longer says the password is masked, and the docstring says three attempts on the
      real account.
    - 1.3: a non-numeric `exp` is `EXP_NOT_NUMERIC` (was "no exp"), an `exp` not after `iat` is
      `EXP_NOT_AFTER_IAT` (was `NO_IAT_CLAIM`), and 47 hours reads "1 day 23 hours" (was "1 day").
    - 1.1: a path variant's redirect is `VARIANT_REDIRECTED`; the cleanup note covers a DELETE that was not served.
    - 1.4: the finding says the token stays usable after revocation, not "for the rest of its lifetime" (unmeasured).
    - The guarantees catalogue cites the ASVS 5.0.0 numbers of 1.5 and 1.6, checked on the source: 7.2.3 and 7.2.4
      for the session token.
  - **2.x** (D235-18 to D235-24; D235-25 needs no change, lab names only in comments):
    - 2.1: a public method is left out of the method comparison (a public GET next to a refused HEAD was a CERTAIN
      `METHOD_CONFUSION`), which is now FIRM, as BFLA.
    - 2.4: a version counts as absent only when up to three of its operations answer 404, not one; it cites OWASP
      API9:2023.
    - 2.5: a read with no answer is `NO_RESPONSE` (rule 4), and the scan's list limit is a named constant, stated.
    - The catalogue's references align with the tests (2.1, 2.2 §2.3, 2.4, 2.5).
  - **4.x, 6.x, 7.x** (D467-15 to D467-25; D467-26 is documented):
    - 6.2: cites ASVS 3.4.2 (CORS) in place of 3.4.3, a script CSP it never checked. A `frame-ancestors` allowing any
      site no longer passes. CORS is split: a reflected origin with credentials is `CORS_ORIGIN_REFLECTED`
      (CERTAIN); `*` with credentials, which browsers refuse, is FIRM and says so.
    - 7.2: a 401, a redirect or a 404 after the benign URL was accepted is `NOT_VERIFIABLE` (it was an SSRF block);
      NIST SP 800-204 §3.2.2 is no longer cited.
    - 7.1: served then refused is `REFUSED_AFTER_SERVED`, and every submission is logged.
    - 4.3: the finding cites the health-check read it rests on.
    - The 4.1 and 7.3 limitations are corrected.
  - **External** (EXT-12, EXT-13, EXT-15, EXT-16, EXT-18, EXT-19):
    - Schemathesis is also found beside the Python running apiguard (an environment that is not activated SKIPped
      it), and a local specification or a binary on PATH is shown without a home directory.
    - ffuf names one word list per job and shows its `-maxtime`; a base URL with a path is no longer prefixed twice
      when the candidates are re-verified.
    - testssl's `security_headers` entry (6.2's question) is not shown as a TLS note.
    - The external-test guide matches the code.
  - **Pipeline** (PIPE-5 to PIPE-13):
    - The exit codes of `list-tests` and `generate-seed`, and `validate-config`'s single request (the specification
      download), are documented.
    - The console lists only the files this run wrote.
    - The report states `test_ids` when it replaced `min_priority` and `strategies`.
    - The docstrings on relative `$ref` and the engine's comments are corrected.
  - **Docs** (DOCS-11 to DOCS-27):
    - A password shorter than 8 characters, which is not redacted, is now logged as such by its label; the evidence
      format says so instead of "passwords never appear".
    - Also corrected: the sdist contents (measured), the gateway-adapter and native-test guides, `config.example.yaml`'s
      gateway and resource comments, the seed template's vocabulary, the coverage values (lowercase in the JSON),
      the methodology's priority examples, and the dangling references to deleted plans.
    - The lab figures measured again on 2026-11-05 (full runs on the three labs, crAPI reset first):
      - crAPI: 16 FAIL, 8 PASS, 3 INCONCLUSIVE, 4 SKIP, 25 findings.
      - 1.1 on Forgejo: 371 and 261 not-verifiable judgements of 486, without and with `path_seed`.
      - Forgejo: 4 of the 12 passing tests partial.
    - The crAPI 503s that made 4.1 and 7.3 INCONCLUSIVE in a full assessment were described as load. The cause was
      Kong's health check, tripped by 7.2's hanging probes. Since 7.2's stop rule, both conclude: FAIL in a full
      assessment, 7.3 with all 15 concurrent applications accepted.
- **A credential in the query could reach a debug log, and documentation that said otherwise than the tool**
  (external audit of 2026-11-03, DOCS-1 to DOCS-6, DOCS-9, DOCS-10, DOCS-23). With `--log-level debug`, httpx
  logged every request's full URL, so a credential placed in the query reached the log in clear: httpx and httpcore
  stay at WARNING at every level (checked: no `access_token=` other than redacted in a debug run). The docs now say
  what the tool does, each fact checked on it: `fail_fast` stops on FAIL, ERROR or INCONCLUSIVE (six documents said
  FAIL or ERROR); 4.1's default burst is 150; the roles each test needs (`user_b` is required by 2.2, P0, not
  "reserved"; `config.example.yaml` lists it); 28 native tests and "18 of the 28" in `validate-config` (was 29);
  seven SKIPs on the reference lab, no test 5.2; a `${VAR}` in a YAML comment is not read (two guides said it
  stops the tool); the report schema's example is a real 2026-11-04 excerpt, SKIP no longer covers a disabled tool
  (that is `not_run`), INCONCLUSIVE is among the contract's statuses; `list-tests --json` lists all its fields.
- **Findings of 1.2, 1.3 and 1.4 without the records they rest on** (external audit of 2026-11-03, D1-10, D1-12).
  1.2's and 1.4's findings cited no control: the anchor now keeps its request without a credential, and 1.2 cites
  the genuine token served and that refusal, 1.4 those two and the confirmed revocation, all pinned in the
  evidence. 1.3's "valid for 7 days" could not be checked, the token being redacted: the finding now gives `iat`
  and `exp` as dates. Checked on crAPI: 1.2 cites `1.2_001` (genuine, 200) and `1.2_002` (no credential, 401),
  present in the evidence; 1.3 names both dates.
- **The HTML report's data block could be broken by a target's answer** (external audit of 2026-11-03, PIPE-2). The
  report embeds its data as JSON in a `<script>` block and escaped only `</`: a body with `<!--` and `<script`
  (previews are cut, a closing `-->` can be lost) could put the browser's parser in a state where the block did not
  end where it should. Every `<`, `>` and `&` is now written as its `\u` escape, which JSON.parse turns back into
  the same text. Checked on a crAPI report: no `<` left in the block, the data parsed equal to the JSON report, the
  HTML bodies restored.
- **A path search cut short by ffuf's own time limit counted as finished** (external audit of 2026-11-03, EXT-9).
  ffuf stops itself at `-maxtime` with exit code 0 and a partial output; the connector judged it as a finished
  search, so a cut search could give "no undocumented path". A job that used up its remaining time is now a
  timeout. Checked against a local server answering after one second: the cut search is an ERROR "the search did
  not finish"; Forgejo + Kong's search (30 s) is unchanged.
- **testssl.sh: a hang on a prompt, findings lost on its exit code, the tool's problems shown as the target's**
  (external audit of 2026-11-03, EXT-6, EXT-7, EXT-8, EXT-10, EXT-11). External tools inherited the terminal's
  input, and testssl.sh asked "Really proceed?" on a plain-HTTP target, waiting until the timeout: no tool gets an
  input now, and testssl.sh runs with `--warnings batch` (in the displayed command too). Its exit code counts the
  errors or ambiguous results of a completed scan (its manual): any code above 1 was an ERROR that dropped the
  findings; now only 242 and above are, the count going in a note. Its entries about its own scan
  (`engine_problem`, its bundled OpenSSL without an engine; `scanProblem`; any FATAL) were "TLS notes" about the
  target carrying the tool's local path: they are a note about the tool, without the path, and a FATAL one makes
  "no weakness" `NOT_VERIFIABLE/SCAN_INCOMPLETE`. A HIGH finding no longer says the traffic can be "downgraded or
  decrypted" whatever it is (an expired certificate is neither). A connector's timeout message named
  `external_tools.schemathesi`. Checked on Forgejo + Kong: PASS partial as before, the `engine_problem` note
  about the tool and without path.
- **The Kong adapter read only the first breaker plugin of each name** (external audit of 2026-11-03, CORE-7). A
  disabled instance listed before an enabled one hid it, and 4.3 reported no breaker. Every instance is now
  reported, as the APISIX adapter does, and 4.3 judges the enabled ones. The Kong labs, 4.3 alone: PASS as before.
- **Test 7.3's threads: a cookie jar cleared under them, and requests not released together** (external audit of
  2026-11-03, CORE-4, D467-14, DOCS-7). The HTTP client cleared its shared cookie jar after every request; with
  7.3's threads one could clear it while another read it (a possible `RuntimeError`, or a cookie in another thread's
  request). The jar now keeps no cookie at all (a cookie policy refusing every one), so nothing is cleared;
  checked on a local server: its `Set-Cookie` is recorded (redacted) and not sent back on the next request. 7.3's
  threads now wait at a barrier and send together, instead of leaving as the pool started them. The docs saying
  the client is not thread-safe are corrected. 7.3 itself is checked in the final full runs (its crAPI coupon is
  claimed once per lab reset).
- **The labs' paths in what a user copies** (external audit of 2026-11-03, D467-13, PIPE-14). The parameter
  examples of 7.1, 7.2 and 7.3, generated into `config.example.yaml`, were crAPI's and Forgejo's endpoints
  (`/workshop/api/shop/apply_coupon` with `TRAC075`, a Forgejo hook of `type: gitea`); they are now neutral examples
  of the same shape, and `apiguard generate-seed --help` no longer names a lab configuration.
- **Tests 6.1 and 6.4: findings on URLs and on secret references, a CLEAN on nothing** (external audit of
  2026-11-03, D467-9 to D467-12). Test 6.1 took a file-system path inside a URL (`https://host/home/...`), any
  `app/` and the text "at /" for a stack trace: a path now counts only where it starts a value, and the two generic
  markers are gone (the real traces of Java, Python, Node, Ruby, PHP are still found, checked on samples). A sample
  whose every answer failed, or was a gateway's `503`/`429`, was CLEAN: those answers are set aside, and with none
  left the sub-tests are `NOT_VERIFIABLE/NO_USABLE_RESPONSE`. Its texts promised internal `X-*` headers and a
  type-mismatch probe it never had: they now say what is checked. Test 6.4 reported a reference to a secret kept
  elsewhere (Kong `{vault://...}`, APISIX `$secret://`, `$ENV://`) as a plaintext credential, which is what its
  remediation asks for; each adapter now states its gateway's syntax (`secret_reference_prefixes`, read on the
  gateways' docs) and such a value is not reported. The labs, each test alone: the same verdicts as before.
- **Tests 4.1 and 4.2: a burst cut short by one error, a limit taken for a failure, numbers no standard sets**
  (external audit of 2026-11-03, D467-6, D467-7, D467-8, D467-22). Test 4.1 ended its burst on a single 5xx from
  the third request on, against its own comment; it now takes three failing answers in a row. A run of `503` after
  served answers, which a limiter rejecting with `503` instead of `429` gives as well as a backend going down, is
  `NOT_VERIFIABLE/LIMIT_OR_UNAVAILABLE` instead of an unavailable backend. Test 4.2 attributed its 5 s and 30 s
  bounds to NIST SP 800-204A section 4.3, which asks for timeouts (SM-DR9) but sets no value (read on the PDF): they
  are the methodology's, and its finding no longer describes "100 concurrent requests" nobody measured. Checked: the
  labs FAIL on 4.1 as before; a scratch server answering `503` after five requests gives `LIMIT_OR_UNAVAILABLE`.
- **Tests 2.2 and 2.5 left objects on the target without saying so** (external audit of 2026-11-03, D235-16). An
  object whose resource has no delete request (a crAPI order), or whose delete failed, went to the log only; the
  result now names it in a note ("order {'order_id': '9'}"), as rule 7 asks, through one helper
  (`not_deleted_note`). Checked: crAPI names the orders, Forgejo deletes its repositories and has no note.
- **Test 3.3 cited RFCs for a forgery they rule out** (external audit of 2026-11-03, D235-15, D235-22; owner
  decision 2026-11-05). A policy allowing HMAC-MD5 or HMAC-SHA-1 was a CERTAIN finding saying "an attacker can
  forge a signature", citing RFC 6151 and 6194, which say that HMAC-MD5's attacks "do not seem to indicate a
  practical vulnerability" and that "HMAC-SHA-1 remains secure". By default only HMAC-MD5 is now forbidden (RFC
  6151: not in new designs), HMAC-SHA-1 only when the operator adds it to `forbidden_algorithms`; the finding is
  FIRM with what the RFC says, and the 300-second replay bound is the methodology's, no longer attributed to NIST SP
  800-107. The labs, 3.3 alone: PASS as before (SHA-256 and stronger).
- **Domain 2: confidence beyond the evidence, and a PASS on a refusal that said nothing** (external audit of
  2026-11-03, D235-9 to D235-13). Test 2.2: a 2xx to user_b's modify of user_a's object is FIRM (the write was
  accepted; with an empty body a change is not shown), its delete CERTAIN only when user_a's read afterwards finds
  the object gone; the re-read no longer claims to confirm what it does not compare. Test 2.1: a BFLA finding is
  FIRM (that the operation is privileged rests on its path's name, whatever the admin control shows) and cites the
  admin control when it ran. Test 2.4: a sibling version's refusal counts only when a random path right under that
  version is not refused the same way, and a documented operation that answers neither 2xx nor a refusal is not
  verifiable instead of "not protected". Checked: crAPI's 2.4 goes from PASS to INCONCLUSIVE (its identity service
  answers 401 to any path under `/v1` and `/v3`, so the 8 comparisons said nothing); 2.1 on crAPI FAIL as before,
  FIRM, its control cited and present in the evidence.
- **Domain 1: false verdicts and evidence that hid what was sent** (external audit of 2026-11-03, Medium and Low
  items D1-6 to D1-9, D1-11, D1-13 to D1-16, D1-24). Test 1.5: with `base_url` on a port other than 443 and no
  `http_url`, it asked the HTTPS port in cleartext and judged that answer (a false CERTAIN finding on Kong's `400`);
  the HTTP listener is now `HTTP_LISTENER_UNKNOWN`. A timeout on the HTTP port is no longer "unreachable" (only a
  refused connection is), the HTTPS request handles a missing answer, a quoted `max-age` is read. The anchor of
  1.2 and 1.4 must be refused without a credential (401, 403), not merely not served. Test 1.2's tampered token
  adds a claim instead of changing the subject, so a refusal can only be the signature check; 1.2 and 1.3 take the
  token as obtained instead of stripping a list of known prefixes. Test 1.6: an empty cookie value is no longer
  redacted (it is how a cookie is cleared, and the redacted value made the deletion a false finding), and an
  anti-CSRF cookie is not asked `HttpOnly` (ASVS v5.0.0-3.3.4). Test 1.1's malformed credentials are shown in the
  evidence as `[public probe] ...` instead of `[REDACTED]`. Messages of 1.2, 1.3, 1.4, 1.6 no longer name the labs.
  Checked: the labs, each test alone, give the same verdicts; 1.5 without `http_url` on Forgejo + Kong gives
  `HTTP_LISTENER_UNKNOWN`; 1.6 with a temporary gateway cookie (the lab then restored) gives PASS for an
  `XSRF-TOKEN` without `HttpOnly` and nothing to judge for a cleared cookie.
- **Domain 0: an unauthenticated DELETE on a real path, and four false verdicts** (external audit of 2026-11-03,
  Medium and Low items D0-5, D0-6, D0-7, D0-12, D0-13, D0-14). Test 0.1: after an accepted `PUT` on a path without
  parameters its cleanup sent a `DELETE` to that real path; only what a probe surely created (a `Location`, or a
  `PUT` on a random path) is deleted now, any other accepted write is named in the result. A path served exactly
  as its random siblings (a server answering every path) is `SERVED_LIKE_UNKNOWN`, no longer a CERTAIN finding; on
  a path with parameters the finding is FIRM, with a text that no longer claims a comparison; a path whose random
  siblings another documented route captures (`/users/search` next to `/users/{username}`) is
  `SIBLING_ROUTE_DOCUMENTED`; a gateway route given as a regular expression is tried on the documented paths with
  values in their parameters (a template never matched it). Test 0.3: a deprecated operation answering `405` is
  switched off (`METHOD_SWITCHED_OFF`), and a redirect is not verifiable; both were "still served". Test 0.2: its
  findings cite the backend's refusal that made the gateway's refusal trusted. Checked on the labs, each test
  alone: the same verdicts as before (the new branches do not occur there); the regex and captured-route rules on
  Forgejo's specification and sample routes. Docs: 0.2's crAPI workshop 404 is gunicorn's, not Spring's; the
  catalogue no longer promises a configured backend list for 0.4.
- **`ext.3.1.schemathesis` reached a small part of the API** (owner decision 2026-11-04). Unauthenticated, it got
  only `4xx` on most operations: Schemathesis makes up a credential for the security schemes the specification
  declares (on Forgejo even the public endpoints answered `401`), and fills the path parameters with names that do
  not exist (`404`). With user_a's credential configured (new optional need `USER_ACCOUNT`) and placed in a header
  or a cookie, it now sends it (`-H`, shown redacted) and tests reads only (`--include-method GET`: a generated
  write with a valid credential would change data the tool cannot clean up), with the operator's resources in the
  path parameters (`--set-path` from `path_seed`). Without a credential, or with one in the query, it runs as
  before. The credential is replaced in the tool's whole output before it is stored, and a connector timeout no
  longer chains the command line (credential included) into the logged traceback. External tests' `_invoke_connector`
  now receives the run's context. The labs: the Forgejo labs reach 110 to 211 of their 241 reads (40 to 89 before),
  no server error; crAPI gives a new finding, `GET /workshop/api/mechanic/receive_report` answering `500`, reached
  only with the credential. No JWT in any output.
- **`ext.3.1.schemathesis` reported findings it does not measure, and counted unreached operations as checked**
  (found in the review of the audit fixes; owner decisions 2026-11-04). With the reproduction commands visible,
  two of its three checks turned out to report something other than input validation, all titled "Input not
  validated": `response_schema_conformance` a response not matching the specification (crAPI's order endpoint),
  `negative_data_rejection` endpoints without parameters answering `200` to a nameless extra header and query
  parameter (9 on Forgejo + APISIX, `/api/v1/version` among them). Both are dropped: the test runs
  `not_a_server_error`, and a finding is "Server error on a generated input" with the request that causes it.
  Operations whose every generated request got a `4xx` (on Forgejo, Schemathesis's made-up credential answers
  `401`) were counted as checked: they are now `NOT_VERIFIABLE/ONLY_4XX`, read from Schemathesis's own warning.
  An unreadable JUnit report now quotes the end of Schemathesis's output instead of the temp file's path (seen
  once on Forgejo + APISIX, not reproduced). The labs: crAPI FAIL with 4 reproducible `500`s; the Forgejo labs
  PASS partial on the 56 and 89 operations reached (469 counted before).
- **Schemathesis's findings lost their proof and could show a 503 as their reason** (found in the review of the
  audit fixes, 2026-11-04). The connector cut each failure message at 500 characters, which dropped the commands
  that reproduce the failing requests, and the 502/503/504 filter judged the whole message: an operation whose
  first case was Kong's 503 and whose second was a real failure was shown as "Server error [503]". The message is
  now kept whole in the artifact; each test case is judged on its own, the unavailable ones set aside, and the
  finding quotes every other case with its reproduction command. Checked on crAPI: the same 4 findings and 23 not
  verifiable, each finding now naming the request that proves it.
- **Test 5.1 knew the gateways' plugin names** (external audit of 2026-11-03, D235-2; owner decision 2026-11-04).
  Against design decision D7, 5.1 matched fragments of Kong and APISIX plugin names inside the test and named both
  gateways in its finding; the fragment `-logger` also matched APISIX's `file-logger`, which writes on the gateway's
  own host. A new neutral concept, `log_shipping()` (`LogShipper`), answers which plugins ship request logs: the
  Kong and APISIX adapters each hold their list, read on the gateways' sources (Kong 3.9.0 `constants.lua`, APISIX
  `config.yaml.example`), without the local ones (Kong `file-log`, `syslog`; APISIX `file-logger`). 5.1 only asks it.
  Checked on the three labs: FAIL as before; Forgejo + Kong with a temporary global `http-log` gives PASS, the lab
  then restored (FAIL again).
- **Schemathesis's per-request timeout was fixed in the code** (external audit of 2026-11-03, EXT-17; owner decision
  2026-11-04). It is now `external_tools.schemathesis.request_timeout_seconds` (default 5, the value it had, 1 to
  300). Checked on Forgejo + Kong: the command still carries `--request-timeout 5000`. The same run gave one finding
  (`GET /api/v1/users/search` accepting an input generated as invalid) where the morning's run with the same
  configuration gave PASS: the inputs are drawn at random on every run, now stated on the page.
- **Test 2.1 promised configuration it does not have** (external audit of 2026-11-03, D235-17; owner decision
  2026-11-04). Its docstring and page said the configuration "adds or corrects" the privileged operations and can
  confirm a destructive one so that it is sent, and that the test subsumes guarantee 2.3; no such key exists, the
  operations come from the specification only and destructive methods are never sent. The docs now state those
  limits; no code change.
- **The docs presented the strategy as an access boundary** (external audit of 2026-11-03, DOCS-8; owner decision
  2026-11-04). They said the gateway's Admin API serves the WHITE_BOX audits, while five BLACK_BOX tests (0.1, 0.2,
  4.1, 4.4, 6.4) read it when a gateway is configured and 2.1 uses the admin account when given, so
  `execution.strategies: [BLACK_BOX]` does not keep a run away from them. The strategy is what a test needs at
  least: the assessment model, the configuration reference, the overview, the adapter guide, the compatibility page
  and CLAUDE.md now say so, and how to keep a run away from the Admin API (leave the `gateway` section out). No code
  change.
- **A run in which every test was SKIP exited 0** (external audit of 2026-11-03, PIPE-4; owner decision
  2026-11-04). Nothing verified, and a pipeline saw success, against the exit-codes page ("a run never ends 0
  without running at least one test"). Such a run now exits `3`; a run in which at least one test ran keeps the
  rule that a SKIP does not affect the code. Checked on Forgejo + Kong: 7.4 alone (SKIP, no webhook configured)
  exits 3, 7.4 with 3.3 exits 0.
- **Test 0.4 did not try the address Kong resolved a backend to** (external audit of 2026-11-03, CORE-8; owner
  decision 2026-11-04). Kong declares a backend by name (`forgejo:3000`), which does not resolve where the tool
  runs, while its health endpoint also states the IP it resolved it to; the adapter dropped it, so on the Kong labs
  0.4 could not reach a backend that APISIX's resolved node showed answering. The live-health concept now carries
  `resolved` (the addresses the gateway states, filled by the Kong adapter), and 0.4 tries them as declared
  addresses. The labs, 0.4 alone: Forgejo + Kong FAIL (`172.22.0.3:3000` answers like the gateway, CERTAIN), crAPI +
  Kong FAIL with 3 findings, Forgejo + APISIX FAIL as before; both Kong labs were a PASS before the corrections of
  that day.
- **An unreadable gateway concept gave SKIP in some tests and INCONCLUSIVE in others** (external audit of
  2026-11-03, CORE-6; owner decision 2026-11-04). With an Admin API that does not answer or refuses, 3.3, 4.2 and
  5.1 returned SKIP (exit 0: a pipeline saw nothing wrong) while 0.2, 0.4, 4.3 and 6.4 recorded NOT_VERIFIABLE.
  Now a concept the gateway has but that cannot be read makes every sub-test
  `NOT_VERIFIABLE/CONCEPT_NOT_ACCESSIBLE`, INCONCLUSIVE with a note (`BaseTest._unread_concept`, which replaces
  `_skip_for_concept`); a concept the gateway does not have stays SKIP. D7 rewritten. Checked on a scratch Forgejo +
  Kong configuration with the Admin API pointed at a closed port: 3.3, 4.2, 5.1 INCONCLUSIVE, exit 3 (SKIP, exit 0
  before); the lab as configured unchanged.
- **Test 1.5 rewarded a redirect that OWASP ASVS forbids on API endpoints** (external audit of 2026-11-03, D1-4;
  owner decision 2026-11-04). A plain-HTTP request to an API path answered `301`/`308` to `https` was ENFORCED, and
  the finding recommended the redirect. ASVS v5.0.0-4.1.2 allows a transparent redirect only on endpoints meant
  for a browser: the first request, with its credential, has already crossed in cleartext, and an API client that
  wrongly uses HTTP is never told. Such a redirect is now `VIOLATION/TRANSPARENT_REDIRECT`, CERTAIN, ASVS 4.1.2
  added to the references, and the remediation says to refuse plain HTTP on API endpoints. The labs, 1.5 alone:
  FAIL on all three (their gateways redirect on purpose), HSTS still PASS.
- **Test 4.4 read a gateway's own authentication as "body forwarded"** (external audit of 2026-11-03, D467-3; owner
  decision 2026-11-04). The oversized body is sent without a credential, and any answer other than 413 meant
  "forwarded": a gateway that authenticates before its size check (Kong runs `key-auth` before
  `request-size-limiting`) would get a false FIRM finding on its 401. After a 401 or 403 the same body is now sent
  with user_a's credential (optional need `USER_ACCOUNT`) and that answer judged; when it is refused too, a forged
  credential tells who refused (same status: `REFUSED_BEFORE_SIZE_CHECK`; different: past the refuser, no 413).
  Without a credential: `NO_CREDENTIAL_TO_RETRY`. The labs, 4.4 alone: FAIL on all three, now proven past
  authentication (Forgejo `403` for the token's scope, crAPI `400` "product_id is required"); a scratch server that
  authenticates before its size check gives PASS with its key and `REFUSED_BEFORE_SIZE_CHECK` without, where both
  were false FAILs before.
- **Test 7.2 passed on malformed URLs while every internal address was accepted** (external audit of 2026-11-03,
  D467-2; owner decision 2026-11-04). On the Forgejo labs 7.2 was PASS partial on 15 payloads rejected as malformed
  or for their scheme, while every cloud-metadata and private-IP URL was accepted (not verifiable without a
  listener). A test can now declare **essential sub-tests** (`TestInfo.essential_sub_tests`, carried as `essential`
  on each sub-test's result, so the status stays recomputable): without a violation, a test none of whose
  essential sub-tests passed is INCONCLUSIVE. 7.2 declares `cloud_metadata` and `private_ip`; no other test
  declares any, so no other verdict changes. The labs, 7.2 alone: both Forgejo labs go from PASS partial to
  INCONCLUSIVE, crAPI stays INCONCLUSIVE.
- **Test 7.2 took crAPI's backend out of service for the tests after it** (external audit of 2026-11-03, D467-1;
  owner decision 2026-11-04). Each cloud-metadata URL hung crAPI's `contact_mechanic` until the gateway answered
  `504`; after three, Kong's passive health check took the workshop backend out of service, and 0.1, 4.1, 4.4, 7.3
  and Schemathesis, which ran next, got `503` and measured nothing (the pages blamed load or a race). 7.2 now stops
  at the first payload left without an answer or answered `502`, `503` or `504`, and records the rest
  `NOT_VERIFIABLE/NOT_SENT_AFTER_TIMEOUT` with a note. The labs, 7.2 alone: crAPI INCONCLUSIVE as before, in 30 s
  instead of 90, with the backend still in service afterwards; the Forgejo labs unchanged (PASS partial).
- **Test 3.3 read a replay window the gateway does not state as unbounded** (external audit of 2026-11-03,
  D235-14). A signing policy without a stated window was a CERTAIN `REPLAY_UNBOUNDED` violation, whether the
  gateway said the date is never checked (APISIX `clock_skew` 0) or simply did not say; only the first is now a
  violation, the second is `NOT_VERIFIABLE/REPLAY_WINDOW_NOT_STATED`, as unstated algorithms already were. The
  labs, 3.3 alone: PASS as before (their policies state a window).
- **Test 0.4 passed on a guess at the backend's address** (external audit of 2026-11-03, D0-3). For each backend it
  tries the address the gateway declares and a derived one (the target's host with the backend's port). On the
  Kong labs the declared names do not resolve from the run host, and the derived ports refuse: 0.4 was PASS, while
  the backends answer from that host at their container address. A refusal at the derived address now counts only
  when the declared one refused too, otherwise `NOT_VERIFIABLE/DERIVED_REFUSAL_ONLY`. The labs, 0.4 alone: both
  Kong labs go from PASS to INCONCLUSIVE, Forgejo + APISIX stays FAIL. Whether the Kong adapter should keep the
  resolved IP, so that 0.4 can try it, is left to the owner (CORE-8).
- **Test 5.1 claimed that requests are not logged, which it cannot see** (external audit of 2026-11-03, D235-1).
  Its finding said "requests are not logged at the gateway", CERTAIN, on the sole basis that no logging plugin is
  enabled, while every gateway writes its own access log, which the Admin API does not show (the Kong labs set
  `KONG_PROXY_ACCESS_LOG=/dev/stdout`). It now says what it observes: no plugin ships the request logs to a
  separate system (ASVS v5.0.0-16.4.3), FIRM, since a collector on the gateway's host would be invisible; Kong's
  `file-log`, which writes on that host, no longer counts as shipping. The details are now `LOGS_SHIPPED` and
  `LOGS_NOT_SHIPPED` (were `LOGGING_CONFIGURED`, `NO_REQUEST_LOGGING`). The three labs, 5.1 alone: FAIL as before,
  with the new finding.
- **Test 1.7 missed a block, and cited NIST for a rule it does not probe** (external audit of 2026-11-03, D1-3,
  D1-2). The repeated attempts stopped only on a `429`, a server error or a slowdown: a `403` or `423` block, or a
  `401` that started saying "too many attempts", ran on to a FIRM `ATTEMPTS_NOT_LIMITED` finding. A block is now
  recognised when the answer changes and stays changed (three consecutive answers alike and unlike the normal one,
  by status or by body with the submitted values and digits masked), `ENFORCED/ATTEMPTS_BLOCKED`; a body that
  changes on every request is never taken for one. The finding cited NIST SP 800-63B-4 §3.2.2, whose limit is per
  account, while the attempts go to an account that cannot exist: it now names the missing per-caller limit (ASVS
  v5.0.0-6.3.1) and keeps NIST as the source of the 101 bound only. Checked on a scratch login server that answers
  `423` after 12 failures: PASS, `ATTEMPTS_BLOCKED` at the third `423`, and `NO_DISCREPANCY` seen for the first
  time; the labs, 1.7 alone, are unchanged (FAIL, 3 findings each).
- **Test 1.1 did not test a credential placed in the query, and no record showed a query** (external audit of
  2026-11-03, D1-5). With a credential placement in a query parameter, 1.1's malformed credentials were sent as
  headers named after the parameter, so the target's refusal (the credential was simply missing) counted as
  ENFORCED; they are now sent in the query. The HTTP client recorded the path without its query, so on such a target
  no record showed what was sent; `request_url` now carries the query parameters the tool added, each value redacted
  before it is written (a query is not encoded there, so a registered secret cannot escape the redaction by being
  encoded). Checked on a scratch Forgejo + Kong configuration with `security_scheme: AccessToken`: the malformed
  values go as `?access_token=...` and are refused, user_a's and admin's tokens appear as `[REDACTED: ...]` only; the
  labs in their own configuration (credential in a header) are unchanged.
- **Test 7.4 counted a rejected delivery as signature verification without a positive control** (external audit of
  2026-11-03, D467-4). Without `signing_secret`, or when the validly signed delivery got no answer, any rejection of
  the unsigned and wrongly signed deliveries was ENFORCED (only a note said "inferred"): a wrong path's 404 or a
  gateway's 401 made 7.4 PASS. A rejection is now ENFORCED only when a validly signed delivery was accepted, and
  `NOT_VERIFIABLE/SIGNATURE_NOT_CONFIRMED` otherwise; an accepted forged delivery is still a violation. Checked
  against a scratch HMAC receiver (outside the repository) and the Forgejo lab: every verdict of the test observed
  for the first time (`SIGNATURE_REQUIRED`, `REJECTS_ALL`, `SIGNATURE_NOT_CONFIRMED`, `UNSIGNED_ACCEPTED`,
  `BAD_SIGNATURE_ACCEPTED`); the wrong-path, no-secret and Forgejo cases, PASS before, are now not verifiable.
- **Tests 2.1 and 2.2 counted refusals that did not prove the user was refused** (external audit of 2026-11-03,
  D235-7, D235-8). Test 2.2 took any non-2xx answer of user_b as a refusal, including a 422 from body validation
  (its modify sends an empty body), a 405 or a redirect; only 401, 403 and 404 are now a refusal, any other answer
  is `NOT_VERIFIABLE/NOT_A_REFUSAL`. Both tests also took a 401 or 403 as enforcement without anything proving the
  role's credential was accepted (a static token is stored as configured, and may have expired). A forged
  credential, a random value placed as the run's credential is, is now sent on the same safe request (2.2: the
  object's read; 2.1: the privileged function, only when user_a is refused); a refusal in the same category as its
  answer is `NOT_VERIFIABLE/CREDENTIAL_NOT_CONFIRMED`, and when the forged credential is not refused a 401 is not
  counted. Checked on the three labs, each test alone: the same verdicts as before (the forged credential gets 401,
  the user 403 or 404). With an invalid token in a scratch crAPI configuration, 2.2's modify and 2.1 are now not
  verifiable, where they counted a refusal before.
- **Test 2.5 reported a masked card number, and mass assignment as refused without evidence** (external audit of
  2026-11-03, D235-4, D235-5, D235-6). A sensitive name was matched as a substring of the field name (`ssn` in
  `classname`) and the value was ignored, so crAPI's order, which shows its owner the card number masked
  (`XXXXXXXXXXXX0796`), was a FAIL; a short marker (`ssn`, `hash`, `pwd`, `cvv`, `salt`) must now be a whole word
  of the name, a longer one is still found inside it (separators ignored, so nothing caught before is lost), and a
  null, empty or masked value discloses nothing. `mass_assignment` was ENFORCED when the object read back showed none of the injected fields
  (crAPI's order), and when the create body was not a JSON object the fields were silently not injected at all; both
  are now not verifiable (`FIELDS_NOT_EXPOSED`, `FIELDS_NOT_INJECTED`). Checked on the labs, 2.5 alone: crAPI goes
  from FAIL to PASS partial, Forgejo is unchanged (PASS). Compatibility: crAPI challenge 4 is now "missed".
- **Test 0.1 judged undeclared methods on paths with parameters without evidence** (external audit of 2026-11-03,
  D0-1 and D0-4). On such a path the probe and its random siblings are the same route with other values, so the
  calibration compared the method with itself, and an answer like a 404 on the non-existent object was counted as
  "method not served" (ENFORCED), although a handled method answers it too. There only a 2xx or a 405 is evidence
  now; any other answer is `NOT_VERIFIABLE/NONEXISTENT_OBJECT`. Checked on the labs, 0.1 alone: Forgejo goes from
  1046 to 951 enforced, 95 judgements not verified, still PASS partial; crAPI is unchanged (its paths with
  parameters answer 405, or 401 before routing). The page also described a reference method (`APIGUARDPROBE`, a
  log key `test_0_1_method_reference`) that the code never had: removed.
- **Test 0.1 counted a version as absent when the target refused before routing** (external audit of 2026-11-03,
  D0-2). A version probe answered like a random sibling was judged ENFORCED (`VERSION_ABSENT`) even when that
  shared answer was a refusal of the request itself: crAPI's identity service answers 401 to every path, so its v1
  and v3 probes proved nothing. Such a probe is now `NOT_VERIFIABLE/REFUSED_BEFORE_ROUTING`, as the undeclared
  methods already were. Checked on the labs, 0.1 alone: crAPI's versions go from 6 ENFORCED ("complete") to 4
  ENFORCED and 2 not verifiable ("partial"); Forgejo is unchanged.
- **A cited record missing from the evidence, and a configuration read without its defaults** (external audit of
  2026-11-03, CORE-2 and CORE-3). Test 1.7's two enumeration findings cite the answer for the account that does not
  exist as their support, and that record was never stored, so `evidence.json` lacked it on every lab (rule 6); it is
  now pinned before it is cited, and 1.7's findings resolve completely. The APISIX adapter, unable to read a
  plugin's or an upstream's schema, carried on with an empty one, so a signing policy, a breaker or a health check
  read as configured but without the defaults APISIX applies; such a concept is now "not accessible". Checked on the
  APISIX lab with the plugin-schema address pointed nowhere in scratch copies: 3.3 reported PASS on the incomplete
  configuration before and "not verifiable: no access to request signing policies" after; with the schemas readable,
  3.3 and 4.3 are unchanged.

- **Two ways a secret could reach the outputs** (external audit of 2026-11-03, D1-1 and PIPE-3). Test 1.2's three
  degraded tokens each keep parts of the genuine one (the tampered token its signature, the unsigned one its
  payload), so together they rebuild it. In `Authorization` the whole value is always redacted, which is why the
  labs never showed it; but with the credential in a header of its own or a query parameter they were written in
  clear. Each variant is now registered as a secret before it is sent, so it is redacted wherever it travels, and the
  evidence names it (`[REDACTED: user_a token, ALG_NONE variant]`), which also makes the three variants
  distinguishable. And test 7.4's `signing_secret` was not marked as a secret, so a literal value was copied to
  `config_used.yaml`; it now becomes a variable name with the instruction to export it, as passwords do. Checked:
  a variant in an `X-API-Key` header, in clear before and redacted after; crAPI's 1.2 FAIL unchanged with no
  JWT-shaped string left in its outputs; a literal secret in a scratch configuration, in clear before and a
  placeholder after.

- **One unexpected error ended the whole run with no report** (external audit of 2026-11-03, PIPE-1 and CORE-1; a
  regression from v0.1.0). A test must return its result and never raise, but 16 tests catch only the tool's own
  errors and the engine had no guard around them, so anything else ended the run with exit 10, no report, and every
  verdict already reached lost. The likeliest trigger was in the HTTP client itself: of `httpx`'s request errors only
  six were handled, so a connection reset escaped as a raw `httpx.ReadError`, with no record. Every request error is
  now reported as the tool's own error with its record (`transport_error: protocol_error` for a reset), and the
  engine turns any error a test lets through into that test's ERROR and carries on. Proven without touching a lab:
  a local server resetting every connection gave a raw `ReadError` before and the client's error with record
  `check_001` after; and with an error injected into a scratch copy of test 0.3, the committed engine ended the run
  with "no security verdict" and no report, losing 0.2's FAIL, while the new one marked 0.3 ERROR, kept 0.2's FAIL
  and wrote both reports.

- **`ext.3.1.schemathesis` tested nothing on Forgejo and turned crAPI's outage into findings** (external audit of
  2026-11-03, findings EXT-1 to EXT-4). Schemathesis takes the base path from its `--base-url` and drops the
  specification's own, so on both Forgejo labs every generated request went to `/<path>` instead of
  `/api/v1/<path>`, answered `404`, and the test reported PASS: with Schemathesis limited to `GET`, all 241
  operations answered only `4xx` before and 142 after (the rest are reached; those 142 need a credential). The base
  URL now carries the specification's base path, kept on the discovered surface (`AttackSurface.base_path`, empty
  when there is none). On crAPI, 24 of the 27 failures were Kong's `503` once its health check had marked the
  backend unhealthy, each a FIRM finding: a failure whose only quoted statuses are `502`, `503` or `504` is now
  `NOT_VERIFIABLE/UPSTREAM_UNAVAILABLE`. Schemathesis generated valid data only (its default), so the
  `negative_data_rejection` check the documentation describes never ran; it now generates both
  (`--data-generation-method all`). Its report's errored and skipped operations were counted as passes; they are now
  `OPERATION_NOT_CHECKED`, and "input validated" needs at least one operation checked. **Changed results**: crAPI
  3 findings instead of 20 (two `500`s on `check-otp`, one response outside crAPI's schema); Forgejo still PASS,
  now on requests that reach the API, in 45 s instead of 26.

- **What a code review of this review's own changes found** (2026-11-03). The uncommitted changes were reviewed
  for correctness; of ten findings, seven held and were fixed, one did not hold and two were left on purpose. Fixed:
  6.2's new CORS verdict counted "no usable answer" as "origin not allowed" (a probe that failed or met a `429`
  or `5xx` now gives `NOT_VERIFIABLE/NO_RESPONSE`); 7.3's rendering of its body, added for consistency with 7.2,
  made a body with a literal brace fail at run time after a resource had been created, and was taken back out,
  since the crAPI configuration never needed it; 2.5 judged a read-back that was refused or failed as proof that
  nothing leaked (now `NOT_VERIFIABLE/OBJECT_NOT_READABLE`); 6.1's error probe sent its malformed body without a
  `Content-Type`, so on the labs it never reached a JSON parser (crAPI `415`, Forgejo `403`), and any answer without
  a trace counted as "no stack trace" (it now declares `application/json`, counts only a provoked error, `400`,
  `422` or `5xx`, and reports `ERROR_NOT_PROVOKED` otherwise); 6.1's sampled responses were keyed by path, so a
  `HEAD` could stand as a `GET`'s proof; `evidence.json` could hold one record id twice, when one response proves
  two findings or two tests pin the same record (it now keeps one, preferring the proof of a finding); and a
  garbled docstring in 2.5 and a misplaced comment in 6.4. Not held: the review took the path check in 6.1 and 4.4
  for redundant, but `random_sibling_path` replaces the last segment even without parameters. Left on purpose: the
  numeric limits 4.1 and 4.4 cannot read (stated on their pages), and the copies of the "answers that say nothing"
  table across tests (some differ deliberately, 7.1 counts a `429` as the control it looks for). **Changed
  results**: 6.1 goes from PASS `complete` to PASS `partial` on both Forgejo labs; nothing else moved on the three
  labs, and no evidence file holds a duplicated id.
- **Clean reference results** (2026-11-03). `outputs/` was emptied (52 MB of review leftovers: `baseline/`,
  `pilot/`, `review/`, nothing referred to them) and the three reference results regenerated, crAPI after a reset
  and with the Forgejo labs stopped: Forgejo + Kong and Forgejo + APISIX 15 PASS, 9 FAIL, 7 SKIP, 89 findings (the
  earlier result less the removed 5.2); crAPI 13 FAIL, 10 PASS, 4 INCONCLUSIVE, 4 SKIP, 34 to 37 findings, recorded in
  `06-compatibility.md`. In that run 7.3 met crAPI's workshop answering `503` for its whole burst and reported
  `OPERATION_FAILED`, "the operation did not run", which pointed at the configuration; with no success and the
  target unavailable it now reports the reason (`UPSTREAM_UNAVAILABLE`), as 7.1 does. `docs/project/roadmap.md` and
  `docs/project/test-review.md` were removed (owner, 2026-11-03): the review is complete, and the two items left (the
  licence and the 1.0.0 tag) are the owner's to settle; the ten links to the roadmap now point where each fact lives.
- **The last open questions of the review, settled** (test-by-test review, 2026-11-03). 6.2 judged an answer to an
  arbitrary `Origin` that grants no cross-origin access as `NOT_APPLICABLE/NO_CORS`, which understated it: that answer
  is the evidence the origin is not allowed, so it is now `ENFORCED/ORIGIN_NOT_ALLOWED`. **Changed results**: 6.2
  goes from PASS `partial` to PASS `complete` on both Forgejo labs; crAPI unchanged. The other three were settled
  without code: 6.4's page now states that consumer credentials are scanned on APISIX but not on Kong (the Kong
  reader does not read `/consumers/{id}/<plugin>`, a new capability not added); 0.4's that a hostname is not retried by
  the IP Kong resolved; and `HealthCounters`, which no test reads, stays because 0.4 pins the whole live-health
  answer as evidence and a reader sees the counters there.
- **Test 7.3 ran for the first time, and found a real race in crAPI** (test-by-test review, owner's decision of
  2026-11-03). It had never run on any lab: it needs a once-only operation named in the configuration, and the labs
  named none. crAPI has one in its own API, applying a coupon, so crAPI's lab configuration now prepares a coupon
  through crAPI's API (`resources.coupon`) and points `race_operation` at `POST /workshop/api/shop/apply_coupon`; the
  tool's code learned nothing about coupons. The first run fired 15 simultaneous applications as user A and **all 15
  were accepted** for a coupon allowed once; user A's credit went from 0.0 to 60.0, so 6 took effect. Two corrections
  follow from that measurement: the finding said the operation "took effect" as many times as it was accepted,
  which the test cannot see, so it now says "accepted" and is FIRM rather than CERTAIN, telling the reader to
  confirm on the target's state. A later run reports `OPERATION_FAILED` (the coupon is already claimed),
  the same wear as the order of tests 2.2 and 2.5. crAPI's own specification is wrong on one point met on the way:
  its coupon service wants `amount` as a string, not the integer it declares.
- **Test 7.1's passing side was seen for the first time** (test-by-test review, 2026-11-03). With a scratch flow
  (Forgejo's Markdown preview, as user A, which stores nothing) and a temporary global rate limit on the reference
  lab's Kong, the answers were `200, 200, 200, 429` and the test passed on `ANTI_AUTOMATION_THROTTLE`. The throttle
  also stopped the run's own clean-up, which the tool reported ("1 of 1 resources NOT removed"); the token was
  removed by hand, the gateway restored and checked, and the recipe is on the test's page. Test 7.4 still has never
  run on a lab, because none of the three applications receives signed webhooks; its page now says so plainly
  instead of deferring a decision.
- **Test 7.1 reported, with certainty, that a burst the flow had refused "was all accepted"** (test-by-test review,
  2026-11-03). Its page promised a violation only when "the whole burst accepted" and its module promised
  `NOT_VERIFIABLE` when "the flow errors for another reason"; the code reported `VIOLATION/NO_ANTI_AUTOMATION`,
  CERTAIN, whenever no throttle or challenge was seen, whatever the answers, and `FLOW_UNAVAILABLE` could not fire
  because a transport failure still returns a record. Proven with a scratch flow on the reference lab, `POST
  /api/v1/orgs` without a credential: 12 answers `401`, nothing created, and the finding said "12 identical
  submissions ... were all accepted". A violation now needs every submission accepted; a refused burst is
  `NOT_VERIFIABLE/FLOW_NOT_ACCEPTED` and one the target could not serve `NOT_VERIFIABLE/FLOW_UNAVAILABLE`. crAPI's
  forgot-password flow, accepted twelve times, still fails.
- **Three tests counted a failing or throttling target as a defence** (test-by-test review, 2026-11-03). 7.2, the P0
  SSRF test, classified a `429` as "the URL was rejected", so on a rate-limited target every payload past the limit
  of its 75-payload burst counted as a defended SSRF attempt; 7.4 gave `ENFORCED/SIGNATURE_REQUIRED` to any answer
  that was not a `2xx`, a `503` or a dropped connection included; 7.3 read one success among concurrent requests
  that otherwise failed as "concurrency serialized", which is also what a server collapsing under the burst
  produces. All three now give `NOT_VERIFIABLE` with the reason, as every other test does (rule 1). No lab exercises
  these branches (7.3 and 7.4 have no configured case, the labs do not throttle).
- **Concurrent requests could share a record ID** (test-by-test review, 2026-11-03). Test 7.3 sends its burst from
  several threads through the one HTTP client, whose record counter was a read-modify-write without a lock. Calling
  the real method from 32 threads under frequent thread switches duplicated about half of 64,000 IDs; with the lock
  added, none in three runs. Two records under one ID would have made a finding's proof ambiguous and, since the
  transaction log is now completed by ID, hidden requests of the very burst 7.3 judges.
- **The report now lists every request the tool sent to the target** (test-by-test review, owner's decision of
  2026-11-03). The report schema calls a test's `transaction_log` "every HTTP request of the test", the evidence
  reference calls it "the full list of requests", and every run ends with "Every finding, request and response is in
  the reports". The log was filled by each test by hand, and counting on the reference lab what each test sent
  against what it listed showed eight of 31 leaving requests out: 6.2 listed none of its two behind its PASS, 4.1 one
  of its 150, 1.4 three of seven, and 0.2, 2.2, 2.5, 6.1 and 7.2 some. Now the client keeps every record it builds
  for the test the engine is running (`collect_requests_of()`, `collected_requests()`), and the engine adds to the
  test's log, as an unjudged step and in the order sent, every one the test did not record itself; a test can no
  longer forget one. Requests of the login and of the reference responses keep their own ids and stay out of a
  test's log. **Changed results**: transaction logs grow (4.1's by 149 entries); statuses and findings unchanged.
- **Test 6.4 counted an unavailable debug endpoint as blocked** (test-by-test review, 2026-11-03). Any answer to a
  debug path that was not a `2xx` gave `ENFORCED/DEBUG_BLOCKED`, a `503`, `429` or `500` included, while every
  other test treats those as saying nothing (rule 1). They now give `NOT_VERIFIABLE` with the reason. No lab
  exercises it: the configured debug paths answer only `200` or `404`.
- **Tests 6.1 and 6.2 attached as proof a response that contradicted the finding** (test-by-test review,
  2026-11-03). Both sample one endpoint per service and record one judgement per check, and the finding pointed at
  the *last* response sampled. For an inconsistent header that can be an endpoint where the header is present: on
  crAPI, 6.2's two findings said `X-Content-Type-Options` and the framing header are absent on
  `/community/api/v2/community/posts/recent` and pointed at `/workshop/api/mechanic/`, whose response carries
  `nosniff` and `X-Frame-Options: DENY`. Each finding now points at the response of the endpoint it names (and, for
  CORS, at the answer to the cross-origin probe on it); verified on crAPI, statuses unchanged on the three labs.
- **Tests 6.1 and 4.4 could send their write probe to one of the operator's real objects** (test-by-test review,
  2026-11-03; it settles an open question of the review). Both pick the shortest documented write and filled its
  path parameters from the path seed, which holds the operator's existing resources; 6.1 sends a malformed body with
  user_a's credential, so on a target whose shortest write is a `PUT` on an object, a server reading an unparseable
  body as empty would replace a real object. 6.1 now prefers a write without path parameters and otherwise addresses
  a random sibling, an object that does not exist; 4.4 addresses a random sibling too, which costs it nothing because
  the gateway applies its size limit to the route before the object is looked up. On the three labs both already
  probed parameter-free writes (`/api/v1/orgs`, `/identity/api/auth/login`, `/workshop/api/shop/orders`), so no
  result moves. 6.1's module also still said READ_ONLY, missed when its declaration changed.
- **4.4's crAPI result is a race, not a stable INCONCLUSIVE** (test-by-test review, 2026-11-03). The entry below of
  2026-10-29 described crAPI's early `401` and connection reset as what always happens; eight isolated runs gave 5
  INCONCLUSIVE and 3 FAIL, depending on whether the 2 MB upload finishes before the close. Both outcomes are right for
  what each run saw, the FAIL being the gateway's real state. Test 4.4's page, its limitations and the crAPI
  measurement in `06-compatibility.md` now say so, and that measurement no longer calls every status stable.
- **Test 5.1 passed a gateway whose only logging plugin was switched off** (test-by-test review, 2026-11-03). Its
  page promised "a known logging plugin is enabled", but neither adapter read a plugin's state: Kong's reader took
  every entry of `/plugins` regardless of its `enabled`, APISIX's every plugin regardless of `_meta.disable`. A
  disabled `http-log` therefore gave `ENFORCED/LOGGING_CONFIGURED`. `ConfigValue` now carries `enabled` (the
  pattern `CircuitBreaker.enabled` already followed), both readers set it from the gateway's own field (verified on
  Kong's plugin object and APISIX's plugin schema), and 5.1 ignores the values of a disabled plugin, as do the limit
  readers of 4.1 and 4.4. Test 6.4 still scans them: a credential in a disabled plugin is still in the
  configuration. Seen against a stand-in Kong Admin API on `127.0.0.1` (no lab touched): disabled `http-log`, PASS
  before and FAIL after; enabled, PASS. The three real gateways carry no disabled plugin (2, 4 and 5 plugins,
  checked) and are unchanged on 4.1, 4.4, 5.1 and 6.4.
- **Test 4.1 reported "the gateway does not limit the request rate" as CERTAIN after a burst that could not reach a
  normal production limit** (test-by-test review, 2026-11-03). The burst size was meant to be the gateway's
  configured limit plus a margin, read through the adapter. Neither adapter can deliver it: both gateways state a
  rate limit as a number (Kong's `rate-limiting.minute` is `number`, APISIX's `limit-count.count` is
  `integer`, read on their own schemas) and the configuration scan collects strings only. So the burst was always
  `max_burst`, 150 requests, and a gateway limiting at 1,000 requests per minute was told, with certainty, that it
  had no limit. The finding is now FIRM and says "no limit applies at or below 150 requests; a higher limit would
  not be seen", CERTAIN only where a configured limit was read and the burst went past it, and a limit read above
  the cap gives `NOT_VERIFIABLE/LIMIT_ABOVE_BUDGET` instead of a violation. The scan was deliberately not taught to
  collect numbers: the limit reader takes the smallest positive number of the plugin's configuration, which on
  Kong would also see the Redis port and its timeouts. Test 4.4 has the same blind spot
  (`request-size-limiting.allowed_payload_size` is an integer) but already reported it honestly as FIRM; its
  limitations now say the CERTAIN branch is not reached today. **Changed results**: the confidence and the text of
  4.1's `NO_RATE_LIMIT` finding, CERTAIN to FIRM on all three labs; statuses unchanged.
- **Domain 4, the rest** (test-by-test review, 2026-11-03). Test 4.2's module still described its oracle as the
  unreviewed v0.1.0 one, pending a "Q-29" in a "phase 1"; the page already justified `NOT_STATED` as a violation and
  said when it can occur, so the module now says the same. Eight code comments cited question ids (`Q-29`, `Q-31`,
  `Q-32`, `Q-67`, `Q-68`, `Q-69`) from a tracker that no longer exists and resolved nowhere; each sentence already
  stated its fact, so the tag was removed. Test 4.3's page now explains why an empty health-check answer on Kong is
  a true finding and not an empty read: a health check lives on an Upstream object, so a service pointing straight
  at a host has none. Domain re-run on the reference lab: 4.1, 4.2, 4.3 and 4.4 statuses identical.
- **Domain 3 read test by test: `ext.3.1.schemathesis` promised the target's behaviour as its own** (test-by-test
  review, 2026-10-29). Its effects section said "many generated requests, unauthenticated (no data created)", which
  is a fact about the target: the requests it generates include the writes the specification declares. Nothing was
  created on the three labs because every operation served without a credential there is a `GET` (measured by test
  1.1 the same day, 78 findings, all `GET`), but an API with an unauthenticated write has it exercised. The page and
  the module now say so, and say why the declaration stays `STRESSES_TARGET`: that is the last slot of the run order
  and the vocabulary has no value for "stresses and may write", so an operator who cannot accept it disables the
  external tools. Test 3.3 needed nothing, and reading it settled an open question of this review: its two
  violation branches were already proven on the reference lab with the lab change documented and undone, so the
  question asked how to produce what the page already records. Both tests re-run: identical.
- **Domain 2 read test by test: two findings had no proof, and rule 6 promised more than the suite delivers**
  (test-by-test review, 2026-10-29). Every finding of every test was checked for the `evidence_ref` rule 6 demands.
  Two carried none, both on crAPI: test 2.5's `SENSITIVE_FIELD`, which is the `card_number` finding the tool exists
  to make there, and test 1.3's `LIFETIME_EXCESSIVE`. Both now name their proof: 2.5 judges the read response with
  `_judge`, so the record reaches `evidence.json` (`2.5_002`), and 1.3 pins the login response that carried the
  token and points at it (`auth_setup_001`), the pattern test 1.6 already used. Two more findings rest on something
  that is not a single response and cannot name a record without a dangling reference, since an `ENFORCED` record is
  not written to `evidence.json`: 1.5's `PLAIN_HTTP`, whose proof is the configured base URL, and 2.1's
  `METHOD_CONFUSION`, whose proof is the set of per-method answers. Rule 6 now states those two exceptions, and each
  finding's detail says where its proof is. Also in 2.5: the comment and the page claimed "a unique string sentinel"
  per injected field while all six share one value, and a bound field is in fact recognised by its own name in the
  read-back object; the wording is corrected and an unused parameter of the matcher removed. Test 2.2's limitations
  now say that one operation of each kind is probed, not all. Verdicts unchanged everywhere: the five tests re-run
  on crAPI (4 findings, each naming its record) and six on the reference lab, identical to the baseline.
- **Domain 1 read test by test: 1.2 claimed an attack was impossible that its own lab makes possible, and rule 11
  described only two of the three external tests** (test-by-test review, 2026-10-29). Test 1.2 told the reader, in
  the report itself, that the key-based JWT attacks are "not verifiable here (not by this tool and not by any
  other)", and its page explained crAPI's `NEEDS_KEY_MATERIAL` as "(no JWKS)". crAPI publishes an RSA public key at
  `GET /identity/api/auth/jwks.json` (checked 2026-10-29), so algorithm confusion is testable there with a
  dedicated tool; what is true is that this test neither fetches key material nor implements the attack, by the
  decision of 2026-10-22. The note, the sub-test description, the crAPI row and the limitations now say that.
  Rule 11 said "the oracle is the tool's check, not its severity", which `ext.1.5.testssl` cannot follow because
  testssl.sh rates findings instead of naming checks: the rule now distinguishes a tool that names checks
  (`ext.3.1.schemathesis`), one that rates what it finds (`ext.1.5.testssl`, severity class as the oracle, the id
  read only to recognise the revocation case) and one that merely proposes candidates the test verifies itself
  (`ext.0.1.ffuf`), and that page's self-contradiction is gone. Test 1.7's effects section now says that three of
  its failed attempts carry a wrong password for the operator's own account and can count towards a lockout, while
  the 101 cannot. Tests 1.1, 1.3, 1.4, 1.5 and 1.6 needed nothing; 1.6 is the suite's model, with every branch of
  its oracle seen on a lab. The seven native tests re-run on the reference lab: identical to the baseline, 78
  findings on 1.1 and 3 on 1.7 included.
- **Domain 0 read test by test: two defects in 0.1, two statements added** (test-by-test review, 2026-10-29).
  Test 0.1 titled every finding of its method probe "Undeclared method handled", including the case its own oracle
  calls `UNDECLARED_METHOD_KNOWN`, where the method was *not* served and the evidence is only that the path answers
  differently from unknown paths: the title now says "known" for that case. Its page's oracle table was also split
  in two by a blank line, so the rows after the first rendered without a header; repaired, and every other page
  checked for the same break (none). Test 0.2's per-route-path precedence ("the best news wins": one neighbour the
  gateway refused with its own answer gives ENFORCED even when another answered 401) was in the code and on no
  page, and is now stated with the reason. Test 0.4 counts a timeout as `BACKEND_UNREACHABLE`, because the
  transport vocabulary has one `timeout` and cannot say whether the connection was accepted: a backend that accepts
  and never answers therefore reads as unreachable, now in its limitations. Tests 0.3 and `ext.0.1.ffuf` needed
  nothing. Checked on the reference lab: 0.1, 0.2, 0.3 and 0.4 identical to the baseline, down to every sub-test
  counter.
- **Three crAPI claims in the documentation no longer reproduced, and one of them was a consequence of our own
  retry rule** (test-by-test review, 2026-10-29). Comparing every page's validation table against three fresh full
  assessments, 44 of 47 claims reproduced exactly; the three that did not were all on crAPI. 2.5's came back after a
  lab reset (user A's credit was 0.0). 4.1's depends on load: run on its own after a reset it reports FAIL as its
  page says, in a full assessment of the same lab the workshop service no longer answers and it reports
  `UPSTREAM_UNAVAILABLE`. 4.4's claim was wrong for a subtler reason: crAPI answers `401` and resets the connection,
  in some runs while the 2 MB body is still uploading, and since the retry rule of 2026-10-28 that non-idempotent
  request is not sent again, so in those runs the test cannot conclude where it used to report a violation (it is a
  race: 8 isolated runs on 2026-11-03 gave 5 INCONCLUSIVE and 3 FAIL). The pages now state each case, 4.4
  has the limitation spelled out, and the crAPI matrix of `06-compatibility.md` carries today's measurement
  (13 FAIL, 10 PASS, 6 SKIP, 3 INCONCLUSIVE) with the reason two tests cannot conclude there and the note that
  `ext.3.1.schemathesis` reports a variable number of findings.
- **Nine oracle cases a test can report were on no page** (test-by-test review, 2026-10-29). Every `outcome` and
  `detail` the 32 test modules record was extracted from the code and looked for on the test's page. Most absences
  were wildcard rows that already cover the case in prose (`NO_*_OPERATION`, `NOT_VERIFIABLE/<reason>`, a transport
  failure). Nine were real: 6.2 documented the CORS violation and the no-CORS case but never the enforced one
  (`CORS_BOUNDED`); 2.1 never mentioned that nothing privileged being derived gives `NO_PRIVILEGED_ENDPOINT`, the
  likeliest outcome on a target with no `admin` segment, nor `SINGLE_SAFE_METHOD`; 1.1 never said its
  malformed-credential and path-variant sub-tests verify nothing without a proven control (`NO_PROVEN_CONTROL`);
  0.2's `REFUSAL_NOT_TRUSTED`, 0.4's `NO_ATTEMPT`, 1.7's `LOGIN_NOT_ANSWERING`, 2.4's `NO_VERSION_SIBLING` and
  2.2's and 2.5's `OBJECT_NOT_CREATED`, which is what a worn crAPI produces, were equally absent. Each page now has
  its row, and 6.1's enforced row names both its details (`CLEAN` and `NO_STACK_TRACE`).
- **Test 6.1 declared `READ_ONLY` and sent a write** (test-by-test review, 2026-10-29). Its error probe posts a
  malformed body (`{"apiguard": "unterminated`) to the shortest documented `POST`/`PUT`/`PATCH` of the target's own
  specification. No JSON parser can build an object from it, and nothing was created on any lab, but on a target
  whose shortest documented write is a `PUT` on an existing object a server treating an unparseable body as an empty
  one would replace that object. The test now declares `CHANGES_DATA`: the effects table an operator reads before a
  production run says what the tool sends, not what a well-behaved server does with it. `Effect` only orders the run
  and informs the operator, so no verdict changes; 6.1 moves from the read-only group into the data-changing one.
- **A gateway configuration that reads as empty gave a verdict in both directions: a false finding in 5.1, a false
  reassurance in 6.4** (test-by-test review, 2026-10-29). Four tests read the gateway's configuration values. 4.1
  and 4.4 only look for a configured limit there and decide from the live burst, so an empty answer costs them
  nothing. The other two treated "nothing matched among the values read" and "no value was read at all" as the same
  case: 5.1 reported `VIOLATION/NO_REQUEST_LOGGING`, accusing the target of having no logging plugin on the basis of
  having read nothing, and 6.4 reported `ENFORCED/CONFIG_NO_SECRET`, a pass earned by scanning nothing. Both now
  record `NOT_VERIFIABLE/NO_CONFIG_VALUE`, 5.1 with a note saying the read was empty. Seen against a stand-in Admin
  API answering every endpoint with an empty collection (a local process on `127.0.0.1`, no lab touched): before,
  5.1 `FAIL` with 1 finding and 6.4 `PASS complete`; after, 5.1 `INCONCLUSIVE` with 0 findings and 6.4 `PASS
  partial`. The three real gateways are unchanged, 11, 25 and 15 values read.
- **Test 6.4's debug probe verified nothing on any lab, and three lab configurations carried the review's
  scaffolding** (pass D of the test-by-test review, 2026-10-29). The `debug_endpoint_paths` block of the two Forgejo
  labs was commented out during the test review and never uncommented, so `debug_endpoint_no_secret` judged
  `NOT_APPLICABLE` everywhere and 6.4 was `partial` on all three labs: the page had to say the check "verified
  nothing". The block is live again on both Forgejo labs and the sub-test now judges 11 paths (one served and clean,
  three refused by the application, seven by the gateway's deny-by-default), taking 6.4 to `PASS complete` there;
  crAPI configures no debug path and stays `partial`. Removed in the same pass: the stale sentence announcing that
  parameters return uncommented with their test, and three commented blocks setting keys that no longer exist
  (`test_2_1.admin_endpoint_paths`, `admin_endpoint_method`, `gateway_block_body_fragment`), one of which would have
  created a duplicate `domain_2:` key and silently dropped the resources of tests 2.2 and 2.5 if believed. Checked
  with a full assessment of the three labs immediately before and after: 31 of 32 tests identical on each lab, 6.4
  the only difference.
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

- **Test 5.2, Security Alerting Audit** (test-by-test review, owner's decision of 2026-11-03). It could not produce
  a verdict on any target: its `execute()` returned SKIP unconditionally, because alerting lives in the SIEM or the
  notification channel and observing an alert needs a receiver the tool controls, which was decided "not built and
  not planned" on 2026-10-27, while its module still promised that follow-up. By the review's own rule (a test that
  does not earn its place is removed) and the precedent of guarantees 2.3 and 6.3, the guarantee stays in the
  methodology catalogue as `[P2 proposed, no test]` with a **Coverage by the tool** block naming the neighbours
  that cover adjacent ground (5.1 request logging, 1.7 attempt limiting) and saying to verify the alerting rules by
  hand. The suite has 31 tests; a full run has one SKIP fewer on every lab. Measurements dated before today keep
  the count they were taken with.

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

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

### Fixed

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
  `execution.openapi_fetch_timeout_seconds` the run stops with exit `10`.

### Removed

- `TargetContext.effective_base_url` and the `<TOOL>_SERVICE_URL` tool discovery: both were never functional.
  External tools are found in `./tools/` or `PATH`; a missing tool gives SKIP (with `<TOOL>_SERVICE_URL` set it
  used to give ERROR).

### Changed

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
- **Breaking:** strategies say what the tester has (BLACK_BOX: network only; GREY_BOX: an ordinary account;
  WHITE_BOX: the API's administrator account or internal access) and `execution.strategies` filters external tests
  too. Relabelled: 1.5, 1.6, 6.2, `ext.1.5.testssl`, `ext.1.5.sslyze` WHITE_BOX → BLACK_BOX (network access only);
  1.4 GREY_BOX → WHITE_BOX (administrator account). With all three strategies (the default) the same tests run; the
  `strategy` field of these tests changes in the report. Phase 1 warnings follow the exact SKIP conditions: WHITE_BOX
  without `gateway_adapter` (was: without `admin_api_url`, which missed an URL without adapter), WHITE_BOX without
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
  `target.path_seed` are not affected. `config.yaml` and `config_crapi.yaml` are unchanged and valid.
- **Breaking:** exit code `3` now means ERROR (at least one test could not complete, no FAIL); it was `2`. `2`
  now means only an invalid invocation (unknown option or command), so a wrapper can tell "nothing ran" from "the
  run completed with errors". The same value is in `executive_summary.exit_code` of `apiguard_report.json`.
- Test lab (`test-environments/forgejo-kong/`): every credential and secret comes from `.env` (new variables
  `LAB_DB_PASSWORD`, `LAB_FORGEJO_SECRET_KEY`, `LAB_TEST_REPO`, `LAB_TEST_ORG`, `LAB_TEST_TAG` in `.env.example`);
  the setup container creates users that can call the API immediately, plus the repository, organization, tag,
  issue and comment that `path_seed` points to; `gen-certs.sh` makes the key readable by Kong.
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

# Open Questions - Documentation Restructuring

Living log of doubts raised while restructuring the documentation.
Rule: nothing is written in the final docs on the basis of an open entry.
Each entry is closed only with evidence (command output, code location, or a test run).

Status values: `open` · `verified` (fact confirmed, recorded below) · `resolved` (decision taken) · `deferred` (out of current scope).

---

### Q-01 - Supported operating systems
- Status: open
- Source: `README.md:92` (Windows venv activation), `README.md:114` ("wheel is cross-platform … works on any system with Python 3.11+"), `pyproject.toml:63-64` (classifiers: Linux, macOS only)
- Question: Is Windows supported? Has the tool been run on macOS? The wheel being `py3-none-any` does not imply external tools (testssl.sh, nuclei) work on every OS.
- How to verify: user confirms on which OSes the tool has actually been run; docs then state only tested platforms.
- Resolution:

### Q-02 - Supported Python versions
- Status: open
- Source: `pyproject.toml:25` (`requires-python = ">=3.11"`), `pyproject.toml:67-68` (classifiers 3.11, 3.12), `README.md:80`
- Question: Which Python versions have actually been tested (3.11, 3.12, 3.13+)?
- How to verify: user confirms; optionally run `hatch run dev:pytest` under each interpreter.
- Evidence found: `docs/project/audits/2026-05-18-v0.1.0-release.it.md` §A.6 records the v0.1.0 audit run on Python 3.12.3.
- Resolution:

### Q-03 - Reference target for `getting-started/first-assessment.md`
- Status: open
- Source: `test-environments/forgejo-kong/docker-compose.yml`, `config_crapi.yaml:3-4`
- Question: All tests were developed and run against Forgejo + Kong. `config_crapi.yaml` targets cRAPI directly on `:8888` with `admin_api_url: null`, so WHITE_BOX tests SKIP; no cRAPI compose file exists in the repo. Which target does the tutorial use? Should cRAPI be put behind Kong?
- How to verify: discussion with user; the chosen environment is brought up from scratch following the tutorial steps literally.
- Resolution:

### Q-04 - Generated reference documentation
- Status: open
- Source: `src/cli.py` (Typer app), `src/config/schema/*.py` (Pydantic fields, most with `description=`), `src/tests/base.py:189-196` and `src/external_tests/base.py:195-199` (test ClassVars)
- Question: Adopt a script that generates `reference/` tables and the `tests/` index from code, with a `--check` mode to detect drift? Where is the check enforced? The repo has no CI and no pre-commit config (verified 2026-10-05).
- How to verify: decision with user; separate task after the inventory.
- Resolution:

### Q-05 - Licence
- Status: deferred
- Source: `pyproject.toml` (licence intentionally unspecified pending university regulations)
- Question: Which licence, and when?
- Resolution: Deferred by user (2026-10-05).

### Q-06 - SECURITY.md
- Status: deferred
- Question: Vulnerability disclosure policy for the tool itself.
- Resolution: Out of scope for now (user, 2026-10-05).

### Q-07 - Stale path in ADDING_tests.md
- Status: verified
- Source: `docs/guides/extending/add-a-native-test.md:1078` references `src/core/models.py`
- Question: The module is now the package `src/core/models/`. Are other parts of ADDING_tests.md equally outdated?
- How to verify: full read of ADDING_tests.md during the inventory, checking each code reference.
- Resolution: Path is stale (verified: `src/core/models/` is a package). Extent of drift to be assessed in the inventory.

### Q-08 - Public README links an internal document
- Status: verified
- Source: `README.md:441`, `README.en.md:441` link `docs/project/roadmap.md`
- Question: In the new structure the link must target `docs/project/roadmap.md`.
- Resolution: Fix during the move phase.

### Q-09 - `ext.0.1.nuclei` partial status
- Status: open
- Source: `docs/project/roadmap.md:52`, `:105` (marked `[~]`)
- Question: What exactly is missing for `[x]` (additional Cat A connectors ffuf/katana planned for M2?), and how should a partially covered guarantee be presented in the user-facing `tests/` page?
- How to verify: read PROJECT_status legend + TOOLS_decisions Domain 0; confirm with user.
- Resolution:

### Q-10 - External tests ignore `execution.strategies`
- Status: open
- Source: `src/engine.py:646-651` (external discovery receives `min_priority` and `allowed_ids`, not `strategies`); `src/external_tests/registry.py:374-417` (filters: allowed_ids, priority, per-tool enabled)
- Question: With `strategies: [BLACK_BOX]`, `ext.1.5.testssl` and `ext.1.5.sslyze` (WHITE_BOX) still run. Intended (external tests filtered only by `external_tools.*.enabled`) or a bug? The docs must state the real rule.
- How to verify: decision with user; optional confirmation run with `strategies: [BLACK_BOX]` against the lab target.
- Resolution:

### Q-11 - sslyze AGPL licence vs production integration
- Status: open
- Source: `pyproject.toml` optional dependency `sslyze` (comment: "for SaaS distribution, this extra must be removed or replaced")
- Question: The tool will be embedded in another product. Is the `[sslyze]` extra acceptable there, or must docs mark `ext.1.5.sslyze` as research-only?
- How to verify: decision with user (licensing, not code).
- Resolution:

### Q-12 - Project test suite
- Status: open
- Source: `README.md:121` (`hatch run dev:pytest -v`), `pyproject.toml` `[tool.pytest.ini_options] testpaths = []`; no `test_*.py` / `conftest.py` outside `src/`; dev deps include `pytest-httpx` while CLAUDE.md forbids httpx mocks
- Question: There is no automated test suite for the tool itself. What does CONTRIBUTING document as the verification procedure (E2E run on lab target? `hatch run dev:check`?)
- How to verify: decision with user.
- Resolution:

### Q-13 - Existing `hatch run dev:docs` script
- Status: open
- Source: `pyproject.toml` `[tool.hatch.envs.dev.scripts] docs` (pydoc-markdown → `docs/API_REFERENCE.md`, file not present in repo)
- Question: Keep, remove, or replace it as part of Q-04?
- How to verify: decide together with Q-04.
- Resolution:

### Q-14 - Priority ↔ strategy table vs implemented tests
- Status: open
- Source: `README.md:443-448` ("P1 typical GREY_BOX", "P2 GREY_BOX", "P3 WHITE_BOX")
- Question: Implemented tests: P1 = 4.2, 4.3 (both WHITE_BOX); P2 = 1.4, 2.1 (GREY), 1.5, 6.4, ext.1.5.* (WHITE); P3 = 1.6, 3.3, 6.2 (WHITE). Is the table the methodology's intended mapping (keep in `knowledge/`) or should user docs show only the real per-test values?
- How to verify: compare with `docs/knowledge/methodology/methodology.it.md` priority matrix; decide with user.
- Evidence found: the README table reproduces the methodology table (`3-Metodologia.md:63-66`, "P1 → Grey Box"). Per-test priorities in code match `3-Metodologia.md` for all 15 implemented tests; `TOOLS_decisions.md` / `TOOLS_catalog.md` list 1.4 and 2.1 as P1 (stale). Open point is only the strategy column (4.2, 4.3 are P1 but WHITE_BOX).
- Resolution:

### Q-15 - Layering: `external_tests` imports `config`
- Status: open
- Source: `src/external_tests/registry.py:61` (`from src.config.schema.external_tools import ExternalToolsConfig`); CLAUDE.md dependency direction does not mention `config/`
- Question: Is this an accepted exception (the module is a re-export of `core/models/external_tools.py`) or a rule violation? Determines how the dependency rule is written in `architecture/overview.md`.
- How to verify: decision with user.
- Resolution:

### Q-16 - No CI and no pre-commit
- Status: open
- Source: no `.github/workflows/`, `.gitlab-ci.yml` or `.pre-commit-config.yaml` in the repo (verified 2026-10-05); quality scripts exist only as `hatch run dev:lint|audit|check` in `pyproject.toml`
- Question: Add a CI pipeline and/or pre-commit hooks (lint, mypy, bandit, docs drift check from Q-04, link check)? Which platform hosts the repo (GitHub, GitLab)?
- How to verify: decision with user; separate task after the documentation restructuring.
- Evidence found: remote `origin` = `https://github.com/eneamanzi/apiguard-assurance` → GitHub Actions is the natural option.
- Resolution:

### Q-17 - Roadmap source of truth (Milestone 2)
- Status: open
- Source: `docs/architecture/overview.md:285-445` vs `docs/project/roadmap.md:178-245`
- Question: The two documents disagree on planned tests. Examples: 1.2 GREY_BOX (ARCHITECTURE) vs BLACK_BOX (PROJECT_status); 3.1 GREY_BOX vs BLACK_BOX; 5.1/5.2 GREY_BOX vs WHITE_BOX; 6.3 GREY+WHITE vs BLACK_BOX; dependency on 1.2 present in ARCHITECTURE, absent in PROJECT_status. PROJECT_status is also framed around the thesis ("July deadline", tests chosen for property demonstration). Which is current, and what is the post-thesis roadmap?
- How to verify: decision with user.
- Resolution:

### Q-18 - Target portability of each test
- Status: open
- Source: `src/tests/domain_1/test_1_4_token_revocation.py:70-76` (hardcoded Forgejo token API paths); `src/tests/helpers/auth_forgejo.py:66`; `src/tests/helpers/forgejo_resources.py`; `src/tests/domain_7/test_7_2_ssrf_prevention.py` (`injection_mode: forgejo_webhook | fixed_path`); `src/core/gateway/` (Kong only); `docs/knowledge/design-properties.it.md` D1.P1 ("no hardcoded application paths")
- Question: For a production integration, which tests run on any OpenAPI target, which need Forgejo (or a config switch), which need Kong? Behaviour of 1.4 on a non-Forgejo target is unknown. The only cRAPI output (`outputs/crapi/`, 2026-04-28) predates the current report schema, so it is not valid evidence.
- How to verify: code reading per test + a fresh run against a second target (ties into Q-03).
- Evidence found (2026-10-05, per-test pages): Forgejo-specific code or defaults in 1.4 (token API paths and `token` auth scheme), 2.1 (default `admin_endpoint_paths`), 7.2 (default `injection_mode: forgejo_webhook`); Kong-specific defaults in 0.2 (`gateway_server_identifiers` includes kong) and 6.4 (`gateway_block_body_fragment` is Kong's message); 3.3, 4.2, 4.3 and 6.4 sub-test B need the Kong adapter.
- Resolution:

### Q-19 - Stale documentation paths in source comments and scripts
- Status: open
- Source: 26 references in docstrings/comments of `src/engine.py` `src/discovery/seed_generator.py` `src/external_tests/ext_test_1_5_tls_analysis.py` `src/report/builder.py` `src/tests/domain_0/test_0_1_shadow_api_discovery.py` `src/core/models/enums.py` `src/tests/domain_1/test_1_4_token_revocation.py` `src/tests/domain_2/test_2_1_rbac_enforcement.py` `src/tests/domain_0/test_0_2_deny_by_default.py` `src/external_tests/ext_test_0_1_shadow_api_nuclei.py` `src/tests/domain_6/test_6_4_hardcoded_credentials_audit.py` `src/tests/registry.py` `src/tests/domain_1/test_1_1_authentication_required.py` `src/core/models/runtime.py` `src/tests/domain_0/test_0_3_deprecated_api_enforcement.py` `src/core/dag.py` `src/core/exceptions.py` `src/core/models/results.py` `src/core/evidence.py` - mostly "`4-Implementazione.md` §x", plus `docs/pub/…`, `docs/priv/…`. Also `build_zip.sh:62-64` (exclusion list already pointing to non-existent `docs/*.md` names).
- Question: Docs moved on 2026-10-05 (see mapping in `docs/project/docs-inventory.md`). Source files were deliberately not touched (no code changes during docs work). Update comments to the new paths once the target pages exist (e.g. `architecture/…`, `tests/<id>.md`).
- How to verify: `grep -rn -E "4-Implementazione|3-Metodologia|docs/(pub|priv)|ADDING_tests|ARCHITECTURE\.md|PROJECT_status" src build_zip.sh` returns nothing.
- Resolution:

### Q-20 - CLI usage errors share exit code 2 with "ERROR"
- Status: open
- Source: Typer/Click default; verified 2026-10-05: `apiguard run --bogus`, `--log-format xml`, and `apiguard` without arguments all exit 2. `src/engine.py:131` uses 2 for "at least one test ERROR".
- Question: A wrapper cannot distinguish "bad invocation" from "assessment completed with ERROR". Map usage errors to a distinct code? Documented as-is in `docs/reference/exit-codes.md`.
- How to verify: decision with user (code change).
- Resolution:

### Q-21 - `generate-seed` stdout output is not valid YAML when redirected
- Status: open
- Source: `src/cli.py:443-450` prints panel, log lines and template on stdout; Rich wraps long comment lines. Verified 2026-10-05: `apiguard generate-seed ./specs/crapi-openapi.json --log-format json > f` → `yaml.safe_load` fails; with `--output f` the file is valid.
- Question: Make stdout mode redirect-safe (logs to stderr, no wrapping)? Docs currently tell users to use `--output`.
- How to verify: decision with user (code change).
- Resolution:

### Q-22 - Unknown keys in config.yaml are silently ignored
- Status: open
- Source: no Pydantic `extra="forbid"` in `src/config/schema/*`, `src/core/models/external_tools.py`. Verified 2026-10-05: `execution.min_prioriti: 0` (typo) → `validate-config` exits 0 and the default applies.
- Question: Reject unknown keys (`extra="forbid"`) so typos fail at Phase 1? Documented as a warning in `docs/reference/configuration.md`.
- How to verify: decision with user (code change).
- Resolution:

### Q-23 - `generated_at_utc` in apiguard_report.json is not UTC
- Status: open
- Source: `src/report/builder.py:394` - `datetime.now(ZoneInfo("Europe/Rome"))`; real output: `"2026-10-05T17:12:00.515745+02:00"`. `evidence.json` uses UTC (`+00:00`).
- Question: Use UTC as the field name promises (affects the integration contract → `output_schema_version` policy)? Documented as-is in `docs/reference/report-schema.md`.
- How to verify: decision with user (code change).
- Resolution:

### Q-24 - Config fields accepted but without effect
- Status: open
- Source: `external_tools.sslyze.extra_flags` (never read by `src/connectors/sslyze.py` or `ext_test_1_5_tls_analysis.py`); `tests.domain_7.test_7_2.ssrf_request_timeout_ms` (description: "reserved for future… currently the global execution.read_timeout governs all requests"; only passed through `src/engine.py:496`).
- Question: Remove, implement, or keep documented as no-op?
- How to verify: decision with user.
- Resolution:

### Q-25 - Stability policy for the integration interfaces
- Status: open
- Source: `docs/reference/compatibility.md` "Interface stability"; only `apiguard_report.json` has a version (`output_schema_version`, policy in `src/report/builder.py:322-327`).
- Question: The tool will be embedded in another product. Which interfaces are a stable contract (exit codes, report JSON, evidence JSON, config schema, CLI), how are breaking changes signalled (version field, CHANGELOG, major bump)?
- How to verify: decision with user; feeds `CHANGELOG.md` and `guides/integration/`.
- Resolution:

### Q-26 - Schema descriptions say "SKIP" for disabled external tools; the registry excludes them
- Status: open
- Source: `src/core/models/external_tools.py` (`enabled` description: "When False, all tests for this tool return SKIP"), `ToolConfig.external_tools` description in `src/config/schema/tool_config.py`; actual behaviour in `src/external_tests/registry.py:88-104, 405-440` (master switch → `[]`; per-tool disabled → filtered out). Consistent with `outputs/crapi/` (no `external_tools` section → no `ext.*` rows).
- Question: Fix the descriptions (code comments) or change behaviour so that disabled tools appear as SKIP in the report (visible coverage gap)? Docs describe the actual behaviour.
- How to verify: decision with user.
- Resolution:

### Q-27 - `<TOOL>_SERVICE_URL` availability channel
- Status: open
- Source: `src/connectors/base.py:364-384` (`is_available()` returns True when `os.getenv(SERVICE_ENV_VAR)` is set); `NUCLEI_SERVICE_URL` (`src/connectors/nuclei.py:142`), `TESTSSL_SERVICE_URL` (`src/connectors/testssl.py:138`).
- Question: When only the service variable is set (no local binary, nothing in PATH), how does `run()` execute the tool? Is this channel functional or a placeholder? Not documented in user docs until clarified.
- How to verify: code reading of `run()` / `_resolve_binary_path()` with the env var set; test with the variable set and no binary.
- Resolution:

---

## Findings from writing `docs/tests/` and `docs/reference/` (2026-10-05)

The test pages describe what the code does. Each item below is a divergence or a behaviour worth a decision.
None has been changed in code.

### Q-28 - Docstrings and field descriptions that contradict the code
- Status: open
- Question: Update each comment to match the code, or change the code to match the comment? Item by item:
  - [ ] `src/tests/domain_0/test_0_1_shadow_api_discovery.py:17,107` - announces a "version discovery" sub-check; the code runs only path fuzzing and undeclared-method probing.
  - [ ] `src/external_tests/ext_test_0_1_shadow_api_nuclei.py:11-12` - describes native 0.1 as using `OPTIONS` and a versioning check; it does neither.
  - [ ] `src/tests/domain_1/test_1_1_authentication_required.py:45-46` - says parametric `DELETE` uses the placeholder `apiguard-probe`; the code (`:515-520`) uses `path_seed` values first.
  - [ ] `src/tests/domain_2/test_2_1_rbac_enforcement.py:29` - says `404` is inconclusive; `:70` counts `403` and `404` as enforced.
  - [ ] `src/tests/domain_4/test_4_3_circuit_breaker_audit.py:64` - "PASS + informational Finding"; the code attaches an InfoNote (a PASS cannot carry findings).
  - [ ] `src/tests/domain_6/test_6_2_security_headers_audit.py:19` - says `includeSubDomains` is required; `:563` only logs it at debug level, no finding.
  - [ ] `src/external_tests/ext_test_1_5_tls_analysis.py:22,33-36` - refers to `tests.domain_1.test_1_5.testssl_binary_path` and a "legacy sub-test 3"; neither exists.
  - [ ] `src/tests/domain_7/test_7_2_ssrf_prevention.py:58` calls the redirect sub-test "G"; `:151` (skip reason shown in the report) and `:229` call it "E".
  - [ ] `src/core/models/http.py:109` - `request_body` "sanitized of secrets"; `src/core/client.py:562-567` stores the JSON body as sent.
  - [ ] `src/config/schema/tool_config.py:178` - `admin_api_url`: "If absent, all WHITE_BOX tests return SKIP"; tests 1.5, 1.6, 6.2 and 6.4 run without it.
  - [ ] `src/connectors/_template_connector.py:12` - points to `src/config/schema/external_tools.py`; the config classes live in `src/core/models/external_tools.py`.
  - [ ] `src/cli.py:500-503` - says third-party logs go through the structlog pipeline; `:537-541` prints them as plain text.
  - [ ] 19 references in 15 files cite `3_TOP_metodologia.md` (a file name that never existed in the repo); see also Q-19 for the other stale paths.
- How to verify: re-read each location after the decision.
- Resolution:

### Q-29 - Lenient or weak oracles
- Status: open
- Question: For each item, is the behaviour intended (document it as a limitation) or should the oracle be tightened?
  - [ ] 1.4 - any non-`2xx` on the revoked-token re-probe is PASS, including `404`/`5xx` (`src/tests/domain_1/test_1_4_token_revocation.py:380-434`).
  - [ ] 2.1 - `404` counts as enforced, so a wrong or non-existent `admin_endpoint_paths` entry yields PASS (`test_2_1_rbac_enforcement.py:70`).
  - [ ] ext.1.5.sslyze - TLS 1.0 / 1.1 support is MEDIUM → InfoNote, not FAIL (`src/connectors/sslyze.py:297-309`); the methodology requires TLS 1.2+ only.
  - [ ] 0.2 - the URL-encoded variant uses `urllib.parse.quote`, unchanged for ASCII segments, so it is almost never sent (`test_0_2_deny_by_default.py`, `_build_path_variants`).
  - [ ] 0.2 - only `200` on a normalization variant is a finding; other `2xx` are "rejected".
  - [ ] 1.1 - only `2xx` is a bypass; "protected" means "declared with `security` in the spec" (undeclared endpoints are not tested).
  - [ ] 1.5 - any exception during the HTTP probe counts as "HTTP not served" (`test_1_5_insecure_credential_transport.py`, `except Exception: return None`).
  - [ ] 0.3 - an unparseable `Sunset` header is treated as compliant.
  - [ ] 3.3 - only the first plugin matching `plugin_names` is audited; if it is disabled the test SKIPs even when another instance is enabled.
  - [ ] 4.1 - one probe endpoint only; budget fixed by `max_requests`, not derived from the documented limit.
  - [ ] 4.3 - Level 2 passes if at least one upstream has a valid passive health check (others may have none); on FAIL the observability InfoNote is converted into a Finding and counted.
  - [ ] 6.2 - `X-Frame-Options` accepts any value except `ALLOW-FROM`; `Permissions-Policy` content not evaluated.
  - [ ] 7.2 - only `200`/`201` count as accepted (`_ACCEPTED_STATUS_CODES`); acceptance of the URL is checked, not an actual outbound request.
  - [ ] 7.2 - FAIL carries a single consolidated Finding; per-payload detail only in the transaction log and `evidence.json` (`test_7_2_ssrf_prevention.py:402-427`).
- How to verify: decision per item; tests pages "Limitations" sections list the same points.
- Resolution:

### Q-30 - Side effects on the target
- Status: open
- Question: Acceptable for a production assessment tool? Should they be documented in a "safety" page, made opt-in, or changed?
  - [ ] 1.1 sends `POST`/`PUT`/`PATCH` with `{}` and parametric `DELETE` without credentials to every protected endpoint; with real IDs in `target.path_seed` the `DELETE` targets real resources.
  - [ ] 0.1 sends undeclared `POST`/`PUT`/`PATCH`/`DELETE` without credentials to up to 10 documented paths.
  - [ ] 0.3 sends each deprecated endpoint's declared method (possibly `POST`/`DELETE`) without credentials.
  - [ ] 7.2 `fixed_path` mode registers nothing for teardown: accepted payloads may leave persistent objects. `forgejo_webhook` mode creates a repository and up to 73 inactive webhooks (removed by teardown).
  - [ ] 1.4 creates and deletes an API token on the admin account.
  - [ ] 4.1 sends up to 2 × `max_requests` requests in a burst and exhausts the tool's rate-limit budget for the following tests.
- How to verify: decision with user.
- Resolution:

### Q-31 - Sensitive data in the outputs
- Status: open
- Source: `src/core/models/http.py:150-157` (only `authorization` redacted); `src/core/client.py:562-578` (bodies stored as sent/received); test 6.4 quotes matched secrets in finding details.
- Question: Cookies, custom API-key headers, request and response bodies and secrets found by 6.4 are written to `evidence.json` and `apiguard_report.json`. Redact more (which headers/fields), or document the outputs as sensitive (current state in `docs/reference/evidence-format.md`)?
- How to verify: decision with user.
- Resolution:

### Q-32 - Methodology sub-tests not implemented
- Status: open
- Source: section "Coverage against the methodology" of every page in `docs/tests/`.
- Question: The pages list methodology sub-tests that the code does not run (e.g. 0.1 documentation drift via Admin API, 1.4 token after password change, 2.1 method confusion and role hierarchy, 4.1 per-user limits and burst, 7.2 domain whitelist). The methodology does not say which were deferred on purpose. Mark each as "out of scope" or add it to the roadmap?
- How to verify: decision with user; feeds `docs/project/roadmap.md`.
- Resolution:

### Q-33 - Inconsistencies inside the knowledge documents
- Status: open
- Question:
  - [ ] `docs/knowledge/methodology/methodology.it.md:312` gives 2.2 priority `[P1]`, while the priority matrix (`:63-79`) lists 2.2 under P2.
  - [ ] `docs/knowledge/tools/decisions.it.md` and `tools/catalog.it.md` list 1.4 and 2.1 as P1; methodology and code say P2.
  - [ ] `docs/knowledge/target-selection.it.md` lists requirements and candidates but not why Forgejo was chosen; needed for `knowledge/target-selection` when translating.
- How to verify: decision with user while translating `knowledge/`.
- Resolution:

### Q-34 - Gateway Admin API: no authentication, TLS always verified
- Status: open
- Source: `src/core/gateway/kong.py:297-307` (`httpx.Client(timeout=…, follow_redirects=False)`, plain `GET`, no headers, httpx default `verify=True`); `target.verify_tls` is applied only to `base_url` (`src/engine.py` Phase 3).
- Question: Production Admin APIs are usually protected (Kong Enterprise RBAC token, mTLS, or a self-signed certificate on an internal network). Today the adapter cannot send credentials and cannot accept a self-signed Admin API certificate. Add `target.admin_api_*` auth/TLS options?
- How to verify: decision with user (code + config change).
- Resolution:

### Q-35 - `openapi_fetch_timeout_seconds` does not stop a hanging spec server
- Status: verified (bug)
- Source: `src/discovery/openapi.py:429-447` - the `TimeoutError` is raised inside `with ThreadPoolExecutor(...)`; leaving the block calls `shutdown(wait=True)`, which waits for the blocked prance/requests thread.
- Evidence: 2026-10-05, local socket server that accepts and never answers; `_fetch_and_dereference(url, 2.0)` was still blocked after 20 s and the process could not exit (killed by `timeout 60`, exit 124).
- Question: Fix (e.g. `executor.shutdown(wait=False)` / daemon thread, or a socket timeout on prance's requests session)? Until then the run can hang indefinitely in Phase 2 when `openapi_spec_url` points to an unresponsive server. Documented in `docs/reference/configuration.md`.
- Resolution:

### Q-36 - `effective_base_url` / `APIGUARD_TARGET_EFFECTIVE_URL` not wired
- Status: verified
- Source: `src/core/context.py:200-227` says the engine reads `APIGUARD_TARGET_EFFECTIVE_URL` in Phase 3 and refers to `docker-compose.external-tools.yml`; `grep` finds no read of that variable in `src/` and the compose file does not exist. `TargetContext` is built in `src/engine.py` Phase 3 without `effective_base_url`, so `effective_endpoint_base_url()` always falls back to `base_url`.
- Question: Implement the "Docker Compose mode" (external tools in a container addressing the target by service name), or remove the field and comments? Also listed as property D7.P3 in `docs/knowledge/design-properties.it.md`.
- How to verify: decision with user.
- Resolution:

### Q-37 - Convention "every test has a config model" vs code
- Status: open
- Source: previous `ADDING_tests.md` ("When the test has no operator-tunable parameters: create the config model anyway"; git `fd3bd90:docs/guides/extending/add-a-native-test.md:236-241`); code: no `Test01Config`/`Test03Config` and no `RuntimeTest01Config`/`RuntimeTest03Config` (13 runtime configs for 15 native tests). Also the old guide said a missing `src/config/schema/__init__.py` export raises `ImportError`; nothing imports `Test*Config` from that package (`tests_config.py` imports domain modules directly).
- Question: Keep the convention (add empty models for 0.1, 0.3) or drop it? The new guide documents the code as it is.
- How to verify: decision with user.
- Resolution:

### Q-38 - Gateway adapter abstraction returns gateway-specific data
- Status: open
- Source: `src/core/gateway/base.py` (methods return "gateway-specific" dicts); tests 3.3, 4.2, 4.3 and 6.4 sub-test B parse Kong fields (`config.clock_skew`, `connect_timeout`/`read_timeout`/`write_timeout`, `healthchecks.passive.unhealthy.*`, Kong `/status`); engine Phase 3 instantiates only `KongGatewayAdapter` (`src/engine.py`, `if config.target.gateway_adapter == "kong"`); the schema accepts only `"kong"` (`src/config/schema/tool_config.py`, `gateway_adapter_requires_admin_api_url`). `check_connectivity()` and `get_plugin_by_name()` are never called outside `src/core/gateway/`.
- Question: To support another gateway, should adapters normalise data into a gateway-neutral model (and tests read that), or should each adapter return Kong-shaped dicts? Is a connectivity check wanted in Phase 3?
- How to verify: decision with user (design).
- Resolution:

### Q-39 - Coding rules vs code and tooling
- Status: open
- Source: CLAUDE.md "Hard Rules", `docs/project/claude-rules.it.md` §5, `pyproject.toml` hatch scripts; checks run 2026-10-05.
- Question (one decision per item):
  - [ ] "No numbers in module filenames" (CLAUDE.md) vs the required test naming `test_<D>_<N>_*.py` / `ext_test_<D>_<N>_*.py`: state the exception explicitly.
  - [ ] "Pydantic v2 only, no TypedDict for data models" vs `TypedDict` in `src/connectors/base.py:865` (`ConnectorRawOutput`), `src/connectors/types/tls_findings.py:37` (`TlsFinding`, external tool output), `src/tests/base.py:105`, `src/external_tests/base.py:133`: clarify where TypedDict is allowed.
  - [ ] `claude-rules.it.md` §5.3 says code must pass `ruff format --check .`; it does not (7 files would be reformatted: `src/config/schema/domain_4.py`, `src/connectors/sslyze.py`, `src/core/models/external_tools.py`, `src/external_tests/ext_test_0_1_shadow_api_nuclei.py`, `src/external_tests/ext_test_1_5_tls_analysis.py`, `src/tests/domain_1/test_1_4_token_revocation.py`, `src/tests/domain_1/test_1_5_insecure_credential_transport.py`) and `hatch run dev:check` does not include the format check.
  - [ ] `claude-rules.it.md` §5.6 refers to an E2E suite in `tests_e2e/` that does not exist (see Q-12).
  - [ ] `hatch run dev:check` passes (ruff check, mypy strict, bandit medium, vulture 80) as of 2026-10-05.
- How to verify: decision with user; `hatch run dev:ruff format --check .`.
- Resolution:

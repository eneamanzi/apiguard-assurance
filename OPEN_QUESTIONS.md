# Open Questions - Documentation Restructuring

Living log of doubts raised while restructuring the documentation.
Rule: nothing is written in the final docs on the basis of an open entry.
Claude collects evidence (command output, code location, test run) and may write a *proposed resolution*;
an entry is closed only by a decision of the project owner. Working order: see `docs/project/plan.md`.

Status values: `open` · `verified` (fact confirmed, recorded below) · `resolved` (decision taken) · `deferred` (out of current scope).

---

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

### Q-13 - Existing `hatch run dev:docs` script
- Status: open
- Source: `pyproject.toml` `[tool.hatch.envs.dev.scripts] docs` (pydoc-markdown → `docs/API_REFERENCE.md`, file not present in repo)
- Question: Keep, remove, or replace it as part of Q-04?
- How to verify: decide together with Q-04.
- Resolution:

### Q-15 - Layering: `external_tests` imports `config`
- Status: decided (owner, 2026-10-06), implementation pending (group 3.D, cleanup block)
- Source: `src/external_tests/registry.py:61` (`from src.config.schema.external_tools import ExternalToolsConfig`); CLAUDE.md dependency direction does not mention `config/`
- Question: Is this an accepted exception (the module is a re-export of `core/models/external_tools.py`) or a rule violation? Determines how the dependency rule is written in `architecture/overview.md`.
- How to verify: decision with user.
- Evidence (2026-10-06): it is the only import from `config/` in `core/`, `connectors/`, `tests/`, `external_tests/`. `src/config/schema/external_tools.py` is a re-export shim of `src/core/models/external_tools.py`; both imports return the same class object (`A is B` → `True`).
- Decision (owner, 2026-10-06): no exception to the dependency rule. Change `src/external_tests/registry.py:61` to `from src.core.models.external_tools import ExternalToolsConfig` (no behaviour change); verify with `hatch run dev:check` and a run with the external tools; remove "(registry only, Q-15)" from `docs/architecture/overview.md`. Also add an automatic check of the dependency rule (e.g. `import-linter`) to `dev:check` (see Q-39).
- Resolution:

### Q-16 - No CI and no pre-commit
- Status: open
- Source: no `.github/workflows/`, `.gitlab-ci.yml` or `.pre-commit-config.yaml` in the repo (verified 2026-10-05); quality scripts exist only as `hatch run dev:lint|audit|check` in `pyproject.toml`
- Question: Add a CI pipeline and/or pre-commit hooks (lint, mypy, bandit, docs drift check from Q-04, link check)? Which platform hosts the repo (GitHub, GitLab)?
- How to verify: decision with user; separate task after the documentation restructuring.
- Evidence found: remote `origin` = `https://github.com/eneamanzi/apiguard-assurance` → GitHub Actions is the natural option.
- Resolution:

### Q-17 - Roadmap source of truth (Milestone 2)
- Status: decided in part (owner, 2026-10-06); rewrite pending (end of group 3.D planning)
- Source: `docs/architecture/overview.md:285-445` vs `docs/project/roadmap.md:178-245`
- Question: The two documents disagree on planned tests. Examples: 1.2 GREY_BOX (ARCHITECTURE) vs BLACK_BOX (PROJECT_status); 3.1 GREY_BOX vs BLACK_BOX; 5.1/5.2 GREY_BOX vs WHITE_BOX; 6.3 GREY+WHITE vs BLACK_BOX; dependency on 1.2 present in ARCHITECTURE, absent in PROJECT_status. PROJECT_status is also framed around the thesis ("July deadline", tests chosen for property demonstration). Which is current, and what is the post-thesis roadmap?
- How to verify: decision with user.
- Evidence (2026-10-06): the conflict no longer exists: the old `ARCHITECTURE.md` was replaced by `docs/architecture/overview.md`, which has no future plan; `docs/project/roadmap.md` is the only source. It was still framed around the thesis ("Pre-Thesis Writing", "Future Work (Thesis Chapter)", "July deadline", connectors chosen as "tier demo") and did not contain the real next work (group 3.D).
- Done (owner decision, 2026-10-06): light correction of `roadmap.md`: English title and legend, thesis and deadline wording removed, Milestone 1 = v0.1.0, Milestone 2 renamed "Candidate tests (not yet planned)" with a note that strategy, priority, tools and order are to be confirmed per test, header pointing to `plan.md`.
- To do: rewrite `roadmap.md` as a product roadmap (a "v1.0 production-ready" milestone with the work of group 3.D, then new tests) after group 3.D is planned.
- Resolution:

### Q-18 - Target portability of each test
- Status: open
- Source: `src/tests/domain_1/test_1_4_token_revocation.py:70-76` (hardcoded Forgejo token API paths); `src/tests/helpers/auth_forgejo.py:66`; `src/tests/helpers/forgejo_resources.py`; `src/tests/domain_7/test_7_2_ssrf_prevention.py` (`injection_mode: forgejo_webhook | fixed_path`); `src/core/gateway/` (Kong only); `docs/knowledge/design-properties.it.md` D1.P1 ("no hardcoded application paths")
- Question: For a production integration, which tests run on any OpenAPI target, which need Forgejo (or a config switch), which need Kong? Behaviour of 1.4 on a non-Forgejo target is unknown. The only cRAPI output (`outputs/crapi/`, 2026-04-28) predates the current report schema, so it is not valid evidence.
- How to verify: code reading per test + a fresh run against a second target (ties into Q-52).
- Evidence found (2026-10-05, per-test pages): Forgejo-specific code or defaults in 1.4 (token API paths and `token` auth scheme), 2.1 (default `admin_endpoint_paths`), 7.2 (default `injection_mode: forgejo_webhook`); Kong-specific defaults in 0.2 (`gateway_server_identifiers` includes kong) and 6.4 (`gateway_block_body_fragment` is Kong's message); 3.3, 4.2, 4.3 and 6.4 sub-test B need the Kong adapter.
- Evidence (2026-10-06, fresh isolated cRAPI, `config_crapi.yaml`, no gateway): 1.4 ERROR (`ForgejoResourceError: GET /api/v1/user returned HTTP 404`); 2.1 PASS only because the default Forgejo path does not exist on cRAPI (404 counted as enforced); 7.2 works in `fixed_path` mode (73 payloads rejected); 3.3, 4.2, 4.3 SKIP (no adapter); 0.1, 0.2, 0.3, 1.1, 1.5, 1.6, 4.1, 6.2, 6.4 run normally. No `ext.*` tests (no `external_tools` section). Totals: 4 PASS, 5 FAIL, 5 SKIP, 1 ERROR, exit 1, 3 min 8 s.
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
- Evidence (2026-10-06, first superficial pass): only `apiguard_report.json` has a version (`output_schema_version: "1.0"`, policy in `src/report/builder.py:322-327`); `evidence.json`, exit codes, `config.yaml`, CLI have none. Known defects whose fix changes what an integrator sees: Q-20 (usage errors exit 2), Q-22 (unknown config keys ignored), Q-23 (`generated_at_utc` not UTC), Q-45 (`test_ids` selection), Q-50 (findings without `evidence_ref`); Q-31 and Q-47 may change the report too.
- Draft only, NOT decided (to be reviewed in depth in group 3.D): stable interfaces = exit codes, report JSON, `evidence.json` (add a version field), CLI commands and options, documented `config.yaml` keys; not contract = log events, Python modules, message texts, `oracle_state` values; signalling = per-file format version (major = breaking), "Breaking changes" section in `CHANGELOG.md`, semver from 1.0.0; fix the defects above together, then declare 1.0.0.
- Owner decision (2026-10-06): not settled now. The question touches code that belongs to the code phase; it was only looked at superficially. Moved to 3.D as the first block of the code phase ("contract 1.0"), to be reviewed in depth there, after the 3.C decisions that may change the report (Q-31, Q-47).
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
- Evidence (2026-10-06): `is_available()` (`src/connectors/base.py:362-384`) returns True when `<TOOL>_SERVICE_URL` is set, but `NucleiConnector.run()` (`src/connectors/nuclei.py:197-205`) raises `ExternalToolError` "binary not found via any discovery channel" when `_resolve_binary_path()` is None; no code ever calls the URL. So with only the variable set, the test is scheduled and ends in ERROR instead of SKIP. The channel is a non-functional placeholder; docs do not mention it.
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
  - [ ] ext.0.1.nuclei - results on other services of the target host are reported (2026-10-06, lab: `ssh-sha1-hmac-algo` on `localhost:22`, the owner's VM SSH, not the API); severity info, so InfoNote only, but out of scope for an API assessment.
  - [ ] 7.2 - FAIL carries a single consolidated Finding; per-payload detail only in the transaction log and `evidence.json` (`test_7_2_ssrf_prevention.py:402-427`).
- How to verify: decision per item; tests pages "Limitations" sections list the same points.
- Evidence (2026-10-06): 2.1 on cRAPI returned PASS with the Forgejo default `admin_endpoint_paths`, a path that does not exist there.
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
- Owner decision (2026-10-06): not to be settled by labelling items "planned" or "out of scope". Many tests are implemented superficially and must be improved in the code: handle this as a per-test quality review in group 3.D, together with Q-29 (lenient oracles). Current list of missing or partial sub-tests (from the "Coverage against the methodology" sections, 2026-10-06): 0.1 versioning completeness (partial), documentation drift via Admin API; 0.2 double encoding and `../`; 0.3 differential rate limiting, differential logging; 1.4 token after password change, concurrent logout; 1.6 session fixation, session-store TTL / replication / entropy; 2.1 HTTP method confusion, role hierarchy; 3.3 application-level HMAC, key entropy, empirical tampering/replay; 4.1 `Retry-After` reset (partial), per-user vs per-IP, burst; 4.2 application pool and outbound timeouts, slow mock service; 4.3 30-day metrics, disabled dependency; 6.4 container image layers, secret rotation; 7.2 domain whitelist, blind SSRF (out-of-band); ext.1.5 limits already in Q-29.
- Resolution:

### Q-33 - Inconsistencies inside the knowledge documents
- Status: open
- Question:
  - [ ] `docs/knowledge/methodology/methodology.it.md:312` gives 2.2 priority `[P1]`, while the priority matrix (`:63-79`) lists 2.2 under P2.
  - [ ] `docs/knowledge/tools/decisions.it.md` and `tools/catalog.it.md` list 1.4 and 2.1 as P1; methodology and code say P2.
  - [ ] `docs/knowledge/target-selection.it.md` lists requirements and candidates but not why Forgejo was chosen; needed for `knowledge/target-selection` when translating.
  - [ ] `docs/knowledge/methodology/methodology.it.md` (priority/approach table near line 63, and the headings "Grey Box ... P1, P2", "White Box ... P3") presents priority and strategy as linked. Owner decision on the former Q-14 (2026-10-06): they are independent (priority = severity, strategy = what the tester needs). Reword when translating.
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
- Status: decided (owner, 2026-10-06), implementation pending (group 3.D)
- Source: previous `ADDING_tests.md` ("When the test has no operator-tunable parameters: create the config model anyway"; git `fd3bd90:docs/guides/extending/add-a-native-test.md:236-241`); code: no `Test01Config`/`Test03Config` and no `RuntimeTest01Config`/`RuntimeTest03Config` (13 runtime configs for 15 native tests). Also the old guide said a missing `src/config/schema/__init__.py` export raises `ImportError`; nothing imports `Test*Config` from that package (`tests_config.py` imports domain modules directly).
- Question: Keep the convention (add empty models for 0.1, 0.3) or drop it? The new guide documents the code as it is.
- How to verify: decision with user.
- Evidence (2026-10-06): test 0.1 does have a tunable written in the code: `list(surface.endpoints)[:10]` (`src/tests/domain_0/test_0_1_shadow_api_discovery.py:172`, the "first 10 endpoints" of the undeclared-method sub-check), a magic number under the project rules; its wordlist (`SHADOW_API_WORDLIST`) is also fixed in code. Test 0.3 has only protocol constants (410, `Sunset`).
- Decision (owner, 2026-10-06): every native test always has its configuration model, empty if it has no parameters. A missing model is a developer error: it is checked in `hatch run dev:check` (not at runtime, never shown to the end user).
- To implement: models for 0.1 and 0.3; the check in `dev:check`; update `add-a-native-test.md` (remove the "no parameters" special case). Still to decide: the `10` of test 0.1 becomes a `config.yaml` parameter (needs owner confirmation) or a named constant. Implement together with Q-53, so that the new models already use the single definition.
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
  - [ ] `claude-rules.it.md` §5.6 refers to an E2E suite in `tests_e2e/` that does not exist (planned: Q-51).
  - [ ] The dependency rule (`core/` ← `connectors/` ← `tests/`, `external_tests/` ← `engine.py`) is not checked automatically; owner decision on Q-15 (2026-10-06): add a check (e.g. `import-linter`) to `dev:check`.
  - [ ] `hatch run dev:check` passes (ruff check, mypy strict, bandit medium, vulture 80) as of 2026-10-05.
- How to verify: decision with user; `hatch run dev:ruff format --check .`.
- Resolution:

### Q-43 - The tool is meant to be application- and gateway-agnostic, but several parts are tied to Forgejo and Kong
- Status: open
- Goal (user, 2026-10-06): the tool must be agnostic with respect to the target API and the gateway.
- Known couplings (consolidates and extends Q-18 and Q-38):
  - [ ] Forgejo, code: `src/tests/helpers/auth_forgejo.py`, `forgejo_resources.py`; test 1.4 token paths and `token` auth scheme (`test_1_4_token_revocation.py:70-76`); test 7.2 `forgejo_webhook` mode and default body.
  - [ ] Forgejo, defaults: `credentials.auth_type` default `forgejo_token`; test 2.1 `admin_endpoint_paths` default `/api/v1/admin/users`; test 7.2 `injection_mode`, `injection_path_template`, `injection_body_template`; `config.yaml` `path_seed` and test 1.5 `http_probe_url` are lab values.
  - [ ] Kong, code: `KongGatewayAdapter` is the only adapter; tests 3.3, 4.2, 4.3, 6.4 (sub-test B) read Kong field names and `/status`; test 4.3 levels are designed around Kong OSS.
  - [ ] Kong, defaults: test 0.2 `gateway_server_identifiers`; test 6.4 `gateway_block_body_fragment` ("no Route matched with those values").
  - [ ] Silent false results instead of an explicit "not applicable": 2.1 PASS on a target where the configured admin path does not exist (observed on cRAPI, 2026-10-06); 1.4 ERROR on a non-Forgejo target.
- Question: For each item decide: (a) move to configuration with a neutral default, (b) keep behind an adapter/strategy selected by `config.yaml`, (c) return SKIP "not applicable to this target" when the precondition does not hold. Which items block the production integration?
- How to verify: decision with user; re-run on cRAPI (`config_crapi.yaml`) as a second target.
- Resolution:

### Q-44 - A run looks stuck, and interrupting it discards everything
- Status: open
- Evidence (2026-10-06): during the author's first run from a fresh clone, the run was stopped by hand with Ctrl+C because it seemed to hang; `outputs/` then contained only `evidence_tmp/` (14 `.jsonl` files, no report). In my own runs the console stayed for minutes on the external-tool tests (nuclei, testssl, sslyze) with no progress indication.
- Source: reports are written only in Phase 7 (`src/engine.py`); Ctrl+C ends the run with exit 130 and skips Phase 7 (`docs/reference/exit-codes.md`).
- Question: Add progress output (current test, elapsed time, expected duration) and/or write partial reports on interruption? Meanwhile `first-assessment.md` tells users to wait and not to interrupt.
- How to verify: decision with user (code change).
- Resolution:

### Q-45 - `execution.test_ids` with only native IDs also runs every enabled external test
- Status: verified
- Source: `src/engine.py:595-650` splits `test_ids` into native and `ext.` IDs. If the native subset is empty the engine schedules no native test (`test_registry_skipped_all_ids_are_external`); if the external subset is empty it is passed to `ExternalTestRegistry` as "no filter" (`if allowed_ids:` in `src/external_tests/registry.py`). The two cases are handled asymmetrically.
- Evidence (2026-10-06): `test_ids: ["1.1", "1.4", "2.1", "7.2"]` also ran `ext.0.1.nuclei`, `ext.1.5.sslyze`, `ext.1.5.testssl`. Correction (2026-10-06, verified): a list with only `ext.*` IDs does **not** run native tests (`test_ids: ["ext.1.5.sslyze"]` → only `ext.1.5.sslyze`, log `test_registry_skipped_all_ids_are_external`); the earlier statement was an inference, now removed from the docs. Only the native-only case leaks.
- Question: Should a non-empty `test_ids` run exactly the listed tests (fix), or is the current behaviour intended? `docs/reference/configuration.md` now documents the current behaviour.
- Resolution:

### Q-47 - Test 1.1 reports anonymous reads of public data as authentication bypass
- Status: open
- Source: test 1.1 (`src/tests/domain_1/test_1_1_authentication_required.py`, oracle in `docs/tests/domain-1/1-1-authentication-required.md`): an endpoint is "protected" if the spec declares a `security` requirement; any `2xx` without credentials is `AUTH_BYPASS` → Finding.
- Evidence (2026-10-06, fresh lab, test 1.1 only, run by the owner): the Forgejo spec declares security on every operation (`attack_surface_build_completed public_endpoints=0`), but Forgejo serves public data to anonymous users by design. 78 findings, all anonymous `GET` with `200`: e.g. `/version`, `/licenses`, `/settings/ui`, `/users/search`, public repository contents, issue 1, tag, organization. None is a write.
- Question: keep these as FAIL (the spec promises a protection the server does not apply), or distinguish them in the report (e.g. a separate state or InfoNote for anonymous reads), so that an analyst does not read 78 critical violations where there is a spec inaccuracy?
- Resolution:

### Q-48 - `config_coherence_warning` messages confuse priority and strategy
- Status: open
- Source: `src/config/loader.py` (warnings `white_box_without_admin_api`, `grey_box_without_credentials`).
- Evidence (2026-10-06, `apiguard validate-config` on a minimal configuration): the messages say "All P3 (WHITE_BOX) tests will return SKIP with reason 'Admin API not configured'" and "All P1/P2 (GREY_BOX) tests will return SKIP". Priority and strategy are independent (`docs/architecture/assessment-model.md`): 4.2 and 4.3 are P1 WHITE_BOX, 7.2 is P0 GREY_BOX; WHITE_BOX tests 1.5, 1.6, 6.2 and 6.4 (sub-test A) run without the Admin API (verified: same minimal run, 1.5 FAIL, 6.2 and 6.4 PASS). The real skip reason is also different: "Gateway adapter not configured: ...".
- Question: rewrite the two messages (strategy only, list the affected tests or point to the docs)? Note: priority and strategy are independent (owner decision on the former Q-14, 2026-10-06); the messages must not link them.
- Resolution:

### Q-50 - Some findings have no `evidence_ref`
- Status: open
- Source: `src/tests/domain_4/test_4_1_rate_limiting.py` (findings built with `evidence_ref=None`), `src/tests/domain_7/test_7_2_ssrf_prevention.py` (one aggregate finding); `docs/architecture/assessment-model.md` says a Finding of an HTTP test has an `evidence_ref` to the proving transaction.
- Evidence (2026-10-06, lab, native tests only): 0.1 (16), 0.2 (1), 1.1 (78) findings all have an `evidence_ref` that resolves in `evidence.json`. 4.1: 2 findings, no `evidence_ref`, no transaction marked `is_fail_evidence` (300 `PROBE_HIT`), nothing in `evidence.json`. 7.2: 1 aggregate finding ("58 SSRF payload(s) produced an unblocked response") with no `evidence_ref`; the 58 transactions are marked `is_fail_evidence` and are in `evidence.json` (`7.2_001`...).
- Question: should every finding point to evidence (4.1: e.g. the last request without `429`; 7.2: one finding per payload or a list of refs), or is "the transaction log is the evidence" acceptable for aggregate findings? Until decided, `guides/usage/read-the-report.md` tells the reader to use the transaction log for these tests.
- Resolution:

### Q-51 - E2E test suite against the lab
- Status: open (decided in principle, to be planned)
- Source: decision on the former Q-12 (owner, 2026-10-06). The tool has no automated tests (`pyproject.toml` `[tool.pytest.ini_options] testpaths = []`, no test files); `docs/project/claude-rules.it.md` §5.6 planned a `tests_e2e/` suite against the real lab, never built. The dev environment installs `pytest`, `pytest-asyncio` and `pytest-httpx`, all unused; `pytest-httpx` mocks HTTP, which the project rules forbid.
- Evidence (2026-10-06): the lab created from scratch gives identical results on every run (test 1.1: `AUTH_BYPASS` 78, `INCONCLUSIVE_PARAMETRIC` 63, `ENFORCED` 311 in two independent fresh labs), so expected outcomes can be written down and compared automatically.
- Question: build the suite as pytest (run the tool on the lab, assert per-test status, finding counts, no ERROR) or as a lighter expected-results file plus a comparison script? Where are the expected values stored, and how are they updated when the lab changes? Remove `pytest-httpx` at the same time. Planned together with CI (Q-16).
- Resolution:

### Q-52 - Second official lab: cRAPI
- Status: open (decided in principle by the owner, 2026-10-06; to be planned)
- Source: former Q-03. The reference lab is Forgejo + Kong; a second target is needed to show that the tool works on another API (Q-43, Q-18) and later for the E2E suite (Q-51).
- Evidence (2026-10-06): upstream `VERSION` file in the owner's clone: `1.1.5`. `config_crapi.yaml` is tracked but points to `./specs/crapi-openapi.json`, and `specs/` is ignored by git (`.gitignore:16`): a fresh clone has the configuration without the specification (the run stops with exit 10). cRAPI itself is not in the repository (owner's local clone `../crAPI-main`); its licence is Apache 2.0 (`LICENSE.md`), its services are published images (`crapi/crapi-identity`, `crapi-community`, `crapi-workshop`, `crapi-web`, `crapi-chatbot`, `gateway-service`, `mailhog`) tagged `${VERSION:-latest}` in the upstream `deploy/docker/docker-compose.yml`, plus `postgres:14`, `mongo:4.4`, `chromadb/chroma:latest`. The run recorded in Q-18 used cRAPI without a gateway; the web service also needed `crapi-chatbot`.
- Proposal: `test-environments/crapi-kong/` with its own compose using the upstream images pinned to exact versions, cRAPI behind Kong (so the gateway-audit tests also run on the second target), the specification committed in the lab folder with attribution, a setup container that registers the users from the `CRAPI_*` variables in `.env`, `config_crapi.yaml` updated, a documentation section for the second lab.
- To decide: behind Kong or without a gateway; ports (the two labs both use 8000/8001/8443: one lab at a time, or separate ports for cRAPI); whether the chatbot service is required and what it needs.
- Resolution:

### Q-53 - Every test parameter is defined twice (configuration model and runtime model)
- Status: open (direction agreed with the owner, 2026-10-06; to be done after Q-51)
- Source: per parameter, a configuration model in `src/config/schema/domain_X.py` (validates `config.yaml`), a runtime copy in `src/core/models/runtime.py` (1084 lines, `RuntimeTest*Config`, what the test reads through `target.tests_config`), and one copy line in `src/engine.py` Phase 3 (48 `config.tests.domain_...` lines). Reason given in the `runtime.py` header: tests may import only `core/`, not `config/`.
- Evidence (2026-10-06, `max_endpoints_cap` of test 1.1): the configuration model uses named constants (`TEST_11_MAX_ENDPOINTS_CAP_DEFAULT`, `_MIN`, `domain_1.py:119`), the runtime copy rewrites `default=0, ge=0` by hand (`runtime.py:238`) and its description cites `TestDomain1Config` and `config/schema.py` (the class is `Test11Config`, the file no longer exists). Values agree today; the copies can drift silently.
- Precedent in the code: external-tool configuration models live in `src/core/models/external_tools.py` and `src/config/schema/external_tools.py` only re-exports them: one definition, dependency rule respected.
- Proposal: do the same for native tests: move the per-test configuration models to `core/`, let tests read them directly, remove the `RuntimeTest*Config` copies and the copy lines in `engine.py`. Refactoring of the 13 tests with parameters: verify every test on the lab before and after (needs the E2E suite, Q-51). Implement Q-37 at the same time.
- Resolution:

### Q-54 - `.env` is not found when the tool is installed with pip
- Status: verified (bug)
- Source: `src/cli.py:59` `load_dotenv(override=False)` without a path. python-dotenv `find_dotenv()` (`dotenv/main.py:361-370`) starts from the folder of the calling file, not from the current working directory, unless `usecwd=True`.
- Evidence (2026-10-06): same repository folder, same `.env`, same configuration. Hatch environment (editable install, code inside the repository): `.env` found, run completes. Fresh venvs with `pip install ".[sslyze]"` on Python 3.11, 3.13, 3.14 (code in `site-packages`): `validate-config` and `run` exit 10, `Environment variable(s) not set: ADMIN_PASSWORD, ADMIN_USERNAME, ...`. With the variables exported in the shell, the same venvs work.
- Impact: the integration path (`pip install` into another product) never reads `.env`; the docs said "`.env` from the working directory" (corrected on 2026-10-06 in `reference/cli.md`, `reference/configuration.md`, `architecture/security-model.md` to describe the real behaviour).
- Question: load `.env` from the working directory (`load_dotenv(find_dotenv(usecwd=True), override=False)`), add an explicit option (e.g. `--env-file`), or rely only on exported variables when installed? Belongs to the integration contract (Q-25 block).
- Resolution:

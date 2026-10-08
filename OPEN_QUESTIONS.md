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
- Status: decided in principle (owner, 2026-10-06); detailed per-test review and implementation in the code phase
- Source: `src/engine.py:646-651` (external discovery receives `min_priority` and `allowed_ids`, not `strategies`); `src/external_tests/registry.py:374-417` (filters: allowed_ids, priority, per-tool enabled)
- Question: With `strategies: [BLACK_BOX]`, `ext.1.5.testssl` and `ext.1.5.sslyze` (WHITE_BOX) still run. Intended (external tests filtered only by `external_tools.*.enabled`) or a bug? The docs must state the real rule.
- How to verify: decision with user; optional confirmation run with `strategies: [BLACK_BOX]` against the lab target.
- Evidence (2026-10-06): the native registry already filters by `execution.strategies` (normal mode; ignored when `test_ids` is set); the external registry filters only by priority, `test_ids` and tool enablement (`src/external_tests/registry.py:374-417`). The code defines WHITE_BOX as "read access to gateway configuration via Admin API" (`src/core/models/enums.py:39`), but 1.5, 1.6, 6.2, `ext.1.5.testssl`, `ext.1.5.sslyze` are WHITE_BOX and need only network access; 6.4 needs the Admin API only for sub-test B. GREY_BOX is defined as "tokens for at least two distinct roles", but 1.4 uses only admin and 2.1, 7.2 only `user_a`. With `strategies: [BLACK_BOX]` the native 1.5, 1.6, 6.2 are excluded although they could run, while the external TLS tests run anyway.
- Decision (owner, 2026-10-06): the strategy states what the tester has. BLACK_BOX = an external user (network only, no credentials); GREY_BOX = a normal user (credentials of an account; how many accounts is not the point); WHITE_BOX = a super user (internal access: gateway configuration, files, internal systems). Labels must state the truth and the filter must apply to every test, external ones included.
- To do in the code phase, carefully, test by test (owner: not now): review the label of every test against the definitions (first candidates: 1.5, 1.6, 6.2, `ext.1.5.testssl`, `ext.1.5.sslyze` to BLACK_BOX; 6.4 to be decided); update the definitions in `enums.py`; make the external registry respect `execution.strategies`; update the docs together with the code (test catalogue, test pages, `assessment-model.md`, `configure-a-target.md`, `select-tests.md`). The strategy is a report field: part of the "contract 1.0" block. Methodology alignment: Q-33.
- Resolution:

### Q-11 - sslyze AGPL licence vs production integration
- Status: deferred (owner, 2026-10-07): waiting for information on how the product will be distributed
- Source: `pyproject.toml` optional dependency `sslyze` (comment: "for SaaS distribution, this extra must be removed or replaced")
- Question: The tool will be embedded in another product. Is the `[sslyze]` extra acceptable there, or must docs mark `ext.1.5.sslyze` as research-only?
- How to verify: decision with user (licensing, not code).
- Evidence (2026-10-07, installed packages): sslyze 6.3.1 and its dependency `nassl` are AGPL v3 and are imported as a library in the tool's process; testssl.sh is GPL v2 and nuclei MIT, both run as separate programs. sslyze is already an optional extra (`[sslyze]`), included by default only in the Hatch environment; without it `ext.1.5.sslyze` is SKIP and guarantee 1.5 stays covered by `ext.1.5.testssl` (on the lab both found TLS issues: sslyze 1 finding, testssl 3). The tool's own licence is undecided (Q-05).
- Owner (2026-10-07): the distribution model of the product (internal use, distributed to customers, online service) is not known yet; the owner will ask. Interim: sslyze stays an optional extra; the integration guide (step 2.2) must say not to install `[sslyze]` in a product until the licence is checked. Fallback if unclear: leave sslyze out (options otherwise: run sslyze as a separate program, or remove it). Decide together with Q-05.
- Resolution:

### Q-13 - Existing `hatch run dev:docs` script
- Status: deferred to block 9 with Q-04 (owner, 2026-10-07)
- Source: `pyproject.toml` `[tool.hatch.envs.dev.scripts] docs` (pydoc-markdown → `docs/API_REFERENCE.md`, file not present in repo)
- Question: Keep, remove, or replace it as part of Q-04?
- How to verify: decide together with Q-04.
- Evidence (2026-10-07): `hatch run dev:docs` works and writes `docs/API_REFERENCE.md` (about 80 KB, pydoc-markdown output of selected modules); the file is not kept in the repository (removed after the test). Owner: handle with Q-04 in block 9.
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
- Owner decision (2026-10-07): this is an analysis, not a decision: moved to group 3.D, agnosticism block, after the second lab (Q-52); feeds Q-43.
- Resolution:

### Q-20 - CLI usage errors share exit code 2 with "ERROR"
- Status: open
- Source: Typer/Click default; verified 2026-10-05: `apiguard run --bogus`, `--log-format xml`, and `apiguard` without arguments all exit 2. `src/engine.py:131` uses 2 for "at least one test ERROR".
- Question: A wrapper cannot distinguish "bad invocation" from "assessment completed with ERROR". Map usage errors to a distinct code? Documented as-is in `docs/reference/exit-codes.md`.
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
- Status: sslyze part done (2026-10-07, block 2); `ssrf_request_timeout_ms` pending (7.2 review)
- Source: `external_tools.sslyze.extra_flags` (never read by `src/connectors/sslyze.py` or `ext_test_1_5_tls_analysis.py`); `tests.domain_7.test_7_2.ssrf_request_timeout_ms` (description: "reserved for future… currently the global execution.read_timeout governs all requests"; only passed through `src/engine.py:496`).
- Question: Remove, implement, or keep documented as no-op?
- How to verify: decision with user.
- Evidence (2026-10-07): `extra_flags` is read by the testssl and nuclei connectors (CLI tools); sslyze is a Python library with no command line, its `extra_flags` exists only because `SslyzeConfig` inherits `BaseExternalToolConfig` (`src/core/models/external_tools.py:212`) and `src/connectors/sslyze.py` never reads it. `ssrf_request_timeout_ms` is validated (`src/config/schema/domain_7.py:386`), copied to the runtime model (`src/engine.py:496`) and never read by test 7.2, which uses `execution.read_timeout` (default 30 s).
- Decision (owner, 2026-10-07): no configuration option without effect: implement it or remove it (removed keys must then be rejected, see Q-22). `external_tools.sslyze.extra_flags`: remove. `tests.domain_7.test_7_2.ssrf_request_timeout_ms`: decide implement vs remove during the review of test 7.2 (per-test quality review, Q-29/Q-32). Until then `docs/reference/configuration.md` documents both as without effect.
- Done (2026-10-07, block 2): `extra_flags` removed from `BaseExternalToolConfig`; it remains on `TestsslConfig` and `NucleiConfig` with the same defaults (they already declared it). A `sslyze.extra_flags` key in `config.yaml` is still accepted and ignored, as before, until unknown keys are rejected (Q-22). Docs updated (`reference/configuration.md`, `add-an-external-test.md`).
- Resolution:

### Q-25 - Stability policy for the integration interfaces
- Status: open
- Source: `docs/reference/compatibility.md` "Interface stability"; only `apiguard_report.json` has a version (`output_schema_version`, policy in `src/report/builder.py:322-327`).
- Question: The tool will be embedded in another product. Which interfaces are a stable contract (exit codes, report JSON, evidence JSON, config schema, CLI), how are breaking changes signalled (version field, CHANGELOG, major bump)?
- How to verify: decision with user; feeds `CHANGELOG.md` and `guides/integration/`.
- Evidence (2026-10-06, first superficial pass): only `apiguard_report.json` has a version (`output_schema_version: "1.0"`, policy in `src/report/builder.py:322-327`); `evidence.json`, exit codes, `config.yaml`, CLI have none. Known defects whose fix changes what an integrator sees: Q-20 (usage errors exit 2), Q-22 (unknown config keys ignored), Q-23 (`generated_at_utc` not UTC), Q-45 (`test_ids` selection), Q-50 (findings without `evidence_ref`); Q-31 may change the report too (Q-47 closed on 2026-10-07 without report change).
- Draft only, NOT decided (to be reviewed in depth in group 3.D): stable interfaces = exit codes, report JSON, `evidence.json` (add a version field), CLI commands and options, documented `config.yaml` keys; not contract = log events, Python modules, message texts, `oracle_state` values; signalling = per-file format version (major = breaking), "Breaking changes" section in `CHANGELOG.md`, semver from 1.0.0; fix the defects above together, then declare 1.0.0.
- Owner decision (2026-10-06): not settled now. The question touches code that belongs to the code phase; it was only looked at superficially. Moved to 3.D as the first block of the code phase ("contract 1.0"), to be reviewed in depth there, after the 3.C decisions that may change the report (Q-31; Q-47 closed without change).
- Resolution:

### Q-26 - Schema descriptions say "SKIP" for disabled external tools; the registry excludes them
- Status: descriptions fixed (2026-10-07, block 2); "not run by choice" list pending (contract 1.0 block)
- Source: `src/core/models/external_tools.py` (`enabled` description: "When False, all tests for this tool return SKIP"), `ToolConfig.external_tools` description in `src/config/schema/tool_config.py`; actual behaviour in `src/external_tests/registry.py:88-104, 405-440` (master switch → `[]`; per-tool disabled → filtered out). Consistent with `outputs/crapi/` (no `external_tools` section → no `ext.*` rows).
- Question: Fix the descriptions (code comments) or change behaviour so that disabled tools appear as SKIP in the report (visible coverage gap)? Docs describe the actual behaviour.
- How to verify: decision with user.
- Evidence (2026-10-07): the descriptions still say SKIP (`src/core/models/external_tools.py:64`, `:257`; `src/config/schema/tool_config.py:863`); the registry excludes the tests; `docs/reference/configuration.md` already describes the real behaviour.
- Decision (owner, 2026-10-07): keep the rule "absent = not selected (operator's choice: priority, strategy, `test_ids`, tool disabled); SKIP = selected but something is missing (credentials, Admin API, tool not installed)". SKIP must never be used for a deliberate exclusion. Disabled tools stay absent; fix the three descriptions (cleanup block).
- Also agreed (to evaluate in the contract 1.0 block): make deliberate exclusions visible, listing every test not run by choice, native and external, with the reason, separately from the SKIPs, in **every** output (HTML report, `apiguard_report.json`, console summary, and any other artefact), not only in the HTML report.
- Done (2026-10-07, block 2): the three descriptions now say that disabled tools are not scheduled and do not appear in the report (`src/core/models/external_tools.py`, `src/config/schema/tool_config.py`, which also listed "ffuf" instead of sslyze).
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
  - [ ] 0.1 - the undeclared-method sub-check samples the first `method_probe_sample_size` endpoints (default 10) and then skips the parametric ones: on the Forgejo spec only 3 of the first 10 are non-parametric, so only 3 endpoints are probed (10 requests). Sampling only non-parametric endpoints would cover more (verified 2026-10-07: sample 1 → 41 requests, 3 and 10 → 49).
  - [ ] 1.1 - idea (owner, 2026-10-07, on the former Q-47): state in the test message how many findings are reads and how many are writes (e.g. "78 findings: 78 GET, 0 writes"); text only, no new severity level.
  - [ ] 1.5 - any exception during the HTTP probe counts as "HTTP not served" (`test_1_5_insecure_credential_transport.py`, `except Exception: return None`).
  - [ ] 0.3 - an unparseable `Sunset` header is treated as compliant.
  - [ ] 3.3 - only the first plugin matching `plugin_names` is audited; if it is disabled the test SKIPs even when another instance is enabled.
  - [ ] 4.1 - one probe endpoint only; budget fixed by `max_requests`, not derived from the documented limit.
  - [ ] 4.3 - Level 2 passes if at least one upstream has a valid passive health check (others may have none); on FAIL the observability InfoNote is converted into a Finding and counted.
  - [ ] 6.2 - HSTS without `includeSubDomains` is only logged at debug level, no finding (the old docstring said it was required; aligned to the code in block 2).
  - [ ] 6.2 - `X-Frame-Options` accepts any value except `ALLOW-FROM`; `Permissions-Policy` content not evaluated.
  - [ ] 7.2 - only `200`/`201` count as accepted (`_ACCEPTED_STATUS_CODES`); acceptance of the URL is checked, not an actual outbound request.
  - [ ] ext.0.1.nuclei - results on other services of the target host are reported (2026-10-06, lab: `ssh-sha1-hmac-algo` on `localhost:22`, the owner's VM SSH, not the API); severity info, so InfoNote only, but out of scope for an API assessment.
  - [ ] 7.2 - FAIL carries a single consolidated Finding; per-payload detail only in the transaction log and `evidence.json` (`test_7_2_ssrf_prevention.py:402-427`).
- How to verify: decision per item; tests pages "Limitations" sections list the same points.
- Evidence (2026-10-06): 2.1 on cRAPI returned PASS with the Forgejo default `admin_endpoint_paths`, a path that does not exist there.
- Resolution:

### Q-30 - Side effects on the target
- Status: decided (owner, 2026-10-07); code items in the code phase
- Question: Acceptable for a production assessment tool? Should they be documented in a "safety" page, made opt-in, or changed?
  - [ ] 1.1 sends `POST`/`PUT`/`PATCH` with `{}` and parametric `DELETE` without credentials to every protected endpoint; with real IDs in `target.path_seed` the `DELETE` targets real resources.
  - [ ] 0.1 sends undeclared `POST`/`PUT`/`PATCH`/`DELETE` without credentials to up to 10 documented paths.
  - [ ] 0.3 sends each deprecated endpoint's declared method (possibly `POST`/`DELETE`) without credentials.
  - [ ] 7.2 `fixed_path` mode registers nothing for teardown: accepted payloads may leave persistent objects. `forgejo_webhook` mode creates a repository and up to 73 inactive webhooks (removed by teardown).
  - [ ] 1.4 creates and deletes an API token on the admin account.
  - [ ] 4.1 sends up to 2 × `max_requests` requests in a burst and exhausts the tool's rate-limit budget for the following tests.
- How to verify: decision with user.
- Evidence (2026-10-07): Phase 6 teardown works for what the tool creates (1.4 token, `context.register_resource_for_teardown`, `test_1_4:329`; 7.2 `forgejo_webhook` repository); 7.2 `fixed_path` registers nothing. Test 1.1 docstring (`:45-50`) says parametric `DELETE` uses the placeholder `apiguard-probe`; the code uses `path_seed` first: in the last lab run 76 unauthenticated `DELETE`, none with `apiguard-probe`, including `/admin/users/user-a`, `/orgs/test-org`, `/repos/user-a/test-repo` (all 401). Placeholder vs real resource on the lab: `DELETE /repos/apiguard-probe/apiguard-probe` 404 (inconclusive) vs `/repos/user-a/test-repo` 401 (conclusive); same for `/orgs`, comments. In the Forgejo spec 35 of 44 path parameters appear in writes or `DELETE` (`owner`, `repo` in 49 `DELETE` endpoints each): no useful read-only subset.
- Decision (owner, 2026-10-07): keep the behaviour. `path_seed` is the operator's declaration of test resources that may receive any request, `DELETE` and unauthenticated writes included: only volatile test resources, never real ones. Say it everywhere `path_seed` appears (done 2026-10-07: `reference/configuration.md`, test 1.1 page, `configure-a-target.md`; code phase: `generate-seed` template, comment above `path_seed` in `config.yaml`, test 1.1 docstring, done in block 2). After a successful unauthenticated `DELETE` the tool does not restore the resource (it cannot recreate what it did not create: creation endpoint unknown, server-assigned identifiers change, content and cascades are lost); restoring is the environment's job (lab: full reset, `down -v` then start and setup; setup alone gives new numbers). Code phase, test 1.1 review: send `DELETE` last; after the test, check that the `path_seed` resources still exist and report any deleted one, marking later results that depend on it. Test 7.2 `fixed_path` (creates objects with valid credentials, no cleanup): test 7.2 review, rule "who creates cleans up, or declares in the report what was left".
- Resolution:

### Q-31 - Sensitive data in the outputs
- Status: decided in principle (owner, 2026-10-07); implementation in the code phase (contract 1.0 block)
- Source: `src/core/models/http.py:150-157` (only `authorization` redacted); `src/core/client.py:562-578` (bodies stored as sent/received); test 6.4 quotes matched secrets in finding details.
- Question: Cookies, custom API-key headers, request and response bodies and secrets found by 6.4 are written to `evidence.json` and `apiguard_report.json`. Redact more (which headers/fields), or document the outputs as sensitive (current state in `docs/reference/evidence-format.md`)?
- How to verify: decision with user.
- Evidence (2026-10-07, lab run, `evidence.json` + `apiguard_report.json`): `authorization` is `[REDACTED]` everywhere (but the placeholder does not say which credential was used); no cookies on the lab; in clear: the full API token created by test 1.4 (`"sha1":"..."` in the response of `POST /users/<admin>/tokens`, in both files; harmless on the lab because the test deletes it, a valid admin token if the run stops before deletion), the random webhook secret of 7.2 payloads, response bodies (lab data; personal data on a real target).
- Decision (owner, 2026-10-07): evidence must stay full of meaning. Redact only secret **values**, never what proves a finding, and keep the meaning with typed placeholders: `Authorization` → `[REDACTED: <role> token]` (today the role is lost); `Cookie`/`Set-Cookie` → value redacted, attributes kept (`Secure`, `HttpOnly`, `SameSite`: what test 1.6 judges); token created by 1.4 → fingerprint kept (last characters or hash) so that the create / delete / reuse requests can be correlated; tool-generated secrets (7.2 webhook secret) → redacted. Response bodies are not redacted (they are often the proof itself, e.g. 6.4); the outputs stay documented as sensitive. No "raw evidence" mode for now (it would be a new config parameter).
- Requirement (owner): every redaction must be justified and checked one by one: for each field, state why the value is not needed as proof and verify on the lab, before and after, that every finding keeps its evidence and its meaning.
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
  - [ ] Strategy definitions (owner decision on Q-10, 2026-10-06): BLACK_BOX = external user, GREY_BOX = normal user with credentials, WHITE_BOX = super user with internal access. Align the "Assunzioni e Prerequisiti" approach of **every** guarantee to them, implemented or not; checks the tool performs from outside (TLS, headers, cookies) are not "White Box configuration audit".
  - [ ] `docs/knowledge/design-properties.it.md` D3.P1 and D6.P3 cite `src/core/models/runtime.py` (`RuntimeTest*Config`, "mirror immutabile") and `src/config/schema/domain_N.py`: since block 4 (Q-53) the per-test models live in `src/test_config/` (single definition, all frozen) and `RuntimeTestsConfig` in `src/test_config/runtime.py`. Update when translating.
- How to verify: decision with user while translating `knowledge/`.
- Resolution:

### Q-34 - Gateway Admin API: no authentication, TLS always verified
- Status: open
- Source: `src/core/gateway/kong.py:297-307` (`httpx.Client(timeout=…, follow_redirects=False)`, plain `GET`, no headers, httpx default `verify=True`); `target.verify_tls` is applied only to `base_url` (`src/engine.py` Phase 3).
- Question: Production Admin APIs are usually protected (Kong Enterprise RBAC token, mTLS, or a self-signed certificate on an internal network). Today the adapter cannot send credentials and cannot accept a self-signed Admin API certificate. Add `target.admin_api_*` auth/TLS options?
- How to verify: decision with user (code + config change).
- Resolution:

### Q-37 - Convention "every test has a config model" vs code
- Status: implemented (2026-10-07, block 4), awaiting the owner to close
- Source: previous `ADDING_tests.md` ("When the test has no operator-tunable parameters: create the config model anyway"; git `fd3bd90:docs/guides/extending/add-a-native-test.md:236-241`); code: no `Test01Config`/`Test03Config` and no `RuntimeTest01Config`/`RuntimeTest03Config` (13 runtime configs for 15 native tests). Also the old guide said a missing `src/config/schema/__init__.py` export raises `ImportError`; nothing imports `Test*Config` from that package (`tests_config.py` imports domain modules directly).
- Question: Keep the convention (add empty models for 0.1, 0.3) or drop it? The new guide documents the code as it is.
- How to verify: decision with user.
- Evidence (2026-10-06): test 0.1 does have a tunable written in the code: `list(surface.endpoints)[:10]` (`src/tests/domain_0/test_0_1_shadow_api_discovery.py:172`, the "first 10 endpoints" of the undeclared-method sub-check), a magic number under the project rules; its wordlist (`SHADOW_API_WORDLIST`) is also fixed in code. Test 0.3 has only protocol constants (410, `Sunset`).
- Decision (owner, 2026-10-06): every native test always has its configuration model, empty if it has no parameters. A missing model is a developer error: it is checked in `hatch run dev:check` (not at runtime, never shown to the end user).
- To implement: models for 0.1 and 0.3; the check in `dev:check`; update `add-a-native-test.md` (remove the "no parameters" special case). Still to decide: the `10` of test 0.1 becomes a `config.yaml` parameter (needs owner confirmation) or a named constant. Implement together with Q-53, so that the new models already use the single definition.
- Decision update (owner, 2026-10-07): no check script. Instead the engine wiring becomes automatic: `RuntimeTestsConfig.from_domains(config.tests)` collects every `test_<D>_<N>` from the domain containers by name; `RuntimeTestsConfig` forbids unknown fields and `from_domains` fails if a field has no matching domain model, so a missing or extra piece stops the run at the first start (developer-visible) instead of silently using defaults. The convention "every native test has a model, even empty" is stated in the guide. The `10` of test 0.1 becomes the parameter `tests.domain_0.test_0_1.method_probe_sample_size` (default 10; owner confirmation 2026-10-07); test 0.3 gets an empty model.
- Implemented (2026-10-07): `RuntimeTestsConfig.from_domains()` (extra fields forbidden, missing domain models rejected) replaces the 13 wiring lines in `engine.py`; `Test01Config` (`method_probe_sample_size`, 1-100, default 10) and empty `Test03Config` added; test 0.1 reads the parameter. Verified: old 48 parameters identical; both mismatch cases stop (simulated, and in a real run before the runtime fields were added: exit 10 naming `test_0_1`, `test_0_3`); test 0.1 identical with the default (16 findings, 49 requests), 41 requests with 1; 0 and 101 rejected by `validate-config`; `dev:check`. Docs: guide (7 steps, no engine step), data-model, configuration reference, 0.1 test page, `config.yaml` block, CHANGELOG.
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
  - [ ] The dependency rule (`core/` ← `connectors/` ← `tests/`, `external_tests/` ← `engine.py`) is not checked automatically; owner decision (2026-10-06, layering import question; done in block 1): add a check (e.g. `import-linter`) to `dev:check`.
  - [ ] `pyproject.toml` excludes `scripts/` from ruff (`[tool.ruff] exclude`, line 375) but defines `per-file-ignores` for `scripts/*` (line 384): the ignores never apply. Harmless; decide whether `scripts/` should be linted.
  - [ ] ruff 0.16 also formats Python code blocks inside Markdown files (`ruff format --check .` reports `add-a-native-test.md`, `add-an-external-test.md`): exclude `*.md` from the formatter (owner decision 2026-10-07, block 1).
  - [ ] `hatch run dev:check` passes (ruff check, mypy strict, bandit medium, vulture 80) as of 2026-10-05.
- How to verify: decision with user; `hatch run dev:ruff format --check .`.
- Done (2026-10-07, block 1 step 2): `ruff format` applied to the 7 Python files (syntax trees identical to the previous commit; 15 native tests and `ext.1.5.sslyze` give the same results on the lab); `ruff format --check .` added to `dev:check`; Markdown excluded from the formatter (`[tool.ruff.format] exclude = ["*.md"]`). Remaining items: rule exceptions, `scripts/` lint config, E2E reference (Q-51), layering check (done in block 1 step 3).
- Done (2026-10-07, block 1 step 4): the two exceptions written in `CLAUDE.md` and `coding-rules.md` (numbers in test module names; `TypedDict` only for raw external-tool output shapes and `**kwargs` bundles, the 4 current uses); the full dependency rule written in `CLAUDE.md`. Remaining items: `scripts/` lint configuration; `claude-rules.it.md` §5.6 E2E reference (Q-51).
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
- Owner decision (2026-10-07): not now. Expected values taken from today's output would only freeze current results (regression, not correctness), and block 6 will change them. Build the suite after the test quality review, with each expected result stating its basis: `lab-design` (justified by the lab configuration, e.g. 4.1 FAIL because `rate-limiting` is commented out in `kong.yml:36`; 6.2 PASS because Kong adds the headers and `KONG_HEADERS=off`; 1.5 PASS because port 8000 redirects with 301) or `observed`; ideally prove each test on a secure and a vulnerable lab variant. Meanwhile regressions are checked by comparing two reports with `scripts/compare_reports.py`.
- Resolution:

### Q-52 - Second official lab: cRAPI
- Status: open (decided in principle by the owner, 2026-10-06; to be planned)
- Source: former Q-03. The reference lab is Forgejo + Kong; a second target is needed to show that the tool works on another API (Q-43, Q-18) and later for the E2E suite (Q-51).
- Evidence (2026-10-06): upstream `VERSION` file in the owner's clone: `1.1.5`. `config_crapi.yaml` is tracked but points to `./specs/crapi-openapi.json`, and `specs/` is ignored by git (`.gitignore:16`): a fresh clone has the configuration without the specification (the run stops with exit 10). cRAPI itself is not in the repository (owner's local clone `../crAPI-main`); its licence is Apache 2.0 (`LICENSE.md`), its services are published images (`crapi/crapi-identity`, `crapi-community`, `crapi-workshop`, `crapi-web`, `crapi-chatbot`, `gateway-service`, `mailhog`) tagged `${VERSION:-latest}` in the upstream `deploy/docker/docker-compose.yml`, plus `postgres:14`, `mongo:4.4`, `chromadb/chroma:latest`. The run recorded in Q-18 used cRAPI without a gateway; the web service also needed `crapi-chatbot`.
- Proposal: `test-environments/crapi-kong/` with its own compose using the upstream images pinned to exact versions, cRAPI behind Kong (so the gateway-audit tests also run on the second target), the specification committed in the lab folder with attribution, a setup container that registers the users from the `CRAPI_*` variables in `.env`, `config_crapi.yaml` updated, a documentation section for the second lab.
- To decide: behind Kong or without a gateway; ports (the two labs both use 8000/8001/8443: one lab at a time, or separate ports for cRAPI); whether the chatbot service is required and what it needs.
- Resolution:

### Q-53 - Every test parameter is defined twice (configuration model and runtime model)
- Status: implemented (2026-10-07, block 4), awaiting the owner to close
- Source: per parameter, a configuration model in `src/config/schema/domain_X.py` (validates `config.yaml`), a runtime copy in `src/core/models/runtime.py` (1084 lines, `RuntimeTest*Config`, what the test reads through `target.tests_config`), and one copy line in `src/engine.py` Phase 3 (48 `config.tests.domain_...` lines). Reason given in the `runtime.py` header: tests may import only `core/`, not `config/`.
- Evidence (2026-10-06, `max_endpoints_cap` of test 1.1): the configuration model uses named constants (`TEST_11_MAX_ENDPOINTS_CAP_DEFAULT`, `_MIN`, `domain_1.py:119`), the runtime copy rewrites `default=0, ge=0` by hand (`runtime.py:238`) and its description cites `TestDomain1Config` and `config/schema.py` (the class is `Test11Config`, the file no longer exists). Values agree today; the copies can drift silently.
- Precedent in the code: external-tool configuration models live in `src/core/models/external_tools.py` and `src/config/schema/external_tools.py` only re-exports them: one definition, dependency rule respected.
- Proposal: do the same for native tests: move the per-test configuration models to `core/`, let tests read them directly, remove the `RuntimeTest*Config` copies and the copy lines in `engine.py`. Refactoring of the 13 tests with parameters: verify every test on the lab before and after (needs the E2E suite, Q-51). Implement Q-37 at the same time.
- Evidence (2026-10-07, all 13 pairs compared by script): same field names, types and defaults; constraints differ in 5 tests (1.4 `token_name`, 2.1 `admin_endpoint_paths`, 4.1 `max_requests`/`request_interval_ms`, 7.2 `injection_mode`/`injection_path_template`/`injection_url_field`) and the 4.3 coherence validator exists only in the configuration model; `engine.py` copies values without transformations (only `list(...)`); tests read `target.tests_config.test_X_Y.<param>` (20 places), 3 tests use `RuntimeTest15/16/43Config` in signatures, 2 use `Any` (3.3, 4.2). The `domain_*.py` schema modules import only pydantic and stdlib.
- Decision (owner, 2026-10-07): option C. Keep one model per test in a dedicated package outside `core/` (e.g. `src/test_config/`): `core/` is the engine of the tool, test parameters belong to the tests. Rejected: models in `core/` (mixes test knowledge into the engine); models declared inside each test with validation after discovery (bigger change, not convincing now). External-tool configuration models to be moved to the same package later. Tests keep reading `target.tests_config.test_X_Y.<param>`.
- Decision (owner, 2026-10-07): `src/test_config/` is the lowest layer (it depends only on pydantic and imports nothing from the tool); `core/` imports it only to type `TargetContext.tests_config`. Rejected alternative: an untyped field plus a typed accessor in `test_config/` (core would know nothing, but every test access changes and typing goes through a runtime check). Documented in the dependency rule and checked by `import-linter`.
- Implemented (2026-10-07): `src/config/schema/domain_*.py` moved with `git mv` to `src/test_config/` (new package, lowest layer); `RuntimeTestsConfig` moved to `src/test_config/runtime.py`, its fields are the real models; `engine.py` passes `config.tests.domain_<D>.test_<D>_<N>` (13 lines instead of about 100 lines of copies); the 13 `RuntimeTest*Config` classes removed (`src/core/models/runtime.py` 1084 → 160 lines, only `RuntimeCredentials`); tests 1.5, 1.6, 4.3, 3.3, 4.2 typed with the real models (3.3 and 4.2 were `Any`; mypy finds no error). `import-linter`: `test_config` added as lowest layer plus a contract "imports nothing from the tool" (proved to catch a violation). Verified: the 48 parameters of the 13 tests identical before/after with `config.yaml` and with defaults; reassignment still blocked (`frozen`), list content mutable before and after (Q-57); `dev:check`; lab: 15 native tests and `ext.1.5.sslyze` unchanged; wheel contains `src/test_config/`. Docs updated: `add-a-native-test.md` (8 steps instead of 9), `data-model.md`, `overview.md` (import graph recomputed), `configuration.md`, `coding-rules.md`, `CLAUDE.md`.
- Resolution:

### Q-54 - `.env` is not found when the tool is installed with pip
- Status: verified (bug)
- Source: `src/cli.py:59` `load_dotenv(override=False)` without a path. python-dotenv `find_dotenv()` (`dotenv/main.py:361-370`) starts from the folder of the calling file, not from the current working directory, unless `usecwd=True`.
- Evidence (2026-10-06): same repository folder, same `.env`, same configuration. Hatch environment (editable install, code inside the repository): `.env` found, run completes. Fresh venvs with `pip install ".[sslyze]"` on Python 3.11, 3.13, 3.14 (code in `site-packages`): `validate-config` and `run` exit 10, `Environment variable(s) not set: ADMIN_PASSWORD, ADMIN_USERNAME, ...`. With the variables exported in the shell, the same venvs work.
- Impact: the integration path (`pip install` into another product) never reads `.env`; the docs said "`.env` from the working directory" (corrected on 2026-10-06 in `reference/cli.md`, `reference/configuration.md`, `architecture/security-model.md` to describe the real behaviour).
- Question: load `.env` from the working directory (`load_dotenv(find_dotenv(usecwd=True), override=False)`), add an explicit option (e.g. `--env-file`), or rely only on exported variables when installed? Belongs to the integration contract (Q-25 block).
- Resolution:

### Q-56 - How many steps does adding a native test require?
- Status: open (future, owner 2026-10-07)
- Source: discussion of Q-53. Even with one model per test (option C), adding a native test touches several places: the test module, its configuration model, the domain container, the `RuntimeTestsConfig` field, the commented block in `config.yaml`, the test page and catalogue row in `docs/tests/`, `reference/configuration.md`, the roadmap.
- Question: are all these steps necessary? Review them after block 4 and look for refactoring or simplification (e.g. generating the documentation rows from the code, Q-04; a test declaring its own model, option B of Q-53, if tests become plugins in the agnosticism work).
- Resolution:

### Q-57 - List parameters of the tests can be modified at runtime
- Status: open (safety check to do separately, owner 2026-10-07; keep as is for now)
- Source: per-test models in `src/test_config/` are `frozen` (a parameter cannot be reassigned), but list-valued parameters (e.g. `test_2_1.admin_endpoint_paths`, `test_0_2.gateway_server_identifiers`) are Python lists, so a test could append to or change them; the same object is shared by every test of the run.
- Evidence (2026-10-07, same check on the code before block 1 and after Q-53): reassigning a parameter or replacing a test's parameters is blocked (`ValidationError`) in both; appending to a list parameter is possible in both (before, the runtime copies also had list fields and one shared container). No test modifies a list parameter; nothing reads `config.tests` after Phase 3.
- Question: make list parameters tuples (fully immutable; `config.yaml` unchanged)? Check type by type and verify on the lab.
- Resolution:


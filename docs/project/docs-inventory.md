# Documentation Inventory - Mapping to Target Structure

Working document for the documentation restructuring. Not part of the final docs.
Every row maps a section of an existing file to a page of the target structure.
Every factual claim was checked against source code; results are in the per-document
"Verification log". Doubts that need a decision are tracked in `/OPEN_QUESTIONS.md`.

**Phase A move (2026-10-05).** The inventory below was written against the old paths; files were then
moved with `git mv` (content unchanged, so all line numbers below remain valid):

| Old path | New path |
|---|---|
| `docs/pub/ARCHITECTURE.md` | `docs/architecture/overview.md` |
| `docs/pub/ADDING_tests.md` | `docs/guides/extending/add-a-native-test.md` |
| `docs/pub/ADDING_external_tests.md` | `docs/guides/extending/add-an-external-test.md` |
| `docs/priv/PROJECT_status.md` | `docs/project/roadmap.md` |
| `docs/priv/AUDIT_milestone1_release.md` | `docs/project/audits/2026-05-18-v0.1.0-release.it.md` (verbatim, historical) |
| `docs/priv/LOCAL_commands.md` | `docs/project/maintainer-commands.md` |
| `docs/priv/DOCS_inventory.md` | `docs/project/docs-inventory.md` (this file) |
| `docs/priv/apiguard_property.md` | `docs/knowledge/design-properties.it.md` |
| `docs/priv/TOOLS_catalog.md` | `docs/knowledge/tools/catalog.it.md` |
| `docs/priv/TOOLS_decisions.md` | `docs/knowledge/tools/decisions.it.md` |
| `docs/priv/knowledge/2-Background_compact.md` | `docs/knowledge/background/state-of-the-art-compact.it.md` |
| `docs/priv/knowledge/2-Background_extensive.md` | `docs/knowledge/background/archive/state-of-the-art-extensive.it.md` |
| `docs/priv/knowledge/3-Metodologia.md` | `docs/knowledge/methodology/methodology.it.md` |
| `docs/priv/knowledge/4-Implementazione.md` | `docs/knowledge/archive/implementation-chapter.it.md` |
| `docs/priv/knowledge/5-Scenario-test.md` | `docs/knowledge/target-selection.it.md` |
| `docs/priv/knowledge/RULES_claude.md` | `docs/project/claude-rules.it.md` |

Exceptions to "content unchanged": path references were updated, the repository tree (§9) and packaging
text (§10) of `architecture/overview.md` now describe the new `docs/` layout. `src/` comments still use old
paths (Q-19).

**Phase B progress.** `reference/` and `tests/` written; `architecture/` written (2026-10-05) and
`architecture/overview.md` now holds the new English page. The original Italian ARCHITECTURE (sections 1-10,
including §7 contributor quick-reference used as a source for `guides/extending/`) is available with
`git show fd3bd90:docs/architecture/overview.md`.

**Legend - Content type:** tutorial · how-to · reference · explanation · research · status · personal
**Legend - Action:**
- `move` - content is correct, relocate (and translate to English if needed)
- `merge` - combine with other sources into the destination page
- `generate` - destination content should be produced from code (see Q-04)
- `rewrite` - topic is needed but current text is inaccurate or too thin
- `drop` - not carried over (reason given)

**Target structure (agreed 2026-10-05):**
```
README.md · CHANGELOG.md · CONTRIBUTING.md
docs/index.md
docs/getting-started/{installation, first-assessment}.md
docs/guides/usage/{configure-a-target, select-tests, read-the-report}.md
docs/guides/integration/{run-in-ci, consume-the-report, deployment-and-secrets}.md
docs/guides/extending/{add-a-native-test, add-an-external-test, add-a-gateway-adapter, coding-rules}.md
docs/tests/README.md + one page per test
docs/reference/{configuration, cli, report-schema, evidence-format, exit-codes, compatibility}.md
docs/architecture/{overview, data-model, assessment-model, security-model}.md
docs/knowledge/ (README, methodology/, tools/, background/, target-selection.md)
docs/project/ (roadmap.md, audits/)
```

---

## 1. README.md / README.en.md

`README.en.md` is a faithful translation of `README.md`: identical heading structure and identical
set of inline code tokens (verified with `diff`). Line numbers below refer to `README.md`;
the English text of `README.en.md` is the source for the move.

| Section | Lines | Type | Destination | Action | Claims to verify |
|---|---|---|---|---|---|
| Title + tagline + contributor pointer | 1-33 | explanation | `README.md` | rewrite | "8 domains, up to 29 guarantees" → consistent with ARCHITECTURE §4.1 catalogue (3+6+5+2+3+2+4+4 = 29); recheck against `knowledge/3-Metodologia.md` |
| Duplicate TOC ("Indice") | 35-57 | - | - | drop | Duplicate of the TOC at lines 5-24 |
| 1. Value and use cases | 60-75 | explanation | `README.md` (short "Why") | rewrite | "Integration via `apiguard_report.json`" ✔; "`--log-format json`" ✔ (`src/cli.py`) |
| 2. Requirements and installation | 77-135 | how-to | `getting-started/installation.md` | merge | Windows line (92) → Q-01; "3.11+" → Q-02; "cross-platform" (114) → Q-01; `hatch run dev:pytest -v` runs nothing → Q-12; static analysis commands → `guides/extending/coding-rules.md` |
| 3.1 `config.yaml` example | 141-232 | reference | `reference/configuration.md` (full) + `guides/usage/configure-a-target.md` (minimal annotated example) | generate + merge | Defaults verified ✔ (see log). Note: `verify_tls` default is `true`; example shows `false` with "lab only" comment |
| 3.2 `.env` secrets | 234-251 | how-to | `guides/usage/configure-a-target.md`; precedence rule → `guides/integration/deployment-and-secrets.md` | move | `load_dotenv(override=False)` ✔ `src/cli.py:59`; interpolation before YAML parse ✔ `src/config/loader.py:130-134`; `.env.example` exists ✔ but has no `CRAPI_*` vars used by `config_crapi.yaml` |
| 3.3 Validate configuration | 253-259 | how-to | `guides/usage/configure-a-target.md` + `reference/cli.md` | move | exit 0 / 10 ✔ `src/cli.py` (`typer.Exit(code=10)`) |
| 4. Run the assessment | 265-282 | how-to | `getting-started/first-assessment.md` + `reference/cli.md` | merge | Options `--config/-c`, `--log-format`, `--log-level`, `--banner/--no-banner` ✔ |
| 4. Generate `path_seed` | 284-299 | how-to | `guides/usage/configure-a-target.md` + `reference/cli.md` | move | `FILL_ME` ✔, default timeout 30 s ✔ `src/discovery/seed_generator.py:69`, `-o` ✔; `INCONCLUSIVE_PARAMETRIC` ✔ |
| 4. Select a subset of tests | 301-333 | how-to | `guides/usage/select-tests.md` | rewrite | `test_ids` overrides priority+strategy ✔ for native; **external tests ignore `strategies` entirely** → Q-10 |
| 4. CI/CD integration | 335-354 | how-to | `guides/integration/run-in-ci.md` | rewrite | Script has a defect: with `set -e` a non-zero exit of `apiguard run` terminates the script before `EXIT_CODE=$?`, so the `case` never runs for codes 1/2/10 - verified 2026-10-05 with a stub script returning 1: `case` not reached, script exits 1 |
| 5. Outputs (table) | 358-366 | reference | `reference/report-schema.md`, `reference/evidence-format.md`, `guides/usage/read-the-report.md` | rewrite | Three filenames ✔ `tool_config.py:112-114`; **missing**: `outputs/tools/` (raw external-tool artefacts, `engine.py:543`) and `evidence_tmp/` (crash artefact) |
| 5. `evidence.json` | 368-376 | reference | `reference/evidence-format.md` | rewrite | ✘ "array of EvidenceRecord" - real file is an object `{generated_at_utc, record_count, records[]}` (verified on `outputs/evidence.json`); 10,000-char truncation ✔ `http.py:66`; `record_id` format ✔ |
| 5. HTML report | 378-386 | explanation | `guides/usage/read-the-report.md` | move | `is_fail_evidence` ✔ `http.py:277`; content of template not yet checked against `src/report/templates/report.html` |
| 6. Pipeline overview | 390-422 | explanation | `architecture/overview.md` (short version also in `README.md`) | merge | ✘ "phases 1, 2 and 4 are blocking" - code: phases **1-4** blocking (`engine.py:215-221`) |
| 7. Domains table | 426-441 | reference | `tests/README.md` | generate | Test list ✔ (15 native + 3 external, counted from ClassVars); link to `docs/project/roadmap.md` → Q-08 |
| 7. Priority table | 443-448 | explanation | `architecture/assessment-model.md` | rewrite | "Typical strategy" column does not match implemented tests → Q-14 |
| 7. `min_priority` mapping | 450-459 | reference | `reference/configuration.md` + `guides/usage/select-tests.md` | move | ✔ `tool_config.py:637-643`; footnote on 7.2 (P0 + GREY_BOX) ✔ |
| 8. Exit codes | 463-472 | reference | `reference/exit-codes.md` | rewrite | 0/1/2/10 and FAIL > ERROR > CLEAN ✔ `results.py:380-391`; ✘ incomplete: exit 10 also on any unexpected engine exception (`engine.py:193-200`) |
| 9. Repository structure | 476-515 | reference | `architecture/overview.md` (single copy) | merge | Duplicate of ARCHITECTURE §9; keep one tree only |
| Alternative target - cRAPI | 519-528 | how-to | `getting-started/first-assessment.md` or `guides/usage/configure-a-target.md` (`jwt_login` example) | merge | Depends on Q-03 |

### Verification log - README

| Claim | Result | Evidence |
|---|---|---|
| `admin_connect_timeout_seconds` default 5, range 1-30 | ✔ | `tool_config.py:88-91` |
| `admin_read_timeout_seconds` default 10, range 1-60 | ✔ | `tool_config.py:88-93` |
| `auth_type` default `forgejo_token`; supported `forgejo_token`, `jwt_login` | ✔ | `tool_config.py:388`, `:510` |
| `username_body_field` default `username`, `password_body_field` default `password` | ✔ | `tool_config.py:472-484` |
| `token_response_path` default | ✔ (`access_token`; README example shows `token` for cRAPI, correct as override) | `tool_config.py:485-493` |
| Execution defaults: `min_priority` 3, connect 5, read 30, retries 3, OpenAPI fetch 60 | ✔ | `tool_config.py:60-111`, `:637-697` |
| `fail_fast`: "aborts on first FAIL of a P0 test" | ✘ triggers on **FAIL or ERROR** of a P0 test | `engine.py:859-875`; schema `tool_config.py:652-655` is correct |
| `test_ids` overrides priority and strategy filters | ✔ native; external: overrides priority (strategy never applied) | `tool_config.py:698-707`; `external_tests/registry.py:374-417` |
| Phases 1, 2, 4 blocking | ✘ phases 1-4 | `engine.py:215-221` |
| Exit 10 only for ConfigurationError/OpenAPILoadError/DAGCycleError | ✘ also any unexpected exception | `engine.py:193-200` |
| `evidence.json` is an array | ✘ object envelope | `outputs/evidence.json`; `evidence.py` `merge_and_finalize` |
| `apiguard_report.json` schema version | not documented; exists: `output_schema_version: "1.0"` | `report/builder.py:328` |
| `install_tools.sh` installs nuclei + testssl at pinned versions | ✔ testssl 3.2.3, nuclei 3.8.0; exits on non-Linux/macOS | `install_tools.sh:22,56,63-71` |

---

## 2. docs/architecture/overview.md

| Section | Lines | Type | Destination | Action | Claims to verify |
|---|---|---|---|---|---|
| Header + TOC + audience | 1-40 | - | - | drop | Replaced by `docs/index.md` |
| 1.1 API-agnostic philosophy | 46-50 | explanation | `architecture/overview.md` | move | Thesis-oriented sentence ("academic justification") → `knowledge/` or drop |
| 1.2 Split state and immutability | 52-54 | explanation | `architecture/overview.md` | move | `TargetContext` frozen ✔ (stated in CLAUDE.md; recheck `context.py` when writing) |
| 2. Dependency rules | 58-84 | explanation | `architecture/overview.md` + `guides/extending/coding-rules.md` | rewrite | ✘ diagram omits `connectors/`, `external_tests/`, `core/gateway/`; ✘ "`core/models/` imports only stdlib + pydantic" - `core/models/external_tools.py` imports `structlog`; `external_tests/registry.py:61` imports `src.config` → Q-15. Actual graph computed with `ast` (see log) |
| 3. Phases ↔ folders map | 88-139 | explanation | `architecture/overview.md` | merge | Omits `external_tests/`, `connectors/` in Phase 5 |
| 4. Detailed pipeline | 143-281 | explanation | `architecture/overview.md` | move | Phase 1-4 blocking ✔ (correct here, wrong in README); teardown codes {200, 204, 404} ✔ `engine.py:912`; fail-fast FAIL or ERROR ✔ |
| 4.1 Catalogue per domain (implemented + planned) | 285-377 | reference + status | implemented → `tests/<id>.md`; planned → `project/roadmap.md` | merge | Implemented entries cross-check with ClassVars ✔ (priority/strategy match); planned entries are roadmap, not product docs |
| 4.1 Dependency map | 379-417 | reference + status | `tests/README.md` (implemented, generated) + `project/roadmap.md` (planned) | generate + move | Implemented `depends_on` ✔ match ClassVars |
| 4.1 Execution batches | 419-445 | explanation | `architecture/overview.md` (DAG section) | rewrite | ✘ "external tests do not go through DAGScheduler" - they are merged with native tests and scheduled together (`engine.py:653-679`) |
| 4.1 Shared helpers map | 447-464 | reference | `guides/extending/add-a-native-test.md` | move | ✔ usage of `auth`, `forgejo_resources`, `path_resolver`, `response_inspector`, `target.gateway` verified with grep |
| Phase 2 - OpenAPI details | 468-474 | explanation | `architecture/overview.md` | move | prance exact pin to verify in `pyproject.toml` when writing |
| Phase 4 - registry R1-R3, stall detection | 478-488 | explanation | `architecture/overview.md` | move | - |
| Phase 5 - `execute()` contract | 492-501 | reference | `guides/extending/add-a-native-test.md` (single home; also in ADDING_tests) | merge | - |
| 5. Components (engine, client, evidence store, contexts) | 505-543 | explanation | `architecture/overview.md` (components) + `architecture/data-model.md` (contexts) | move | `run_id` format ✔ `engine.py:1072-1078`; retried exceptions ✔ `client.py:90-95`; `record_id` `{test_id}_{counter:03d}` ✔ |
| 6. Data model, three SSOT, memory hierarchy | 547-631 | explanation | `architecture/data-model.md` | move | Truncation 2,000 / 1,000 / 10,000 ✔ `http.py:66,183-184` |
| 6. Dual audit trail | 633-647 | explanation | `architecture/data-model.md` + `guides/usage/read-the-report.md` (user-level summary) | merge | - |
| 6. Model invariants | 649-657 | reference | `architecture/data-model.md` | move | Validators to recheck in `results.py` when writing |
| 6. Models catalogue | 659-689 | reference | `architecture/data-model.md` | generate | Candidate for generation from `src/core/models/__init__.py` |
| 7. Contributor quick-reference (BaseTest internals, guards, conventions) | 693-733 | how-to + reference | `guides/extending/add-a-native-test.md` | merge | Guards ✔ `base.py:668-757`; ✘ "canonical oracle states" lists 6 - tests use ~25 distinct states, defined as per-test module constants (e.g. `test_4_1_rate_limiting.py:125`) → each `tests/<id>.md` page lists its own states |
| 7. Helpers table | 735-744 | reference | `guides/extending/add-a-native-test.md` | rewrite | ✘ `auth.py` described as "Forgejo Basic Auth" - it is now a dispatcher over `auth_forgejo.py` and `auth_jwt_login.py`; those two modules are missing from the table |
| 7. Attack payload modules | 746-751 | reference | `guides/extending/add-a-native-test.md` | rewrite | ✘ lists only `ssrf_payloads.py`; real: `auth_payloads.py`, `inspector_patterns.py`, `shadow_wordlists.py`, `ssrf_payloads.py` |
| 8. Exception hierarchy | 755-793 | reference | `architecture/overview.md` (errors section); exit mapping → `reference/exit-codes.md` | move | All classes exist ✔ (`exceptions.py`, `gateway/base.py:49`, `seed_generator.py:426,454`); per-class fields to recheck when writing |
| 9. Repository structure | 797-930 | reference | `architecture/overview.md` | rewrite | Accurate for `src/`; lists planned `injection_payloads.py`; docs tree will change after restructuring |
| 10. Packaging | 934-947 | reference | `guides/integration/deployment-and-secrets.md` + `reference/compatibility.md` | move | sdist include list ✔ `pyproject.toml` (`docs/pub/` is included → must be updated when docs move); sslyze extra AGPL → Q-11 |

### Verification log - ARCHITECTURE

Actual inter-package imports (computed by parsing every module with `ast`):

```
cli            -> config, core/exceptions, discovery, engine
config         -> core/exceptions, core/models
connectors     -> core/exceptions
core/*         -> core/exceptions, core/gateway, core/models
discovery      -> core/exceptions, core/models
external_tests -> config, connectors, core/context, core/evidence, core/exceptions, core/models
report         -> config, core/models
tests          -> core/client, core/context, core/evidence, core/exceptions, core/gateway, core/models
engine         -> everything
```

No module imports `engine` ✔. `tests/` never imports `config/`, `discovery/`, `report/` ✔.

---

## 3. docs/guides/extending/add-a-native-test.md (English, 1,901 lines)

Overall: a step-by-step contributor how-to, already in English. **Identifier check:** all 97 functions/classes
referenced exist in `src/` (automated scan; only placeholders `TestN2Config`, `RuntimeTestN2Config` absent).
Main destination: `guides/extending/add-a-native-test.md`.

| Section | Lines | Type | Destination | Action | Claims to verify |
|---|---|---|---|---|---|
| Intro ("source of truth", read top to bottom) | 1-62 | how-to | `add-a-native-test.md` | rewrite | Wording targets an AI assistant ("Do not invent patterns"); rewrite for human contributors. Link to `../priv/PROJECT_status.md` → `project/roadmap.md` |
| Which steps apply; file pipeline (6 / 9 files) | 64-120 | how-to | `add-a-native-test.md` | move | 13 `RuntimeTest*Config` classes in `runtime.py` and 13 wired in `engine.py` ✔ consistent with the pipeline |
| Why two config layers | 122-134 | explanation | `architecture/data-model.md` (config section) + short note in guide | merge | - |
| Steps 1-7 (schema, tests_config, `__init__`, runtime, models `__init__`, engine, domain `__init__`) | 136-516 | how-to | `add-a-native-test.md` | move | Step 5 example inventory lists 11 of 13 runtime classes (missing `RuntimeTest14Config`, `RuntimeTest21Config`) - illustrative, refresh when moving; all `domain_N/__init__.py` exist and are empty ✔ |
| Step 8 - test module (filename, docstring, imports, constants, ClassVars, `_transaction_log`, structure) | 518-806 | how-to | `add-a-native-test.md` | move | 8 mandatory ClassVars ✔ match `has_required_metadata()` in `src/tests/base.py` |
| Canonical entry patterns ("real code from test 1.1 / 4.2") | 807-1073 | how-to | `add-a-native-test.md` | rewrite | ✘ labelled "real code" but only 12/27 (1.1) and 15/34 (4.2) non-comment lines match the current source verbatim → extract fresh excerpts or label as simplified |
| Iterating AttackSurface; building results; recording transactions; Findings; resources | 1074-1370 | how-to + reference | `add-a-native-test.md` | move | Stale path `src/core/models.py` at line 1078 (Q-07) |
| Step 9 - `config.yaml` | 1371-1428 | how-to | `add-a-native-test.md` | move | - |
| Strategy → Priority → Guard mapping | 1429-1454 | reference | `architecture/assessment-model.md` | merge | Must reflect real per-test values (Q-14) |
| Reference tables (guards, helpers, AttackSurface filters) | 1455-1547 | reference | `add-a-native-test.md` (appendix) | move | Guards ✔ `base.py:668-757` |
| Worked example - Test 2.1 | 1548-1780 | tutorial | `add-a-native-test.md` | rewrite | ✘ only 26/104 snippet lines match current `test_2_1_rbac_enforcement.py` |
| Post-implementation verification | 1781-1845 | how-to | `add-a-native-test.md` | move | Depends on Q-12 (no automated test suite) |
| Pre-output checklist | 1846-1882 | how-to | `add-a-native-test.md` (as "Checklist") | rewrite | AI-oriented naming |
| Common errors and fixes | 1883-1901 | reference | `add-a-native-test.md` | move | - |

---

## 4. docs/guides/extending/add-an-external-test.md (English, 1,212 lines)

Overall: contributor how-to for external tests and connectors. **Identifier check:** all 75 referenced
identifiers exist in `src/`. Destination: `guides/extending/add-an-external-test.md`.

| Section | Lines | Type | Destination | Action | Claims to verify |
|---|---|---|---|---|---|
| Architecture overview | 64-86 | explanation | `architecture/overview.md` (external tests + connectors section) | merge | Connector tiers ✔ `BaseConnector`, `BaseSubprocessConnector`, `BaseLibraryConnector` (`connectors/base.py:136,245,954`) |
| Critical rules 1-3 (`_evaluate`, `command_json`) | 87-170 | how-to | `add-an-external-test.md` | move | - |
| File pipeline (scenario A / B) | 171-196 | how-to | `add-an-external-test.md` | move | - |
| Naming conventions | 197-251 | reference | `add-an-external-test.md` | move | `ext.X.Y.tool` IDs ✔ match the three implemented tests |
| Step B.0 - tool output reconnaissance | 252-352 | how-to | `add-an-external-test.md` | move | - |
| Step B.1 - per-tool config | 353-428 | how-to | `add-an-external-test.md` | move | Location `src/core/models/external_tools.py` ✔; ✘ `src/connectors/_template_connector.py` docstring still says `src/config/schema/external_tools.py` (code comment drift, not a doc issue) |
| Step B.2 - connector (ClassVars, `ConnectorRawOutput`, paths, `run()`) | 429-672 | how-to | `add-an-external-test.md` | move | 4 keys `command`, `command_json`, `results`, `all_count` ✔ `connectors/base.py:865`; `_sanitize_paths_in_findings` ✔ `:736` |
| Step B.3 - `connectors/__init__.py` | 673-687 | how-to | `add-an-external-test.md` | move | - |
| Step 1/B.4 - external test module (imports, constants, 9 ClassVars, `_evaluate` patterns) | 688-1050 | how-to | `add-an-external-test.md` | move | 9 ClassVars ✔ (`test_id`, `test_name`, `domain`, `priority`, `strategy`, `depends_on`, `tags`, `cwe_id`, `tool_name`) + fixed `source` (`external_tests/base.py:195-205`) |
| Step B.5 - `config.yaml` | 1051-1071 | how-to | `add-an-external-test.md` | move | - |
| DA-2 connector injection | 1072-1093 | explanation | `architecture/overview.md` | merge | "DA-2" is a thesis label (from `apiguard_property.md`); replace with a descriptive name |
| Post-implementation verification; checklist; common errors | 1094-1212 | how-to | `add-an-external-test.md` | move | Same remark as ADDING_tests (Q-12) |
| Not mentioned | - | - | `add-an-external-test.md` | gap | The two template files `src/connectors/_template_connector.py` and `src/external_tests/_template_ext_test.py` are referenced only marginally (3 mentions) |

---

## 5. docs/project/roadmap.md (English, 295 lines)

Overall: project tracking, thesis-framed ("Pre-Thesis Writing", "July deadline", tests chosen for
"architectural property demonstration"). Destination: `project/roadmap.md`.

| Section | Lines | Type | Destination | Action | Claims to verify |
|---|---|---|---|---|---|
| Legend + naming convention | 31-45 | reference | `project/roadmap.md` (legend); ID convention → `tests/README.md` | move | - |
| Tests overview table | 47-92 | status | `project/roadmap.md` (implemented part generatable) | generate + move | Implemented IDs ✔ match code |
| Milestone 1 per domain (with "Key Properties") | 94-158 | status | `project/roadmap.md`; per-test status → `tests/<id>.md` | merge | "Key Properties" column (D1.P1…) is thesis traceability → `knowledge/design-properties.md` |
| DAG state, strategy coverage | 159-176 | reference | `tests/README.md` (generated) | generate | - |
| Milestone 2 - future work | 178-245 | status | `project/roadmap.md` | rewrite | ✘ conflicts with ARCHITECTURE §4.1 on strategy/dependencies of planned tests → Q-17; thesis framing to be removed |
| Connectors (Cat A implemented / planned, Cat B) | 247-291 | status + reference | implemented → `reference/compatibility.md` (pinned versions); planned → `project/roadmap.md` | merge | nuclei 3.8.0 ✔, templates 10.4.3 ✔ (`install_tools.sh:56,110`); ✘ testssl "3.2.x" - pinned 3.2.3; ✘ sslyze ">=6.0" - `pyproject.toml` says `>=6.3,<7` |
| Connector decision log | 283-291 | research | `knowledge/tools/decisions.md` | move | - |
| TODO M1 | 293-295 | status | - | drop | M1 complete |

---

## 6. docs/project/audits/2026-05-18-v0.1.0-release.it.md (Italian, 375 lines)

Overall: dated snapshot (2026-05-18) of the v0.1.0 release audit. Destination: `project/audits/2026-05-18-v0.1.0-release.md`.

| Section | Lines | Type | Destination | Action | Claims to verify |
|---|---|---|---|---|---|
| Part A - verdicts, performance, idempotence, teardown, DAG, versions, deferred items | 35-166 | status | `project/audits/…` (as historical record) | move | Historical snapshot: not re-verified. Facts reusable with date attribution: tested Python **3.12.3**, Forgejo 14.0.3, Kong DB-less (→ Q-02, `reference/compatibility.md`); runtime ≈ 4 min 50 s, peak ≈ 290 MB (→ `guides/integration/deployment-and-secrets.md`, labelled "measured on v0.1.0") |
| Part B - 73 verification checks | 168-355 | status | `project/audits/…` | move | Historical |
| Appendix - verification commands | 356-375 | how-to | `CONTRIBUTING.md` (release checks) | merge | Commands exist ✔ (`hatch run dev:lint|audit|deps` in `pyproject.toml`) |
| A.7 deferred: CHANGELOG from v0.2.0 | 157-166 | status | `CHANGELOG.md` | - | Confirms CHANGELOG starts at next release |

Translation: historical record; translate or keep in Italian with an English summary → decide during writing phase.

---

## 7. docs/project/maintainer-commands.md (English, 198 lines)

Overall: personal cheat sheet. Mixed: some content is product how-to, some is maintainer-only, some is personal.

| Section | Lines | Type | Destination | Action | Claims to verify |
|---|---|---|---|---|---|
| Export utility (`build_zip.sh`) | 18-38 | personal | - | drop | Personal tooling (zip for sharing); not product docs |
| Viewing the report (VS Code Remote) | 39-48 | how-to | `guides/usage/read-the-report.md` (tip) | move | - |
| Hatch environment | 49-58 | how-to | `CONTRIBUTING.md` | move | - |
| Running the tool, other commands, exit codes | 59-103 | how-to + reference | `reference/cli.md`, `reference/exit-codes.md` | merge | `python -m src.cli` works ✔ (`cli.py:653` `__main__`); duplicate exit-code table |
| Building the package | 104-137 | how-to | `CONTRIBUTING.md` (release section) | rewrite | ✘ sdist list includes the file itself (then `docs/priv/LOCAL_commands.md`) and omits `README.en.md` - real sdist (`dist/apiguard_assurance-0.1.0.tar.gz`) contains `.env.example`, `.gitignore`, `README.md`, `README.en.md`, `config.yaml`, `install_tools.sh`, `pyproject.toml`, `docs/pub/*`, `src/` |
| Static analysis | 138-153 | how-to | `guides/extending/coding-rules.md` / `CONTRIBUTING.md` | move | Scripts ✔ |
| Kong configuration changes | 154-161 | how-to | `getting-started/first-assessment.md` (lab env) | move | - |
| Git history clean-up | 162-184 | personal | - | drop | Personal git workflow (`push -f`); not project docs |
| Git tag + release | 185-198 | how-to | `CONTRIBUTING.md` (release section) | rewrite | Tag `v0.1.0` exists ✔; remote is GitHub `eneamanzi/apiguard-assurance` ✔ |

---

## 8. docs/knowledge/design-properties.it.md (Italian, 794 lines)

Overall: catalogue of 39 architectural properties (D1-D7), each with definition, code locus, consequences,
evidence type, future development. Written as thesis traceability (properties cited in PROJECT_status).
Destination: `knowledge/design-properties.md` (rationale). Factual parts feed `architecture/*`.

| Section | Lines | Type | Destination | Action | Claims to verify |
|---|---|---|---|---|---|
| D1 Architecture & design (6 props) | 56-171 | explanation | `knowledge/design-properties.md`; summaries → `architecture/overview.md` | translate + merge | ✘ D1.P1 "no hardcoded application paths": `test_1_4_token_revocation.py:70-76` hardcodes Forgejo token paths, `helpers/auth_forgejo.py:66` and `forgejo_resources` are Forgejo-specific → statement must be scoped (CLAUDE.md already calls these "environment adapters") → Q-18 |
| D2 Extensibility (8 props) | 172-315 | explanation | same | translate + merge | - |
| D3 Config & reproducibility (5 props) | 316-416 | explanation | same | translate + merge | - |
| D4 Robustness & security (9 props) | 417-576 | explanation | same; D4.P2/P4/P7 → `architecture/security-model.md` | translate + merge | - |
| D5 Quality & observability | 577-665 | explanation | same | translate + merge | - |
| D6 CI/CD & DevEx (3 props) | 666-723 | explanation | same; D6.P1 → `reference/exit-codes.md` (rationale link) | translate + merge | - |
| D7 Packaging (3 props) | 724-783 | explanation | same; D7.P2 (AGPL isolation) → `guides/integration/deployment-and-secrets.md` | translate + merge | Q-11 |
| Taxonomic summary | 784-794 | reference | `knowledge/design-properties.md` | translate | - |

Note: the "D1.P1"-style IDs are thesis labels. Keep them inside `knowledge/` only; product docs use descriptive names.

---

## 9. docs/knowledge/tools/decisions.it.md (Italian, 410 lines) and TOOLS_catalog.md (Italian, 1,051 lines)

Overall: research on external tools - `TOOLS_catalog` lists candidates per test/domain with appendices;
`TOOLS_decisions` records the chosen tool per test (Cat A / B / C) with rationale.
Destination: `knowledge/tools/catalog.md` and `knowledge/tools/decisions.md`; per-test summary → "Why" section of `tests/<id>.md`.

| Section | Lines | Type | Destination | Action | Claims to verify |
|---|---|---|---|---|---|
| TOOLS_decisions per domain | 1-378 | research | `knowledge/tools/decisions.md`; per-test excerpt → `tests/<id>.md` | translate + merge | ✘ priorities of 1.4 and 2.1 shown as P1; methodology and code both say **P2** (automated comparison of all 29 IDs: only these two differ) |
| TOOLS_decisions summaries (shared connectors, classification) | 379-410 | research | `knowledge/tools/decisions.md` | translate | - |
| TOOLS_catalog legend + per-domain catalogue | 123-895 | research | `knowledge/tools/catalog.md` | translate | Same P1 drift for 1.4 / 2.1 |
| TOOLS_catalog appendices A-E (cross-cutting, non-REST, abandoned, future, confidence) | 896-1051 | research | `knowledge/tools/catalog.md` | translate | - |

---

## 10. docs/priv/knowledge/

| File | Lines | Type | Destination | Action | Notes / claims to verify |
|---|---|---|---|---|---|
| `3-Metodologia.md` - box-gradient note + priority matrix | 1-82 | explanation | `architecture/assessment-model.md` (product view) + `knowledge/methodology/overview.md` (full rationale) | translate + merge | Matrix priorities ✔ match code for all 15 implemented tests; ✘ internal inconsistency: 2.2 is `[P1]` in its heading (line 312) but listed in the P2 row of the matrix |
| `3-Metodologia.md` - guarantees 0.1-7.4 (references, concept, failure scenarios, prerequisites, test logic) | 84-758 | research | `knowledge/methodology/domain-N-*.md`; implemented tests → "What it checks / Why" of `tests/<id>.md` | translate + merge | Highest-value source for test pages. 3.2 merged into 6.1 → 29 guarantees ✔ |
| `3-Metodologia.md` - risk-based prioritisation | 758-818 | explanation | `knowledge/methodology/overview.md` | translate | - |
| `4-Implementazione.md` | 1-742 | explanation | `architecture/*` (only unique parts) | merge + drop | Italian thesis version of ARCHITECTURE.md (same sections, updated to gateway/JSONL). Unique: §1 problem and constraints (→ `architecture/overview.md` intro), §6 special behaviours (→ relevant pages). ✘ §1 mentions "PDF report" - no PDF output exists |
| `5-Scenario-test.md` | 1-33 | research | `knowledge/target-selection.md` | translate | Requirements for target apps + candidates; why Forgejo was chosen is not stated explicitly → ask user when writing |
| `RULES_claude.md` | 1-138 | personal (AI assistant rules) | §5 coding standards → `guides/extending/coding-rules.md`; rest stays assistant-only (CLAUDE.md / `.claude/`) | merge | ✘ refers to `tests_e2e/` (does not exist) and to `4-Implementazione.md` as architecture source of truth; §1 roadmap is the original thesis plan (historical) → Q-12 |
| `2-Background_compact.md` | 1-1074 | research | `knowledge/background/README.md` (intro + §3.4 "implications for the tool") and topic files | translate (condensed) | Condensed rewrite of the extensive version |
| `2-Background_extensive.md` | 1-3851 | research | `knowledge/background/{gateway-architectures, api-protocols, architecture-protocol-matrix}.md` | translate or keep as Italian archive → decide | Phases 1.A (gateway/K8s/mesh/serverless), 1.B (REST, GraphQL, gRPC, SOAP, WebSocket, SSE), 1.C (physiology/pathology matrix). Most protocols are outside the tool's REST scope |

---

## 11. Cross-cutting findings

**Duplication map**

| Fact | Currently in | Single home |
|---|---|---|
| Exit codes | README §8, ARCHITECTURE §4, LOCAL_commands, 4-Implementazione §7, apiguard_property D6.P1 | `reference/exit-codes.md` |
| Repository tree | README §9, ARCHITECTURE §9, 4-Implementazione §2, CLAUDE.md | `architecture/overview.md` |
| Test list per domain | README §7, ARCHITECTURE §4.1, PROJECT_status, CLAUDE.md | `tests/README.md` (generated) |
| Exception hierarchy | ARCHITECTURE §8, CLAUDE.md, 4-Implementazione §8 | `architecture/overview.md` |
| 7-phase pipeline | README §6, ARCHITECTURE §3-4, 4-Implementazione §5 | `architecture/overview.md` |
| Component descriptions (contexts, client, evidence store, registry, DAG) | ARCHITECTURE §5, 4-Implementazione §4, apiguard_property D1-D4 | `architecture/overview.md` + `architecture/data-model.md` |
| Test priority | code ClassVars, 3-Metodologia, TOOLS_decisions, TOOLS_catalog, PROJECT_status, README §7 | code (generated into `tests/`); methodology keeps the rationale |
| Planned tests (M2) | ARCHITECTURE §4.1, PROJECT_status M2, TOOLS_decisions | `project/roadmap.md` (Q-17) |
| Pinned external-tool versions | `install_tools.sh`, `config.yaml` `expected_version`, PROJECT_status, AUDIT A.6 | `reference/compatibility.md` (values from `install_tools.sh`) |
| sdist / wheel contents | ARCHITECTURE §10, LOCAL_commands | `CONTRIBUTING.md` (release) - derived from `pyproject.toml` |
| Coding rules | CLAUDE.md, RULES_claude §5, ADDING_* conventions | `guides/extending/coding-rules.md` |
| BaseTest contract / conventions | ARCHITECTURE §4 Phase 5 + §7, ADDING_tests | `guides/extending/add-a-native-test.md` |

**Gaps (target pages with no existing source)**
- `reference/report-schema.md` - `apiguard_report.json` structure (top-level keys verified: `output_schema_version`, `tool_version`, `run_id`, `generated_at_utc`, `target_base_url`, `spec_title`, `spec_version`, `min_priority_label`, `strategies_label`, `executive_summary`, `domains`, `all_rows`)
- `reference/compatibility.md` - what is a stable contract (`output_schema_version` exists but has no documented policy)
- `guides/integration/consume-the-report.md`
- `guides/extending/add-a-gateway-adapter.md` - `BaseGatewayAdapter` is described in 4-Implementazione §4.6.1 and apiguard_property D1.P6, but no how-to exists
- `CHANGELOG.md` - AUDIT A.7: starts from v0.2.0
- `docs/index.md`
- `tests/<id>.md` pages - content exists scattered (methodology + code + tools decisions); no per-test page exists
- Target portability (which tests work on non-Forgejo / non-Kong targets) - Q-18
- `knowledge/target-selection.md` - why Forgejo was chosen is not written down

**Generatable from code**
- `reference/cli.md` ← Typer app `src/cli.py`
- `reference/configuration.md` ← Pydantic models `src/config/schema/*` (most fields have `description=`)
- `tests/README.md` ← ClassVars `src/tests/base.py:189-196`, `src/external_tests/base.py:195-199`
- `reference/exit-codes.md` ← `src/engine.py:129-132` (+ hand-written conditions)
- `architecture/data-model.md` models catalogue ← `src/core/models/`
- Existing: `hatch run dev:docs` (pydoc-markdown → `docs/API_REFERENCE.md`, file not present) → Q-13

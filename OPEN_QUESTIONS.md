# Open Questions — Documentation Restructuring

Living log of doubts raised while restructuring the documentation.
Rule: nothing is written in the final docs on the basis of an open entry.
Each entry is closed only with evidence (command output, code location, or a test run).

Status values: `open` · `verified` (fact confirmed, recorded below) · `resolved` (decision taken) · `deferred` (out of current scope).

---

### Q-01 — Supported operating systems
- Status: open
- Source: `README.md:92` (Windows venv activation), `README.md:114` ("wheel is cross-platform … works on any system with Python 3.11+"), `pyproject.toml:63-64` (classifiers: Linux, macOS only)
- Question: Is Windows supported? Has the tool been run on macOS? The wheel being `py3-none-any` does not imply external tools (testssl.sh, nuclei) work on every OS.
- How to verify: user confirms on which OSes the tool has actually been run; docs then state only tested platforms.
- Resolution:

### Q-02 — Supported Python versions
- Status: open
- Source: `pyproject.toml:25` (`requires-python = ">=3.11"`), `pyproject.toml:67-68` (classifiers 3.11, 3.12), `README.md:80`
- Question: Which Python versions have actually been tested (3.11, 3.12, 3.13+)?
- How to verify: user confirms; optionally run `hatch run dev:pytest` under each interpreter.
- Evidence found: `docs/project/audits/2026-05-18-v0.1.0-release.it.md` §A.6 records the v0.1.0 audit run on Python 3.12.3.
- Resolution:

### Q-03 — Reference target for `getting-started/first-assessment.md`
- Status: open
- Source: `test-environments/forgejo-kong/docker-compose.yml`, `config_crapi.yaml:3-4`
- Question: All tests were developed and run against Forgejo + Kong. `config_crapi.yaml` targets cRAPI directly on `:8888` with `admin_api_url: null`, so WHITE_BOX tests SKIP; no cRAPI compose file exists in the repo. Which target does the tutorial use? Should cRAPI be put behind Kong?
- How to verify: discussion with user; the chosen environment is brought up from scratch following the tutorial steps literally.
- Resolution:

### Q-04 — Generated reference documentation
- Status: open
- Source: `src/cli.py` (Typer app), `src/config/schema/*.py` (Pydantic fields, most with `description=`), `src/tests/base.py:189-196` and `src/external_tests/base.py:195-199` (test ClassVars)
- Question: Adopt a script that generates `reference/` tables and the `tests/` index from code, with a `--check` mode to detect drift? Where is the check enforced? The repo has no CI and no pre-commit config (verified 2026-10-05).
- How to verify: decision with user; separate task after the inventory.
- Resolution:

### Q-05 — Licence
- Status: deferred
- Source: `pyproject.toml` (licence intentionally unspecified pending university regulations)
- Question: Which licence, and when?
- Resolution: Deferred by user (2026-10-05).

### Q-06 — SECURITY.md
- Status: deferred
- Question: Vulnerability disclosure policy for the tool itself.
- Resolution: Out of scope for now (user, 2026-10-05).

### Q-07 — Stale path in ADDING_tests.md
- Status: verified
- Source: `docs/guides/extending/add-a-native-test.md:1078` references `src/core/models.py`
- Question: The module is now the package `src/core/models/`. Are other parts of ADDING_tests.md equally outdated?
- How to verify: full read of ADDING_tests.md during the inventory, checking each code reference.
- Resolution: Path is stale (verified: `src/core/models/` is a package). Extent of drift to be assessed in the inventory.

### Q-08 — Public README links an internal document
- Status: verified
- Source: `README.md:441`, `README.en.md:441` link `docs/project/roadmap.md`
- Question: In the new structure the link must target `docs/project/roadmap.md`.
- Resolution: Fix during the move phase.

### Q-09 — `ext.0.1.nuclei` partial status
- Status: open
- Source: `docs/project/roadmap.md:52`, `:105` (marked `[~]`)
- Question: What exactly is missing for `[x]` (additional Cat A connectors ffuf/katana planned for M2?), and how should a partially covered guarantee be presented in the user-facing `tests/` page?
- How to verify: read PROJECT_status legend + TOOLS_decisions Domain 0; confirm with user.
- Resolution:

### Q-10 — External tests ignore `execution.strategies`
- Status: open
- Source: `src/engine.py:646-651` (external discovery receives `min_priority` and `allowed_ids`, not `strategies`); `src/external_tests/registry.py:374-417` (filters: allowed_ids, priority, per-tool enabled)
- Question: With `strategies: [BLACK_BOX]`, `ext.1.5.testssl` and `ext.1.5.sslyze` (WHITE_BOX) still run. Intended (external tests filtered only by `external_tools.*.enabled`) or a bug? The docs must state the real rule.
- How to verify: decision with user; optional confirmation run with `strategies: [BLACK_BOX]` against the lab target.
- Resolution:

### Q-11 — sslyze AGPL licence vs production integration
- Status: open
- Source: `pyproject.toml` optional dependency `sslyze` (comment: "for SaaS distribution, this extra must be removed or replaced")
- Question: The tool will be embedded in another product. Is the `[sslyze]` extra acceptable there, or must docs mark `ext.1.5.sslyze` as research-only?
- How to verify: decision with user (licensing, not code).
- Resolution:

### Q-12 — Project test suite
- Status: open
- Source: `README.md:121` (`hatch run dev:pytest -v`), `pyproject.toml` `[tool.pytest.ini_options] testpaths = []`; no `test_*.py` / `conftest.py` outside `src/`; dev deps include `pytest-httpx` while CLAUDE.md forbids httpx mocks
- Question: There is no automated test suite for the tool itself. What does CONTRIBUTING document as the verification procedure (E2E run on lab target? `hatch run dev:check`?)
- How to verify: decision with user.
- Resolution:

### Q-13 — Existing `hatch run dev:docs` script
- Status: open
- Source: `pyproject.toml` `[tool.hatch.envs.dev.scripts] docs` (pydoc-markdown → `docs/API_REFERENCE.md`, file not present in repo)
- Question: Keep, remove, or replace it as part of Q-04?
- How to verify: decide together with Q-04.
- Resolution:

### Q-14 — Priority ↔ strategy table vs implemented tests
- Status: open
- Source: `README.md:443-448` ("P1 typical GREY_BOX", "P2 GREY_BOX", "P3 WHITE_BOX")
- Question: Implemented tests: P1 = 4.2, 4.3 (both WHITE_BOX); P2 = 1.4, 2.1 (GREY), 1.5, 6.4, ext.1.5.* (WHITE); P3 = 1.6, 3.3, 6.2 (WHITE). Is the table the methodology's intended mapping (keep in `knowledge/`) or should user docs show only the real per-test values?
- How to verify: compare with `docs/knowledge/methodology/methodology.it.md` priority matrix; decide with user.
- Evidence found: the README table reproduces the methodology table (`3-Metodologia.md:63-66`, "P1 → Grey Box"). Per-test priorities in code match `3-Metodologia.md` for all 15 implemented tests; `TOOLS_decisions.md` / `TOOLS_catalog.md` list 1.4 and 2.1 as P1 (stale). Open point is only the strategy column (4.2, 4.3 are P1 but WHITE_BOX).
- Resolution:

### Q-15 — Layering: `external_tests` imports `config`
- Status: open
- Source: `src/external_tests/registry.py:61` (`from src.config.schema.external_tools import ExternalToolsConfig`); CLAUDE.md dependency direction does not mention `config/`
- Question: Is this an accepted exception (the module is a re-export of `core/models/external_tools.py`) or a rule violation? Determines how the dependency rule is written in `architecture/overview.md`.
- How to verify: decision with user.
- Resolution:

### Q-16 — No CI and no pre-commit
- Status: open
- Source: no `.github/workflows/`, `.gitlab-ci.yml` or `.pre-commit-config.yaml` in the repo (verified 2026-10-05); quality scripts exist only as `hatch run dev:lint|audit|check` in `pyproject.toml`
- Question: Add a CI pipeline and/or pre-commit hooks (lint, mypy, bandit, docs drift check from Q-04, link check)? Which platform hosts the repo (GitHub, GitLab)?
- How to verify: decision with user; separate task after the documentation restructuring.
- Evidence found: remote `origin` = `https://github.com/eneamanzi/apiguard-assurance` → GitHub Actions is the natural option.
- Resolution:

### Q-17 — Roadmap source of truth (Milestone 2)
- Status: open
- Source: `docs/architecture/overview.md:285-445` vs `docs/project/roadmap.md:178-245`
- Question: The two documents disagree on planned tests. Examples: 1.2 GREY_BOX (ARCHITECTURE) vs BLACK_BOX (PROJECT_status); 3.1 GREY_BOX vs BLACK_BOX; 5.1/5.2 GREY_BOX vs WHITE_BOX; 6.3 GREY+WHITE vs BLACK_BOX; dependency on 1.2 present in ARCHITECTURE, absent in PROJECT_status. PROJECT_status is also framed around the thesis ("July deadline", tests chosen for property demonstration). Which is current, and what is the post-thesis roadmap?
- How to verify: decision with user.
- Resolution:

### Q-18 — Target portability of each test
- Status: open
- Source: `src/tests/domain_1/test_1_4_token_revocation.py:70-76` (hardcoded Forgejo token API paths); `src/tests/helpers/auth_forgejo.py:66`; `src/tests/helpers/forgejo_resources.py`; `src/tests/domain_7/test_7_2_ssrf_prevention.py` (`injection_mode: forgejo_webhook | fixed_path`); `src/core/gateway/` (Kong only); `docs/knowledge/design-properties.it.md` D1.P1 ("no hardcoded application paths")
- Question: For a production integration, which tests run on any OpenAPI target, which need Forgejo (or a config switch), which need Kong? Behaviour of 1.4 on a non-Forgejo target is unknown. The only cRAPI output (`outputs/crapi/`, 2026-04-28) predates the current report schema, so it is not valid evidence.
- How to verify: code reading per test + a fresh run against a second target (ties into Q-03).
- Resolution:

### Q-19 — Stale documentation paths in source comments and scripts
- Status: open
- Source: 26 references in docstrings/comments of `src/engine.py` `src/discovery/seed_generator.py` `src/external_tests/ext_test_1_5_tls_analysis.py` `src/report/builder.py` `src/tests/domain_0/test_0_1_shadow_api_discovery.py` `src/core/models/enums.py` `src/tests/domain_1/test_1_4_token_revocation.py` `src/tests/domain_2/test_2_1_rbac_enforcement.py` `src/tests/domain_0/test_0_2_deny_by_default.py` `src/external_tests/ext_test_0_1_shadow_api_nuclei.py` `src/tests/domain_6/test_6_4_hardcoded_credentials_audit.py` `src/tests/registry.py` `src/tests/domain_1/test_1_1_authentication_required.py` `src/core/models/runtime.py` `src/tests/domain_0/test_0_3_deprecated_api_enforcement.py` `src/core/dag.py` `src/core/exceptions.py` `src/core/models/results.py` `src/core/evidence.py` — mostly "`4-Implementazione.md` §x", plus `docs/pub/…`, `docs/priv/…`. Also `build_zip.sh:62-64` (exclusion list already pointing to non-existent `docs/*.md` names).
- Question: Docs moved on 2026-10-05 (see mapping in `docs/project/docs-inventory.md`). Source files were deliberately not touched (no code changes during docs work). Update comments to the new paths once the target pages exist (e.g. `architecture/…`, `tests/<id>.md`).
- How to verify: `grep -rn -E "4-Implementazione|3-Metodologia|docs/(pub|priv)|ADDING_tests|ARCHITECTURE\.md|PROJECT_status" src build_zip.sh` returns nothing.
- Resolution:

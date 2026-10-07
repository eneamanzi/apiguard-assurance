# Changelog

Notable changes to APIGuard Assurance. Format based on [Keep a Changelog](https://keepachangelog.com/); versions
follow [Semantic Versioning](https://semver.org/) (0.x: interfaces may still change, see
[compatibility](docs/reference/compatibility.md#interface-stability)).

## [Unreleased]

The test logic is unchanged since 0.1.0. Results on the lab differ only because the lab changed (below): with
the new `path_seed` resources, test 1.1 reports 78 findings instead of 56.

### Changed

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

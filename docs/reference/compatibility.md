# Compatibility

> **Audience:** users, integrators · **Status:** draft - several points are open (see `OPEN_QUESTIONS.md`) ·
> **Source of truth:** `pyproject.toml`, `install_tools.sh`, `src/core/gateway/`, `src/discovery/openapi.py`,
> `test-environments/forgejo-kong/docker-compose.yml` · **Verified:** 2026-10-05, v0.1.0; interface stability 2026-10-09

This page separates what the code **declares**, what has been **tested**, and what is **unknown**.
Nothing in the "unknown" column should be assumed to work.

## Runtime

| Item | Declared | Tested | Unknown |
|---|---|---|---|
| Python | `>=3.11,<3.15` (`pyproject.toml`); classifiers 3.11 to 3.14 | 3.11.14, 3.12.3, 3.13.9, 3.14.0 (2026-10-06: `pip install ".[sslyze]"` in a venv per version, then the 15 native tests and `ext.1.5.sslyze` on the lab; identical results on every version) | 3.15 and later: not installable until verified and added to the range |
| Operating system | Linux only (classifier `POSIX :: Linux`) | Linux | Not supported: macOS, Windows. `install_tools.sh` also accepts macOS (x86_64, arm64), but the tool is not tested there; on Windows it exits with an error. |

## Target and gateway

| Item | Declared | Tested | Notes |
|---|---|---|---|
| Specification formats | Swagger 2.0; OpenAPI 3.0.x and 3.1.x (validator chosen by minor version) | Swagger 2.0 (Forgejo), OpenAPI 3.0.1 (`specs/crapi-openapi.json`) | OpenAPI 3.1 not exercised on a real target. Swagger 2.0 skips structural validation (`src/discovery/openapi.py`). A major version other than `swagger: 2` / `openapi: 3` → `OpenAPILoadError` (exit `10`). |
| Gateway adapter (WHITE_BOX audits) | `kong` only (`target.gateway_adapter`) | Kong 3.9.3 in DB-less mode (see [Test lab](#test-lab)) | Other gateways: configuration-audit tests SKIP. |
| Target application | any REST API with an OpenAPI spec | Forgejo 14.0.5 behind Kong (see [Test lab](#test-lab)); 14.0.3 in the v0.1.0 release audit | Some tests or defaults are Forgejo-specific (test 1.4 token API paths; test 7.2 default `injection_mode`; test 2.1 default admin path). Per-test portability is not yet established (Q-18). |
| Token acquisition (`credentials.auth_type`) | `forgejo_token`, `jwt_login` | `forgejo_token` on Forgejo; `jwt_login` on cRAPI (`config_crapi.yaml`, run of 2026-10-06 recorded in Q-18) | cRAPI ran without a gateway; per-test results in Q-18. |

## Test lab

The lab in `test-environments/forgejo-kong/` pins every image to an exact version, so that an assessment on it can
be repeated with the same target. These are the versions the documentation and the measured results refer to.

| Component | Image | Version |
|---|---|---|
| Forgejo (API under test, and the setup container) | `codeberg.org/forgejo/forgejo:14.0.5` | 14.0.5 (`14.0.5+gitea-1.22.0`) |
| Kong (gateway, DB-less) | `kong:3.9.3` | 3.9.3 |
| PostgreSQL (Forgejo database) | `postgres:15.19-alpine` | 15.19 |

Pinned on 2026-10-06 to the images already in use (identical image IDs to the previous floating tags `forgejo:14`,
`kong:3.9`, `postgres:15-alpine`); the lab was rebuilt from scratch and gave the same results. Before that the tags
were floating: the v0.1.0 release audit (2026-05-18) ran on Forgejo 14.0.3.

To change a version: edit the `image:` lines in `docker-compose.yml` and this table together, rebuild the lab from
scratch ([first assessment](../getting-started/first-assessment.md), steps 2-4) and compare the results with the
previous run.

## External tools

| Tool | Version | Installed by | Licence note |
|---|---|---|---|
| testssl.sh | 3.2.3 (pinned) | `install_tools.sh` → `tools/testssl/` | - |
| nuclei | 3.8.0 (pinned) | `install_tools.sh` → `tools/nuclei/` | - |
| nuclei-templates | 10.4.3 (pinned) | `install_tools.sh` → `tools/nuclei-templates/` | - |
| sslyze | `>=6.3,<7` (Python extra `[sslyze]`) | `pip install "apiguard-assurance[sslyze]"` | AGPL v3; `pyproject.toml` notes it must be removed or replaced for SaaS distribution (Q-11). |

`external_tools.<tool>.expected_version` lets the tool warn when the installed version differs.

## Python dependencies

Runtime dependencies use `>=FLOOR,<NEXT_MAJOR` ranges (`pyproject.toml`), except `prance`, pinned exactly
(`==25.4.8.0`) because the discovery layer relies on one of its internal attributes.

## Interface stability

What an integrator can rely on (owner decision, 2026-10-09, Q-25). The list is a documented promise, not an
automated check.

**One version.** The tool version (`tool_version` in `apiguard_report.json` and `evidence.json`, `apiguard
version`) is the only version of every interface below; the output files have no separate format version. It
follows [Semantic Versioning](https://semver.org/): from 1.0.0, a breaking change raises the major, an addition the
minor, a fix the patch; before 1.0.0 (0.x) a breaking change raises the minor. The version changes only at a
release: changes accumulate under `[Unreleased]` in [`CHANGELOG.md`](../../CHANGELOG.md).

**A. Contract** - not broken without notice: a change that breaks it is marked **Breaking:** in the changelog and
raises the version as above. Adding something (a field, a test, an option, a reason) is not breaking.

| Interface | What it covers | Reference |
|---|---|---|
| Exit codes | `0`, `1`, `2`, `3`, `10` (`130` / `143` come from the signal) | [`exit-codes.md`](exit-codes.md) |
| `apiguard_report.json` | fields, types and meanings; allowed values: statuses (`PASS`, `FAIL`, `SKIP`, `ERROR`), strategies, `not_run` reasons, domain numbers and names | [`report-schema.md`](report-schema.md) |
| `evidence.json` | structure, record ID format (`<test_id>_<NNN>`, the target of `evidence_ref`), redaction placeholders (`[REDACTED: <label>]`, `[public probe] <value>`) | [`evidence-format.md`](evidence-format.md) |
| Output files | names and location: `apiguard_report.json`, `evidence.json`, `assessment_report.html` in `output.directory`, external-tool outputs in `tools/` | [`report-schema.md`](report-schema.md), [`evidence-format.md`](evidence-format.md) |
| Test IDs | `X.Y` and `ext.X.Y.tool` identifiers: renaming or removing a test is breaking, adding one is not | [`../tests/README.md`](../tests/README.md) |
| CLI | commands, options and defaults; stdout / stderr split (`generate-seed` writes the YAML on stdout); `--log-format json` is one JSON object per line | [`cli.md`](cli.md) |
| `config.yaml` | documented keys, types, defaults, validation (unknown keys rejected), `${VAR}` syntax, `.env` lookup | [`configuration.md`](configuration.md) |
| Accepted inputs | specification dialects (Swagger 2.0, OpenAPI 3.x), `path_seed` format, `auth_type` values, gateway adapters | [`configuration.md`](configuration.md) |

**B. Documented behaviour** - may change, always announced under **Changed results** in the changelog, without
counting as breaking:

| Behaviour | Why it matters | Reference |
|---|---|---|
| Test oracles (the rules of each verdict) and coverage | the same target can get a different verdict | [`../tests/`](../tests/README.md) |
| Effects on the target (what each test creates, changes and deletes) | for runs on real systems | [`../tests/`](../tests/README.md) |
| Requirements (Python versions, platforms) | for installation | this page |

**C. Not a contract** - may change freely: texts (finding titles and details, messages), the per-transaction
`oracle_state` labels, log event names and fields, the Python modules (`src.*`), the layout of the HTML report.

**When 1.0.0:** after the agnosticism work (plan, block 8), the last one expected to change `config.yaml` keys and
accepted inputs. Until then the project is 0.x.

## See also

- [`../project/roadmap.md`](../project/roadmap.md)

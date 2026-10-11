# Compatibility

> **Audience:** users, integrators · **Status:** draft - several points are open (see `OPEN_QUESTIONS.md`) ·
> **Source of truth:** `pyproject.toml`, `install_tools.sh`, `src/core/gateway/`, `src/discovery/openapi.py`,
> `test-environments/*/docker-compose.yml` · **Verified:** 2026-10-05, v0.1.0; interface stability 2026-10-09; crAPI lab
> 2026-10-10

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
| Specification formats | Swagger 2.0; OpenAPI 3.0.x and 3.1.x (validator chosen by minor version) | Swagger 2.0 (Forgejo), OpenAPI 3.0.1 (crAPI, `test-environments/crapi-kong/crapi-openapi-spec.json`) | OpenAPI 3.1 not exercised on a real target. Swagger 2.0 skips structural validation (`src/discovery/openapi.py`). A major version other than `swagger: 2` / `openapi: 3` → `OpenAPILoadError` (exit `10`). |
| Gateway adapter (WHITE_BOX audits) | `kong` only (`target.gateway_adapter`) | Kong 3.9.3 in DB-less mode (see [Test lab](#test-lab)) | Other gateways: configuration-audit tests SKIP. |
| Target application | any REST API with an OpenAPI spec | Forgejo 14.0.5 and OWASP crAPI 1.1.6, each behind Kong (see [Test lab](#test-lab)); Forgejo 14.0.3 in the v0.1.0 release audit | Some tests or defaults are Forgejo-specific (test 1.4 token API paths; test 7.2 default `injection_mode`; test 2.1 default admin path). Per-test portability is not yet established (Q-18). |
| Token acquisition (`credentials.auth_type`) | `forgejo_token`, `jwt_login` | `forgejo_token` on Forgejo; `jwt_login` on crAPI (cRAPI lab) | |

## Test lab

Two labs, each pinning every image to an exact version, so that an assessment on them can be repeated with the same
target. These are the versions the documentation and the measured results refer to. Each lab has its own ports, so
both can run at the same time.

| Lab | Folder | Configuration | Ports (proxy HTTP, proxy HTTPS, Admin API) |
|---|---|---|---|
| Forgejo + Kong | `test-environments/forgejo-kong/` | `test-environments/forgejo-kong/config.yaml` | 8000, 8443, 8001 (Forgejo directly: 3000) |
| crAPI + Kong | `test-environments/crapi-kong/` | `test-environments/crapi-kong/config.yaml` | 9000, 9443, 9001 (nothing else exposed) |

### Forgejo + Kong

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

### crAPI + Kong

[OWASP crAPI](https://github.com/OWASP/crAPI), an API vulnerable by design (Apache License 2.0), behind Kong with
the **same gateway configuration** as the Forgejo lab (`kong/kong.yml`: timeouts, passive health checks with an
active check that re-enables an excluded backend, security headers, Kong's HTTP-to-HTTPS redirect, hmac-auth audit
service): only the API changes between the two labs. Added on
2026-10-10.

| Component | Image | Version |
|---|---|---|
| crAPI identity, community, workshop, mailhog, mock dealership | `crapi/crapi-identity`, `crapi-community`, `crapi-workshop`, `mailhog`, `gateway-service`, pinned by digest | 1.1.6 (release commit `700f03d`) |
| Kong (gateway, DB-less) | `kong:3.9.3` | 3.9.3 |
| PostgreSQL, MongoDB (crAPI databases) | `postgres:14.24`, `mongo:4.4.30` | 14.24, 4.4.30 (crAPI declares `postgres:14`, `mongo:4.4`) |
| Setup container | `curlimages/curl:8.22.0` | 8.22.0 |

How it was built, and why:

- **No published guide puts crAPI behind an API gateway** (searched 2026-10-10); crAPI's own entry point is its web
  front end, `crapi-web`, an nginx that forwards `/identity`, `/community` and `/workshop` to the services and
  answers every other path with the web page. The lab follows Kong's documented pattern for microservices instead:
  one service per backend, one route per path prefix, `strip_path: false`
  ([Kong routes](https://developer.konghq.com/gateway/entities/route/)). `crapi-web` and the chatbot (it needs an
  OpenAI key and is reached only through `crapi-web`) are left out; without `crapi-web`, URLs inside some responses
  keep the services' internal host names.
- **Images by digest**: the release workflow of tag `v1.1.6` failed after publishing only `crapi-identity:1.1.6`;
  the complete 1.1.6 build is the successful "Publish Images" run on `main` for the release commit `700f03d`
  (2025-09-22, GitHub Actions of OWASP/crAPI). The `main` tag moves, hence the digests.
- **Accounts**: the setup creates user A and user B through crAPI's signup endpoint, through the gateway; the admin
  is `admin@example.com`, created by crAPI at startup (its password is public in crAPI's source); all from `.env`.
- **Specification**: crAPI's own `openapi-spec/crapi-openapi-spec.json` at the same tag, stored in the lab
  (`NOTICE.md` lists the copied files).

Start, reset and run: [maintainer commands](../project/maintainer-commands.md#test-labs). Repeatability: two runs
of the native tests on a lab reset in between gave identical results (2026-10-10).

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

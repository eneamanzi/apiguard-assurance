# Compatibility

> **Audience:** users, integrators · **Status:** draft - several points are open (see `OPEN_QUESTIONS.md`) ·
> **Source of truth:** `pyproject.toml`, `install_tools.sh`, `src/core/gateway/`, `src/discovery/openapi.py`,
> `test-environments/*/docker-compose.yml` · **Verified:** 2026-10-05, v0.1.0; interface stability 2026-10-09; crAPI lab
> 2026-10-10; APISIX lab and adapter 2026-10-12

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
| Gateway adapter (WHITE_BOX audits) | `kong`, `apisix` (`target.gateway_adapter`) | Kong 3.9.3 in DB-less mode; Apache APISIX 3.19.0, traditional deployment with etcd, Admin API key of role `viewer`, Control API for live health (see [Test lab](#test-lab)) | Kong with a database, other APISIX versions, APISIX standalone (no Admin API: its configuration cannot be read). Other gateways: configuration-audit tests SKIP. |
| Target application | any REST API with an OpenAPI spec | Forgejo 14.0.5 behind Kong and behind APISIX, OWASP crAPI 1.1.6 behind Kong (see [Test lab](#test-lab)); Forgejo 14.0.3 in the v0.1.0 release audit | What each test needs from the target: [Test portability](#test-portability). |
| Authentication (`credentials.auth_type`; how the credential is sent: the specification's security schemes, `security_scheme`, `send_as`) | `basic`, `static_token`, `login` (a [prepared resource](configuration.md#resources) that logs in) | `login` with Forgejo's token API (resource `forgejo-token`, scheme `AuthorizationHeaderToken` + `token ` prefix) on both Forgejo labs and with crAPI's JSON login (resource `crapi-login`, scheme `bearerAuth`) (2026-10-14); `basic` and `static_token` on Forgejo + Kong for tests 1.4, 2.1, 7.2 (2026-10-14, before `login` replaced `forgejo_token` and `json_login`) | OAuth 2.0 client credentials, session cookies obtained by login, mutual TLS: not implemented (`docs/project/auth-survey.md`). Revocation (test 1.4): `login` with a delete request (token deletion); revocation by a logout request not implemented. |

## Test portability

What each test needs to run on a target other than the labs, and what happens when the need is not met: most tests
return SKIP with a reason naming what is missing; 0.2 and 6.4 run anyway, with the effect stated. Measured on the three labs on 2026-10-14
(native tests, lab configurations); the external tests were last run on Forgejo + Kong.

| Test | Needs | Without it | Forgejo + Kong | crAPI + Kong | Forgejo + APISIX |
|---|---|---|---|---|---|
| 0.1, 1.1, 1.5, 4.1, 6.2 | the specification and the target URL only | - | ran | ran | ran |
| 0.2 | the gateway's server identifiers (`gateway_server_identifiers`; default includes Kong's) | a 404 with another gateway's `Server` header is reported as coming from the backend (false finding) | ran | ran | ran (set to `apisix`) |
| 0.3 | operations marked `deprecated` in the specification, without path parameters | SKIP | SKIP (all have path parameters) | SKIP (none marked) | SKIP (as Forgejo + Kong) |
| 1.4 | `auth_type: login` with a login resource that has a delete request, and `verify_request` | SKIP "Not applicable", or SKIP naming `verify_request` | ran | SKIP (no revocation) | ran |
| 1.6 | session cookies set by the target (`session_cookie_names`) | SKIP | SKIP | SKIP | SKIP |
| 2.1 | credentials and `admin_endpoint_paths` | SKIP naming the key | ran | SKIP (not configured) | ran |
| 3.3, 4.2, 4.3 | a gateway adapter (`kong` or `apisix`) and access to its Admin API | SKIP with the reason (no adapter, not supported, not accessible) | ran | ran | ran |
| 6.4 | sub-test A: the gateway's block message (`gateway_block_body_fragment`; default is Kong's); sub-test B: a gateway adapter | without the message, a blocked endpoint is labelled blocked by the application, not by the gateway (same verdict); without an adapter, sub-test B gives a note and sub-test A still runs | ran | ran | ran (message set) |
| 7.2 | credentials and the injection endpoint keys (and `injection_resource` when the endpoint belongs to an object) | SKIP naming the keys | ran (resource `repository`) | ran (fixed path) | ran (resource `repository`) |
| ext.0.1.nuclei, ext.1.5.testssl, ext.1.5.sslyze | the tool installed | SKIP | ran | not run | not run |

"Ran" means the test reached a verdict (PASS or FAIL), not that the verdict is right: verdict correctness is the
subject of the test review (`OPEN_QUESTIONS.md` Q-29: for example 2.1 counts a `404` as enforced, so a path the
target does not have gives PASS). No test or helper contains Forgejo paths: what is specific to an application (its
login, the objects a test needs, the request that checks a revoked token) is configuration
([`resources`](configuration.md#resources)); the Forgejo values are in the lab configurations.

## Test lab

Three labs, each pinning every image to an exact version, so that an assessment on them can be repeated with the same
target. These are the versions the documentation and the measured results refer to. Each lab has its own ports, so
they can run at the same time.

| Lab | Folder | Configuration | Ports (proxy HTTP, proxy HTTPS, Admin API) |
|---|---|---|---|
| Forgejo + Kong | `test-environments/forgejo-kong/` | `test-environments/forgejo-kong/config.yaml` | 8000, 8443, 8001 (Forgejo directly: 3000) |
| crAPI + Kong | `test-environments/crapi-kong/` | `test-environments/crapi-kong/config.yaml` | 9000, 9443, 9001 (nothing else exposed) |
| Forgejo + APISIX | `test-environments/forgejo-apisix/` | `test-environments/forgejo-apisix/config.yaml` | 10000, 10443, 10001 (Control API: 10002; Forgejo directly: 10003; Admin and Control API on 127.0.0.1 only) |

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

### Forgejo + APISIX

The Forgejo lab's API, users and test resources behind [Apache APISIX](https://apisix.apache.org/), with a gateway
configuration of the same intent as `kong/kong.yml` (`apisix/setup.sh`): only the gateway changes. Added on
2026-10-12.

| Component | Image | Version |
|---|---|---|
| Forgejo (API under test, and the setup container) | `codeberg.org/forgejo/forgejo:14.0.5` | 14.0.5 |
| APISIX (gateway) | `apache/apisix:3.19.0-debian` | 3.19.0 |
| etcd (APISIX configuration store) | `quay.io/coreos/etcd:v3.5.34` | 3.5.34 |
| PostgreSQL (Forgejo database) | `postgres:15.19-alpine` | 15.19 |
| APISIX setup container | `curlimages/curl:8.22.0` | 8.22.0 |

How it was built, and why:

- **Deployment**: APISIX's default (traditional) mode, with etcd, from the official
  [apisix-docker example](https://github.com/apache/apisix-docker/tree/master/example). The standalone modes were
  left out: file-driven standalone has no Admin API, and API-driven standalone keeps the configuration in memory
  only and serves it as one block ([deployment modes](https://github.com/apache/apisix/blob/3.19.0/docs/en/latest/deployment-modes.md)).
- **etcd**: the official image of the etcd project, instead of the example's `bitnamilegacy/etcd`, which is no
  longer maintained.
- **Admin API keys** from `.env` (`${{VAR}}` in `apisix/config.yaml`): `admin` for the setup only, `viewer` (GET
  only, `apisix/admin/init.lua`) for the tool, through `target.admin_api_headers`.
- **Configuration through the Admin API**: APISIX with etcd starts without routes; `apisix-setup` writes the
  certificate, the upstream (timeouts 5/30/30 s, passive checks as in the Kong labs, active check), the `/api`
  route (`redirect` `http_to_https`, `response-rewrite` security headers) and an `hmac-auth` route (`hmac-sha256`,
  `hmac-sha512`, 300 s, body signed), each with `PUT` and a fixed id.
- **Readiness**: the container health check asks the Status API (`/status/ready`, 200 once every worker has the
  configuration from etcd); the image has no curl or wget, so the request is made with bash.
- **Ports**: APISIX listens inside the container on the published ports, because the `redirect` plugin sends HTTP
  requests to the HTTPS port APISIX listens on. The Admin API and the Control API are published on `127.0.0.1` only,
  as the APISIX documentation recommends.
- **`fallback_sni: localhost`**: without it APISIX closes the TLS handshake of a client that sends no server name
  (e.g. `https://127.0.0.1:10443`); Kong answers with its default certificate.

Unavoidable differences from the Kong labs: APISIX's `hmac-auth` has no `hmac-sha384`; APISIX probes healthy nodes
too (interval at least 1 s, here 60 s), where the Kong labs probe only unhealthy targets; an HTTP request other than
GET or HEAD gets a 308 redirect, where Kong answers 301.

Results (2026-10-12, native tests): the same tests, statuses, findings and oracle states as the Forgejo + Kong lab;
every audit read APISIX (concept artifacts with `"adapter": "apisix"`).

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

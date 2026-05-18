**English Version** | [Versione Italiana](README.md)

# APIGuard Assurance

- [Table of Contents](#table-of-contents)
- [1. Value proposition and use cases](#1-value-proposition-and-use-cases)
- [2. Requirements and installation](#2-requirements-and-installation)
- [3. Configuration](#3-configuration)
  - [3.1 `config.yaml` — structural parameters (versionable)](#31-configyaml--structural-parameters-versionable)
  - [3.2 `.env` file — secrets (do not version)](#32-env-file--secrets-do-not-version)
  - [3.3 Configuration validation (without starting an assessment)](#33-configuration-validation-without-starting-an-assessment)
- [4. Practical usage](#4-practical-usage)
  - [Starting an assessment](#starting-an-assessment)
  - [Generating the `path_seed` template](#generating-the-path_seed-template)
  - [Selecting a test subset](#selecting-a-test-subset)
  - [CI/CD pipeline integration](#cicd-pipeline-integration)
- [5. Assessment output](#5-assessment-output)
  - [`evidence.json` — Forensic archive](#evidencejson--forensic-archive)
  - [`assessment_report.html` — Interactive report](#assessment_reporthtml--interactive-report)
- [6. How it works — High-level pipeline](#6-how-it-works--high-level-pipeline)
- [7. Test domains and priorities](#7-test-domains-and-priorities)
- [8. Exit codes](#8-exit-codes)
- [9. Repository structure](#9-repository-structure)
- [Alternative target — cRAPI](#alternative-target--crapi)

**Automated Security Assessment Tool for REST APIs in Cloud Environments**

APIGuard Assurance is a CLI tool for security auditing of REST APIs protected by an API Gateway. It executes the APIGuard methodology — 8 domains, up to 29 verifiable security guarantees — against any target documented with an OpenAPI 3.x or Swagger 2.0 specification, producing an interactive HTML report and a formal, reproducible evidence archive.

> **Are you a contributor or developer?**
> This document is aimed at people who *use* the tool. If you want to understand the internal architecture, data model, or how to add a new test, read **[`docs/pub/ARCHITECTURE.md`](docs/pub/ARCHITECTURE.md)**.

---

## Table of Contents

- [Table of Contents](#table-of-contents)
- [1. Value proposition and use cases](#1-value-proposition-and-use-cases)
- [2. Requirements and installation](#2-requirements-and-installation)
- [3. Configuration](#3-configuration)
  - [3.1 `config.yaml` — structural parameters (versionable)](#31-configyaml--structural-parameters-versionable)
  - [3.2 `.env` file — secrets (do not version)](#32-env-file--secrets-do-not-version)
  - [3.3 Configuration validation (without starting an assessment)](#33-configuration-validation-without-starting-an-assessment)
- [4. Practical usage](#4-practical-usage)
  - [Starting an assessment](#starting-an-assessment)
  - [Generating the `path_seed` template](#generating-the-path_seed-template)
  - [Selecting a test subset](#selecting-a-test-subset)
  - [CI/CD pipeline integration](#cicd-pipeline-integration)
- [5. Assessment output](#5-assessment-output)
  - [`evidence.json` — Forensic archive](#evidencejson--forensic-archive)
  - [`assessment_report.html` — Interactive report](#assessment_reporthtml--interactive-report)
- [6. How it works — High-level pipeline](#6-how-it-works--high-level-pipeline)
- [7. Test domains and priorities](#7-test-domains-and-priorities)
- [8. Exit codes](#8-exit-codes)
- [9. Repository structure](#9-repository-structure)
- [Alternative target — cRAPI](#alternative-target--crapi)

---

## 1. Value proposition and use cases

Manually auditing an API Gateway is slow, hard to reproduce, and subject to systematic omissions. APIGuard Assurance addresses these issues with a formal, deterministic, and documented approach.

**For Security Auditors:**
- Reproducible execution of the same guarantee set on any compatible target: same tests, same order, same output.
- Three privilege levels — Black Box (no credentials), Grey Box (valid JWTs for multiple roles), White Box (Admin API access) — configurable independently to match the engagement perimeter.
- Formal evidence collected automatically: every violation is paired with the full request, full response, and a `record_id` that lets the analyst reproduce the attack with no additional context.
- Interactive HTML report with the complete audit trail of every HTTP transaction executed, PASS included, as coverage proof.

**For development and DevSecOps teams:**
- Native integration into CI/CD pipelines via structured JSON output (`apiguard_report.json`) and semantic exit codes.
- Structured JSON logging (`--log-format json`) compatible with Elasticsearch, Splunk, Datadog, and similar aggregators.
- Zero-secret architecture: credentials never appear in clear text in versioned configuration files.

---

## 2. Requirements and installation

**System requirements:**
- Python 3.11 or higher
- Network access to the target API (Gateway proxy + optional Admin API)

**Development installation (recommended):**

```bash
git clone <repository-url>
cd apiguard-assurance

# Create and activate a virtual environment
python -m venv .venv
source .venv/bin/activate   # Linux/macOS
# .venv\Scripts\activate    # Windows

# Install the package with all runtime dependencies
pip install -e .

# Verify the installation
apiguard version
```

**Alternative: install from a pre-built wheel:**

```bash
# Build the installable wheel into dist/
hatch build --target wheel

# Install the wheel into any virtual environment
pip install dist/apiguard_assurance-*.whl

# Verify
apiguard version
```

The wheel is cross-platform and cross-Python 3 (`py3-none-any`): it works on any system with Python 3.11+. The `dist/` folder is excluded from the repository.

**Installation with development dependencies (for contributors):**

```bash
pip install hatch
hatch env create dev
hatch run dev:pytest -v
```

**Static analysis tools:**

```bash
# Linting and formatting (ruff — replaces flake8 + isort + black)
hatch run dev:ruff check src/
hatch run dev:ruff format src/

# Strict type checking (mypy)
hatch run dev:mypy src/
```

---

## 3. Configuration

The configuration is split into two distinct and deliberately decoupled layers: versionable structural parameters and environment-sourced secrets.

### 3.1 `config.yaml` — structural parameters (versionable)

```yaml
target:
  base_url: "https://my-gateway.example.com:8443"
  openapi_spec_url: "http://my-backend.example.com:3000/swagger.v1.json"
  # Alternative: spec from a local file
  # openapi_spec_path: "./specs/openapi.yaml"
  admin_api_url: "http://my-gateway.example.com:8001"  # omit to disable WHITE_BOX tests
  gateway_adapter: "kong"   # gateway adapter for WHITE_BOX tests; currently only "kong"
  # Optional timeouts for Admin API calls (only relevant when admin_api_url is configured).
  # admin_connect_timeout_seconds: 5.0    # TCP connect timeout — default: 5.0 s (range: 1–30)
  # admin_read_timeout_seconds: 10.0      # HTTP read timeout — default: 10.0 s (range: 1–60)
  verify_tls: false         # true in production; false accepts self-signed certs (lab only)

  # Maps OpenAPI path parameters to real resource identifiers on the target.
  # Generate the template with: apiguard generate-seed <openapi_spec_url>
  path_seed:
    owner: "mario_rossi"
    repo: "my-test-repo"
    id: "1"

credentials:
  # Credentials NEVER appear in clear text here.
  # ${VAR} placeholders are resolved from environment variables at runtime.
  #
  # Token-acquisition strategy for GREY_BOX tests.
  # "forgejo_token" (default): Forgejo/Gitea Token API (POST /users/{u}/tokens).
  # "jwt_login": generic JSON login endpoint (crAPI, Django REST, FastAPI, Rails, etc.).
  auth_type: "forgejo_token"
  admin_username: "${ADMIN_USERNAME}"
  admin_password: "${ADMIN_PASSWORD}"
  user_a_username: "${USER_A_USERNAME}"
  user_a_password: "${USER_A_PASSWORD}"
  user_b_username: "${USER_B_USERNAME}"
  user_b_password: "${USER_B_PASSWORD}"

  # Additional fields required only with auth_type: "jwt_login"
  # login_endpoint: "/identity/api/auth/login"  # path relative to base_url
  # username_body_field: "email"                 # default: "username"
  # password_body_field: "password"              # default: "password"
  # token_response_path: "token"                 # dotted JSONPath — e.g. "data.access_token"

execution:
  min_priority: 3        # 0 = only P0 | 1 = P0+P1 | 2 = P0-P2 | 3 = all (default)
  strategies:
    - BLACK_BOX
    - GREY_BOX
    - WHITE_BOX
  test_ids: []           # list of test_ids to run; empty list = run all (normal behaviour)
  fail_fast: false       # if true, halt at the first FAIL on a P0 test
  connect_timeout: 5.0
  read_timeout: 30.0
  max_retry_attempts: 3
  openapi_fetch_timeout_seconds: 60.0

output:
  directory: "outputs"   # Accepts relative or absolute paths; created if missing

tests:
  # Per-test tuning. The config.yaml included in the repository contains
  # full documentation for every parameter.
  domain_1:
    test_1_1:
      max_endpoints_cap: 0    # 0 = probe every protected endpoint (recommended)
  domain_4:
    test_4_1:
      max_requests: 150       # request budget before declaring rate limit absent
      request_interval_ms: 50

external_tools:
  enabled: true   # false = disable all external tests in one line (useful in CI without binaries)
  testssl:
    enabled: true
    timeout_seconds: 180
    extra_flags: "--quiet --color 0 --connect-timeout 10"
    expected_version: "3.2.3"      # expected binary version; WARNING if it differs, test still runs
    dev_mode: false                # true = use local cache instead of running the binary
  nuclei:
    enabled: true
    timeout_seconds: 240
    template_dir: "./tools/nuclei-templates"
    tags: ["api", "exposure", "misconfig", "panel"]
    per_request_timeout: 10        # per-request HTTP timeout for nuclei (seconds)
    rate_limit_rps: 30             # max req/s — avoids triggering Test 4.1 Rate Limiting
    expected_version: "3.8.0"      # expected binary version; WARNING if it differs, test still runs
    dev_mode: false                # true = use local cache instead of running the binary
  sslyze:
    enabled: true
    timeout_seconds: 60
    dev_mode: false                # true = use local cache instead of running sslyze
```

### 3.2 `.env` file — secrets (do not version)

```bash
# Copy the template and fill in the fields
cp .env.example .env
```

```bash
# .env — local environment variables
ADMIN_USERNAME=thesis-admin
ADMIN_PASSWORD=<admin-password>
USER_A_USERNAME=user-a
USER_A_PASSWORD=<user-a-password>
USER_B_USERNAME=user-b
USER_B_PASSWORD=<user-b-password>
```

The loader (`src/config/loader.py`) performs environment-variable interpolation **before** YAML parsing. An unresolved placeholder (`${MISSING_VAR}`) raises a `ConfigurationError` that names the missing variable explicitly, making diagnosis immediate. Variables already set in the process environment take precedence over the `.env` file (`override=False` behaviour of `load_dotenv`), which makes the tool correct for CI/CD environments that inject secrets via the orchestrator.

### 3.3 Configuration validation (without starting an assessment)

```bash
apiguard validate-config --config config.yaml
```

Runs only Phase 1 (load and validation) and returns exit code 0 if the configuration is valid, 10 otherwise.

---

## 4. Practical usage

### Starting an assessment

```bash
# Standard run (config.yaml in the current working directory)
apiguard run

# Config at an explicit path
apiguard run --config /etc/apiguard/config.yaml

# JSON output for CI/CD — machine-readable logs, no banner
apiguard run --log-format json --no-banner

# Verbose debug: every HTTP transaction is logged individually
apiguard run --log-level debug

# Suppress the banner while keeping human-readable logs (handy in scripts)
apiguard run --no-banner
```

### Generating the `path_seed` template

The `generate-seed` command reads the OpenAPI specification and produces a YAML template with every path parameter (`{owner}`, `{repo}`, `{id}`, etc.) pre-filled with the placeholder `FILL_ME`. Paste the result into the `path_seed` section of `config.yaml` and replace each placeholder with a real value from your target deployment.

```bash
# From an OpenAPI spec URL
apiguard generate-seed http://localhost:3000/swagger.v1.json

# From a local file — writing output to a file
apiguard generate-seed ./specs/forgejo-swagger.v1.json --output seed.yaml

# From a remote URL with extended timeout (default: 30 s)
apiguard generate-seed https://api.example.com/openapi.json --output seed.yaml --timeout 60
```

Without a populated `path_seed`, probes against parametric paths (e.g. `/api/v1/repos/{owner}/{repo}/issues`) receive a `404` before reaching the authentication middleware, producing an oracle state of `INCONCLUSIVE_PARAMETRIC` instead of `ENFORCED` or `BYPASS`.

### Selecting a test subset

Selection happens via `config.yaml`, not via CLI arguments. Two independent and composable mechanisms are available:

**By priority and strategy** — filter by required privilege level:

```yaml
# Black Box tests only — no credentials required
execution:
  min_priority: 0
  strategies:
    - BLACK_BOX

# Only critical P0 tests across all strategies
execution:
  min_priority: 0
  strategies:
    - BLACK_BOX
    - GREY_BOX
    - WHITE_BOX
```

**By specific test_ids** — runs exactly the listed tests, ignoring priority and strategy filters:

```yaml
execution:
  test_ids: ["1.1", "1.4"]            # specific native tests
  test_ids: ["ext.1.5.testssl"]       # external tests only
  test_ids: ["0.1", "ext.0.1.nuclei"] # mix of native and external
  test_ids: []                         # empty list = run all (default behaviour)
```

Native tests use numeric IDs (`"0.1"`, `"1.1"`, etc.); external tests use the `ext.` prefix (`"ext.0.1.nuclei"`, `"ext.1.5.testssl"`, `"ext.1.5.sslyze"`).

### CI/CD pipeline integration

```bash
#!/bin/bash
set -e

apiguard run \
  --config config.yaml \
  --log-format json \
  --no-banner

EXIT_CODE=$?

case $EXIT_CODE in
  0)  echo "CLEAN: no violation detected"; exit 0 ;;
  1)  echo "FAIL: at least one security guarantee is violated"; exit 1 ;;
  2)  echo "ERROR: at least one verification did not complete"; exit 2 ;;
  10) echo "INFRA: infrastructure error, assessment did not complete"; exit 10 ;;
esac
```

---

## 5. Assessment output

At the end of every run, three files are produced in the configured directory (`output.directory`):

| File | Format | Purpose |
|---|---|---|
| `assessment_report.html` | Interactive HTML | Analyst-friendly report with full per-transaction audit trail |
| `evidence.json` | JSON | Forensic archive of FAIL evidence (full reproducible payloads) |
| `apiguard_report.json` | JSON | Structured report for CI/CD, SIEMs, and machine-to-machine integrations |

### `evidence.json` — Forensic archive

Contains a chronologically ordered array of `EvidenceRecord`, one per HTTP transaction that produced a FAIL or that the test explicitly "pinned" as key context. Each record includes:

- Full request (method, URL, headers with `Authorization: [REDACTED]`, body)
- Full response (status code, headers, body truncated to 10,000 chars)
- `record_id` in the format `{test_id}_{sequence}` (e.g. `1.1_005`) — cross-reference key with the HTML report

A single `EvidenceRecord` is enough to reproduce the exact request that triggered the vulnerability without any additional context. This is its design purpose: **every record is self-contained**.

### `assessment_report.html` — Interactive report

The HTML report includes:

- Executive summary with aggregate statistics (PASS/FAIL/SKIP/ERROR, total HTTP requests issued, assessment duration)
- Per-test result table with domain, priority, strategy, CWE, and outcome message
- For every FAIL test: the `Finding` with a specific technical description and standard references (CWE, OWASP)
- Expandable per-test audit trail: a table of every HTTP transaction with oracle state (`ENFORCED`, `BYPASS`, `RATE_LIMIT_HIT`, etc.) and body preview
- Bi-directional cross-referencing: entries marked `is_fail_evidence=true` carry the matching `record_id` from `evidence.json`

---

## 6. How it works — High-level pipeline

The tool executes seven sequential phases for every assessment. Phases 1, 2, and 4 are **blocking**: an error produces exit code 10 without running any test. Phases 5, 6, and 7 are non-blocking.

```
config.yaml + .env
      |
      v
  Phase 1: Initialization      — Loads and validates config.yaml, interpolates env secrets
      |
      v
  Phase 2: OpenAPI Discovery   — Downloads the spec, dereferences $ref, builds the endpoint map
      |
      v
  Phase 3: Context Construction — Creates the three shared runtime objects
      |
      v
  Phase 4: Test Discovery      — Discovers tests dynamically, orders by dependencies (DAG),
      |                          applies priority and strategy filters
      v
  Phase 5: Execution           — Runs every test in topological order, collects TestResults
      |
      v
  Phase 6: Teardown            — Removes (best-effort) the resources created during testing
      |
      v
  Phase 7: Report Generation   — Serialises evidence.json, generates HTML and JSON reports
      |
      v
  Outputs: assessment_report.html  evidence.json  apiguard_report.json
```

> For a detailed description of every phase, including edge cases, in-memory data model, and the `BaseTest.execute()` protocol, see [`docs/pub/ARCHITECTURE.md`](docs/pub/ARCHITECTURE.md).

---

## 7. Test domains and priorities

The APIGuard methodology structures security coverage in 8 thematic domains and 4 priority levels:

| Domain | Name | Currently implemented tests |
|---|---|---|
| 0 | API Discovery and Inventory Management | 0.1 Shadow API Discovery, 0.2 Deny by Default, 0.3 Deprecated API Enforcement; `ext.0.1.nuclei` (template scan) |
| 1 | Identity and Authentication | 1.1 Authentication Required, 1.4 Token Revocation, 1.5 Insecure Credential Transport, 1.6 Secure Session Management; `ext.1.5.testssl`, `ext.1.5.sslyze` (TLS analysis) |
| 2 | Authorization and Access Control | 2.1 RBAC Enforcement |
| 3 | Data Integrity | 3.3 HMAC Config Audit |
| 4 | Availability and Resilience | 4.1 Rate Limiting, 4.2 Timeout Config Audit, 4.3 Circuit Breaker Audit |
| 5 | Visibility and Auditing | — (Milestone 2) |
| 6 | Configuration and Hardening | 6.2 Security Headers Audit, 6.4 Hardcoded Credentials Audit |
| 7 | Business Logic and Sensitive Flows | 7.2 SSRF Prevention |

**Milestone 1 total: 18 active tests** — 15 native (`BaseTest`) + 3 external (`ExternalToolTest` wrapping nuclei / testssl.sh / sslyze). Full status and the M2 roadmap are in [`docs/priv/PROJECT_status.md`](docs/priv/PROJECT_status.md).

| Priority | Label | Typical strategy | Description |
|---|---|---|---|
| P0 | Critical | BLACK_BOX¹ | Fundamental perimeter checks. A FAIL on P0 with `fail_fast: true` aborts the whole assessment |
| P1 | High | GREY_BOX | Authentication and authorisation guarantees with valid credentials |
| P2 | Medium | GREY_BOX | Application logic, data integrity, visibility |
| P3 | Low | WHITE_BOX | Configuration audit via the Gateway's Admin API |

**`min_priority` → included tests mapping:**

| `min_priority` | Included tests |
|---|---|
| `0` | P0 only |
| `1` | P0 + P1 |
| `2` | P0 + P1 + P2 |
| `3` | All — P0 + P1 + P2 + P3 (recommended default) |

> ¹ Most P0 tests use BLACK_BOX. Exception: **7.2 SSRF Prevention** is P0 + GREY_BOX because it requires credentials to create the target resource used as injection vector. Include GREY_BOX in strategies to cover all P0 tests.

---

## 8. Exit codes

| Code | Meaning | Condition |
|---|---|---|
| `0` | CLEAN — No violation detected | All tests produced PASS or SKIP |
| `1` | FAIL — At least one security guarantee is violated | At least one `TestResult(status=FAIL)` in the `ResultSet` |
| `2` | ERROR — At least one verification did not complete | No FAIL, but at least one `TestResult(status=ERROR)` |
| `10` | INFRA — Infrastructure error | `ConfigurationError`, `OpenAPILoadError`, `DAGCycleError` |

Priority is: **FAIL (1) > ERROR (2) > CLEAN (0)**. A single FAIL overrides any number of ERRORs. Exit code 10 means the assessment never started and the `ResultSet` is not a reliable basis for any security judgement.

---

## 9. Repository structure

```
apiguard-assurance/
|-- config.yaml                  # Configuration template (versionable)
|-- config_crapi.yaml            # Alternative configuration for crAPI target (OWASP)
|-- .env.example                 # Environment variable template (do not version .env)
|-- install_tools.sh             # External tool installer (nuclei, testssl.sh)
|-- pyproject.toml               # Project metadata, dependencies, tool configuration
|
|-- src/
|   |-- cli.py                   # CLI entry point (Typer) — 4 commands: run, version, validate-config, generate-seed
|   |-- engine.py                # Pipeline orchestrator — 7 sequential phases
|   |
|   |-- config/                  # Phase 1: configuration loading and validation
|   |-- core/                    # Foundation layer: HTTP client, context, DAG, evidence, models, exceptions
|   |   |-- gateway/             # Gateway adapters (BaseGatewayAdapter + KongGatewayAdapter)
|   |   `-- models/              # Pydantic v2 models: Finding, TestResult, AttackSurface, etc.
|   |-- discovery/               # Phase 2: OpenAPI parsing and AttackSurface construction
|   |-- connectors/              # External tool wrappers (NucleiConnector, TestsslConnector, SslyzeConnector)
|   |-- tests/                   # Native BaseTest implementations per domain (domain_0 ... domain_7)
|   |-- external_tests/          # ExternalToolTest implementations: ext.0.1.nuclei, ext.1.5.testssl/sslyze
|   `-- report/                  # Phase 7: HTML and JSON generation plus statistics aggregation
|
|-- tools/                       # Binaries and templates installed by install_tools.sh
|   |-- nuclei/                  # nuclei binary (pinned version)
|   |-- nuclei-templates/        # nuclei templates (pinned version)
|   `-- testssl/                 # testssl.sh script (pinned version)
|
|-- test-environments/
|   `-- forgejo-kong/            # Docker Compose for the local test environment (Forgejo + Kong)
|
|-- specs/                       # Downloaded or locally provided OpenAPI specifications
`-- docs/pub/                    # Public documentation for contributors
    |-- ARCHITECTURE.md          # Detailed internal architecture
    |-- ADDING_tests.md          # Guide to implementing native tests
    `-- ADDING_external_tests.md # Guide to implementing external tests
```

> The complete map with every single file annotated lives in [`docs/pub/ARCHITECTURE.md`](docs/pub/ARCHITECTURE.md#repository-structure).

---

## Alternative target — cRAPI

`specs/crapi-openapi.json` and `config_crapi.yaml` provide a ready-to-use configuration to run the tool against **crAPI** (Completely Ridiculous API) — a deliberately vulnerable API developed by OWASP.
It is useful to validate the tool against a second target independent from Forgejo/Kong, for instance to demonstrate multi-environment applicability.

```bash
apiguard run -c config_crapi.yaml
```

`config_crapi.yaml` sets `auth_type: "jwt_login"` in the `credentials` section: crAPI exposes a JSON login endpoint (`/identity/api/auth/login`) rather than the Forgejo/Gitea Token API. The field `token_response_path: "token"` extracts the JWT from the login response.

---

*APIGuard Assurance v0.1.0*

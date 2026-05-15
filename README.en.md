**English Version** | [Versione Italiana](README.md)

# APIGuard Assurance

**Automated Security Assessment Tool for REST APIs in Cloud Environments**

APIGuard Assurance is a CLI tool for security auditing of REST APIs protected by an API Gateway. It executes the APIGuard methodology — 8 domains, up to 29 verifiable security guarantees — against any target documented with an OpenAPI 3.x or Swagger 2.0 specification, producing an interactive HTML report and a formal, reproducible evidence archive.

> **Are you a contributor or developer?**
> This document is aimed at people who *use* the tool. If you want to understand the internal architecture, data model, or how to add a new test, read **[`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md)**.

---

## Table of Contents

1. [Value proposition and use cases](#1-value-proposition-and-use-cases)
2. [Requirements and installation](#2-requirements-and-installation)
3. [Configuration](#3-configuration)
4. [Practical usage](#4-practical-usage)
5. [Assessment output](#5-assessment-output)
6. [How it works — High-level pipeline](#6-how-it-works--high-level-pipeline)
7. [Test domains and priorities](#7-test-domains-and-priorities)
8. [Exit codes](#8-exit-codes)
9. [Repository structure](#9-repository-structure)

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
  base_url: "http://localhost:8000"           # Gateway proxy URL
  openapi_spec_url: "http://localhost:3000/swagger.v1.json"
  admin_api_url: "http://localhost:8001"      # Omit to disable WHITE_BOX tests

credentials:
  # Credentials NEVER appear in clear text here.
  # ${VAR} placeholders are resolved from environment variables at runtime.
  admin_username: "${ADMIN_USERNAME}"
  admin_password: "${ADMIN_PASSWORD}"
  user_a_username: "${USER_A_USERNAME}"
  user_a_password: "${USER_A_PASSWORD}"
  user_b_username: "${USER_B_USERNAME}"
  user_b_password: "${USER_B_PASSWORD}"

execution:
  min_priority: 3        # 0 = only P0 | 1 = P0+P1 | 2 = P0-P2 | 3 = all (default)
  strategies:
    - BLACK_BOX
    - GREY_BOX
    - WHITE_BOX
  fail_fast: false       # If true, halt execution at the first FAIL on a P0 test
  connect_timeout: 5.0
  read_timeout: 30.0
  max_retry_attempts: 3
  openapi_fetch_timeout_seconds: 60.0

output:
  directory: "outputs"   # Accepts relative or absolute paths; created if missing

rate_limit_probe:
  max_requests: 150      # Maximum requests for the empirical rate-limit probe
  request_interval_ms: 50

tests:
  domain_1:
    max_endpoints_cap: 0 # 0 = probe every protected endpoint (recommended)
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

### Selecting a test subset

Selection happens via `config.yaml`, not via CLI arguments. Edit the `execution` parameters to narrow the perimeter:

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
  Phase 3: Context Construction — Creates the four runtime objects
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

> For a detailed description of every phase, including edge cases, in-memory data model, and the `BaseTest.execute()` protocol, see [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md).

---

## 7. Test domains and priorities

The APIGuard methodology structures security coverage in 8 thematic domains and 4 priority levels:

| Domain | Name | Currently implemented tests |
|---|---|---|
| 0 | API Discovery and Inventory Management | 0.1 Shadow API, 0.2 Deny by Default, 0.3 Deprecated API Enforcement |
| 1 | Identity and Authentication | 1.1 Authentication Required |
| 2 | Authorization and Access Control | — |
| 3 | Data Integrity | — |
| 4 | Availability and Resilience | — |
| 5 | Visibility and Auditing | — |
| 6 | Configuration and Hardening | — |
| 7 | Business Logic and Sensitive Flows | — |

| Priority | Label | Typical strategy | Description |
|---|---|---|---|
| P0 | Critical | BLACK_BOX | Fundamental perimeter checks. A FAIL on P0 with `fail_fast: true` aborts the whole assessment |
| P1 | High | GREY_BOX | Authentication and authorisation guarantees with valid credentials |
| P2 | Medium | GREY_BOX | Application logic, data integrity, visibility |
| P3 | Low | WHITE_BOX | Configuration audit via the Gateway's Admin API |

**`min_priority` → included tests mapping:**

| `min_priority` | Included tests |
|---|---|
| `0` | P0 only (pure Black Box) |
| `1` | P0 + P1 |
| `2` | P0 + P1 + P2 |
| `3` | All — P0 + P1 + P2 + P3 (recommended default) |

**Selective pytest markers:**

```bash
pytest -m "p0 and domain_0" -v
pytest -m "black_box" -v
```

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
|-- .env.example                 # Environment variable template (do not version .env)
|-- pyproject.toml               # Project metadata, dependencies, tool configuration
|
|-- src/
|   |-- cli.py                   # CLI entry point (Typer)
|   |-- engine.py                # Pipeline orchestrator — 7 sequential phases
|   |
|   |-- config/                  # Phase 1: configuration loading and validation
|   |-- core/                    # Foundation layer — shared vocabulary and infrastructure
|   |-- discovery/               # Phase 2: OpenAPI parsing and AttackSurface construction
|   |-- tests/                   # Phase 5: per-domain test implementations
|   `-- report/                  # Phase 7: HTML and JSON generation plus statistics aggregation
|
|-- test-environments/
|   `-- forgejo-kong/            # Docker Compose for the local test environment
```

> The complete map with every single file annotated lives in [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md#repository-structure).

---

## Alternative target — cRAPI

`specs/crapi-openapi.json` and `config_crapi.yaml` provide a ready-to-use configuration to run the tool against **crAPI** (Completely Ridiculous API) — a deliberately vulnerable API developed by OWASP.
It is useful to validate the tool against a second target independent from Forgejo/Kong, for instance to demonstrate multi-environment applicability.

```bash
apiguard run -c config_crapi.yaml
```

---

*APIGuard Assurance v0.1.0*

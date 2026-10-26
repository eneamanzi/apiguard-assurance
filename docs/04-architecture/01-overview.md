# Architecture Overview

> **Audience:** contributors, integrators who need to understand internals · **Status:** v0.1.0 ·
> **Source of truth:** `src/engine.py` and the modules linked below · **Verified:** 2026-10-15 (pipeline, connections
> and TLS, module graph recomputed), 2026-10-05 (module graph
> computed from imports; behaviours checked in code and, where noted, by execution). The previous Italian version
> of this page is in git history (commit `fd3bd90`, `docs/04-architecture/01-overview.md`).

Related pages: [data model](02-data-model.md) · [assessment model](03-assessment-model.md) · [security model](04-security-model.md).

## Design principles

**Target knowledge comes from configuration and the OpenAPI specification.** The core pipeline does not contain
paths or payloads of a specific application: the attack surface is built at runtime from the spec, and
target-specific values live in `config.yaml`, including what the tool creates on the target and how it logs in
(prepared resources, `src/tests/helpers/resources.py`; design [D6](05-design-decisions.md#d6-prepared-resources)). One exception is
deliberate and isolated:

- **gateway adapters** (`src/core/gateway/`, Kong and APISIX) read the gateway configuration for WHITE_BOX audits.

What each test needs from the target is in [compatibility](../03-reference/06-compatibility.md#test-portability).

**Split state.** What is known before execution (`TargetContext`) is immutable; what tests discover or create
(`TestContext`) is mutable and has a typed interface. A test cannot corrupt the inputs of the others.

**Unidirectional dependencies.** Shared vocabulary in `core/`; everything else depends on it, nothing depends on
`engine.py`.

**Sequential execution.** Tests run one at a time, in a deterministic order. Parallel execution is deliberately not
supported: it keeps the state of `TestContext`, `EvidenceStore` and the result set coherent without locks, and keeps
a run predictable and repeatable. The batches of the dependency graph are the natural unit if it is ever added
([design properties D2.P2](../06-knowledge/08-design-properties.md)).

**The constraints the design answers to** (from the thesis, checked against today's code):

| Constraint | What it means | Where it holds |
|---|---|---|
| Agnosticism | Works on any REST API with an OpenAPI specification without touching the source. | D1.P1; the three labs |
| Traceability | A FAIL of an HTTP test points to the transaction that proves it (`evidence_ref`). The rule is decided; 4.1 and 7.2 do not follow it yet (Q-50). | D4.P1, D5.P1 |
| Prioritisation | A run can be limited to the most important tests (`execution.min_priority`), or stop at the first critical failure (`execution.fail_fast`). | [assessment model](03-assessment-model.md#priorities) |
| Robustness | A test that raises an exception does not stop the others: it returns ERROR. | D4.P3 |
| Cleanliness | What a test creates on the target is removed at the end (teardown, in reverse order). | D4.P6 |
| Reproducibility | The same configuration on the same unchanged target gives the same results. | D3.P4 |

No database or external service is needed at runtime: all state is in memory or in local files
([D3.P5](../06-knowledge/08-design-properties.md)).

## Pipeline

`AssessmentEngine.run()` executes seven sequential phases. One engine instance serves exactly one run
(`run_id` format `apiguard-YYYYMMDD-HHMMSS-ffffff`).

| Phase | What happens | Code | On failure |
|---|---|---|---|
| 1 Initialization | Read YAML as written, resolve `${VAR}` in its values, validate with Pydantic → frozen `ToolConfig` (D9); build the TLS context of each connection (`engine.build_connection_contexts`); then discover the tests and check every declaration (`src/core/test_discovery.py`), the `test_ids` entries and the `tests` section against the parameter models the tests declare (`engine.check_tests`, `src/config/tests_section.py`); write `config_used.yaml`, the configuration the run uses (`src/config/config_used.py`) | `src/config/loader.py`, `src/config/schema/`, `src/config/tests_section.py`, `src/config/config_used.py`, `src/core/tls.py`, `src/engine.py` | `ConfigurationError` or `TestDefinitionError` → exit 10 |
| 2 OpenAPI discovery | Download (with the specification's TLS context) or read the spec, dereference `$ref` (prance, in a worker thread), detect dialect, validate, build `AttackSurface` | `src/discovery/download.py`, `openapi.py`, `surface.py` | `OpenAPILoadError` → exit 10 |
| 3 Context construction | Resolve where and how credentials are sent (credentials + the spec's security schemes); build `TargetContext` (config + surface + credentials + placement + per-test config + gateway adapter), `TestContext`, `EvidenceStore` | `src/engine.py`, `src/core/auth_placement.py`, `src/core/context.py`, `src/core/evidence.py` | `ConfigurationError` (placement not determined) → exit 10 |
| 4 Discovery and scheduling | Discover native and external tests, filter, build dependency batches | `src/tests/registry.py`, `src/external_tests/registry.py`, `src/core/dag.py` | `DAGCycleError` → exit 10 |
| 5 Execution | One preflight request to the API, then run each test sequentially in batch order with one shared `SecurityClient` | `src/engine.py`, `src/tests/`, `src/external_tests/` | preflight: TLS problem → `ConfigurationError`, exit 10; per test: `ERROR` result |
| 6 Teardown | Delete resources registered by tests, in reverse order | `src/engine.py`, `TestContext.drain_resources()` | warning, run continues |
| 7 Reporting | Merge evidence, build report data, render HTML, write JSON | `src/core/evidence.py`, `src/report/` | each step logged, others still run |

Phases 1 to 4 are blocking. Any unexpected exception in the engine also ends the run with exit 10. Phase 6 runs in a
`finally` block, so it also runs on Ctrl+C (exit 130) and on SIGTERM (handled in `src/cli.py` like Ctrl+C, exit 143);
Phase 7 does not run after an interruption. Exit codes:
[`reference/exit-codes.md`](../03-reference/03-exit-codes.md).

### Phase 2 details

- A remote spec is downloaded by the tool (`src/discovery/download.py`: httpx with the context of
  `specification.tls`, redirects followed) and given to prance as text, with its URL as the base of external `$ref`.
  `specification.timeout` applies to the download (httpx timeout) and, separately, to the dereferencing, which runs
  in a background daemon thread because prance fetches external `$ref` itself, without a timeout. When it expires
  the run stops with `OpenAPILoadError` (exit `10`), also when the server accepts the connection and never answers
  (verified 2026-10-07). Relative `$ref` in a
  spec read from a URL are not supported (prance resolves them only for files: "non-file reference"); the message
  says to use a local copy.
- Swagger 2.0 specs are dereferenced with `_NonValidatingResolvingParser`, which skips prance's internal validation
  (it rejects `type: file`); OpenAPI 3.0.x / 3.1.x are validated with `openapi-spec-validator`. `prance` is pinned
  exactly (`==25.4.8.0`) because the parser relies on an internal attribute.
- Protected endpoints are those with a `security` requirement (global or per operation).

### Phase 4 details

- **Native tests:** `src/core/test_discovery.py` imports every module of `src/tests` whose name starts with
  `test_`; a class is a test if it is a concrete `BaseTest` subclass defined in that module whose name does not
  start with `_`, and it must declare its own `info = TestInfo(...)`. A test is never left out silently: a module
  that cannot be imported (an invalid declaration included), a test module in a folder without `__init__.py`, a
  class without `info`, a duplicate ID or an unknown prerequisite stops the run with `TestDefinitionError`
  (exit 10), checked right after Phase 1 (`engine.check_tests`, also run by `validate-config`).
- **External tests:** `ExternalTestRegistry` discovers `ExternalToolTest` subclasses in the same way (modules
  `ext_test_*`, IDs `ext.X.Y.tool`, `info.tool` set), drops those whose tool is
  disabled (they are not scheduled at all), and checks tool availability once per tool: available tools get a
  shared connector instance injected, unavailable ones mark their tests to return SKIP.
- **Filters:** native and external tests by `min_priority` and `strategies`; external tests also by tool
  enablement. `test_ids` replaces the priority and strategy filters (not tool enablement).
- **Scheduling:** native and external tests are merged into one dependency map; `DAGScheduler` uses
  `graphlib.TopologicalSorter`, sorts test IDs inside each batch lexicographically, drops the edges to tests
  not in the run, and detects stalls. In Phase 5 the engine skips a test whose prerequisite is not met
  ([dependencies between tests](03-assessment-model.md#dependencies-between-tests)).

## Module structure and dependencies

```
src/
├── cli.py              Typer CLI: run, validate-config, list-tests, generate-seed, version
├── cli_console.py      Console interface of `run`: implements engine.RunObserver (test lines, summary)
├── engine.py           AssessmentEngine: orchestrates the seven phases
├── config/             Phase 1: loader + Pydantic schema of config.yaml (ToolConfig); tests_section.py checks
│                       `tests:` against the parameter models the tests declare; config_used.py writes
│                       config_used.yaml, the configuration a run used
├── discovery/          Phase 2: spec download and loading, AttackSurface builder, path_seed generator
├── core/               Shared vocabulary and infrastructure
│   ├── models/         Pydantic models (results, evidence, surface, credentials, tool config)
│   ├── client.py       SecurityClient: the only HTTP client for the target API
│   ├── tls.py          TLS context of each connection, TLS failure messages
│   ├── context.py      TargetContext (frozen), TestContext (mutable)
│   ├── auth_placement.py Where and how a credential is sent (header / query / cookie, name, prefix)
│   ├── evidence.py     EvidenceStore (streaming JSONL, merged in Phase 7)
│   ├── dag.py          DAGScheduler
│   ├── gateway/        BaseGatewayAdapter + KongGatewayAdapter, ApisixGatewayAdapter
│   ├── test_metadata.py TestInfo: the declaration of a test (ID formats, priority and domain ranges)
│   ├── assessment_test.py AssessmentTest: base of native and external tests (declaration, parameters,
│   │                   result helpers)
│   ├── test_discovery.py Finds the test classes of a package; any test that cannot be used stops the run
│   └── exceptions.py   Exception hierarchy
├── connectors/         Wrappers around external tools (nuclei, testssl.sh, sslyze)
├── tests/              Native tests (domain_0 … domain_7), helpers/ (incl. the authentication methods), data/
├── external_tests/     Tests that run an external tool through a connector
└── report/             Phase 7: ReportData builder, Jinja2 HTML renderer, template
```

Actual import graph (computed from the source, 2026-10-17):

```
cli                  -> cli_console, config, connectors, core/exceptions, core/models, discovery, engine
cli_console          -> connectors, core/models (engine for types only)
engine               -> config, core/*, discovery, external_tests, report, tests
config               -> core/assessment_test, core/exceptions, core/gateway (the adapter names), core/models,
                        core/test_metadata
discovery            -> core/exceptions, core/models, core/tls
tests                -> core/assessment_test, core/auth_placement, core/client, core/context, core/evidence,
                        core/exceptions, core/gateway, core/models, core/templating, core/test_discovery,
                        core/test_metadata
external_tests       -> connectors, core/assessment_test, core/context, core/evidence, core/exceptions,
                        core/models, core/test_discovery, core/test_metadata
connectors           -> core/exceptions
report               -> config, core/models, core/redaction
core/gateway         -> core/exceptions, core/tls
core/context         -> core/auth_placement, core/gateway, core/models, core/redaction
core/client          -> core/exceptions, core/models, core/redaction, core/tls
core/tls             -> core/exceptions, core/models
core/test_metadata   -> core/models
core/assessment_test -> core/models, core/test_metadata (core/context for types only)
core/test_discovery  -> core/assessment_test, core/exceptions, core/test_metadata
```

Rules that hold today: nothing imports `engine`; `core/` imports nothing outside `core/` and knows no test (the
packages to scan are named by the registries, the parameters reach `TargetContext` by test ID); `tests/` never
imports `config/`, `discovery/`, `report/`, `connectors/` or `external_tests/`; `config/` never imports `tests/`
(the tests' parameter models are passed to it by the engine); `connectors/` depend only on `core/exceptions`.
Native tests must not start subprocesses: running external binaries is the job of connectors used by external
tests. The main rules are checked automatically by `lint-imports` in `hatch run dev:check` (`[tool.importlinter]`
in `pyproject.toml`).

## Components

**SecurityClient** (`src/core/client.py`). Wraps httpx. Usable only as a context manager (the underlying client
is created in `__enter__`; using it outside raises `RuntimeError`). Never follows redirects. Retries only transport
errors (`ConnectError`, `ConnectTimeout`, `ReadTimeout`, `WriteTimeout`, `PoolTimeout`, `RemoteProtocolError`)
with exponential backoff and jitter (0.5 s min, 8 s max, 1 s jitter), up to `target.max_retry_attempts`
attempts; HTTP status codes and TLS failures are never retried. Uses the TLS context of `target.tls`. Each request returns the response and an `EvidenceRecord`
(`record_id` `{test_id}_{NNN}`). Not thread-safe; execution is sequential.

**EvidenceStore** (`src/core/evidence.py`). Three ways in: `add_fail_evidence()` (mandatory for each FAIL
transaction), `pin_evidence()` (key context, e.g. the first `429` in test 4.1), `pin_artifact()` (raw output of an
external tool, sanitised, also copied to `outputs/tools/`). Records are streamed to one JSONL file per test in
`evidence_tmp/` and merged into `evidence.json` in Phase 7. Format:
[`reference/evidence-format.md`](../03-reference/05-evidence-format.md).

**TargetContext / TestContext** (`src/core/context.py`). See [data model](02-data-model.md#runtime-contexts).

**Connections and TLS** (`src/core/tls.py`, `src/core/models/tls.py`). The configuration is organised by connection
(`target`, `specification`, `gateway.admin`, `gateway.health`), each with its optional `tls` block (`TlsSettings`).
In Phase 1 `engine.build_connection_contexts()` builds one `ssl.SSLContext` per connection: the system's store
(`truststore`) plus certifi's list by default, only `ca_bundle` when set, no check with `verify: false`, the client
certificate when set; an unusable file stops the run (exit 10) and warnings are logged (key readable by others,
`tls` on an `http://` URL). The contexts go to `SecurityClient` and `TargetContext.tls_context` (API), the spec
download, and the gateway adapter (Admin API, health interface). `certificate_failure()` turns a failed handshake,
`certificate_answer()` an HTTP 400 page of nginx (client certificate missing or not accepted, plain HTTP to an HTTPS
port), into a message naming the key to set. Before the first test the engine sends one request to the API
(`_preflight`, recorded as test `preflight`): a TLS problem stops the run once (exit 10) instead of failing every
test. The report states how each connection was trusted (`ReportData.connections`, `src/report/builder.py`). Design:
[design decisions D1-D3](05-design-decisions.md#d1-configuration-organised-by-connection); security aspects: [security model](04-security-model.md).

**Gateway adapters** (`src/core/gateway/`). `BaseGatewayAdapter` exposes one reader per neutral concept
(`backend_timeouts`, `circuit_breakers`, `health_checks`, `target_health`, `signing_policies`, `routes`,
`config_values`), each answering with a `ConceptRead` (`src/core/gateway/concepts.py`: read, not supported, or not
accessible), read once per run; a `GatewayAdapterError` becomes "not accessible". The base also holds the
constructor shared by every adapter and the HTTP reads (plain `GET`s, the headers of `gateway.admin.headers` to the
Admin API only, with the TLS contexts of `gateway.admin.tls` and `gateway.health.tls`). `KongGatewayAdapter` translates `/services`, `/upstreams`,
`/upstreams/{name}/health`, `/routes`, `/plugins` of the Kong Admin API (with pagination);
`ApisixGatewayAdapter` translates the APISIX Admin API collections, completed with the defaults of the running
APISIX's schemas, and the Control API `/v1/healthcheck` at `gateway.health.url`. The adapter is chosen from
`GATEWAY_ADAPTERS` (`src/core/gateway/__init__.py`) in Phase 3 when the `gateway` section is set; tests access it as `target.gateway` ([add a gateway
adapter](../02-guides/03-extending/04-add-a-gateway-adapter.md)).

**Connectors** (`src/connectors/`). `BaseConnector` with two tiers: `BaseSubprocessConnector` (nuclei,
testssl.sh; `subprocess.run` with an argument list, no shell) and `BaseLibraryConnector` (sslyze). Binaries are
looked up in `./tools/<tool>/` relative to the working directory, then in `PATH`; if neither has it, the tool's
tests return SKIP. Each connector returns a `ConnectorResult` whose `raw_output` has `command`,
`command_json`, `results`, `all_count`. How to add one:
[`guides/extending/add-an-external-test.md`](../02-guides/03-extending/03-add-an-external-test.md).

**Report** (`src/report/`). `builder.py` turns the `ResultSet` into `ReportData`; `renderer.py` renders the HTML
with Jinja2 (`autoescape` on HTML, `StrictUndefined`); the same `ReportData` is written as `apiguard_report.json`
([`reference/report-schema.md`](../03-reference/04-report-schema.md)).

## Errors

All custom exceptions derive from `ToolBaseError` (`src/core/exceptions.py`, plus two local modules).

<!-- [[[cog import generate_docs as g; cog.out(g.exceptions_table()) ]]] -->

| Exception | Fields | Raised, and what follows |
|---|---|---|
| `ConfigurationError` (`src/core/exceptions.py`) | `variable_name`, `config_path` | The configuration cannot be used: config.yaml invalid, an environment variable unset, a certificate file unusable, credentials that do not determine where they are sent, or no test selected. Raised before any test (Phases 1-4); the run stops with exit 10. |
| `TestDefinitionError` (`src/core/exceptions.py`) | `problems` | A test declared incorrectly (an invalid or missing info, a duplicate ID, an unknown prerequisite, a module that cannot be imported or is outside a package). Raised when the tests are discovered, right after Phase 1; the run stops with exit 10. |
| `OpenAPILoadError` (`src/core/exceptions.py`) | `source_url`, `underlying_error` | The specification cannot be downloaded, read, dereferenced or validated (Phase 2); the run stops with exit 10. |
| `DAGCycleError` (`src/core/exceptions.py`) | `cycle` | A circular dependency among the tests' depends_on (Phase 4); the run stops with exit 10. |
| `SecurityClientError` (`src/core/exceptions.py`) | `method`, `url`, `status_code`, `attempt_count`, `record` | A request to the API failed: a TLS failure, or a transport error after every attempt (target.max_retry_attempts); an HTTP status never raises it. Caught in the test, which returns ERROR. |
| `AuthenticationSetupError` (`src/core/exceptions.py`) | `role`, `status_code` | A role's credential could not be obtained: the login request failed (a status not 2xx) or its response has no credential value. Caught in the test, which returns ERROR. |
| `ExternalToolError` (`src/core/exceptions.py`) | `tool_name`, `exit_code`, `timed_out`, `raw_stderr` | An external tool is present but its run failed (an exit code the connector treats as a failure, a timeout with timed_out, output that cannot be read). Caught in the external test, which returns ERROR. |
| `GatewayAdapterError` (`src/core/gateway/base.py`) | `path`, `status_code` | A request to the gateway's Admin API or health interface failed (transport error or unexpected status). Caught by the adapter's concept readers, which answer "not accessible": the audits then SKIP or add a note. |
| `TeardownError` (`src/core/exceptions.py`) | `resource_method`, `resource_path`, `failed_status_code` | Deleting a resource a test created failed (Phase 6). Logged as a warning (teardown_resource_deletion_failed, manual_cleanup_required=True), never propagated: the resource must be removed by hand. |
| `SeedGeneratorFetchError` (`src/discovery/seed_generator.py`) | `spec_source`, `reason` | apiguard generate-seed cannot retrieve the specification (network failure, HTTP error status, missing local file). Caught by the command, which exits with 1. |
| `SeedGeneratorParseError` (`src/discovery/seed_generator.py`) | `spec_source`, `reason` | apiguard generate-seed cannot parse the retrieved specification (JSON or YAML error, no paths, a root that is not a mapping). Caught by the command, which exits with 1. |

<!-- [[[end]]] -->

A test's `execute()` must always return a `TestResult` and never raise; unexpected exceptions become `ERROR`.

## Teardown

Tests register every persistent resource they create (`context.register_resource_for_teardown(method, path,
headers)`) immediately after creation. Phase 6 replays them in LIFO order through `SecurityClient`; `200`, `204`
and `404` are accepted (404 = already gone). Failures are logged and never stop the cleanup of the rest.

## Packaging

`hatch build` produces a wheel (`py3-none-any`, contains `src/` only) and an sdist (sources, `docs/` except
`docs/06-knowledge/` and `docs/project/`, READMEs, `.env.example`, `install_tools.sh`; not `test-environments/`, so no
configuration file). sslyze is an
optional extra: `pip install "apiguard-assurance[sslyze]"` (AGPL v3, Q-11). External binaries are not packaged:
`install_tools.sh` downloads pinned versions into `tools/`.

# Architecture Overview

> **Audience:** contributors, integrators who need to understand internals · **Status:** v0.1.0 ·
> **Source of truth:** `src/engine.py` and the modules linked below · **Verified:** 2026-10-05 (module graph
> computed from imports; behaviours checked in code and, where noted, by execution). The previous Italian version
> of this page is in git history (commit `fd3bd90`, `docs/architecture/overview.md`).

Related pages: [data model](data-model.md) · [assessment model](assessment-model.md) · [security model](security-model.md).

## Design principles

**Target knowledge comes from configuration and the OpenAPI specification.** The core pipeline does not contain
paths or payloads of a specific application: the attack surface is built at runtime from the spec, and
target-specific values live in `config.yaml`. Two exceptions are deliberate and isolated:

- **gateway adapters** (`src/core/gateway/`, Kong only) read the gateway configuration for WHITE_BOX audits;
- **application helpers** (`src/tests/helpers/auth_forgejo.py`, `forgejo_resources.py`) and some test defaults
  are Forgejo-specific. Which tests depend on them is stated on each [test page](../tests/README.md) (Q-18).

**Split state.** What is known before execution (`TargetContext`) is immutable; what tests discover or create
(`TestContext`) is mutable and has a typed interface. A test cannot corrupt the inputs of the others.

**Unidirectional dependencies.** Shared vocabulary in `core/`; everything else depends on it, nothing depends on
`engine.py`.

## Pipeline

`AssessmentEngine.run()` executes seven sequential phases. One engine instance serves exactly one run
(`run_id` format `apiguard-YYYYMMDD-HHMMSS-ffffff`).

| Phase | What happens | Code | On failure |
|---|---|---|---|
| 1 Initialization | Read YAML, resolve `${VAR}`, validate with Pydantic → frozen `ToolConfig`; then check every test declaration (`src/core/test_metadata.py`) and the `test_ids` entries (`engine.check_tests`) | `src/config/loader.py`, `src/config/schema/`, `src/engine.py` | `ConfigurationError` or `TestDefinitionError` → exit 10 |
| 2 OpenAPI discovery | Fetch or read the spec, dereference `$ref` (prance, in a worker thread), detect dialect, validate, build `AttackSurface` | `src/discovery/openapi.py`, `surface.py` | `OpenAPILoadError` → exit 10 |
| 3 Context construction | Build `TargetContext` (config + surface + credentials + per-test config + gateway adapter), `TestContext`, `EvidenceStore` | `src/engine.py`, `src/core/context.py`, `src/core/evidence.py` | exit 10 |
| 4 Discovery and scheduling | Discover native and external tests, filter, build dependency batches | `src/tests/registry.py`, `src/external_tests/registry.py`, `src/core/dag.py` | `DAGCycleError` → exit 10 |
| 5 Execution | Run each test sequentially in batch order with one shared `SecurityClient` | `src/engine.py`, `src/tests/`, `src/external_tests/` | per test: `ERROR` result |
| 6 Teardown | Delete resources registered by tests, in reverse order | `src/engine.py`, `TestContext.drain_resources()` | warning, run continues |
| 7 Reporting | Merge evidence, build report data, render HTML, write JSON | `src/core/evidence.py`, `src/report/` | each step logged, others still run |

Phases 1 to 4 are blocking. Any unexpected exception in the engine also ends the run with exit 10. Phase 6 runs in a
`finally` block, so it also runs on Ctrl+C (exit 130) and on SIGTERM (handled in `src/cli.py` like Ctrl+C, exit 143);
Phase 7 does not run after an interruption. Exit codes:
[`reference/exit-codes.md`](../reference/exit-codes.md).

### Phase 2 details

- Remote specs are fetched by prance in a background daemon thread with a timeout
  (`execution.openapi_fetch_timeout_seconds`). When it expires the run stops with `OpenAPILoadError` (exit `10`),
  also when the server accepts the connection and never answers (verified 2026-10-07).
- Swagger 2.0 specs are dereferenced with `_NonValidatingResolvingParser`, which skips prance's internal validation
  (it rejects `type: file`); OpenAPI 3.0.x / 3.1.x are validated with `openapi-spec-validator`. `prance` is pinned
  exactly (`==25.4.8.0`) because the parser relies on an internal attribute.
- Protected endpoints are those with a `security` requirement (global or per operation).

### Phase 4 details

- **Native tests:** `pkgutil.walk_packages` over `src/tests`, importing modules whose name starts with `test_`.
  A module that fails to import is logged as a warning and skipped. A class is a test if it is a concrete
  `BaseTest` subclass defined in that module with all required metadata.
- **External tests:** `ExternalTestRegistry` discovers `ExternalToolTest` subclasses, drops those whose tool is
  disabled (they are not scheduled at all), and checks tool availability once per tool: available tools get a
  shared connector instance injected, unavailable ones mark their tests to return SKIP.
- **Filters:** native and external tests by `min_priority` and `strategies`; external tests also by tool
  enablement. `test_ids` replaces the priority and strategy filters (not tool enablement).
- **Scheduling:** native and external tests are merged into one dependency map; `DAGScheduler` uses
  `graphlib.TopologicalSorter`, sorts test IDs inside each batch lexicographically, removes dependencies on
  filtered-out tests with a warning, and detects stalls.

## Module structure and dependencies

```
src/
├── cli.py              Typer CLI: run, validate-config, generate-seed, version
├── engine.py           AssessmentEngine: orchestrates the seven phases
├── config/             Phase 1: loader + Pydantic schema of config.yaml (ToolConfig)
├── discovery/          Phase 2: spec loading, AttackSurface builder, path_seed generator
├── core/               Shared vocabulary and infrastructure
│   ├── models/         Pydantic models (results, evidence, surface, credentials, tool config)
│   ├── client.py       SecurityClient: the only HTTP client for the target API
│   ├── context.py      TargetContext (frozen), TestContext (mutable)
│   ├── evidence.py     EvidenceStore (streaming JSONL, merged in Phase 7)
│   ├── dag.py          DAGScheduler
│   ├── gateway/        BaseGatewayAdapter + KongGatewayAdapter
│   └── exceptions.py   Exception hierarchy
├── connectors/         Wrappers around external tools (nuclei, testssl.sh, sslyze)
├── tests/              Native tests (domain_0 … domain_7), helpers/, data/ (payloads, wordlists)
├── external_tests/     Tests that run an external tool through a connector
├── report/             Phase 7: ReportData builder, Jinja2 HTML renderer, template
└── test_config/        Per-test parameter models (one per test, by domain) + RuntimeTestsConfig
```

Actual import graph (computed from the source):

```
cli            -> config, core/exceptions, discovery, engine
engine         -> config, core/*, discovery, external_tests, report, test_config, tests
config         -> core/exceptions, core/models, test_config
discovery      -> core/exceptions, core/models
tests          -> core/client, core/context, core/evidence, core/exceptions, core/gateway, core/models, test_config
external_tests -> connectors, core/context, core/evidence, core/exceptions, core/models
connectors     -> core/exceptions
report         -> config, core/models
core/gateway   -> core/exceptions
core/context   -> test_config (only to type TargetContext.tests_config)
test_config    -> nothing from src/
```

Rules that hold today: nothing imports `engine`; `test_config/` is the lowest layer and imports nothing from
`src/`; `tests/` never imports `config/`, `discovery/`, `report/`,
`connectors/` or `external_tests/`; `connectors/` depend only on `core/exceptions`. Native tests must not start
subprocesses: running external binaries is the job of connectors used by external tests. The main rules are
checked automatically by `lint-imports` in `hatch run dev:check` (`[tool.importlinter]` in `pyproject.toml`).

## Components

**SecurityClient** (`src/core/client.py`). Wraps httpx. Usable only as a context manager (the underlying client
is created in `__enter__`; using it outside raises `RuntimeError`). Never follows redirects. Retries only transport
errors (`ConnectError`, `ConnectTimeout`, `ReadTimeout`, `WriteTimeout`, `PoolTimeout`, `RemoteProtocolError`)
with exponential backoff and jitter (0.5 s min, 8 s max, 1 s jitter), up to `execution.max_retry_attempts`
attempts; HTTP status codes are never retried. Each request returns the response and an `EvidenceRecord`
(`record_id` `{test_id}_{NNN}`). Not thread-safe; execution is sequential.

**EvidenceStore** (`src/core/evidence.py`). Three ways in: `add_fail_evidence()` (mandatory for each FAIL
transaction), `pin_evidence()` (key context, e.g. the first `429` in test 4.1), `pin_artifact()` (raw output of an
external tool, sanitised, also copied to `outputs/tools/`). Records are streamed to one JSONL file per test in
`evidence_tmp/` and merged into `evidence.json` in Phase 7. Format:
[`reference/evidence-format.md`](../reference/evidence-format.md).

**TargetContext / TestContext** (`src/core/context.py`). See [data model](data-model.md#runtime-contexts).

**Gateway adapters** (`src/core/gateway/`). `BaseGatewayAdapter` exposes read-only methods: `check_connectivity`,
`get_routes`, `get_plugins`, `get_services`, `get_upstreams`, `get_plugin_by_name`, `get_status`.
`KongGatewayAdapter` calls `/routes`, `/plugins`, `/services`, `/upstreams`, `/status` on the Admin API with plain
`GET`s, follows pagination, raises `GatewayAdapterError` on transport errors or non-200 status. It sends no
credentials and always verifies TLS (Q-34). It is created in Phase 3 only when `target.gateway_adapter: kong` and
`target.admin_api_url` are set; tests access it as `target.gateway`.

**Connectors** (`src/connectors/`). `BaseConnector` with two tiers: `BaseSubprocessConnector` (nuclei,
testssl.sh; `subprocess.run` with an argument list, no shell) and `BaseLibraryConnector` (sslyze). Binaries are
looked up in `./tools/<tool>/` relative to the working directory, then in `PATH`; if neither has it, the tool's
tests return SKIP. Each connector returns a `ConnectorResult` whose `raw_output` has `command`,
`command_json`, `results`, `all_count`. How to add one:
[`guides/extending/add-an-external-test.md`](../guides/extending/add-an-external-test.md).

**Report** (`src/report/`). `builder.py` turns the `ResultSet` into `ReportData`; `renderer.py` renders the HTML
with Jinja2 (`autoescape` on HTML, `StrictUndefined`); the same `ReportData` is written as `apiguard_report.json`
([`reference/report-schema.md`](../reference/report-schema.md)).

## Errors

All custom exceptions derive from `ToolBaseError` (`src/core/exceptions.py`, plus two local modules).

| Exception | Fields | Raised in | Handling |
|---|---|---|---|
| `ConfigurationError` | `variable_name`, `config_path` | Phase 1; `test_ids` check right after it | exit 10 |
| `TestDefinitionError` | `problems` | test check right after Phase 1 (`engine.check_tests`, both registries) | exit 10 |
| `OpenAPILoadError` | `source_url`, `underlying_error` | Phase 2 | exit 10 |
| `DAGCycleError` | `cycle` | Phase 4 | exit 10 |
| `SecurityClientError` | `method`, `url`, `status_code`, `attempt_count` | `SecurityClient` | caught in the test → `ERROR` (some tests skip the single probe) |
| `AuthenticationSetupError` | `role`, `status_code` | `tests/helpers/auth*.py` | caught in the test → `ERROR` |
| `ExternalToolError` | `tool_name`, `exit_code`, `timed_out`, `raw_stderr` | connectors | caught in the external test → `ERROR` |
| `GatewayAdapterError` (`src/core/gateway/base.py`) | `path`, `status_code` | gateway adapter | caught in the test → `ERROR` |
| `TeardownError` | `resource_method`, `resource_path`, `failed_status_code` | Phase 6 | warning with `manual_cleanup_required=True`, not propagated |
| `SeedGeneratorFetchError`, `SeedGeneratorParseError` (`src/discovery/seed_generator.py`) | `spec_source`, `reason` | `generate-seed` only | exit 1 |

A test's `execute()` must always return a `TestResult` and never raise; unexpected exceptions become `ERROR`.

## Teardown

Tests register every persistent resource they create (`context.register_resource_for_teardown(method, path,
headers)`) immediately after creation. Phase 6 replays them in LIFO order through `SecurityClient`; `200`, `204`
and `404` are accepted (404 = already gone). Failures are logged and never stop the cleanup of the rest.

## Packaging

`hatch build` produces a wheel (`py3-none-any`, contains `src/` only) and an sdist (sources, `docs/` except
`docs/knowledge/` and `docs/project/`, READMEs, `config.yaml`, `.env.example`, `install_tools.sh`). sslyze is an
optional extra: `pip install "apiguard-assurance[sslyze]"` (AGPL v3, Q-11). External binaries are not packaged:
`install_tools.sh` downloads pinned versions into `tools/`.

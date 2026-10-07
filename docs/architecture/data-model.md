# Data Model

> **Audience:** contributors · **Status:** v0.1.0 · **Source of truth:** `src/core/models/` (exports in
> `src/core/models/__init__.py`), `src/core/context.py`, `src/report/builder.py`, `src/config/schema/` ·
> **Verified:** 2026-10-05

All shared data structures are Pydantic v2 models. `src/core/models/` is the shared vocabulary; it depends only on
the standard library, Pydantic and structlog.

## Three sources of truth

| Concern | Object | Lives | Purpose |
|---|---|---|---|
| Logic | `ResultSet` | memory, during the run | collects every `TestResult`, computes the exit code |
| Forensics | `EvidenceStore` | `evidence_tmp/*.jsonl` → `evidence.json` | complete transactions that prove FAILs, pinned context, tool artefacts |
| Presentation | `ReportData` | memory, Phase 7 | DTO rendered to HTML and serialised to `apiguard_report.json` |

## Results

```
ResultSet
└── results: [TestResult]
      ├── status: PASS | FAIL | SKIP | ERROR
      ├── message, skip_reason, duration_ms (set by the engine after execute())
      ├── metadata copied from the test class: test_id, test_name, domain, priority, strategy, cwe_id, tags, source, tool_name
      ├── findings: [Finding]           title, detail, references, evidence_ref ──► EvidenceRecord.record_id
      ├── notes: [InfoNote]             title, detail, references (context, not a violation)
      └── transaction_log: [TransactionSummary]   every HTTP request of the test (PASS included)
```

Invariants enforced by the model (`src/core/models/results.py`):

| Status | Rule |
|---|---|
| `FAIL` | at least one `Finding` |
| `PASS` | no `Finding` (notes allowed) |
| `SKIP` | `skip_reason` required |
| `ERROR` | findings optional |

`ResultSet.compute_exit_code()`: any FAIL → 1, else any ERROR → 2, else 0.

## Dual audit trail

| | `TransactionSummary` | `EvidenceRecord` |
|---|---|---|
| Where | `TestResult.transaction_log`, embedded in both reports | `evidence.json` |
| Which transactions | all | FAIL evidence, pinned, tool artefacts |
| Request body | truncated to 2,000 chars | as sent (JSON bodies only) |
| Response body | preview, 1,000 chars | up to 10,000 chars |
| Extra | `oracle_state`, `is_fail_evidence` | full response headers |

Both redact the `authorization` header (validator on `EvidenceRecord`; the summary is built from the record).
`record_id` links them. Field-level formats: [`reference/evidence-format.md`](../reference/evidence-format.md),
[`reference/report-schema.md`](../reference/report-schema.md).

## Attack surface

Built in Phase 2 from the specification (`src/discovery/surface.py`):

| Model | Content |
|---|---|
| `AttackSurface` | `spec_title`, `spec_version`, `dialect` (`swagger_2`, `openapi_3`), `endpoints`; helpers `get_authenticated_endpoints()`, `get_public_endpoints()`, `get_deprecated_endpoints()`, `get_endpoints_by_method()` |
| `EndpointRecord` | `path` (must start with `/`), `method` (uppercased), `operation_id`, `tags`, `requires_auth`, `is_deprecated`, `parameters`, `request_body_required`, `request_body_content_types` |
| `ParameterInfo` | `name`, `location` (`path`, `query`, `header`, `cookie`), `required`, `schema_type`, `schema_format` |

## Runtime contexts

**`TargetContext`** (`src/core/context.py`, frozen) is built once in Phase 3 and passed to every test:

| Field | Content |
|---|---|
| `base_url`, `openapi_spec_url` / `openapi_spec_path`, `admin_api_url`, admin timeouts | from `target.*` |
| `attack_surface` | from Phase 2 |
| `credentials` | `RuntimeCredentials` (never to be logged) |
| `tests_config` | `RuntimeTestsConfig`: one `RuntimeTest<XY>Config` per configurable test |
| `path_seed`, `verify_tls` | from `target.*` |
| `external_tools` | `ExternalToolsConfig` |
| `gateway` | `BaseGatewayAdapter` instance, or `None` |

Helpers: `endpoint_base_url()` and `admin_endpoint_base_url()` (string URLs without trailing slash),
`admin_api_available` (= `gateway is not None`), `get_openapi_source()`, `is_local_spec`.

**`TestContext`** (mutable) holds what tests create during the run, behind a typed API:

| Channel | Methods | Notes |
|---|---|---|
| Tokens | `set_token(role, token)`, `get_token`, `has_token`, `stored_roles` | roles `admin`, `user_a`, `user_b`; tokens stored without the `Bearer ` prefix |
| Teardown | `register_resource_for_teardown(method, path, headers)`, `drain_resources()`, `registered_resource_count` | LIFO; drained in Phase 6 |
| Shared data | `set_shared(key, value)`, `get_shared`, `has_shared`, `shared_keys` | convention `"{test_id}.{name}"` |

## Configuration: two layers

Test parameters exist twice on purpose:

1. **Schema layer** (`src/config/schema/domain_<D>.py`): `Test<XY>Config` models validate `config.yaml`
   (`tests.domain_<D>.test_<D>_<N>`).
2. **Runtime layer** (`src/core/models/runtime.py`): `RuntimeTest<XY>Config`, copied by the engine in Phase 3 into
   `TargetContext.tests_config` and read by tests as `target.tests_config.test_<D>_<N>`.

Tests depend on `core/` only, so they never import the config schema. The cost is that adding a parameter touches
both layers and the engine wiring (see [`guides/extending/add-a-native-test.md`](../guides/extending/add-a-native-test.md)).
External tools have a single layer: `src/core/models/external_tools.py`, re-exported by
`src/config/schema/external_tools.py`.

## Report models

`src/report/builder.py`: `ReportData` → `ExecutiveSummary`, `DomainSummary` (rows split into native and external),
`TestResultRow` (a flattened `TestResult` plus `domain_name`, `priority_label`, external-tool artefact fields).
`output_schema_version` versions this structure. Field reference:
[`reference/report-schema.md`](../reference/report-schema.md).

## Exported models

`src/core/models/__init__.py` exports: `TestStatus`, `TestStrategy`, `SpecDialect`, `EvidenceRecord`,
`TransactionSummary`, `ParameterInfo`, `EndpointRecord`, `AttackSurface`, `Finding`, `InfoNote`, `TestResult`,
`ResultSet`, `RuntimeCredentials`, the thirteen `RuntimeTest<XY>Config` classes, `RuntimeTestsConfig`,
`BaseExternalToolConfig`, `TestsslConfig`, `NucleiConfig`, `ExternalToolsConfig`. (`SslyzeConfig` exists in
`external_tools.py` but is not exported from the package.)

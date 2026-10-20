# Data Model

> **Audience:** contributors · **Status:** v0.1.0 · **Source of truth:** `src/core/models/` (exports in
> `src/core/models/__init__.py`), `src/core/context.py`, `src/report/builder.py`, `src/config/schema/` ·
> **Verified:** 2026-10-15 (TargetContext fields, from `src/core/context.py`), 2026-10-05

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
      ├── declaration copied from the test's info (TestInfo): test_id, test_name, domain, priority, strategy, cwe_id, tags, tool_name; source
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

`ResultSet.compute_exit_code()`: any FAIL → 1, else any ERROR → 3, else 0 (`ExitCode` in
`src/core/models/enums.py`, the single definition of the codes).

## Dual audit trail

| | `TransactionSummary` | `EvidenceRecord` |
|---|---|---|
| Where | `TestResult.transaction_log`, embedded in both reports | `evidence.json` |
| Which transactions | all | FAIL evidence, pinned, tool artefacts |
| Request body | truncated to 2,000 chars | as sent (JSON bodies only) |
| Response body | preview, 1,000 chars | up to 10,000 chars |
| Extra | `oracle_state`, `is_fail_evidence` | full response headers |

Both carry the redacted values (`src/core/redaction.py`: at capture in `SecurityClient`, again in Phase 7; the
`EvidenceRecord` validator replaces any raw `authorization`; the summary is built from the record).
`record_id` links them. Field-level formats: [`reference/evidence-format.md`](../03-reference/05-evidence-format.md),
[`reference/report-schema.md`](../03-reference/04-report-schema.md).

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
| `base_url` | from `target.*` |
| `openapi_spec_url` / `openapi_spec_path` | from `specification.url` / `specification.path` |
| `admin_api_url` | from `gateway.admin.url` |
| `attack_surface` | from Phase 2 |
| `credentials` | `RuntimeCredentials` (never to be logged) |
| `resources` | the prepared resources of `resources`, by name |
| `credential_placement` | where and how credentials are sent (`src/core/auth_placement.py`), or `None` without credentials |
| `test_params` | every test's validated parameters, by test ID (the instance of the model its class names); a test reads its own with `self.params(target)` |
| `path_seed` | from `target.*` |
| `tls_context` | the `ssl.SSLContext` of the API connection, built at startup from `target.tls` (`src/core/tls.py`); the same trust as `SecurityClient`, for a test that opens its own connection (1.5's HTTP probe) |
| `tls_ca_bundle` | the path of `target.tls.ca_bundle`, or `None`: given to the external TLS tools |
| `external_tools` | `ExternalToolsConfig` |
| `gateway` | `BaseGatewayAdapter` instance, or `None` |

Helpers: `endpoint_base_url()` and `admin_endpoint_base_url()` (string URLs without trailing slash),
`admin_api_available` (= `gateway is not None`), `get_openapi_source()`, `is_local_spec`.

**`TestContext`** (mutable) holds what tests create during the run, behind a typed API:

| Channel | Methods | Notes |
|---|---|---|
| Tokens | `set_token(role, token)`, `get_token`, `has_token`, `stored_roles` | roles `admin`, `user_a`, `user_b`; the credential as the method obtained it, without any prefix (the placement adds it: `src/core/auth_placement.py`) |
| Teardown | `register_resource_for_teardown(method, path, headers)`, `drain_resources()`, `registered_resource_count` | LIFO; drained in Phase 6 |
| Shared data | `set_shared(key, value)`, `get_shared`, `has_shared`, `shared_keys` | convention `"{test_id}.{name}"` |

## Test parameters: declared by the test

A test with tunable values declares **one** model in its own module, `Test<D><N>Params` (frozen, with its
constraints and validators), and names it in its class declaration: `class Test21RbacEnforcement(BaseTest[Test21Params])`
(`src/core/assessment_test.py`, block 10b decision 6.2). A test without parameters writes `BaseTest` alone. The
same model:

1. validates the `tests.domain_<D>.test_<D>_<N>` section of `config.yaml`: once the tests are discovered, right
   after Phase 1 (`engine.check_tests`, also run by `validate-config`), `src/config/tests_section.py` builds one
   model of the whole section from the declared models and validates it, so an unknown test or parameter is
   reported like any unknown key, with the closest name. A model may check its values against the prepared
   resources, which it receives in the validation context (test 7.2);
2. reaches the test unchanged: the validated instances are stored by test ID in `TargetContext.test_params`, and
   the test reads its own with `self.params(target)`, typed as its model (mypy checks every parameter name). A
   test cannot read another test's parameters through it.

All models are frozen: a test cannot reassign a parameter. List parameters are tuples (`config.yaml` still uses
YAML lists), so their content cannot change either; test helpers receive them as `Sequence[...]`. The only
container left mutable is `test_7_2.url_accepting_endpoint.body` (a dict): test 7.2 only ever uses a copy of it.

Before block 10b the models lived apart from the tests, in `src/test_config/` (and before 2026-10 every parameter was
defined twice); the parameters of tests 3.3 and 4.3 that described Kong's plugins are now the Kong adapter's
knowledge (decision 6.6).
External-tool models live in `src/core/models/external_tools.py`, on purpose: they configure the tools (the
`external_tools` section: switches, timeouts, binary flags), not the parameters of a single test, and they are used
by `core` (`TargetContext`), the connectors and the external registry (owner decision 2026-10-09, Q-63).

## Report models

`src/report/builder.py`: `ReportData` → `ExecutiveSummary`, `DomainSummary` (rows split into native and external),
`TestResultRow` (a flattened `TestResult` plus `domain_name`, `priority_label`, external-tool artefact fields).
`tool_version` is the version of this structure (no separate format version, [compatibility](../03-reference/06-compatibility.md#interface-stability)). Field reference:
[`reference/report-schema.md`](../03-reference/04-report-schema.md).

## Exported models

`src/core/models/__init__.py` exports: `TestStatus`, `TestStrategy`, `SpecDialect`, `EvidenceRecord`,
`TransactionSummary`, `ParameterInfo`, `EndpointRecord`, `AttackSurface`, `Finding`, `InfoNote`, `TestResult`,
`ResultSet`, `RuntimeCredentials`,
`BaseExternalToolConfig`, `TestsslConfig`, `NucleiConfig`, `ExternalToolsConfig`. (`SslyzeConfig` exists in
`external_tools.py` but is not exported from the package.)

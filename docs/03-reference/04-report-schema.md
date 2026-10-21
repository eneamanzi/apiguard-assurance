# Report Schema (`apiguard_report.json`)

> **Audience:** integrators · **Status:** stable (contract: [compatibility](06-compatibility.md#interface-stability)) · **Source of truth:**
> `src/report/builder.py` (`ReportData` and nested models), `src/core/models/results.py`,
> `src/core/models/http.py` · **Verified:** 2026-10-15 (`connections`, real output of the three labs), 2026-10-05,
> v0.1.0 (models + real output of a Forgejo + Kong run)

`apiguard_report.json` is the machine-readable result of an assessment: the same data that renders
`assessment_report.html`, serialised with `ReportData.model_dump_json()`. It is written in Phase 7 to
`output.directory` whenever the pipeline reaches Phase 7 - i.e. for exit codes `0`, `1`, `3`; **not** for
`2` (invalid invocation), `10` or an interrupted run ([`exit-codes.md`](03-exit-codes.md)).

## Versioning

The file has no format version of its own: `tool_version` is the version of the output formats, with the policy in
[compatibility](06-compatibility.md#interface-stability) (a breaking change raises the major, the minor before
1.0.0). Until 2026-10 the file also had `output_schema_version` (`"1.0"`, set arbitrarily); it was removed (Q-25).

## Top level - `ReportData`

<!-- [[[cog import generate_docs as g; cog.out(g.report_table("ReportData")) ]]] -->

| Field | Type | Description |
|---|---|---|
| `tool_version` | string | APIGuard version that produced the report: the version of this format (see Versioning above). |
| `run_id` | string | Identifier of the run: `apiguard-YYYYMMDD-HHMMSS-ffffff`. |
| `generated_at_utc` | string | Generation time, ISO 8601 in UTC with `+00:00` offset (e.g. `2026-10-08T09:12:57.870747+00:00`), like `generated_at_utc` in `evidence.json`. The HTML report shows it in the reader's local time zone (UTC value in the tooltip). |
| `target_base_url` | string | `target.base_url` of the configuration. |
| `spec_title` | string | `info.title` of the OpenAPI specification. |
| `spec_version` | string | `info.version` of the OpenAPI specification. |
| `min_priority_label` | string | Label of `execution.min_priority`: one of `P0 — Critical`, `P1 — High`, `P2 — Medium`, `P3 — Low`. |
| `strategies_label` | string | Enabled strategies, comma-separated (`BLACK_BOX, GREY_BOX, WHITE_BOX`). |
| `connections` | array of [`ConnectionTrust`](#connectiontrust) | How the certificate of each connection of the tool was checked. |
| `executive_summary` | [`ExecutiveSummary`](#executivesummary) | Counts and verdict of the run. |
| `domains` | array of [`DomainSummary`](#domainsummary) | The results by methodology domain, ordered by domain; domains without active tests are omitted. |
| `all_rows` | array of [`TestResultRow`](#testresultrow) | Every test result, ordered by `test_id` as text. |
| `not_run` | array of [`NotRunEntry`](#notrunentry) | The tests of the tool not executed in this run, ordered by `test_id` as text. `all_rows` + `not_run` = every test of the tool. |

<!-- [[[end]]] -->

The same `TestResultRow` objects appear both in `domains[].rows` and in `all_rows`; read one or the other.

## `ConnectionTrust`

One entry per connection, in this order: `target`, `specification`, then `gateway.admin` and `gateway.health` when
configured. The HTML report shows them under "Certificate checks", a not verified one in red.

<!-- [[[cog import generate_docs as g; cog.out(g.report_table("ConnectionTrust")) ]]] -->

| Field | Type | Description |
|---|---|---|
| `name` | string | `target`, `specification`, `gateway.admin` or `gateway.health`. |
| `url` | string | The connection's URL (the API's with a trailing `/`), or the specification's absolute file path. |
| `certificate_check` | `verified_system` \| `verified_ca_bundle` \| `not_verified` \| `plain_http` \| `local_file` | `verified_system` (the system's authorities plus certifi's list), `verified_ca_bundle` (only the configured `ca_bundle`), `not_verified` (`verify: false`: the run did not know whether it talked to the right server), `plain_http` (no TLS), `local_file` (the specification was read from a file). |
| `client_certificate` | bool | `true` when the tool presented a client certificate (mutual TLS). |

<!-- [[[end]]] -->

Example (Forgejo + APISIX lab):

```json
"connections": [
  {"name": "target", "url": "https://localhost:10443/", "certificate_check": "verified_ca_bundle", "client_certificate": false},
  {"name": "specification", "url": "https://localhost:10443/swagger.v1.json", "certificate_check": "verified_ca_bundle", "client_certificate": false},
  {"name": "gateway.admin", "url": "https://127.0.0.1:10001/", "certificate_check": "verified_ca_bundle", "client_certificate": true},
  {"name": "gateway.health", "url": "http://127.0.0.1:10002/", "certificate_check": "plain_http", "client_certificate": false}
]
```

## `ExecutiveSummary`

<!-- [[[cog import generate_docs as g; cog.out(g.report_table("ExecutiveSummary")) ]]] -->

| Field | Type | Description |
|---|---|---|
| `scheduled_tests` | int | PASS + FAIL + INCONCLUSIVE + ERROR + SKIP. |
| `executed_tests` | int | PASS + FAIL + INCONCLUSIVE + ERROR (SKIP excluded). |
| `pass_count` | int | Results with status PASS. |
| `fail_count` | int | Results with status FAIL. |
| `inconclusive_count` | int | Results with status INCONCLUSIVE. |
| `skip_count` | int | Results with status SKIP. |
| `error_count` | int | Results with status ERROR. |
| `not_run_count` | int | Number of entries in `not_run`. |
| `total_finding_count` | int | Findings of every result: FAIL results, and ERROR results that carry some. |
| `exit_code` | int | Same value as the process exit code. |
| `exit_code_label` | string | Label and meaning of the exit code (exit-codes.md), e.g. `FAIL - at least one security guarantee is violated`. |
| `pass_rate_pct` | number | `pass_count / executed_tests × 100`, one decimal; `0.0` when nothing executed. |
| `assessment_duration_seconds` | number \| null | Wall-clock duration of the run. |

<!-- [[[end]]] -->

## `NotRunEntry`

A test of the tool that the run did not execute. It is not a result: a SKIP was selected and missed a
precondition, a not-run test was not selected or was stopped (`src/core/models/results.py`).

<!-- [[[cog import generate_docs as g; cog.out(g.report_table("NotRunEntry")) ]]] -->

| Field | Type | Description |
|---|---|---|
| `test_id` | string | The test's ID. |
| `test_name` | string | The test's name. |
| `source` | `native` \| `external` | `native` or `external`. |
| `reason` | string | `priority` (above `min_priority`), `strategy` (not in `strategies`), `not_in_test_ids` (`test_ids` set and not listing it), `tool_disabled` (external tool or master switch off), `fail_fast` (the run stopped earlier). |
| `detail` | string | The values that excluded it, e.g. `priority P2 is above execution.min_priority (P1)`, `external_tools.enabled is false`, `execution.fail_fast: the run stopped after 0.1 returned FAIL`. |

<!-- [[[end]]] -->

## `DomainSummary`

<!-- [[[cog import generate_docs as g; cog.out(g.report_table("DomainSummary")) ]]] -->

| Field | Type | Description |
|---|---|---|
| `domain` | int | Methodology domain, 0-7. |
| `domain_name` | string | Name of the domain (see Domain names below). |
| `rows` | array of [`TestResultRow`](#testresultrow) | The results of this domain. |
| `pass_count` | int | Results with status PASS. |
| `fail_count` | int | Results with status FAIL. |
| `inconclusive_count` | int | Results with status INCONCLUSIVE. |
| `skip_count` | int | Results with status SKIP. |
| `error_count` | int | Results with status ERROR. |
| `total_finding_count` | int | Findings of the results of this domain. |
| `native_rows` | array of [`TestResultRow`](#testresultrow) | `rows` of the native tests. |
| `external_rows` | array of [`TestResultRow`](#testresultrow) | `rows` of the external tests. |

<!-- [[[end]]] -->

## `TestResultRow`

<!-- [[[cog import generate_docs as g; cog.out(g.report_table("TestResultRow")) ]]] -->

| Field | Type | Description |
|---|---|---|
| `test_id` | string | `X.Y` (native) or `ext.X.Y.tool` (external). |
| `test_name` | string | Human-readable name. |
| `domain` | int | Methodology domain, 0-7. |
| `domain_name` | string | Name of the domain. |
| `priority` | int | Priority, 0-3. |
| `priority_label` | string | Label of the priority (as `min_priority_label`). |
| `strategy` | string | `BLACK_BOX`, `GREY_BOX` or `WHITE_BOX`. |
| `status` | string | `PASS`, `FAIL`, `INCONCLUSIVE`, `SKIP` or `ERROR` (see Status semantics below). |
| `coverage` | string \| null | For a `PASS`: `complete`, or `partial` when cases were not verifiable. |
| `sub_tests` | array of [`SubTestResult`](#subtestresult) | Every declared sub-test with its counters and status. |
| `message` | string | One-line outcome. |
| `skip_reason` | string \| null | Set only for `SKIP`: the missing precondition. |
| `duration_ms` | number \| null | Execution time of the test. |
| `finding_count` | int | Length of `findings`. |
| `findings` | array of [`Finding`](#finding) | At least one for `FAIL`, none for `PASS` and `INCONCLUSIVE` (enforced by the model); an `ERROR` result may carry findings collected before the error. |
| `tags` | array of string | Test tags (e.g. `OWASP-API9:2023`). |
| `cwe_id` | string | Primary CWE (e.g. `CWE-306`). |
| `transaction_log` | array of [`TransactionSummary`](#transactionsummary) | Every HTTP request of the test, PASS included. |
| `notes` | array of [`InfoNote`](#infonote) | Informational context that is not a violation (e.g. a compensating control), on any status. |
| `source` | `native` \| `external` | `native` or `external`. |
| `tool_name` | string | External tool name (e.g. `nuclei`); empty for native tests. |
| `tool_artifact` | object \| null | External tests only: the tool's raw output (`command`, `command_json`, `results`, `all_count`, plus `_apiguard_meta_*` keys). |
| `tool_artifact_label` | string \| null | External tests only: label of the tool output, the external test's ID (e.g. `ext.0.1.nuclei`). |
| `tool_artifact_record_id` | string \| null | External tests only: `record_id` of the tool output in `evidence.json`. |

<!-- [[[end]]] -->

### Status semantics

| Status | Meaning | Exit-code effect |
|---|---|---|
| `PASS` | No violation, at least one case verified; `coverage` says whether every applicable case was verified (`complete`) or some could not be (`partial`). | none |
| `FAIL` | Guarantee violated; at least one finding. | → `1` |
| `INCONCLUSIVE` | Run to the end, no violation, nothing verified: every judged case was not verifiable (the sub-tests give the reasons). | → `3` if no FAIL |
| `ERROR` | The verification did not complete (transport failure, rejected credentials, tool failure). Findings may be present. | → `3` if no FAIL |
| `SKIP` | A precondition is missing (credentials, Admin API, tool disabled), or nothing the test applies to. `skip_reason` explains which. | none |

`PASS`, `FAIL` and `INCONCLUSIVE` are computed from the sub-tests, never chosen by the test: a sub-test with a
violation is `FAIL`; otherwise one with a verified case is `PASS`; otherwise one with a case not verifiable is
`INCONCLUSIVE`; otherwise `SKIP`. The test is `FAIL` if a sub-test is, otherwise `PASS` (partial if another
sub-test is `INCONCLUSIVE` or a `PASS` sub-test is partial) if a sub-test is, otherwise `INCONCLUSIVE` if a sub-test
is, otherwise `SKIP`.

## `SubTestResult`

<!-- [[[cog import generate_docs as g; cog.out(g.report_table("SubTestResult")) ]]] -->

| Field | Type | Description |
|---|---|---|
| `name` | string | The sub-test's name, as the test declares it. |
| `status` | string | `PASS`, `FAIL`, `INCONCLUSIVE` or `SKIP`, computed from the counters. |
| `coverage` | string \| null | For a PASS: `complete`, or `partial` when cases were not verifiable. |
| `violations` | int | Cases judged `VIOLATION`. |
| `enforced` | int | Cases judged `ENFORCED`. |
| `not_verifiable` | int | Cases judged `NOT_VERIFIABLE`. |
| `not_applicable` | int | Cases judged `NOT_APPLICABLE`. |
| `not_verifiable_reasons` | object | Why cases were not verifiable: each detail and how many times. |

<!-- [[[end]]] -->

## `Finding`

<!-- [[[cog import generate_docs as g; cog.out(g.report_table("Finding")) ]]] -->

| Field | Type | Description |
|---|---|---|
| `title` | string | Short description of the violation. |
| `detail` | string | Technical description, specific enough to reproduce. |
| `references` | array of string | Standards, e.g. `CWE-1059`, `OWASP-API9:2023`, `NIST-SP-800-204-S3.1`. |
| `evidence_ref` | string \| null | `record_id` of the proof in `evidence.json`. |

<!-- [[[end]]] -->

## `InfoNote`

<!-- [[[cog import generate_docs as g; cog.out(g.report_table("InfoNote")) ]]] -->

| Field | Type | Description |
|---|---|---|
| `title` | string | What the analyst should know (e.g. a compensating control, a skipped sub-check). |
| `detail` | string | The context, in full. |
| `references` | array of string | Standards. |

<!-- [[[end]]] -->

## `TransactionSummary`

<!-- [[[cog import generate_docs as g; cog.out(g.report_table("TransactionSummary")) ]]] -->

| Field | Type | Description |
|---|---|---|
| `record_id` | string | `{test_id}_{NNN}`; matches a record in `evidence.json` when `is_fail_evidence` is `true`. |
| `timestamp_utc` | string, ISO 8601 UTC | Dispatch time. |
| `request_method` | string | HTTP method of the request. |
| `request_url` | string | Full URL of the request. |
| `response_status_code` | int \| null | HTTP status of the response; null when no response arrived. |
| `transport_error` | string \| null | Why no response arrived (as in the evidence record); null otherwise. |
| `category` | string \| null | What the response is, common to every test (`SERVED`, `NOT_FOUND`, `UNAUTHENTICATED`, ...). |
| `sub_test` | string \| null | The sub-test the request belongs to; null for a preparation step. |
| `outcome` | string \| null | What the response means for the guarantee (`VIOLATION`, `ENFORCED`, `NOT_VERIFIABLE`, `NOT_APPLICABLE`); null when the request is not judged (a login, an object created for the test). |
| `detail` | string \| null | The test's detail of the outcome, e.g. `AUTH_BYPASS`, `PATH_NOT_FOUND`; read with the outcome as `VIOLATION/AUTH_BYPASS`. Null with a null outcome. |
| `duration_ms` | number \| null | Duration of the request. |
| `is_fail_evidence` | bool | The transaction is FAIL evidence: the full record is in `evidence.json`. |
| `request_headers` | object | Lowercase names; `authorization` and cookie values redacted with typed placeholders (see the evidence format). |
| `request_body` | string \| null | Request body, truncated to 2,000 characters; null without a body. |
| `response_body_preview` | string \| null | Response body, truncated to 1,000 characters; null without a body. |

<!-- [[[end]]] -->

## Domain names

<!-- [[[cog import generate_docs as g; cog.out(g.domain_names_table()) ]]] -->

| `domain` | `domain_name` |
|---|---|
| 0 | API Discovery and Inventory Management |
| 1 | Identity and Authentication |
| 2 | Authorization and Access Control |
| 3 | Data Integrity |
| 4 | Availability and Resilience |
| 5 | Visibility and Auditing |
| 6 | Configuration and Hardening |
| 7 | Business Logic and Sensitive Flows |

<!-- [[[end]]] -->

## Example (abridged, real run)

```json
{
  "tool_version": "0.1.0",
  "run_id": "apiguard-20261005-150711-021280",
  "executive_summary": {
    "scheduled_tests": 18, "executed_tests": 16,
    "pass_count": 9, "fail_count": 7, "skip_count": 2, "error_count": 0,
    "total_finding_count": 98, "exit_code": 1, "pass_rate_pct": 56.2
  },
  "all_rows": [
    {
      "test_id": "0.1", "status": "FAIL", "source": "native",
      "findings": [{
        "title": "Shadow API endpoint detected (undocumented active path)",
        "references": ["CWE-1059", "OWASP-API9:2023", "NIST-SP-800-204-S3.1"],
        "evidence_ref": "0.1_002"
      }]
    }
  ]
}
```

## See also

- [`evidence-format.md`](05-evidence-format.md)
- [`exit-codes.md`](03-exit-codes.md)
- *planned:* `guides/integration/consume-the-report.md`

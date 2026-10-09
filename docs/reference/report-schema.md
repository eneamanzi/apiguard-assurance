# Report Schema (`apiguard_report.json`)

> **Audience:** integrators · **Status:** stable (`output_schema_version` 1.0) · **Source of truth:**
> `src/report/builder.py` (`ReportData` and nested models), `src/core/models/results.py`,
> `src/core/models/http.py` · **Verified:** 2026-10-05, v0.1.0 (models + real output of a Forgejo + Kong run)

`apiguard_report.json` is the machine-readable result of an assessment: the same data that renders
`assessment_report.html`, serialised with `ReportData.model_dump_json()`. It is written in Phase 7 to
`output.directory` whenever the pipeline reaches Phase 7 - i.e. for exit codes `0`, `1`, `3`; **not** for
`2` (invalid invocation), `10` or an interrupted run ([`exit-codes.md`](exit-codes.md)).

## Versioning

`output_schema_version` identifies the structure of this file, independently of `tool_version` and of the
assessed API's version. Policy declared in `src/report/builder.py:322-327`: bump the **major** for removed or
renamed fields, the **minor** for added optional fields. Check the major before parsing.

## Top level - `ReportData`

| Field | Type | Description |
|---|---|---|
| `output_schema_version` | string | Schema version, currently `"1.0"`. |
| `tool_version` | string | APIGuard version that produced the report. |
| `run_id` | string | `apiguard-YYYYMMDD-HHMMSS-ffffff`. |
| `generated_at_utc` | string, ISO 8601 UTC | Generation time, UTC with `+00:00` offset (e.g. `2026-10-08T09:12:57.870747+00:00`), like `generated_at_utc` in `evidence.json`. The HTML report shows it in the reader's local time zone (UTC value in the tooltip). |
| `target_base_url` | string | `target.base_url`. |
| `spec_title`, `spec_version` | string | `info.title` and `info.version` of the OpenAPI spec. |
| `min_priority_label` | string | One of `P0 — Critical`, `P1 — High`, `P2 — Medium`, `P3 — Low`. |
| `strategies_label` | string | Enabled strategies, comma-separated (`BLACK_BOX, GREY_BOX, WHITE_BOX`). |
| `executive_summary` | object | [`ExecutiveSummary`](#executivesummary). |
| `domains` | array | [`DomainSummary`](#domainsummary), ordered by domain; domains without active tests are omitted. |
| `all_rows` | array | Every [`TestResultRow`](#testresultrow), ordered by `test_id`. |
| `not_run` | array | Every [`NotRunEntry`](#notrunentry): the tests of the tool not executed in this run, ordered by `test_id`. `all_rows` + `not_run` = every test of the tool. |

The same `TestResultRow` objects appear both in `domains[].rows` and in `all_rows`; read one or the other.

## `ExecutiveSummary`

| Field | Type | Description |
|---|---|---|
| `scheduled_tests` | int | PASS + FAIL + ERROR + SKIP. |
| `executed_tests` | int | PASS + FAIL + ERROR (SKIP excluded). |
| `pass_count`, `fail_count`, `skip_count`, `error_count` | int | Counts per status. |
| `not_run_count` | int | Number of entries in `not_run`. |
| `total_finding_count` | int | Findings across all FAIL results. |
| `exit_code` | int | Same value as the process exit code. |
| `exit_code_label` | string | `CLEAN — No violations detected`, `FAIL — At least one security guarantee violated`, `ERROR — At least one verification incomplete`. |
| `pass_rate_pct` | float | `pass_count / executed_tests × 100`, one decimal; `0.0` when nothing executed. |
| `assessment_duration_seconds` | float \| null | Wall-clock duration. |

## `NotRunEntry`

A test of the tool that the run did not execute. It is not a result: a SKIP was selected and missed a
precondition, a not-run test was not selected or was stopped (`src/core/models/results.py`).

| Field | Type | Description |
|---|---|---|
| `test_id`, `test_name` | string | The test. |
| `source` | string | `native` or `external`. |
| `reason` | string | `priority` (above `min_priority`), `strategy` (not in `strategies`), `not_in_test_ids` (`test_ids` set and not listing it), `tool_disabled` (external tool or master switch off), `fail_fast` (the run stopped earlier). |
| `detail` | string | The values that excluded it, e.g. `priority P2 is above execution.min_priority (P1)`, `external_tools.enabled is false`, `execution.fail_fast: the run stopped after 0.1 returned FAIL`. |

## `DomainSummary`

| Field | Type | Description |
|---|---|---|
| `domain` | int | 0-7. |
| `domain_name` | string | See [domain names](#domain-names). |
| `rows` | array | `TestResultRow` of this domain. |
| `native_rows`, `external_rows` | array | `rows` split by `source`. |
| `pass_count`, `fail_count`, `skip_count`, `error_count`, `total_finding_count` | int | Per-domain counts. |

## `TestResultRow`

| Field | Type | Description |
|---|---|---|
| `test_id` | string | `X.Y` (native) or `ext.X.Y.tool` (external). |
| `test_name` | string | Human-readable name. |
| `domain`, `domain_name` | int, string | Methodology domain. |
| `priority`, `priority_label` | int, string | 0-3 and its label. |
| `strategy` | string | `BLACK_BOX`, `GREY_BOX`, `WHITE_BOX`. |
| `status` | string | `PASS`, `FAIL`, `SKIP`, `ERROR`. |
| `message` | string | One-line outcome. |
| `skip_reason` | string \| null | Set only for `SKIP`. |
| `duration_ms` | float \| null | Execution time of the test. |
| `finding_count` | int | Length of `findings`. |
| `findings` | array | [`Finding`](#finding). At least one for `FAIL`, none for `PASS` (both enforced by the model); an `ERROR` result may carry findings collected before the error. |
| `notes` | array | [`InfoNote`](#infonote): informational context that is not a violation. |
| `tags` | array of string | Test tags (e.g. `OWASP-API9:2023`). |
| `cwe_id` | string | Primary CWE (e.g. `CWE-306`). |
| `transaction_log` | array | [`TransactionSummary`](#transactionsummary): every HTTP request of the test, PASS included. |
| `source` | string | `native` or `external`. |
| `tool_name` | string | External tool name; empty for native tests. |
| `tool_artifact` | object \| null | External tests only: raw connector output (`command`, `command_json`, `results`, `all_count`, plus `_apiguard_meta_*` keys). |
| `tool_artifact_label` | string \| null | External tests only: artefact label. |
| `tool_artifact_record_id` | string \| null | External tests only: `record_id` of the artefact in `evidence.json`. |

### Status semantics

| Status | Meaning | Exit-code effect |
|---|---|---|
| `PASS` | Guarantee verified. | none |
| `FAIL` | Guarantee violated; at least one finding. | → `1` |
| `ERROR` | The verification did not complete (transport failure, rejected credentials, tool failure). Findings may be present. | → `3` if no FAIL |
| `SKIP` | A precondition is missing (credentials, Admin API, tool disabled, nothing applicable in the spec). `skip_reason` explains which. | none |

## `Finding`

| Field | Type | Description |
|---|---|---|
| `title` | string | Short description of the violation. |
| `detail` | string | Technical description, specific enough to reproduce. |
| `references` | array of string | Standards, e.g. `CWE-1059`, `OWASP-API9:2023`, `NIST-SP-800-204-S3.1`. |
| `evidence_ref` | string \| null | `record_id` in [`evidence.json`](evidence-format.md). |

## `InfoNote`

| Field | Type | Description |
|---|---|---|
| `title`, `detail` | string | Context the analyst should know (e.g. a compensating control, a skipped sub-check). |
| `references` | array of string | Standards. |

## `TransactionSummary`

| Field | Type | Description |
|---|---|---|
| `record_id` | string | `{test_id}_{NNN}`; matches a record in `evidence.json` when `is_fail_evidence` is `true`. |
| `timestamp_utc` | string, ISO 8601 UTC | Dispatch time. |
| `request_method`, `request_url` | string | Request line. |
| `request_headers` | object | Lowercase names; `authorization` is `[REDACTED]`. |
| `request_body` | string \| null | Truncated to 2,000 characters. |
| `response_status_code` | int | HTTP status. |
| `response_body_preview` | string \| null | Truncated to 1,000 characters. |
| `oracle_state` | string \| null | Test-specific classification of the response (e.g. `ENFORCED`, `BYPASS`, `RATE_LIMIT_HIT`, `INCONCLUSIVE_PARAMETRIC`). Free-form: each test defines its own values. |
| `duration_ms` | float \| null | Duration of the request. |
| `is_fail_evidence` | bool | The transaction is FAIL evidence; the full record is in `evidence.json`. |

## Domain names

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

## Example (abridged, real run)

```json
{
  "output_schema_version": "1.0",
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

- [`evidence-format.md`](evidence-format.md)
- [`exit-codes.md`](exit-codes.md)
- *planned:* `guides/integration/consume-the-report.md`

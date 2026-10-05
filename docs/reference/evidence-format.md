# Evidence Format (`evidence.json`)

> **Audience:** analysts, integrators · **Status:** stable · **Source of truth:** `src/core/models/http.py`
> (`EvidenceRecord`), `src/core/evidence.py` (`EvidenceStore`) · **Verified:** 2026-10-05, v0.1.0 (models +
> real output of a Forgejo + Kong run)

`evidence.json` is the forensic archive of an assessment: the complete HTTP transactions that prove each FAIL,
plus transactions a test explicitly marked as key context ("pinned") and the raw output of external tools.
Every record is self-contained: it is enough to reproduce the request without other context.

It does **not** contain every transaction. The full list of requests (PASS included) is the
`transaction_log` of each test in [`apiguard_report.json`](report-schema.md), with truncated bodies.

## File structure

```json
{
  "generated_at_utc": "2026-10-05T15:12:00.503550+00:00",
  "record_count": 152,
  "records": [ { ...EvidenceRecord... } ]
}
```

| Key | Type | Description |
|---|---|---|
| `generated_at_utc` | string, ISO 8601 UTC | When the file was written (Phase 7). |
| `record_count` | int | Number of records. |
| `records` | array | Records sorted by `timestamp_utc`. Empty array if no evidence was collected. |

## `EvidenceRecord`

| Field | Type | Description |
|---|---|---|
| `record_id` | string | Unique ID. HTTP records: `{test_id}_{NNN}` (e.g. `1.1_005`), counter per test. External-tool artefacts: `artifact-{test_id}-{label}-{HHMMSSffffff}`. |
| `timestamp_utc` | string, ISO 8601 UTC (`Z`) | When the request was dispatched. |
| `request_method` | string | Uppercase HTTP method. For artefacts: the uppercased test ID (e.g. `EXT.0.1.NUCLEI`). |
| `request_url` | string | Full URL. For artefacts: `external://{test_id}/{label}`. |
| `request_headers` | object | Lowercase header names. `authorization` is always `[REDACTED]`. |
| `request_body` | string \| null | Body as sent, only when the request carried JSON; `null` otherwise. |
| `response_status_code` | int | HTTP status. `0` for artefacts. |
| `response_headers` | object | Lowercase header names. |
| `response_body` | string \| null | Body truncated to 10,000 characters + `... [TRUNCATED]`. Undecodable bodies become `[Binary or undecodable response body]`. For artefacts: the tool's raw output as JSON text, with credentials sanitised. |
| `is_pinned` | bool | `true` for pinned transactions and artefacts; `false` for FAIL evidence. |
| `elapsed_ms` | float \| null | Duration of the HTTP transaction including retry waits. `null` for artefacts. |

## Cross-references

```
apiguard_report.json                                  evidence.json
  all_rows[].findings[].evidence_ref  ──────────────►  records[].record_id
  all_rows[].transaction_log[].record_id
      (when is_fail_evidence = true)  ──────────────►  records[].record_id
  all_rows[].tool_artifact_record_id  ──────────────►  records[].record_id  (artefact)
```

## Lifecycle

1. During execution each test streams its records to `output.directory/evidence_tmp/<test_id>.jsonl`
   (dots replaced by underscores: `1.1` → `1_1.jsonl`; one JSON object per line, flushed immediately).
2. In Phase 7 all files are merged, sorted by timestamp, written to `evidence.json`, and `evidence_tmp/` is
   deleted.
3. If the process is killed before Phase 7, `evidence_tmp/` remains: the `.jsonl` files are the evidence
   collected up to that point.

A copy of each external tool's raw output is also written to `output.directory/tools/<label>_output.json`.

## Sensitive data

- The `authorization` request header is replaced with `[REDACTED]` by the model itself, whoever builds the
  record. No other header is redacted (e.g. `cookie`, custom API-key headers).
- Request and response bodies are stored as sent and received, without sanitisation: if the target returns
  secrets in a response body, they are in this file.
- Token acquisition requests made by the authentication helpers (`src/tests/helpers/auth_*.py`) are not
  recorded as evidence.
- External-tool artefacts are sanitised for credentials before being stored.

Treat `evidence.json` as sensitive.

## See also

- [`report-schema.md`](report-schema.md)
- *planned:* `guides/usage/read-the-report.md`

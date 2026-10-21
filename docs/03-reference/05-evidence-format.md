# Evidence Format (`evidence.json`)

> **Audience:** analysts, integrators · **Status:** stable · **Source of truth:** `src/core/models/http.py`
> (`EvidenceRecord`), `src/core/evidence.py` (`EvidenceStore`) · **Verified:** 2026-10-05, v0.1.0 (models +
> real output of a Forgejo + Kong run)

`evidence.json` is the forensic archive of an assessment: the complete HTTP transactions that prove each FAIL,
plus transactions a test explicitly marked as key context ("pinned") and the raw output of external tools.
Every record is self-contained: it is enough to reproduce the request without other context.

It does **not** contain every transaction. The full list of requests (PASS included) is the
`transaction_log` of each test in [`apiguard_report.json`](04-report-schema.md), with truncated bodies.

## File structure

```json
{
  "tool_version": "0.1.0",
  "generated_at_utc": "2026-10-05T15:12:00.503550+00:00",
  "record_count": 152,
  "records": [ { ...EvidenceRecord... } ]
}
```

<!-- [[[cog import generate_docs as g; cog.out(g.evidence_table("EvidenceFile")) ]]] -->

| Field | Type | Description |
|---|---|---|
| `tool_version` | string | APIGuard version that wrote the file: the version of this format. |
| `generated_at_utc` | string | When the file was written (Phase 7), ISO 8601 in UTC with `+00:00` offset. |
| `record_count` | int | Number of records. |
| `records` | array of [`EvidenceRecord`](#evidencerecord) | Records sorted by `timestamp_utc`; empty when no evidence was collected. |

<!-- [[[end]]] -->

The version policy of `tool_version`: [compatibility](06-compatibility.md#interface-stability).

## `EvidenceRecord`

<!-- [[[cog import generate_docs as g; cog.out(g.evidence_table("EvidenceRecord")) ]]] -->

| Field | Type | Description |
|---|---|---|
| `record_id` | string | Unique ID. HTTP records: `{test_id}_{NNN}` (e.g. `1.1_005`), a counter per test. Tool outputs: `artifact-{test_id}-{label}-{HHMMSSffffff}`. |
| `timestamp_utc` | string, ISO 8601 UTC | When the request was dispatched. |
| `request_method` | string | HTTP method, uppercase. For a tool output: its label uppercased, the external test's ID (e.g. `EXT.0.1.NUCLEI`). |
| `request_url` | string | Full URL. For a tool output: `external://{test_id}/{label}`. |
| `request_headers` | object | Lowercase header names; `authorization`, cookie values and the registered secrets replaced with typed placeholders (see Sensitive data below). |
| `request_body` | string \| null | The JSON body as sent, with the registered secrets replaced; null when the request carried no JSON body. |
| `response_status_code` | int \| null | HTTP status; `0` for a tool output; null when no response arrived (`transport_error` says why). |
| `transport_error` | string \| null | Why no response arrived: `timeout`, `connection_failed`, `tls_error`, `protocol_error`; null when a response arrived. |
| `response_headers` | object | Lowercase header names. |
| `response_body` | string \| null | Body truncated to 10,000 characters + `... [TRUNCATED]`; an undecodable body becomes `[Binary or undecodable response body]`. For a tool output: the tool's raw output as JSON, credentials removed, truncated the same way (the full output is in `tools/<label>_output.json`). |
| `is_pinned` | bool | `true` for a transaction a test marked as key context and for a tool output; `false` for FAIL evidence. |
| `elapsed_ms` | number \| null | Duration (ms) of the HTTP transaction, retry waits included; null for a tool output. |

<!-- [[[end]]] -->

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

Rule: only secret **values** are hidden, never what proves a finding, and the placeholder says what was hidden
(`src/core/redaction.py`, `SecretRegistry`).

| What | Becomes | Why the value is not needed as proof |
|---|---|---|
| `authorization` (any request) | `[REDACTED: <label>]`: `user_a token`, `admin token`, `admin Basic credentials`, `1.4 temporary token, last 8: 3dcb8f05`; an unregistered value: `[REDACTED: <scheme> credentials]` | the proof is the response; the label keeps who made the request |
| token created by test 1.4 (anywhere, e.g. the `sha1` of the creation response) | `[REDACTED: 1.4 temporary token, last 8: <last 8 characters>]` | the last 8 characters (as Forgejo's `token_last_eight`) correlate create, revoke and reuse |
| webhook secret generated by test 7.2 | `[REDACTED: 7.2 webhook secret]` | generated by the tool; the proof is the accepted URL |
| `cookie`, `set-cookie` | each value `[REDACTED]`, cookie names and attributes (`Secure`, `HttpOnly`, `SameSite`, ...) kept | test 1.6 judges the attributes |
| a fixed probe value a test sends as `authorization` on purpose (test 1.1: `Bearer null`, `Bearer undefined`, ...) | kept in clear, prefixed: `[public probe] Bearer null` | not a secret; it is what the transaction tested (the HTML "copy as cURL" drops the prefix) |
| any other header, request and response bodies, URLs | unchanged, except the registered secrets above | a body is often the proof itself (e.g. 6.4) |

Redaction is applied when the transaction is captured (so known secrets never reach the temporary files written
during the run) and again when the outputs are written in Phase 7 (secrets learned after their capture, such as a
token in the response that creates it). The `EvidenceRecord` model replaces any `authorization` value that is not
already a placeholder with `[REDACTED]`, whoever builds the record. Values shorter than 8 characters are never
registered as secrets. Passwords never appear in the outputs.
- Token acquisition requests made by the authentication helpers (`src/tests/helpers/auth_*.py`) are not
  recorded as evidence.
- External-tool artefacts are sanitised for credentials before being stored.

Treat `evidence.json` as sensitive.

## See also

- [`report-schema.md`](04-report-schema.md)
- [`guides/usage/read-the-report.md`](../02-guides/01-usage/03-read-the-report.md)

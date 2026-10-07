# Read the Report

> **Audience:** users, analysts · **Status:** v0.1.0 · **Source of truth:** `src/report/builder.py`,
> `src/report/templates/report.html`, `src/core/evidence.py`, `src/core/models/results.py` · **Verified:** 2026-10-06
> on lab runs (native tests only; `ext.1.5.sslyze` only); every command below was run on their output

How to go from the exit code to the proof of each violation. Field-by-field descriptions are in the
[report schema](../../reference/report-schema.md) and the [evidence format](../../reference/evidence-format.md).

Previous page: [Select tests](select-tests.md).

## What a run produces

In `outputs/` (or `output.directory`), replacing the files of the previous run:

| File | For | Content |
|---|---|---|
| `assessment_report.html` | people | interactive report: summary, filters, one card per test |
| `apiguard_report.json` | programs, and you with `jq` | the same data, machine-readable |
| `evidence.json` | proof | the full HTTP transactions behind the findings, and the raw output of the external tools |
| `tools/<test>_output.json` | external tests | raw output of each tool (e.g. `tools/ext_1_5_sslyze_output.json`) |

If the run was interrupted with `Ctrl+C`, none of these is written and only `evidence_tmp/` remains (Q-44).

**`evidence.json` is sensitive.** Response bodies are stored as received: if the API returns secrets, they are in
this file. Only the `Authorization` header is redacted.

## 1. The verdict

The exit code of `apiguard run` is the overall verdict ([exit codes](../../reference/exit-codes.md)):

| Exit | Meaning |
|---|---|
| `0` | every executed test passed (SKIPs do not count) |
| `1` | at least one test FAILED: a security guarantee is violated |
| `2` | no FAIL, but at least one test could not complete (ERROR) |
| `10` | the assessment did not run (configuration, unreachable specification): **no verdict, not "clean"** |

The executive summary gives the counts:

```bash
jq '.executive_summary' outputs/apiguard_report.json
```

`executed_tests` excludes the SKIPs, and `pass_rate_pct` is `pass_count / executed_tests`.

## 2. The outcome of each test

```bash
jq -r '.all_rows[] | "\(.test_id)\t\(.status)\t\(.finding_count)\t\(.message)"' outputs/apiguard_report.json
```

| Status | What it tells you | What to do |
|---|---|---|
| `FAIL` | the guarantee is violated; at least one finding | read the findings (step 3) |
| `PASS` | the guarantee holds **for what the test covers** | check the test page for what it does not cover |
| `SKIP` | a precondition was missing; `skip_reason` says which | not a pass: provide the precondition or accept the gap |
| `ERROR` | the check did not complete; the message says why | fix the cause (URL, credentials, tool) and run again |

A test filtered out by the [selection](select-tests.md) does not appear at all.

Each test can also carry **InfoNotes** (`notes`): context that is not a violation, such as a sub-check that could
not run or something to verify by hand. Read them for PASS results too.

## 3. From a finding to its proof

Each finding has a title, a detail and, for most tests, an `evidence_ref`: the ID of the transaction that proves it,
stored in `evidence.json`. Example on the lab, test 1.1:

```bash
jq -r '.all_rows[] | select(.test_id=="1.1") | .findings[] | "\(.evidence_ref)  \(.title)"' outputs/apiguard_report.json
```

```
1.1_054  Protected endpoint accessible without authentication
1.1_056  Protected endpoint accessible without authentication
...
```

Then look the ID up:

```bash
jq '.records[] | select(.record_id=="1.1_054")' outputs/evidence.json
```

The record holds the request as sent (method, URL, headers, body) and the response (status, headers, body up to
10,000 characters). In this example: `GET https://localhost:8443/api/v1/gitignore/templates` without credentials,
answered `200`.

**Findings without `evidence_ref`** (Q-50): 4.1 and the aggregate finding of 7.2 have none. For 7.2 the proving
transactions are marked in the test's transaction log:

```bash
jq -r '.all_rows[] | select(.test_id=="7.2") | .transaction_log[] | select(.is_fail_evidence) | .record_id' outputs/apiguard_report.json
```

and each ID is in `evidence.json` as above. For 4.1 the finding's detail describes the probe (endpoint, number of
requests, no `429` received) and the transaction log lists every request.

## 4. Every request of a test: the transaction log

`transaction_log` lists **all** the requests of a test, PASS included, each with an `oracle_state`: the test's
classification of that response (e.g. `ENFORCED`, `AUTH_BYPASS`, `INCONCLUSIVE_PARAMETRIC`). The states are
defined per test, on each [test page](../../tests/README.md). To count them:

```bash
jq '[.all_rows[] | select(.test_id=="1.1") | .transaction_log[].oracle_state] | group_by(.) | map({(.[0]): length}) | add' outputs/apiguard_report.json
```

Many `INCONCLUSIVE_*` states mean the test could not reach a conclusion on those requests: in 1.1 they usually mean
`path_seed` is missing values ([configure a target](configure-a-target.md#4-real-identifiers-path_seed)).

Only the transactions marked `is_fail_evidence` are stored in full in `evidence.json`; the log keeps a preview of
the others (request body up to 2,000 characters, response up to 1,000).

## 5. External tests

An external test (`ext.*`) carries the tool's output in `tool_artifact`: the command it ran (`command`, to repeat
it by hand), and all the tool's results (`results`, `all_count`), unfiltered. The test's findings are the results
it judged as violations.

```bash
jq '.all_rows[] | select(.test_id=="ext.1.5.sslyze") | .tool_artifact.command' outputs/apiguard_report.json
```

The same output is in `tools/<test>_output.json` and, as one record, in `evidence.json` (`tool_artifact_record_id`).

## 6. The HTML report

Open it through a local web server:

```bash
cd outputs && python3 -m http.server 8080
```

and browse to `http://localhost:8080/assessment_report.html` (`Ctrl+C` stops the server, then `cd ..`). If the tool
runs on a remote machine opened with VS Code Remote, VS Code forwards port 8080 to your browser (Ports panel); with
plain SSH, connect with `ssh -L 8080:localhost:8080 <host>`.

- **Executive summary** at the top, with filters by status, priority and domain, and a search box.
- **One section per domain**, one card per test: status, message, findings (with their evidence ID), notes.
- **View Audit Trail**: the transaction log of a native test, with search and CSV export.
- **Tool Output**: the raw output of an external test, with copy and download.

## Read with care

- **PASS is bounded by coverage.** Each test page lists the parts of the methodology it does not implement.
- **Findings are differences from the test's oracle, to be judged by the analyst**
  ([oracles and verdicts](../../architecture/assessment-model.md#oracles-and-verdicts)). Example: test 1.1 compares
  the API with its specification. On the lab, all 78 findings are anonymous `GET` requests answered `200` on
  endpoints the specification declares as protected, while Forgejo serves that data to everyone on purpose. They are
  real differences from the specification: check whether they are intended; if so, it is the specification that is
  wrong.
- **Known limits that produce misleading findings:**
  - 1.5 reports a false FAIL if `http_probe_url` is not set on an HTTPS port that is not 443
    ([configure a target](configure-a-target.md#2-tls)).
  - 2.1 on a non-Forgejo target with the default `admin_endpoint_paths` can PASS without testing anything (Q-18).
- **Counts depend on the target's data.** More real resources in `path_seed` move probes from inconclusive to
  conclusive, and can change the number of findings.

## See also

- [Report schema](../../reference/report-schema.md) · [Evidence format](../../reference/evidence-format.md) ·
  [Exit codes](../../reference/exit-codes.md)
- Consuming the JSON from another program: *planned:* `guides/integration/`.

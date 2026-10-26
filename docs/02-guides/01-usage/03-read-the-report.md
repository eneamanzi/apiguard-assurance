# Read the Report

> **Audience:** users, analysts · **Status:** v0.1.0 · **Source of truth:** `src/report/builder.py`,
> `src/report/templates/report.html`, `src/core/evidence.py`, `src/core/models/results.py` · **Verified:** 2026-10-06
> on lab runs (native tests only; `ext.1.5.testssl` only); every command below was run on their output

How to go from the exit code to the proof of each violation. Field-by-field descriptions are in the
[report schema](../../03-reference/04-report-schema.md) and the [evidence format](../../03-reference/05-evidence-format.md).

Previous page: [Select tests](02-select-tests.md).

## What a run produces

In `output.directory` (`outputs/forgejo/` with the Forgejo lab's configuration, used in the examples below),
replacing the files of the previous run:

| File | For | Content |
|---|---|---|
| `assessment_report.html` | people | interactive report: summary, filters, one card per test |
| `apiguard_report.json` | programs, and you with `jq` | the same data, machine-readable |
| `evidence.json` | proof | the full HTTP transactions behind the findings, and the raw output of the external tools |
| `config_used.yaml` | you, and a re-run | every configuration value the run used, `# specified` or `# default`; `apiguard run --config config_used.yaml` repeats the run ([details](../../03-reference/01-configuration.md#the-configuration-a-run-used-config_usedyaml)) |
| `tools/<test>_output.json` | external tests | raw output of each tool (e.g. `tools/ext_1_5_testssl_output.json`) |

If the run was interrupted (`Ctrl+C`, SIGTERM), the reports are not written: the folder keeps `config_used.yaml`
(written before the run contacts the target) and, when the tests had started, `evidence_tmp/` with the evidence
collected so far.

**`evidence.json` is sensitive.** Response bodies are stored as received: if the API returns secrets, they are in
this file. Only secret values are redacted: `Authorization` and cookie values, and the secrets the tool knows
(passwords, tokens, the values it generates) ([sensitive data](../../03-reference/05-evidence-format.md#sensitive-data)).

## 1. The verdict

The exit code of `apiguard run` is the overall verdict: every code and its meaning in
[exit codes](../../03-reference/03-exit-codes.md). Two to keep in mind when reading a report: `10` means the assessment did
not run or did not complete, so **no verdict, never "clean"**; `3` may come with findings, since an ERROR result
can carry the findings collected before the error.

The executive summary gives the counts:

```bash
jq '.executive_summary' outputs/forgejo/apiguard_report.json
```

`executed_tests` excludes the SKIPs, and `pass_rate_pct` is `pass_count / executed_tests`.

## 2. The outcome of each test

```bash
jq -r '.all_rows[] | "\(.test_id)\t\(.status)\t\(.finding_count)\t\(.message)"' outputs/forgejo/apiguard_report.json
```

| Status | What it tells you | What to do |
|---|---|---|
| `FAIL` | the guarantee is violated; at least one finding | read the findings (step 3) |
| `PASS` | the guarantee holds **for what the test covers** | check the test page for what it does not cover |
| `INCONCLUSIVE` | the test ran but verified nothing: no violation and nothing enforced, only cases it could not verify | not a pass; read the notes and the per-request `outcome` (step 4), often a missing precondition or an unreachable target |
| `SKIP` | a precondition was missing; `skip_reason` says which | not a pass: provide the precondition or accept the gap |
| `ERROR` | the check did not complete; the message says why | fix the cause (URL, credentials, tool) and run again |

A PASS can be **partial** (`coverage: PARTIAL`): the guarantee held for the cases checked, but some could not be
verified; the notes and the per-request `outcome` (step 4) say which. A test excluded by the
[selection](02-select-tests.md) or stopped by fail-fast is not a result: it is listed in `not_run` (HTML: "Not Run"
section) with the reason.

Each test can also carry **InfoNotes** (`notes`): context that is not a violation, such as a sub-check that could
not run or something to verify by hand. Read them for PASS results too.

## 3. From a finding to its proof

Each finding has a title, a detail, a `confidence` (`CERTAIN`, `FIRM` or `TENTATIVE` — how sure the tool is the
violation is real, not a severity) and, for most tests, an `evidence_ref`: the ID of the transaction that proves it,
stored in `evidence.json`. A finding whose verdict rests on reference responses also lists their `supporting_refs`
(the baseline probes it stood on, step from the assessment model). Example on the lab, test 1.1:

```bash
jq -r '.all_rows[] | select(.test_id=="1.1") | .findings[] | "\(.evidence_ref)  \(.title)"' outputs/forgejo/apiguard_report.json
```

```
1.1_054  Protected endpoint accessible without authentication
1.1_056  Protected endpoint accessible without authentication
...
```

Then look the ID up:

```bash
jq '.records[] | select(.record_id=="1.1_054")' outputs/forgejo/evidence.json
```

The record holds the request as sent (method, URL, headers, body) and the response (status, headers, body up to
10,000 characters). In this example: `GET https://localhost:8443/api/v1/gitignore/templates` without credentials,
answered `200`.

**Findings and their proof.** A finding from an HTTP probe carries `evidence_ref`, the `record_id` of the proving
transaction in `evidence.json` (set by the test's `_judge()`); look it up as above. To list every transaction a
test stored as FAIL evidence:

```bash
jq -r '.all_rows[] | select(.test_id=="1.1") | .transaction_log[] | select(.is_fail_evidence) | .record_id' outputs/forgejo/apiguard_report.json
```

A finding from a gateway-configuration audit (3.3, 4.2, 4.3) references the gateway concept it read instead of an
HTTP transaction.

## 4. Every request of a test: the transaction log

`transaction_log` lists **all** the requests of a test, PASS included. Each judged request carries an `outcome`
(`VIOLATION`, `ENFORCED`, `NOT_VERIFIABLE`, `NOT_APPLICABLE`), a test-specific `detail` (e.g. `AUTH_BYPASS`,
`PATH_NOT_FOUND`) and a common `category` (what the response is). The details are defined per test, on each
[test page](../../05-tests/README.md). To count the outcomes:

```bash
jq '[.all_rows[] | select(.test_id=="1.1") | .transaction_log[] | select(.outcome!=null) | .outcome] | group_by(.) | map({(.[0]): length}) | add' outputs/forgejo/apiguard_report.json
```

Many `NOT_VERIFIABLE` outcomes mean the test could not reach a conclusion on those requests: in 1.1 they usually
mean `path_seed` is missing values ([configure a target](01-configure-a-target.md#4-real-identifiers-path_seed)).

Only the transactions marked `is_fail_evidence` are stored in full in `evidence.json`; the log keeps a preview of
the others (request body up to 2,000 characters, response up to 1,000).

## 5. External tests

An external test (`ext.*`) carries the tool's output in `tool_artifact`: the command it ran (`command`, to repeat
it by hand), and all the tool's results (`results`, `all_count`), unfiltered. The test's findings are the results
it judged as violations.

```bash
jq '.all_rows[] | select(.test_id=="ext.1.5.testssl") | .tool_artifact.command' outputs/forgejo/apiguard_report.json
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
  ([oracles and verdicts](../../04-architecture/03-assessment-model.md#oracles-and-verdicts)). Example: test 1.1 compares
  the API with its specification. On the lab, all 78 findings are anonymous `GET` requests answered `200` on
  endpoints the specification declares as protected, while Forgejo serves that data to everyone on purpose. They are
  real differences from the specification: check whether they are intended; if so, it is the specification that is
  wrong.
- **Known limits that produce misleading findings:**
  - 1.5 reports a false FAIL if `http_url` is not set on an HTTPS port that is not 443
    ([configure a target](01-configure-a-target.md#2-tls-and-certificates)).
- **Counts depend on the target's data.** More real resources in `path_seed` move probes from inconclusive to
  conclusive, and can change the number of findings.

## See also

- [Report schema](../../03-reference/04-report-schema.md) · [Evidence format](../../03-reference/05-evidence-format.md) ·
  [Exit codes](../../03-reference/03-exit-codes.md)
- Consuming the JSON from another program: *planned:* `guides/integration/`.

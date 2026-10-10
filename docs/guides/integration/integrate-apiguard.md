# Integrate APIGuard Assurance

> **Audience:** developers integrating the tool into another product or an automated pipeline · **Status:** 0.x
> (see [versions](#versions)) · **Source of truth:** `src/cli.py`, `src/engine.py`, the
> [reference pages](../../reference/) · **Verified:** 2026-10-09 with a wheel installed by `pip` in a fresh virtual
> environment, run from a working directory outside the repository, against the Forgejo + Kong lab

How to run the tool from another program and use what it produces. Every command on this page was run as written.
What to configure on the target side is in [Configure a target](../usage/configure-a-target.md); what each test
does is in the [test catalogue](../../tests/README.md).

## 1. What you integrate

A **command**, `apiguard`, not a Python library: your program starts a process, waits for its exit code and reads
the files it writes. The Python modules (`src.*`) are not a public interface.

What stays stable between versions (exit codes, report and evidence formats, output file names, test IDs, CLI,
`config.yaml` keys) and what may change is listed in [compatibility](../../reference/compatibility.md#interface-stability).

## 2. Install

Linux, Python 3.11 to 3.14. Build the wheel from the repository, then install it where your program runs:

```bash
hatch build -t wheel                                   # in the repository: dist/apiguard_assurance-<version>-py3-none-any.whl
pip install "dist/apiguard_assurance-0.1.0-py3-none-any.whl[sslyze]"   # [sslyze]: optional TLS test ext.1.5.sslyze
apiguard version
```

The wheel contains the Python code of the tool only: no `config.yaml`, and **neither the external tools nor
`install_tools.sh`**, the repository script that downloads them. The tests that use an external program:

| Test | Needs | With a pip install |
|---|---|---|
| `ext.1.5.sslyze` | the sslyze Python library | install the `[sslyze]` extra (above) |
| `ext.0.1.nuclei` | the `nuclei` program and its templates | download nuclei and its templates yourself |
| `ext.1.5.testssl` | the `testssl.sh` program | download testssl.sh yourself |

The tool looks for `nuclei` and `testssl.sh` in two places: the `PATH` (the folders where the system looks for
commands, e.g. `/usr/local/bin`), or a `tools/` folder inside the directory the command is run from (this is where
`install_tools.sh` puts them in the repository). Verified with the `PATH`.

nuclei also needs a folder of templates (the rules it applies). `external_tools.nuclei.template_dir` defaults to
`./tools/nuclei-templates`, a path relative to the directory the command is run from: it exists in the repository
after `install_tools.sh`, not elsewhere. Set the real location, e.g.:

```yaml
external_tools:
  nuclei:
    template_dir: "/opt/nuclei-templates"
```

An enabled tool that is not found makes its test return SKIP ("External tool 'nuclei' is not available on this
system"); the other tests run normally. A disabled tool (`enabled: false`) is listed in `not_run`. Tested versions:
[compatibility](../../reference/compatibility.md).

## 3. Prepare a configuration and the credentials

Start from the repository's `config.yaml` (every key: [configuration](../../reference/configuration.md)). Secrets
never go in the file: write `${VAR}` and provide the variables at run time, either exported in the environment of
the process or in a file passed with `--env-file` (variables already in the environment win):

```bash
apiguard validate-config -c config.yaml --env-file credentials.env
```

`validate-config` contacts nothing; it checks the configuration, the test declarations and `test_ids`, and exits
`0` (`Configuration valid. Target: ...`) or `10` with every problem listed (e.g. the variables that are not set).
Run it whenever the configuration changes.

**One output directory per run.** The reports are written to `output.directory` and a new run **overwrites** them.
To keep each run, take the directory from a variable, like the credentials:

```yaml
output:
  directory: "${APIGUARD_OUTPUT_DIR}"
```

**One run at a time per target.** The tool is designed for one assessment at a time on a target: concurrent runs
change the target under each other (verified: test 1.4 creates a token with a fixed name, and in one of two runs
started together it returns ERROR).

## 4. Run

```bash
APIGUARD_OUTPUT_DIR=runs/r1 apiguard run -c config.yaml --env-file credentials.env
```

On the lab a run takes about 25 seconds with the native tests and about 5 minutes with nuclei and testssl.sh;
nuclei alone takes about 195 seconds against its default limit of 240 (`external_tools.nuclei.timeout_seconds`):
give your own timeout a margin.

**Output for people or for machines.** The default console output is a progress view (one line per test, a
summary with the report paths). For a log collector use JSON lines:

```bash
APIGUARD_OUTPUT_DIR=runs/r2 apiguard run -c config.yaml --env-file credentials.env --log-format json --log-level info > runs/r2.log
```

One JSON object per line (only at `--log-level debug` third-party libraries may add plain-text lines). At the
default level (`warning`) only problems are logged. Details: [CLI](../../reference/cli.md#output-streams).

To run part of the tests (a subset, by priority or strategy): [Select tests](../usage/select-tests.md).

## 5. Exit codes

| Code | Meaning | What your program should do |
|---|---|---|
| `0` | every executed test passed (SKIPs do not count) | read `not_run` and the SKIPs to know what was not checked |
| `1` | at least one security guarantee is violated | read the findings |
| `2` | invalid invocation: nothing ran | fix the command line |
| `3` | no violation found, but at least one test could not complete | read the ERROR messages, fix, run again |
| `10` | the assessment did not run (configuration, specification, test selection) | read the error message (stderr / log) |
| `130`, `143` | interrupted (Ctrl+C, SIGTERM) after cleaning the target | no report: run again |

Full reference: [exit codes](../../reference/exit-codes.md). A script that keeps the code even with `set -e`:

```bash
#!/usr/bin/env bash
set -euo pipefail
config="${1:-config.yaml}"
mkdir -p runs
export APIGUARD_OUTPUT_DIR="runs/$(date -u +%Y%m%dT%H%M%SZ)"

status=0
timeout --preserve-status --kill-after=30s 1200s \
  apiguard run -c "$config" --env-file credentials.env --log-format json --log-level info \
  > "$APIGUARD_OUTPUT_DIR.log" || status=$?

case "$status" in
  0)       echo "CLEAN: no violation ($APIGUARD_OUTPUT_DIR)" ;;
  1)       echo "FAIL: violations found ($APIGUARD_OUTPUT_DIR)" ;;
  3)       echo "ERROR: some checks did not complete ($APIGUARD_OUTPUT_DIR)" ;;
  2|10)    echo "NOT RUN: see $APIGUARD_OUTPUT_DIR.log" ;;
  130|143) echo "INTERRUPTED: the target was cleaned, no report" ;;
  *)       echo "UNEXPECTED exit code $status" ;;
esac
exit "$status"
```

`|| status=$?` stops `set -e` from ending the script before the code is read. `timeout --preserve-status` passes on
the tool's own code (`143` after SIGTERM); without it `timeout` returns its own code `124`.

## 6. Read the results

Three files in the output directory: `apiguard_report.json` (results, the file to read),
`evidence.json` (the HTTP transactions that prove the findings) and `assessment_report.html` (for people).
Fields: [report schema](../../reference/report-schema.md), [evidence format](../../reference/evidence-format.md).

```bash
cd runs/r1

# Verdict and counts
jq '.executive_summary | {exit_code, pass_count, fail_count, skip_count, error_count, not_run_count, total_finding_count}' apiguard_report.json

# Failed tests: ID, number of findings, name
jq -r '.all_rows[] | select(.status == "FAIL") | "\(.test_id)\t\(.finding_count)\t\(.test_name)"' apiguard_report.json

# Every finding with the ID of the transaction that proves it
jq -r '.all_rows[] | select(.status == "FAIL") | .findings[] | "\(.evidence_ref // "-")\t\(.title)"' apiguard_report.json

# The transaction behind a finding
jq --arg id "0.1_002" '.records[] | select(.record_id == $id) | {request_method, request_url, response_status_code}' evidence.json

# What was not checked: SKIP and ERROR reasons, tests not run
jq -r '.all_rows[] | select(.status == "SKIP" or .status == "ERROR") | "\(.test_id)\t\(.status)\t\(.skip_reason // .message)"' apiguard_report.json
jq -r '.not_run[] | "\(.test_id)\t\(.reason)\t\(.detail)"' apiguard_report.json
```

Some findings have no `evidence_ref` today: those of tests 4.1 and 7.2 and, when they fail, of the configuration
audits 3.3, 4.2 and 4.3; the transactions of 4.1 and 7.2 are in the test's `transaction_log` (Q-50).

## 7. Stop a run

Send SIGTERM (or SIGINT) and give the tool a few seconds: it removes what the tests created on the target, then
exits with `143` (`130` for SIGINT), without reports; the output directory keeps only `evidence_tmp/` (partial
files). Repeated signals do not interrupt the cleanup. **Never SIGKILL** (`kill -9`): the cleanup does not run and
tokens or repositories stay on the target. `timeout --kill-after=30s` sends SIGKILL only if the tool is still
running 30 seconds after SIGTERM; on the lab the cleanup takes about one second. Details:
[stopping a run](../../reference/exit-codes.md#stopping-a-run).

## 8. Effects on the target and sensitive data

The tests send attack traffic and create, then delete, resources on the target with the configured accounts
(tokens, a repository and webhooks on Forgejo). Run the tool on environments made for it, with dedicated accounts.
What each test creates or changes is on its page in the [test catalogue](../../tests/README.md).

The output files contain the target's responses: treat them as sensitive. Credentials and the secrets the tool
creates are replaced with placeholders such as `[REDACTED: user_a token]`; response bodies are kept, because they
are the evidence ([sensitive data](../../reference/evidence-format.md#sensitive-data)).

## 9. Versions

`tool_version` in `apiguard_report.json` and `evidence.json` is the only version of the output formats. The project
is at 0.x: a change that breaks an interface raises the minor version until 1.0.0 and is marked **Breaking:** in
the [changelog](../../../CHANGELOG.md); changed test oracles are listed under "Changed results". Policy:
[compatibility](../../reference/compatibility.md#interface-stability).

## See also

- [Configure a target](../usage/configure-a-target.md), [Select tests](../usage/select-tests.md),
  [Read the report](../usage/read-the-report.md)
- [CLI](../../reference/cli.md), [exit codes](../../reference/exit-codes.md),
  [report schema](../../reference/report-schema.md), [evidence format](../../reference/evidence-format.md)

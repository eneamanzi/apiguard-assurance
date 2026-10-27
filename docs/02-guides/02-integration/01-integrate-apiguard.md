# Integrate APIGuard Assurance

> **Audience:** developers integrating the tool into another product or an automated pipeline · **Status:** 0.x
> (see [versions](#9-versions)) · **Source of truth:** `src/cli.py`, `src/engine.py`, the
> [reference pages](../../03-reference/) · **Verified:** 2026-10-27 (the durations, measured on the lab); 2026-10-09 with a wheel installed by `pip` in a fresh virtual
> environment, run from a working directory outside the repository, against the Forgejo + Kong lab; certificates
> and the `connections` checks 2026-10-15 on the three labs

How to run the tool from another program and use what it produces. Every command on this page was run as written.
What to configure on the target side is in [Configure a target](../01-usage/01-configure-a-target.md); what each test
does is in the [test catalogue](../../05-tests/README.md). A program that needs the list of tests, their parameters
(as JSON Schema) and which of them can run with a given configuration reads it from `apiguard list-tests --json`
([CLI reference](../../03-reference/02-cli.md#list-tests)).

## 1. What you integrate

A **command**, `apiguard`, not a Python library: your program starts a process, waits for its exit code and reads
the files it writes. The Python modules (`src.*`) are not a public interface.

What stays stable between versions (exit codes, report and evidence formats, output file names, test IDs, CLI,
`config.yaml` keys) and what may change is listed in [compatibility](../../03-reference/06-compatibility.md#interface-stability).

## 2. Install

Linux, Python 3.11 to 3.14. Build the wheel from the repository, then install it where your program runs:

```bash
hatch build -t wheel                                   # in the repository: dist/apiguard_assurance-<version>-py3-none-any.whl
pip install "dist/apiguard_assurance-0.1.0-py3-none-any.whl[schemathesis]"   # [schemathesis]: optional test ext.3.1.schemathesis
apiguard version
```

The wheel contains the Python code of the tool only: no `config.yaml`, and **neither the external tools nor
`install_tools.sh`**, the repository script that downloads them. The tests that use an external program:

| Test | Needs | With a pip install |
|---|---|---|
| `ext.3.1.schemathesis` | the schemathesis Python library | install the `[schemathesis]` extra (above) |
| `ext.0.1.ffuf` | the `ffuf` program and its wordlists | download ffuf and SecLists yourself |
| `ext.1.5.testssl` | the `testssl.sh` program | download testssl.sh yourself |

The tool looks for `ffuf` and `testssl.sh` in two places: the `PATH` (the folders where the system looks for
commands, e.g. `/usr/local/bin`), or a `tools/` folder inside the directory the command is run from (this is where
`install_tools.sh` puts them in the repository). Verified with the `PATH`.

ffuf also needs a folder of wordlists (the paths it tries). `external_tools.ffuf.wordlist_dir` defaults to
`./tools/seclists`, a path relative to the directory the command is run from: it exists in the repository
after `install_tools.sh`, not elsewhere. Set the real location, e.g.:

```yaml
external_tools:
  ffuf:
    wordlist_dir: "/opt/seclists"
```

An enabled tool that is not found makes its test return SKIP ("External tool 'ffuf' is not available on this
system"); the other tests run normally. A disabled tool (`enabled: false`) is listed in `not_run`. Tested versions:
[compatibility](../../03-reference/06-compatibility.md).

## 3. Prepare a configuration and the credentials

Start from `config.example.yaml` in the repository root, which lists every key with its description and default
(reference: [configuration](../../03-reference/01-configuration.md)), and keep what your target needs. Relative paths
in the file (specification, output directory, ffuf's wordlist directory) are resolved against the directory the command
runs from: start the tool from the directory that holds the file, or write absolute paths. Secrets
never go in the file: write `${VAR}` and provide the variables at run time, either exported in the environment of
the process or in a file passed with `--env-file` (variables already in the environment win):

```bash
apiguard validate-config -c config.yaml --env-file credentials.env
```

`validate-config` does not contact the API; it checks the configuration, the certificate files, the test
declarations and `test_ids`, and exits `0` (`Configuration valid. Target: ...`) or `10` with every problem listed
(e.g. the variables that are not set). With credentials configured it also reads the specification (download or
file), to resolve where they are sent. Run it whenever the configuration changes.

**Certificates and keys.** Each connection (the API, the specification, the gateway's Admin API) checks the server's
certificate against the system's store by default; for a private authority, a client certificate or a key, see
[TLS and certificates](../01-usage/01-configure-a-target.md#2-tls-and-certificates). When the tool runs inside another
product, give it files, not contents: the product writes the authority, the client certificate and its key to files
readable only by the user that runs the tool (`600` for the key), passes their paths through variables
(`client_key: "${APIGUARD_ADMIN_CLIENT_KEY_FILE}"`), and deletes them after the run if they are temporary. The key
is never printed in the logs or the reports; an encrypted key is refused, so decrypt it first.

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

On the lab a run takes about 18 seconds with the native tests alone and about two and a half minutes with the
three external tools as well: testssl.sh about 75 seconds against the lab's limit of 180
(`external_tools.testssl.timeout_seconds`), Schemathesis about 31 and ffuf about 30, both against a limit of 600.
Give your own limits a margin (the run warns, `external_tool_near_time_limit`, when a tool ends after more than 70%
of its limit).

**Output for people or for machines.** The default console output is a progress view (one line per test, a
summary with the report paths). For a log collector use JSON lines:

```bash
APIGUARD_OUTPUT_DIR=runs/r2 apiguard run -c config.yaml --env-file credentials.env --log-format json --log-level info > runs/r2.log
```

One JSON object per line (only at `--log-level debug` third-party libraries may add plain-text lines). At the
default level (`warning`) only problems are logged. Details: [CLI](../../03-reference/02-cli.md#output-streams).

To run part of the tests (a subset, by priority or strategy): [Select tests](../01-usage/02-select-tests.md).

## 5. Exit codes

What each code means: [exit codes](../../03-reference/03-exit-codes.md). What your program should do with it:

| Code | What your program should do |
|---|---|
| `0` | read `not_run` and the SKIPs to know what was not checked |
| `1` | read the findings |
| `2` | fix the command line |
| `3` | read the ERROR messages and their findings, fix, run again |
| `10` | read the reason: the `Reason` line on the console, or `detail` of the log event `assessment_pipeline_infrastructure_failure` with `--log-format json` (complete) |
| `130`, `143` | no report: run again |

A script that keeps the code even with `set -e`:

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

A program reads `apiguard_report.json` ([report schema](../../03-reference/04-report-schema.md)); the proof of each finding
is in `evidence.json` ([evidence format](../../03-reference/05-evidence-format.md)). Every file of the output directory
and what it is for: [read the report](../01-usage/03-read-the-report.md). Keep `config_used.yaml` with the results: it
repeats the run.

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

# How each connection's certificate was checked (a not verified one means the run could not know it talked to
# the right server; the second command exits 1 when one was not verified)
jq -r '.connections[] | "\(.name)\t\(.certificate_check)\tclient certificate: \(.client_certificate)"' apiguard_report.json
jq -e '[.connections[] | select(.certificate_check == "not_verified")] | length == 0' apiguard_report.json

# What was not checked: SKIP and ERROR reasons, tests not run
jq -r '.all_rows[] | select(.status == "SKIP" or .status == "ERROR") | "\(.test_id)\t\(.status)\t\(.skip_reason // .message)"' apiguard_report.json
jq -r '.not_run[] | "\(.test_id)\t\(.reason)\t\(.detail)"' apiguard_report.json
```

A finding from an HTTP probe carries `evidence_ref`, the `record_id` of the proving transaction in `evidence.json`
(set by `_judge()`). A finding from a gateway-configuration check references the gateway concept it read instead of an
HTTP transaction: its `evidence_ref` starts with `artifact-` (3.3, 4.2, 4.3, 5.1, and the route-drift part of 0.1
and 0.2).

## 7. Stop a run

Send SIGTERM (or SIGINT) and give the tool a few seconds: it removes what the tests created on the target, then
exits with `143` (`130` for SIGINT), without reports; the output directory keeps `config_used.yaml` and, when the tests
had started, `evidence_tmp/` (partial files). Repeated signals do not interrupt the cleanup. **Never SIGKILL** (`kill -9`): the cleanup does not run and
tokens or repositories stay on the target. `timeout --kill-after=30s` sends SIGKILL only if the tool is still
running 30 seconds after SIGTERM; on the lab the cleanup took about a second for three resources, and it grows with their number. Details:
[stopping a run](../../03-reference/03-exit-codes.md#stopping-a-run).

## 8. Effects on the target and sensitive data

The tests send attack traffic and create, then delete, resources on the target with the configured accounts
(tokens, a repository and webhooks on Forgejo). Run the tool on environments made for it, with dedicated accounts.
What each test creates or changes is on its page in the [test catalogue](../../05-tests/README.md).

The output files contain the target's responses: treat them as sensitive. Credentials and the secrets the tool
creates are replaced with placeholders such as `[REDACTED: user_a token]`; response bodies are kept, because they
are the evidence ([sensitive data](../../03-reference/05-evidence-format.md#sensitive-data)).

## 9. Versions

`tool_version` in `apiguard_report.json` and `evidence.json` is the only version of the output formats. The project
is at 0.x: a change that breaks an interface raises the minor version until 1.0.0 and is marked **Breaking:** in
the [changelog](../../../CHANGELOG.md); changed test oracles are listed under "Changed results". Policy:
[compatibility](../../03-reference/06-compatibility.md#interface-stability).

## See also

- [Configure a target](../01-usage/01-configure-a-target.md), [Select tests](../01-usage/02-select-tests.md),
  [Read the report](../01-usage/03-read-the-report.md)
- [CLI](../../03-reference/02-cli.md), [exit codes](../../03-reference/03-exit-codes.md),
  [report schema](../../03-reference/04-report-schema.md), [evidence format](../../03-reference/05-evidence-format.md)

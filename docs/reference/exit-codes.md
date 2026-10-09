# Exit Codes

> **Audience:** users, integrators · **Status:** stable · **Source of truth:** `src/core/models/enums.py`
> (`ExitCode`), `src/core/models/results.py` (`ResultSet.compute_exit_code`), `src/cli.py` · **Verified:** 2026-10-08

## `apiguard run`

| Code | Label | Meaning |
|---|---|---|
| `0` | CLEAN | Every executed test returned PASS or SKIP. |
| `1` | FAIL | At least one test returned FAIL: a security guarantee is violated. |
| `2` | USAGE | Invalid invocation: the assessment did not start (see [Usage errors](#usage-errors)). |
| `3` | ERROR | No FAIL, but at least one test returned ERROR: a verification did not complete. |
| `10` | INFRA | The assessment did not run. Raised on `ConfigurationError` (Phase 1; an `execution.test_ids` entry that does not exist or whose tool is disabled, checked right after Phase 1; no test selected by the filters, Phase 4), `TestDefinitionError` (a test class declared incorrectly, checked right after Phase 1), `OpenAPILoadError` (Phase 2), `DAGCycleError` (Phase 4), or any unexpected exception inside the engine. A run never ends `0` without running at least one test. |
| `130` | Interrupted | The process received Ctrl+C (SIGINT). See [Stopping a run](#stopping-a-run). |
| `143` | Terminated | The process received SIGTERM (`kill`, `docker stop`, a CI timeout, a calling program). See [Stopping a run](#stopping-a-run). |

**Precedence:** FAIL > ERROR > CLEAN. A single FAIL yields `1` regardless of how many ERRORs occurred.
SKIP never affects the exit code.

**Exit 10 means no security verdict.** Phases 1-4 are blocking; when one fails, no test has run and the
output files are not produced. Never treat `10` as "clean".

## Stopping a run

Ctrl+C (SIGINT) and SIGTERM are handled alike during `apiguard run`:

1. the tool writes on stderr `Ctrl+C received: ...` or `SIGTERM received: stopping the assessment and removing the
   resources created on the target. Please wait.`;
2. teardown (Phase 6) runs: the tokens, repositories and other resources created by the tests are removed; a
   running external tool (nuclei, testssl.sh) is stopped;
3. any further Ctrl+C or SIGTERM does not interrupt the cleanup, it only repeats `Still removing the resources
   created on the target. Please wait.`;
4. the process ends by the **first** signal received: exit `130` (SIGINT) or `143` (SIGTERM), 128 + the signal
   number. A calling program sees a process terminated by that signal (Python `subprocess`: `returncode` `-2` or
   `-15`). **No report files are written** (Phase 7 does not run; partial report: Q-26).

Do not use SIGKILL (`kill -9`): it cannot be intercepted, so teardown does not run and the resources the tests
created on the target are left behind. Leave the tool a few seconds to clean up: `docker stop` sends SIGKILL 10
seconds after SIGTERM by default; teardown took about half a second on the lab. Other commands
(`validate-config`, `generate-seed`, `version`) keep Python's default behaviour.

**Fail-fast:** with `execution.fail_fast: true`, the run stops after the first P0 test that returns FAIL **or
ERROR**. Teardown and report generation still run; the exit code follows the precedence rule on the results
collected so far. Tests that had not started are absent from the report - they are not recorded as SKIP.

## Other commands

| Command | Code | Meaning |
|---|---|---|
| `validate-config` | `0` | Configuration valid (Phase 1: YAML parsing, `${VAR}` interpolation, schema validation; plus the `execution.test_ids` check). |
| `validate-config` | `10` | Configuration invalid or file not found. |
| `generate-seed` | `0` | Template generated. |
| `generate-seed` | `1` | Specification could not be fetched or parsed. |
| `version` | `0` | Always. |

## Usage errors

Invalid invocations (unknown option, invalid choice such as `--log-format xml`, unknown command, no command) are
rejected by the CLI framework (Typer/Click) with exit code **`2`**, for every command, before the tool starts:
no test runs and no output file is written. `2` is reserved for this case (the usual convention of shells,
`argparse` and Click); a completed run never returns it. Until 2026-10 ERROR was also `2` (Q-20).

## Handling in scripts

`set -e` makes the shell exit as soon as `apiguard` returns non-zero, before the code can be inspected. Capture
it explicitly:

```bash
apiguard run --config config.yaml --log-format json --no-banner
code=$?
case "$code" in
  0)   echo "CLEAN" ;;
  1)   echo "FAIL: security guarantee violated" ;;
  2)   echo "USAGE: invalid invocation, nothing ran" ;;
  3)   echo "ERROR: verification incomplete" ;;
  10)  echo "INFRA: assessment did not run" ;;
  130) echo "Interrupted (Ctrl+C)" ;;
  143) echo "Terminated (SIGTERM)" ;;
esac
exit "$code"
```

## See also

- [`cli.md`](cli.md) - commands and options
- [`report-schema.md`](report-schema.md) - `executive_summary.exit_code` in the JSON report
- [`../architecture/overview.md`](../architecture/overview.md) - pipeline phases

# Select Tests

> **Audience:** users · **Status:** v0.1.0 · **Source of truth:** `src/engine.py` (Phase 4), `src/tests/registry.py`,
> `src/external_tests/registry.py`, `src/config/schema/tool_config.py` (`ExecutionConfig`) · **Verified:** 2026-10-06
> on the lab (runs: native tests only, test 1.1 only, `ext.1.5.testssl` only)

How to run only part of the assessment: a single test while you fix something, the fast tests only, or a subset
for a pipeline. By default the tool runs every test whose preconditions can be checked.

Previous page: [Configure a target](01-configure-a-target.md). Every key is in the
[configuration reference](../../03-reference/01-configuration.md#execution).

## Where the time goes

Measured on the lab: **the native tests take well under a minute**; a full run with the external tools takes several
minutes. The external tools (testssl.sh, ffuf, schemathesis) print nothing while they run. While you work on the
configuration or on a single test, leave them off.

## How to change the selection

The selection lives in the configuration file. To change it for one run without touching your main file, copy it
and edit the copy:

```bash
cp test-environments/forgejo-kong/config.yaml /tmp/config-partial.yaml
```

Open `/tmp/config-partial.yaml` in an editor, change the keys described below, save, and run:

```bash
hatch run apiguard run -c /tmp/config-partial.yaml
```

The reports go to the copy's `output.directory` as usual (`outputs/forgejo/` for the lab) and replace the previous
ones. Run the command from the repository folder: paths in the file are relative to it.

## Common cases

### Native tests only (fast)

Turn off the master switch of the external tools:

```yaml
external_tools:
  # Master switch. Set false to skip all external tests in one line.
  enabled: false
```

The external tests disappear from the report (they are not scheduled, not SKIP): the native tests alone run in well
under a minute.

### One or a few tests

List their IDs in `execution.test_ids`:

```yaml
execution:
  test_ids: ["1.1"]
```

Only the listed tests run, native or external, whatever `external_tools` enables. Measured on the lab:
`test_ids: ["1.1"]`, one test, 7 seconds; `test_ids: ["0.2"]` with every external tool enabled runs only 0.2.

External IDs work the same way:

```yaml
execution:
  test_ids: ["ext.1.5.testssl"]
```

A mixed list (`["1.1", "ext.1.5.testssl"]`) runs exactly the listed tests.

`test_ids` chooses only among the available tests: listing an external test whose tool is disabled in
`external_tools` is an error (enable the tool, or remove the test from the list).

ID formats: `X.Y` for native tests (`1.1`, `7.2`), `ext.X.Y.tool` for external tests (`ext.0.1.ffuf`,
`ext.1.5.testssl`). A malformed ID, an ID that does not exist, or a test of a disabled tool stops
the tool at startup (exit `10`, also with `validate-config`), listing every wrong entry; for an unknown ID it
suggests the closest one (`unknown test 'ext.1.5.testsll' (did you mean 'ext.1.5.testssl'?)`). The full list is in
the [test catalogue](../../05-tests/README.md).

When `test_ids` is set, `min_priority` and `strategies` are ignored. Without `test_ids`, a combination of filters that
selects no test stops the run with exit `10` (`No test selected: ...`) instead of an empty CLEAN report.

### By priority

`execution.min_priority` is the **lowest importance** included: `0` runs only P0 (critical) tests, `3` (default)
runs everything.

```yaml
execution:
  min_priority: 0
```

It applies to native and external tests. Which tests each priority holds is the P0 column of the generated matrix
in the [assessment model](../../04-architecture/03-assessment-model.md#strategies-knowledge-and-privilege-of-the-tester).

### By strategy

`execution.strategies` keeps the tests, native and external, of the listed strategies:

```yaml
execution:
  strategies:
    - BLACK_BOX
```

With only `BLACK_BOX` the run has the tests that need no credential and no gateway access: the `BLACK_BOX` row of
the generated matrix in the
[assessment model](../../04-architecture/03-assessment-model.md#strategies-knowledge-and-privilege-of-the-tester),
minus any external test whose tool is disabled.

### One external tool only

Each tool has its own `enabled` under `external_tools` (`testssl`, `nuclei`, `ffuf`, `schemathesis`). Set the ones you do not want
to `false` and keep the master switch on. A tool that is enabled but not installed returns SKIP. Enabling `nuclei`
changes nothing: its connector is in the codebase but no test uses it ([roadmap](../../project/roadmap.md)).

## Things to know

- **Prerequisites.** A test can require another one (no current test does). If the selection leaves the
  prerequisite out, or it does not end as required, the test returns SKIP and the reason names the prerequisite to
  add ([dependencies between tests](../../04-architecture/03-assessment-model.md#dependencies-between-tests)).
- **Stop at the first critical failure.** `execution.fail_fast: true` stops after the first P0 test that returns
  FAIL or ERROR; the tests not yet run are listed in `not_run` with reason `fail_fast`
  ([exit codes](../../03-reference/03-exit-codes.md)).
- **Misspelled keys stop the run.** `min_prioriti: 0` is rejected at startup (exit `10`) with the suggestion
  `did you mean 'min_priority'?`.
- **Not run is not SKIP.** A test excluded by the selection is not executed and is listed in the report's
  `not_run` section with the reason (`priority`, `strategy`, `not_in_test_ids`, `tool_disabled`, `fail_fast`) and
  the values that excluded it; the HTML report shows it in the "Not Run" section and the console log in
  `pipeline_tests_not_run`. A SKIP means the test was selected but a precondition was missing. Executed tests plus
  not-run tests are always every test of the tool.

## See also

- Next: [Read the report](03-read-the-report.md).

- [Configuration reference: `execution`](../../03-reference/01-configuration.md#execution) and
  [`external_tools`](../../03-reference/01-configuration.md#external_tools)
- [Assessment model](../../04-architecture/03-assessment-model.md): priorities, strategies, outcomes

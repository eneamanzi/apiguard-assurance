# Select Tests

> **Audience:** users · **Status:** v0.1.0 · **Source of truth:** `src/engine.py` (Phase 4), `src/tests/registry.py`,
> `src/external_tests/registry.py`, `src/config/schema/tool_config.py` (`ExecutionConfig`) · **Verified:** 2026-10-06
> on the lab (runs: native tests only, test 1.1 only, `ext.1.5.sslyze` only)

How to run only part of the assessment: a single test while you fix something, the fast tests only, or a subset
for a pipeline. By default the tool runs every test whose preconditions can be checked.

Previous page: [Configure a target](configure-a-target.md). Every key is in the
[configuration reference](../../reference/configuration.md#execution).

## Where the time goes

Measured on the lab: a full run takes about 5 minutes, of which **the 15 native tests take about 30 seconds**. The
rest is the external tools (nuclei, testssl.sh, sslyze), which print nothing while they run. While you work on the
configuration or on a single test, leave them off.

## How to change the selection

The selection lives in the configuration file. To change it for one run without touching your main file, copy it
and edit the copy:

```bash
cp config.yaml /tmp/config-partial.yaml
```

Open `/tmp/config-partial.yaml` in an editor, change the keys described below, save, and run:

```bash
hatch run apiguard run -c /tmp/config-partial.yaml
```

The reports go to `outputs/` as usual and replace the previous ones.

## Common cases

### Native tests only (fast)

Turn off the master switch of the external tools:

```yaml
external_tools:
  # Master switch. Set false to skip all external tests in one line.
  enabled: false
```

The external tests disappear from the report (they are not scheduled, not SKIP). Measured on the lab: 27 seconds,
15 tests.

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
  test_ids: ["ext.1.5.sslyze"]
```

A mixed list (`["1.1", "ext.1.5.sslyze"]`) runs exactly the listed tests.

`test_ids` chooses only among the available tests: listing an external test whose tool is disabled in
`external_tools` is an error (enable the tool, or remove the test from the list).

ID formats: `X.Y` for native tests (`1.1`, `7.2`), `ext.X.Y.tool` for external tests (`ext.0.1.nuclei`,
`ext.1.5.testssl`, `ext.1.5.sslyze`). A malformed ID, an ID that does not exist, or a test of a disabled tool stops
the tool at startup (exit `10`, also with `validate-config`), listing every wrong entry; for an unknown ID it
suggests the closest one (`unknown test 'ext.1.5.sslyzee' (did you mean 'ext.1.5.sslyze'?)`). The full list is in
the [test catalogue](../../tests/README.md).

When `test_ids` is set, `min_priority` and `strategies` are ignored. Without `test_ids`, a combination of filters that
selects no test stops the run with exit `10` (`No test selected: ...`) instead of an empty CLEAN report.

### By priority

`execution.min_priority` is the **lowest importance** included: `0` runs only P0 (critical) tests, `3` (default)
runs everything.

```yaml
execution:
  min_priority: 0
```

It applies to native and external tests: with `0`, the run includes the P0 native tests (0.1, 0.2, 0.3, 1.1, 4.1,
7.2) and `ext.0.1.nuclei`. Priorities per test: [assessment model](../../architecture/assessment-model.md#priorities).

### By strategy

`execution.strategies` keeps the native tests of the listed strategies:

```yaml
execution:
  strategies:
    - BLACK_BOX
```

External tests are **not** filtered by strategy (Q-10): turn them off separately if you do not want them.
Strategies per test: [assessment model](../../architecture/assessment-model.md#strategies-knowledge-and-privilege-of-the-tester).

### One external tool only

Each tool has its own `enabled` under `external_tools` (`testssl`, `nuclei`, `sslyze`). Set the ones you do not want
to `false` and keep the master switch on. A tool that is enabled but not installed returns SKIP.

## Things to know

- **Dependencies.** 1.4 and 2.1 are declared to run after 1.1. If you select 1.4 or 2.1 without 1.1, the dependency
  is dropped with a warning and the test runs anyway.
- **Stop at the first critical failure.** `execution.fail_fast: true` stops after the first P0 test that returns
  FAIL or ERROR; the tests not yet run are missing from the report
  ([exit codes](../../reference/exit-codes.md)).
- **Misspelled keys stop the run.** `min_prioriti: 0` is rejected at startup (exit `10`) with the suggestion
  `did you mean 'min_priority'?`.
- **Absent tests are not SKIP.** A test filtered out by the selection does not appear in the report at all. A SKIP
  means the test was selected but a precondition was missing.

## See also

- Next: [Read the report](read-the-report.md).

- [Configuration reference: `execution`](../../reference/configuration.md#execution) and
  [`external_tools`](../../reference/configuration.md#external_tools)
- [Assessment model](../../architecture/assessment-model.md): priorities, strategies, outcomes

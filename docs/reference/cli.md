# CLI Reference

> **Audience:** users, integrators · **Status:** stable · **Source of truth:** `src/cli.py` (Typer app) ·
> **Verified:** 2026-10-05, v0.1.0 (`--help` output and test invocations); `.env` and `--env-file` 2026-10-08

```
apiguard [COMMAND] [OPTIONS]
```

The entry point is installed as `apiguard`. From a source checkout without installation:
`python -m src.cli [COMMAND] [OPTIONS]`.

| Command | Purpose |
|---|---|
| [`run`](#run) | Run the assessment against the configured target. |
| [`validate-config`](#validate-config) | Validate `config.yaml` (Phase 1 and the test checks) without contacting the target. |
| [`generate-seed`](#generate-seed) | Generate a `path_seed` template from an OpenAPI specification. |
| [`version`](#version) | Print the tool version. |

There are no CLI options to select tests: selection is done in `config.yaml` (`execution.*`, see
[`configuration.md`](configuration.md#execution)).

## Environment and `.env`

`run` and `validate-config` load a `.env` file before reading `config.yaml` (`_load_env_file`, `src/cli.py`);
`${VAR}` placeholders in `config.yaml` are resolved from the resulting environment.

- **Without `--env-file`:** `.env` in the **current working directory** (where you run the command), if it exists.
  No other folder is searched: not the tool's installation folder, not parent folders. No `.env` is not an error;
  a variable that is still missing stops the tool when `config.yaml` is loaded (exit `10`, naming the variable).
- **With `--env-file PATH`:** that file instead. A path that is not an existing file is an invalid invocation
  (exit `2`).
- **Precedence:** variables already set in the process environment (exported in the shell, set by a CI pipeline,
  a container or a calling program) are never overwritten by the file (`override=False`). Without any file, the
  exported variables alone are enough.

The loaded file is logged (`env_file_loaded`, path only, never values). `generate-seed` and `version` load no file.
Verified on 2026-10-08 with a `pip` install in a fresh virtual environment, run from a folder outside the
repository (Q-54; before, the file was searched from the tool's code folder and a `pip` install never found it).

## Output streams

| Command | stdout | stderr |
|---|---|---|
| `run`, `validate-config`, `version` | console format of `run`: the progress interface and the technical log; JSON format: the log lines; result messages | human-readable error summary of `validate-config` |
| `generate-seed` | **only the YAML template** (when `--output` is not given), so that `generate-seed SPEC > seed.yaml` writes a valid file | the panel, logs, messages and errors |

**Console format of `run`.** The interface is always shown: a header (target, specification, selection), one line
per test with its status, findings grouped by kind (up to 5 kinds; the full list is in the reports), the reason of
a SKIP or ERROR, then the cleanup, the result counts, the exit code and the paths of the reports. On a terminal the
test in progress is shown on a line that updates in place with the elapsed time; with the output redirected, a
test with a time limit (an external tool) prints a "running (limit Ns)" line first. `--log-level` only decides how
much technical log appears below the interface (short local time, paths relative to the working directory, values
cut to 160 characters). Python warnings raised inside libraries are shown only at `debug`.

With `--log-format json`, the tool's own log events are one JSON object per line, complete, and there is no
interface. At the default level (`warning`) only problems are logged: use `--log-level info` for the full event
stream. Messages emitted by third-party libraries through Python's standard `logging`
(httpx, prance, …) are printed as plain text on the same stream as the logs (`logging.basicConfig`, `src/cli.py`);
above `debug` level only their WARNING and higher messages appear. A consumer parsing the logs should skip lines
that are not valid JSON. `validate-config` also prints its result message as plain text in JSON mode.

## `run`

```
apiguard run [--config PATH] [--log-format console|json] [--log-level LEVEL] [--banner|--no-banner]
```

| Option | Default | Description |
|---|---|---|
| `--config`, `-c` | `config.yaml` | Path to the configuration file. Resolved to an absolute path. |
| `--log-format` | `console` | `console`: human-readable, coloured. `json`: one JSON object per line. Case-insensitive. |
| `--log-level` | `warning` | Level of the technical log shown below the interface: `error` only failures of the tool; `warning` also problems the user should know (configuration, cleanup, network, external tools); `info` also the steps of the run and each test result; `debug` also every HTTP transaction, third-party loggers (httpx, httpcore, prance, openapi_spec_validator, urllib3, chardet) and library warnings. |
| `--banner` / `--no-banner` | `--banner` | Show the header and the final summary of the interface (console format only; the test lines are always shown). |
| `--env-file` | `.env` in the working directory | Environment file to load ([Environment and `.env`](#environment-and-env)). Must exist. |

Outputs are written to `output.directory` (see [`report-schema.md`](report-schema.md),
[`evidence-format.md`](evidence-format.md)). Exit codes: [`exit-codes.md`](exit-codes.md).

```bash
apiguard run
apiguard run -c /etc/apiguard/config.yaml --log-format json --no-banner
apiguard run --log-level debug
```

## `validate-config`

```
apiguard validate-config [--config PATH] [--log-format console|json]
```

Runs Phase 1 (reads the YAML, resolves `${VAR}` placeholders, validates the schema) and the test checks: every
test class is declared correctly (`Test definitions invalid: ...`, listing every problem) and every
`execution.test_ids` entry exists and its tool is enabled. It does not fetch the OpenAPI specification and does not
contact the target or the gateway. A filter combination that selects no test is detected only by `run` (Phase 4).

| Option | Default | Description |
|---|---|---|
| `--config`, `-c` | `config.yaml` | Path to the configuration file. |
| `--log-format` | `console` | As for `run`. Log level is fixed to `warning`. |
| `--env-file` | `.env` in the working directory | As for `run`. |

On success prints `Configuration valid. Target: <base_url>` and exits `0`. On failure prints
`Configuration invalid: <reason>` on stderr and exits `10`. Detected failures include: file not found,
unresolved `${VAR}`, invalid values, violated cross-field rules, unknown or misspelled keys (see
[`configuration.md`](configuration.md#validation-rules)). Every schema error is listed, one per line, with its
dotted path.

## `generate-seed`

```
apiguard generate-seed SPEC [--output PATH] [--timeout SECONDS] [--log-format console|json]
```

Extracts every unique path-parameter name (`{owner}`, `{id}`, …) from the specification and produces a YAML
template with each value set to `FILL_ME`. Replace the placeholders with identifiers of real resources on the
target and paste the `path_seed:` block under `target:` in `config.yaml`.

| Argument / option | Default | Description |
|---|---|---|
| `SPEC` (required) | - | HTTP/HTTPS URL or local file path of the specification. Read as-is, without `$ref` dereferencing. |
| `--output`, `-o` | stdout | Write the template to this file (parent directories are created). |
| `--timeout` | `30.0` | Fetch timeout in seconds for URLs, range 1-120. Ignored for local files. |
| `--log-format` | `console` | As for `run`. |

Without `--output` the template is printed to stdout and everything else to stderr, so both
`generate-seed SPEC -o seed.yaml` and `generate-seed SPEC > seed.yaml` produce the same valid file.

Generated template (from `specs/crapi-openapi.json`):

```yaml
path_seed:
  order_id: "FILL_ME"
  postId: "FILL_ME"
  vehicleId: "FILL_ME"
  video_id: "FILL_ME"
```

Exit codes: `0` success, `1` fetch or parse error.

## `version`

```
apiguard version
```

Prints `APIGuard Assurance version <x.y.z>`. The version is read from the installed package metadata
(`pyproject.toml`).

## See also

- [`configuration.md`](configuration.md) - every `config.yaml` field
- [`exit-codes.md`](exit-codes.md)

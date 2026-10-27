# CLI Reference

> **Audience:** users, integrators · **Status:** stable · **Source of truth:** `src/cli.py` (Typer app) ·
> **Verified:** 2026-10-05, v0.1.0 (`--help` output and test invocations); `.env` and `--env-file` 2026-10-08; `list-tests` and the
> SKIP lines of `validate-config` 2026-10-17

```
apiguard [COMMAND] [OPTIONS]
```

The entry point is installed as `apiguard`. From a source checkout without installation:
`python -m src.cli [COMMAND] [OPTIONS]`.

| Command | Purpose |
|---|---|
| [`run`](#run) | Run the assessment against the configured target. |
| [`validate-config`](#validate-config) | Validate `config.yaml` (Phase 1 and the test checks) without contacting the target. |
| [`list-tests`](#list-tests) | List the tests with their declaration, needs and parameters; with a configuration, which run and which SKIP. |
| [`generate-seed`](#generate-seed) | Generate a `path_seed` template from an OpenAPI specification. |
| [`version`](#version) | Print the tool version. |

There are no CLI options to select tests: selection is done in `config.yaml` (`execution.*`, see
[`configuration.md`](01-configuration.md#execution)).

## Environment and `.env`

`run`, `validate-config`, `list-tests --config` and `generate-seed --config` load a `.env` file before reading
`config.yaml` (`_load_env_file`, `src/cli.py`); `${VAR}` placeholders in `config.yaml` are resolved from the
resulting environment.

- **Without `--env-file`:** `.env` in the **current working directory** (where you run the command), if it exists.
  No other folder is searched: not the tool's installation folder, not parent folders. No `.env` is not an error;
  a variable that is still missing stops the tool when `config.yaml` is loaded (exit `10`, naming the variable).
- **With `--env-file PATH`:** that file instead. A path that is not an existing file is an invalid invocation
  (exit `2`).
- **Precedence:** variables already set in the process environment (exported in the shell, set by a CI pipeline,
  a container or a calling program) are never overwritten by the file (`override=False`). Without any file, the
  exported variables alone are enough.

The loaded file is logged (`env_file_loaded`, path only, never values). `version` loads no file, and neither do
`list-tests` and `generate-seed` without `--config`: with no configuration to read there is no placeholder to
resolve.
Verified on 2026-10-08 with a `pip` install in a fresh virtual environment, run from a folder outside the
repository (before, the file was searched from the tool's code folder and a `pip` install never found it).

## Output streams

| Command | stdout | stderr |
|---|---|---|
| `run`, `validate-config`, `version` | console format of `run`: the progress interface and the technical log; JSON format: the log lines; result messages | human-readable error summary of `validate-config` |
| `validate-config --show-config` | **only the configuration** (`config_used.yaml`) | the result messages, logs and errors |
| `generate-seed` | **only the YAML template** (when `--output` is not given), so that `generate-seed SPEC > seed.yaml` writes a valid file | the panel, logs, messages and errors |

**Console format of `run`.** The interface is always shown: a header (target, specification, selection), one line
per test with its status, findings grouped by kind (up to 5 kinds; the full list is in the reports), the reason of
a SKIP or ERROR, then the cleanup, the result counts, the exit code and the paths of the reports. A run that stops
before any verdict (exit 10) shows the exit code and, on a `Reason` line, the reason in full (the technical log
cuts it). On a terminal the
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

<!-- [[[cog import generate_docs as g; cog.out(g.cli_synopsis("run")) ]]] -->

```
apiguard run [--config FILE] [--log-format console|json] [--log-level debug|info|warning|error] [--banner|--no-banner] [--env-file FILE]
```
<!-- [[[end]]] -->

<!-- [[[cog import generate_docs as g; cog.out(g.cli_options("run")) ]]] -->

| Option | Value | Default | Description |
|---|---|---|---|
| `--config`, `-c` | FILE | `config.yaml` | Path to the config.yaml file, resolved to an absolute path. Its ${VAR} placeholders are resolved from the environment (after the .env file is loaded). |
| `--log-format` | `console` \| `json` | `console` | Log format: console (human-readable, coloured) or json (one JSON object per line). Case-insensitive. |
| `--log-level` | `debug` \| `info` \| `warning` \| `error` | `warning` | Level of the technical log shown below the interface: error, only failures of the tool; warning, also problems the user should know (configuration, cleanup, network, external tools); info, also the steps of the run and each test result; debug, also every HTTP transaction, third-party loggers and library warnings. |
| `--banner` / `--no-banner` |  | `--banner` | Show the header and the final summary of the interface (console format only; the test lines are always shown). |
| `--env-file` | FILE | '.env' in the working directory | Load environment variables from this file, which must exist, instead of '.env' in the current working directory. Variables already set in the environment take precedence. |

<!-- [[[end]]] -->

Outputs are written to `output.directory` (see [`report-schema.md`](04-report-schema.md),
[`evidence-format.md`](05-evidence-format.md)). Exit codes: [`exit-codes.md`](03-exit-codes.md).

```bash
apiguard run
apiguard run -c /etc/apiguard/config.yaml --log-format json --no-banner
apiguard run --log-level debug
```

## `validate-config`

<!-- [[[cog import generate_docs as g; cog.out(g.cli_synopsis("validate-config")) ]]] -->

```
apiguard validate-config [--config FILE] [--log-format console|json] [--env-file FILE] [--show-config]
```
<!-- [[[end]]] -->

Runs Phase 1 (reads the YAML, resolves `${VAR}` placeholders, validates the schema) and the test checks: every
test module loads and every test class is declared correctly (`Test definitions invalid: ...`, listing every
problem with its module) and every
`execution.test_ids` entry exists and its tool is enabled. When credentials are configured it also reads the OpenAPI
specification (download or local file, as the run does), to check where the credentials are sent; it never
contacts the gateway or sends a request to the API. A filter combination that selects no test is detected only by `run` (Phase 4).

<!-- [[[cog import generate_docs as g; cog.out(g.cli_options("validate-config")) ]]] -->

| Option | Value | Default | Description |
|---|---|---|---|
| `--config`, `-c` | FILE | `config.yaml` | Path to the config.yaml file to validate. |
| `--log-format` | `console` \| `json` | `console` | Log format: console (human-readable, coloured) or json (one JSON object per line). Case-insensitive. The log level is fixed to warning. |
| `--env-file` | FILE | '.env' in the working directory | Load environment variables from this file, which must exist, instead of '.env' in the current working directory. Variables already set in the environment take precedence. |
| `--show-config` |  | off | Print on stdout the configuration a run would use (config_used.yaml: every key, specified or default); the other messages go to stderr, so the output can be redirected to a file. |

<!-- [[[end]]] -->

On success prints `Configuration valid. Target: <base_url>` (then the credential placement and the resources,
when configured, and `N of the M selected tests will SKIP (what they need is not configured):` with one line per
such test and its reason) and exits `0`. On failure prints
`Configuration invalid: <reason>` on stderr and exits `10`. Detected failures include: file not found,
unresolved `${VAR}`, invalid values, violated cross-field rules, unknown or misspelled keys (see
[`configuration.md`](01-configuration.md#validation-rules)). Every schema error is listed, one per line, with its
dotted path.

With `--show-config` it also prints, on stdout only, the configuration a run would use, as `config_used.yaml`
([details](01-configuration.md#the-configuration-a-run-used-config_usedyaml)): `apiguard validate-config --show-config > used.yaml`
writes the file.

## `list-tests`

<!-- [[[cog import generate_docs as g; cog.out(g.cli_synopsis("list-tests")) ]]] -->

```
apiguard list-tests [--config FILE] [--json] [--env-file FILE]
```
<!-- [[[end]]] -->

Lists every test, native and external, from the tests' own declarations (`TestInfo` and the parameter model in
each test module). Does not contact the target.

<!-- [[[cog import generate_docs as g; cog.out(g.cli_options("list-tests")) ]]] -->

| Option | Value | Default | Description |
|---|---|---|---|
| `--config`, `-c` | FILE | none | Also say, for this config.yaml, whether the run selects each test (the execution filters, the external tools' switches) and why it would SKIP for an unmet need. The configuration, the test declarations and the tests section are checked; the certificates and the specification are not read. |
| `--json` |  | off | Print {"tests": [...]} on stdout instead of the text list, for programs. |
| `--env-file` | FILE | '.env' in the working directory | Load environment variables from this file, which must exist, instead of '.env' in the current working directory. Variables already set in the environment take precedence. |

<!-- [[[end]]] -->

`--env-file` is read only with `--config`.

Text output: one line per test (`ID  P<n>  STRATEGY  name  [needs ...]`); with `--config` a second line, `runs`,
`not selected` or `SKIP: <reasons>`.

JSON output, one object per test (native first, then external, by ID):

| Field | Type | Meaning |
|---|---|---|
| `id`, `name`, `priority`, `strategy`, `cwe`, `tags`, `depends_on`, `requires_pass`, `tool` | as in `TestInfo` | the declaration (`tool` is `null` for a native test) |
| `needs` | list of strings | the `Need` members ([assessment model](../04-architecture/03-assessment-model.md#needs-what-the-configuration-must-hold)) |
| `domain` | int | the methodology domain (first number of the ID) |
| `source` | string | `native` or `external` |
| `parameters_key` | string \| null | the test's section in `config.yaml` (`tests.domain_4.test_4_2`), `null` when it has no parameters |
| `needed_parameters` | list of strings | parameters the test cannot run without |
| `parameters_schema` | object \| null | JSON Schema of the parameters (Pydantic `model_json_schema()`: types, ranges, defaults, descriptions) |
| `selected` | bool | with `--config` only: the run selects the test |
| `unmet_needs` | list of strings | with `--config` only: why it would SKIP (empty when it can run) |

Exit codes: `0` listed, `10` a test cannot be used or the configuration is invalid.

```bash
apiguard list-tests
apiguard list-tests -c config.yaml --json
```

## `generate-seed`

<!-- [[[cog import generate_docs as g; cog.out(g.cli_synopsis("generate-seed")) ]]] -->

```
apiguard generate-seed [SPEC] [--config FILE] [--env-file FILE] [--output FILE] [--timeout 1-120] [--log-format console|json]
```
<!-- [[[end]]] -->

Extracts every unique path-parameter name (`{owner}`, `{id}`, …) from the specification and produces a YAML
template with each value set to `FILL_ME`. Replace the placeholders with identifiers of real resources on the
target and paste the `path_seed:` block under `target:` in `config.yaml`.

<!-- [[[cog import generate_docs as g; cog.out(g.cli_options("generate-seed")) ]]] -->

| Option | Value | Default | Description |
|---|---|---|---|
| `SPEC` |  | none | The OpenAPI specification: an HTTP/HTTPS URL or a local file path, read as-is, without $ref dereferencing. Instead of --config. |
| `--config`, `-c` | FILE | none | Take the specification from this config.yaml: its source, its timeout and its certificate settings (specification.tls). Instead of the SPEC argument. |
| `--env-file` | FILE | '.env' in the working directory | Load environment variables from this file, which must exist, instead of '.env' in the current working directory. Variables already set in the environment take precedence. |
| `--output`, `-o` | FILE | stdout | Write the template to this file (parent directories are created) instead of stdout. |
| `--timeout` | number 1-120 | `30.0` | Fetch timeout (s) for a URL; ignored for a local file. |
| `--log-format` | `console` \| `json` | `console` | Log format: console (human-readable, coloured) or json (one JSON object per line). Case-insensitive. |

<!-- [[[end]]] -->

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

<!-- [[[cog import generate_docs as g; cog.out(g.cli_synopsis("version")) ]]] -->

```
apiguard version
```
<!-- [[[end]]] -->

Prints `APIGuard Assurance version <x.y.z>`. The version is read from the installed package metadata
(`pyproject.toml`).

## See also

- [`configuration.md`](01-configuration.md) - every `config.yaml` field
- [`exit-codes.md`](03-exit-codes.md)

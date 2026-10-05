# CLI Reference

> **Audience:** users, integrators · **Status:** stable · **Source of truth:** `src/cli.py` (Typer app) ·
> **Verified:** 2026-10-05, v0.1.0 (`--help` output and test invocations)

```
apiguard [COMMAND] [OPTIONS]
```

The entry point is installed as `apiguard`. From a source checkout without installation:
`python -m src.cli [COMMAND] [OPTIONS]`.

| Command | Purpose |
|---|---|
| [`run`](#run) | Run the assessment against the configured target. |
| [`validate-config`](#validate-config) | Validate `config.yaml` (Phase 1 only) without contacting the target. |
| [`generate-seed`](#generate-seed) | Generate a `path_seed` template from an OpenAPI specification. |
| [`version`](#version) | Print the tool version. |

There are no CLI options to select tests: selection is done in `config.yaml` (`execution.*`, see
[`configuration.md`](configuration.md#execution)).

## Environment and `.env`

At startup every command loads a `.env` file from the **current working directory**, if present. Variables
already set in the process environment take precedence over `.env` (`load_dotenv(override=False)`,
`src/cli.py:59`). `${VAR}` placeholders in `config.yaml` are resolved from this environment.

## Output streams

| Stream | Content |
|---|---|
| stdout | Structured logs (console or JSON lines), startup banner, completion panel, command results |
| stderr | Human-readable error summary for `validate-config` and `generate-seed` failures |

With `--log-format json`, the tool's own log events are one JSON object per line and the banner and completion
panel are not printed. Messages emitted by third-party libraries through Python's standard `logging`
(httpx, prance, …) are printed as plain text (`logging.basicConfig(format="%(message)s")`, `src/cli.py:537-541`);
above `debug` level only their WARNING and higher messages appear. A consumer parsing stdout should skip lines
that are not valid JSON. `validate-config` and `generate-seed` also print their result message on stdout as
plain text in JSON mode.

## `run`

```
apiguard run [--config PATH] [--log-format console|json] [--log-level LEVEL] [--banner|--no-banner]
```

| Option | Default | Description |
|---|---|---|
| `--config`, `-c` | `config.yaml` | Path to the configuration file. Resolved to an absolute path. |
| `--log-format` | `console` | `console`: human-readable, coloured. `json`: one JSON object per line. Case-insensitive. |
| `--log-level` | `info` | `debug`, `info`, `warning`, `error`. `debug` logs every HTTP transaction and lets third-party loggers (httpx, httpcore, prance, openapi_spec_validator, urllib3, chardet) through; above `debug` they are limited to WARNING. |
| `--banner` / `--no-banner` | `--banner` | Show the startup banner and completion panel. Only effective with `--log-format console`. |

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

Runs Phase 1 only: reads the YAML, resolves `${VAR}` placeholders, validates the schema. It does not fetch the
OpenAPI specification and does not contact the target or the gateway.

| Option | Default | Description |
|---|---|---|
| `--config`, `-c` | `config.yaml` | Path to the configuration file. |
| `--log-format` | `console` | As for `run`. Log level is fixed to `info`. |

On success prints `Configuration valid. Target: <base_url>` and exits `0`. On failure prints
`Configuration invalid: <reason>` on stderr and exits `10`. Detected failures include: file not found,
unresolved `${VAR}`, invalid values, violated cross-field rules (see
[`configuration.md`](configuration.md#validation-rules)).

**Not detected:** misspelled or unknown keys - they are ignored and the default applies (Q-22).

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

**Use `--output` to produce a file.** Without it, the template is printed to stdout together with logs and a
panel, and long lines may be wrapped: redirecting stdout to a file does not produce valid YAML (Q-21).

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

# Coding Rules

> **Audience:** contributors · **Status:** v0.1.0 · **Source of truth:** `pyproject.toml` (tool configuration and
> hatch scripts), the project rules in `CLAUDE.md` and `docs/project/claude-rules.it.md` §5 ·
> **Verified:** 2026-10-05 (`hatch run dev:check` passes; `ruff format --check` does not, see below)

Rules every change must follow. Where the current code deviates, the deviation is stated and tracked in
`OPEN_QUESTIONS.md`.

## Language and style

- Everything in English: identifiers, docstrings, comments, log event names, exception messages. Only literal
  target values (e.g. an endpoint path) may be in another language.
- Ruff is the only formatter and linter: `line-length = 100`, `target-version = "py311"`, rule sets
  `E, W, F, I, N, UP, B, S, ANN` (`S101` ignored), double quotes.
- Comments explain *why*, not *what*. No `TODO`, `FIXME`, `HACK`, no emoji. No `pass` placeholders; `...` only as
  the body of an `@abstractmethod`.

## Types and models

- Type hints on every function signature, return type included. `Any` only when unavoidable (arbitrary JSON),
  with a comment.
- mypy in strict mode with the Pydantic plugin.
- Data that crosses a boundary (configuration, HTTP data, results) is modelled with Pydantic v2; configuration and
  context models are `frozen`.
- `TypedDict` is currently used for typed dict shapes: `ConnectorRawOutput`, `TlsFinding` and two internal
  metadata helpers. Where it is allowed is to be clarified (Q-39).
- Public functions and methods have full docstrings.

## Constants and configuration

- No magic numbers or strings: use named module constants, or a `config.yaml` parameter when the value is
  something an operator may need to tune.
- Every tunable parameter lives under `tests.domain_<D>.test_<D>_<N>.<param>` (or `external_tools.<tool>`), has a
  Pydantic `description` and is documented in [`reference/configuration.md`](../../reference/configuration.md).

## Architecture

- Dependency direction: `core/` ← `connectors/` ← `tests/`, `external_tests/` ← `engine.py`. Nothing imports
  `engine.py`; tests never import `config/`, `discovery/`, `report/` or `connectors/`
  ([overview](../../architecture/overview.md#module-structure-and-dependencies)).
- All requests to the target API go through `SecurityClient.request()`; do not import `httpx` in tests. (Test 1.5
  sub-test 1 is a documented exception: it probes the plain-HTTP port directly.)
- Native tests never start subprocesses; external tools run only through connectors.
- No module-level singleton of `SecurityClient`.
- File paths shown in reports go through `_relativize_display_path()` in `src/connectors/base.py`, the only
  normalisation function; temporary file paths never appear in `command` / `command_json`.

## Errors and logging

- Raise only exceptions from the project hierarchy (`src/core/exceptions.py`, `GatewayAdapterError`); no bare
  `except:` and no silent `except Exception: pass`. A test's `execute()` ends with
  `except Exception as exc: return self._make_error(exc)`.
- Logging with `structlog`, as events with key-value pairs (`log.info("test_2_1_starting", endpoint_count=...)`),
  not interpolated strings. No `print()`; terminal output in the CLI uses `rich` consoles.
- Never log credential values. Use `[REDACTED]` if a structure that may contain them must be logged.
- Random values for security purposes come from `secrets`, never `random`.

## Naming

| Item | Convention |
|---|---|
| Native test module | `src/tests/domain_<D>/test_<D>_<N>_<description>.py` |
| External test module | `src/external_tests/ext_test_<D>_<N>_<description>.py` |
| Native `test_id` | `"<D>.<N>"` |
| External `test_id` | `"ext.<D>.<N>.<tool>"` |
| Config key | `test_<D>_<N>` |
| Oracle states | `SCREAMING_SNAKE_CASE` module constants |

Numbers in module names are reserved for test modules (the general rule "no numbers in module filenames" has this
exception, Q-39).

## Dependencies

Runtime dependencies use `>=FLOOR,<NEXT_MAJOR`, where FLOOR is the version tested; the only exact pin is
`prance==25.4.8.0`. Optional, licence-sensitive tools go in `[project.optional-dependencies]` (sslyze, AGPL v3).

## Testing

There is no automated unit test suite; mocking `httpx` is not accepted because it would not prove anything about
security behaviour. Changes are verified by running the affected tests against the lab target
(`test-environments/forgejo-kong/`) with `execution.test_ids`. An E2E suite against the lab is planned (Q-51).

## Before submitting

```bash
hatch run dev:check                  # ruff check, mypy src/, bandit (medium), vulture (80)
hatch run dev:ruff format --check .  # not part of dev:check
hatch run dev:deps                   # pip-audit, before a release
```

State on 2026-10-05: `dev:check` passes; `ruff format --check` reports 7 files to reformat (listed in Q-39).

Update the documentation in the same change: the test page in `docs/tests/`, the catalogue row,
`reference/configuration.md` for new parameters, and `docs/project/roadmap.md`.

## See also

- [`add-a-native-test.md`](add-a-native-test.md) · [`add-an-external-test.md`](add-an-external-test.md) · [`add-a-gateway-adapter.md`](add-a-gateway-adapter.md)

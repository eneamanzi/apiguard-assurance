# Contributing

How to work on APIGuard Assurance itself. To use the tool, start from the [README](README.md).

## Set up

Follow [Installation](docs/getting-started/installation.md) and [First assessment](docs/getting-started/first-assessment.md):
the lab they start (Forgejo + Kong in Docker) is the target every change is verified against.

The project uses two Hatch environments, both created on first use:

| Environment | Used by | Contains |
|---|---|---|
| `default` | `hatch run apiguard ...`, `hatch shell` | the tool and its runtime dependencies (sslyze included) |
| `dev` | `hatch run dev:<script>`, `hatch shell dev` | the tool plus ruff, mypy, bandit, vulture, pip-audit |

## Before you write code

- [Coding rules](docs/guides/extending/coding-rules.md): style, types, constants, architecture, errors and logging.
- [Architecture overview](docs/architecture/overview.md): pipeline phases and module dependencies (the dependency
  direction is strict).
- To add something, follow the matching guide:
  [native test](docs/guides/extending/add-a-native-test.md),
  [external test or connector](docs/guides/extending/add-an-external-test.md),
  [gateway adapter](docs/guides/extending/add-a-gateway-adapter.md).

## Verify a change

There is no automated test suite yet (an E2E suite against the lab is planned, Q-51); mocking HTTP would prove nothing
about security behaviour. Until then a change is verified by hand against the lab.

1. Static checks (must pass):

   ```bash
   hatch run dev:check
   ```

   It runs `ruff check`, `ruff format --check`, `mypy src/` (strict), `bandit` (medium severity), `vulture` and
   `lint-imports` (the dependency rules between packages). To fix the formatting: `hatch run dev:ruff format .`.

2. Run the affected tests only, not the full assessment: copy `config.yaml`, set `execution.test_ids` and turn off
   the external tools if you do not need them ([select tests](docs/guides/usage/select-tests.md)). Compare the
   result with the previous run (status, findings, `oracle_state` counts) with the development helper:

   ```bash
   hatch run python scripts/compare_reports.py before.json after.json
   ```

   It prints the differences test by test and exits `0` when there are none.

3. Before a release, check the dependencies for known vulnerabilities:

   ```bash
   hatch run dev:deps
   ```


## Update the documentation in the same change

| You changed | Update |
|---|---|
| a test's behaviour | its page in [`docs/tests/`](docs/tests/README.md) and the catalogue row |
| a configuration parameter | [`docs/reference/configuration.md`](docs/reference/configuration.md) and the commented `config.yaml` |
| the report or evidence format | [`report-schema.md`](docs/reference/report-schema.md), [`evidence-format.md`](docs/reference/evidence-format.md) |
| the lab | [`first-assessment.md`](docs/getting-started/first-assessment.md) (commands and expected output) |
| what is implemented | [`docs/project/roadmap.md`](docs/project/roadmap.md) and [`CHANGELOG.md`](CHANGELOG.md) |

Documentation states only facts checked against the code or a run. A doubt, or a behaviour that looks wrong, goes
to [`OPEN_QUESTIONS.md`](OPEN_QUESTIONS.md) with its evidence; the project owner decides and closes it.

## Commits

Commit messages start with the area of the change, as in the history: `docs:`, `fix:`, `refactor:`, `lab:`,
followed by a short summary. Never commit `.env` (it is ignored by git) or anything containing real credentials.

## Project state

What is implemented and what comes next: [`docs/project/roadmap.md`](docs/project/roadmap.md). Current work plan:
[`docs/project/plan.md`](docs/project/plan.md).

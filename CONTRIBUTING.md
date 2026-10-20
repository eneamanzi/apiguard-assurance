# Contributing

How to work on APIGuard Assurance itself. To use the tool, start from the [README](README.md).

## Set up

Follow [Installation](docs/01-getting-started/01-installation.md) and [First assessment](docs/01-getting-started/02-first-assessment.md):
the lab they start (Forgejo + Kong in Docker) is the target every change is verified against.

The project uses two Hatch environments, both created on first use:

| Environment | Used by | Contains |
|---|---|---|
| `default` | `hatch run apiguard ...`, `hatch shell` | the tool and its runtime dependencies (sslyze included) |
| `dev` | `hatch run dev:<script>`, `hatch shell dev` | the tool plus ruff, mypy, bandit, vulture, pip-audit |

## Before you write code

- [Coding rules](docs/02-guides/03-extending/01-coding-rules.md): style, types, constants, architecture, errors and logging.
- [Architecture overview](docs/04-architecture/01-overview.md): pipeline phases and module dependencies (the dependency
  direction is strict).
- To add something, follow the matching guide:
  [native test](docs/02-guides/03-extending/02-add-a-native-test.md),
  [external test or connector](docs/02-guides/03-extending/03-add-an-external-test.md),
  [gateway adapter](docs/02-guides/03-extending/04-add-a-gateway-adapter.md).

## Verify a change

There is no automated test suite yet (an E2E suite against the lab is planned, Q-51); mocking HTTP would prove nothing
about security behaviour. Until then a change is verified by hand against the lab.

1. Static checks (must pass):

   ```bash
   hatch run dev:check
   ```

   It runs `ruff check`, `ruff format --check`, `mypy src/ scripts/` (strict), `bandit` (medium severity), `vulture`,
   `lint-imports` (the dependency rules between packages), the check of `config.example.yaml` and the check of the
   generated documentation; what each step checks: [maintainer commands](docs/project/maintainer-commands.md#static-analysis).
   To fix the formatting: `hatch run dev:ruff format .`. GitHub runs the same on every push and pull request
   (`.github/workflows/check.yml`, Python 3.11 and 3.14), and checks that the built package installs and runs.

2. Run the affected tests only, not the full assessment: copy the lab's configuration (`test-environments/forgejo-kong/config.yaml`), set `execution.test_ids` and turn off
   the external tools if you do not need them ([select tests](docs/02-guides/01-usage/02-select-tests.md)). Compare the
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
| a test's behaviour | its page in [`docs/05-tests/`](docs/05-tests/README.md) and the catalogue row |
| a configuration parameter | [`docs/03-reference/01-configuration.md`](docs/03-reference/01-configuration.md) and `config.example.yaml` (checked by `hatch run dev:check`: every key must be listed) |
| the report or evidence format | [`report-schema.md`](docs/03-reference/04-report-schema.md), [`evidence-format.md`](docs/03-reference/05-evidence-format.md) |
| the lab | [`first-assessment.md`](docs/01-getting-started/02-first-assessment.md) (commands and expected output) |
| what is implemented | [`docs/project/roadmap.md`](docs/project/roadmap.md) and [`CHANGELOG.md`](CHANGELOG.md) |

Documentation states only facts checked against the code or a run. A doubt, or a behaviour that looks wrong, goes
to [`OPEN_QUESTIONS.md`](OPEN_QUESTIONS.md) with its evidence; the project owner decides and closes it.

## Commits

Commit messages start with the area of the change, as in the history: `docs:`, `fix:`, `refactor:`, `lab:`,
followed by a short summary. Never commit `.env` (it is ignored by git) or anything containing real credentials.

## Project state

What is implemented and what comes next: [`docs/project/roadmap.md`](docs/project/roadmap.md). Current work plan:
[`docs/project/plan.md`](docs/project/plan.md).

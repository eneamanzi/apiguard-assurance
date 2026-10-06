# APIGuard Assurance - Maintainer Cheat Sheet

> **Audience:** project owner · Personal commands for maintaining the repository. Product commands are
> documented in [`reference/cli.md`](../reference/cli.md) and [`CONTRIBUTING.md`](../../CONTRIBUTING.md); this page
> repeats them only as a quick reminder.

- [Export Utility](#export-utility)
  - [New mode (recommended)](#new-mode-recommended)
  - [Legacy mode (manual)](#legacy-mode-manual)
- [Viewing the Report (VS Code Remote)](#viewing-the-report-vs-code-remote)
- [Environment Management (Hatch)](#environment-management-hatch)
- [Running the Tool (CLI)](#running-the-tool-cli)
  - [Other CLI commands](#other-cli-commands)
  - [Exit codes](#exit-codes)
- [Building the Package](#building-the-package)
- [Static Analysis](#static-analysis)
- [Kong Configuration Changes](#kong-configuration-changes)
- [Git - Clean Up Commit History](#git---clean-up-commit-history)
- [Git tag + release](#git-tag--release)


## Export Utility

Create an updated ZIP with all sources and tests (excluding cache, pycache, and reports).

### New mode (recommended)
```bash
# Create a zip with all domains, same exclusions as the manual zip command below.
./build_zip.sh

# Create a zip including only the specified domain.
./build_zip.sh -d 6

# Create a zip including only the specified domains.
./build_zip.sh -d 5,6
```

### Legacy mode (manual)
```bash
zip -r apiguard-assurance.zip . -x "*.git/*" -x "*__pycache__*" -x "*.pyc" -x "*.ruff_cache*" -x "*.pytest_cache*" -x "*.mypy_cache*" -x "*.vscode*" -x "*outputs/*" -x "*specs/*" -x "*.zip" -x ".env" -x "src/report/templates/*"
```

## Viewing the Report (VS Code Remote)

Start a local web server to view the HTML report via Port Forwarding:
```bash
cd outputs
python3 -m http.server 8080
```
Open `http://localhost:8080` in your browser and click `assessment_report.html`. Press `Ctrl+C` to stop.


## Environment Management (Hatch)

Open a shell in an environment (`exit` to leave):
```bash
hatch shell        # default environment: the tool (apiguard ...)
hatch shell dev    # dev environment: the tool + ruff, mypy, bandit, vulture, pip-audit
```

Or prefix single commands: `hatch run apiguard ...`, `hatch run dev:<script>`.


## Running the Tool (CLI)

> `.env` is read from the working directory: run from the repository root.

```bash
hatch run apiguard run                        # config.yaml in the working directory
hatch run apiguard run -c config_crapi.yaml   # another configuration file
```

Inside `hatch shell` drop the `hatch run` prefix.

### Other CLI commands

```bash
apiguard version                              # Print the tool version and exit
apiguard validate-config                      # Run only Phase 1 (config load + validation), exit 0 if OK / 10 if invalid
apiguard validate-config -c config_crapi.yaml # Validate a non-default config

apiguard generate-seed <openapi-spec-url>     # Generate a path_seed YAML template from an OpenAPI spec
apiguard generate-seed <spec> -o seed.yaml    # Write the template to seed.yaml instead of stdout
```

`generate-seed` extracts every `{param}` placeholder declared in the OpenAPI spec and emits a YAML template
with `FILL_ME` defaults. After filling in real resource identifiers, paste the template under `target:` in
`config.yaml` so parametric endpoints (e.g. `/repos/{owner}/{repo}`) receive routable values during the
assessment instead of generic placeholders.

### Exit codes

`0` clean, `1` violation, `2` a check did not complete, `10` the assessment did not run, `130` interrupted.
Details: [`reference/exit-codes.md`](../reference/exit-codes.md).


## Building the Package

`hatch build` compiles the project into distributable artifacts inside `dist/` (ignored by git):

```bash
hatch build                  # produces both wheel (.whl) and source distribution (.tar.gz)
hatch build --target wheel   # wheel only (faster: use for install testing)
```

**What gets produced:**

| File | Purpose |
|------|---------|
| `dist/apiguard_assurance-X.Y.Z-py3-none-any.whl` | Installable wheel: use for cold-install tests or PyPI upload |
| `dist/apiguard_assurance-X.Y.Z.tar.gz` | Source distribution: contains only the public surface (see below) |

**What the sdist includes** (whitelist in `pyproject.toml`, checked with `hatch build -t sdist` on 2026-10-06):
`src/`, `docs/` except `docs/knowledge/` and `docs/project/`, `README.md`, `pyproject.toml`, `config.yaml`,
`.env.example`, `.gitignore`, `install_tools.sh`.

**What the sdist excludes**: `docs/knowledge/`, `docs/project/`, `CLAUDE.md`, `CONTRIBUTING.md`, `CHANGELOG.md`,
`OPEN_QUESTIONS.md`, `test-environments/`, `outputs/`, `tools/`, `.claude/`, `.env`.

**Cold-install test** (verifies the wheel works in a clean environment):
```bash
python -m venv /tmp/cold-test
source /tmp/cold-test/bin/activate
pip install dist/apiguard_assurance-*.whl
apiguard --help
apiguard validate-config --config config.yaml
deactivate && rm -rf /tmp/cold-test
```

> `dist/` is regenerated on every `hatch build`.


## Static Analysis

```bash
hatch run dev:lint    # ruff + mypy           (fast: run on every commit)
hatch run dev:audit   # bandit + vulture       (slower: run before push)
hatch run dev:check   # full suite in sequence
hatch run dev:deps    # pip-audit              (run before any release)
```

Individual tools:
```bash
ruff check src/
mypy src/
```


## Kong Configuration Changes

Reload Kong and pick up a new declarative configuration:
```bash
docker compose --env-file ../../.env up -d --force-recreate kong   # from test-environments/forgejo-kong
```


## Git - Clean Up Commit History

View commit log:
```bash
git log --oneline
```

Interactive rebase to squash/reword commits:
```bash
git rebase -i <HASH>   # first stable commit hash
# In the editor: keep the first of each group as 'pick',
# change subsequent ones to 'fixup' (drops their message)
# or 'reword' (lets you rename the message).
git log --oneline      # verify the result
git push -f
```

Add a forgotten file to the previous commit:
```bash
git add <file>
git commit --amend --no-edit
```

## Git tag + release
Create and push tag (update `CHANGELOG.md` first: move "Unreleased" under the new version)
```bash
git tag -a v0.1.0 -m "Release v0.1.0 - Milestone 1: 18 automated tests, 3 connectors, full 7-phase pipeline"

git push origin v0.1.0
```

Delete tag locally and remote
```bash
git tag -d v0.1.0

git push origin -d v0.1.0
```

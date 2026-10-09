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
cd outputs && python3 -m http.server 8080    # Ctrl+C to stop, then: cd ..
```
Open `http://localhost:8080` in your browser and click `assessment_report.html`.

If the page does not load:
- look at the server terminal while reloading: a `"GET /... 200"` line means the request arrives (reload with
  `Ctrl+Shift+R`); no line means the port forwarding is broken;
- VS Code **PORTS** tab: right-click 8080 → **Stop Forwarding**, then **Forward a Port** → `8080`; check that the
  "Forwarded Address" column says `localhost:8080` (if 8080 is busy on your computer VS Code picks another port);
- or use another port: `python3 -m http.server 8090`;
- "Address already in use": a server is still running in another terminal, stop it first.

Without any server: Explorer → `outputs/assessment_report.html` → right-click → **Download...**, then open the
file on your computer (the report is a single self-contained file).


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

**How much to see** (the progress interface is always shown; `--log-level` adds the technical log below it; the
value goes without dashes: `--log-level info`, not `--log-level --info`):
```bash
apiguard run                       # default (warning): one line per test, problems only, summary
apiguard run --log-level info      # + steps of the run and every single test result
apiguard run --log-level debug     # + every HTTP request, third-party logs, library warnings
apiguard run --log-level error     # technical log: only failures of the tool
apiguard run --no-banner           # without header and final summary
apiguard run --log-format json --log-level info   # machine format: one JSON event per line, no interface
```

**Run only some tests** (fast checks, no full run): in a copy of `config.yaml` set
```yaml
execution:
  test_ids: ["1.1", "7.2"]            # only these (native or ext.X.Y.tool)
external_tools:
  enabled: false                      # or keep true and list the ext.* IDs you want
```
then `apiguard run -c config.test.yaml`. Only native tests: `external_tools.enabled: false` with no `test_ids`.

**Stopping a run:** `Ctrl+C` (or `kill <pid>`) removes what the tests created on the target, then exits; a second
`Ctrl+C` only says to wait. Never `kill -9`: it leaves tokens and repositories on the target.

**Check that the lab is clean** (after an interrupted run; only `user-a/test-repo` must remain):
```bash
set -a; . ./.env; set +a
curl -s -u "$USER_A_USERNAME:$USER_A_PASSWORD" http://localhost:8000/api/v1/users/$USER_A_USERNAME/tokens
curl -s -u "$USER_A_USERNAME:$USER_A_PASSWORD" http://localhost:8000/api/v1/user/repos | python3 -c "import json,sys; print([r['full_name'] for r in json.load(sys.stdin)])"
```

**Compare two runs** (development helper; tests, statuses, findings, oracle states, exit code):
```bash
cp outputs/apiguard_report.json /tmp/before.json      # before a change
hatch run python scripts/compare_reports.py /tmp/before.json outputs/apiguard_report.json   # after
```

### Other CLI commands

```bash
apiguard version                              # Print the tool version and exit
apiguard validate-config                      # Phase 1 + test checks (config, test declarations, test_ids), exit 0 if OK / 10 if invalid
apiguard validate-config -c config_crapi.yaml # Validate a non-default config

apiguard generate-seed <openapi-spec-url>     # Generate a path_seed YAML template from an OpenAPI spec
apiguard generate-seed <spec> -o seed.yaml    # Write the template to seed.yaml instead of stdout
```

`generate-seed` extracts every `{param}` placeholder declared in the OpenAPI spec and emits a YAML template
with `FILL_ME` defaults. After filling in real resource identifiers, paste the template under `target:` in
`config.yaml` so parametric endpoints (e.g. `/repos/{owner}/{repo}`) receive routable values during the
assessment instead of generic placeholders.

### Exit codes

`0` clean, `1` violation, `2` invalid invocation, `3` a check did not complete, `10` the assessment did not run,
`130` interrupted (Ctrl+C), `143` terminated (SIGTERM).
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

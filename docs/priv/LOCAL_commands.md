# APIGuard Assurance — Command Cheat Sheet

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

Activate the virtual environment:
```bash
hatch shell dev
```

Or prefix commands with `hatch run -e dev`.


## Running the Tool (CLI)

> Ensure `.env` variables are loaded or the file exists in the project root.

**Development (direct):**
```bash
python -m src.cli
```

**Installed (if configured in pyproject.toml):**
```bash
apiguard run
```

**Run against a different config:**
```bash
apiguard run -c config_crapi.yaml
```

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

| Code | Meaning |
|------|---------|
| `0` | CLEAN — no violation detected |
| `1` | FAIL — at least one security guarantee violated |
| `2` | ERROR — at least one verification did not complete |
| `10` | INFRA — configuration / OpenAPI / DAG bootstrap error (assessment did not start) |


## Building the Package

`hatch build` compiles the project into distributable artifacts inside `dist/` (ignored by git):

```bash
hatch build                  # produces both wheel (.whl) and source distribution (.tar.gz)
hatch build --target wheel   # wheel only (faster — use for install testing)
```

**What gets produced:**

| File | Purpose |
|------|---------|
| `dist/apiguard_assurance-X.Y.Z-py3-none-any.whl` | Installable wheel — use for cold-install tests or PyPI upload |
| `dist/apiguard_assurance-X.Y.Z.tar.gz` | Source distribution — contains only the public surface (see below) |

**What the sdist includes** (whitelist in `pyproject.toml`):
`src/`, `docs/pub/`, `README.md`, `docs/priv/LOCAL_commands.md`, `pyproject.toml`, `config.yaml`, `.env.example`, `.gitignore`, `install_tools.sh`

**What the sdist excludes**: `docs/priv/` internal files (audit, status, knowledge), `outputs/`, `tools/`, `.claude/`, `CLAUDE.md`.

**Cold-install test** (verifies the wheel works in a clean environment):
```bash
python -m venv /tmp/cold-test
source /tmp/cold-test/bin/activate
pip install dist/apiguard_assurance-*.whl
apiguard --help
apiguard validate-config --config config.yaml
deactivate && rm -rf /tmp/cold-test
```

> `dist/` is regenerated on every `hatch build` and is deterministic — two consecutive builds produce byte-identical wheels.


## Static Analysis

```bash
hatch run dev:lint    # ruff + mypy           (fast — run on every commit)
hatch run dev:audit   # bandit + vulture       (slower — run before push)
hatch run dev:check   # full suite in sequence (CI gate)
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
docker compose up -d --force-recreate kong
```


## Git — Clean Up Commit History

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

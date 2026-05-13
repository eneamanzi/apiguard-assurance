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

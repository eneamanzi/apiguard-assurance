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
cd outputs/forgejo && python3 -m http.server 8080    # Ctrl+C to stop, then: cd ../..   (crAPI lab: outputs/crapi, APISIX lab: outputs/forgejo-apisix)
```
Open `http://localhost:8080` in your browser and click `assessment_report.html`.

If the page does not load:
- look at the server terminal while reloading: a `"GET /... 200"` line means the request arrives (reload with
  `Ctrl+Shift+R`); no line means the port forwarding is broken;
- VS Code **PORTS** tab: right-click 8080 → **Stop Forwarding**, then **Forward a Port** → `8080`; check that the
  "Forwarded Address" column says `localhost:8080` (if 8080 is busy on your computer VS Code picks another port);
- or use another port: `python3 -m http.server 8090`;
- "Address already in use": a server is still running in another terminal, stop it first.

Without any server: Explorer → `outputs/forgejo/assessment_report.html` → right-click → **Download...**, then open the
file on your computer (the report is a single self-contained file).


## Environment Management (Hatch)

Open a shell in an environment (`exit` to leave):
```bash
hatch shell        # default environment: the tool (apiguard ...)
hatch shell dev    # dev environment: the tool + ruff, mypy, bandit, vulture, pip-audit
```

Or prefix single commands: `hatch run apiguard ...`, `hatch run dev:<script>`.


## Running the Tool (CLI)

> Run from the repository root: `.env` and the relative paths in the configuration files are read from the
> working directory. The lab configurations: [Test Labs](#test-labs).

```bash
hatch run apiguard run -c test-environments/forgejo-kong/config.yaml   # Forgejo lab
hatch run apiguard run -c test-environments/crapi-kong/config.yaml     # crAPI lab
hatch run apiguard run -c test-environments/forgejo-apisix/config.yaml # Forgejo + APISIX lab
```

The examples below use the Forgejo lab configuration, set once in the shell:
```bash
CFG=test-environments/forgejo-kong/config.yaml
```

Inside `hatch shell` drop the `hatch run` prefix.

**How much to see** (the progress interface is always shown; `--log-level` adds the technical log below it; the
value goes without dashes: `--log-level info`, not `--log-level --info`):
```bash
apiguard run -c $CFG                       # default (warning): one line per test, problems only, summary
apiguard run -c $CFG --log-level info      # + steps of the run and every single test result
apiguard run -c $CFG --log-level debug     # + every HTTP request, third-party logs, library warnings
apiguard run -c $CFG --log-level error     # technical log: only failures of the tool
apiguard run -c $CFG --no-banner           # without header and final summary
apiguard run -c $CFG --log-format json --log-level info   # machine format: one JSON event per line, no interface
```

**Run only some tests** (fast checks, no full run): in a copy of the lab configuration (`cp $CFG config.test.yaml`) set
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
curl -sk -u "$USER_A_USERNAME:$USER_A_PASSWORD" https://localhost:8443/api/v1/users/$USER_A_USERNAME/tokens
curl -sk -u "$USER_A_USERNAME:$USER_A_PASSWORD" https://localhost:8443/api/v1/user/repos | python3 -c "import json,sys; print([r['full_name'] for r in json.load(sys.stdin)])"
```

**Compare two runs** (development helper; tests, statuses, findings, oracle states, exit code):
```bash
cp outputs/forgejo/apiguard_report.json /tmp/before.json      # before a change
hatch run python scripts/compare_reports.py /tmp/before.json outputs/forgejo/apiguard_report.json   # after
```

### Other CLI commands

```bash
apiguard version                              # Print the tool version and exit
apiguard validate-config -c $CFG              # Phase 1 + test checks (config, test declarations, test_ids), exit 0 if OK / 10 if invalid
apiguard validate-config -c test-environments/crapi-kong/config.yaml   # the crAPI lab configuration

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
`src/`, `docs/` except `docs/knowledge/` and `docs/project/`, `README.md`, `pyproject.toml`, `.env.example`,
`.gitignore`, `install_tools.sh`. No configuration file: the lab configurations are in `test-environments/`.

**What the sdist excludes**: `docs/knowledge/`, `docs/project/`, `CLAUDE.md`, `CONTRIBUTING.md`, `CHANGELOG.md`,
`OPEN_QUESTIONS.md`, `test-environments/`, `outputs/`, `tools/`, `.claude/`, `.env`.

**Cold-install test** (verifies the wheel works in a clean environment):
```bash
python -m venv /tmp/cold-test
source /tmp/cold-test/bin/activate
pip install dist/apiguard_assurance-*.whl
apiguard --help
apiguard validate-config -c test-environments/forgejo-kong/config.yaml   # from the repository root
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
docker compose --env-file ../../.env up -d --force-recreate kong   # from the lab folder (forgejo-kong or crapi-kong)
```

Check a declarative configuration before loading it (from the lab folder):
```bash
docker run --rm -e KONG_DATABASE=off -v "$PWD/kong:/kong:ro" kong:3.9.3 kong config parse /kong/kong.yml
```

## APISIX Configuration Changes

From `test-environments/forgejo-apisix`. Routes, upstream and plugins (`apisix/setup.sh`) are written through the
Admin API: run the setup again after changing them. The startup configuration (`apisix/config.yaml`) is read when
APISIX starts: restart it, the routes stay in etcd.
```bash
docker compose --env-file ../../.env up apisix-setup                                         # after editing apisix/setup.sh
docker compose --env-file ../../.env restart apisix && docker compose --env-file ../../.env up -d --wait apisix   # after editing apisix/config.yaml
```


## Test Labs

Three labs, same steps. Each has its own ports, so they can run at the same time. Versions and design:
[compatibility](../reference/compatibility.md#test-lab). Every `docker compose` command runs from the lab folder
with `--env-file ../../.env`: compose looks for `.env` only in the folder it runs from, and the credentials are in
the `.env` of the repository root.

| | Forgejo + Kong | crAPI + Kong | Forgejo + APISIX |
|---|---|---|---|
| Folder | `test-environments/forgejo-kong` | `test-environments/crapi-kong` | `test-environments/forgejo-apisix` |
| Tool configuration | `test-environments/forgejo-kong/config.yaml` | `test-environments/crapi-kong/config.yaml` | `test-environments/forgejo-apisix/config.yaml` |
| Ports (proxy HTTP, HTTPS, Admin API) | 8000, 8443, 8001 (+ Forgejo 3000) | 9000, 9443, 9001 | 10000, 10443, 10001 (+ Control API 10002, Forgejo 10003) |
| Setup services | `forgejo-setup` | `crapi-setup` | `forgejo-setup`, `apisix-setup` |

**Start** (the first time it downloads the images). The first command starts the lab and waits until the gateway is
healthy; the second runs the setup once, in the foreground, so its output is shown. Running the setup again is
harmless.

```bash
# Forgejo lab
cd test-environments/forgejo-kong
docker compose --env-file ../../.env up -d --wait kong
docker compose --env-file ../../.env up forgejo-setup     # ends with "Provisioning completed."
cd ../..

# crAPI lab
cd test-environments/crapi-kong
docker compose --env-file ../../.env up -d --wait kong
docker compose --env-file ../../.env up crapi-setup       # ends with three "Login ... OK" and "crAPI lab ready"
cd ../..

# Forgejo + APISIX lab (APISIX starts without routes: apisix-setup writes them)
cd test-environments/forgejo-apisix
docker compose --env-file ../../.env up -d --wait apisix
docker compose --env-file ../../.env up forgejo-setup apisix-setup   # "Provisioning completed." and "APISIX configuration completed."
cd ../..
```

**Runs one after the other need no reset, but on the crAPI lab wait a few seconds.** Test 7.2 makes the workshop
service answer 503/504 and Kong's passive health check excludes it; the active health check re-enables it about 5
seconds later (Q-66). A run started within that window gets 503 from the workshop endpoints, and test 1.1 can PASS
without having checked them (seen 2026-10-14, Q-29). Before the next run, the last command of the crAPI check below
must print `"health":"HEALTHY"`.

**Check that a lab is ready** (each line must print `200`):

```bash
# Forgejo lab
curl -s  -o /dev/null -w "forgejo     %{http_code}\n" http://localhost:3000/swagger.v1.json
curl -sk -o /dev/null -w "kong https  %{http_code}\n" https://localhost:8443/api/v1/version
curl -s  -o /dev/null -w "kong admin  %{http_code}\n" http://localhost:8001/status

# crAPI lab (a public endpoint of crAPI's identity service, through Kong)
curl -sk -o /dev/null -w "kong https  %{http_code}\n" https://localhost:9443/identity/api/auth/jwks.json
curl -s  -o /dev/null -w "kong admin  %{http_code}\n" http://localhost:9001/status
curl -s http://localhost:9001/upstreams/workshop-upstream/health | grep -o '"health":"[A-Z]*"' | head -1   # "HEALTHY"

# Forgejo + APISIX lab (from the repository root: the Admin API needs the viewer key of .env)
curl -s  -o /dev/null -w "forgejo       %{http_code}\n" http://localhost:10003/swagger.v1.json
curl -sk -o /dev/null -w "apisix https  %{http_code}\n" https://localhost:10443/api/v1/version
curl -s  -o /dev/null -w "apisix admin  %{http_code}\n" -H "X-API-KEY: $(sed -n 's/^APISIX_VIEWER_KEY=//p' .env)" http://127.0.0.1:10001/apisix/admin/routes
curl -s http://127.0.0.1:10002/v1/healthcheck | grep -o '"status":"[a-z_]*"' | head -1   # "healthy" (empty until the first request through APISIX)
```

**Full reset** (deletes the data; then start again as above). From the lab folder:

```bash
docker compose --env-file ../../.env down -v
```

**Stop without deleting the data** / **see what is running**:

```bash
docker compose --env-file ../../.env stop       # from the lab folder; start again with the commands above
docker ps --format '{{.Names}}\t{{.Status}}'    # Forgejo lab: kong, forgejo, forgejo-db; crAPI lab: crapi-lab-*; APISIX lab: forgejo-apisix-*
```

**Run the tool on a lab**, from the repository root:

```bash
hatch run apiguard validate-config -c test-environments/forgejo-kong/config.yaml     # or crapi-kong, forgejo-apisix
hatch run apiguard run -c test-environments/forgejo-kong/config.yaml                 # reports in outputs/forgejo/ (crAPI: outputs/crapi/, APISIX: outputs/forgejo-apisix/)
```

The three lab configurations run every test, native and external (nuclei, testssl.sh, sslyze: about 5 minutes
more), with the same commented filters above `execution`: for the native tests only, set
`external_tools.enabled: false` (a run of one or two minutes); for some tests only, `execution.test_ids`.

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

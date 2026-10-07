# First Assessment

> **Audience:** users, contributors · **Status:** v0.1.0 · **Verified:** 2026-10-06 in the repository folder on
> Linux, Python 3.12.3, Docker 29.3.1 / Compose v5.1.1, Hatch 1.16.5, with the values of `.env.example`

You will start a local test target (Forgejo behind Kong, in Docker), run the tool against it, and read the result.
About 10 minutes, 5 of them waiting for the assessment.

Previous page: [Installation](installation.md). Do this **only against systems you are allowed to test**; the lab
is local and disposable.

## What the lab is

`test-environments/forgejo-kong/` is a Docker Compose environment: PostgreSQL, Forgejo 14.0.5 (the API under test),
Kong 3.9.3 in DB-less mode (the gateway, with an HTTPS proxy and the Admin API) and a one-shot setup container that
creates three users and the test data (a repository, an organization, a tag, an issue and a comment). The tool is developed and tested against this setup
([compatibility](../reference/compatibility.md); every image version is pinned, see
[Test lab](../reference/compatibility.md#test-lab)).

The lab publishes ports **3000** (Forgejo), **8000** and **8443** (Kong proxy, HTTP and HTTPS) and **8001** (Kong
Admin API). All commands run from the repository folder unless a `cd` says otherwise.

**One file for all credentials.** The lab and the tool read usernames, passwords and secrets from the same `.env`
file in the repository folder; no credential is written in `docker-compose.yml`. That is why every
`docker compose` command on this page has `--env-file ../../.env`.

## 1. Create the secrets file

```bash
cp .env.example .env
```

Creates `.env` from the template, with fictitious credentials that work for the lab as they are. `.env` is ignored
by git.

If you already have a `.env`, skip this command (it would overwrite yours) and make sure your `.env` contains every
variable listed in `.env.example`.

## 2. Reset and check the machine

Remove any lab previously started from this folder (containers, volumes, network; it does nothing if none exists):

```bash
cd test-environments/forgejo-kong
docker compose --env-file ../../.env down -v
cd ../..
```

Check Docker:

```bash
docker info --format 'docker: running, server {{.ServerVersion}}'
```

Check that the four lab ports are free:

```bash
for p in 3000 8000 8001 8443; do
  if ss -ltn "sport = :$p" | grep -q LISTEN; then echo "port $p: IN USE"; else echo "port $p: free"; fi
done
```

| What you see | What to do |
|---|---|
| `docker: running`, the four ports `free` | continue with step 3 |
| `Cannot connect to the Docker daemon` | start Docker, then repeat |
| a port `IN USE` | another program or a lab started from another folder holds it: stop it (`ss -ltnp "sport = :8001"` shows which program), or see [If a port is already in use](#if-a-port-is-already-in-use) |

## 3. Start the lab

```bash
cd test-environments/forgejo-kong
docker compose --env-file ../../.env up -d --wait kong
docker compose --env-file ../../.env up forgejo-setup
cd ../..
```

The first command starts PostgreSQL, Forgejo and Kong and waits until they are healthy (the first time it also
downloads the images). Kong uses the self-signed example certificate already in `certs/` (valid until 2028-08-02,
lab only, see [If you regenerate the TLS certificate](#if-you-regenerate-the-tls-certificate)).

The second runs the setup container once. With the values of `.env` it creates the three users and, owned by
`user-a`, the repository `LAB_TEST_REPO`, the organization `LAB_TEST_ORG`, the tag `LAB_TEST_TAG`, issue 1 and
comment 1. `config.yaml` points the tool at these resources (`target.path_seed`, which reads the same variables), so
that paths like `/api/v1/repos/{owner}/{repo}/issues/{index}` reach a real resource instead of returning 404.
Expected output:

```
New user 'thesis-admin' has been successfully created!
New user 'user-a' has been successfully created!
New user 'user-b' has been successfully created!
Repository user-a/test-repo created.
Organization test-org created.
Tag v0.1.0 created.
Issue 1 created.
Comment 1 created.
Provisioning completed.
```

Running it again is harmless: it reports `user already exists` and `already exists` for each resource.

## 4. Check that the lab is ready

Each line must print `200`:

```bash
curl -s  -o /dev/null -w "forgejo     %{http_code}\n" http://localhost:3000/swagger.v1.json
curl -sk -o /dev/null -w "kong https  %{http_code}\n" https://localhost:8443/api/v1/version
curl -s  -o /dev/null -w "kong admin  %{http_code}\n" http://localhost:8001/status
```

## 5. Run

The commands below start with `hatch run`, which runs one command inside the tool's environment and returns. To
type several commands without the prefix, open a shell inside the environment instead:

```bash
hatch shell
```

From then on write `apiguard validate-config` and `apiguard run` (without `hatch run`); `exit` leaves the shell.
Both ways use the same environment and give the same result. Use `hatch shell` without a name: `hatch shell dev`
opens the contributors' environment (linters, type checker), not needed here.

Validate the configuration:

```bash
hatch run apiguard validate-config
```

Expected: `Configuration valid. Target: https://localhost:8443/`. The committed `config.yaml` is already set up for
this lab ([how loading works](../reference/configuration.md#loading-rules)).

Run the assessment:

```bash
hatch run apiguard run
```

About 5 minutes; progress is logged to the terminal (add `--log-level debug` to see every HTTP request).

**Do not interrupt it.** Almost all of the 5 minutes are spent in the external-tool tests (nuclei, testssl.sh,
sslyze; the native tests take about 30 seconds), which print nothing while they run, so it can look stuck. Reports are written only at the very end: if
you press `Ctrl+C` there are no reports and `outputs/` keeps only `evidence_tmp/` (Q-44).

When it finishes, print its exit code:

```bash
echo $?
```

`$?` holds the exit code of the last command, so run it right after the assessment. Expected: `1`, meaning the
tool found violations, which is the normal result on this lab ([exit codes](../reference/exit-codes.md)).

## 6. Check the result

Measured on this lab with the full run: exit code `1`, 18 tests scheduled, no `ERROR`, `SKIP` for 0.3 (no
deprecated endpoint declared) and 1.6 (no session cookie), the rest PASS or FAIL. The exact number of findings
varies with the lab data.

Results are written to `outputs/` (a previous run's files are replaced):

| File | Content |
|---|---|
| `assessment_report.html` | interactive report |
| `apiguard_report.json` | machine-readable report ([schema](../reference/report-schema.md)) |
| `evidence.json` | full HTTP transactions proving the FAILs ([format](../reference/evidence-format.md)) |

Open the HTML report:

```bash
cd outputs && python3 -m http.server 8080
```

then browse to `http://localhost:8080/assessment_report.html`. Stop the server with `Ctrl+C`, then `cd ..`.

Quick verdict list without a browser:

```bash
python3 -c "import json;r=json.load(open('outputs/apiguard_report.json'));[print(x['test_id'],x['status'],x['finding_count']) for x in r['all_rows']]"
```

What each test does and what its status means: [test catalogue](../tests/README.md).

## 7. Clean up

```bash
cd test-environments/forgejo-kong
docker compose --env-file ../../.env down -v
cd ../..
```

Removes the lab's containers, volumes and network. The Docker images stay, so the next start is fast. `.env`,
`tools/` and `outputs/` are ignored by git and stay.

## Next step

Run it against your own API: [Configure a target](../guides/usage/configure-a-target.md). Every parameter is in the
[configuration reference](../reference/configuration.md); the commands are in the [CLI reference](../reference/cli.md).

---

## If a port is already in use

The lab needs ports 3000, 8000, 8001 and 8443. If another program holds one of them, stop it. If you cannot, change
the **left** number of the matching line in the `ports:` section of
`test-environments/forgejo-kong/docker-compose.yml` (for example `"13000:3000"`), change the same port in the URLs
of `config.yaml` (`base_url`, `openapi_spec_url`, `admin_api_url`, `http_probe_url`) and in the `curl` commands.
Both files are tracked by git: restore them with `git checkout` when you no longer need the change.

## If you regenerate the TLS certificate

The lab ships a self-signed example certificate and key in `test-environments/forgejo-kong/certs/`, committed on
purpose and valid until 2028-08-02. They are for this lab only: the key is public, never reuse it. To create a new
pair (for example when the certificate expires):

```bash
cd test-environments/forgejo-kong/certs
./gen-certs.sh
cd ../../..
```

The script also makes the key readable by Kong, which runs as a non-root user inside its container. Then restart
Kong:

```bash
cd test-environments/forgejo-kong
docker compose --env-file ../../.env up -d --force-recreate --wait kong
cd ../..
```

## Troubleshooting

| Symptom | Cause and fix |
|---|---|
| test 1.1 reports a successful `DELETE` without credentials, or many results became inconclusive after a previous run | a test resource of `path_seed` was deleted: reset the lab from scratch (step 2, then step 3). Running only the setup again is not enough: Forgejo never reuses issue numbers or comment ids, so the setup stops with `Issue 1 was deleted earlier ...` or `Comment 1 was deleted earlier ...` and asks for a full reset |
| `required variable ... is missing a value` or `... missing in .env` | `--env-file ../../.env` missing from the command, `.env` does not exist (step 1), or the variable is missing from `.env` (compare with `.env.example`) |
| `... creation failed: HTTP ...` in the setup output | Forgejo rejected the request: check `USER_A_USERNAME`, `USER_A_PASSWORD` and the `LAB_TEST_*` names in `.env`, reset (step 2) and start again |
| Kong never becomes healthy and `docker logs kong` shows `Permission denied` on `server.key` | the key is not readable by Kong (permissions changed by hand, or created without `gen-certs.sh`): run `chmod 644 test-environments/forgejo-kong/certs/server.key`, then restart Kong as in [If you regenerate the TLS certificate](#if-you-regenerate-the-tls-certificate) |
| `Configuration invalid: Environment variable(s) not set: X` | `.env` has no value for `X` (also checked for `${X}` written inside YAML comments) |
| many `INCONCLUSIVE_PARAMETRIC` states in the report | the test repository is missing: check the setup output (step 3) |
| `ext.1.5.sslyze` is SKIP | the tool was not started through Hatch (no sslyze) |
| `bind: address already in use` | a port is taken: see [If a port is already in use](#if-a-port-is-already-in-use) |

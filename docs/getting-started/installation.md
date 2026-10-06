# Installation

> **Audience:** users, contributors · **Status:** v0.1.0 · **Verified:** 2026-10-06 on Linux with Python 3.12.3:
> state check run on an existing installation; install steps run from a fresh `git clone` (Hatch environment created
> automatically in 13 s)

Getting started has two pages, in this order:

1. **Installation** (this page): check what you already have, clean up if needed, install what is missing.
2. **[First assessment](first-assessment.md)**: run the tool against a local test target and read the result.

## Requirements

| Requirement | Notes |
|---|---|
| Linux | the only supported platform ([compatibility](../reference/compatibility.md)) |
| Python 3.12 | `pyproject.toml` declares `>=3.11`; only 3.12 has been tested |
| `git` | to clone the repository |
| [Hatch](https://hatch.pypa.io) | creates and manages the Python environment: `pip install hatch` |
| `curl`, `tar`, `unzip` | used by `install_tools.sh` |
| Docker with Compose | for the test target (next page) |

## 1. Check what you already have

Skip this section on a machine where you have never installed the tool. Otherwise run these checks one by one,
**from the repository folder**. They only read: nothing is changed, moved or deleted.

### 1.1 Prerequisites

```bash
git --version
python3 --version
hatch --version
docker --version
docker compose version
```

Each command prints a version. `command not found` means the program is missing: install it before continuing.
Python must be 3.12 (see [Requirements](#requirements)).

`curl`, `tar` and `unzip` are needed only by `install_tools.sh`:

```bash
curl --version
tar --version
unzip -v
```

### 1.2 Hatch environment (is the tool already installed?)

```bash
ls -d "$(hatch env find default)"
```

Hatch keeps the tool's Python environment outside the repository, under `~/.local/share/hatch/env/virtual/`.

- It prints a path: the environment exists, so the tool is already installed. Skip section 3 step 2.
- `No such file or directory`: the environment has not been created yet. Section 3 step 2 creates it.

### 1.3 Test lab

```bash
docker ps -a
```

Containers named `kong`, `forgejo`, `forgejo-db`, `forgejo_setup` belong to the test lab (running or stopped).
To start the first assessment from a clean lab, remove them with [2.1](#21-test-lab).

```bash
ss -ltn | grep -E ':(3000|8000|8001|8443)\b'
```

No output: the four lab ports are free. A line for a port while no lab container exists means another program uses
it: see [If a port is already in use](first-assessment.md#if-a-port-is-already-in-use).

If all checks pass and there is no lab container, the installation is complete: go to the
[first assessment](first-assessment.md).

## 2. Clean up (optional)

Run only the parts you need, from the repository folder. Each part says exactly what it removes. None of them
touches files tracked by git.

### 2.1 Test lab

```bash
cd test-environments/forgejo-kong
docker compose --env-file ../../.env down -v
cd ../..
```

`--env-file ../../.env` is required by every `docker compose` command of the lab, because the lab reads its
credentials from `.env` (see the [first assessment](first-assessment.md)). **Deletes** the lab containers, their volumes (Forgejo data, the three users, the test repository) and the lab
network. The Docker images stay, so the next start is fast. If no lab exists it does nothing.

### 2.2 Python environment

```bash
hatch env prune
```

**Deletes** the Hatch environments of this repository (the tool and the development tools). The next
`hatch run ...` creates them again (about 15 seconds).

## 3. Install

Do the steps that section 1 reported as missing; on a new machine do all of them.

```bash
git clone https://github.com/eneamanzi/apiguard-assurance.git
cd apiguard-assurance
hatch run apiguard version
./install_tools.sh
```

1. `git clone` and `cd`: get the repository and enter it. **Run every following command from this folder.**
2. `hatch run apiguard version`: the first time, Hatch creates the Python environment and installs the tool in it
   (about 15 seconds), then runs it. Expected output: `APIGuard Assurance version 0.1.0`.
3. `./install_tools.sh`: downloads the external tools into `./tools/` (testssl.sh 3.2.3, nuclei 3.8.0,
   nuclei-templates 10.4.3); tools already present are skipped. Only needed for the external tests (`ext.*`);
   without them those tests return SKIP and the native tests run normally. nuclei also creates `~/.pdcp` in your
   home directory.

Run the check of section 1 again: everything except `.env` and the lab should now be `ok`.

## Next step

Go to **[First assessment](first-assessment.md)**.

---

## Background

**Why Hatch.** Hatch creates a virtual environment for the project by itself (under
`~/.local/share/hatch/env/virtual/`), installs the project in editable mode with its dependencies **including
sslyze**, and defines the project scripts in `pyproject.toml`. Every clone gets its own environment. A manual
`python -m venv` + `pip install .` gives a different environment (no sslyze, no development tools, code copied
instead of linked), so the same run can give different results: `ext.1.5.sslyze` is SKIP without sslyze (Q-42).
Use pip only to install the package into another product.

**Binary lookup.** The tool looks for external binaries in `./tools/<tool>/` relative to the working directory,
then in `PATH`. That is why commands are run from the repository folder.

**Everyday commands** (all in the [CLI reference](../reference/cli.md)):

| Task | Command |
|---|---|
| Validate the configuration | `hatch run apiguard validate-config` |
| Run an assessment | `hatch run apiguard run` |
| Use another configuration file | `hatch run apiguard run -c other.yaml` |
| Open a shell inside the environment | `hatch shell` |
| Code quality checks (contributors) | `hatch run dev:check` |
| Remove this repository's environment | `hatch env prune` |

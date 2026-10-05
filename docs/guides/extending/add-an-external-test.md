# Developer Guide — Adding a New External Test (and Connector)

- [Architecture overview (read before any step)](#architecture-overview-read-before-any-step)
- [Critical rules (read before writing any code)](#critical-rules-read-before-writing-any-code)
  - [Rule 1 — `_evaluate()` must never construct `TestResult(...)` directly](#rule-1--_evaluate-must-never-construct-testresult-directly)
  - [Rule 2 — `command_json` is always a plain `str` from `" ".join(...)`, never `json.dumps()`](#rule-2--command_json-is-always-a-plain-str-from--join-never-jsondumps)
  - [Rule 3 — `command_json` renders directly in Jinja2, never with `| join(' ')`](#rule-3--command_json-renders-directly-in-jinja2-never-with--join-)
- [File pipeline](#file-pipeline)
  - [Scenario A — new test, existing tool (e.g., second testssl test)](#scenario-a--new-test-existing-tool-eg-second-testssl-test)
  - [Scenario B — new test, new tool (e.g., nuclei)](#scenario-b--new-test-new-tool-eg-nuclei)
- [Naming conventions (non-optional)](#naming-conventions-non-optional)
- [Step B.0 — Tool output reconnaissance  *(new tool only)*](#step-b0--tool-output-reconnaissance--new-tool-only)
  - [Artifact 1 — version and help output](#artifact-1--version-and-help-output)
  - [Artifact 2 — a real JSON/JSONL output sample](#artifact-2--a-real-jsonjsonl-output-sample)
  - [What happens with the artifacts](#what-happens-with-the-artifacts)
- [Step B.1 — `src/core/models/external_tools.py`  *(new tool only)*](#step-b1--srccoremodelsexternal_toolspy--new-tool-only)
  - [Per-tool config class](#per-tool-config-class)
  - [Field in `ExternalToolsConfig`](#field-in-externaltoolsconfig)
- [Step B.2 — `src/connectors/<toolname>.py`  *(new tool only)*](#step-b2--srcconnectorstoolnamepy--new-tool-only)
  - [Connector ClassVars (all mandatory)](#connector-classvars-all-mandatory)
  - [ConnectorRawOutput contract (4 required keys — no exceptions)](#connectorrawoutput-contract-4-required-keys--no-exceptions)
  - [Critical rule: `command` and `command_json` are always plain `str`](#critical-rule-command-and-command_json-are-always-plain-str)
  - [`_build_reproducible_commands()` helper (preferred)](#_build_reproducible_commands-helper-preferred)
  - [Path normalisation in finding data (`_sanitize_paths_in_findings()`)](#path-normalisation-in-finding-data-_sanitize_paths_in_findings)
  - [Canonical `run()` implementation](#canonical-run-implementation)
- [Step B.3 — `src/connectors/__init__.py`  *(new tool only)*](#step-b3--srcconnectors__init__py--new-tool-only)
- [Step 1 (or B.4) — `src/external_tests/ext_test_<id>_<description>.py`](#step-1-or-b4--srcexternal_testsext_test_id_descriptionpy)
  - [Module docstring](#module-docstring)
  - [Canonical import block](#canonical-import-block)
  - [Module-level constants](#module-level-constants)
  - [9 mandatory ClassVar attributes](#9-mandatory-classvar-attributes)
  - [`_build_connector()` — object construction only](#_build_connector--object-construction-only)
  - [`_invoke_connector()` — bridge to connector.run()](#_invoke_connector--bridge-to-connectorrun)
  - [`_evaluate()` — oracle evaluation](#_evaluate--oracle-evaluation)
    - [Canonical three-bucket partition pattern](#canonical-three-bucket-partition-pattern)
    - [Minimal `_evaluate()` — tool produces no findings](#minimal-_evaluate--tool-produces-no-findings)
- [Step B.5 — `config.yaml`  *(new tool only)*](#step-b5--configyaml--new-tool-only)
- [DA-2 connector injection — what it means for test implementation](#da-2-connector-injection--what-it-means-for-test-implementation)
- [Post-implementation verification](#post-implementation-verification)
- [Pre-output checklist](#pre-output-checklist)
- [Common errors and fixes](#common-errors-and-fixes)

**Source of truth:** every pattern in this document was extracted directly
from the verified implementation: `ext_test_1_5_tls_analysis.py` (contains
both `ext.1.5.testssl` and `ext.1.5.sslyze`), `ext_test_0_1_shadow_api_nuclei.py`
(nuclei); the connectors `TestsslConnector` and `NucleiConnector` (both
`BaseSubprocessConnector` tier) and `SslyzeConnector` (`BaseLibraryConnector`
tier — Python-native library, no subprocess); the bases `ExternalToolTest`,
`BaseSubprocessConnector`, `BaseLibraryConnector`, `BaseConnector`; and the
configuration `ExternalToolsConfig`. Code excerpts are canonical. Do not
invent patterns not present here.

**Scope:** this guide covers two distinct scenarios:

| Scenario | Files required |
|---|---|
| New test using an **existing tool** (e.g., second nuclei test) | 1 file: `src/external_tests/ext_test_*.py` |
| New test requiring a **new tool** | 5 files: connector + external_tools config + `__init__.py` + ext_test file + config.yaml |

Read the relevant sections top to bottom before writing a single line of code.

---

## Architecture overview (read before any step)

External tests differ from native tests in four structural ways:

**1. No `runtime.py` mirror is needed.**
External tests read config directly from `target.external_tools.<tool>.*`.
`TargetContext.external_tools` is already an `ExternalToolsConfig` frozen
object — no separate `RuntimeTest*Config` class, no engine population step.

**2. No `engine.py` registration is needed.**
`ExternalTestRegistry` discovers test files automatically via `pkgutil`
scanning of `src/external_tests/`. File naming is the only registration.

**3. `execute()` receives no `SecurityClient`.**
External tests invoke subprocesses, not `httpx`. The engine calls
`test.execute(target, context, store)` — note: no `client` parameter.

**4. Evidence is stored via `store.pin_artifact()`, not `store.add_fail_evidence()`.**
The connector's raw JSON output is pinned as an artifact. Individual
`Finding` objects reference the `artifact_ref` string (not an `EvidenceRecord`).

---

## Critical rules (read before writing any code)

Three patterns that pass static type-checking but produce silent runtime failures.
Each is enforced by the pre-output checklist at the end of this document.

### Rule 1 — `_evaluate()` must never construct `TestResult(...)` directly

`TestResult` appears in the import block as a return type annotation for
`_evaluate()`. It must never be instantiated directly inside that method.

`TestResult(...)` built directly produces a result with empty metadata fields:
`test_name=""`, `domain=-1`, `source=""`, `tool_name=""`. The report builder uses
`source` to partition native vs. external results and `domain` to build per-domain
statistics. A result with `source=""` falls into an unclassified bucket and the
report renders dashes where test data should appear. No exception is raised — the
failure is completely silent.

```python
# WRONG — produces empty metadata, silent report corruption
return TestResult(
    test_id=self.test_id,
    status=TestStatus.PASS,
    message="...",
)

# CORRECT
return self._make_pass(message="...")
return self._make_fail(message="...", findings=[...])
return self._make_skip(reason="...")
```

`_make_pass()`, `_make_fail()`, and `_make_skip()` call `_metadata_kwargs()`
internally, which injects `test_name`, `domain`, `priority`, `strategy`, `tags`,
`cwe_id`, `source`, and `tool_name` into every `TestResult`. There is no other
way to populate these fields.

### Rule 2 — `command_json` is always a plain `str` from `" ".join(...)`, never `json.dumps()`

`ConnectorRawOutput` declares `command_json: str`. The field name means "the command
that runs the tool in JSON output mode" — not a JSON serialization of the command list.
Both `command` and `command_json` are plain space-separated strings.

`json.dumps(cmd)` satisfies the `str` type annotation, so no type error is raised.
The HTML report renders `command_json` directly as a string — a `json.dumps()` value
produces character-spaced output in the report (`[ " / h o m e / ...`).

```python
# WRONG — passes type-checking, corrupts HTML report silently
raw_output = {
    "command":      " ".join(cmd),
    "command_json": json.dumps(cmd),
}

# CORRECT — both keys are plain space-separated strings
raw_output = {
    "command":      " ".join(cmd_without_json_flag),
    "command_json": " ".join(cmd_with_json_flag),
}
```

`command` = the CLI command a human analyst pastes into a terminal for human-readable
output (e.g. without `-je <path>` for nuclei, without `--jsonfile` for testssl).

`command_json` = the CLI command APIGuard runs internally, with the JSON output flag
included. It is a plain space-separated `str`, not a JSON-serialized list.

When using `_build_reproducible_commands()` (preferred), both return values are already
plain strings — the error cannot occur. When building `raw_output` manually (any tool
with a temp-file output path, like nuclei or testssl), always use `" ".join(cmd)`.

### Rule 3 — `command_json` renders directly in Jinja2, never with `| join(' ')`

`command_json` is a `str`. Jinja2's `| join(' ')` filter applied to a string iterates
its **characters**, not its words.

```jinja
{{ row.tool_artifact.command_json }}                    {# correct #}
{{ row.tool_artifact.command_json | join(' ') }}        {# wrong — iterates chars #}
```

The filter is only correct on lists. `command_json` is never a list.

---

## File pipeline

### Scenario A — new test, existing tool (e.g., second testssl test)

```
1. src/external_tests/ext_test_<id>_<description>.py   ← the test
```

One file only. The existing `ExternalToolsConfig.testssl` block in
`external_tools.py` and the existing config.yaml `external_tools.testssl`
section are reused without modification.

### Scenario B — new test, new tool (e.g., nuclei)

```
0. Tool output reconnaissance              ← collect --version, --help, real JSON sample FIRST
1. src/core/models/external_tools.py       ← add per-tool config class + ExternalToolsConfig field
   (src/config/schema/external_tools.py is a re-export shim — do not edit it)
2. src/connectors/<toolname>.py            ← implement the connector
3. src/connectors/__init__.py              ← export new connector class
4. src/external_tests/ext_test_<id>_<description>.py   ← the test
5. config.yaml                             ← add external_tools.<toolname> block
```

---

## Naming conventions (non-optional)

**External test files:**
```
src/external_tests/ext_test_<methodology_id>_<description>.py
```

`ext_test_` prefix is mandatory — `ExternalTestRegistry` uses it as the
discovery filter. Files without this prefix are silently ignored.

Examples:
```
ext_test_1_5_tls_analysis.py       ← methodology section 1.5 (testssl + sslyze)
ext_test_0_1_shadow_api_nuclei.py  ← methodology section 0.1 (nuclei)
```

**`test_id` convention:**
```
"ext.N.M.toolname"   ← always "ext." prefix + tool suffix (e.g. "ext.1.5.testssl")
```

The engine builds a global `test_lookup` dict keyed by `test_id`. A native
`"1.5"` and an external `"1.5"` would silently overwrite each other. The
`ext.` prefix avoids the collision; the `.toolname` suffix makes the ID
self-documenting and unique when multiple tools cover the same guarantee
(e.g. `"ext.1.5.testssl"` and `"ext.1.5.sslyze"` coexist for Garanzia 1.5).

**`depends_on` — declaring dependencies on native tests:**

The DAG is built from the merged list of native and external tests. An
external test can depend on a native test and vice versa. The `depends_on`
value must be the exact `test_id` string of the dependency, including the
dot form and the `ext.` prefix where applicable.

```python
# External test that must run after the native 1.5 check:
depends_on: ClassVar[list[str]] = ["1.5"]

# External test that must run after another external test:
depends_on: ClassVar[list[str]] = ["ext.1.5.testssl"]

# External test with no dependencies (most common):
depends_on: ClassVar[list[str]] = []
```

**`tool_name` convention:**
Must exactly match the field name in `ExternalToolsConfig`. The registry
calls `ExternalToolsConfig.is_tool_enabled(tool_name)` to decide whether
to include the test. A typo (e.g. `"testsll"` instead of `"testssl"`) is
caught by `is_tool_enabled()` with a WARNING log, but the test is silently
excluded from the run. Current valid values: `"testssl"`, `"nuclei"`,
`"sslyze"`.

---

## Step B.0 — Tool output reconnaissance  *(new tool only)*

**This step must be completed before writing a single line of connector or
test code.** The entire `_evaluate()` implementation depends on knowing the
exact field names in the tool's JSON output. There is no way to infer them
from the existing codebase: testssl.sh uses `severity`, `id`, `finding`;
nuclei uses `info.severity`, `templateID`, `matched-at`; sslyze exposes
structured Python objects via its library API. Writing `_evaluate()` without first
inspecting real output produces code that silently returns empty lists
because `item.get("severity")` is always `None` for a tool that stores
severity under a different key.

**What to collect and provide before starting implementation:**

Collect both artifacts by running the tool against the live test
environment. Paste them into the **same message in which you request the
implementation** — material provided in a previous turn may no longer be
in the model's active context and will be silently ignored.

---

### Artifact 1 — version and help output

```bash
# Version — establishes the exact build; field names can change across versions.
<toolname> --version

# Help — shows all flags, especially the JSON output flag(s).
<toolname> --help 2>&1 | head -100
# or, for tools with a man page:
man <toolname> | col -b | head -200
```

Paste both outputs verbatim. The help output is needed to identify:
- The flag that enables JSON or JSONL output (e.g. `--json`, `-json`,
  `--jsonfile <path>`, `-o json`).
- Whether the tool writes to stdout or to a file.
- Any flag that limits output to machine-readable format only (e.g.
  `-silent` for nuclei).

---

### Artifact 2 — a real JSON/JSONL output sample

Run the tool against the live test environment with the JSON output flag
and save the result to a file. Paste the file content into the conversation.

```bash
# Example for a tool that writes JSONL to stdout:
<toolname> <json-flag> -u https://<target> > /tmp/tool_output.jsonl
cat /tmp/tool_output.jsonl

# Example for a tool that writes JSON to a file (like testssl.sh --jsonfile):
<toolname> --jsonfile /tmp/tool_output.json https://<target>
cat /tmp/tool_output.json
```

The output sample must be real — do not paste example output from the
tool's documentation. Documentation examples are often simplified and
omit fields that appear in practice (e.g. `ip`, `port`, `cve_ids`,
`references`). A real run against the actual target guarantees that
`_evaluate()` accesses fields that exist in the version installed.

**What makes a useful sample:**
- Run it against the real test environment (Forgejo + Kong), not a dummy
  host, so the output reflects the kind of findings the oracle will
  actually process.
- If the tool finds nothing, that is still useful (confirms the empty-list
  path in `_evaluate()`). Run it anyway.
- If the output is large (>200 lines), paste the first 50 lines and the
  last 20 — enough to see both the structure and a few finding entries.

---

### What happens with the artifacts

Once both artifacts are in the conversation, the connector's `run()`
method can be implemented with the correct output-parsing helper
(`_parse_json_output` vs `_parse_jsonl_output` vs the `--jsonfile` temp
file pattern), and `_evaluate()` can be written with the real field names.

Specifically, the JSON sample determines:
- Which `_parse_*` helper to use in `run()`.
- The exact key path for severity in `_evaluate()`:
  `item.get("severity")` vs `item["info"]["severity"]` vs
  `item.get("result", {}).get("level")`.
- The key for the finding description: `"finding"`, `"details"`,
  `"description"`, `"matched-at"`.
- The key for the finding identifier: `"id"`, `"templateID"`, `"check"`.
- Whether severity values are uppercase (`"HIGH"`), lowercase (`"high"`),
  or title-case (`"High"`) — which determines whether `FAIL_SEVERITIES`
  uses `.upper()` normalization or exact match.

**For Scenario A (second test on an existing tool):** this step is not
needed. The field structure is already established by the existing
`ext_test_*.py` file. Read that file's `_evaluate()` method and the
`FAIL_SEVERITIES` / `NOTE_SEVERITIES` constants — the field names are
already correct for that tool version.

---

## Step B.1 — `src/core/models/external_tools.py`  *(new tool only)*

Add a per-tool config class inheriting from `BaseExternalToolConfig`,
then add a field to `ExternalToolsConfig`.

> **File location:** the authoritative definitions live in
> `src/core/models/external_tools.py` so that `TargetContext` (in `core/`)
> can hold `ExternalToolsConfig` without violating the unidirectional
> dependency rule. `src/config/schema/external_tools.py` is a pure re-export
> shim — do not add new code there.

### Per-tool config class

```python
class NucleiConfig(BaseExternalToolConfig):
    """
    Configuration for the nuclei connector (template-based vulnerability scanning).

    Inherits enabled, timeout_seconds, extra_flags, and the
    _timeout_required_when_enabled validator from BaseExternalToolConfig.
    Add only nuclei-specific fields here.
    """

    timeout_seconds: int | None = Field(
        default=None,
        ge=60,
        le=600,
        description=(
            "Wall-clock timeout for a single nuclei execution in seconds. "
            "Mandatory when enabled=True.  Recommended: 180."
        ),
    )
    template_tags: str = Field(
        default="owasp,api",
        description=(
            "Comma-separated nuclei template tags to run (-tags flag). "
            "Default runs OWASP and API templates."
        ),
    )
    extra_flags: str = Field(
        default="-silent",
        description=(
            "Additional CLI flags appended verbatim.  "
            "Must not contain credentials or secrets."
        ),
    )
```

**Rules:**
- Inherit from `BaseExternalToolConfig` — never from `BaseModel` directly.
  The base class enforces the timeout-when-enabled validator for free.
- Override `timeout_seconds` with tool-specific `ge`/`le` constraints and
  a tool-specific description. Do not redeclare `_timeout_required_when_enabled`.
- `model_config = {"frozen": True}` is inherited — do not redeclare.
- Tool-specific fields go after the overridden shared fields.

### Field in `ExternalToolsConfig`

```python
class ExternalToolsConfig(BaseModel):
    model_config = {"frozen": True}

    # ... existing fields ...
    nuclei: NucleiConfig = Field(
        default_factory=NucleiConfig,
        description="Configuration for the nuclei connector.",
    )
```

**`is_tool_enabled()` is zero-cost to extend:** the method uses `getattr(self, tool_name, None)`
to look up the per-tool config. Adding a field to `ExternalToolsConfig`
automatically makes `is_tool_enabled("nuclei")` work — no code change to
that method is required.

---

## Step B.2 — `src/connectors/<toolname>.py`  *(new tool only)*

Implement the connector by subclassing `BaseSubprocessConnector` (for OS
binaries) or `BaseLibraryConnector` (for Python packages).

Use `src/connectors/_template_connector.py` as the starting point — copy
and rename it, then fill in the ClassVars and implement `run()`.

### Connector ClassVars (all mandatory)

```python
class NucleiConnector(BaseSubprocessConnector):
    TOOL_NAME: ClassVar[str] = "nuclei"          # human-readable, used in logs/report
    BINARY_NAME: ClassVar[str] = "nuclei"         # binary name for shutil.which()
    SERVICE_ENV_VAR: ClassVar[str] = "NUCLEI_SERVICE_URL"  # Docker Compose env var
    DEFAULT_TIMEOUT_SECONDS: ClassVar[int] = 180  # fallback only; callers must pass explicit timeout

    # Set LOCAL_TOOLS_SUBDIR when install_tools.sh places the binary in ./tools/<subdir>/
    # e.g. LOCAL_TOOLS_SUBDIR = "nuclei" -> ./tools/nuclei/nuclei
    # Leave as "" to skip local-tools discovery and rely on PATH only.
    LOCAL_TOOLS_SUBDIR: ClassVar[str] = ""
```

### ConnectorRawOutput contract (4 required keys — no exceptions)

`raw_output` in `ConnectorResult` must always contain these four keys.
The HTML report template raises `KeyError` silently (via Jinja2
`default_dash`) if any are absent; `_validate_raw_output()` in
`ExternalToolTest` raises `ExternalToolError` at runtime to convert
silent failures into visible ERRORs.

**You do not call `_validate_raw_output()` yourself.** It is called
automatically by `_run()` after `_invoke_connector()` returns and before
`_evaluate()` is called. As a connector implementer, your only obligation
is to ensure all four keys are present in `raw_output`. If any key is
missing, `_run()` will catch the `ExternalToolError` and return a
`TestResult(ERROR)` with a diagnostic message — `_evaluate()` will never
be called in that case.

```python
raw_output: ConnectorRawOutput = {
    "command":      command,       # str: plain space-separated command WITHOUT json flag
    "command_json": command_json,  # str: plain space-separated command WITH json flag
    "results":      all_findings,  # list[dict]: complete UNFILTERED findings from the tool
    "all_count":    len(all_findings),  # int: total findings count
}
```

### Critical rule: `command` and `command_json` are always plain `str`

Both `command` and `command_json` are **plain space-separated strings**,
not JSON-serialized lists. The `ConnectorRawOutput` TypedDict declares both
as `str`. The HTML template renders them directly with no filter.

```python
# CORRECT
"command":      " ".join(cmd_text_mode),       # e.g. "nuclei -u https://localhost:8443 ..."
"command_json": " ".join(cmd_json_mode),       # e.g. "nuclei -je /tmp/out.json -u https://..."

# WRONG — produces broken HTML (character-spaced rendering)
"command_json": json.dumps(cmd),               # ← NEVER use json.dumps here
```

**Semantic distinction:**
- `command` = the CLI command a human analyst pastes into a terminal to
  reproduce the scan with human-readable (non-JSON) output.
- `command_json` = the CLI command APIGuard runs internally, with the
  JSON output flag(s) included. For tools that always run in JSON mode
  (e.g. nuclei with `-je`), `command` and `command_json` may be identical.

### `_build_reproducible_commands()` helper (preferred)

Use the base class helper whenever the JSON output flag is a simple CLI
argument. This centralises path normalisation logic and eliminates the
`json.dumps` error by construction.

```python
cmd_prefix = [binary_cmd, *flag_tokens]

command, command_json = self._build_reproducible_commands(
    cmd_prefix=cmd_prefix,
    scan_target=scan_target,       # the target argument (URL or host:port)
    json_output_args=["-json"],    # tool-specific JSON output flag(s)
)
```

The helper always returns two plain `str` values. Use it for any tool
that writes JSON to stdout via a simple flag.

**When NOT to use it:** when the JSON output flag requires a *path argument*
(like nuclei's `-je /tmp/file.json` or testssl's `--jsonfile /tmp/file.json`),
the helper cannot generate the full command because the temp file path is not
known at command-building time. In this case, build `command` and `command_json`
manually using `" ".join(...)`. See the nuclei connector for the reference pattern.

### Path normalisation in finding data (`_sanitize_paths_in_findings()`)

`_build_reproducible_commands()` normalises paths in CLI *command strings*.
A separate helper handles paths that appear *inside finding dicts* in the tool's
JSON output.

Some tools embed absolute filesystem paths in their finding fields.  For example,
nuclei includes the absolute path to the matched template file in `template-path`
(`/home/analyst/project/tools/nuclei-templates/http/.../swagger-api.yaml`) because
it receives an absolute `-t` argument.  This leaks the analyst's directory structure
into stored artefacts.

Call `_sanitize_paths_in_findings()` **after parsing the results** and **before
building `raw_output`**, specifying only the keys that contain local infrastructure
paths:

```python
results = self._read_json_export(json_export_path)

# template-path is the local filesystem path of the matched template file
# (infrastructure data about OUR machine, not about the target).
results = self._sanitize_paths_in_findings(results, path_keys=("template-path",))
```

**Contract — which keys to sanitise:**
Only pass keys whose values are paths from the **local tool invocation
infrastructure** (binary locations, template directories, temp file paths).
Never pass keys whose values are **finding data from the target system** — matched
URLs, discovered paths on the target, HTTP request/response bodies.  Those must
be preserved verbatim as security evidence.

`EvidenceStore._sanitize_artifact()` handles credential redaction (tokens,
passwords, JWTs, Authorization headers).  It does **not** perform path
normalisation — that responsibility belongs exclusively to the connector layer.

### Canonical `run()` implementation

```python
def run(
    self,
    target_url: str,
    timeout_seconds: int,
    *,
    extra_flags: str = _DEFAULT_EXTRA_FLAGS,
    template_tags: str = _DEFAULT_TEMPLATE_TAGS,
) -> ConnectorResult:
    """
    Invoke nuclei against the target and return all findings unfiltered.

    Args:
        target_url:      Base URL of the target API.
        timeout_seconds: Wall-clock limit (sourced from config.yaml, never a literal).
        extra_flags:     Additional CLI flags verbatim.
        template_tags:   Comma-separated template tags (-tags flag).

    Returns:
        ConnectorResult: Parsed nuclei output.

    Raises:
        ExternalToolError: On timeout, OS error, or unparsable output.
    """
    scan_target: str = target_url
    binary_cmd: str = self._resolve_binary_path() or self.BINARY_NAME
    flag_tokens = [t for t in extra_flags.split() if t]

    # nuclei writes to a temp JSON export file inside a freshly created
    # unique directory.  TemporaryDirectory() handles cleanup automatically
    # on every exit path (return, exception, timeout) — no leaked temp files.
    # Use this pattern over tempfile.mktemp() (CWE-377: predictable temp path
    # is a TOCTOU race-condition risk).
    with tempfile.TemporaryDirectory(prefix="apiguard_nuclei_") as temp_dir_str:
        json_export_path = Path(temp_dir_str) / "nuclei_findings.json"

        cmd: list[str] = [
            binary_cmd, "-u", scan_target,
            "-tags", template_tags,
            "-je", str(json_export_path),
            *flag_tokens,
        ]

        # Both command strings are plain space-separated str — never json.dumps().
        # command      = what the analyst runs manually (identical here, since -je
        #                is always present in nuclei's normal invocation mode)
        # command_json = what APIGuard runs internally (same command)
        command: str = " ".join(cmd)
        command_json: str = " ".join(cmd)

        log.info(
            "nuclei_connector_run_starting",
            scan_target=scan_target,
            timeout_seconds=timeout_seconds,
            reproducible_command=command,
        )

        start_time_ms = int(time.monotonic() * 1000)

        _stdout, exit_code = self._run_subprocess(
            cmd=cmd,
            timeout_seconds=timeout_seconds,
            tool_name=self.TOOL_NAME,
        )

        execution_time_ms = int(time.monotonic() * 1000) - start_time_ms
        all_findings: list[dict[str, Any]] = self._read_json_export(json_export_path)

        log.info(
            "nuclei_connector_run_complete",
            scan_target=scan_target,
            all_count=len(all_findings),
            execution_time_ms=execution_time_ms,
        )

        raw_output: ConnectorRawOutput = {
            "command":      command,       # plain str
            "command_json": command_json,  # plain str — NOT json.dumps()
            "results":      all_findings,
            "all_count":    len(all_findings),
        }

        return ConnectorResult(
            tool_name=self.TOOL_NAME,
            tool_version=self.get_version(),
            raw_output=raw_output,
            exit_code=exit_code,
            execution_time_ms=execution_time_ms,
            timed_out=False,
        )
```

**Output parsing helpers (choose based on tool output format):**
- `_parse_json_output(raw_stdout, tool_name)` — tool writes one JSON
  object (or array) to stdout. Returns `dict` or `list`.
- `_parse_jsonl_output(raw_stdout, tool_name)` — tool writes one JSON
  object per line (JSONL). Returns `list[dict]`. Use for tools with JSONL stdout output.
- nuclei writes to a temp file via `-je` — see `NucleiConnector.run()`
  for the `tempfile.TemporaryDirectory()` + `-je` + `_read_json_export()`
  pattern (file path inside a freshly created unique directory, auto-cleanup).
- testssl.sh writes to a temp file via `--jsonfile` — see `TestsslConnector.run()`
  for the `tempfile.mkstemp()` + `--jsonfile` pattern (atomic file creation).
- Do NOT use `tempfile.mktemp()`: it returns a predictable path without
  creating the file, which is a TOCTOU race vector (CWE-377).

**"Dumb pipe" contract:** connectors pass ALL findings in `results`.
Severity-based partitioning (FAIL / note / ignore) is the exclusive
responsibility of `ExternalToolTest._evaluate()`. Never filter by severity
inside a connector.

---

## Step B.3 — `src/connectors/__init__.py`  *(new tool only)*

Add the new connector class to the package public API:

```python
from src.connectors.nuclei import NucleiConnector   # ← add here

__all__ = [
    # ... existing ...
    "NucleiConnector",  # ← add here
]
```

---

## Step 1 (or B.4) — `src/external_tests/ext_test_<id>_<description>.py`

Use `src/external_tests/_template_ext_test.py` as the starting point —
copy, rename, fill in ClassVars, implement the three abstract methods.

### Module docstring

Every external test file opens with a module-level docstring documenting:
- The guarantee from `3_TOP_metodologia.md` that this test covers.
- Which native test (if any) covers the complementary checks (split rationale).
- The test_id convention (why `ext.N.M`, not `N.M`).
- The timeout source.
- The oracle: FAIL / NOTE / IGNORE bucket criteria.
- The DAG placement (`depends_on`).
- The dependency rule for imports.

### Canonical import block

```python
from __future__ import annotations

from typing import ClassVar

import structlog

from src.connectors.base import BaseConnector, ConnectorResult
from src.connectors.testssl import TestsslConnector   # ← replace with actual connector
from src.core.context import TargetContext
from src.core.models import Finding, InfoNote, TestStrategy
from src.core.models.results import TestResult
from src.external_tests.base import ExternalToolTest

log: structlog.BoundLogger = structlog.get_logger(__name__)
```

**No `SecurityClient` import.** External tests never call `client.request()`.
**No `TestContext` import** unless the test reads from TestContext (rare).
**Note on `execute()` type annotations:** if you write a fully annotated
override of `execute()` — which the pre-output checklist requires — add
`from src.core.context import TestContext` (alongside `TargetContext`)
so that the `context: TestContext` parameter annotation resolves. The
real `ext_test_1_5_tls_analysis.py` omits it because its `execute()`
override inherits the base class signature without re-annotating. Both
styles are acceptable; the fully annotated style is recommended.
**No `EvidenceStore` import** — the `execute()` signature includes `store`
but `ExternalToolTest.execute()` handles `store.pin_artifact()` internally in
`_run()`. The test only interacts with `store` if it needs to call
`store.pin_artifact()` in `_evaluate()` — which it normally does not.
**`TestResult` in imports:** import it for the return type annotation of
`_evaluate()`. But use it **only** as a type annotation — never to construct
results directly. All result construction goes through `self._make_pass()`,
`self._make_fail()`, `self._make_skip()`. If you find yourself writing
`return TestResult(...)` in `_evaluate()`, stop and use the helpers instead.

### Module-level constants

```python
# Severity levels that trigger FAIL. Defined here (not in the connector)
# because the oracle decision belongs to the test, not the data-delivery layer.
FAIL_SEVERITIES: frozenset[str] = frozenset({"HIGH", "CRITICAL"})

# Severity levels that produce an InfoNote (below-threshold observations).
NOTE_SEVERITIES: frozenset[str] = frozenset({"WARN", "MEDIUM"})

# Standards references included in every Finding and InfoNote.
_REFERENCES: tuple[str, ...] = (
    "OWASP-API2:2023",
    "NIST-SP-800-52-Rev2",
    "OWASP-ASVS-v5.0.0-V14.2.1",
)
```

### 9 mandatory ClassVar attributes

```python
class ExtTestNMDescription(ExternalToolTest):
    # 8 standard metadata attributes (same role as in BaseTest)
    test_id:    ClassVar[str]          = "ext.N.M"    # MUST start with "ext." prefix
    test_name:  ClassVar[str]          = "Full Guarantee Name From Methodology"
    domain:     ClassVar[int]          = N
    priority:   ClassVar[int]          = 2             # 0=P0, 1=P1, 2=P2, 3=P3
    strategy:   ClassVar[TestStrategy] = TestStrategy.WHITE_BOX  # usually BLACK_BOX or WHITE_BOX
    depends_on: ClassVar[list[str]]    = []            # exact test_id strings
    tags:       ClassVar[list[str]]    = ["tag", "OWASP-APIX:2023"]
    cwe_id:     ClassVar[str]          = "CWE-XXX"

    # 9th attribute — external test specific
    tool_name:  ClassVar[str]          = "testssl"     # MUST match ExternalToolsConfig field name
```

`source` is fixed at `"external"` in the base class — do NOT declare it in subclasses.

---

### `_build_connector()` — object construction only

```python
def _build_connector(self) -> BaseConnector:
    """
    Instantiate and return the connector. Object construction only — no I/O.

    Called by _get_connector() and by ExternalTestRegistry._inject_connectors()
    (DA-2) to check availability once per tool group.

    Returns:
        BaseConnector: Freshly constructed connector instance.
    """
    return TestsslConnector()
```

**Rule:** zero I/O, zero subprocess calls, zero network access inside this
method. It is called during `ExternalTestRegistry._inject_connectors()` —
the registry expects it to be instantaneous.

---

### `_invoke_connector()` — bridge to connector.run()

```python
def _invoke_connector(
    self,
    connector: BaseConnector,
    target: TargetContext,
    target_url: str,
) -> ConnectorResult:
    """
    Call connector.run() with the correct tool-specific parameters.

    Timeout access pattern:
        target.external_tools.<tool>.timeout_seconds
    Never read timeout from target.tests_config domain fields.

    Args:
        connector:   Connector instance (injected by registry or freshly built).
        target:      Frozen TargetContext with target URL and external_tools config.
        target_url:  URL from target.effective_endpoint_base_url().
                     Use this directly — do NOT call effective_endpoint_base_url()
                     again inside this method; _run() already resolved it.

    Returns:
        ConnectorResult: Parsed tool output.

    Raises:
        ExternalToolError: Propagated to _run() for timeout/OS error handling.
    """
    # timeout_seconds is guaranteed non-None here: Phase 1 rejects
    # enabled=True with timeout_seconds=None (ConfigurationError — bloccante).
    timeout_seconds: int = target.external_tools.testssl.timeout_seconds  # type: ignore[assignment]
    extra_flags: str = target.external_tools.testssl.extra_flags

    log.info(
        "ext_test_n_m_invoke_connector",
        target_url=target_url,
        timeout_seconds=timeout_seconds,
    )

    return connector.run(
        target_url=target_url,
        timeout_seconds=timeout_seconds,
        extra_flags=extra_flags,
    )
```

**Timeout access pattern — mandatory:**
```python
target.external_tools.<tool>.timeout_seconds
target.external_tools.<tool>.extra_flags
target.external_tools.<tool>.<tool_specific_field>
```

Never use `target.tests_config.test_N_M.something_timeout` for external tests.
The `target.tests_config` subtree is exclusively for native tests.

---

### `_evaluate()` — oracle evaluation

**Read Rule 1 above before implementing this method.** This is the
highest-risk method in an external test. The rule is absolute:

```
_evaluate() ALWAYS returns self._make_pass() / self._make_fail() / self._make_skip()
_evaluate() NEVER returns TestResult(...) directly
```

`TestResult` is imported only for the return type annotation `-> TestResult`.
It is never constructed directly in this method.

This is where the security logic lives. The subclass inspects
`result.raw_output["results"]` and returns `PASS`, `FAIL`, or `SKIP`.

#### Canonical three-bucket partition pattern

```python
def _evaluate(
    self,
    result: ConnectorResult,
    artifact_ref: str,
) -> TestResult:
    """
    Apply the oracle to ConnectorResult and return a TestResult.

    Oracle:
        FAIL   (HIGH / CRITICAL) -> one Finding per item -> FAIL result.
        NOTE   (MEDIUM / WARN)   -> one InfoNote per item -> PASS-with-note.
        IGNORE (OK / INFO / LOW) -> silently discarded.

    Args:
        result:       ConnectorResult from _invoke_connector().
        artifact_ref: EvidenceStore record ID from store.pin_artifact().
                      Include in every Finding.evidence_ref.

    Returns:
        TestResult: PASS, FAIL, or SKIP (never ERROR).
    """
    all_findings: list[dict] = result.raw_output.get("results", [])
    all_count: int = result.raw_output.get("all_count", 0)

    log.info("ext_test_n_m_oracle_evaluation", all_count=all_count)

    if not all_findings:
        # self._make_pass() — NEVER TestResult(...) directly
        return self._make_pass(
            message=(
                f"Tool found no issues. Total findings analysed: {all_count}."
            )
        )

    # Three-bucket partition.
    # SEVERITY FIELD PATH IS TOOL-SPECIFIC — determine from Step B.0:
    #
    #   testssl.sh  -> severity at top level, uppercase:
    #       str(item.get("severity", "")).upper() in FAIL_SEVERITIES
    #       (FAIL_SEVERITIES = {"HIGH", "CRITICAL"})
    #
    #   nuclei      -> severity nested under "info", lowercase:
    #       str(item.get("info", {}).get("severity", "")).lower() in FAIL_SEVERITIES
    #       (FAIL_SEVERITIES = {"critical", "high", "medium"})
    #
    # The template below shows the testssl.sh style. Adapt the field path and
    # case normalisation to match the tool's actual JSON output confirmed in B.0.
    fail_items = [
        item for item in all_findings
        if str(item.get("severity", "")).upper() in FAIL_SEVERITIES
    ]
    note_items = [
        item for item in all_findings
        if str(item.get("severity", "")).upper() in NOTE_SEVERITIES
    ]
    # Items not in either bucket (OK / INFO / LOW) are silently ignored.

    # Build InfoNotes for NOTE bucket items.
    notes: list[InfoNote] = [
        InfoNote(
            title=f"[{str(item.get('severity','')).upper()}] Observation: {item.get('id', 'unknown')}",
            detail=str(item.get("finding", "")),
            references=list(_REFERENCES),
        )
        for item in note_items
    ]

    if fail_items:
        findings = [
            Finding(
                title=f"[{str(item.get('severity','')).upper()}] Issue: {item.get('id', 'unknown')}",
                detail=str(item.get("finding", "")),
                references=list(_REFERENCES),
                evidence_ref=artifact_ref,   # link every Finding to the raw artifact
            )
            for item in fail_items
        ]
        # self._make_fail() — NEVER TestResult(...) directly
        return self._make_fail(
            message=(
                f"{len(findings)} critical/high finding(s) detected. "
                f"Raw evidence: artifact_ref={artifact_ref}."
            ),
            findings=findings,
            notes=notes,   # attach NOTE items alongside FAIL items
        )

    # PASS-with-note: only NOTE items, no FAIL.
    # self._make_pass() — NEVER TestResult(...) directly
    return self._make_pass(
        message=(
            f"{len(note_items)} MEDIUM/WARN item(s) below FAIL threshold. "
            f"Raw evidence: artifact_ref={artifact_ref}."
        ),
        notes=notes,
    )
```

**`evidence_ref` in `Finding` objects:** always set to `artifact_ref` (the
string returned by `store.pin_artifact()` inside `_run()`). This is the
cross-reference that links a Finding in the HTML report to the raw tool
output in `evidence.json`. Never set `evidence_ref=None` in external test
findings — the artifact always exists.

---

#### Minimal `_evaluate()` — tool produces no findings

When the tool runs successfully but finds nothing, `results` is an empty
list. The canonical pattern handles this as the first fast-path check in
the three-bucket template above (`if not all_findings: ...`). If the test
has no note-level observations either, the entire method collapses to:

```python
def _evaluate(
    self,
    result: ConnectorResult,
    artifact_ref: str,
) -> TestResult:
    """
    Oracle: no findings from the tool -> PASS.

    Args:
        result:       ConnectorResult from _invoke_connector().
        artifact_ref: EvidenceStore record ID (always exists, always include).

    Returns:
        TestResult: PASS with zero findings.
    """
    all_findings: list[dict] = result.raw_output.get("results", [])
    all_count: int = result.raw_output.get("all_count", 0)

    log.info("ext_test_n_m_oracle_evaluation", all_count=all_count)

    if not all_findings:
        return self._make_pass(   # NOT TestResult(...)
            message=(
                f"Tool found no issues. Total findings analysed: {all_count}. "
                f"Raw output: artifact_ref={artifact_ref}."
            )
        )

    # All findings present but none meet the FAIL threshold.
    return self._make_pass(   # NOT TestResult(...)
        message=(
            f"No findings above the FAIL threshold. "
            f"Total findings analysed: {all_count}. "
            f"Raw output: artifact_ref={artifact_ref}."
        )
    )
```

---

| Helper | Signature | Notes |
|---|---|---|
| `_make_pass(message, notes=None)` | `(str, list[InfoNote] \| None)` | Captures metadata automatically via `_metadata_kwargs()` |
| `_make_fail(message, findings, notes=None)` | `(str, list[Finding], list[InfoNote] \| None)` | DIFFERENT from BaseTest's `_make_fail()` — takes `findings` list, not `detail` string |
| `_make_skip(reason)` | `(str,)` | No `notes=` parameter on external skip |
| `_make_error(exc, message_override=None)` | `(Exception, str \| None)` | Called by `_run()` automatically; use in `_evaluate()` only if needed |

**Critical difference from native `BaseTest._make_fail()`:**
`ExternalToolTest._make_fail()` takes a pre-built `findings: list[Finding]`,
not `detail: str`. There is no single-finding shortcut on external tests —
always build the `Finding` objects and pass the list. Even for a single
finding, pass `findings=[my_finding]`.

---

## Step B.5 — `config.yaml`  *(new tool only)*

Add the per-tool block under `external_tools`. The block must be present
even when using all defaults — it documents the available knobs to operators.

```yaml
external_tools:
  enabled: true
  nuclei:
    enabled: false            # flip to true when the binary is installed
    timeout_seconds: 180      # mandatory when enabled: true (Phase 1 validator)
    template_tags: "owasp,api"
    extra_flags: "-silent"
```

For an existing tool, no config.yaml changes are needed when adding a
second test — `external_tools.testssl.timeout_seconds` is shared across
all tests that use testssl.

---

## DA-2 connector injection — what it means for test implementation

`ExternalTestRegistry._inject_connectors()` is called automatically during
Phase R4 of pipeline startup. It groups tests by `tool_name`, calls
`_build_connector()` once per tool group, calls `is_available()` once,
and sets either `_injected_connector` or `_skip_reason_from_registry` on
every test in the group.

**As a test implementer, you do not call or implement DA-2 directly.** Its
effects are transparent: if the tool is available, `_get_connector()` in
`_run()` returns the injected instance and `_check_and_skip()` returns None.
If the tool is absent, `_run()` returns SKIP immediately via
`_skip_reason_from_registry`, and `execute()` returns `TestResult(SKIP)`
before your `_invoke_connector()` or `_evaluate()` is called.

The only operational implication: **when a tool is absent, one WARNING is
logged for the entire group**, not one per test. This is the intended
behaviour — do not add extra availability checks in `_build_connector()` or
`_invoke_connector()`.

---

## Post-implementation verification

**Step 1 — Verify the test is discovered by ExternalTestRegistry:**

```bash
python -c "
from src.external_tests.registry import ExternalTestRegistry
from src.core.models.external_tools import ExternalToolsConfig
r = ExternalTestRegistry()
tests = r.discover(
    external_tools_config=ExternalToolsConfig(),
    min_priority=3,
)
ids = [t.test_id for t in tests]
print('Discovered external test IDs:', ids)
target_id = 'ext.N.M'  # replace with your actual test_id
if target_id in ids:
    print(f'OK  {target_id} is discoverable.')
else:
    print(f'MISSING  {target_id} not found.')
    print('Check: filename starts with ext_test_, tool_name matches ExternalToolsConfig field.')
"
```

If the output is `MISSING` and the file exists, the two most common causes
are: the filename does not start with `ext_test_` (silently ignored by the
registry), or `tool_name` ClassVar does not exactly match a field name in
`ExternalToolsConfig` (caught with a WARNING log by `is_tool_enabled()`).

**Step 2 — Verify the tool availability path works:**

```bash
python -c "
from src.connectors.<toolname> import <ToolnameConnector>
c = <ToolnameConnector>()
print('available:', c.is_available())
print('version:', c.get_version())
"
```

If `is_available()` returns `False` and the binary is installed, check
`BINARY_NAME` and `SERVICE_ENV_VAR` in the connector ClassVars.

**Step 3 — Verify the config block is reachable:**

```bash
python -c "
from src.config.loader import load_config
config = load_config('config.yaml')
tool_cfg = config.external_tools.<toolname>
print('enabled:', tool_cfg.enabled)
print('timeout_seconds:', tool_cfg.timeout_seconds)
"
```

An `AttributeError` here means the field name in `ExternalToolsConfig`
does not match what you wrote in `config.yaml` (Step B.5).

---

## Pre-output checklist

- [ ] **New tool only (Step B.0):** `--version`, `--help`, and a real JSON/JSONL output sample from the live test environment were collected and inspected before writing any connector or `_evaluate()` code
- [ ] **New tool only (Step B.0):** severity field key path and exact string values confirmed from real output (not documentation) — `FAIL_SEVERITIES` and `NOTE_SEVERITIES` use `.upper()` normalization if tool emits mixed case

- [ ] `test_id` starts with `"ext."` prefix and is unique across all `src/tests/` and `src/external_tests/` — verified with: `grep -rn 'test_id.*ClassVar' src/tests/ src/external_tests/ | grep -v "__pycache__\|base.py\|_template"`
- [ ] `test_id` does not collide with any native test_id — confirmed by the same grep
- [ ] `tool_name` exactly matches a field name in `ExternalToolsConfig` — confirmed by inspection
- [ ] All 9 ClassVar attributes declared (`test_id`, `test_name`, `domain`, `priority`, `strategy`, `depends_on`, `tags`, `cwe_id`, `tool_name`)
- [ ] `source` ClassVar NOT declared in the subclass (it is fixed at `"external"` by the base class)
- [ ] `_build_connector()` performs zero I/O — object construction only
- [ ] `_invoke_connector()` reads timeout from `target.external_tools.<tool>.timeout_seconds`, NOT from `target.tests_config`
- [ ] `_invoke_connector()` uses `target_url` directly as passed by `_run()` — does NOT call `target.effective_endpoint_base_url()` again
- [ ] **`_evaluate()` uses `self._make_pass()` / `self._make_fail()` / `self._make_skip()` exclusively — zero direct `TestResult(...)` construction anywhere in the method body**
- [ ] Every `Finding.evidence_ref` is set to `artifact_ref` (not `None`)
- [ ] `raw_output` in `ConnectorResult` contains all 4 required keys: `command`, `command_json`, `results`, `all_count`
- [ ] **`command_json` in `raw_output` is a plain `str` from `" ".join(...)` — NOT `json.dumps(cmd)` and NOT a list**
- [ ] If connector uses `_build_reproducible_commands()`: both returned values are used as-is (plain strings) — no further transformation
- [ ] If connector builds `raw_output` manually: both `"command"` and `"command_json"` values are `" ".join(some_list_of_str)`, verified not `json.dumps()`
- [ ] Connector passes ALL findings in `results` — no severity filtering inside the connector
- [ ] `log: structlog.BoundLogger = structlog.get_logger(__name__)` present after imports in both connector and ext_test file
- [ ] `TestStrategy` imported from `src.core.models` — **never** from `src.tests.strategy` (violates the "must never import from tests/" rule)
- [ ] `TestResult` imported from `src.core.models.results` (not from `src.core.models` directly)
- [ ] Module-level constants defined for `FAIL_SEVERITIES`, `NOTE_SEVERITIES`, `_REFERENCES`
- [ ] If new tool: `BaseExternalToolConfig` subclass added to `src/core/models/external_tools.py` with `frozen=True` inherited (NOT to `src/config/schema/external_tools.py` — that is a re-export shim)
- [ ] If new tool: field added to `ExternalToolsConfig` with `default_factory`
- [ ] If new tool: connector exported from `src/connectors/__init__.py`
- [ ] If new tool: `config.yaml` `external_tools.<tool>` block added
- [ ] No `print()` — only `structlog`
- [ ] No magic numbers — all thresholds from `target.external_tools.<tool>.*` or module-level constants
- [ ] No `TODO`, `FIXME`, `HACK` in any file
- [ ] No import wildcards
- [ ] All code in English
- [ ] No emoji in source code
- [ ] Module docstring present with: guarantee, native-test split rationale, test_id convention, oracle, DAG placement, dependency rule

---

## Common errors and fixes

| Symptom | Root cause | Fix |
|---|---|---|
| External test never discovered, no log entry | File does not match `ext_test_` prefix | Rename to `ext_test_<id>_<description>.py` |
| Test always SKIPs with "tool not enabled" | `tool_name` ClassVar typo — not found in `ExternalToolsConfig` | Check WARNING in log: `external_tools_unknown_tool_name`; fix spelling to match exact field name |
| Test always SKIPs even when binary is installed | `tool_name` matches config but `enabled: false` in config.yaml | Set `external_tools.<tool>.enabled: true` and `timeout_seconds: N` |
| `ConfigurationError` at startup: "timeout_seconds mandatory when enabled=true" | `external_tools.<tool>.enabled: true` but `timeout_seconds` not set | Add `timeout_seconds: N` to config.yaml `external_tools.<tool>` block |
| HTML report shows empty cells for `command` / `command_json` | `ConnectorRawOutput` keys missing from `raw_output` | Add all 4 keys; use `_build_reproducible_commands()` for the command strings |
| `ExternalToolError` at runtime: "raw_output missing required keys" | Same as above — caught at runtime by `_validate_raw_output()` | Add all 4 keys to `raw_output` dict |
| **`command_json` renders as `[ " / h o m e / ...` (spaced chars)** | **`"command_json": json.dumps(cmd)` — JSON string treated as char iterable** | **Change to `"command_json": " ".join(cmd)` — plain space-separated str** |
| `TestResult` missing `test_name`, `domain`, `tags` in HTML report | `TestResult(...)` built directly in `_evaluate()` instead of using `_make_*()` | Replace with `self._make_fail()` / `self._make_pass()` / `self._make_skip()` |
| Report builder places test in unclassified bucket (domain=-1, source="") | Same as above — `_metadata_kwargs()` not called | Same fix: use `_make_*()` helpers |
| More than one WARNING log entry for the same absent tool (N entries instead of 1) | DA-2 not working — `tool_name` missing or `_build_connector()` raises | Ensure `tool_name` ClassVar is set; `_build_connector()` must not raise |
| `TypeError: execute() missing 1 required positional argument: 'client'` | Engine called `ExternalToolTest.execute()` with client (BaseTest signature) | This means the class was accidentally placed in `src/tests/` instead of `src/external_tests/` |
| `timeout_seconds` from config.yaml silently ignored | Reading from `target.tests_config` instead of `target.external_tools` | Fix `_invoke_connector()` to use `target.external_tools.<tool>.timeout_seconds` |
| `Finding.evidence_ref` is None in report | `evidence_ref=None` passed when constructing Finding | Use `evidence_ref=artifact_ref` — the artifact always exists for external tests |
| `ExternalToolError: timed_out=True` even with high timeout | `timeout_seconds` read incorrectly (e.g. integer vs None) | Confirm `target.external_tools.<tool>.timeout_seconds` is an `int`, not `None` |
| Connector double-counts findings (both FAIL and NOTE) | Severity check uses mutable state or inclusive conditions | Ensure FAIL and NOTE frozensets are mutually exclusive; verify partition logic |
| `author` field in nuclei findings shows `[REDACTED]` | `"auth"` substring in `evidence.py` sensitive-key patterns false-positives on `"author"` | Fixed in `evidence.py` via word-boundary regex — update evidence.py if this recurs |
| `ImportError` or wrong `TestStrategy` at startup | `TestStrategy` imported from `src.tests.strategy` — illegal import from `tests/` | Change to `from src.core.models import TestStrategy` |
| InfoNote cards missing in report despite message saying "N informational findings" | Note items embedded as text in the message string; `notes=` parameter never passed to `_make_pass()` / `_make_fail()` | Build `list[InfoNote]` from note_items and pass as `notes=all_notes` to both result helpers |
# Add an External Test (and a Connector)

> **Audience:** contributors · **Status:** v0.1.0 · **Source of truth:** `src/external_tests/base.py`,
> `src/external_tests/registry.py`, `src/connectors/base.py`, `src/core/models/external_tools.py`, the templates
> `src/connectors/_template_connector.py` and `src/external_tests/_template_ext_test.py`, `src/core/test_metadata.py`
> (`TestInfo`), `src/core/assessment_test.py` · **Verified:** 2026-10-05; declaration and result helpers 2026-10-16.
> The previous long version of this guide is in git history (commit `fd3bd90`).

An external test checks a guarantee by running an external tool (binary or Python library) through a
**connector**. Native tests never run external tools.

```
ExternalToolTest (src/external_tests/)            Connector (src/connectors/)
  _build_connector()  -> connector instance          is_available(), get_version()
  _invoke_connector() -> connector.run(...)  ──────► run(target_url, timeout_seconds) -> ConnectorResult
  _evaluate(result, artifact_ref) -> TestResult      (no verdict: returns all tool results)
```

The connector is a "dumb pipe": it runs the tool and returns **all** results. The test decides what is a FAIL, a
note or noise.

## Which steps apply

| Situation | Steps |
|---|---|
| New test with an already supported tool (nuclei, testssl, sslyze) | 5, 6 |
| New tool | 1 to 6 |

## 1. Connector (`src/connectors/<tool>.py`)

Copy `_template_connector.py`. Pick the base class:

<!-- [[[cog import generate_docs as g; cog.out(g.connector_bases_table()) ]]] -->

| Base | For | Declares | Optional (default) |
|---|---|---|---|
| `BaseSubprocessConnector` | Base of a connector for a tool run as a program (nuclei, testssl.sh). | `TOOL_NAME`, `BINARY_NAME` | `DEFAULT_TIMEOUT_SECONDS` (120), `LOCAL_TOOLS_SUBDIR` ('') |
| `BaseLibraryConnector` | Base of a connector for a tool used as a Python library (sslyze). | `TOOL_NAME`, `LIBRARY_MODULE` | - |

<!-- [[[end]]] -->

Implement `run(self, target_url: str, timeout_seconds: int, ...) -> ConnectorResult`. Helpers provided by
`BaseSubprocessConnector`:

<!-- [[[cog import generate_docs as g; cog.out(g.methods_table(('Helper', 'Purpose'), 'src.connectors.base:BaseSubprocessConnector._resolve_binary_path', 'src.connectors.base:BaseSubprocessConnector._build_reproducible_commands', 'src.connectors.base:BaseSubprocessConnector._run_subprocess', 'src.connectors.base:BaseSubprocessConnector._parse_jsonl_output', 'src.connectors.base:BaseSubprocessConnector._sanitize_paths_in_findings')) ]]] -->

| Helper | Purpose |
|---|---|
| `_resolve_binary_path()` | Return the binary's path: ./tools/<LOCAL_TOOLS_SUBDIR>/<BINARY_NAME> (relative to the working directory), else the one on PATH, else None. |
| `_build_reproducible_commands(cmd_prefix, scan_target, json_output_args)` | Build the command and command_json display strings of the raw output, with local paths normalised. |
| `_run_subprocess(cmd, timeout_seconds, tool_name)` | Run an argument list (no shell) and return (stdout, exit_code); a timeout raises ExternalToolError with timed_out=True. |
| `_parse_jsonl_output(raw_stdout, tool_name, *, skip_invalid_lines=True)` | Parse the JSON Lines output of a tool. |
| `_sanitize_paths_in_findings(findings, path_keys)` | Make the local file paths inside the tool's results relative (with _relativize_display_path). |

<!-- [[[end]]] -->

`raw_output` must contain exactly these four keys (`ConnectorRawOutput`); a missing key turns the test into
`ERROR`:

```python
raw_output = {
    "command": reproducible_command,         # plain str, space-separated (not json.dumps)
    "command_json": reproducible_command_json,
    "results": all_findings,                 # complete, unfiltered
    "all_count": len(all_findings),
}
return ConnectorResult(tool_name=self.TOOL_NAME, tool_version=self.get_version(),
                       raw_output=raw_output, exit_code=exit_code,
                       execution_time_ms=execution_time_ms, timed_out=False)
```

Raise `ExternalToolError(message, tool_name, exit_code=..., timed_out=...)` on tool failure. Connectors import only
the standard library, structlog, `src.connectors.base` and `src.core.exceptions`.

**Library connectors:** import the library only inside `run()` (types under `TYPE_CHECKING`), as
`src/connectors/sslyze.py` does, so the package still imports when the optional dependency is missing.

## 2. Export the connector

Add it to `src/connectors/__init__.py` (import and `__all__`).

## 3. Configuration model (`src/core/models/external_tools.py`)

Subclass `BaseExternalToolConfig`, which already provides `enabled` (default `false`), `timeout_seconds`
(required when enabled), `expected_version`, `dev_mode`. A command-line tool also declares `extra_flags` (see
`TestsslConfig`, `NucleiConfig`); a library has none. Override fields to set ranges and defaults, add tool-specific
fields, then add a field to `ExternalToolsConfig`:

```python
class ExternalToolsConfig(BaseModel):
    ...
    testssl: TestsslConfig = Field(...)
    nuclei: NucleiConfig = Field(...)
    sslyze: SslyzeConfig = Field(...)
```

**The field name must equal the test's `tool`** (in its `info`). The registry looks it up with
`getattr(external_tools, tool)`; an unknown name excludes the test with the warning
`external_tools_unknown_tool_name`.

Optionally re-export the class in `src/core/models/__init__.py` (today `SslyzeConfig` is not re-exported and
nothing breaks).

## 4. Installation and dependencies

- Binary: add a pinned download to `install_tools.sh` into `tools/<subdir>/` and set `expected_version` in
  `config.yaml`.
- Library: add an optional extra in `pyproject.toml` (`[project.optional-dependencies]`) and check its licence
  (sslyze is AGPL v3, Q-11).

## 5. The test (`src/external_tests/ext_test_<D>_<N>_<description>.py`)

Copy `_template_ext_test.py`. The registry imports only modules whose name starts with `ext_test_`.

**Declaration:** the same `TestInfo` as native tests (`src/core/test_metadata.py`), with an ID
`ext.<domain>.<guarantee>.<tool>` and `tool` set, checked like native ones (an invalid declaration, a native ID,
a missing `tool` or a module that cannot be imported stops the run, `TestDefinitionError`):

```python
info = TestInfo(
    id="ext.1.5.testssl",
    name="TLS Stack Analysis (testssl.sh)",
    priority=2,
    strategy=TestStrategy.BLACK_BOX,
    cwe="CWE-326",
    tags=(...),
    tool="testssl",          # = field name in ExternalToolsConfig
)
```

`depends_on` (tests whose data this test uses) and `requires_pass` (tests that must PASS first) are omitted when
empty.

`source` is fixed to `"external"` by the base class. `execution.test_ids` validates the `ext.X.Y.tool` format.

**Three methods to implement:**

<!-- [[[cog import generate_docs as g; cog.out(g.methods_table(('Method', 'Rule'), 'src.external_tests.base:ExternalToolTest._build_connector', 'src.external_tests.base:ExternalToolTest._invoke_connector', 'src.external_tests.base:ExternalToolTest._evaluate', typed=True)) ]]] -->

| Method | Rule |
|---|---|
| `_build_connector() -> BaseConnector` | Construct the connector only, no I/O: the registry calls it once per tool to check availability and injects the instance into the tool's tests. |
| `_invoke_connector(connector: BaseConnector, target: TargetContext, target_url: str) -> ConnectorResult` | Call connector.run(...) with the tool's timeout_seconds and the test's own parameters; target_url is target.endpoint_base_url(). |
| `_evaluate(result: ConnectorResult, artifact_ref: str) -> TestResult` | Apply the oracle to result.raw_output['results'] and return the TestResult; put artifact_ref in each finding's evidence_ref. |

<!-- [[[end]]] -->

**Result helpers** (`src/core/assessment_test.py`, the same as native tests):

<!-- [[[cog import generate_docs as g; cog.out(g.methods_table(('Helper', 'Use'), 'src.core.assessment_test:AssessmentTest._make_pass', 'src.core.assessment_test:AssessmentTest._make_fail', 'src.core.assessment_test:AssessmentTest._make_fail_multi', 'src.core.assessment_test:AssessmentTest._make_skip', 'src.core.assessment_test:AssessmentTest._make_error')) ]]] -->

| Helper | Use |
|---|---|
| `_make_pass(message, notes=None)` | Return a PASS result: the guarantee holds; notes may add context that is not a violation. |
| `_make_fail(message, detail, evidence_record_id=None, additional_references=None, notes=None)` | Return a FAIL result with one finding, titled with the test's name, with its CWE as first reference. |
| `_make_fail_multi(message, findings, notes=None)` | Return a FAIL result with the caller's findings, one per violation (preferred: each finding names the endpoint). |
| `_make_skip(reason, notes=None)` | Return a SKIP result naming the missing precondition. |
| `_make_error(exc, message=None)` | Return an ERROR result from an exception, keeping the transactions logged so far. |

<!-- [[[end]]] -->

`_make_fail_multi` is the usual case (one finding per tool result above the threshold); `_make_error` is normally not
needed, since the base class turns tool errors into ERROR. `_evaluate` returns only through these helpers.

Never build `TestResult(...)` directly: the helpers copy the declaration (name, domain, priority, tool) into the
result; without them the report shows empty fields.

**Typical oracle** (from `ext_test_1_5_tls_analysis.py`): partition results by severity:

```python
FAIL_SEVERITIES = frozenset({"HIGH", "CRITICAL"})     # -> Finding
NOTE_SEVERITIES = frozenset({"WARN", "MEDIUM"})       # -> InfoNote
# anything else -> ignored
```

What the base class does around your methods (`ExternalToolTest._run`):

1. return SKIP if the registry found the tool unavailable;
2. with `dev_mode: true` and a cached `outputs/tools/<label>_output.json`, reuse it instead of running the tool;
3. call `_invoke_connector`; `ExternalToolError` → ERROR (timeouts reported as such);
4. check the four `raw_output` keys (missing → ERROR);
5. store the raw output with `store.pin_artifact(...)` (sanitised, also written to `outputs/tools/`) and pass its
   ID as `artifact_ref`;
6. call `_evaluate`.

## 6. `config.yaml`

Add the tool block under `external_tools` with `enabled`, `timeout_seconds`, `extra_flags` (command-line tools only),
`expected_version`, `dev_mode: false` and tool-specific keys, each commented.

## Verify

1. `apiguard validate-config` (an enabled tool without `timeout_seconds` fails here).
2. `execution.test_ids: ["ext.<D>.<N>.<tool>"]` in a copy of the config (an `ext.`-only list runs only that test),
   then `apiguard run -c <copy>`.
3. In the run's `apiguard_report.json` (`outputs/forgejo/` with the lab configuration): the row with `source: "external"`, `tool_name`, `tool_artifact` with the four
   keys; the artefact in `evidence.json` and `outputs/tools/`.
4. Disable the tool and check the test disappears from the report; enable it with the binary missing and check it
   returns SKIP.
5. Write the page in `docs/05-tests/external/domain-<D>/` with its header marker (as for a native test:
   `g.test_header("ext.<D>.<N>.<tool>", page=cog.inFile)`), then `hatch run dev:gen` and `hatch run dev:check`.

## Common errors

| Symptom | Cause |
|---|---|
| Test absent, warning `external_tools_unknown_tool_name` | `info.tool` does not match a field of `ExternalToolsConfig` |
| Test absent, no warning | tool disabled, master switch off, module name not starting with `ext_test_`, or filtered by priority / `test_ids` |
| SKIP "not available" | binary not in `./tools/<subdir>/` or `PATH`; library not installed |
| ERROR "missing keys" | `raw_output` without one of `command`, `command_json`, `results`, `all_count` |
| Empty name/domain cells in the report | `TestResult` built directly instead of through the helpers |

## See also

- [`add-a-native-test.md`](02-add-a-native-test.md) · [`coding-rules.md`](01-coding-rules.md)
- [`../../tests/external/domain-1/ext-1-5-tls-analysis.md`](../../05-tests/external/domain-1/ext-1-5-tls-analysis.md) - an implemented example

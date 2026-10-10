# Add an External Test (and a Connector)

> **Audience:** contributors · **Status:** v0.1.0 · **Source of truth:** `src/external_tests/base.py`,
> `src/external_tests/registry.py`, `src/connectors/base.py`, `src/core/models/external_tools.py`, the templates
> `src/connectors/_template_connector.py` and `src/external_tests/_template_ext_test.py` · **Verified:** 2026-10-05.
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

| Base | For | Class attributes |
|---|---|---|
| `BaseSubprocessConnector` | a binary (nuclei, testssl.sh) | `TOOL_NAME`, `BINARY_NAME`, `DEFAULT_TIMEOUT_SECONDS`, `LOCAL_TOOLS_SUBDIR` |
| `BaseLibraryConnector` | a Python library (sslyze) | `TOOL_NAME`, `LIBRARY_MODULE` |

Implement `run(self, target_url: str, timeout_seconds: int, ...) -> ConnectorResult`. Helpers provided by
`BaseSubprocessConnector`:

| Helper | Purpose |
|---|---|
| `_resolve_binary_path()` | `./tools/<LOCAL_TOOLS_SUBDIR>/<BINARY_NAME>` (relative to the working directory), else `PATH` |
| `_build_reproducible_commands(cmd_prefix, scan_target, json_output_args)` | the `command` / `command_json` display strings, with local paths normalised |
| `_run_subprocess(cmd, timeout_seconds, tool_name)` | runs an argument list (no shell), returns `(stdout, exit_code)`, raises `ExternalToolError` on timeout |
| `_parse_jsonl_output(raw_stdout, tool_name)` | JSON Lines parsing |
| `_sanitize_paths_in_findings(findings, path_keys)` | normalises file paths inside results |

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

**The field name must equal the test's `tool_name`.** The registry looks it up with
`getattr(external_tools, tool_name)`; an unknown name excludes the test with the warning
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

**Class attributes:** the eight of native tests plus `tool_name`, checked at discovery like native ones (a missing
or invalid one stops the run, `TestDefinitionError`):

```python
test_id: ClassVar[str] = "ext.1.5.testssl"     # ext.<domain>.<guarantee>.<tool>
test_name: ClassVar[str] = "TLS Stack Analysis (testssl.sh)"
domain: ClassVar[int] = 1
priority: ClassVar[int] = 2
strategy: ClassVar[TestStrategy] = TestStrategy.BLACK_BOX
depends_on: ClassVar[list[str]] = []            # tests whose data this test uses
requires_pass: ClassVar[list[str]] = []         # tests that must PASS first
tags: ClassVar[list[str]] = [...]
cwe_id: ClassVar[str] = "CWE-326"
tool_name: ClassVar[str] = "testssl"            # = field name in ExternalToolsConfig
```

`source` is fixed to `"external"` by the base class. `execution.test_ids` validates the `ext.X.Y.tool` format.

**Three methods to implement:**

| Method | Rule |
|---|---|
| `_build_connector(self) -> BaseConnector` | construct the connector only: no I/O. The registry uses it to check availability once per tool and injects one shared instance into all tests of that tool. |
| `_invoke_connector(self, connector, target, target_url) -> ConnectorResult` | call `connector.run(...)` with `target.external_tools.<tool>.timeout_seconds` and tool options. `target_url` comes from `target.endpoint_base_url()`. |
| `_evaluate(self, result, artifact_ref) -> TestResult` | apply the oracle to `result.raw_output["results"]`; put `artifact_ref` in each Finding's `evidence_ref`. Return only through the helpers below. |

**Result helpers** (`ExternalToolTest`, different from `BaseTest`):

| Helper | Note |
|---|---|
| `_make_pass(message, notes=None)` | |
| `_make_fail(message, findings, notes=None)` | takes a **list** of findings (in `BaseTest`, `_make_fail` builds a single finding) |
| `_make_skip(reason)` | |
| `_make_error(exc, message_override=None)` | normally not needed: tool errors are handled by the base class |

Never build `TestResult(...)` directly: the helpers copy the class metadata (name, domain, priority, tool name)
into the result; without them the report shows empty fields.

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
3. In `outputs/apiguard_report.json`: the row with `source: "external"`, `tool_name`, `tool_artifact` with the four
   keys; the artefact in `evidence.json` and `outputs/tools/`.
4. Disable the tool and check the test disappears from the report; enable it with the binary missing and check it
   returns SKIP.
5. `hatch run dev:check`; write the page in `docs/tests/external/domain-<D>/`.

## Common errors

| Symptom | Cause |
|---|---|
| Test absent, warning `external_tools_unknown_tool_name` | `tool_name` does not match a field of `ExternalToolsConfig` |
| Test absent, no warning | tool disabled, master switch off, module name not starting with `ext_test_`, or filtered by priority / `test_ids` |
| SKIP "not available" | binary not in `./tools/<subdir>/` or `PATH`; library not installed |
| ERROR "missing keys" | `raw_output` without one of `command`, `command_json`, `results`, `all_count` |
| Empty name/domain cells in the report | `TestResult` built directly instead of through the helpers |

## See also

- [`add-a-native-test.md`](add-a-native-test.md) · [`coding-rules.md`](coding-rules.md)
- [`../../tests/external/domain-1/ext-1-5-tls-analysis.md`](../../tests/external/domain-1/ext-1-5-tls-analysis.md) - an implemented example

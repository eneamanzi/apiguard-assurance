# APIGuard Assurance - Claude Code Context

## Project

Python CLI for automated security assessment of REST APIs behind an API gateway. Born as a Master's thesis in
Cybersecurity; v0.1.0 released 2026-05-18 (15 native + 3 external tests). Current phase: documentation and
hardening for production use and integration into another product.

**Development targets:** three labs in `test-environments/`: Forgejo behind Kong (DB-less, `forgejo-kong/`, the
reference), OWASP crAPI behind Kong (`crapi-kong/`), Forgejo behind Apache APISIX (`forgejo-apisix/`). Each lab
configuration holds only its own values; every key is in `config.example.yaml` (checked by `dev:check`).
The tool is agnostic of the target API and gateway (OpenAPI spec + `config.yaml`, including the prepared resources:
login and objects a test creates); gateways through adapters (`kong`, `apisix`). What each test needs from a target is
in `docs/reference/compatibility.md` (Test portability).

## Where things are

| Need | Read |
|---|---|
| Map of all documentation | `docs/index.md` |
| Current work: what to do next, step by step | `docs/project/plan.md` |
| Open doubts, with evidence (closed **only** by the owner) | `OPEN_QUESTIONS.md` |
| What is implemented, milestones | `docs/project/roadmap.md` (single source of truth) |
| Pipeline, modules, dependencies, components | `docs/architecture/overview.md` |
| Data models, assessment model, security model | `docs/architecture/data-model.md`, `assessment-model.md`, `security-model.md` |
| Why a design choice was made (decisions D1-D9) | `docs/architecture/design-decisions.md` |
| Coding rules (English) | `docs/guides/extending/coding-rules.md` |
| Adding a native test / external test / gateway adapter | `docs/guides/extending/add-a-native-test.md`, `add-an-external-test.md`, `add-a-gateway-adapter.md` |
| What each test does, its oracle, its effects on the target | `docs/tests/` (index `docs/tests/README.md`) |
| Verified facts: configuration, CLI, exit codes, report and evidence formats, compatibility | `docs/reference/` (check here before answering "what does X do") |
| Methodology (guarantees, oracles, box gradient), Italian | `docs/knowledge/methodology/methodology.it.md` |
| Thesis implementation chapter (superseded by `docs/architecture/`), Italian | `docs/knowledge/archive/implementation-chapter.it.md` |
| Original coding rules and workflow protocol, Italian | `docs/project/claude-rules.it.md` |

`*.it.md` files are Italian sources pending selective translation.

## Directory Layout

```
src/
├── cli.py            # Entry point (Typer): run, validate-config, list-tests, generate-seed, version
├── cli_console.py    # Console interface of `run` (engine RunObserver): test lines, summary
├── engine.py         # Orchestrator, the only module with full visibility
├── config/           # Phase 1: loader (YAML + ${VAR} interpolation) + ToolConfig schema;
│                     #   tests_section (the tests: section, checked against the tests' models);
│                     #   config_used (config_used.yaml, the configuration a run used)
├── discovery/        # Phase 2: OpenAPI fetch/dereference, AttackSurface, seed generator
├── core/             # Shared infrastructure, zero test logic: client, context, evidence, dag,
│                     #   gateway/ (BaseGatewayAdapter + Kong, APISIX), auth_placement,
│                     #   models/, exceptions,
│                     #   test_metadata (TestInfo, the declaration of a test),
│                     #   assessment_test (base of every test), test_discovery
├── connectors/       # External tool wrappers, zero test logic (nuclei, testssl, sslyze)
├── external_tests/   # ExternalToolTest hierarchy, parallel to tests/ (both on core's AssessmentTest)
├── tests/            # BaseTest, registry, helpers/, domain_0 … domain_7 (each test module holds its
│                     #   declaration, TestInfo, and its parameter model)
└── report/           # Phase 7: builder, renderer, templates/report.html
```

Module-level detail and the actual import graph: `docs/architecture/overview.md`.

**Dependency direction (absolute):**
`core/` ← `connectors/` ← `tests/` and `external_tests/` ← `engine.py`
No lateral, no upward, no circular imports. `core/` knows no test; `config/` never imports `tests/` (the engine
passes it the tests' parameter models). `core/`, `connectors/`, `tests/` and `external_tests/` never import
`config/`, `discovery/`, `report/` or `cli`; native tests never import `connectors/`.
Checked automatically by `lint-imports` in `hatch run dev:check` (`[tool.importlinter]` in `pyproject.toml`).

**Gateway adapter pattern:**
WHITE_BOX tests access the gateway admin plane via `target.gateway` (a `BaseGatewayAdapter`
injected by engine.py Phase 3). Tests declare `needs=(Need.GATEWAY,)` in their `TestInfo`: without a gateway the
engine records them as SKIP before they run.
The ABC and all concrete implementations live in `src/core/gateway/` (currently: `KongGatewayAdapter`,
`ApisixGatewayAdapter`).
The adapter type is configured via `gateway.adapter` (`kong` or `apisix`) in `config.yaml`, with the Admin API in
`gateway.admin` (`url`, `headers`, `tls`).

---

## Hard Rules - Non-Negotiable

If a request conflicts with any of these, **stop and flag it before proceeding.**

### Code
- `pass`, `# TODO`, `# FIXME` - **forbidden**.
  `...` (Ellipsis) is allowed **only** as the body of `@abstractmethod` declarations
  (idiomatic Python ABC stub) and inside type-only stubs. It must never appear
  in a concrete method body or as a placeholder for unfinished implementation.
- `print()` - **forbidden**; use `structlog` (logs) and `rich` (terminal UI)
- Bare `except:` or `except Exception: pass` - **forbidden**; use the custom hierarchy
- Magic numbers/strings - **forbidden**; named constants or `config.yaml`
- No global module-level singletons for `SecurityClient`
- No numbers in module filenames, except test modules, which follow the `test_X_Y_` / `ext_test_X_Y_` naming
  required in Testing below
- Native `BaseTest` subclasses must **never** invoke external binary subprocesses.
  That responsibility belongs exclusively to `ExternalToolTest` subclasses via connectors.

### Configuration
Every tunable parameter of a test lives in `config.yaml` under `tests.domain_X.test_X_Y.<param>`: the test
declares its model in its own module (`class TestXY...(BaseTest[TestXYParams])`) and reads it with
`self.params(target)`.
**Before adding a new config param: stop, flag it, wait for confirmation.**

### Types and Documentation
- Pydantic v2 only - no `TypedDict` for data models. `TypedDict` is allowed only as a static type for plain
  dicts that are not data models: the shape of raw external-tool output (`ConnectorRawOutput`, `TlsFinding`)
- Type hints on every function signature (params + return type)
- Full docstrings on every public method
- All identifiers, docstrings, log keys, comments in **English**
- Credentials and sensitive values in logs: always `[REDACTED]`

### Path Sanitization
`_relativize_display_path()` in `connectors/base.py` is the **single authoritative function**
for path normalization. Never duplicate this logic.
Temp file paths (`/tmp/xxx.json`) must never appear in `command`/`command_json` display strings.
Use clean placeholders (`nuclei_result.json`, `testssl_result.json`).

### Testing
- E2E only against the real target - no `httpx` mocks, no `MagicMock`
- Native test filename: `tests/domain_X/test_X_Y_<description>.py`
- External test filename: `external_tests/ext_test_X_Y_<description>.py`

### Workflow
- One file/class per response. Explain internal logic and rationale. Wait for explicit go-ahead.
- Before writing: state the file and why. Wait for confirmation.

### Documentation
- Write only facts verified against the code or a run; a doubt goes to `OPEN_QUESTIONS.md` with its evidence,
  never guessed. Claude may propose a resolution; only the owner closes a question.
- Documentation in English, Markdown.

---

## Exception Hierarchy (`src/core/exceptions.py`)

```
ToolBaseError
 ├── ConfigurationError       # Phase 1 - invalid config or missing env var [BLOCKS STARTUP]
 ├── TestDefinitionError      # after Phase 1 - a test declared incorrectly (invalid or missing
 │                            #   info = TestInfo(...), duplicate ID, module that cannot be
 │                            #   imported or outside a package) [BLOCKS STARTUP]
 ├── OpenAPILoadError         # Phase 2 - spec unreachable or malformed [BLOCKS STARTUP]
 ├── DAGCycleError            # Phase 4 - circular dependency [BLOCKS STARTUP]
 ├── SecurityClientError      # Phase 5, native tests → caught in execute() → TestResult(ERROR)
 ├── AuthenticationSetupError # Phase 5, helpers/auth*.py - a role's credential not obtained (login
 │                            #   request not 2xx, no credential value); caught in execute() → TestResult(ERROR)
 ├── ExternalToolError        # Phase 5, external tests (fields: tool_name, exit_code, timed_out, raw_stderr)
 │                            #   → caught in execute() → TestResult(ERROR)
 └── TeardownError            # Phase 6 → WARNING log, never propagated
```

`GatewayAdapterError` (in `src/core/gateway/base.py`) extends `ToolBaseError` and is raised
by gateway adapters on transport failure or unexpected HTTP status from the admin endpoint.
The concept readers of `BaseGatewayAdapter` catch it and answer "not accessible"; the tests then SKIP or add a note.

`SeedGeneratorFetchError` and `SeedGeneratorParseError` (in `src/discovery/seed_generator.py`)
extend `ToolBaseError` and are raised exclusively by the `apiguard generate-seed` CLI helper
when the OpenAPI specification cannot be retrieved or parsed. They are caught in `src/cli.py`
and converted to a non-zero exit code with an actionable message. They do not appear during
the main Phase 1-7 assessment pipeline.

Missing external tool → `TestResult(SKIP)` via `_skip_reason_from_registry`. Not an exception.

---

## Session Startup

1. Read `docs/project/plan.md` to see the current step; check `OPEN_QUESTIONS.md` for the questions it involves.
2. For code work, check `docs/project/roadmap.md` and read the relevant files from "Where things are":
   - implementing a test: the matching guide in `docs/guides/extending/`, then the methodology;
   - touching infrastructure: `docs/architecture/overview.md`.
3. State the file you are about to write. Wait for confirmation.
4. Write one file. Explain internal logic and rationale.
5. Verify against the lab with only the affected tests (`execution.test_ids` in a copy of `test-environments/forgejo-kong/config.yaml`), not the
   full assessment.
6. After completing a test, update `docs/project/roadmap.md`, the test page in `docs/tests/` and `CHANGELOG.md`, then
   `hatch run dev:gen` (the generated documentation: catalogue, page headers, parameter tables, `config.example.yaml`).

# APIGuard Assurance — Claude Code Context

## Project

Python tool for automated REST API security assessment. Master's thesis in Cybersecurity.
**Phase 4 active:** implementation.
**Development target:** Forgejo REST API protected by Kong Gateway (DB-less mode).
The tool is API-agnostic by design: it works against any documented REST API via `config.yaml`
and the target's OpenAPI spec. No application-specific logic may be hardcoded in `src/`.

**Project state (implemented tests, connectors, milestones):** `Z-CHECKLIST.md` — single source of truth.

Reference documents — load with `/add-file` when needed:
- `.claude/LLM_rules.md` — coding rules, anti-patterns, workflow protocol
- `.claude/Implementazione.md` — full architecture (v4.1)
- `.claude/3_TOP_metodologia.md` — test methodology, oracles, box-gradient

---

## Directory Layout

```
src/
├── cli.py                   # Entry point (Typer)
├── engine.py                # Orchestrator — only module with full visibility
├── core/                    # Shared infrastructure — zero test logic
│   ├── client.py            # SecurityClient (httpx, no auto-redirect)
│   ├── context.py           # TargetContext (frozen) + TestContext (mutable)
│   ├── evidence.py          # EvidenceStore (deque maxlen=100)
│   ├── dag.py               # DAGScheduler (graphlib.TopologicalSorter)
│   ├── models.py            # TestResult, Finding, TestStatus (Pydantic v2)
│   └── exceptions.py        # Custom exception hierarchy
├── config/
│   ├── schema/              # Pydantic v2 schemas per domain + tool_config.py
│   └── loader.py            # YAML load + ${VAR} env interpolation
├── discovery/
│   ├── openapi.py           # Fetch + prance dereference + spec validation
│   └── surface.py           # AttackSurface — structured endpoint map
├── connectors/              # External tool wrappers — zero test logic
│   ├── base.py              # BaseConnector hierarchy + _relativize_display_path()
│   ├── testssl.py
│   └── nuclei.py
├── external_tests/          # Parallel hierarchy to tests/ — NOT BaseTest subclasses
│   ├── base.py              # ExternalToolTest ABC + dev-mode cache logic
│   ├── registry.py          # ExternalTestRegistry (Phase R4: connector injection)
│   ├── ext_test_0_1_shadow_api_nuclei.py
│   └── ext_test_1_5_tls_analysis.py
├── tests/
│   ├── base.py              # BaseTest ABC
│   ├── registry.py          # Dynamic discovery via pkgutil.walk_packages
│   ├── strategy.py          # TestStrategy Enum
│   ├── helpers/             # auth, auth_forgejo, auth_jwt_login, forgejo_resources,
│   │                        # jwt_forge, kong_admin, path_resolver, response_inspector
│   ├── domain_0/            # test_0_1, test_0_2, test_0_3
│   ├── domain_1/            # test_1_1, test_1_5, test_1_6
│   ├── domain_4/            # test_4_1, test_4_2, test_4_3
│   └── domain_7/            # test_7_2
└── report/
    ├── builder.py
    ├── renderer.py
    └── templates/report.html

tests_e2e/                   # E2E against real target — no mocks
Z-CHECKLIST.md               # Project state — implemented tests, connectors, milestones
```

**Dependency direction (absolute):**
`core/` ← `connectors/` ← `tests/` and `external_tests/` ← `engine.py`
No lateral, no upward, no circular imports.

---

## Hard Rules — Non-Negotiable

If a request conflicts with any of these, **stop and flag it before proceeding.**

### Code
- `pass`, `...`, `# TODO`, `# FIXME` — **forbidden**
- `print()` — **forbidden**; use `structlog` (logs) and `rich` (terminal UI)
- Bare `except:` or `except Exception: pass` — **forbidden**; use the custom hierarchy
- Magic numbers/strings — **forbidden**; named constants or `config.yaml`
- No global module-level singletons for `SecurityClient`
- No numbers in module filenames

### Configuration
Every tunable parameter lives in `config.yaml` under `tests.domain_X.test_X_Y.<param>`,
accessed via `TargetContext` or `TestContext`.
**Before adding a new config param: stop, flag it, wait for confirmation.**

### Types and Documentation
- Pydantic v2 only — no `TypedDict` for data models
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
- E2E only against the real target — no `httpx` mocks, no `MagicMock`
- Native test filename: `tests/domain_X/test_X_Y_<description>.py`
- External test filename: `external_tests/ext_test_X_Y_<description>.py`

### Workflow
- One file/class per response. Explain internal logic and rationale. Wait for explicit go-ahead.
- Before writing: state the file and why. Wait for confirmation.

---

## Exception Hierarchy (`src/core/exceptions.py`)

```
ToolBaseError
 ├── ConfigurationError    # Phase 1 — invalid config or missing env var [BLOCKS STARTUP]
 ├── OpenAPILoadError      # Phase 2 — spec unreachable or malformed [BLOCKS STARTUP]
 ├── DAGCycleError         # Phase 4 — circular dependency [BLOCKS STARTUP]
 ├── SecurityClientError   # Phase 5, native tests → caught in execute() → TestResult(ERROR)
 ├── ExternalToolError     # Phase 5, external tests (fields: tool_name, exit_code, timed_out)
 │                         #   → caught in execute() → TestResult(ERROR)
 └── TeardownError         # Phase 6 → WARNING log, never propagated
```

Missing external tool → `TestResult(SKIP)` via `_skip_reason_from_registry`. Not an exception.

---

## Test Implementation Guides

Full contracts, templates, and step-by-step guides for implementing native and external tests:
- `docs/ADDING_TESTS.md` — `BaseTest` contract, `ClassVar` fields, `execute()` signature,
  `TestResult` statuses, strategy/priority mapping
- `docs/ADDING_EXTERNAL_TESTS.md` — `ExternalToolTest` contract, `_build_connector()`,
  `_invoke_connector()`, `_evaluate()`, dev-mode cache, connector injection (Phase R4)

Load with `/add-file docs/ADDING_TESTS.md` or `/add-file docs/ADDING_EXTERNAL_TESTS.md`
before implementing any new test.

## Session Startup

1. Check `Z-CHECKLIST.md` to identify what to implement next.
2. Load reference docs as needed:
   - `/add-file .claude/LLM_rules.md` — always useful for a new session
   - `/add-file .claude/3_TOP_metodologia.md` — when implementing a test
   - `/add-file .claude/Implementazione.md` — when touching infrastructure
3. **If implementing a test:** read the relevant guide in `docs/` before writing any code:
   - `/add-file docs/ADDING_TESTS.md` — for native `BaseTest` subclasses
   - `/add-file docs/ADDING_EXTERNAL_TESTS.md` — for `ExternalToolTest` subclasses
4. State the file you are about to write. Wait for confirmation.
5. Write one file. Explain internal logic and rationale.
6. After completing a test, update `Z-CHECKLIST.md` to reflect the new state.
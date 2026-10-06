# Add a Native Test

> **Audience:** contributors · **Status:** v0.1.0 · **Source of truth:** `src/tests/base.py`, `src/tests/registry.py`,
> `src/engine.py` (Phase 3), the existing tests in `src/tests/domain_*/` · **Verified:** 2026-10-05.
> Snippets are copied from `src/tests/domain_2/test_2_1_rbac_enforcement.py` and its configuration chain.
> The previous long version of this guide is in git history (commit `fd3bd90`).

A native test is a Python class that checks one methodology guarantee by sending HTTP requests through the tool's
client. For a test that runs an external binary or library, see
[`add-an-external-test.md`](add-an-external-test.md).

Before starting, read the guarantee in [`methodology.it.md`](../../knowledge/methodology/methodology.it.md) and the
tool decision in [`decisions.it.md`](../../knowledge/tools/decisions.it.md), and the
[assessment model](../../architecture/assessment-model.md) (strategy, priority, outcomes).

## Files to touch

| # | File | When | What |
|---|---|---|---|
| 1 | `src/config/schema/domain_<D>.py` | test has parameters | `Test<DN>Config` model + field in `TestDomain<D>Config` |
| 2 | `src/config/schema/tests_config.py` | new domain | field `domain_<D>` in `TestsConfig` |
| 3 | `src/config/schema/__init__.py` | optional | re-export the new classes (convention; nothing imports them from here) |
| 4 | `src/core/models/runtime.py` | test has parameters | `RuntimeTest<DN>Config` + field `test_<D>_<N>` in `RuntimeTestsConfig` |
| 5 | `src/core/models/__init__.py` | test has parameters | export `RuntimeTest<DN>Config` (import + `__all__`): `engine.py` imports it from here |
| 6 | `src/engine.py` | test has parameters | import + populate `test_<D>_<N>=RuntimeTest<DN>Config(...)` in Phase 3 |
| 7 | `src/tests/domain_<D>/__init__.py` | new domain | empty file |
| 8 | `src/tests/domain_<D>/test_<D>_<N>_<name>.py` | always | the test |
| 9 | `config.yaml` | test has parameters | documented `tests.domain_<D>.test_<D>_<N>` block |

Notes from the current code:

- **Step 7 fails silently.** Without `__init__.py`, `pkgutil.walk_packages` skips the directory and the test is
  never discovered, with no error (verified 2026-10-05).
- **Step 5 fails loudly** (`ImportError` at startup) if the class is not exported.
- A test without parameters needs only step 8 (and 7 for a new domain): tests 0.1 and 0.3 have no config model.
  Some older guidance says every test should have a (possibly empty) config model; the code does not follow it
  (Q-37).

## 1. Configuration (steps 1 to 6, 9)

Why two layers: tests depend only on `core/`, so they read a runtime copy of their parameters
(`target.tests_config.test_<D>_<N>`) instead of the config schema. See
[data model](../../architecture/data-model.md#configuration-two-layers).

**Schema** (`src/config/schema/domain_2.py`): a frozen model with named constants for defaults and bounds, and a
field in the domain aggregator.

```python
class Test21Config(BaseModel):
    model_config = {"frozen": True}

    admin_endpoint_paths: Annotated[list[str], Field(min_length=1)] = Field(
        default_factory=lambda: list(TEST_21_ADMIN_ENDPOINT_PATHS_DEFAULT),
        description="...",
    )
    admin_endpoint_method: str = Field(default=TEST_21_ADMIN_ENDPOINT_METHOD_DEFAULT, description="...")


class TestDomain2Config(BaseModel):
    model_config = {"frozen": True}

    test_2_1: Test21Config = Field(default_factory=Test21Config, description="...")
```

Every field needs a `description`: it is the source of [`reference/configuration.md`](../../reference/configuration.md).

**Runtime mirror** (`src/core/models/runtime.py`): `RuntimeTest21Config` with the same fields, frozen, and a field
`test_2_1` in `RuntimeTestsConfig` with `default_factory`.

**Engine wiring** (`src/engine.py`, `_phase_3_build_contexts`), copying each field explicitly:

```python
test_2_1=RuntimeTest21Config(
    admin_endpoint_paths=list(config.tests.domain_2.test_2_1.admin_endpoint_paths),
    admin_endpoint_method=config.tests.domain_2.test_2_1.admin_endpoint_method,
),
```

**Naming:** `test_id` uses a dot (`"2.1"`); config keys and fields use underscores (`test_2_1`).

## 2. The test module (step 8)

**File name:** `test_<D>_<N>_<description>.py` in `src/tests/domain_<D>/`. Only modules whose name starts with
`test_` are imported by the registry.

**Imports and constants** (from test 2.1). Status codes, oracle-state labels and references are module constants:

```python
from src.core.client import SecurityClient
from src.core.context import ROLE_USER_A, TargetContext, TestContext
from src.core.evidence import EvidenceStore
from src.core.exceptions import AuthenticationSetupError, SecurityClientError
from src.core.models import Finding, TestResult, TestStrategy
from src.tests.base import BaseTest
from src.tests.helpers.auth import acquire_tokens

log: structlog.BoundLogger = structlog.get_logger(__name__)

_RBAC_BYPASS_CODES: frozenset[int] = frozenset(range(200, 300))
_STATE_RBAC_BYPASS: str = "RBAC_BYPASS"
_REFERENCES: list[str] = ["CWE-285", "OWASP-API5:2023", "OWASP-ASVS-v5.0.0-V8.3.1", ...]
```

Allowed imports: `core/`, `src/tests/base.py`, `src/tests/helpers/`, `src/tests/data/`. Never `config/`,
`discovery/`, `report/`, `engine.py`, `connectors/`; never start a subprocess.

**Class metadata.** Eight class attributes are required; a class missing any of them is not registered
(`BaseTest.has_required_metadata()`).

```python
class Test21RbacEnforcement(BaseTest):
    test_id: ClassVar[str] = "2.1"
    test_name: ClassVar[str] = "Only Authorized Users Access Privileged Endpoints"
    domain: ClassVar[int] = 2
    priority: ClassVar[int] = 2
    strategy: ClassVar[TestStrategy] = TestStrategy.GREY_BOX
    depends_on: ClassVar[list[str]] = ["1.1"]
    tags: ClassVar[list[str]] = ["authorization", "rbac", "OWASP-API5:2023", ...]
    cwe_id: ClassVar[str] = "CWE-285"
```

Take the priority from the methodology's severity criteria ([priorities](../../architecture/assessment-model.md#priorities)); set
the strategy from what the test needs to run (nothing, credentials, or configuration access), independently of the
priority; `depends_on` lists test IDs whose results or tokens this test
needs (`[]` otherwise).

**`execute()`** must always return a `TestResult` and never raise. Structure: guards, setup, probes in private
helpers, verdict, and a catch-all:

```python
def execute(self, target: TargetContext, context: TestContext,
            client: SecurityClient, store: EvidenceStore) -> TestResult:
    try:
        guard = self._requires_grey_box_credentials(target)
        if guard is not None:
            return guard
        try:
            acquire_tokens(target, context, client, required_roles=frozenset({ROLE_USER_A}))
        except (AuthenticationSetupError, SecurityClientError) as exc:
            return self._make_error(exc)
        skip = self._requires_token(context, ROLE_USER_A)
        if skip is not None:
            return skip

        cfg = target.tests_config.test_2_1
        findings: list[Finding] = []
        for path in cfg.admin_endpoint_paths:
            finding = self._probe_admin_endpoint(client=client, store=store, ...)
            if finding is not None:
                findings.append(finding)

        if findings:
            return self._make_fail_multi(message="...", findings=findings)
        return self._make_pass(message="...")
    except Exception as exc:  # noqa: BLE001
        return self._make_error(exc)
```

**A probe**: every request goes through `client.request()`, every response is logged with
`_log_transaction()`, and a violation stores its evidence **before** logging it:

```python
response, record = client.request(
    method=method, path=path, test_id=self.test_id,
    headers={"Authorization": f"Bearer {user_a_token}"},
)
if response.status_code in _RBAC_BYPASS_CODES:
    store.add_fail_evidence(record)
    self._log_transaction(record, oracle_state=_STATE_RBAC_BYPASS, is_fail=True)
    return Finding(
        title=f"RBAC Bypass: {method} {path}",
        detail=f"Sent {method} {path} with a '{ROLE_USER_A}' token. Expected 403 ... Received {response.status_code} ...",
        references=_REFERENCES,
        evidence_ref=record.record_id,
    )
self._log_transaction(record, oracle_state=_STATE_RBAC_ENFORCED)
```

## 3. Building blocks

**Result helpers** (`src/tests/base.py`). They copy the class metadata into the `TestResult`:

| Helper | Use |
|---|---|
| `_make_pass(message, notes=None)` | guarantee holds |
| `_make_fail(message, detail, evidence_record_id=None, additional_references=None, notes=None)` | one consolidated finding built from the test's own name and CWE |
| `_make_fail_multi(message, findings, notes=None)` | one finding per violation (preferred: each finding names the endpoint) |
| `_make_skip(reason, notes=None)` | missing precondition |
| `_make_error(exc)` | unexpected failure; keeps the transactions logged so far |

**Guards** (return a SKIP result or `None`): `_requires_attack_surface(target)`,
`_requires_grey_box_credentials(target)`, `_requires_token(context, role)`, `_requires_admin_api(target)`.

**Evidence and audit trail:**

| Call | When |
|---|---|
| `self._log_transaction(record, oracle_state=..., is_fail=False)` | after **every** `client.request()` |
| `store.add_fail_evidence(record)` | each transaction that proves a FAIL, before `_log_transaction(..., is_fail=True)` |
| `store.pin_evidence(record)` | a non-failing transaction that is key evidence |

Oracle-state labels are free strings in `SCREAMING_SNAKE_CASE`, defined as module constants and documented on the
test page.

**Attack surface** (`target.attack_surface`, check `_requires_attack_surface` first):
`get_authenticated_endpoints()`, `get_public_endpoints()`, `get_deprecated_endpoints()`,
`get_endpoints_by_method(method)`; each `EndpointRecord` has `path`, `method`, `requires_auth`, `is_deprecated`,
`parameters`.

**Helpers** (`src/tests/helpers/`):

| Module | Provides |
|---|---|
| `auth.py` | `acquire_tokens(target, context, client, required_roles=...)`: dispatches to `auth_forgejo.py` or `auth_jwt_login.py` according to `credentials.auth_type` and stores tokens in `TestContext` |
| `path_resolver.py` | `resolve_path_with_seed(path, seed, fallback)`, `extract_param_names_from_path(path)`; constants `PATH_PARAM_FALLBACK_DEFAULT` (`"1"`), `PATH_PARAM_FALLBACK_SAFE_DELETE` (`"apiguard-probe"`) |
| `forgejo_resources.py` | `get_authenticated_user`, `create_repository`, `create_issue`, `list_repositories` (Forgejo only; creation helpers register teardown) |
| `response_inspector.py` | `contains_stack_trace`, `contains_sensitive_fields`, `extract_debug_fields`, `check_security_headers`, `find_missing_security_headers`, `find_invalid_security_headers`, `find_leaky_headers`, `auth_errors_are_uniform` |

**Payload data** (`src/tests/data/`): `auth_payloads.py`, `inspector_patterns.py`, `shadow_wordlists.py`,
`ssrf_payloads.py`. Put reusable payload lists there, not in the test.

**Gateway configuration** (WHITE_BOX audits): guard with `_requires_admin_api(target)`, then call
`target.gateway.get_services()`, `get_plugins()`, `get_routes()`, `get_upstreams()`, `get_status()`; catch
`GatewayAdapterError` and return `_make_error`.

**Resources created on the target** must be registered immediately after creation:
`context.register_resource_for_teardown(method, path, headers=None)`. Phase 6 deletes them in reverse order.

## 4. Verify

There is no automated test suite yet (planned: Q-51). Verify against the lab target:

1. `apiguard validate-config` - the new parameters load.
2. Run only the new test: in a copy of `config.yaml` set `execution.test_ids: ["<D>.<N>"]` and
   `external_tools.enabled: false` (otherwise the external tests run too, Q-45), then
   `apiguard run -c <copy> --log-level debug`.
3. Check in `outputs/apiguard_report.json` that the test appears with the expected status, findings and oracle
   states, and that FAIL evidence is in `evidence.json`.
4. `hatch run dev:check` (ruff, mypy, bandit, vulture) - see [`coding-rules.md`](coding-rules.md).
5. Write the test page in [`docs/tests/`](../../tests/README.md) and add the row to the catalogue.

## Common errors

| Symptom | Cause |
|---|---|
| Test missing from the report, no error | missing `__init__.py` in a new domain directory; module name not starting with `test_`; a required class attribute missing; or filtered out by `min_priority` / `strategies` / `test_ids` |
| `ImportError` at startup | `RuntimeTest<DN>Config` not exported from `src/core/models/__init__.py` |
| `AttributeError` on `target.tests_config.test_<D>_<N>` | field missing in `RuntimeTestsConfig` or not populated in `engine.py` |
| Pydantic error when building the result | FAIL without findings, PASS with findings, or SKIP without reason |
| FAIL finding without evidence link | `add_fail_evidence()` not called, or `evidence_ref` not set |

## See also

- [`add-an-external-test.md`](add-an-external-test.md) · [`coding-rules.md`](coding-rules.md)
- [`../../architecture/overview.md`](../../architecture/overview.md)

# Add a Native Test

> **Audience:** contributors · **Status:** v0.1.0 · **Source of truth:** `src/core/test_metadata.py` (`TestInfo`),
> `src/core/assessment_test.py`, `src/tests/base.py`, `src/core/test_discovery.py`, `src/engine.py` (Phase 3), the
> existing tests in `src/tests/domain_*/` · **Verified:** 2026-10-05; declaration and discovery 2026-10-16.
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
| 1 | `src/tests/domain_<D>/__init__.py` | new domain | empty file (a test module outside a package stops the run) |
| 2 | `src/tests/domain_<D>/test_<D>_<N>_<name>.py` | always | the test: its declaration (`info`), its parameter model if it has parameters, its code |
| 3 | `docs/tests/<domain>/<test>.md` | always | the test page: its prose, and under the title the two lines of the header marker, copied from any test page (e.g. `docs/tests/domain-1/1-4-token-revocation.md`) with the ID in `test_header("<D>.<N>", page=cog.inFile)` changed |

Then `hatch run dev:gen` writes what repeats the code: the page header, the catalogue row (`docs/tests/README.md`),
the tests by strategy and priority (`docs/architecture/assessment-model.md`), the parameter table
(`docs/reference/configuration.md`) and the parameter block of `config.example.yaml` (`scripts/generate_docs.py`,
written by Cog between markers). `hatch run dev:check` fails when one of them is out of date, showing the
difference, and when a test has no page. Still by hand: the page's prose, the "Test portability" row of
`docs/reference/compatibility.md` (a measurement on the labs) and `docs/project/roadmap.md`.

Nothing else declares a test: no list of tests, no configuration container, no line in `engine.py`. The test is
discovered by its module name, its parameters are checked against the model it declares (the user's keys are
`tests.domain_<D>.test_<D>_<N>.<param>`, derived from the ID), and a mistake in either stops the run at startup with
a message naming the test (verified 2026-10-17).

## 1. Parameters

A test with tunable values declares **one** frozen model in its own module, named `Test<D><N>Params`, with named
constants for defaults and bounds, and names it in its class declaration. See
[data model](../../architecture/data-model.md#test-parameters-declared-by-the-test).

```python
TEST_21_ADMIN_ENDPOINT_METHOD_DEFAULT: str = "GET"


class Test21Params(BaseModel):
    model_config = {"frozen": True, "extra": "forbid"}

    admin_endpoint_paths: tuple[str, ...] = Field(default=(), description="...")
    admin_endpoint_method: str = Field(default=TEST_21_ADMIN_ENDPOINT_METHOD_DEFAULT, description="...")


class Test21RbacEnforcement(BaseTest[Test21Params]):
    ...
    def execute(self, target, context, client, store):
        cfg = self.params(target)            # Test21Params: mypy checks every name
```

- Every field needs a `description`: it is the source of
  [`reference/configuration.md`](../../reference/configuration.md). Its first sentence must stand on its own: the
  generated `config.example.yaml` shows only that, `configuration.md` the whole description.
- A test without parameters writes `class Test03...(BaseTest)` and declares no model; a key under its section is
  rejected as unknown.
- A check of a parameter against the rest of the configuration uses the validation context: test 7.2's model
  checks its templates against `resources` (`PARAMS_CONTEXT_RESOURCES`, `src/core/assessment_test.py`); a parameter
  that names a prepared resource is marked `json_schema_extra=REFERS_TO_RESOURCE`, so that `validate-config`
  lists the test among the resource's users.
- A test reads only its own parameters.

**Naming:** the test ID uses a dot (`"2.1"`); config keys use underscores (`test_2_1`).

## 2. The test module

**File name:** `test_<D>_<N>_<description>.py` in `src/tests/domain_<D>/`. Only modules whose name starts with
`test_` are imported by the registry.

**Imports and constants** (from test 2.1). Status codes, oracle-state labels and references are module constants:

```python
from src.core.client import SecurityClient
from src.core.context import ROLE_USER_A, TargetContext, TestContext
from src.core.evidence import EvidenceStore
from src.core.exceptions import AuthenticationSetupError, SecurityClientError
from src.core.models import Finding, TestResult, TestStrategy
from src.core.test_metadata import TestInfo
from src.tests.base import BaseTest
from src.tests.helpers.auth import acquire_tokens, auth_parts

log: structlog.BoundLogger = structlog.get_logger(__name__)

_RBAC_BYPASS_CODES: frozenset[int] = frozenset(range(200, 300))
_STATE_RBAC_BYPASS: str = "RBAC_BYPASS"
_REFERENCES: list[str] = ["CWE-285", "OWASP-API5:2023", "OWASP-ASVS-v5.0.0-V8.3.1", ...]
```

Allowed imports: `core/`, `src/tests/base.py`, `src/tests/helpers/`, `src/tests/data/`. Never `config/`,
`discovery/`, `report/`, `engine.py`, `connectors/`; never start a subprocess.

**Declaration.** A test declares who it is in one `TestInfo` (`src/core/test_metadata.py`), its `info` class
attribute: ID, name, priority, strategy, CWE, and optionally tags and prerequisites (`depends_on`, `requires_pass`,
empty when omitted). The domain is not written: it is the first number of the ID. The results carry these values
under their report names (`test_id`, `test_name`, `domain`, `cwe_id`).

```python
class Test21RbacEnforcement(BaseTest):
    info = TestInfo(
        id="2.1",
        name="Only Authorized Users Access Privileged Endpoints",
        priority=2,
        strategy=TestStrategy.GREY_BOX,
        cwe="CWE-285",
        tags=("authorization", "rbac", "OWASP-API5:2023", ...),
    )
```

`TestInfo` is checked when the module is imported, and test discovery (`src/core/test_discovery.py`) checks the
rest: an invalid declaration (for example `priority` outside 0-3, an ID not of the form `X.Y`, a CWE not of the
form `CWE-<number>`), a class without `info`, an ID already used by another class, a prerequisite that is not a
test, a class that cannot be instantiated without arguments, or a test module that cannot be imported stops the
run with exit `10` (`TestDefinitionError`), listing every problem with its module; `apiguard validate-config`
reports the same. A helper base class shared by the tests of a module must have a name starting with `_`: it is
not a test and is not checked.

Take the priority from the methodology's severity criteria ([priorities](../../architecture/assessment-model.md#priorities)); set
the strategy from what the tester needs to run it in full, independently of the priority: network only →
`BLACK_BOX`; an ordinary account → `GREY_BOX`; the API's administrator account or internal access (gateway Admin API,
files) → `WHITE_BOX` ([strategies](../../architecture/assessment-model.md#strategies-knowledge-and-privilege-of-the-tester)); `depends_on` lists the tests whose data this test
uses, `requires_pass` the tests that must pass for this test to be meaningful; both `[]` otherwise, and not for
tokens, which `acquire_tokens()` shares ([dependencies between tests](../../architecture/assessment-model.md#dependencies-between-tests)).

**`execute()`** must always return a `TestResult` and never raise. Structure: setup, probes in private helpers,
verdict, and a catch-all:

```python
def execute(self, target: TargetContext, context: TestContext,
            client: SecurityClient, store: EvidenceStore) -> TestResult:
    try:
        # info.needs=(Need.USER_ACCOUNT,) and admin_endpoint_paths NEEDED_TO_RUN:
        # the engine has already recorded SKIP if either is missing.
        try:
            acquire_tokens(target, context, client, required_roles=frozenset({ROLE_USER_A}))
        except (AuthenticationSetupError, SecurityClientError) as exc:
            return self._make_error(exc)

        cfg = self.params(target)
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
user_a_auth = auth_parts(target, context, ROLE_USER_A)   # headers and query parameters
response, record = client.request(
    method=method, path=path, test_id=self.info.id,
    headers=dict(user_a_auth.headers), params=dict(user_a_auth.params) or None,
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

**Result helpers** (`src/core/assessment_test.py`, shared with external tests). They copy the declaration and the
transaction log into the `TestResult`:

<!-- [[[cog import generate_docs as g; cog.out(g.methods_table(('Helper', 'Use'), 'src.core.assessment_test:AssessmentTest._make_pass', 'src.core.assessment_test:AssessmentTest._make_fail', 'src.core.assessment_test:AssessmentTest._make_fail_multi', 'src.core.assessment_test:AssessmentTest._make_skip', 'src.core.assessment_test:AssessmentTest._make_error')) ]]] -->

| Helper | Use |
|---|---|
| `_make_pass(message, notes=None)` | Return a PASS result: the guarantee holds; notes may add context that is not a violation. |
| `_make_fail(message, detail, evidence_record_id=None, additional_references=None, notes=None)` | Return a FAIL result with one finding, titled with the test's name, with its CWE as first reference. |
| `_make_fail_multi(message, findings, notes=None)` | Return a FAIL result with the caller's findings, one per violation (preferred: each finding names the endpoint). |
| `_make_skip(reason, notes=None)` | Return a SKIP result naming the missing precondition. |
| `_make_error(exc, message=None)` | Return an ERROR result from an exception, keeping the transactions logged so far. |

<!-- [[[end]]] -->

**Needs, not guards.** What a test needs from the configuration is declared, not checked in `execute()`:
`TestInfo(needs=(Need.USER_ACCOUNT,))` (the vocabulary is `Need` in `src/core/test_metadata.py`: `ADMIN_ACCOUNT`,
`USER_ACCOUNT`, `GATEWAY`, `REVOCABLE_LOGIN`) and, for a parameter the test cannot run without,
`Field(..., json_schema_extra=NEEDED_TO_RUN)`. The engine records SKIP before `execute()` when one is missing, with
a uniform reason, and warns before the first test (`src/core/test_needs.py`, where a new need is one entry). What
only the target can reveal (no deprecated operation, no session cookie, a gateway that does not support a concept)
stays a SKIP inside the test. `_requires_attack_surface(target)` remains for the attack surface.

**Evidence and audit trail:**

<!-- [[[cog import generate_docs as g; cog.out(g.methods_table(('Call', 'When'), ('self.', 'src.tests.base:BaseTest._log_transaction'), ('store.', 'src.core.evidence:EvidenceStore.add_fail_evidence'), ('store.', 'src.core.evidence:EvidenceStore.pin_evidence'))) ]]] -->

| Call | When |
|---|---|
| `self._log_transaction(record, *, oracle_state=None, is_fail=False, duration_ms=None)` | Add a request to the test's audit trail (transaction_log in the report): call it after every client.request(). |
| `store.add_fail_evidence(record)` | Store a transaction that proves a FAIL in evidence.json; log it with _log_transaction(..., is_fail=True). |
| `store.pin_evidence(record)` | Store in evidence.json a transaction that is key context but proves no FAIL. |

<!-- [[[end]]] -->

Oracle-state labels are free strings in `SCREAMING_SNAKE_CASE`, defined as module constants and documented on the
test page.

**Secrets in the evidence** ([evidence format](../../reference/evidence-format.md#sensitive-data)): tokens stored with
`context.set_token()` are redacted automatically. A secret the test creates or receives (a token it creates, a
generated webhook secret, a Basic `Authorization` value) must be registered right away with
`context.register_secret(value, label)`, before the request that sends it, with a label saying what it is (e.g.
`"7.2 webhook secret"`); it is then replaced with `[REDACTED: <label>]` everywhere. A fixed probe value the test
sends on purpose as `Authorization` (e.g. a malformed token) is not a secret: declare it with
`context.declare_public_value(value)` and it stays readable as `[public probe] <value>`.

**Attack surface** (`target.attack_surface`, check `_requires_attack_surface` first):
`get_authenticated_endpoints()`, `get_public_endpoints()`, `get_deprecated_endpoints()`,
`get_endpoints_by_method(method)`; each `EndpointRecord` has `path`, `method`, `requires_auth`, `is_deprecated`,
`parameters`.

**Helpers** (`src/tests/helpers/`):

| Module | Provides |
|---|---|
| `auth.py` | `acquire_tokens(target, context, client, required_roles=...)`: obtains each role's credential with the method of `credentials.auth_type` (`auth_static.py`: `basic`, `static_token`; `auth_login.py`: `login`, from a prepared resource) and stores it in `TestContext`. `auth_parts(target, context, role)`: the headers and query parameters that carry it, as the run's credential placement says; never write `Authorization: Bearer` in a test. `revocation_capability(target)`: the method when, as configured, it can revoke a credential (test 1.4), else `None` |
| `path_resolver.py` | `resolve_path_with_seed(path, seed, fallback)`, `extract_param_names_from_path(path)`; constants `PATH_PARAM_FALLBACK_DEFAULT` (`"1"`), `PATH_PARAM_FALLBACK_SAFE_DELETE` (`"apiguard-probe"`) |
| `resources.py` | `create_resource(target, context, client, name, role, test_id)`: creates a [prepared resource](../../reference/configuration.md#resources) of `config.yaml` for a role, reads its values, registers its deletion for teardown and the credential as a secret; `delete_resource(...)`: sends its delete request at once. A test that needs an object on the target takes a resource name from its configuration (as 7.2's `url_accepting_endpoint.resource`), never a path written in the code |
| `response_inspector.py` | `contains_stack_trace`, `contains_sensitive_fields`, `extract_debug_fields`, `check_security_headers`, `find_missing_security_headers`, `find_invalid_security_headers`, `find_leaky_headers`, `auth_errors_are_uniform` |

**Payload data** (`src/tests/data/`): `auth_payloads.py`, `inspector_patterns.py`, `shadow_wordlists.py`,
`ssrf_payloads.py`. Put reusable payload lists there, not in the test.

**Gateway configuration** (WHITE_BOX audits): declare `needs=(Need.GATEWAY,)` in `info` (without a gateway the
engine records SKIP before `execute()`), then read the neutral concepts you need (`target.gateway.backend_timeouts()`, `health_checks()`, `signing_policies()`, ...; [add a gateway
adapter](add-a-gateway-adapter.md)). Store each answer with `self._record_gateway_concept(target, store, CONCEPT_...,
answer)` and use the returned id as the findings' `evidence_ref`; when the answer is not READ, return
`self._skip_for_concept(...)`, or add an InfoNote if the test can still judge another part.

**Resources created on the target** must be registered immediately after creation:
`context.register_resource_for_teardown(method, path, headers=None)`. Phase 6 deletes them in reverse order.

## 4. Verify

There is no automated test suite yet (planned: Q-51). Verify against the lab target:

1. `apiguard validate-config` - the declaration and the new parameters load.
2. Run only the new test: in a copy of `config.yaml` set `execution.test_ids: ["<D>.<N>"]`, then
   `apiguard run -c <copy> --log-level debug`.
3. Check in the run's `apiguard_report.json` (`outputs/forgejo/` with the lab configuration) that the test appears with the expected status, findings and oracle
   states, and that FAIL evidence is in `evidence.json`.
4. Write the test page in [`docs/tests/`](../../tests/README.md), then `hatch run dev:gen`.
5. `hatch run dev:check` (ruff, ruff format, mypy, bandit, vulture, lint-imports, the configuration keys, the
   generated documentation) - see [`coding-rules.md`](coding-rules.md).

## Common errors

| Symptom | Cause |
|---|---|
| Test missing from the report, no error | module name not starting with `test_`; class name starting with `_`; or filtered out by `min_priority` / `strategies` / `test_ids` (the report lists the filtered tests under "not run") |
| `Test definitions invalid: ...`, exit 10 | an invalid `info`, a class without `info`, a duplicate ID, an unknown prerequisite, a module that cannot be imported or that is outside a package (the message names the module or class and the field) |
| `tests.domain_<D>.test_<D>_<N>.<param>: unknown key`, exit 10 | a parameter the model does not declare (the closest name is suggested), or a parameter given to a test without a model |
| Pydantic error when building the result | FAIL without findings, PASS with findings, or SKIP without reason |
| FAIL finding without evidence link | `add_fail_evidence()` not called, or `evidence_ref` not set |

## See also

- [`add-an-external-test.md`](add-an-external-test.md) · [`coding-rules.md`](coding-rules.md)
- [`../../architecture/overview.md`](../../architecture/overview.md)

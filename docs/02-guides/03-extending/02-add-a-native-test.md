# Add a Native Test

> **Audience:** contributors · **Status:** v0.1.0 · **Source of truth:** `src/core/test_metadata.py` (`TestInfo`),
> `src/core/assessment_test.py`, `src/tests/base.py`, `src/core/test_discovery.py`, `src/engine.py` (Phase 3), the
> existing tests in `src/tests/domain_*/` · **Verified:** 2026-10-05; declaration and discovery 2026-10-16.
> Snippets are copied from `src/tests/domain_4/test_4_2_timeout_config_audit.py` (parameters) and
> `src/tests/domain_2/test_2_1_function_level_authorization.py` (declaration).
> The previous long version of this guide is in git history (commit `fd3bd90`).

A native test is a Python class that checks one methodology guarantee by sending HTTP requests through the tool's
client. For a test that runs an external binary or library, see
[`add-an-external-test.md`](03-add-an-external-test.md).

Before starting, read the guarantee in [`03-guarantees.md`](../../06-knowledge/03-guarantees.md) and the
tool decision in [`04-tool-decisions.md`](../../06-knowledge/04-tool-decisions.md), and the
[assessment model](../../04-architecture/03-assessment-model.md) (strategy, priority, outcomes).

## Files to touch

| # | File | When | What |
|---|---|---|---|
| 1 | `src/tests/domain_<D>/__init__.py` | new domain | empty file (a test module outside a package stops the run) |
| 2 | `src/tests/domain_<D>/test_<D>_<N>_<name>.py` | always | the test: its declaration (`info`), its parameter model if it has parameters, its code |
| 3 | `docs/05-tests/<domain>/<test>.md` | always | the test page: its prose, and under the title the two lines of the header marker, copied from any test page (e.g. `docs/05-tests/domain-1/1-4-credential-revocation.md`) with the ID in `test_header("<D>.<N>", page=cog.inFile)` changed |

Then `hatch run dev:gen` writes what repeats the code: the page header, the catalogue row (`docs/05-tests/README.md`),
the tests by strategy and priority (`docs/04-architecture/03-assessment-model.md`), the parameter table
(`docs/03-reference/01-configuration.md`) and the parameter block of `config.example.yaml` (`scripts/generate_docs.py`,
written by Cog between markers). `hatch run dev:check` fails when one of them is out of date, showing the
difference, and when a test has no page. Still by hand: the page's prose and the "Test portability" row of
`docs/03-reference/06-compatibility.md` (a measurement on the labs).

Nothing else declares a test: no list of tests, no configuration container, no line in `engine.py`. The test is
discovered by its module name, its parameters are checked against the model it declares (the user's keys are
`tests.domain_<D>.test_<D>_<N>.<param>`, derived from the ID), and a mistake in either stops the run at startup with
a message naming the test (verified 2026-10-17).

## 1. Parameters

A test with tunable values declares **one** frozen model in its own module, named `Test<D><N>Params`, with named
constants for defaults and bounds, and names it in its class declaration. See
[data model](../../04-architecture/02-data-model.md#test-parameters-declared-by-the-test).

```python
TEST_42_MAX_CONNECT_TIMEOUT_MS_DEFAULT: int = 5_000


class Test42Params(BaseModel):
    model_config = {"frozen": True, "extra": "forbid"}

    max_connect_timeout_ms: Annotated[int, Field(ge=1)] = Field(
        default=TEST_42_MAX_CONNECT_TIMEOUT_MS_DEFAULT,
        description=(
            "Maximum acceptable backend connect timeout of a gateway service, in milliseconds. "
            "Methodology oracle: connect_timeout <= 5 000 ms (NIST SP 800-204A Section 4.3). "
            "Services with a higher value will produce a FAIL finding."
        ),
    )


class Test42TimeoutConfigAudit(BaseTest[Test42Params]):
    ...
    def execute(self, target, context, client, store):
        cfg = self.params(target)            # Test42Params: mypy checks every name
```

- Every field needs a `description`: it is the source of
  [`reference/configuration.md`](../../03-reference/01-configuration.md). Its first sentence must stand on its own: the
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
from src.core.context import ROLE_USER_A
from src.core.exceptions import AuthenticationSetupError, SecurityClientError
from src.core.models import (Confidence, Finding, Outcome, Reference, ResponseCategory, Standard,
                             TestResult, TestStrategy)
from src.core.test_metadata import Effect, Need, TestInfo
from src.core.assessment_test import category_of
from src.tests.base import BaseTest
from src.tests.helpers.auth import auth_parts

log: structlog.BoundLogger = structlog.get_logger(__name__)

_REFUSED: frozenset[ResponseCategory] = frozenset(
    {ResponseCategory.FORBIDDEN, ResponseCategory.UNAUTHENTICATED}
)
# Categories that say nothing about the guarantee (rule 1).
_SPOILING: dict[ResponseCategory, str] = {
    ResponseCategory.UPSTREAM_UNAVAILABLE: "UPSTREAM_UNAVAILABLE",
    ResponseCategory.RATE_LIMITED: "RATE_LIMITED",
    ...
}
_SUB_REFUSES: str = "privileged_function_refuses_user"
_REFERENCES: tuple[Reference, ...] = (
    Reference(standard=Standard.OWASP_API_TOP10, id="API5:2023"),
    Reference(standard=Standard.ASVS, id="v5.0.0-8.3.1"),
    ...
)
```

Allowed imports: `core/`, `src/tests/base.py`, `src/tests/helpers/`, `src/tests/data/`. Never `config/`,
`discovery/`, `report/`, `engine.py`, `connectors/`; never start a subprocess.

**Declaration.** A test declares who it is in one `TestInfo` (`src/core/test_metadata.py`), its `info` class
attribute: ID, name, priority, strategy, CWE, and optionally the other standards of the guarantee (`references`), tags
and prerequisites (`depends_on`, `requires_pass`, empty when omitted). Each reference is the standard and the
identifier as that standard writes it, checked against its format ([`Reference`](../../03-reference/04-report-schema.md#reference));
a finding without references of its own cites the test's. Tags are topics only, lowercase words joined by hyphens
(`rate-limit`): a standard written as a tag stops the start. The domain is not written: it is the first number of the ID. The results carry these values
under their report names (`test_id`, `test_name`, `domain`, `cwe_id`).

```python
class Test21FunctionLevelAuthorization(BaseTest):
    info = TestInfo(
        id="2.1",
        name="Function-Level Authorization",
        priority=1,
        strategy=TestStrategy.GREY_BOX,
        cwe="CWE-285",
        references=_REFERENCES,
        tags=("authorization", "bfla"),
        needs=(Need.USER_ACCOUNT,),                   # the engine acquires the account and SKIPs the test without it
        optional_needs=(Need.ADMIN_ACCOUNT,),         # used when configured; its absence does not SKIP the test
        effect=Effect.READ_ONLY,                      # required: READ_ONLY | CHANGES_DATA | STRESSES_TARGET
        sub_tests=(_SUB_REFUSES, _SUB_METHOD),        # required, at least one; every judgement belongs to one
    )
```

`effect` and `sub_tests` are mandatory: `effect` sets the run order (read-only tests first, then the ones that
change data, then the ones that stress the target), and `sub_tests` are the named parts whose per-case outcomes the
status is computed from (`_SUB_REFUSES = "privileged_function_refuses_user"`, `_SUB_METHOD = "method_not_confused"`).
`needs` lets the engine provide a declared account (the test no longer calls `acquire_tokens()` itself) and SKIP the
test when the configuration does not supply it; `optional_needs` declares an account the test uses when it is
configured and does without when it is not.

`TestInfo` is checked when the module is imported, and test discovery (`src/core/test_discovery.py`) checks the
rest: an invalid declaration (for example `priority` outside 0-3, an ID not of the form `X.Y`, a CWE not of the
form `CWE-<number>`), a class without `info`, an ID already used by another class, a prerequisite that is not a
test, a class that cannot be instantiated without arguments, or a test module that cannot be imported stops the
run with exit `10` (`TestDefinitionError`), listing every problem with its module; `apiguard validate-config`
reports the same. A helper base class shared by the tests of a module must have a name starting with `_`: it is
not a test and is not checked.

Take the priority from the methodology's severity criteria ([priorities](../../04-architecture/03-assessment-model.md#priorities)); set
the strategy from what the tester needs to run it in full, independently of the priority: network only →
`BLACK_BOX`; an ordinary account → `GREY_BOX`; the API's administrator account or internal access (gateway Admin API,
files) → `WHITE_BOX` ([strategies](../../04-architecture/03-assessment-model.md#strategies-knowledge-and-privilege-of-the-tester)); `depends_on` lists the tests whose data this test
uses, `requires_pass` the tests that must pass for this test to be meaningful; both `[]` otherwise, and not for
tokens, which `acquire_tokens()` shares ([dependencies between tests](../../04-architecture/03-assessment-model.md#dependencies-between-tests)).

**`execute()`** must always return a `TestResult` and never raise. Structure: setup, probes in private helpers,
verdict, and a catch-all:

```python
def execute(self, target: TargetContext, context: TestContext,
            client: SecurityClient, store: EvidenceStore) -> TestResult:
    try:
        # info.needs=(Need.USER_ACCOUNT,) and admin_endpoint_paths NEEDED_TO_RUN:
        # the engine has already recorded SKIP if either is missing, and has
        # acquired the account; auth_parts() reads its credential.
        user_a = auth_parts(target, context, ROLE_USER_A)
        cfg = self.params(target)
        for path in cfg.admin_endpoint_paths:
            self._probe_admin_endpoint(client, store, user_a, path)
        return self._finish()
    except (AuthenticationSetupError, SecurityClientError) as exc:
        return self._error(exc)
```

`execute()` records a judgement for every case and returns `self._finish()`: it never chooses PASS, FAIL or
INCONCLUSIVE itself, `_finish()` computes the status from the recorded outcomes. A probe that cannot run returns
`self._skip(reason)`; an unexpected error returns `self._error(exc)`.

**A probe**: every request goes through `client.request()`, and `self._judge()` records the outcome, logs the
transaction, and (for a `VIOLATION`) stores the full evidence and points the finding at it (`evidence_ref`) in one
call:

```python
response, record = client.request(
    method=method, path=path, test_id=self.info.id,
    headers=dict(user_a.headers), params=dict(user_a.params) or None,
)
category = category_of(record)               # step 1: the closed list, never a raw status code (rule 1)
if category in _SPOILING:                    # the response says nothing about the guarantee
    self._judge(record, store, _SUB_REFUSES, Outcome.NOT_VERIFIABLE, _SPOILING[category])
elif category in _REFUSED:
    self._judge(record, store, _SUB_REFUSES, Outcome.ENFORCED, "REFUSED")
elif category == ResponseCategory.SERVED:    # step 2: the test's own rule on the category
    self._judge(
        record, store, _SUB_REFUSES, Outcome.VIOLATION, "BFLA",
        Finding(
            title=f"Ordinary user reached a privileged function: {method} {path}",
            detail=(
                f"A request to {method} {path} with the user_a credential answered "
                f"HTTP {record.response_status_code}. This is a privileged operation ({basis}), so "
                "an authenticated but unprivileged user reached a function meant for an "
                "administrator (BFLA, OWASP API5:2023)."
            ),
            # CERTAIN when a positive control confirmed the operation is privileged,
            # FIRM when only the specification says so (rule 6).
            confidence=Confidence.CERTAIN if certain else Confidence.FIRM,
        ),
    )
else:
    self._judge(record, store, _SUB_REFUSES, Outcome.NOT_VERIFIABLE, category.name)
```

The `finding` is given exactly when the outcome is `VIOLATION`; its `evidence_ref` and `supporting_refs` are set by
`_judge()`, not by hand.

## 3. Building blocks

**Result helpers** (`src/core/assessment_test.py`, shared with external tests). A test records judgements and ends
with `_finish()`, which computes the status (it never chooses PASS, FAIL or INCONCLUSIVE) and copies the declaration
and the transaction log into the `TestResult`:

<!-- [[[cog import generate_docs as g; cog.out(g.methods_table(('Helper', 'Use'), 'src.core.assessment_test:AssessmentTest._record', 'src.core.assessment_test:AssessmentTest._finish', 'src.core.assessment_test:AssessmentTest._skip', 'src.core.assessment_test:AssessmentTest._error')) ]]] -->

| Helper | Use |
|---|---|
| `_record(sub_test, outcome, detail, finding=None)` | Record one judgement: the outcome of one case of a declared sub-test. |
| `_finish(notes=None, message=None)` | The result of a test that ran to the end, computed from its judgements. |
| `_skip(reason, notes=None)` | SKIP before the start: something the test needs is missing. |
| `_error(exc, message=None)` | ERROR from an exception, for the except block of a test. |

<!-- [[[end]]] -->

**Needs, not guards.** What a test needs from the configuration is declared, not checked in `execute()`:
`TestInfo(needs=(Need.USER_ACCOUNT,))` (the vocabulary is `Need` in `src/core/test_metadata.py`; every member,
with the tests that depend on it, is in the [assessment model](../../04-architecture/03-assessment-model.md#needs-what-the-configuration-must-hold))
and, for a parameter the test cannot run without,
`Field(..., json_schema_extra=NEEDED_TO_RUN)`. The engine records SKIP before `execute()` when one is missing, with
a uniform reason, and warns before the first test (`src/core/test_needs.py`, where a new need is one entry). What
only the target can reveal (no deprecated operation, no session cookie, a gateway that does not support a concept)
stays a SKIP inside the test. `_requires_attack_surface(target)` remains for the attack surface.

**Evidence and audit trail:**

<!-- [[[cog import generate_docs as g; cog.out(g.methods_table(('Call', 'When'), ('self.', 'src.tests.base:BaseTest._judge'), ('self.', 'src.tests.base:BaseTest._step'), ('store.', 'src.core.evidence:EvidenceStore.pin_evidence'))) ]]] -->

| Call | When |
|---|---|
| `self._judge(record, store, sub_test, outcome, detail, finding=None, *, reference_responses=(), duration_ms=None)` | Judge one HTTP response: log it, record the judgement, keep the proof. |
| `self._step(record, *, duration_ms=None)` | Log a request that is not judged: a preparation step of the test. |
| `store.pin_evidence(record)` | Store in evidence.json a transaction that is key context but proves no FAIL. |

<!-- [[[end]]] -->

Every response is judged (`_judge`) or logged as a preparation step (`_step`). A judgement is an outcome
(`VIOLATION`, `ENFORCED`, `NOT_VERIFIABLE`, `NOT_APPLICABLE`) with the test's detail in `UPPER_SNAKE_CASE`, read as
`VIOLATION/SERVED_WITHOUT_CREDENTIAL`; the category of the response comes from `category_of(record)` (`src/tests/base.py`). The
test page documents the oracle table.

**Secrets in the evidence** ([evidence format](../../03-reference/05-evidence-format.md#sensitive-data)): tokens stored with
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
| `resources.py` | `create_resource(target, context, client, name, role, test_id)`: creates a [prepared resource](../../03-reference/01-configuration.md#resources) of `config.yaml` for a role, reads its values, registers its deletion for teardown and the credential as a secret; `delete_resource(...)`: sends its delete request at once. A test that needs an object on the target takes a resource name from its configuration (as 7.2's `url_accepting_endpoint.resource`), never a path written in the code |
| `response_inspector.py` | `contains_stack_trace`, `contains_sensitive_fields`, `extract_debug_fields`, `check_security_headers`, `find_missing_security_headers`, `find_invalid_security_headers`, `find_leaky_headers`, `auth_errors_are_uniform` |

**Payload data** (`src/tests/data/`): `auth_payloads.py`, `inspector_patterns.py`, `shadow_wordlists.py`,
`ssrf_payloads.py`. Put reusable payload lists there, not in the test.

**Gateway configuration** (WHITE_BOX audits): declare `needs=(Need.GATEWAY,)` in `info` (without a gateway the
engine records SKIP before `execute()`), then read the neutral concepts you need (`target.gateway.backend_timeouts()`, `health_checks()`, `signing_policies()`, ...; [add a gateway
adapter](04-add-a-gateway-adapter.md)). Store each answer with `self._record_gateway_concept(target, store, CONCEPT_...,
answer)` and use the returned id as the findings' `evidence_ref`; when the answer is not READ, return
`self._skip_for_concept(...)`, or add an InfoNote if the test can still judge another part.

**Resources created on the target** must be registered immediately after creation:
`context.register_resource_for_teardown(method, path, headers=None)`. Phase 6 deletes them in reverse order.

## 4. Verify

There is no automated test suite. Verify against the lab target:

1. `apiguard validate-config` - the declaration and the new parameters load.
2. Run only the new test: in a copy of `config.yaml` set `execution.test_ids: ["<D>.<N>"]`, then
   `apiguard run -c <copy> --log-level debug`.
3. Check in the run's `apiguard_report.json` (`outputs/forgejo/` with the lab configuration) that the test appears with the expected status, findings and oracle
   states, and that FAIL evidence is in `evidence.json`.
4. Write the test page in [`docs/05-tests/`](../../05-tests/README.md), then `hatch run dev:gen`.
5. `hatch run dev:check` (ruff, ruff format, mypy, bandit, vulture, lint-imports, the configuration keys, the
   generated documentation) - see [`coding-rules.md`](01-coding-rules.md).

## Common errors

| Symptom | Cause |
|---|---|
| Test missing from the report, no error | module name not starting with `test_`; class name starting with `_`; or filtered out by `min_priority` / `strategies` / `test_ids` (the report lists the filtered tests under "not run") |
| `Test definitions invalid: ...`, exit 10 | an invalid `info`, a class without `info`, a duplicate ID, an unknown prerequisite, a module that cannot be imported or that is outside a package (the message names the module or class and the field) |
| `tests.domain_<D>.test_<D>_<N>.<param>: unknown key`, exit 10 | a parameter the model does not declare (the closest name is suggested), or a parameter given to a test without a model |
| Pydantic error when building the result | FAIL without findings, PASS with findings, or SKIP without reason |
| FAIL finding without evidence link | `add_fail_evidence()` not called, or `evidence_ref` not set |

## See also

- [`add-an-external-test.md`](03-add-an-external-test.md) · [`coding-rules.md`](01-coding-rules.md)
- [`../../architecture/overview.md`](../../04-architecture/01-overview.md)

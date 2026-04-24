# Developer Guide — Adding a New Test

**Source of truth:** every pattern in this document was extracted directly
from the five tests verified OK against a live target: `1.1`, `4.1`, `4.2`,
`4.3`, `6.2`. Code excerpts are copied verbatim from those files.
Do not invent patterns not present here.

**Read this document top to bottom before writing a single line of code.**
Every step is mandatory. Skipping one produces a runtime error or a
silently broken report. The consequences of each mistake are stated
inline — not only in the Common Errors table at the end.

---

## Which steps apply to your case

| Situation | Required steps |
|---|---|
| New test in an **existing** domain | 1 (extend existing file), 4, 5, 6, 8, 9 |
| New test in a **new** domain | 1 (new file), 2, 3, 4, 5, 6, 7, 8, 9 |

Steps 2, 3, and 7 are only needed when a brand-new `domain_N.py` config file
and `domain_N/` test directory are created. If the domain already has a
`src/config/schema/domain_N.py` and a `src/tests/domain_N/` directory,
add the new config class and field inside the existing schema file (Step 1,
extension mode) and proceed from Step 4.

---

## The 8-file pipeline (9 files for a new domain)

```
1. src/config/schema/domain_N.py          ← operator-tunable parameters (Pydantic, frozen)
2. src/config/schema/tests_config.py      ← wire domain config into TestsConfig aggregator
3. src/config/schema/__init__.py          ← export new symbols from the schema package
4. src/core/models/runtime.py             ← immutable runtime mirror of the config
5. src/core/models/__init__.py            ← export RuntimeTestNNConfig (3 places)
6. src/engine.py                          ← populate RuntimeTestNNConfig in Phase 3
7. src/tests/domain_N/__init__.py         ← empty file; required for pkgutil discovery (NEW DOMAIN ONLY)
8. src/tests/domain_N/test_N_N_name.py   ← the actual test implementation
9. config.yaml                            ← operator-facing defaults
```

Steps 3 and 5 are the most commonly missed because they are pure bookkeeping
with no logic: both produce `ImportError` at startup with no obvious pointer
to the missing line. Step 7 (`__init__.py`) is missed only for new domains,
but its failure mode is the most dangerous: no error is raised, the test file
is simply never discovered, and the pipeline reports zero tests found in that
domain with no diagnostic message. This guide marks Steps 3 and 5 with a
**[CRITICAL — missed most often]** header and Step 7 with a
**[CRITICAL — silent failure]** header.

---

## Why two config layers? (read this before Step 1)

The pipeline separates config loading (`src/config/schema/`) from runtime
consumption (`src/core/models/runtime.py`). The reason is the immutability
invariant on `TargetContext`: the context is frozen by Pydantic before any
test runs. If tests accessed the raw `ToolConfig` Pydantic model directly,
any future change to the YAML schema would silently break every test that
reads those fields. The `RuntimeTest*Config` mirror decouples the two: the
loader owns the YAML schema, the runtime model owns what tests can access.
`engine.py` bridges them in `_phase_3_build_contexts()` by copying every
field explicitly.

---

## Step 1 — `src/config/schema/domain_N.py`

**New domain:** create the file.
**Existing domain:** add a config class and one field to the existing
`TestDomainNConfig` aggregator.

Canonical reference: `src/config/schema/domain_6.py` (Test 6.2).

```python
# src/config/schema/domain_N.py
"""
src/config/schema/domain_N.py

Pydantic v2 configuration models for Domain N (...) tests.

Adding a new Domain N test requires:
    1. Defining a TestNXConfig model in this file.
    2. Adding a field to TestDomainNConfig below.
    3. Adding a RuntimeTestNXConfig mirror in core/models/runtime.py.
    4. Adding the population line in engine.py Phase 3.
    5. Adding the tests.domain_N.test_N_X block to config.yaml.

Dependency rule: imports only from pydantic and the stdlib.
"""

from __future__ import annotations

from typing import Annotated

from pydantic import BaseModel, Field

# ---------------------------------------------------------------------------
# Constants — named, never inline
# ---------------------------------------------------------------------------

TEST_N2_SOME_THRESHOLD_DEFAULT: int = 10
TEST_N2_SOME_THRESHOLD_MIN: int = 1


# ---------------------------------------------------------------------------
# Per-test config model
# ---------------------------------------------------------------------------


class TestN2Config(BaseModel):
    """
    Tuning parameters for Test N.2 (Short Description).

    Cite the methodology section and the standard (ASVS VX.Y, NIST SP ...,
    RFC ...) that justifies each default value.
    """

    model_config = {"frozen": True}

    some_threshold: Annotated[
        int,
        Field(ge=TEST_N2_SOME_THRESHOLD_MIN),
    ] = Field(
        default=TEST_N2_SOME_THRESHOLD_DEFAULT,
        description=(
            "Description citing the standard that justifies this default. "
            f"Default: {TEST_N2_SOME_THRESHOLD_DEFAULT}."
        ),
    )


# ---------------------------------------------------------------------------
# Domain-level aggregator — one field per implemented test
# ---------------------------------------------------------------------------


class TestDomainNConfig(BaseModel):
    """
    Aggregator for all Domain N (...) test configs.

    tests_config.py imports only this class. default_factory on each field
    makes the entire block optional in config.yaml.
    """

    model_config = {"frozen": True}

    test_n_2: TestN2Config = Field(
        default_factory=TestN2Config,
        description=(
            "Tuning parameters for Test N.2 (Short Description). "
            "Maps to 'tests.domain_N.test_N_2' in config.yaml."
        ),
    )
```

**Rules:**
- All models `frozen=True`. This is not optional: `TargetContext` must be
  fully immutable. A mutable config model inside a frozen context breaks the
  immutability guarantee silently (Pydantic does not recursively enforce
  `frozen` across nested models).
- All defaults and bounds are named module-level constants — no inline literals.
- `default_factory=TestN2Config` on the aggregator makes the `config.yaml`
  block optional; the defaults defined in the model are used when the block
  is absent.

---

## Step 2 — `src/config/schema/tests_config.py`  *(new domain only)*

Two places in the file:

```python
# 1. Import at top:
from src.config.schema.domain_N import TestDomainNConfig

# 2. Field inside TestsConfig:
class TestsConfig(BaseModel):
    model_config = {"frozen": True}

    # ... existing fields ...
    domain_N: TestDomainNConfig = Field(
        default_factory=TestDomainNConfig,
        description="Tuning parameters for Domain N (...) tests.",
    )
```

---

## Step 3 — `src/config/schema/__init__.py`  *(new domain only)*  [CRITICAL — missed most often]

Three places in the file. All three must be present or `ImportError` is
raised at startup. The symptom is `ImportError: cannot import name
'TestDomainNConfig' from 'src.config.schema'` — nothing in the traceback
points to this file.

```python
# 1. Docstring inventory at top (keep alphabetical):
#     domain_N.py         TestN2Config, TestDomainNConfig

# 2. Import block:
from src.config.schema.domain_N import TestN2Config, TestDomainNConfig

# 3. __all__ list:
__all__ = [
    # ... existing ...
    "TestN2Config",
    "TestDomainNConfig",
]
```

**Known debt:** `domain_6.py` is currently missing from
`config/schema/__init__.py`. The code works at runtime because
`tests_config.py` and `engine.py` both import from `domain_6` directly,
bypassing the facade — so the incomplete facade is never hit by any
existing consumer. **Do not replicate this debt.** Complete all three
places in Step 3 for every new domain. An incomplete facade breaks
external consumers (future CLI extensions, test harnesses, any module
that imports from `src.config.schema` without knowing the internal
layout) and introduces a maintenance trap where the package's public
API is silently out of sync with its contents.

---

## Step 4 — `src/core/models/runtime.py`

Add one `RuntimeTestN2Config` class and one field to `RuntimeTestsConfig`.
Place the new class after the last existing `RuntimeTest*Config` block,
before `RuntimeTestsConfig`.

**Both the per-test class and the field in the aggregator must be
`frozen=True`. This is how TargetContext enforces full immutability.**

```python
# ---------------------------------------------------------------------------
# RuntimeTestN2Config — runtime parameters for Test N.2
# ---------------------------------------------------------------------------


class RuntimeTestN2Config(BaseModel):
    """
    Runtime mirror of TestN2Config fields consumed by Test N.2.

    Populated by engine.py Phase 3 from config.tests.domain_N.test_N_2.
    Access pattern inside the test:
        cfg = target.tests_config.test_n_2
        cfg.some_threshold
    """

    model_config = {"frozen": True}   # mandatory — see "Why two layers?" above

    some_threshold: int = Field(
        default=10,
        ge=1,
        description="Mirrors TestN2Config.some_threshold. Default: 10.",
    )
```

Then extend `RuntimeTestsConfig`:

```python
class RuntimeTestsConfig(BaseModel):
    model_config = {"frozen": True}

    # ... existing fields ...
    test_n_2: RuntimeTestN2Config = Field(
        default_factory=RuntimeTestN2Config,
        description=(
            "Runtime parameters for Test N.2 (Short Description). "
            "Mirrors TestN2Config from config.tests.domain_N.test_N_2."
        ),
    )
```

**Naming rule — test_id vs field name:**
The `test_id` ClassVar (e.g. `"N.2"`) uses a dot separator and is the
DAG key and the report identifier. The Pydantic field name (e.g.
`test_n_2`) uses an underscore separator to comply with Python attribute
naming. These are two different things. Writing `test_id = "N_2"` (with
underscore) silently breaks the DAG and produces wrong report entries —
the DAG lookup fails to match `depends_on` references that use the dot
form. Always use the dot form for `test_id`, the underscore form for
field names.

The field name `test_X_Y` must exactly match the key used in `engine.py`
and the access path inside the test (`target.tests_config.test_X_Y`).

---

## Step 5 — `src/core/models/__init__.py`  [CRITICAL — missed most often]

Three places in the file. The symptom of a missing entry is `ImportError:
cannot import name 'RuntimeTestN2Config'` at startup — nothing in the
traceback points here.

```python
# 1. Docstring inventory (runtime.py section — add RuntimeTestN2Config):
#    runtime.py      RuntimeCredentials,
#                    RuntimeTest11Config,
#                    RuntimeTest41Config, RuntimeTest42Config, RuntimeTest43Config,
#                    RuntimeTest62Config,
#                    RuntimeTestN2Config,    # ← add here
#                    RuntimeTestsConfig

# 2. Import block:
from src.core.models.runtime import (
    RuntimeCredentials,
    RuntimeTest11Config,
    RuntimeTest41Config,
    RuntimeTest42Config,
    RuntimeTest43Config,
    RuntimeTest62Config,
    RuntimeTestN2Config,    # ← add here
    RuntimeTestsConfig,
)

# 3. __all__ list:
    "RuntimeTestN2Config",  # ← add here
```

---

## Step 6 — `src/engine.py`

Two places in the file.

```python
# 1. Import block at top (inside the existing from src.core.models import):
from src.core.models import (
    # ... existing ...
    RuntimeTestN2Config,    # ← add here
    RuntimeTestsConfig,
)

# 2. Population inside RuntimeTestsConfig(...) in _phase_3_build_contexts():
tests_config = RuntimeTestsConfig(
    # ... existing entries ...
    test_n_2=RuntimeTestN2Config(
        some_threshold=config.tests.domain_N.test_n_2.some_threshold,
    ),
)
```

**Rule:** copy every field explicitly. Never use `model_dump()` or `**kwargs`
to pass config values. Explicit field copying makes the mapping visible and
statically verifiable.

---

## Step 7 — `src/tests/domain_N/__init__.py`  *(new domain only)*  [CRITICAL — silent failure]

Create an empty `__init__.py` in the new domain directory:

```
src/tests/domain_N/__init__.py
```

The file must exist and must be empty (no imports, no content). Its only
purpose is to make the directory a proper Python package so that
`pkgutil.walk_packages` — used by `TestRegistry` during Phase R1 — can
recursively traverse it and discover test modules inside.

**Why this is the most dangerous omission:** unlike Steps 3 and 5, which
raise `ImportError` at startup with a clear message, a missing `__init__.py`
produces no error at all. `pkgutil.walk_packages` silently skips directories
it cannot walk as packages, `TestRegistry` logs nothing, and the pipeline
continues normally — discovering and running zero tests from that domain.
The only symptom is that the new test never appears in the report.

**Verification:** after creating the file, run:

```bash
python -c "
import pkgutil, importlib
pkg = importlib.import_module('src.tests')
names = [m.name for m in pkgutil.walk_packages(pkg.__path__, prefix='src.tests.')]
print([n for n in names if 'domain_N' in n])
"
```

If the output includes your new test module name, the `__init__.py` is in place
and the directory is discoverable. An empty output means the file is missing
or in the wrong location.

---

## Step 8 — `src/tests/domain_N/test_N_N_name.py`

### Filename convention (mandatory for TestRegistry discovery)

```
src/tests/domain_N/test_N_M_description.py
```

`N` = domain number (0–7), `M` = test number within the domain,
`description` = `snake_case`. A file that does not match this pattern is
silently ignored by `TestRegistry` — no warning is emitted.

---

### Module docstring

Every test file opens with a module-level docstring that documents:
- The guarantee being verified (reference to `3_TOP_metodologia.md` section).
- The strategy and its justification.
- The priority level.
- Sub-tests and their oracles.
- The `EvidenceStore` policy (see the `oracle_state` section below for
  the vocabulary to use).

This docstring is the primary source of truth for anyone reading the test
in isolation. Do not omit it.

---

### Canonical import block

Every test file starts with this exact structure. The base block is always
present; add only the helpers your strategy requires.

```python
# ── always present ────────────────────────────────────────────────────────
from __future__ import annotations

from typing import ClassVar        # always needed for ClassVar attributes
# import re, time, secrets, ...   # stdlib only if used by test logic

import structlog

from src.core.client import SecurityClient
from src.core.context import TargetContext, TestContext
from src.core.evidence import EvidenceStore
from src.core.models import (
    Finding,        # always needed for Finding(...)
    TestResult,     # always needed (return type of execute)
    TestStatus,     # needed for manual TestResult(status=TestStatus.FAIL, ...)
    TestStrategy,   # needed for ClassVar[TestStrategy] attribute
    # Add as needed:
    # EndpointRecord  — when iterating AttackSurface endpoints
    # EvidenceRecord  — when type-annotating the record from client.request()
    # InfoNote        — when _make_pass(notes=[InfoNote(...)]) is used
)
from src.tests.base import BaseTest

# ── BLACK_BOX (P0) — no additional imports needed ─────────────────────────
# SecurityClientError is NOT imported here. client.request() can raise it on
# non-recoverable transport failure, but in BLACK_BOX tests it is intentionally
# caught by the outermost `except Exception as exc: return self._make_error(exc)`.
# Do not add an explicit SecurityClientError import or catch to BLACK_BOX tests:
# it would be redundant and inconsistent with all existing BLACK_BOX implementations.

# ── GREY_BOX (P1/P2) — add when test acquires or uses tokens ──────────────
# from src.core.context import ROLE_ADMIN, ROLE_USER_A, ROLE_USER_B
# from src.core.exceptions import AuthenticationSetupError, SecurityClientError
# from src.tests.helpers.auth import acquire_all_tokens_if_needed

# ── WHITE_BOX without Admin API (P3, header/response audit) ───────────────
# No extra imports beyond response_inspector if needed.
# Example: from src.tests.helpers.response_inspector import find_missing_security_headers

# ── WHITE_BOX with Kong Admin API (P1/P3, config audit) ───────────────────
# from src.tests.helpers.kong_admin import KongAdminError, get_services
# (replace get_services with get_routes, get_plugins, get_upstreams as needed)

# ── GREY_BOX tests creating persistent resources (BOLA, RBAC) ─────────────
# from src.tests.helpers.forgejo_resources import (
#     ForgejoResourceError,
#     create_repository,
#     create_issue,
# )

# ── module-level logger — mandatory in every test file ────────────────────
log: structlog.BoundLogger = structlog.get_logger(__name__)
```

---

### Module-level constants (before the class)

All string literals, integer thresholds, status code sets, and reference
lists used inside the test logic must be named module-level constants.
Never inline raw values in the class body or in `execute()`.

```python
# ---------------------------------------------------------------------------
# Module-level constants
# ---------------------------------------------------------------------------

# Oracle HTTP status codes (example from test 1.1).
_ENFORCED_STATUS_CODES: frozenset[int] = frozenset({401, 403})
_BYPASS_STATUS_CODES:   frozenset[int] = frozenset(range(200, 300))

# Oracle state labels — free-form strings used in _log_transaction() calls.
# They appear verbatim in the HTML report's Audit Trail column under "State".
# Use SCREAMING_SNAKE_CASE, be specific, be consistent within a test.
# Examples drawn from existing tests:
_STATE_ENFORCED: str = "AUTH_ENFORCED"    # test 1.1
_STATE_BYPASS:   str = "AUTH_BYPASS"     # test 1.1
_STATE_PASS:     str = "TIMEOUT_OK"      # hypothetical timeout test
_STATE_FAIL:     str = "TIMEOUT_EXCEEDS_ORACLE"

# References cited in every Finding this test produces.
_REFERENCES: list[str] = [
    "OWASP-API2:2023",
    "NIST-SP-800-63B-4-S4.3.1",
    "OWASP-ASVS-V6.3",
]
```

**On `oracle_state`:** `_log_transaction(record, oracle_state=...)` accepts
any string. It is stored in `TransactionSummary.oracle_state` and rendered
verbatim in the HTML Audit Trail column. It has no effect on the test
status or exit code — its purpose is diagnostic context for the analyst.
Define all state strings as module-level constants (not inline literals)
so that the Audit Trail column is consistent throughout the test.

---

### 8 mandatory ClassVar attributes

```python
class TestN2ShortDescription(BaseTest):
    test_id:    ClassVar[str]          = "N.2"     # dot separator — DAG key and report ID
    test_name:  ClassVar[str]          = "Full Guarantee Name From Methodology"
    priority:   ClassVar[int]          = 2         # 0=P0, 1=P1, 2=P2, 3=P3
    domain:     ClassVar[int]          = N
    strategy:   ClassVar[TestStrategy] = TestStrategy.GREY_BOX
    depends_on: ClassVar[list[str]]    = []        # exact test_id strings (dot form)
    tags:       ClassVar[list[str]]    = ["tag", "OWASP-APIX:2023"]
    cwe_id:     ClassVar[str]          = "CWE-XXX"
```

Verify `test_id` is unique across all existing tests before declaring it.
A duplicate `test_id` silently breaks the DAG (dependency resolution fails)
and the HTML report (two rows share the same ID with undefined ordering).

---

### `_transaction_log` — what it is and how it works

`self._transaction_log` is a `list[TransactionSummary]` defined in
`BaseTest.__init__`. It is populated automatically every time you call
`self._log_transaction(record, oracle_state=...)`. You do not append to it
directly. You do not create `TransactionSummary` objects directly.

The list is consumed in two ways:
1. `_make_pass()`, `_make_skip()`, `_make_error()` all call
   `list(self._transaction_log)` internally — you do not pass it.
2. When building a manual `TestResult` (multi-finding FAIL), you must
   include `transaction_log=list(self._transaction_log)` explicitly —
   those helpers are not called in that path.

If you omit `transaction_log=list(self._transaction_log)` from a manual
`TestResult`, the HTML Audit Trail for that test is empty. The test still
runs and the finding is recorded, but no HTTP transaction history appears
in the report.

---

### Canonical entry patterns for `execute()`

Choose the pattern that matches the test's `strategy`. Copy it verbatim,
then add the test logic inside it.

---

#### BLACK_BOX — no credentials (real code from test 1.1)

```python
def execute(
    self,
    target: TargetContext,
    context: TestContext,
    client: SecurityClient,
    store: EvidenceStore,
) -> TestResult:
    """
    Verify that all documented protected endpoints enforce authentication.

    Oracle: every unauthenticated request to a protected endpoint must
    receive 401 or 403. A 2xx response is a BYPASS finding.
    Returns SKIP if the spec declares no protected endpoints.
    """
    try:
        # Guard: requires an AttackSurface to be available.
        # Returns SKIP if target.attack_surface is None.
        skip = self._requires_attack_surface(target)
        if skip is not None:
            return skip

        surface = target.attack_surface
        protected = surface.get_authenticated_endpoints()
        if not protected:
            return self._make_skip(
                reason=(
                    "No endpoints with security requirements found in the "
                    "OpenAPI spec. Nothing to probe for authentication enforcement."
                )
            )

        cfg = target.tests_config.test_1_1
        findings: list[Finding] = []

        for endpoint in protected:
            response, record = client.request(
                method=endpoint.method,
                path=endpoint.path,
                test_id=self.test_id,
                # No Authorization header — unauthenticated probe.
            )

            if response.status_code in _BYPASS_STATUS_CODES:
                store.add_fail_evidence(record)
                self._log_transaction(record, oracle_state=_STATE_BYPASS, is_fail=True)
                findings.append(
                    Finding(
                        title=f"Authentication Bypass: {endpoint.method} {endpoint.path}",
                        detail=(
                            f"Sent {endpoint.method} {endpoint.path} with no "
                            f"Authorization header. Expected 401 or 403. "
                            f"Received {response.status_code}."
                        ),
                        references=_REFERENCES,
                        evidence_ref=record.record_id,
                    )
                )
            else:
                self._log_transaction(record, oracle_state=_STATE_ENFORCED)

        if findings:
            return TestResult(
                test_id=self.test_id,
                status=TestStatus.FAIL,
                message=f"{len(findings)} authentication bypass(es) detected.",
                findings=findings,
                transaction_log=list(self._transaction_log),
                **self._metadata_kwargs(),
            )

        return self._make_pass(
            message=f"All {len(protected)} protected endpoint(s) enforce authentication."
        )

    except Exception as exc:  # noqa: BLE001
        return self._make_error(exc)
```

---

#### GREY_BOX — test acquires and uses tokens

```python
def execute(
    self,
    target: TargetContext,
    context: TestContext,
    client: SecurityClient,
    store: EvidenceStore,
) -> TestResult:
    """One-sentence summary. Oracle and PASS/FAIL/SKIP/ERROR semantics."""
    try:
        # Guard: returns SKIP if no credentials are configured.
        guard = self._requires_grey_box_credentials(target)
        if guard is not None:
            return guard

        # Acquire tokens for all configured roles into TestContext.
        # Safe to call multiple times — skips roles already tokenised.
        try:
            acquire_all_tokens_if_needed(target, context, client)
        except (AuthenticationSetupError, SecurityClientError) as exc:
            return self._make_error(exc)

        # Guard: ensure the specific role this test needs has a live token.
        # Call AFTER acquire_all_tokens_if_needed, never before.
        skip = self._requires_token(context, ROLE_USER_A)
        if skip is not None:
            return skip

        token = context.get_token(ROLE_USER_A)
        cfg = target.tests_config.test_n_2

        response, record = client.request(
            method="GET",
            path="/api/v1/resource",
            test_id=self.test_id,
            headers={"Authorization": f"Bearer {token}"},
        )

        if response.status_code in _BYPASS_STATUS_CODES:
            store.add_fail_evidence(record)
            self._log_transaction(record, oracle_state=_STATE_FAIL, is_fail=True)
            return self._make_fail(
                message="One-line summary of the violated guarantee.",
                detail=(
                    f"Sent GET /api/v1/resource with {ROLE_USER_A} token. "
                    f"Expected 403. Received {response.status_code}."
                ),
                evidence_record_id=record.record_id,
                additional_references=_REFERENCES,
            )

        self._log_transaction(record, oracle_state=_STATE_PASS)
        return self._make_pass(message="Access correctly denied.")

    except Exception as exc:  # noqa: BLE001
        return self._make_error(exc)
```

---

#### WHITE_BOX with Kong Admin API (real code from test 4.2)

```python
def execute(
    self,
    target: TargetContext,
    context: TestContext,
    client: SecurityClient,
    store: EvidenceStore,
) -> TestResult:
    """
    Audit Kong service timeout configuration via the Admin API.

    No HTTP requests are made to the target API. No _log_transaction()
    calls are needed because there are no EvidenceRecord objects.
    Returns PASS, FAIL, SKIP, or ERROR.
    """
    try:
        skip_guard = self._requires_admin_api(target)
        if skip_guard is not None:
            return skip_guard

        admin_base_url = target.admin_endpoint_base_url()
        # admin_endpoint_base_url() returns None only when admin_api_url is None,
        # already caught by _requires_admin_api() above.
        # The assertion keeps mypy and static analysis happy.
        assert admin_base_url is not None, (  # noqa: S101
            "admin_endpoint_base_url() returned None despite admin_api_available=True. "
            "TargetContext invariant violation."
        )

        cfg = target.tests_config.test_4_2

        log.info(
            "test_4_2_starting",
            admin_base_url=admin_base_url,
            max_connect_timeout_ms=cfg.max_connect_timeout_ms,
        )

        # Wrap every kong_admin call in a helper that returns None on KongAdminError.
        services = self._fetch_services(admin_base_url)
        if services is None:
            return self._make_error(
                RuntimeError(
                    "Kong Admin API call failed -- see structured log for details."
                )
            )

        if not services:
            return self._make_skip(
                reason="No Kong services registered. Nothing to audit."
            )

        findings = self._audit_service_timeouts(services, cfg)

        if findings:
            return TestResult(
                test_id=self.test_id,
                status=TestStatus.FAIL,
                message=f"Timeout audit found {len(findings)} violation(s).",
                findings=findings,
                transaction_log=list(self._transaction_log),
                **self._metadata_kwargs(),
            )

        return self._make_pass(
            message=f"All {len(services)} Kong service(s) have compliant timeout configuration."
        )

    except Exception as exc:  # noqa: BLE001
        log.exception("test_n_2_unexpected_error", error=str(exc))
        return self._make_error(exc)


def _fetch_services(self, admin_base_url: str) -> list[dict[str, Any]] | None:
    """
    Retrieve items from Kong Admin API.

    Returns None on KongAdminError so the caller can produce ERROR
    without catching the exception again.
    """
    try:
        return get_services(admin_base_url)
    except KongAdminError as exc:
        log.error(
            "test_n_2_admin_api_error",
            path="/services",
            status_code=exc.status_code,
            error=str(exc),
        )
        return None
```

**Note on `_log_transaction()` in config-audit tests:** config-audit tests
(4.2, 4.3, partially 6.2) call Kong Admin API helpers that use their own
internal HTTP client. No `EvidenceRecord` is produced by those calls, so
`_log_transaction()` is never called. `transaction_log=list(self._transaction_log)`
will be an empty list in the manual `TestResult` — this is correct and
expected. The Audit Trail in the report for these tests is intentionally
empty.

---

### Iterating the AttackSurface

When a test needs to iterate over endpoints from the OpenAPI spec, use
the `AttackSurface` filter methods. The available surface query methods
(from `src/core/models.py`) are:

```python
surface = target.attack_surface   # AttackSurface | None
# Always guard with _requires_attack_surface(target) before accessing.

# All endpoints with at least one security requirement:
protected: list[EndpointRecord] = surface.get_authenticated_endpoints()

# All publicly accessible endpoints (no security requirement):
public: list[EndpointRecord] = surface.get_public_endpoints()

# All endpoints marked deprecated in the spec:
deprecated: list[EndpointRecord] = surface.get_deprecated_endpoints()

# Endpoints accepting a specific HTTP method:
get_endpoints: list[EndpointRecord] = surface.get_endpoints_by_method("GET")

# Endpoints with at least one path parameter (e.g. /users/{id}):
parametric: list[EndpointRecord] = surface.get_endpoints_with_path_parameters()

# Exact lookup by path and method (returns None if not found):
ep: EndpointRecord | None = surface.find_endpoint("/api/v1/users", "GET")
```

`EndpointRecord` fields used by most tests:

```python
ep.path          # str: '/api/v1/users/{id}' — may contain {param} templates
ep.method        # str: 'GET', 'POST', ... always uppercase
ep.requires_auth # bool: True if the spec declares a security requirement
ep.is_deprecated # bool: True if the spec marks it deprecated
ep.parameters    # list[ParameterInfo]: path, query, header params
```

When a path contains `{param}` templates, resolve them before sending the
request with:

```python
from src.tests.helpers.path_resolver import resolve_path_with_seed
concrete_path = resolve_path_with_seed(endpoint, seed)
```

See `src/tests/domain_1/test_1_1_authentication_required.py` for the
complete method-safety matrix that governs unauthenticated probes of
parametric paths.

---

### Building a result — four cases

#### PASS

```python
return self._make_pass(message="All checks passed. Describe what was verified.")
```

With informational notes (not findings — use only when a contextual
architectural observation must appear in the report alongside a PASS):

```python
from src.core.models import InfoNote

return self._make_pass(
    message="Circuit breaker compensating control detected.",
    notes=[
        InfoNote(
            title="Compensating Control: Upstream Passive Health Check",
            detail=(
                "Kong's passive health check is active (unhealthy_threshold=5). "
                "This is functionally equivalent to a circuit breaker for most "
                "traffic patterns but does not support Half-Open probing. "
                "See OWASP ASVS v5.0.0 V16.5.2 for full requirements."
            ),
            references=["OWASP-ASVS-v5.0.0-V16.5.2"],
        )
    ],
)
```

**`InfoNote` vs `Finding`:** a `Finding` documents a security guarantee
violation and is attached only to FAIL results. An `InfoNote` documents
architectural context or compensating controls on a PASS result. `InfoNote`
objects are rendered in blue in the HTML report; `Finding` objects in red.
`InfoNote` objects are NOT counted in the finding totals and do NOT affect
the exit code. Use `InfoNote` only when the test PASSES but contextual
information is genuinely useful for an analyst reading the report.

---

#### FAIL — single finding

```python
# Always store and log BEFORE calling _make_fail.
store.add_fail_evidence(record)
self._log_transaction(record, oracle_state=_STATE_FAIL, is_fail=True)

return self._make_fail(
    message="One-line summary of the violated guarantee.",
    detail=(
        "Technical detail: what was sent, what was received, "
        "what the correct behaviour should have been."
    ),
    evidence_record_id=record.record_id,
    additional_references=["OWASP-API2:2023"],
)
```

For config-audit findings (no HTTP record exists), use `evidence_record_id=None`:

```python
return self._make_fail(
    message="Timeout not configured on service 'forgejo'.",
    detail="connect_timeout == 0 on Kong service 'forgejo'. Oracle: must be > 0 and <= 5000 ms.",
    evidence_record_id=None,
    additional_references=_REFERENCES,
)
```

**`_make_fail()` sets `Finding.title` automatically to `self.test_name`.** There is
no `title` parameter. This is why `test_name` must be a precise, human-readable
description of the violated guarantee — it becomes the finding headline in the
HTML report (rendered in red). Write `test_name` as if it were the title of a
CVE entry: `"JWT Signature Validation Not Enforced"`, not `"Test 1.2"`.

When constructing `Finding` objects manually for multi-finding results (see
below), you supply `title` explicitly — one specific title per endpoint or
service — because `self.test_name` describes the test class, not the individual
violation. The two paths are mutually exclusive: single violation → `_make_fail()`,
multiple violations on distinct targets → manual `Finding` list + manual
`TestResult`.

---

#### FAIL — multiple findings (manual TestResult)

Use this form only when a single test produces findings on multiple
distinct targets (e.g. multiple endpoints, multiple services).

```python
findings: list[Finding] = []

# ... loop: for each violation, build and append a Finding ...

if findings:
    return TestResult(
        test_id=self.test_id,
        status=TestStatus.FAIL,
        message=f"{len(findings)} violation(s) detected.",
        findings=findings,
        transaction_log=list(self._transaction_log),  # NEVER omit
        **self._metadata_kwargs(),                     # NEVER omit
    )
```

**`**self._metadata_kwargs()` must never be omitted** from a manually
constructed `TestResult`. It injects `domain`, `priority`, `strategy`,
`test_name`, `tags`, and `cwe_id` into the result. Without it, the HTML
report shows `Domain -1 — Unknown Domain` for that test.

---

#### SKIP

```python
return self._make_skip(reason="Explicit reason: Admin API not configured / no credentials.")
```

---

### Recording HTTP transactions

Every HTTP transaction that is security-relevant must be recorded.

```python
response, record = client.request(
    method="GET",
    path="/some/path",
    test_id=self.test_id,
    headers={"Authorization": f"Bearer {token}"},  # omit for unauthenticated probes
    json={"key": "value"},                          # omit if no request body
    params={"page": "1"},                           # omit if no query params
)

# Normal outcome (PASS, INCONCLUSIVE):
self._log_transaction(record, oracle_state=_STATE_PASS)

# FAIL outcome — store evidence AND log:
store.add_fail_evidence(record)
self._log_transaction(record, oracle_state=_STATE_FAIL, is_fail=True)

# Pinning a setup transaction (marks it as key evidence without being a FAIL):
store.pin_evidence(record)
self._log_transaction(record, oracle_state="SETUP_PINNED")
```

**Never call both `add_fail_evidence()` and `pin_evidence()` on the same
record.** `add_fail_evidence()` writes the full transaction to
`evidence.json` and marks it as a security violation. `pin_evidence()` also
writes to `evidence.json` but marks it as contextual evidence. Calling both
writes two entries for the same transaction, and the second call overwrites
the `is_fail_evidence` flag with `False`, silently downgrading a finding.

---

### Building `Finding` objects

```python
Finding(
    title="Short title describing the violated guarantee",
    detail=(
        "Precise: method, path, payload sent, response received "
        "(status code, relevant headers/body), correct expected behaviour."
    ),
    references=[
        self.cwe_id,
        "OWASP-API2:2023",
        "NIST-SP-800-63B-4-S4.3.1",
    ],
    evidence_ref=record.record_id,  # None for config-audit findings
)
```

---

### Creating and cleaning up persistent resources

Tests that create resources in the target (users, repositories, API tokens)
**must** register those resources for teardown immediately after creation —
before any subsequent assertion that could raise. If the registration is
placed after an assertion that fails, the resource is leaked.

The teardown interface is on `TestContext`:

```python
context.register_resource_for_teardown(
    method="DELETE",
    path=f"/api/v1/repos/{owner}/{repo_name}",
    headers={"Authorization": f"token {token}"},  # Forgejo token format — NOT "Bearer {token}"
)
```

**Auth header format for Forgejo resources:** Forgejo's API uses
`Authorization: token {value}` — not `Bearer {value}`. Using `Bearer` here
will cause the DELETE to return 401 during teardown, leaving the resource
orphaned. The `forgejo_resources` helpers handle this correctly internally;
this only matters if you call `register_resource_for_teardown` directly.

In practice, use the `forgejo_resources` helpers — they call
`register_resource_for_teardown` internally:

```python
from src.tests.helpers.forgejo_resources import (
    ForgejoResourceError,
    create_repository,
    create_issue,
)

# create_repository registers the DELETE /api/v1/repos/{owner}/{repo} teardown
# immediately after the POST returns 201.
try:
    repo = create_repository(target, context, client, role=ROLE_USER_A)
except ForgejoResourceError as exc:
    return self._make_error(exc)
```

The engine's Phase 6 calls `context.drain_resources()` and issues the
DELETE calls in LIFO order (reverse creation order) after all tests have
run. A teardown failure is logged as a `WARNING` but does not affect the
exit code or the assessment result.

**Rule:** if your test creates a resource without using a `forgejo_resources`
helper, call `context.register_resource_for_teardown()` on the very next
line after confirming the creation response status, before any `if`, `assert`,
or further `client.request()` call.

---

## Step 9 — `config.yaml`

Add the block even when using all defaults — it documents the available
tuning knobs to operators.

```yaml
tests:
  domain_N:
    test_N_2:
      some_threshold: 10   # ASVS VX.Y.Z — one-line rationale for this default
```

If the test has no tunable parameters:

```yaml
    test_N_3:
      # No operator-tunable parameters. Configuration is fully automatic.
```

---

## Strategy → Priority → Guard mapping

| Strategy | Priority | Required guards | Required imports |
|---|---|---|---|
| `BLACK_BOX` | P0 | `_requires_attack_surface` if iterating endpoints | No credential imports |
| `GREY_BOX` | P1, P2 | `_requires_grey_box_credentials` + `_requires_token` | `acquire_all_tokens_if_needed`, `ROLE_*`, `AuthenticationSetupError`, `SecurityClientError` |
| `WHITE_BOX` (no Admin API) | P3 | `_requires_attack_surface` only | `response_inspector` helpers if doing header checks |
| `WHITE_BOX` (Kong Admin) | P1, P3 | `_requires_admin_api` + `assert admin_base_url is not None` | `KongAdminError` + specific `kong_admin` helper |

**Guard ordering for GREY_BOX** (must not be inverted):
1. `_requires_grey_box_credentials(target)` — check credentials are configured.
2. `acquire_all_tokens_if_needed(target, context, client)` — acquire tokens.
3. `_requires_token(context, ROLE_X)` — verify the specific role has a token.

Calling `_requires_token` before `acquire_all_tokens_if_needed` will always
produce SKIP even when valid credentials are in the config, because no tokens
have been acquired yet.

---

## Reference tables

### Guards

| Guard | When to use | Returns |
|---|---|---|
| `_requires_attack_surface(target)` | Test iterates OpenAPI endpoints | `TestResult(SKIP)` or `None` |
| `_requires_admin_api(target)` | Test calls Kong Admin API | `TestResult(SKIP)` or `None` |
| `_requires_grey_box_credentials(target)` | Test needs at least one role configured | `TestResult(SKIP)` or `None` |
| `_requires_token(context, role)` | Test needs a live JWT for a specific role | `TestResult(SKIP)` or `None` |

### BaseTest helpers

| Helper | Use when | Notes |
|---|---|---|
| `_make_pass(message, notes=None)` | Test passed, no findings | Captures `_transaction_log` automatically |
| `_make_fail(message, detail, evidence_record_id, additional_references)` | Exactly one finding | Call `store.add_fail_evidence` and `_log_transaction` first |
| `_make_skip(reason)` | Precondition not met (predictable) | Captures `_transaction_log` automatically |
| `_make_error(exc)` | Unexpected exception | Captures `_transaction_log` automatically |
| `_log_transaction(record, oracle_state, is_fail=False)` | After every `client.request()` | Appends to `_transaction_log` |
| `_metadata_kwargs()` | Inside manual `TestResult(...)` | Injects domain/priority/tags — never omit |

### `src/tests/helpers/` modules

**Rule: before writing any logic that manipulates JWTs, inspects response headers,
creates Forgejo resources, or queries Kong, check this table first. Every function
listed here is already implemented and tested. Reimplementing any of them in a
test file is a violation of the DRY principle and a bug risk.**

| File | Public API used by tests |
|---|---|
| `auth.py` | `acquire_all_tokens_if_needed(target, context, client)` |
| `kong_admin.py` | `KongAdminError`, `get_routes`, `get_services`, `get_plugins`, `get_upstreams`, `get_status`, `get_plugin_by_name` |
| `path_resolver.py` | `resolve_path_with_seed(endpoint, seed)`, `extract_param_names_from_path(path)`, `PATH_PARAM_FALLBACK_DEFAULT`, `PATH_PARAM_FALLBACK_SAFE_DELETE` |
| `response_inspector.py` | `find_missing_security_headers(headers)`, `find_invalid_security_headers(headers)`, `find_leaky_headers(headers)`, `check_security_headers(headers)`, `contains_stack_trace(body)`, `contains_sensitive_fields(data)`, `extract_debug_fields(data)`, `auth_errors_are_uniform(response_bodies)`, `SECURITY_HEADER_DEFINITIONS`, `STACK_TRACE_PATTERNS`, `SENSITIVE_FIELD_NAMES`, `LEAKY_HEADERS` |
| `forgejo_resources.py` | `create_repository(target, context, client, role)`, `create_issue(target, context, client, role, repo_owner, repo_name)`, `get_authenticated_user(target, context, client, role)`, `list_repositories(target, context, client, role)`, `ForgejoResourceError` |
| `jwt_forge.py` | `forge_alg_none(token)`, `forge_tampered_payload(token, claim, new_value)`, `forge_expired(token, seconds_ago=3600)`, `forge_strip_signature(token)`, `forge_hs256_key_confusion(public_key_pem, payload)`, `decode_header(token)`, `decode_payload(token)`, `is_jwt_format(token)` |

**Notes on `jwt_forge.py`:**
- `forge_expired` is the primary tool for test 1.3 — it sets `exp` to a past
  timestamp. Its docstring explicitly states "Test 1.3 uses this function."
- `forge_strip_signature` is distinct from `forge_alg_none`: the header still
  declares the original algorithm; only the signature segment is emptied. Use
  it for the "Signature Stripping" sub-test of test 1.2.
- `decode_header` and `decode_payload` return `dict[str, Any]` — use them to
  inspect the claims of a valid token before forging variants.

**Notes on `forgejo_resources.py`:**
- `create_repository` **registers teardown internally** — no manual
  `register_resource_for_teardown` call is needed after it.
- `create_issue` **does NOT register teardown separately**. Issues are deleted
  automatically when the parent repository is deleted by Phase 6 teardown.
  If a test creates issues without a parent repository created via
  `create_repository`, those issues will NOT be cleaned up automatically.
- `get_authenticated_user` fetches the Forgejo user dict for a role —
  useful when a test needs to know the `login` (username) associated with a
  token before constructing resource paths.

**Notes on `response_inspector.py`:**
- `contains_stack_trace(body: str) -> list[str]`: returns matching patterns
  found in the response body — use for domain 6.1 (Error Handling) tests.
- `auth_errors_are_uniform(response_bodies: list[str]) -> bool`: returns True
  if all error messages are indistinguishable — use to verify that "user not
  found" and "wrong password" produce identical error text (prevents username
  enumeration, domain 6.1).
- `check_security_headers(headers) -> dict`: higher-level wrapper that combines
  `find_missing_security_headers` and `find_invalid_security_headers` into a
  single call returning `{"missing": [...], "invalid": [...]}`. Prefer it over
  calling the two functions separately.

### `AttackSurface` filter methods

| Method | Returns |
|---|---|
| `surface.get_authenticated_endpoints()` | Endpoints with `requires_auth=True` |
| `surface.get_public_endpoints()` | Endpoints with `requires_auth=False` |
| `surface.get_deprecated_endpoints()` | Endpoints with `is_deprecated=True` |
| `surface.get_endpoints_by_method("GET")` | Endpoints with the given HTTP method |
| `surface.get_endpoints_with_path_parameters()` | Endpoints with `{param}` templates |
| `surface.find_endpoint("/path", "METHOD")` | Single `EndpointRecord` or `None` |

---

## Worked example — Test 2.1 (minimal GREY_BOX)

This example shows the exact naming chain from Step 1 through Step 8 for a
hypothetical GREY_BOX test. **Every step is shown completely — no
placeholder logic.**

**Step 1** — `src/config/schema/domain_2.py` (new file):

```python
from __future__ import annotations
from pydantic import BaseModel, Field

TEST_21_SAMPLE_SIZE_DEFAULT: int = 5
TEST_21_SAMPLE_SIZE_MIN: int = 1

class Test21Config(BaseModel):
    model_config = {"frozen": True}
    sample_size: int = Field(
        default=TEST_21_SAMPLE_SIZE_DEFAULT,
        ge=TEST_21_SAMPLE_SIZE_MIN,
        description="Number of privileged endpoints to probe for RBAC. ASVS V8.3.1. Default: 5.",
    )

class TestDomain2Config(BaseModel):
    model_config = {"frozen": True}
    test_2_1: Test21Config = Field(
        default_factory=Test21Config,
        description="Params for Test 2.1. Maps to tests.domain_2.test_2_1.",
    )
```

**Step 2** — `tests_config.py`:

```python
from src.config.schema.domain_2 import TestDomain2Config
# inside TestsConfig:
domain_2: TestDomain2Config = Field(default_factory=TestDomain2Config, ...)
```

**Step 3** — `config/schema/__init__.py` (3 places):

```python
# docstring:  domain_2.py    Test21Config, TestDomain2Config
from src.config.schema.domain_2 import Test21Config, TestDomain2Config
# __all__:    "Test21Config", "TestDomain2Config"
```

**Step 4** — `src/core/models/runtime.py`:

```python
class RuntimeTest21Config(BaseModel):
    model_config = {"frozen": True}   # mandatory
    sample_size: int = Field(
        default=5,
        ge=1,
        description="Mirrors Test21Config.sample_size. Default: 5.",
    )

# inside RuntimeTestsConfig:
test_2_1: RuntimeTest21Config = Field(
    default_factory=RuntimeTest21Config,
    description="Runtime parameters for Test 2.1.",
)
```

**Step 5** — `src/core/models/__init__.py` (3 places):

```python
# docstring:  RuntimeTest21Config
from src.core.models.runtime import (..., RuntimeTest21Config, ...)
# __all__:    "RuntimeTest21Config"
```

**Step 6** — `src/engine.py` (2 places):

```python
# import:     RuntimeTest21Config
# inside RuntimeTestsConfig(...):
test_2_1=RuntimeTest21Config(
    sample_size=config.tests.domain_2.test_2_1.sample_size,
),
```

**Step 7** — `src/tests/domain_2/__init__.py` (new domain — empty file):

```
(empty)
```

Required for `pkgutil.walk_packages` to traverse the directory. See Step 7
in the main pipeline for the verification command.

**Step 8** — `src/tests/domain_2/test_2_1_rbac_enforcement.py`:

```python
from __future__ import annotations

from typing import ClassVar

import structlog

from src.core.client import SecurityClient
from src.core.context import ROLE_USER_A, TargetContext, TestContext
from src.core.evidence import EvidenceStore
from src.core.exceptions import AuthenticationSetupError, SecurityClientError
from src.core.models import Finding, TestResult, TestStatus, TestStrategy
from src.tests.base import BaseTest
from src.tests.helpers.auth import acquire_all_tokens_if_needed

log: structlog.BoundLogger = structlog.get_logger(__name__)

# ---------------------------------------------------------------------------
# Module-level constants
# ---------------------------------------------------------------------------

_STATE_RBAC_ENFORCED: str = "RBAC_ENFORCED"
_STATE_RBAC_BYPASS:   str = "RBAC_BYPASS"

_PRIVILEGED_ENDPOINT: str = "/api/v1/admin/users"
_PRIVILEGED_METHOD:   str = "GET"

_REFERENCES: list[str] = [
    "OWASP-API5:2023",
    "NIST-SP-800-53-Rev5-AC-3",
    "OWASP-ASVS-V8.3.1",
]


class Test21RbacEnforcement(BaseTest):
    test_id:    ClassVar[str]          = "2.1"
    test_name:  ClassVar[str]          = "Only Authorized Users Access Privileged Endpoints"
    priority:   ClassVar[int]          = 1
    domain:     ClassVar[int]          = 2
    strategy:   ClassVar[TestStrategy] = TestStrategy.GREY_BOX
    depends_on: ClassVar[list[str]]    = ["1.1"]
    tags:       ClassVar[list[str]]    = ["authorization", "rbac", "OWASP-API5:2023"]
    cwe_id:     ClassVar[str]          = "CWE-285"

    def execute(
        self,
        target: TargetContext,
        context: TestContext,
        client: SecurityClient,
        store: EvidenceStore,
    ) -> TestResult:
        """
        Verify that privileged endpoints reject requests from non-privileged users.

        Oracle: a request authenticated as ROLE_USER_A to the admin-only endpoint
        _PRIVILEGED_ENDPOINT must return 403 Forbidden.  A 200/2xx response is a FAIL.
        Returns SKIP if credentials are not configured or the user_a token is unavailable.
        """
        try:
            guard = self._requires_grey_box_credentials(target)
            if guard is not None:
                return guard

            try:
                acquire_all_tokens_if_needed(target, context, client)
            except (AuthenticationSetupError, SecurityClientError) as exc:
                return self._make_error(exc)

            skip = self._requires_token(context, ROLE_USER_A)
            if skip is not None:
                return skip

            token = context.get_token(ROLE_USER_A)
            cfg = target.tests_config.test_2_1

            log.info(
                "test_2_1_starting",
                sample_size=cfg.sample_size,
                probing_endpoint=_PRIVILEGED_ENDPOINT,
            )

            response, record = client.request(
                method=_PRIVILEGED_METHOD,
                path=_PRIVILEGED_ENDPOINT,
                test_id=self.test_id,
                headers={"Authorization": f"Bearer {token}"},
            )

            if 200 <= response.status_code < 300:
                store.add_fail_evidence(record)
                self._log_transaction(record, oracle_state=_STATE_RBAC_BYPASS, is_fail=True)
                return self._make_fail(
                    message=(
                        f"RBAC bypass: {_PRIVILEGED_METHOD} {_PRIVILEGED_ENDPOINT} "
                        f"returned {response.status_code} for a non-privileged user."
                    ),
                    detail=(
                        f"Sent {_PRIVILEGED_METHOD} {_PRIVILEGED_ENDPOINT} with a "
                        f"'{ROLE_USER_A}' token. Expected 403 Forbidden. "
                        f"Received {response.status_code}. "
                        f"The endpoint did not verify the caller's role before serving "
                        f"the response. A low-privilege user can access admin functionality."
                    ),
                    evidence_record_id=record.record_id,
                    additional_references=_REFERENCES,
                )

            self._log_transaction(record, oracle_state=_STATE_RBAC_ENFORCED)
            return self._make_pass(
                message=(
                    f"{_PRIVILEGED_METHOD} {_PRIVILEGED_ENDPOINT} correctly returned "
                    f"{response.status_code} for a non-privileged user."
                )
            )

        except Exception as exc:  # noqa: BLE001
            return self._make_error(exc)
```

**Step 9** — `config.yaml`:

```yaml
tests:
  domain_2:
    test_2_1:
      sample_size: 5   # ASVS V8.3.1 — number of privileged endpoints to probe
```

---

## Pre-output checklist

- [ ] `test_id` is unique — checked against all existing values in `src/tests/`
- [ ] `test_id` uses dot separator (`"N.2"`), not underscore (`"N_2"`)
- [ ] If new domain: `src/tests/domain_N/__init__.py` created (empty file) — run verification command from Step 7
- [ ] All 8 `ClassVar` attributes present in the test class
- [ ] `log: structlog.BoundLogger = structlog.get_logger(__name__)` present after imports
- [ ] Module-level constants defined for all string literals, status code sets, and reference lists
- [ ] All `oracle_state` strings are module-level constants, not inline literals
- [ ] `execute()` has outermost `try/except Exception as exc: return self._make_error(exc)`
- [ ] Every manually built `TestResult` includes `**self._metadata_kwargs()` and `transaction_log=list(self._transaction_log)`
- [ ] `_make_fail()` used for single-finding results (not manual `TestResult`)
- [ ] `store.add_fail_evidence(record)` and `_log_transaction(..., is_fail=True)` called **before** `_make_fail()`
- [ ] `store.add_fail_evidence()` and `store.pin_evidence()` never called on the same record
- [ ] GREY_BOX tests call `acquire_all_tokens_if_needed` before `_requires_token`
- [ ] WHITE_BOX (Kong Admin) tests call `_requires_admin_api` + `assert admin_base_url is not None  # noqa: S101`
- [ ] WHITE_BOX (Kong Admin) tests wrap every kong helper in a private method returning `None` on `KongAdminError`
- [ ] `frozen=True` present on both `TestN2Config` (Step 1) and `RuntimeTestN2Config` (Step 4)
- [ ] `RuntimeTestNNConfig` added to `src/core/models/__init__.py` in all three places (docstring, import, `__all__`)
- [ ] Population line added to `engine.py` `_phase_3_build_contexts()` inside `RuntimeTestsConfig(...)`
- [ ] If new domain: `TestDomainNConfig` exported from `src/config/schema/__init__.py` in all three places
- [ ] `config.yaml` block added for the new test (even if all defaults — documents the knobs)
- [ ] Tests creating persistent resources call `context.register_resource_for_teardown()` immediately after creation, before any assertion
- [ ] No `print()` — only `structlog`
- [ ] No magic numbers — all thresholds in named module-level constants or read from `target.tests_config`
- [ ] No `TODO`, `FIXME`, `HACK` in any file
- [ ] No import wildcards (`from module import *`)
- [ ] All code in English (variables, docstrings, log keys, exception messages)
- [ ] No emoji in source code
- [ ] Credentials and tokens sanitised with `[REDACTED]` in log messages
- [ ] Module docstring present documenting guarantee, strategy, priority, sub-tests, oracle, EvidenceStore policy

---

## Common errors and fixes

| Symptom | Root cause | Where it happens | Fix |
|---|---|---|---|
| Test never discovered, no error logged, domain absent from report | `src/tests/domain_N/__init__.py` missing for a new domain | Step 7 | Create the empty file; run Step 7 verification command to confirm |
| `ImportError: cannot import name 'RuntimeTestN2Config'` at startup | Step 5 (`core/models/__init__.py`) missed | Any import of the new config | Add to docstring + import + `__all__` in that file |
| `ImportError: cannot import name 'TestDomainNConfig'` at startup | Step 3 (`config/schema/__init__.py`) missed | Any import of the new domain config | Add to docstring + import + `__all__` in that file |
| HTML report shows `Domain -1 — Unknown Domain` | `**self._metadata_kwargs()` omitted from manual `TestResult` | Step 7, FAIL multi-finding block | Add it to every manually constructed `TestResult` |
| HTML Audit Trail empty for a test that made HTTP requests | `transaction_log=list(self._transaction_log)` omitted from manual `TestResult` | Step 7, FAIL multi-finding block | Add it to every manually constructed `TestResult` |
| Test never discovered / never runs | Filename does not match `test_N_M_description.py` | Step 7, filename | Rename the file |
| DAG reports dependency cycle or missing dependency | `test_id` in `depends_on` does not exactly match the dependency's `test_id` | Step 7, ClassVar | Check exact string value including the dot form |
| `target.tests_config.test_n_2` raises `AttributeError` | Step 4 (field in `RuntimeTestsConfig`) or Step 6 (population in engine) was skipped | Inside `execute()` | Complete both steps |
| `config.yaml` values ignored / defaults used always | YAML key path does not match the Pydantic field chain | Step 8 | Align `tests.domain_N.test_N_2` key with `TestsConfig` → `TestDomainNConfig` → `TestN2Config` |
| `NameError: name 'log' is not defined` | `log: structlog.BoundLogger = ...` line missing from test file | Step 7, after imports | Add it after the import block, before module constants |
| `AttributeError: 'NoneType' object has no attribute ...` on Admin API call | `admin_endpoint_base_url()` result not asserted non-None | Step 7, WHITE_BOX pattern | Add `assert admin_base_url is not None  # noqa: S101` after the call |
| GREY_BOX test returns SKIP even with credentials in config | `_requires_token(context, role)` called before `acquire_all_tokens_if_needed` | Step 7, GREY_BOX pattern | Swap the order: acquire first, then guard |
| Finding reported twice in evidence.json | `add_fail_evidence()` and `pin_evidence()` both called on same record | Step 7, recording block | Use only one of the two per record |
| `TargetContext` mutated after construction | `RuntimeTestN2Config` missing `frozen=True` | Step 4 | Add `model_config = {"frozen": True}` to the class |
| DAG accepts test_id but report shows wrong test | `test_id` uses underscore (`"N_2"`) instead of dot (`"N.2"`) | Step 7, ClassVar | Use dot form for `test_id`, underscore form for field names |
<a id="src.engine"></a>

# src.engine

src/engine.py

Assessment pipeline orchestrator for the APIGuard Assurance tool.

The engine is the only module with full visibility across all components.
Its responsibility is exclusively orchestrative: it calls the right modules
in the right order, passes the right objects, and records the results.

The engine contains NO domain logic, NO test interpretation, NO decisions
about what to test. Every such decision is delegated to the appropriate
component:
    - What to test:        TestRegistry + DAGScheduler
    - How to test:         BaseTest.execute() implementations
    - What HTTP to send:   SecurityClient
    - What to record:      EvidenceStore (populated by tests)
    - What to report:      report/builder.py + report/renderer.py

Pipeline phases (Implementazione.md, Section 5):

    Phase 1 -- Initialization:
        Load and validate config.yaml via config/loader.py.
        Raises ConfigurationError on failure [BLOCKS STARTUP].

    Phase 2 -- OpenAPI Discovery:
        Resolve the spec source via TargetConfig.get_openapi_source().
        This returns either an HTTP/HTTPS URL or a local filesystem path,
        depending on which field is set in config.yaml. The distinction is
        transparent to the rest of the engine: load_openapi_spec() accepts
        both formats natively.
        Fetch or read, dereference, and validate the OpenAPI spec.
        Build AttackSurface from the dereferenced spec.
        Raises OpenAPILoadError on failure [BLOCKS STARTUP].

    Phase 3 -- Context Construction:
        Build TargetContext (frozen) from ToolConfig + AttackSurface.
        Propagates both openapi_spec_url and openapi_spec_path from
        TargetConfig to TargetContext (exactly one will be non-None).
        Build TestContext (mutable, empty).
        Build EvidenceStore (streaming JSONL, unbounded capacity).
        Build SecurityClient (context manager, not yet open).

    Phase 4 -- Test Discovery and Scheduling:
        TestRegistry discovers and filters active tests.
        DAGScheduler builds the topological execution order.
        Raises DAGCycleError on dependency cycle [BLOCKS STARTUP].

    Phase 5 -- Execution:
        For each ScheduledBatch in topological order:
            For each test in the batch (sequential):
                Call test.execute(target, context, client, store).
                Add TestResult to ResultSet.
                Check fail-fast condition.

    Phase 6 -- Teardown (Best-Effort):
        Drain TestContext resource registry in LIFO order.
        DELETE each registered resource via SecurityClient.
        Log TeardownError as WARNING; continue on failure.

    Phase 7 -- Report Generation:
        Aggregate ResultSet statistics via report/builder.py.
        Serialize EvidenceStore to config.output.evidence_path.
        Render HTML report to config.output.report_path.
        Compute and return exit code.

Dependency rule:
    engine.py imports from all src/ layers (config/, core/, discovery/,
    tests/, report/). It is the only module permitted to do so.
    No other module imports from engine.py.

<a id="src.engine.AssessmentEngine"></a>

## AssessmentEngine Objects

```python
class AssessmentEngine()
```

Orchestrator for the APIGuard Assurance assessment pipeline.

One AssessmentEngine instance is created per pipeline run by cli.py.
The run() method executes all seven phases sequentially and returns
the process exit code.

The engine is intentionally not reusable across multiple runs: each
run creates fresh instances of all shared state objects (TargetContext,
TestContext, EvidenceStore, ResultSet). Reusing an engine instance would
risk contaminating results from a previous run.

<a id="src.engine.AssessmentEngine.__init__"></a>

#### \_\_init\_\_

```python
def __init__(config_path: Path) -> None
```

Initialize the engine with the path to the configuration file.

Does not load the configuration or perform any I/O at construction
time. All I/O begins in run() Phase 1.

**Arguments**:

- `config_path` - Path to the config.yaml file.

<a id="src.engine.AssessmentEngine.run"></a>

#### run

```python
def run() -> int
```

Execute the complete assessment pipeline and return the exit code.

**Returns**:

- `int` - Process exit code. One of: 0, 1, 2, 10.

<a id="src.core.models.runtime"></a>

# src.core.models.runtime

src/core/models/runtime.py

Runtime configuration models for the APIGuard Assurance tool.

Contains the immutable credential and per-test parameter snapshots that
are propagated into TargetContext by the engine during Phase 3, and
consumed by test implementations via target.tests_config and
target.credentials.

    RuntimeCredentials      -- Immutable credentials propagated to TargetContext.
    RuntimeTest11Config     -- Runtime mirror of TestDomain1Config fields for Test 1.1.
    RuntimeTest15Config     -- Runtime mirror of Test15Config for Test 1.5.
    RuntimeTest16Config     -- Runtime mirror of Test16Config for Test 1.6.
    RuntimeTest41Config     -- Runtime mirror of Test41ProbeConfig for Test 4.1.
    RuntimeTest42Config     -- Runtime mirror of Test42AuditConfig for Test 4.2.
    RuntimeTest43Config     -- Runtime mirror of Test43AuditConfig for Test 4.3.
    RuntimeTest72Config     -- Runtime mirror of Test72SSRFConfig for Test 7.2.
    RuntimeTestsConfig      -- Immutable container for all per-test runtime configs.

Design rationale:
    Runtime*Config models live in core/ (not config/) so TargetContext can
    reference them without importing from config/. This preserves the
    unidirectional dependency rule: config/ imports core/, never the reverse.

    Each RuntimeTest*Config mirrors only the fields that the corresponding
    test actually reads at runtime. Adding a new test requires adding one
    field to RuntimeTestsConfig and one population line in engine.py Phase 3.

Dependency rule: this module imports only from pydantic and the stdlib.
It must never import from any other src/ module.

<a id="src.core.models.runtime.RuntimeCredentials"></a>

## RuntimeCredentials Objects

```python
class RuntimeCredentials(BaseModel)
```

Immutable snapshot of credentials propagated into TargetContext.

Lives in core/ so TargetContext can reference it without importing from
config/ (unidirectional dependency rule: config/ imports core/, never reverse).

auth_type mirrors CredentialsConfig.auth_type and is read by the auth
dispatcher (src/tests/helpers/auth.py) to select the correct token-acquisition
implementation at runtime. The jwt_login-specific fields are only populated
when auth_type == 'jwt_login'; they are None otherwise.

<a id="src.core.models.runtime.RuntimeCredentials.has_admin"></a>

#### has\_admin

```python
def has_admin() -> bool
```

True if both admin_username and admin_password are present and non-empty.

<a id="src.core.models.runtime.RuntimeCredentials.has_user_a"></a>

#### has\_user\_a

```python
def has_user_a() -> bool
```

True if both user_a_username and user_a_password are present and non-empty.

<a id="src.core.models.runtime.RuntimeCredentials.has_user_b"></a>

#### has\_user\_b

```python
def has_user_b() -> bool
```

True if both user_b_username and user_b_password are present and non-empty.

<a id="src.core.models.runtime.RuntimeCredentials.has_any_grey_box_credentials"></a>

#### has\_any\_grey\_box\_credentials

```python
def has_any_grey_box_credentials() -> bool
```

True if at least one role has complete credentials configured.

<a id="src.core.models.runtime.RuntimeCredentials.available_roles"></a>

#### available\_roles

```python
def available_roles() -> list[str]
```

Return the list of role names with complete credentials configured.

Role name strings match ROLE_* constants in context.py.
Local import avoided here to prevent a circular dependency.

<a id="src.core.models.runtime.RuntimeTest02Config"></a>

## RuntimeTest02Config Objects

```python
class RuntimeTest02Config(BaseModel)
```

Runtime mirror of Test02ProbeConfig consumed by Test 0.2.

Populated by engine.py Phase 3 from config.tests.domain_0.test_0_2.
Access pattern inside the test:
    cfg = target.tests_config.test_0_2
    gateway_ids = frozenset(cfg.gateway_server_identifiers)

Why frozenset at the call site rather than here:
    Pydantic frozen models allow mutable field types (list) as long as the
    model itself is frozen (no attribute re-assignment). Converting to
    frozenset at the call site is a one-time O(n) operation and avoids the
    complexity of a custom Pydantic type for a small set of strings.

<a id="src.core.models.runtime.RuntimeTest02Config.model_config"></a>

#### model\_config

mandatory — see "Why two layers?" in ADDING_TESTS.md

<a id="src.core.models.runtime.RuntimeTest11Config"></a>

## RuntimeTest11Config Objects

```python
class RuntimeTest11Config(BaseModel)
```

Runtime mirror of TestDomain1Config fields consumed by Test 1.1.

<a id="src.core.models.runtime.RuntimeTest15Config"></a>

## RuntimeTest15Config Objects

```python
class RuntimeTest15Config(BaseModel)
```

Runtime mirror of Test15Config fields consumed by Test 1.5.

Populated by engine.py Phase 3 from config.tests.domain_1.test_1_5.
Access pattern inside the test:
    cfg = target.tests_config.test_1_5
    cfg.hsts_min_max_age_seconds
    cfg.http_probe_enabled
    cfg.http_probe_timeout_seconds
    cfg.expected_redirect_status_codes
    cfg.testssl_binary_path

<a id="src.core.models.runtime.RuntimeTest15Config.model_config"></a>

#### model\_config

mandatory — see "Why two layers?" in ADDING_TESTS.md

<a id="src.core.models.runtime.RuntimeTest16Config"></a>

## RuntimeTest16Config Objects

```python
class RuntimeTest16Config(BaseModel)
```

Runtime mirror of Test16Config fields consumed by Test 1.6.

Populated by engine.py Phase 3 from config.tests.domain_1.test_1_6.
Access pattern inside the test:
    cfg = target.tests_config.test_1_6
    cfg.cookie_probe_paths
    cfg.session_cookie_names
    cfg.check_samesite
    cfg.expected_samesite_value

<a id="src.core.models.runtime.RuntimeTest16Config.model_config"></a>

#### model\_config

mandatory — see "Why two layers?" in ADDING_TESTS.md

<a id="src.core.models.runtime.RuntimeTest16Config.session_cookie_names_not_empty"></a>

#### session\_cookie\_names\_not\_empty

```python
@field_validator("session_cookie_names")
@classmethod
def session_cookie_names_not_empty(cls, v: list[str]) -> list[str]
```

Reject empty list: would silently SKIP on every target.

<a id="src.core.models.runtime.RuntimeTest33Config"></a>

## RuntimeTest33Config Objects

```python
class RuntimeTest33Config(BaseModel)
```

Runtime mirror of Test33Config fields consumed by Test 3.3.

Populated by engine.py Phase 3 from config.tests.domain_3.test_3_3.
Access pattern inside the test:
    cfg = target.tests_config.test_3_3
    cfg.max_clock_skew_seconds
    cfg.forbidden_algorithms
    cfg.plugin_names
    cfg.field_clock_skew
    cfg.field_algorithms
    cfg.field_validate_body
    cfg.clock_skew_unconfigured_value

<a id="src.core.models.runtime.RuntimeTest33Config.model_config"></a>

#### model\_config

mandatory — see "Why two layers?" in ADDING_TESTS.md

<a id="src.core.models.runtime.RuntimeTest41Config"></a>

## RuntimeTest41Config Objects

```python
class RuntimeTest41Config(BaseModel)
```

Runtime mirror of Test41ProbeConfig fields consumed by Test 4.1.

Mirrors config/schema/domain_4.py:Test41ProbeConfig, nested under
config.tests.domain_4.test_4_1 in config.yaml (previously at the
root level as 'rate_limit_probe' -- migrated in schema refactoring).

Access pattern in the test:
    target.tests_config.test_4_1.max_requests
    target.tests_config.test_4_1.request_interval_seconds

<a id="src.core.models.runtime.RuntimeTest41Config.request_interval_seconds"></a>

#### request\_interval\_seconds

```python
@property
def request_interval_seconds() -> float
```

Convert request_interval_ms to seconds for use in time.sleep() calls.

<a id="src.core.models.runtime.RuntimeTest42Config"></a>

## RuntimeTest42Config Objects

```python
class RuntimeTest42Config(BaseModel)
```

Runtime mirror of Test42AuditConfig fields consumed by Test 4.2.

Stores the maximum acceptable timeout values (in milliseconds) for Kong
service objects. Mirrored from config/schema.py:Test42AuditConfig, which
is nested under config.tests.domain_4.test_4_2.

Access pattern in the test:
    target.tests_config.test_4_2.max_connect_timeout_ms
    target.tests_config.test_4_2.max_read_timeout_ms
    target.tests_config.test_4_2.max_write_timeout_ms

<a id="src.core.models.runtime.RuntimeTest43Config"></a>

## RuntimeTest43Config Objects

```python
class RuntimeTest43Config(BaseModel)
```

Runtime mirror of Test43AuditConfig fields consumed by Test 4.3.

Stores all parameters needed by the Dual-Check a 3 Livelli strategy.
Mirrored from config/schema.py:Test43AuditConfig, nested under
config.tests.domain_4.test_4_3.

Level 1 parameters (native CB plugin validation):
    accepted_cb_plugin_names, failure_threshold_min/max,
    timeout_duration_min/max_seconds.

Level 2 parameters (upstream passive healthcheck oracle thresholds):
    passive_hc_max_http_failures, passive_hc_max_tcp_failures,
    passive_hc_max_timeouts.

Access pattern in the test:
    target.tests_config.test_4_3.accepted_cb_plugin_names
    target.tests_config.test_4_3.failure_threshold_min
    target.tests_config.test_4_3.failure_threshold_max
    target.tests_config.test_4_3.timeout_duration_min_seconds
    target.tests_config.test_4_3.timeout_duration_max_seconds
    target.tests_config.test_4_3.passive_hc_max_http_failures
    target.tests_config.test_4_3.passive_hc_max_tcp_failures
    target.tests_config.test_4_3.passive_hc_max_timeouts

<a id="src.core.models.runtime.RuntimeTest62Config"></a>

## RuntimeTest62Config Objects

```python
class RuntimeTest62Config(BaseModel)
```

Runtime mirror of Test62AuditConfig fields consumed by Test 6.2.

Stores the two tunable parameters for the Security Header Configuration
Audit.  Mirrored from config/schema/domain_6.py:Test62AuditConfig,
nested under config.tests.domain_6.test_6_2 in config.yaml.

Access pattern in the test:
    target.tests_config.test_6_2.hsts_min_max_age_seconds
    target.tests_config.test_6_2.endpoint_sample_size

<a id="src.core.models.runtime.RuntimeTest64Config"></a>

## RuntimeTest64Config Objects

```python
class RuntimeTest64Config(BaseModel)
```

Runtime mirror of Test64AuditConfig fields consumed by Test 6.4.

Stores the operator-tunable list of debug endpoint paths to probe for
credential exposure.  Mirrored from config/schema/domain_6.py:Test64AuditConfig,
nested under config.tests.domain_6.test_6_4 in config.yaml.

Access pattern inside the test:
    cfg = target.tests_config.test_6_4
    cfg.debug_endpoint_paths   # list[str]

<a id="src.core.models.runtime.RuntimeTest72Config"></a>

## RuntimeTest72Config Objects

```python
class RuntimeTest72Config(BaseModel)
```

Runtime mirror of Test72SSRFConfig fields consumed by Test 7.2.

Populated by engine.py Phase 3 from config.tests.domain_7.test_7_2.
Access pattern inside the test:
    cfg = target.tests_config.test_7_2
    cfg.payload_categories
    cfg.injection_mode
    cfg.injection_path_template
    cfg.injection_url_field
    cfg.injection_body_template
    cfg.ssrf_redirect_server_url
    cfg.ssrf_malformed_url_keywords
    cfg.ssrf_unsupported_scheme_keywords
    cfg.ssrf_block_response_keywords
    cfg.ssrf_request_timeout_ms

<a id="src.core.models.runtime.RuntimeTestsConfig"></a>

## RuntimeTestsConfig Objects

```python
class RuntimeTestsConfig(BaseModel)
```

Immutable container for all per-test runtime configurations.

Populated by engine.py in Phase 3 from config.tests and sibling
config blocks. Stored in TargetContext and accessed by test
implementations via target.tests_config.

Convention: one field per test, named test_X_Y where X is the domain
number and Y is the test number within that domain. Each field holds
an immutable RuntimeTest{XY}Config model with only the parameters
that specific test needs. This pattern scales cleanly as new tests
are added: adding a test requires only adding one field here and
one population line in engine.py Phase 3.

Transaction log parameters are absent by design:
    transaction_log_max_entries_per_test -> removed (no cap needed with
        TransactionSummary's ~160-byte minimal model).
    transaction_log_preview_chars -> removed (no body content in summaries).

<a id="src.config.schema.tests_config"></a>

# src.config.schema.tests\_config

src/config/schema/tests_config.py

Pydantic v2 aggregator for all per-domain test tuning configurations.

TestsConfig is the single object that ToolConfig (in tool_config.py) exposes
as its 'tests' field. It imports one aggregator per domain (TestDomain1Config,
TestDomain4Config, ...) and exposes them as typed fields.

Scaling convention:
    Adding a new domain requires:
        1. Creating src/config/schema/domain_N.py with TestDomainNConfig.
        2. Importing TestDomainNConfig here and adding a field.
        3. Exporting it via __init__.py.
    No other files in this package need to change.

Dependency rule: imports only from pydantic, the stdlib, and sibling domain
modules within this package. Must never import from tool_config.py (that
would create a circular dependency: tool_config imports tests_config).

<a id="src.config.schema.tests_config.TestsConfig"></a>

## TestsConfig Objects

```python
class TestsConfig(BaseModel)
```

Container for all per-domain test tuning parameters.

Populated by config.yaml under the 'tests:' top-level key and stored
(after propagation through engine.py Phase 3) in TargetContext.tests_config
as a RuntimeTestsConfig instance.

Default values are defined in each domain's individual model (e.g.
Test41ProbeConfig) and require no operator override for a standard assessment.

<a id="src.core.client"></a>

# src.core.client

src/core/client.py

SecurityClient: centralized HTTP client for all assessment traffic.

Every HTTP request performed during the assessment passes through this class.
No test module, discovery module, or any other src/ module is permitted to
import httpx directly. This single-point-of-entry design enables:

    - Uniform timeout enforcement on every request.
    - Centralized retry logic with exponential backoff (tenacity).
    - Consistent EvidenceRecord construction for every transaction.
    - Guaranteed non-following of HTTP redirects (a redirect is security
      information, not a transport inconvenience to hide from the test).

The client does NOT:
    - Interpret HTTP status codes (the test's responsibility).
    - Add authentication headers (the test's responsibility).
    - Write to EvidenceStore (the test's responsibility, using the returned record).
    - Follow redirects (disabled unconditionally).

Return contract:
    Every successful call to request() returns a tuple:
        (httpx.Response, EvidenceRecord)
    The test uses the Response for its oracle logic and decides independently
    whether to pass the EvidenceRecord to store.add_fail_evidence() or
    store.pin_evidence().

    On non-recoverable transport failure, SecurityClientError is raised.
    The test's execute() method must catch it and return TestResult(ERROR).

Dependency rule: this module imports from stdlib, httpx, tenacity, structlog,
and src.core only. It must never import from tests/, config/, discovery/, or
report/.

<a id="src.core.client.SecurityClient"></a>

## SecurityClient Objects

```python
class SecurityClient()
```

Centralized HTTP client for all assessment HTTP traffic.

Wraps an httpx.Client with:
    - Configurable timeouts (connect, read, write, pool).
    - Retry logic with exponential backoff and jitter via tenacity.
      Retries only on transport-layer exceptions, never on HTTP responses.
    - Automatic EvidenceRecord construction for every completed transaction.
    - Redirect following disabled unconditionally.

One SecurityClient instance is created during Phase 3 (Context Construction)
and shared across all test executions for the entire pipeline run. The client
is not thread-safe (consistent with the sequential execution model of V1.0).

The underlying httpx.Client is managed as a context manager. The SecurityClient
itself exposes __enter__ and __exit__ so that engine.py can use it in a
'with' block, ensuring the connection pool is properly closed after Phase 6
regardless of exceptions.

Usage in engine.py:

    with SecurityClient(connect_timeout=5.0, read_timeout=30.0) as client:
        # Phase 5: pass client to each test.execute()
        result = test.execute(target, context, client, store)
    # httpx connection pool closed here.

Usage in a BaseTest.execute() implementation:

    response, record = client.request(
        method="GET",
        path="/api/v1/users/me",
        test_id=self.test_id,
        headers={"Authorization": f"Bearer {token}"},
    )
    if response.status_code != 401:
        store.add_fail_evidence(record)
        return TestResult(status=TestStatus.FAIL, ...)

<a id="src.core.client.SecurityClient.__init__"></a>

#### \_\_init\_\_

```python
def __init__(base_url: str,
             connect_timeout: float = DEFAULT_CONNECT_TIMEOUT_SECONDS,
             read_timeout: float = DEFAULT_READ_TIMEOUT_SECONDS,
             write_timeout: float = DEFAULT_WRITE_TIMEOUT_SECONDS,
             pool_timeout: float = DEFAULT_POOL_TIMEOUT_SECONDS,
             max_retry_attempts: int = DEFAULT_MAX_RETRY_ATTEMPTS,
             retry_wait_min: float = DEFAULT_RETRY_WAIT_MIN_SECONDS,
             retry_wait_max: float = DEFAULT_RETRY_WAIT_MAX_SECONDS,
             retry_jitter: float = DEFAULT_RETRY_JITTER_SECONDS,
             verify_tls: bool = True) -> None
```

Initialize the SecurityClient with timeout and retry configuration.

The httpx.Client is NOT created here: it is created in __enter__ so
that the client can only be used as a context manager, making improper
usage (forgetting to close the connection pool) a runtime error rather
than a silent resource leak.

**Arguments**:

- `base_url` - The base URL prepended to every request path.
  Typically target.endpoint_base_url() from TargetContext.
  Must not end with a trailing slash.
- `connect_timeout` - Seconds to wait for TCP connection establishment.
- `read_timeout` - Seconds to wait for the server to send a response byte.
- `write_timeout` - Seconds to wait for the server to accept a request byte.
- `pool_timeout` - Seconds to wait to acquire a connection from the pool.
- `max_retry_attempts` - Total number of attempts (initial + retries).
  Minimum 1 (no retry). Maximum recommended: 5.
- `retry_wait_min` - Minimum wait in seconds between retry attempts.
- `retry_wait_max` - Maximum wait in seconds between retry attempts.
- `retry_jitter` - Random jitter in seconds added to each wait interval.
  Jitter prevents thundering herd in concurrent scenarios.
- `verify_tls` - Whether to verify the TLS certificate against trusted CAs.
- `Default` - True.  Set to False ONLY in lab environments
  where the Gateway uses a self-signed certificate (e.g.
  generated by gen-certs.sh).  Forwarded verbatim to
  httpx.Client(verify=...).  Never False in production.

<a id="src.core.client.SecurityClient.__enter__"></a>

#### \_\_enter\_\_

```python
def __enter__() -> SecurityClient
```

Open the underlying httpx.Client and return self.

redirect following is disabled via follow_redirects=False.
This is unconditional: a redirect from the server is security-relevant
information that the test must observe, not a transport detail to hide.

The verify=True default enforces TLS certificate validation.
In a lab environment with self-signed certificates, this can be
overridden by passing verify_tls=False to the SecurityClient constructor.
That override is explicit, documented in TargetConfig, and requires
an intentional opt-in in config.yaml (verify_tls: false).

<a id="src.core.client.SecurityClient.__exit__"></a>

#### \_\_exit\_\_

```python
def __exit__(exc_type: type[BaseException] | None,
             _exc_val: BaseException | None,
             _exc_tb: TracebackType | None) -> None
```

Close the underlying httpx.Client and release the connection pool.

Called by the engine's 'with' block after Phase 6 (Teardown) completes,
or immediately if an unhandled exception propagates out of the block.
Does not suppress exceptions (returns None, which is falsy).

<a id="src.core.client.SecurityClient.request"></a>

#### request

```python
def request(
    method: str,
    path: str,
    test_id: str,
    headers: dict[str, str] | None = None,
    json: object | None = None,
    content: bytes | None = None,
    params: dict[str, Any] | None = None
) -> tuple[httpx.Response, EvidenceRecord]
```

Perform an HTTP request and return the response with an evidence record.

This is the single method that all test implementations call for every
HTTP transaction. It enforces the full retry policy, constructs the
EvidenceRecord, and raises SecurityClientError on non-recoverable failure.

The caller (the test) is responsible for:
- Deciding whether to pass the record to store.add_fail_evidence()
or store.pin_evidence() based on the response status.
- Never calling both methods on the same record (contract documented
in BaseTest to prevent duplicate entries in EvidenceStore).

Redirect behavior: if the server responds with 3xx, the response is
returned as-is with the 3xx status code. The test observes the redirect
and can record it as evidence if relevant to the security guarantee
under test (e.g., Test 1.5 verifies that HTTP redirects to HTTPS).

**Arguments**:

- `method` - HTTP method, case-insensitive. Normalized to uppercase.
- `path` - API path relative to base_url. Must start with "/".
- `Example` - "/api/v1/users/me".
- `test_id` - The test_id of the calling test (e.g., "1.2").
  Used to generate the EvidenceRecord.record_id.
- `headers` - Optional request headers. If an Authorization header is
  present, its value appears as "[REDACTED]" in the
  EvidenceRecord (enforced by EvidenceRecord's validator).
- `json` - Optional request body, serialized to JSON by httpx.
  Mutually exclusive with content.
- `content` - Optional raw request body as bytes.
  Mutually exclusive with json.
- `params` - Optional query string parameters.
  

**Returns**:

  Tuple of (httpx.Response, EvidenceRecord).
  The EvidenceRecord captures the full transaction including the
  redacted Authorization header and the truncated response body.
  

**Raises**:

- `SecurityClientError` - If the request fails after all retry attempts
  due to a transport-layer error (connection refused, timeout,
  protocol error). NOT raised for 4xx or 5xx HTTP responses —
  those are valid responses returned normally.
- `RuntimeError` - If called outside of a 'with' block (i.e., before
  __enter__ or after __exit__). This is a programming error in
  the caller, not a security assessment error.

<a id="src.tests.base"></a>

# src.tests.base

src/tests/base.py

BaseTest: abstract base class defining the contract for all test implementations.

Every security test in the tool is a concrete subclass of BaseTest. The engine
interacts exclusively with this interface — it never inspects the internal
implementation of a test. This design makes adding new tests a purely additive
operation: create a file in the correct domain directory, subclass BaseTest,
implement execute(), and the test is automatically discovered by TestRegistry.

Contract guarantees that BaseTest enforces:

    1. Class-level metadata attributes (test_id, priority, strategy, etc.)
       must be declared on every concrete subclass. TestRegistry inspects
       these at discovery time; tests with missing attributes are excluded.

    2. execute() must always return a TestResult. It must never raise.
       Any exception that escapes execute() is a contract violation — the
       engine is not required to handle it and will abort the pipeline.

    3. A TestResult(status=FAIL) must contain at least one Finding.
       Enforced by TestResult's model_validator, not here.

    4. Metadata propagation: every _make_* helper copies ClassVar metadata
       (test_name, domain, priority, strategy, tags, cwe_id) into the
       returned TestResult, so builder.py needs no knowledge of tests/.

    5. Transaction log propagation: every _make_* helper includes
       list(self._transaction_log) in the returned TestResult.
       The log accumulates via _log_transaction() during execute() and is
       automatically included in the result regardless of which exit path
       the test takes (PASS, FAIL, SKIP, or ERROR).

_log_transaction() calling convention:
    After every client.request() call, the test must call _log_transaction()
    to record the interaction in the audit trail. The method accepts the
    oracle_state so the test can annotate the semantic meaning of the
    response (e.g. 'ENFORCED', 'BYPASS', 'RATE_LIMIT_HIT') independently
    of the HTTP status code.

    Pattern:
        response, record = client.request(method, path, test_id=self.test_id)

        if response.status_code in BYPASS_CODES:
            store.add_fail_evidence(record)
            self._log_transaction(record, oracle_state="BYPASS", is_fail=True)
            findings.append(Finding(...))
        else:
            self._log_transaction(record, oracle_state="ENFORCED")

    The is_fail=True flag links the TransactionSummary to the corresponding
    EvidenceRecord in evidence.json via record_id, so the HTML report can
    highlight the entry and provide a cross-reference for the analyst.

Dependency rule:
    This module imports from stdlib, structlog, abc, and src.core only.
    It must never import from config/, discovery/, report/, or engine.py.
    Test subclasses import from src.tests.base and src.core; they must not
    import from other test modules to avoid coupling between domains.

<a id="src.tests.base.BaseTest"></a>

## BaseTest Objects

```python
class BaseTest(ABC)
```

Abstract base class for all APIGuard security test implementations.

Concrete subclasses must:
    1. Declare all ClassVar metadata attributes listed below.
    2. Implement the execute() method.
    3. Call self._log_transaction() after every SecurityClient.request().
    4. Ensure execute() never raises — all exceptions must be caught
       internally and returned as TestResult(status=ERROR).

Instance-level state:
    __init__ initialises self._transaction_log as an empty list.
    This is an instance variable — not a ClassVar — so each test instance
    maintains its own independent audit trail. Since TestRegistry creates
    each test class exactly once and the engine calls execute() exactly
    once per instance, no reset mechanism is needed.

ClassVar attributes (inspected by TestRegistry at discovery time):

    test_id: str
        Unique test identifier. Format: '{domain}.{sequence}', e.g. '1.2'.

    priority: int
        Execution priority level, 0 (most critical) to 3 (least critical).

    strategy: TestStrategy
        Execution privilege level (BLACK_BOX, GREY_BOX, WHITE_BOX).

    depends_on: list[str]
        List of test_id values that must execute before this test.

    test_name: str
        Human-readable name of the security guarantee being verified.

    domain: int
        Domain number (0-7) matching the methodology chapter.

    tags: list[str]
        Categorical labels for filtering and reporting.

    cwe_id: str
        Primary CWE identifier for the vulnerability class this test verifies.

<a id="src.tests.base.BaseTest.__init__"></a>

#### \_\_init\_\_

```python
def __init__() -> None
```

Initialise the per-instance transaction log.

This is a concrete __init__ on an ABC, which is valid and necessary.
Without it, each test subclass would need to explicitly define __init__
or the _transaction_log attribute would not exist before execute() runs.

The list is instance-level (not ClassVar) to ensure that each test
instance accumulates its own independent audit trail. A ClassVar would
cause all instances of the same class to share one list, which would
corrupt the audit trail if the class were instantiated more than once
within a single pipeline run.

No other instance state is initialised here. All data required by
execute() arrives via its parameters (target, context, client, store).

<a id="src.tests.base.BaseTest.execute"></a>

#### execute

```python
@abstractmethod
def execute(target: TargetContext, context: TestContext,
            client: SecurityClient, store: EvidenceStore) -> TestResult
```

Execute the security test and return a result.

INVARIANT: this method must ALWAYS return a TestResult.
It must NEVER raise an exception. Use _make_error() in a top-level
try/except to catch unexpected exceptions.

Transaction log usage:
Call self._log_transaction(record, oracle_state=...) after every
client.request(). The _make_* helpers automatically include the
accumulated log in the returned TestResult. Example:

try:
response, record = client.request(
method="GET", path=path, test_id=self.test_id
)
except SecurityClientError as exc:
return self._make_error(exc)

if response.status_code in BYPASS_CODES:
store.add_fail_evidence(record)
self._log_transaction(record, oracle_state="BYPASS", is_fail=True)
findings.append(Finding(..., evidence_ref=record.record_id))
else:
self._log_transaction(record, oracle_state="ENFORCED")

**Arguments**:

- `target` - Immutable knowledge about the target API.
- `context` - Mutable state accumulated during the assessment.
- `client` - Centralized HTTP client. Never import httpx directly.
- `store` - Evidence buffer for FAIL and pinned transactions.
  

**Returns**:

  A TestResult with status PASS, FAIL, SKIP, or ERROR.

<a id="src.tests.base.BaseTest.has_required_metadata"></a>

#### has\_required\_metadata

```python
@classmethod
def has_required_metadata(cls) -> bool
```

Check whether all required ClassVar metadata attributes are declared.

Called by TestRegistry on each discovered subclass before adding it
to the active test set.

**Returns**:

  True if all required attributes are present with non-empty values.
  False otherwise.

<a id="src.core.models.results"></a>

# src.core.models.results

src/core/models/results.py

Test result models for the APIGuard Assurance tool.

Contains the complete result hierarchy produced by test executions and
accumulated by the engine over a pipeline run.

    Finding     -- Unit of technical evidence produced by a FAIL result.
    InfoNote    -- Informational annotation for PASS results (non-violation context).
    TestResult  -- Complete outcome of a single BaseTest.execute() call.
    ResultSet   -- Ordered collection of all TestResult objects for a pipeline run.

Dependency rule: this module imports only from pydantic, the stdlib, and
sibling modules within src.core.models. It must never import from any other
src/ package.

<a id="src.core.models.results.Finding"></a>

## Finding Objects

```python
class Finding(BaseModel)
```

A single unit of technical evidence produced when a test detects a
violation of a security guarantee.

Deliberately free of severity judgment. The tool provides objective
technical evidence; severity assessment is delegated to the analyst
or external risk-scoring systems.

One TestResult(status=FAIL) must contain at least one Finding.
One TestResult may contain multiple Findings for distinct violations.

<a id="src.core.models.results.Finding.must_not_be_empty"></a>

#### must\_not\_be\_empty

```python
@field_validator("title", "detail")
@classmethod
def must_not_be_empty(cls, value: str) -> str
```

Reject empty strings for mandatory narrative fields.

<a id="src.core.models.results.InfoNote"></a>

## InfoNote Objects

```python
class InfoNote(BaseModel)
```

A non-security-finding annotation attached to a PASS TestResult.

InfoNote is semantically distinct from Finding:

    Finding  -- evidence of a security guarantee VIOLATION.
                Attached only to FAIL results. Counted in totals.
                Rendered in red in the HTML report.

    InfoNote -- informational annotation documenting architectural context,
                compensating controls, or observability gaps on a PASS result.
                Does NOT represent a violation. NOT counted in finding totals.
                Does NOT affect the test status or exit code.
                Rendered in blue in the HTML report.

Design rationale (Implementazione.md, Section 4.6):
    The model_validator on TestResult enforces that a PASS result must have
    zero Findings. This is correct: a PASS with findings would be a
    contradiction in terms. However, some tests need to surface contextual
    information alongside a PASS — for example, Test 4.3 Level 2, which
    PASSES via a compensating control and needs to explain the architectural
    difference between a passive healthcheck and a true circuit breaker.

    InfoNote solves this without relaxing the model_validator invariant.
    It is a separate field (TestResult.notes) that the validator does not
    constrain, and the HTML report renders it in a visually distinct blue
    card to make the semantic difference immediately clear to the analyst.

Usage:
    notes: list[InfoNote] = [
        InfoNote(
            title="Compensating Control: Upstream Passive HC",
            detail="...",
            references=["OWASP-ASVS-v5.0.0-V16.5.2"],
        )
    ]
    return TestResult(status=TestStatus.PASS, findings=[], notes=notes, ...)

<a id="src.core.models.results.InfoNote.must_not_be_empty"></a>

#### must\_not\_be\_empty

```python
@field_validator("title", "detail")
@classmethod
def must_not_be_empty(cls, value: str) -> str
```

Reject empty strings for mandatory narrative fields.

<a id="src.core.models.results.TestResult"></a>

## TestResult Objects

```python
class TestResult(BaseModel)
```

Complete outcome of a single BaseTest.execute() call.

TestResult is the only object BaseTest.execute() may return.
Raw exceptions are caught internally and converted to status=ERROR.

Transaction log (full audit trail):
    transaction_log holds every TransactionSummary accumulated by the
    test via BaseTest._log_transaction() during execute(). It is embedded
    in the HTML report as a collapsible table inside the expanded row panel.

    NO CAP is applied. The ultra-lightweight TransactionSummary design
    (~160 bytes, no body content) makes a cap architecturally unnecessary:
    - 2000 entries (worst case, Test 4.1) = 320 KB of JSON in HTML
    - Full assessment (2885 entries estimated) = 461 KB
    Both values are safe for browser rendering and Python RAM.

    Body content is absent by design. Reproducibility of FAIL payloads
    is guaranteed by EvidenceStore / evidence.json (full EvidenceRecord).
    The transaction_log provides COVERAGE proof, not payload detail.

<a id="src.core.models.results.TestResult.validate_status_finding_consistency"></a>

#### validate\_status\_finding\_consistency

```python
@model_validator(mode="after")
def validate_status_finding_consistency() -> TestResult
```

Enforce the invariant between status and findings list.

FAIL  -> findings must be non-empty (evidence is mandatory).
PASS  -> findings must be empty (no violation detected).
         notes (list[InfoNote]) are NOT constrained: a PASS result
         may carry informational annotations documenting compensating
         controls or architectural gaps without these representing
         security violations.
SKIP  -> findings empty, skip_reason must be present.
ERROR -> findings may be empty or non-empty.

<a id="src.core.models.results.ResultSet"></a>

## ResultSet Objects

```python
class ResultSet(BaseModel)
```

Ordered collection of all TestResult objects produced during a pipeline run.

Primary input to report/builder.py and source of truth for exit code
calculation. Built incrementally by the engine during Phase 5.

<a id="src.core.models.results.ResultSet.add_result"></a>

#### add\_result

```python
def add_result(result: TestResult) -> None
```

Append a TestResult to the collection.

<a id="src.core.models.results.ResultSet.compute_exit_code"></a>

#### compute\_exit\_code

```python
def compute_exit_code() -> int
```

Compute the process exit code from the current ResultSet state.

Priority: FAIL (1) > ERROR (2) > CLEAN (0).
Exit code 10 (infrastructure error) is handled upstream by the engine.

<a id="src.core.models.results.ResultSet.total_count"></a>

#### total\_count

```python
@property
def total_count() -> int
```

Total number of test results.

<a id="src.core.models.results.ResultSet.pass_count"></a>

#### pass\_count

```python
@property
def pass_count() -> int
```

Number of PASS results.

<a id="src.core.models.results.ResultSet.fail_count"></a>

#### fail\_count

```python
@property
def fail_count() -> int
```

Number of FAIL results.

<a id="src.core.models.results.ResultSet.skip_count"></a>

#### skip\_count

```python
@property
def skip_count() -> int
```

Number of SKIP results.

<a id="src.core.models.results.ResultSet.error_count"></a>

#### error\_count

```python
@property
def error_count() -> int
```

Number of ERROR results.

<a id="src.core.models.results.ResultSet.total_finding_count"></a>

#### total\_finding\_count

```python
@property
def total_finding_count() -> int
```

Total Finding objects across all FAIL results.

<a id="src.core.models.results.ResultSet.total_transaction_count"></a>

#### total\_transaction\_count

```python
@property
def total_transaction_count() -> int
```

Total TransactionSummary entries across all TestResult objects.

Represents the complete number of HTTP requests sent to the target
during the assessment. Used in the HTML report executive summary
stat card 'HTTP Requests Sent'.

<a id="src.core.models.results.ResultSet.duration_seconds"></a>

#### duration\_seconds

```python
@property
def duration_seconds() -> float | None
```

Total assessment duration in seconds. None if not yet completed.

<a id="src.core.models.enums"></a>

# src.core.models.enums

src/core/models/enums.py

Shared enumerations for the APIGuard Assurance tool.

All three enums inherit from StrEnum so their values serialize natively
to JSON strings without extra configuration.

Dependency rule: this module imports only from the stdlib.
It must never import from any other src/ module.

<a id="src.core.models.enums.TestStatus"></a>

## TestStatus Objects

```python
class TestStatus(StrEnum)
```

Possible outcomes of a single test execution.

Inherits from str so values serialize natively to JSON strings.

Semantic contract (Implementazione.md, Section 4.6):
    PASS  -- Control executed, security guarantee satisfied.
    FAIL  -- Control executed, guarantee NOT satisfied. Requires a Finding.
    SKIP  -- Not executed for an explicit, documented reason. Not a failure.
    ERROR -- Unexpected exception. Result uncertain, requires investigation.

<a id="src.core.models.enums.TestStatus.PASS"></a>

#### PASS

noqa: S105

<a id="src.core.models.enums.TestStrategy"></a>

## TestStrategy Objects

```python
class TestStrategy(StrEnum)
```

Execution privilege level mapping to the Black/Grey/White Box gradient
defined in the methodology (3_TOP_metodologia.md).

BLACK_BOX -- Zero credentials. Simulates anonymous external attacker.
GREY_BOX  -- Valid JWT tokens for at least two distinct roles.
WHITE_BOX -- Read access to Gateway configuration via Admin API.

<a id="src.core.models.enums.SpecDialect"></a>

## SpecDialect Objects

```python
class SpecDialect(StrEnum)
```

Detected dialect of the API specification source document.

SWAGGER_2 -- Swagger 2.0 (top-level ``swagger: "2.0"`` key).
OPENAPI_3 -- OpenAPI 3.x (top-level ``openapi: "3.x"`` key).

<a id="src.tests.helpers.auth"></a>

# src.tests.helpers.auth

src/tests/helpers/auth.py

Public auth dispatcher for GREY_BOX test credential acquisition.

Responsibility
--------------
This module is the single import point that every GREY_BOX test uses to
acquire authentication tokens.  It reads target.credentials.auth_type and
delegates to the appropriate implementation:

    "forgejo_token"  ->  auth_forgejo.acquire_all_tokens_if_needed()
    "jwt_login"      ->  auth_jwt_login.acquire_all_tokens_if_needed()

Adding a new auth_type requires:
    1. Implementing a module src/tests/helpers/auth_{type}.py with the
       function acquire_all_tokens_if_needed() following the same signature
       and contract as the existing implementations.
    2. Adding the new auth_type to the elif chain in acquire_tokens() below.
    3. Adding the new auth_type to the supported values in
       src/config/schema/tool_config.py CredentialsConfig.validate_credentials().
    4. Documenting the new type in the CredentialsConfig docstring.

The dispatcher is intentionally thin (< 40 lines of logic).  It contains no
token-acquisition logic of its own.  Domain knowledge lives in the
implementation modules; the dispatcher only routes.

Idempotency contract
--------------------
Every implementation must be idempotent: calling acquire_all_tokens_if_needed()
multiple times within the same pipeline run is safe.  Roles that already have
a token in TestContext are skipped without making network calls.  This allows
multiple GREY_BOX tests to call acquire_tokens() at the start of execute()
without duplicating HTTP requests or creating redundant teardown entries.

Dependency rule
---------------
This module imports from:
    - stdlib only
    - src.core.client, src.core.context, src.core.exceptions
It must never import from src.tests.domain_* or src.engine.
The implementation modules are imported lazily (inside the elif branches) to
avoid loading all implementations when only one is needed.

<a id="src.tests.helpers.auth.acquire_tokens"></a>

#### acquire\_tokens

```python
def acquire_tokens(target: TargetContext,
                   context: TestContext,
                   client: SecurityClient,
                   required_roles: frozenset[str] | None = None) -> None
```

Acquire authentication tokens for all configured roles.

Reads target.credentials.auth_type and delegates to the corresponding
implementation module.  Idempotent: roles that already have a token in
TestContext are skipped.

**Arguments**:

- `target` - TargetContext carrying credentials and auth_type.
- `context` - TestContext where acquired tokens are stored.
- `client` - SecurityClient for HTTP calls.
- `required_roles` - If provided, acquire only these roles (e.g.
  frozenset({"admin", "user_a"})). If None, acquire
  all roles that have credentials configured in
  target.credentials.
  

**Raises**:

- `AuthenticationSetupError` - If auth_type is unsupported, or if token
  acquisition fails for any required role.

<a id="src.tests.helpers.auth_forgejo"></a>

# src.tests.helpers.auth\_forgejo

src/tests/helpers/auth.py

Forgejo token acquisition helper for GREY_BOX test setup.

Responsibility
--------------
This module contains the single function that GREY_BOX tests call at the
start of their execute() method to ensure that valid API tokens are present
in the TestContext before the test logic begins.

The public API is intentionally narrow:

    acquire_all_tokens_if_needed(target, context, client)
        Iterates over all roles that have credentials configured in
        target.credentials and calls acquire_single_token() for each role
        that does not yet have a token in the TestContext.  Idempotent:
        safe to call multiple times across tests in the same pipeline run.

    acquire_single_token(target, context, client, username, password, role)
        Creates a named API token on Forgejo via POST /api/v1/users/{username}/tokens
        authenticated with HTTP Basic Auth.  Stores the token value in
        TestContext and registers the token deletion endpoint for Phase 6
        teardown with the appropriate Basic Auth header.

Forgejo token model
-------------------
Forgejo (and Gitea) uses opaque tokens, not JWTs.  The token value returned
by the API is the ``sha1`` field of the response body.  The token ID (integer)
is required to construct the teardown DELETE path.

Token naming
------------
Each created token is named ``apiguard-{8-char hex suffix}`` where the suffix
is generated via secrets.token_hex(4).  This guarantees uniqueness across
concurrent or repeated assessment runs on the same Forgejo instance without
requiring a central registry.

Dependency rule
---------------
This module imports from:
    - stdlib only: base64, secrets
    - src.core.client, src.core.context, src.core.exceptions, src.core.models
It must never import from src.tests.domain_* or src.engine.

<a id="src.tests.helpers.auth_forgejo.acquire_all_tokens_if_needed"></a>

#### acquire\_all\_tokens\_if\_needed

```python
def acquire_all_tokens_if_needed(
        target: TargetContext,
        context: TestContext,
        client: SecurityClient,
        required_roles: frozenset[str] | None = None) -> None
```

Acquire API tokens for configured roles that do not yet have a token.

Iterates over the roles defined in target.credentials and calls
acquire_single_token() for each role whose credentials are present and
whose token is not yet stored in the TestContext.  Skips roles with
missing credentials and roles that already have a token, making the
function safe to call multiple times within the same pipeline run.

This function is the standard entry point for GREY_BOX tests.  It must
be called before any test logic that requires an authenticated context.

Canonical usage pattern inside execute():

try:
acquire_all_tokens_if_needed(
target, context, client,
required_roles=frozenset({ROLE_USER_A}),
)
except AuthenticationSetupError as exc:
return self._make_error(exc)
except SecurityClientError as exc:
return self._make_error(exc)

The ``required_roles`` parameter scopes the acquisition to only the roles
the calling test actually uses.  Without it, every configured role is
attempted, which means a credential problem for an unused role (e.g.
user_b) causes an ERROR on a test that only needs user_a.

Role filtering logic:
- When ``required_roles`` is None: attempt all configured roles
(original behaviour -- safe for the first test in a pipeline that
acquires tokens on behalf of all subsequent tests).
- When ``required_roles`` is a non-empty frozenset: only attempt roles
in that set; skip all others with a DEBUG log.  Roles not in
required_roles but already present in the TestContext are left
untouched.

**Arguments**:

- `target` - Immutable target context carrying credentials and base_url.
- `context` - Mutable test context where acquired tokens are stored.
- `client` - Centralized HTTP client for all outbound requests.
- `required_roles` - Optional frozenset of role identifiers (ROLE_ADMIN,
  ROLE_USER_A, ROLE_USER_B) to acquire.  When None,
  all configured roles are attempted.
  

**Raises**:

- `AuthenticationSetupError` - If Forgejo rejects the credentials for a
  role in ``required_roles`` (HTTP 401 or 403).  Failures for roles
  not in ``required_roles`` are never raised.
- `SecurityClientError` - If a transport-layer error prevents the token
  creation request from completing (connection refused, timeout).

<a id="src.tests.helpers.auth_forgejo.acquire_single_token"></a>

#### acquire\_single\_token

```python
def acquire_single_token(target: TargetContext, context: TestContext,
                         client: SecurityClient, username: str, password: str,
                         role: str) -> None
```

Create a named API token on Forgejo and store it in the TestContext.

Makes a single POST request to /api/v1/users/{username}/tokens using
HTTP Basic Auth.  On success, stores the token value in the TestContext
and registers the token deletion endpoint for Phase 6 teardown.

The token name is generated as ``apiguard-{8-char hex}`` using
secrets.token_hex(4), guaranteeing uniqueness across runs.

Teardown registration note: Forgejo token deletion requires Basic Auth
from the token owner.  The registration therefore includes the Basic Auth
header so that the engine can authenticate the DELETE request without
needing to re-derive the credentials from the TestContext.

**Arguments**:

- `target` - Immutable target context carrying base_url.
- `context` - Mutable test context where the token is stored.
- `client` - Centralized HTTP client.
- `username` - Forgejo account username. Used in the URL path and in the
  Basic Auth header.  Never logged in plain text.
- `password` - Forgejo account password.  Never logged; always [REDACTED].
- `role` - Role identifier for storage in TestContext (e.g. ROLE_USER_A).
  

**Raises**:

- `AuthenticationSetupError` - If Forgejo returns 401 or 403, indicating
  that the credentials are invalid or the account is locked.
- `SecurityClientError` - If the HTTP request fails at the transport layer.
- `ValueError` - If the Forgejo response body is missing the expected
  ``sha1`` or ``id`` fields (malformed API response).

<a id="src.tests.helpers.auth_jwt_login"></a>

# src.tests.helpers.auth\_jwt\_login

src/tests/helpers/auth_jwt_login.py

JWT login token acquisition for GREY_BOX test setup.

This module implements the "jwt_login" auth_type: it acquires tokens by
sending a POST request to a configurable login endpoint with username and
password as a JSON body, then extracts the token from the response using a
dotted JSONPath expression.

This covers the majority of modern API frameworks that are not Forgejo/Gitea:
- crAPI  (POST /identity/api/auth/login -> {"token": "..."})
- Django REST Framework with SimpleJWT (POST /api/token/ -> {"access": "..."})
- FastAPI with python-jose (POST /auth/token -> {"access_token": "..."})
- Rails Devise Token Auth (POST /auth/sign_in -> {"data": {"token": "..."}})
- Any API that follows the pattern: POST {endpoint} + JSON body -> JWT in body

Token extraction
----------------
The token_response_path field in CredentialsConfig uses simple dot-notation
to navigate the JSON response body.  Examples:

"access_token"          -> response["access_token"]
"token"                 -> response["token"]
"data.access_token"     -> response["data"]["access_token"]

Known limitation: array indexing ("tokens[0].value") and keys that contain
literal dots are NOT supported.  If the target uses such a structure, a custom
auth implementation is required.  Document this in the consuming test's
docstring and in config.yaml.

No teardown
-----------
JWT tokens are stateless bearer tokens.  They do not require deletion via the
API when the assessment ends (unlike Forgejo opaque tokens which are created
as persistent server-side objects).  This implementation therefore registers
no teardown entries in TestContext.

If the target requires an explicit logout call to invalidate tokens, implement
a custom auth module and register the logout endpoint for teardown there.

Dependency rule
---------------
This module imports from:
- stdlib only: typing
- src.core.client, src.core.context, src.core.exceptions
It must never import from src.tests.domain_* or src.engine.

<a id="src.tests.helpers.auth_jwt_login.acquire_all_tokens_if_needed"></a>

#### acquire\_all\_tokens\_if\_needed

```python
def acquire_all_tokens_if_needed(
        target: TargetContext,
        context: TestContext,
        client: SecurityClient,
        required_roles: frozenset[str] | None = None) -> None
```

Acquire JWT tokens for configured roles that do not yet have a token.

Iterates over the roles defined in target.credentials and calls
acquire_single_token() for each role whose credentials are present and
whose token is not yet stored in the TestContext.  Idempotent: safe to
call multiple times within the same pipeline run.

Canonical usage pattern inside execute():

try:
acquire_all_tokens_if_needed(
target, context, client,
required_roles=frozenset({ROLE_USER_A}),
)
except AuthenticationSetupError as exc:
return self._make_error(exc)
except SecurityClientError as exc:
return self._make_error(exc)

**Arguments**:

- `target` - Immutable target context carrying credentials and base_url.
- `context` - Mutable test context where acquired tokens are stored.
- `client` - Centralized HTTP client for all outbound requests.
- `required_roles` - Optional frozenset of role identifiers to acquire.
  When None, all configured roles are attempted.
  

**Raises**:

- `AuthenticationSetupError` - If the target rejects the credentials for a
  role in required_roles (non-2xx response or token not found in body).
  Failures for roles not in required_roles are never raised.
- `SecurityClientError` - If a transport-layer error prevents the login
  request from completing (connection refused, timeout).

<a id="src.tests.helpers.auth_jwt_login.acquire_single_token"></a>

#### acquire\_single\_token

```python
def acquire_single_token(target: TargetContext, context: TestContext,
                         client: SecurityClient, username: str, password: str,
                         role: str) -> None
```

Acquire a JWT token for a single role via the configured login endpoint.

Sends a POST request to target.credentials.login_endpoint with the
username and password as a JSON body.  On a 2xx response, extracts the
token using token_response_path (dotted JSONPath) and stores it in
TestContext via context.set_token(role, token).

No teardown is registered: JWT tokens are stateless and do not require
deletion via API.

**Arguments**:

- `target` - Immutable target context.
- `context` - Mutable test context where the token is stored on success.
- `client` - Centralized HTTP client.
- `username` - Plaintext username (or email) for this role.
- `password` - Plaintext password for this role.
- `role` - Role identifier (ROLE_ADMIN, ROLE_USER_A, ROLE_USER_B).
  

**Raises**:

- `AuthenticationSetupError` - If login_endpoint is not configured, if the
  server returns a non-2xx status, or if the token cannot be found
  at token_response_path in the response body.
- `SecurityClientError` - On transport-layer failure.

<a id="src.tests.helpers.forgejo_resources"></a>

# src.tests.helpers.forgejo\_resources

src/tests/helpers/forgejo_resources.py

Forgejo resource creation helper for GREY_BOX tests that require persistent
objects (repositories, issues) to exist before the test logic runs.

Responsibility
--------------
Each function in this module creates a single Forgejo resource via the
Forgejo API, registers it for Phase 6 teardown in the TestContext, and
returns the full response body as a typed dict so the calling test can
extract identifiers (full_name, number, id) for subsequent requests.

Contract
--------
Every create_* function follows the same contract:

    1. Build the Authorization header from context.get_token(role).
    2. POST to the appropriate Forgejo API endpoint.
    3. Raise ForgejoResourceError on unexpected HTTP status codes.
    4. Call context.register_resource_for_teardown() immediately after a
       successful creation, before any further logic that could raise.
    5. Return the response body dict to the caller.

The teardown path for Forgejo resources (repos, issues) uses the Bearer
token stored in the TestContext — not Basic Auth — because the Gateway
forwards the Bearer token to the Forgejo backend, which applies ownership
authorization internally.  This is why repository and issue teardown
registrations do NOT include explicit headers (unlike token deletion in
auth.py).

Naming convention
-----------------
All created resources use a name prefixed with 'apiguard-' followed by a
secrets.token_hex(4) suffix to avoid collisions across assessment runs.

Dependency rule
---------------
This module imports from:
    - stdlib: secrets
    - src.core.client, src.core.context, src.core.exceptions, src.core.models
It must never import from src.tests.domain_* or src.engine.

<a id="src.tests.helpers.forgejo_resources.ForgejoResourceError"></a>

## ForgejoResourceError Objects

```python
class ForgejoResourceError(ToolBaseError)
```

Raised when a Forgejo resource creation request returns an unexpected
HTTP status code.

Distinct from SecurityClientError (transport failure) and
AuthenticationSetupError (credential rejection).  This exception covers
cases where the HTTP connection succeeded and a response was received,
but the response indicates an application-level error (e.g. 422 Unprocessable
Entity when a repository name already exists, or 404 when a user does not
exist).

The calling test must catch this and return TestResult(status=ERROR).

<a id="src.tests.helpers.forgejo_resources.ForgejoResourceError.__init__"></a>

#### \_\_init\_\_

```python
def __init__(message: str,
             path: str | None = None,
             status_code: int | None = None) -> None
```

Initialize a Forgejo resource error.

**Arguments**:

- `message` - Human-readable description of the failure.
- `path` - API path that returned the unexpected status.
- `status_code` - HTTP status code received.

<a id="src.tests.helpers.forgejo_resources.get_authenticated_user"></a>

#### get\_authenticated\_user

```python
def get_authenticated_user(target: TargetContext, context: TestContext,
                           client: SecurityClient,
                           role: str) -> dict[str, Any]
```

Fetch and return the Forgejo user record for the given role.

Calls GET /api/v1/user with the Bearer token stored in the TestContext
for the specified role.  Used by tests that need to know the username
associated with a role before constructing resource paths.

**Arguments**:

- `target` - Immutable target context carrying base_url.
- `context` - Mutable test context providing the Bearer token for the role.
- `client` - Centralized HTTP client.
- `role` - Role identifier (e.g. ROLE_USER_A).  Must have a token stored
  in context.
  

**Returns**:

  Forgejo user dict including at minimum: 'id' (int), 'login' (str).
  

**Raises**:

- `ForgejoResourceError` - If the API returns a non-200 status.
- `SecurityClientError` - On transport failure.

<a id="src.tests.helpers.forgejo_resources.create_repository"></a>

#### create\_repository

```python
def create_repository(target: TargetContext,
                      context: TestContext,
                      client: SecurityClient,
                      role: str,
                      description: str = "APIGuard assessment test repository",
                      private: bool = False) -> dict[str, Any]
```

Create a Forgejo repository owned by the user of the given role.

The repository is named 'apiguard-{8-char hex}' and registered for
Phase 6 teardown via DELETE /api/v1/repos/{owner}/{repo}.

**Arguments**:

- `target` - Immutable target context.
- `context` - Mutable test context.
- `client` - Centralized HTTP client.
- `role` - Role whose token is used to create the repository.
  The repository owner is the user associated with this role.
- `description` - Repository description string.
- `private` - If True, creates a private repository.
  

**Returns**:

  Forgejo repository dict including at minimum:
  'id' (int), 'name' (str), 'full_name' (str),
  'owner' (dict with 'login' str).
  

**Raises**:

- `ForgejoResourceError` - If the API returns an unexpected status code.
- `SecurityClientError` - On transport failure.

<a id="src.tests.helpers.forgejo_resources.create_issue"></a>

#### create\_issue

```python
def create_issue(
        target: TargetContext,
        context: TestContext,
        client: SecurityClient,
        role: str,
        repo_owner: str,
        repo_name: str,
        title: str | None = None,
        body: str = "Created by APIGuard security assessment."
) -> dict[str, Any]
```

Create an issue in an existing Forgejo repository.

The issue title defaults to 'apiguard-{8-char hex}' if not provided.
Issues are automatically closed (state=closed) when the parent repository
is deleted during teardown, so no separate issue teardown registration
is needed.

**Arguments**:

- `target` - Immutable target context.
- `context` - Mutable test context.
- `client` - Centralized HTTP client.
- `role` - Role whose token is used to create the issue.
- `repo_owner` - Username of the repository owner.
- `repo_name` - Name of the repository in which to create the issue.
- `title` - Issue title. Defaults to 'apiguard-{8-char hex}'.
- `body` - Issue body text.
  

**Returns**:

  Forgejo issue dict including at minimum:
  'id' (int), 'number' (int), 'title' (str), 'html_url' (str).
  

**Raises**:

- `ForgejoResourceError` - If the API returns an unexpected status code.
- `SecurityClientError` - On transport failure.

<a id="src.tests.helpers.forgejo_resources.list_repositories"></a>

#### list\_repositories

```python
def list_repositories(target: TargetContext,
                      context: TestContext,
                      client: SecurityClient,
                      role: str,
                      limit: int = 10) -> list[dict[str, Any]]
```

Return a list of repositories visible to the given role's user.

Uses GET /api/v1/repos/search with the authenticated user's token.
Useful for tests that need to discover existing resources before
operating on them.

**Arguments**:

- `target` - Immutable target context.
- `context` - Mutable test context.
- `client` - Centralized HTTP client.
- `role` - Role whose token is used for the search.
- `limit` - Maximum number of repositories to return (default 10).
  

**Returns**:

  List of Forgejo repository dicts. May be empty if no repositories
  are visible to the authenticated user.
  

**Raises**:

- `ForgejoResourceError` - If the API returns a non-200 status.
- `SecurityClientError` - On transport failure.

<a id="src.tests.helpers.jwt_forge"></a>

# src.tests.helpers.jwt\_forge

src/tests/helpers/jwt_forge.py

Pure JWT manipulation utility for cryptographic validation tests.

Responsibility
--------------
Provides functions to inspect, decode, and forge malformed JWT tokens for use
in security tests that verify server-side JWT validation (test 1.2, test 1.3).
All functions are pure: they take strings and return strings, with no HTTP
calls, no TestContext writes, and no side effects.

JWT structure recap
-------------------
A JWT is three Base64url-encoded segments separated by dots:
    {header_b64}.{payload_b64}.{signature_b64}

Base64url differs from standard Base64 in two ways:
    - '+' is replaced with '-'
    - '/' is replaced with '_'
    - Padding ('=') is stripped when encoding, must be re-added when decoding

Attack surface covered
----------------------
This module supports the attacks defined in methodology section 1.2:

    alg:none        -- Server must reject tokens declaring no algorithm.
    Tampered payload -- Server must re-verify the signature after any claim
                        change; a valid signature on a modified payload is
                        cryptographically invalid.
    Signature strip  -- Removing the signature segment must be treated as
                        equivalent to alg:none, not as a valid token.
    Expired token    -- Server must compare exp claim against current UTC time.
    Key confusion    -- RS256-to-HS256 attack: signing a token with HS256
                        using the RSA public key as HMAC secret. Requires the
                        public key PEM, obtainable from /.well-known/jwks.json.

What this module does NOT do
-----------------------------
    - Generate valid signed tokens (no private keys are available).
    - Validate signatures (that is the server's job, not the tester's).
    - Make HTTP requests.

Dependency rule
---------------
This module imports only from stdlib. It must never import from src.core,
src.tests, or any third-party library. The only external dependency is the
'cryptography' package for the key confusion attack, imported locally inside
forge_hs256_key_confusion() to keep it optional and scoped.

<a id="src.tests.helpers.jwt_forge.is_jwt_format"></a>

#### is\_jwt\_format

```python
def is_jwt_format(token: str) -> bool
```

Return True if the token string has the three-segment JWT structure.

Does not verify the signature or validate any claims. A token that passes
this check may still be invalid, expired, or forged. The check exists
only to determine whether JWT-specific attack functions are applicable
to a given token (Forgejo uses opaque tokens for most operations).

**Arguments**:

- `token` - The token string to inspect.
  

**Returns**:

  True if the token contains exactly two dot separators and each
  segment is non-empty. False otherwise.

<a id="src.tests.helpers.jwt_forge.decode_header"></a>

#### decode\_header

```python
def decode_header(token: str) -> dict[str, Any]
```

Decode and return the JWT header as a Python dict.

Does not verify the signature. Raises ValueError if the token is not in
JWT format or if the header segment cannot be decoded as JSON.

**Arguments**:

- `token` - A JWT string in compact serialization format.
  

**Returns**:

  Decoded header dict (e.g. {"alg": "RS256", "typ": "JWT"}).
  

**Raises**:

- `ValueError` - If the token is not in JWT format or the header is not
  valid Base64url-encoded JSON.

<a id="src.tests.helpers.jwt_forge.decode_payload"></a>

#### decode\_payload

```python
def decode_payload(token: str) -> dict[str, Any]
```

Decode and return the JWT payload as a Python dict.

Does not verify the signature. Raises ValueError if the token is not in
JWT format or if the payload segment cannot be decoded as JSON.

**Arguments**:

- `token` - A JWT string in compact serialization format.
  

**Returns**:

  Decoded payload dict (e.g. {"sub": "1", "exp": 1700000000}).
  

**Raises**:

- `ValueError` - If the token is not in JWT format or the payload is not
  valid Base64url-encoded JSON.

<a id="src.tests.helpers.jwt_forge.forge_alg_none"></a>

#### forge\_alg\_none

```python
def forge_alg_none(token: str) -> str
```

Return a JWT with the 'alg' header set to 'none' and an empty signature.

This attack (CVE-2015-9235) exploits libraries that accept unsigned tokens
when the algorithm is declared as 'none'. A secure server must reject
this token with 401 regardless of the payload's validity.

The payload is preserved unchanged from the original token. Only the
header is modified to declare alg=none and the signature is removed.

**Arguments**:

- `token` - A valid JWT string to use as the base. The payload is copied
  as-is; only the header is rewritten.
  

**Returns**:

  JWT string with alg=none header, original payload, and empty
- `signature` - '{header}.{payload}.'
  

**Raises**:

- `ValueError` - If the token is not in JWT format.

<a id="src.tests.helpers.jwt_forge.forge_tampered_payload"></a>

#### forge\_tampered\_payload

```python
def forge_tampered_payload(token: str, claim: str, new_value: Any) -> str
```

Return a JWT with one payload claim replaced, keeping the original signature.

The signature is no longer valid for the new payload. A secure server must
detect the mismatch and reject the token with 401.

This tests whether the server actually re-verifies the signature after
decoding the payload, rather than trusting the payload and ignoring the
signature.

**Arguments**:

- `token` - A valid JWT string to tamper with.
- `claim` - The claim key to replace (e.g. 'sub', 'role', 'userId').
- `new_value` - The new value to assign to the claim. Must be JSON-serializable.
  

**Returns**:

  JWT string with the modified payload and the original (now-invalid)
- `signature` - '{original_header}.{new_payload}.{original_signature}'
  

**Raises**:

- `ValueError` - If the token is not in JWT format or the payload is not
  valid JSON.

<a id="src.tests.helpers.jwt_forge.forge_expired"></a>

#### forge\_expired

```python
def forge_expired(token: str, seconds_ago: int = 3600) -> str
```

Return a JWT with the 'exp' claim set to a past Unix timestamp.

The signature is no longer valid because the payload has changed. A secure
server must reject this token with 401 because:
1. The exp claim is in the past.
2. The signature does not match the modified payload.

Test 1.3 uses this function to verify that the server enforces token
expiry independently of signature validation.

**Arguments**:

- `token` - A valid JWT string to modify.
- `seconds_ago` - How many seconds in the past to set the exp claim.
  Defaults to 3600 (one hour ago). Must be positive.
  

**Returns**:

  JWT string with exp set to (now - seconds_ago), keeping the original
  header and the original (now-invalid) signature.
  

**Raises**:

- `ValueError` - If the token is not in JWT format, seconds_ago is not
  positive, or the payload is not valid JSON.

<a id="src.tests.helpers.jwt_forge.forge_strip_signature"></a>

#### forge\_strip\_signature

```python
def forge_strip_signature(token: str) -> str
```

Return a JWT with the signature segment removed (empty string after last dot).

Distinct from forge_alg_none: the header still declares the original
algorithm. This tests whether the server rejects a token that has a valid
header and payload structure but no signature, even when the declared
algorithm is not 'none'.

Some vulnerable implementations fall back to accepting unsigned tokens if
the signature field is empty, regardless of the declared algorithm.

**Arguments**:

- `token` - A valid JWT string.
  

**Returns**:

  JWT string with empty signature: '{header}.{payload}.'
  

**Raises**:

- `ValueError` - If the token is not in JWT format.

<a id="src.tests.helpers.jwt_forge.forge_hs256_key_confusion"></a>

#### forge\_hs256\_key\_confusion

```python
def forge_hs256_key_confusion(public_key_pem: str, payload: dict[str,
                                                                 Any]) -> str
```

Return a JWT signed with HS256 using an RSA public key as the HMAC secret.

This attack (key confusion / algorithm substitution) exploits servers that
accept both RS256 and HS256 without restricting the algorithm in the header.
If the server validates the token using the public key as an HMAC secret
(because the header says HS256), the attacker-controlled token passes
verification.

A secure server must either:
a) Reject any token whose header declares an algorithm different from
the one configured for the issuer, or
b) Select the validation key based on the configured algorithm, not the
header's alg claim.

The 'cryptography' library is imported locally because this function is
only called when a JWKS endpoint is available. Keeping the import local
avoids a hard dependency at module load time and keeps the failure mode
explicit: an ImportError here means the test should SKIP, not ERROR.

**Arguments**:

- `public_key_pem` - PEM-encoded RSA public key string, typically fetched
  from /.well-known/jwks.json and converted to PEM.
  Used as the raw HMAC secret (not for RSA verification).
- `payload` - JWT payload claims dict. Must include at minimum 'sub'
  and 'exp'. Values must be JSON-serializable.
  

**Returns**:

  Compact JWT string signed with HMAC-SHA256 using the public key bytes
  as the secret: '{header}.{payload}.{hmac_signature}'
  

**Raises**:

- `ImportError` - If the 'cryptography' package is not installed.
- `ValueError` - If public_key_pem is empty or payload is not serializable.

<a id="src.tests.helpers.path_resolver"></a>

# src.tests.helpers.path\_resolver

src/tests/helpers/path_resolver.py

Context-aware path parameter resolver for the APIGuard Assurance tool.

Responsibility
--------------
This module provides the single authoritative implementation for substituting
OpenAPI path template parameters (``{param}``) with real values during test
execution.  It replaces every test-local ``_resolve_path`` function that used
a single global placeholder, enabling a two-level lookup strategy:

    1. Seed lookup    -- If the parameter name is present in the operator-supplied
                         seed dictionary (``target.path_seed``), use the real value.
                         This allows probes to reach authentication middleware
                         instead of being rejected by the backend with 404.

    2. Fallback       -- If the parameter name is NOT in the seed, substitute the
                         caller-supplied fallback string (default ``"1"``).

Why a shared helper instead of per-test functions
--------------------------------------------------
The path resolution pattern recurs in every test that probes parametric paths
(Tests 1.1, 2.1, 2.2, 2.3, ...).  Extracting it here ensures:

    - A single regex pattern handles constrained variants (``{id:[0-9]+}``).
    - The seed lookup logic is maintained in one place.
    - Unit tests for the resolver do not depend on any test domain.
    - Future tests import ``resolve_path_with_seed`` directly without
      duplicating the substitution logic.

Constrained parameter syntax
-----------------------------
Some framework routers extend the OpenAPI ``{param}`` syntax with inline
constraints, such as ``{id:[0-9]+}``.  The resolver extracts the parameter name
as the substring before the first colon inside the braces.  The seed lookup
and fallback substitution use the extracted name, not the full expression.

    Input path:  ``/api/v1/repos/{owner}/{repo}/issues/{index}``
    Seed:        ``{"owner": "mario_rossi", "repo": "test-repo"}``
    Fallback:    ``"1"``
    Result:      ``/api/v1/repos/mario_rossi/test-repo/issues/1``

    Input path:  ``/api/v1/items/{id:[0-9]+}``
    Seed:        ``{"id": "42"}``
    Fallback:    ``"1"``
    Result:      ``/api/v1/items/42``

Non-parametric paths are returned unchanged regardless of the seed content.

Dependency rule
---------------
This module imports only from stdlib and structlog.  It must never import from
src.core, src.config, src.discovery, src.engine, or any other test module.

<a id="src.tests.helpers.path_resolver.resolve_path_with_seed"></a>

#### resolve\_path\_with\_seed

```python
def resolve_path_with_seed(path: str,
                           seed: dict[str, str],
                           fallback: str = PATH_PARAM_FALLBACK_DEFAULT) -> str
```

Substitute all OpenAPI path template parameters using the seed dictionary.

For each ``{param}`` template found in ``path``:

- If the extracted parameter name is a key in ``seed``, the
corresponding seed value is used as the substitution.  This produces
a real, routable path that reaches the backend (and therefore the
authentication middleware) instead of returning 404 at the routing
layer.

- If the extracted parameter name is NOT in ``seed``, the ``fallback``
string is substituted.  The caller selects the appropriate fallback
for the probe context (generic ``"1"`` for read probes, the
``PATH_PARAM_FALLBACK_SAFE_DELETE`` constant for parametric DELETE
probes).

Non-parametric paths (no ``{...}`` segments) are returned unchanged.

The function logs a DEBUG event for each substitution so that the
assessment audit trail clearly indicates whether a real seed value or a
fallback was used for each probe.

**Arguments**:

- `path` - OpenAPI path template string, e.g.
  ``"/api/v1/repos/{owner}/{repo}/issues/{index}"``.
- `seed` - Operator-supplied dictionary mapping parameter names to real
  resource identifiers (e.g. ``{"owner": "mario_rossi"}``).
  An empty dict causes all parameters to be substituted with
  the fallback, matching the pre-seed behaviour.
- `fallback` - String to use when a parameter name is absent from ``seed``.
  Defaults to ``PATH_PARAM_FALLBACK_DEFAULT`` (``"1"``).
  

**Returns**:

  Path string with all ``{param}`` templates replaced.  For a
  non-parametric path (no template segments) this is the original string.
  

**Examples**:

  >>> resolve_path_with_seed(
  ...     "/api/v1/repos/{owner}/{repo}",
  ...     {"owner": "mario_rossi", "repo": "test-repo"},
  ... )
  "/api/v1/repos/mario_rossi/test-repo"
  
  >>> resolve_path_with_seed(
  ...     "/api/v1/users/{id}",
  ...     {},
  ...     fallback="apiguard-probe",
  ... )
  "/api/v1/users/apiguard-probe"
  
  >>> resolve_path_with_seed("/api/v1/version", {})
  "/api/v1/version"

<a id="src.tests.helpers.path_resolver.extract_param_names_from_path"></a>

#### extract\_param\_names\_from\_path

```python
def extract_param_names_from_path(path: str) -> list[str]
```

Extract all unique parameter names declared in an OpenAPI path template.

Returns the names in the order they appear in the path, deduplicated while
preserving first-occurrence order.  The same name appearing multiple times
(unusual but not impossible) is returned only once.

Constrained variants (``{id:[0-9]+}``) are normalised to the bare name
(``"id"``) using the same colon-split logic as ``resolve_path_with_seed``.

**Arguments**:

- `path` - OpenAPI path template string (e.g.
  ``"/api/v1/repos/{owner}/{repo}/issues/{index}"``).
  

**Returns**:

  Ordered, deduplicated list of parameter name strings.  Empty list if
  the path contains no template segments.
  

**Examples**:

  >>> extract_param_names_from_path("/api/v1/repos/{owner}/{repo}/issues/{index}")
  ["owner", "repo", "index"]
  
  >>> extract_param_names_from_path("/api/v1/version")
  []

<a id="src.tests.helpers.response_inspector"></a>

# src.tests.helpers.response\_inspector

src/tests/helpers/response_inspector.py

Pure response analysis utility for security tests that inspect HTTP response
bodies and headers for information disclosure and misconfiguration.

Responsibility
--------------
Provides deterministic, side-effect-free functions that analyze an HTTP
response body (str or dict) or a headers dict and return structured findings.
No HTTP requests are made here.  No TestContext writes happen here.

Used by
-------
    test 2.5  -- Excessive data exposure: sensitive field detection
    test 6.1  -- Error handling: stack trace and debug field detection
    test 6.2  -- Security headers: presence and value validation
    test 6.3  -- Layer-7 hardening: CORS wildcard detection

Design
------
All pattern lists and frozen sets are module-level constants so that the
cost of compilation is paid once at import time, not per call.  Functions
that return lists return new list objects, never views into constants, so
callers cannot accidentally mutate the module state.

Dependency rule
---------------
This module imports only from stdlib.  It must never import from src.core,
src.tests, src.engine, or any third-party library.

<a id="src.tests.helpers.response_inspector.contains_stack_trace"></a>

#### contains\_stack\_trace

```python
def contains_stack_trace(body: str) -> list[str]
```

Search a response body string for stack trace or framework leakage patterns.

Methodology reference: Garanzia 6.1 — the oracle states that response
bodies must not contain class names, file paths, or exception messages.

**Arguments**:

- `body` - Raw response body as a string.
  

**Returns**:

  List of matched pattern strings found in the body.
  Empty list if no stack trace patterns are detected.

<a id="src.tests.helpers.response_inspector.contains_sensitive_fields"></a>

#### contains\_sensitive\_fields

```python
def contains_sensitive_fields(data: dict[str, Any],
                              *,
                              nested: bool = True) -> list[str]
```

Recursively search a parsed JSON dict for sensitive field names.

Compares lowercased field names against the SENSITIVE_FIELD_NAMES set.
Optionally recurses into nested dicts and lists.

**Arguments**:

- `data` - Parsed JSON response body as a dict.
- `nested` - If True (default), recurse into nested dicts and list elements.
  If False, only inspect top-level keys.
  

**Returns**:

  Sorted list of sensitive field names found (lowercased).
  Empty list if no sensitive fields are present.

<a id="src.tests.helpers.response_inspector.extract_debug_fields"></a>

#### extract\_debug\_fields

```python
def extract_debug_fields(data: dict[str, Any]) -> list[str]
```

Return a list of field names that appear to be debug artifacts.

Checks whether any key in the dict (lowercased) contains a known debug
field substring.  Only inspects top-level keys — debug fields at
deeper nesting levels are less likely to be intentional API surface.

**Arguments**:

- `data` - Parsed JSON response body as a dict.
  

**Returns**:

  List of field names identified as debug artifacts.
  Empty list if none are found.

<a id="src.tests.helpers.response_inspector.check_security_headers"></a>

#### check\_security\_headers

```python
def check_security_headers(headers: dict[str, str]) -> dict[str, str | None]
```

Validate the presence and value of expected security headers.

For each header defined in SECURITY_HEADER_DEFINITIONS, checks whether
the header is present in the response and whether its value satisfies
the expected constraint.  Returns a dict mapping each expected header
to its actual value (or None if absent).

**Arguments**:

- `headers` - Response headers dict.  Keys are expected to be lowercase
  per RFC 9110 (SecurityClient normalizes them).
  

**Returns**:

  Dict mapping each expected security header name (lowercase) to:
  - The actual header value string if present.
  - None if the header is absent.
  Callers treat None entries as missing headers (policy violation).

<a id="src.tests.helpers.response_inspector.find_missing_security_headers"></a>

#### find\_missing\_security\_headers

```python
def find_missing_security_headers(headers: dict[str, str]) -> list[str]
```

Return a list of expected security header names that are absent.

Convenience wrapper around check_security_headers that filters to only
the headers that are missing (value is None in the result).

**Arguments**:

- `headers` - Response headers dict (keys need not be lowercase).
  

**Returns**:

  Sorted list of missing security header names.
  Empty list if all expected headers are present.

<a id="src.tests.helpers.response_inspector.find_invalid_security_headers"></a>

#### find\_invalid\_security\_headers

```python
def find_invalid_security_headers(headers: dict[str, str]) -> list[str]
```

Return a list of present security headers whose values do not meet policy.

Checks each present header against its expected constraint:
- strict-transport-security: must contain 'max-age='
- x-content-type-options: must be exactly 'nosniff'
- x-frame-options: must not be 'allow-from' (deprecated)
- content-security-policy: must not contain 'default-src *'

**Arguments**:

- `headers` - Response headers dict.
  

**Returns**:

  Sorted list of header names that are present but have invalid values.
  Empty list if all present headers satisfy their constraints.

<a id="src.tests.helpers.response_inspector.find_leaky_headers"></a>

#### find\_leaky\_headers

```python
def find_leaky_headers(headers: dict[str, str]) -> list[str]
```

Return a list of response headers that disclose server implementation details.

Checks for headers in LEAKY_HEADERS.  For the 'server' header, also checks
whether the value contains a version string (e.g. 'nginx/1.18.0' is leaky,
'nginx' alone is acceptable).

**Arguments**:

- `headers` - Response headers dict.
  

**Returns**:

  List of leaky header names found in the response.
  Empty list if no leaky headers are present.

<a id="src.tests.helpers.response_inspector.auth_errors_are_uniform"></a>

#### auth\_errors\_are\_uniform

```python
def auth_errors_are_uniform(response_bodies: list[str]) -> bool
```

Check whether multiple authentication error responses are indistinguishable.

Used by test 6.1 to verify that the API does not distinguish between
'user not found' and 'wrong password' in its error messages, which would
enable username enumeration.

Compares each response body against the first one.  If all responses are
identical (or indistinguishable by simple string comparison), returns True.

**Arguments**:

- `response_bodies` - List of raw response body strings from authentication
  failure responses.  Must contain at least two entries.
  

**Returns**:

  True if all response bodies are identical strings.
  False if any response body differs from the first (enumeration risk).
  

**Raises**:

- `ValueError` - If fewer than two response bodies are provided.

<a id="src.tests.helpers.kong_admin"></a>

# src.tests.helpers.kong\_admin

src/tests/helpers/kong_admin.py

Kong Admin API reader for WHITE_BOX (P3) configuration audit tests.

Responsibility
--------------
Provides read-only access to the Kong Admin API for configuration audit tests
(4.2, 4.3, 6.4, 1.6).  Every function in this module performs a single GET
request to the Kong Admin API and returns the parsed response body.

Design decision: direct httpx, not SecurityClient
--------------------------------------------------
This module uses httpx directly rather than SecurityClient for a deliberate
architectural reason: calls to the Kong Admin API are configuration audits,
not security test traffic against the target API.  They must NOT appear in
the EvidenceStore (which records test evidence for the report), must NOT be
retried with the same policy as target API calls, and must NOT be coupled to
the test's EvidenceRecord chain.

The Admin API is a separate trust boundary from the proxy.  Using a dedicated
lightweight httpx client with its own timeout keeps the two boundaries
explicit.

All functions accept admin_base_url as a plain string rather than TargetContext
to keep the scope narrow: callers extract the URL from target.admin_endpoint_base_url()
and pass it in.  This makes the functions testable in isolation without a full
TargetContext.

Dependency rule
---------------
This module imports from:
    - stdlib: only implicitly via httpx
    - httpx (direct, intentional exception to the SecurityClient rule)
    - structlog
It must never import from src.tests, src.engine, src.config, or src.discovery.

<a id="src.tests.helpers.kong_admin.KongAdminError"></a>

## KongAdminError Objects

```python
class KongAdminError(ToolBaseError)
```

Raised when a Kong Admin API request fails or returns an unexpected status.

Covers both transport failures (connection refused, timeout) and
application-level errors (404, 500) from the Admin API itself.

WHITE_BOX tests that call kong_admin helpers must catch this and return
TestResult(status=ERROR) or TestResult(status=SKIP) depending on whether
the Admin API is simply unavailable or erroring unexpectedly.

<a id="src.tests.helpers.kong_admin.KongAdminError.__init__"></a>

#### \_\_init\_\_

```python
def __init__(message: str,
             path: str | None = None,
             status_code: int | None = None) -> None
```

Initialize a Kong Admin API error.

**Arguments**:

- `message` - Human-readable description of the failure.
- `path` - Admin API path that was being called.
- `status_code` - HTTP status code received, or None for transport errors.

<a id="src.tests.helpers.kong_admin.get_routes"></a>

#### get\_routes

```python
def get_routes(admin_base_url: str) -> list[dict[str, Any]]
```

Fetch all routes registered in Kong and return them as a list.

Used by test 0.1 (shadow API discovery via documentation drift) to compare
the set of active Kong routes against the OpenAPI spec.

**Arguments**:

- `admin_base_url` - Base URL of the Kong Admin API, without trailing slash.
- `Example` - 'http://localhost:8001'
  

**Returns**:

  List of Kong route objects.  Each dict contains at minimum:
  'id' (str), 'paths' (list[str] | None), 'methods' (list[str] | None),
  'service' (dict with 'id').
  Empty list if no routes are configured.
  

**Raises**:

- `KongAdminError` - On transport failure or non-200 response.

<a id="src.tests.helpers.kong_admin.get_plugins"></a>

#### get\_plugins

```python
def get_plugins(admin_base_url: str) -> list[dict[str, Any]]
```

Fetch all plugins installed on Kong and return them as a list.

Used by tests 4.3 (circuit breaker audit) and 6.3 (layer-7 hardening)
to verify that expected plugins are present and correctly configured.

**Arguments**:

- `admin_base_url` - Base URL of the Kong Admin API.
  

**Returns**:

  List of Kong plugin objects.  Each dict contains at minimum:
  'id' (str), 'name' (str), 'enabled' (bool), 'config' (dict).
  

**Raises**:

- `KongAdminError` - On transport failure or non-200 response.

<a id="src.tests.helpers.kong_admin.get_services"></a>

#### get\_services

```python
def get_services(admin_base_url: str) -> list[dict[str, Any]]
```

Fetch all services registered in Kong and return them as a list.

Used by test 4.2 (timeout audit) to read connect_timeout, read_timeout,
and write_timeout values configured on each upstream service.

**Arguments**:

- `admin_base_url` - Base URL of the Kong Admin API.
  

**Returns**:

  List of Kong service objects.  Each dict contains at minimum:
  'id' (str), 'name' (str | None),
  'connect_timeout' (int), 'read_timeout' (int), 'write_timeout' (int).
  

**Raises**:

- `KongAdminError` - On transport failure or non-200 response.

<a id="src.tests.helpers.kong_admin.get_upstreams"></a>

#### get\_upstreams

```python
def get_upstreams(admin_base_url: str) -> list[dict[str, Any]]
```

Fetch all upstreams registered in Kong and return them as a list.

**Arguments**:

- `admin_base_url` - Base URL of the Kong Admin API.
  

**Returns**:

  List of Kong upstream objects.
  

**Raises**:

- `KongAdminError` - On transport failure or non-200 response.

<a id="src.tests.helpers.kong_admin.get_plugin_by_name"></a>

#### get\_plugin\_by\_name

```python
def get_plugin_by_name(admin_base_url: str,
                       plugin_name: str) -> dict[str, Any] | None
```

Return the first enabled plugin matching plugin_name, or None.

Fetches all plugins and filters by name.  If no matching plugin is found
(either because the plugin is not installed or is disabled), returns None.
The caller decides whether the absence of a plugin is a FAIL or a SKIP.

**Arguments**:

- `admin_base_url` - Base URL of the Kong Admin API.
- `plugin_name` - Exact Kong plugin name (e.g. 'rate-limiting',
  'circuit-breaker', 'jwt').
  

**Returns**:

  First matching plugin dict (enabled or disabled), or None if no plugin
  with that name is registered.
  

**Raises**:

- `KongAdminError` - On transport failure or non-200 response.

<a id="src.tests.helpers.kong_admin.get_status"></a>

#### get\_status

```python
def get_status(admin_base_url: str) -> dict[str, Any]
```

Fetch the Kong node status endpoint and return the response.

Used as a connectivity check before WHITE_BOX tests begin.  If this call
succeeds, the Admin API is reachable and the other functions will work.

**Arguments**:

- `admin_base_url` - Base URL of the Kong Admin API.
  

**Returns**:

  Kong status dict containing node information and database connectivity.
  

**Raises**:

- `KongAdminError` - On transport failure or non-200 response.


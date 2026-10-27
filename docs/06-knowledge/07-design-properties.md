# Design Properties

> **Audience:** readers of the research, contributors · **Status:** the thesis catalogue of architectural
> properties (39 properties in 7 domains), adapted to English and updated to the code of 2026-10-20; properties
> added or changed since the thesis are marked · **Source of truth:** the code; where each property lives is
> described in [`architecture/`](../04-architecture/01-overview.md), linked from each entry · **Verified:** 2026-10-20

Why the tool is built the way it is: each property states what holds, what follows from it, how it can be checked,
and what it makes possible. What the code does in detail, file by file, is in
[`architecture/overview.md`](../04-architecture/01-overview.md); the decisions taken after the thesis are in
[`architecture/design-decisions.md`](../04-architecture/05-design-decisions.md) (D1-D9).

Each entry: **Definition**, **Consequences**, **Evidence** (by construction: visible in the code; empirical: shown by
a run), **Possible developments** (research ideas, not plans), **In the docs**.

## D1. Architecture and design

### D1.P1 API agnosticism

**Definition.** The tool contains no path, endpoint, data structure or behaviour of a specific application. What it
knows of the target comes at runtime from two sources: `config.yaml` (connections, credentials, prepared resources,
test parameters) and the target's OpenAPI specification, from which the attack surface is built.

**Consequences.** A test that finds no applicable endpoint in the attack surface returns SKIP (an expected
condition), not ERROR. Shadow APIs are the one intended exception: they are by definition the endpoints the
specification does not list, and test 0.1 looks for them. Since the thesis the remaining Forgejo knowledge moved into
configuration: login, the objects a test creates and the revocation request are prepared resources (D6). Gateway
knowledge stays isolated in the gateway adapters.

**Evidence.** Empirical: the same code runs on three labs, Forgejo and OWASP crAPI behind Kong and Forgejo behind
APISIX, with only their configurations differing.

**Possible developments.** Any documented REST API can be assessed: a Kubernetes API server, Stripe, GitHub
Enterprise, internal microservices.

**In the docs.** [Design principles](../04-architecture/01-overview.md#design-principles),
[Test portability](../03-reference/06-compatibility.md#test-portability).

### D1.P2 Unidirectional dependency flow

**Definition.** The module dependency graph is acyclic and points one way: `core/` ← `connectors/` ← `tests/` and
`external_tests/` ← `engine.py`. `config/` never imports `tests/`; `core/`, `connectors/` and the tests never import
`config/`, `discovery/`, `report/` or the CLI; native tests never import `connectors/`.

**Consequences.** Changing a test cannot break `core/`. Changing `core/` breaks tests only if its public interface
changes, and the break is visible statically. A new module in a layer needs no change in the layers above (except
`engine.py`, the coordinator).

**Evidence.** By construction, and checked automatically since the thesis: `lint-imports` (import-linter) runs in
`hatch run dev:check` with the contracts in `pyproject.toml`.

**Possible developments.** Unit testing of `core/` independently of the security tests, packaging as a library,
replacing a layer without touching the others.

**In the docs.** [Module structure and dependencies](../04-architecture/01-overview.md#module-structure-and-dependencies).

### D1.P3 Split state and immutability

**Definition.** State is split in two objects of opposite nature: `TargetContext`, what is known before execution
(frozen Pydantic model, built once), and `TestContext`, what tests obtain or create during the run (mutable, through
typed interfaces only): the **token** channel (`set_token`, `get_token`, `has_token`, `stored_roles`, keyed by role),
the **teardown** channel (`register_resource_for_teardown`, `drain_resources`, LIFO), the **shared data** channel
(`set_shared`, `get_shared`, keys named `"{test_id}.{data_name}"`), and, since the thesis, the run's **secret
registry** (`register_secret`), which the redaction of every output uses.

**Consequences.** A test cannot corrupt the inputs of the others. A missing token is a handled `None`, not a silent
`KeyError`. Tests can pass data to later tests without import dependencies between modules.

**Evidence.** By construction (`frozen` model, typed methods). Empirical: test 1.4 stores a credential through the
token channel and registers what it creates for teardown.

**Possible developments.** Parallel execution: tests that read only `TargetContext` need no lock; synchronisation
for `TestContext` is already confined to its interfaces.

**In the docs.** [Runtime contexts](../04-architecture/02-data-model.md#runtime-contexts).

### D1.P4 Two test hierarchies on one base

**Definition.** Native tests (`BaseTest`, HTTP through `SecurityClient`) and external tests (`ExternalToolTest`, a
tool through a connector) are two hierarchies with separate contracts; since the thesis both derive from one base,
`AssessmentTest` in `core/`, which holds what they share (the `TestInfo` declaration, the result helpers). Both
produce a `TestResult` whose `source` is `native` or `external`; the engine selects the `execute()` signature with
one `isinstance` check.

**Consequences.** An external test does not inherit what it cannot use (transaction logging through
`SecurityClient`), and what both need is written once. The report tells native results from tool results.

**Evidence.** By construction (`src/core/assessment_test.py`, `src/tests/base.py`, `src/external_tests/base.py`).
Empirical: 0.1 (native) and ext.0.1.ffuf (external) in the same domain, told apart in `evidence.json` and the
report.

**Possible developments.** A third hierarchy (for example LLM-assisted tests) adds a branch in the dispatch without
changing the existing contracts.

**In the docs.** [Components](../04-architecture/01-overview.md#components), D8.

### D1.P5 Three-tier connector hierarchy

**Definition.** Wrappers around external tools have three levels: `BaseConnector` (the universal contract),
`BaseSubprocessConnector` (tools run as a process: testssl.sh, nuclei, ffuf, schemathesis) and
`BaseLibraryConnector` (tools used as a Python library). `BaseLibraryConnector` has no concrete connector at present
and stays as the documented extension point for one. Each level carries only the mechanisms of its integration
pattern; `src/connectors/_template_connector.py` is the template for new ones.

**Consequences.** `TestsslConnector` does not inherit the library check (`importlib.util.find_spec`), and a
library connector would not inherit the binary resolution or `_run_subprocess()`. The public contract (`run()`,
`is_available()`, `get_version()`) is the same: the calling test does not know how the tool is integrated.

**Evidence.** Empirical: the subprocess tier is exercised by ext.0.1.ffuf and ext.1.5.testssl. The library tier is
not exercised by a concrete connector today (sslyze, its first user, was removed in the test review); the tier's
`importlib`-based availability and version checks remain in `BaseLibraryConnector`.

**Possible developments.** A new tool needs only a subclass of the right level, with no change to `BaseConnector` or
to the tests that use it.

**In the docs.** [`add-an-external-test.md`](../02-guides/03-extending/03-add-an-external-test.md).

### D1.P6 Gateway-agnostic adapters (changed since the thesis)

**Definition.** WHITE_BOX tests read the gateway through `target.gateway`, a `BaseGatewayAdapter` in `core/gateway/`.
Since the thesis the interface is made of **neutral concepts**, not of one product's objects: `backend_timeouts()`,
`circuit_breakers()`, `health_checks()`, `signing_policies()`, `routes()`, `config_values()`, `target_health()`, each
returning a read, "not supported" or "not accessible" outcome. Adapters exist for Kong and APISIX, chosen by
`gateway.adapter` from a registry (`GATEWAY_ADAPTERS`). A test that needs the gateway declares `Need.GATEWAY` and is
recorded as SKIP before it runs when there is none.

**Consequences.** No test contains Kong or APISIX knowledge, including the ones that read the gateway
([test portability](../03-reference/06-compatibility.md#test-portability) lists them); a new gateway is a new
adapter class and a registry entry, with no change to the tests. Each concept read is kept once as evidence, after masking.

**Evidence.** Empirical: Forgejo behind Kong and behind APISIX give the same native results with the same tests.

**Possible developments.** Other gateways (Amazon API Gateway, Azure API Management, Apigee, Traefik, NGINX) through
new adapters.

**In the docs.** D7, [`add-a-gateway-adapter.md`](../02-guides/03-extending/04-add-a-gateway-adapter.md).

## D2. Extensibility and maintainability

### D2.P1 Dynamic test discovery (changed since the thesis)

**Definition.** There is no central list of tests. The registries scan the domain packages for modules named
`test_X_Y_*` and `ext_test_X_Y_*` (`src/core/test_discovery.py`); since the thesis each test module holds its own
declaration, `info = TestInfo(...)` (ID, name, priority, strategy, CWE, tags, prerequisites, needs, tool), and its
parameter model.

**Consequences.** Adding a test is one file in the right directory with the right name; its parameters appear in the
configuration schema and in the generated documentation. A test declared incorrectly (invalid or missing `TestInfo`,
duplicate ID, module that cannot be imported) stops the tool at startup with `TestDefinitionError` (exit 10): the
thesis version only logged a warning and went on, which could silently drop a test.

**Evidence.** By construction: no test list in `src/engine.py`; `apiguard list-tests` shows what was discovered.

**Possible developments.** A plugin system: test packages contributed by third parties, discovered without changing
the core (for example a GraphQL test package).

**In the docs.** D8, [`add-a-native-test.md`](../02-guides/03-extending/02-add-a-native-test.md).

### D2.P2 Dependency scheduling on a DAG (changed since the thesis)

**Definition.** The run order comes from a directed acyclic graph of the prerequisites each test declares, sorted
with `graphlib.TopologicalSorter`; the output is a list of batches (tests without mutual dependencies in the same
batch, batches in sequence). Since the thesis there are two kinds of prerequisite: `depends_on` (the test uses data
the prerequisite produces: it runs if the prerequisite completed, PASS or FAIL) and `requires_pass` (the test is
meaningful only if the prerequisite holds: it runs if the prerequisite passed).

**Consequences.** A cycle is caught in Phase 4, before any test runs (`DAGCycleError`, exit 10). A prerequisite not
met, including one left out by the selection, gives SKIP with a reason naming it, and the skip propagates; the thesis
version ignored a missing prerequisite with a warning. Tokens are not a reason for a prerequisite: every test obtains
them through `acquire_tokens()`, in any order. No test declares a prerequisite today.

**Evidence.** By construction (`src/core/dag.py`). The thesis example (1.4 depending on 1.1) no longer applies.

**Possible developments.** Each batch is parallelisable: a thread pool in Phase 5 is a local change, once
`TestContext` and `EvidenceStore` are made thread-safe.

**In the docs.** [Dependencies between tests](../04-architecture/03-assessment-model.md#dependencies-between-tests).

### D2.P3 Data separated from evaluation

**Definition.** A connector does not decide whether something fails: it returns the tool's output, parsed, in a
`ConnectorResult` (raw output, exit code, timeout flag, duration). The external test judges it against its oracle in
`_evaluate()`.

**Consequences.** One connector can serve tests with different oracles: the `NucleiConnector`, for instance, could
back both a discovery test and an injection test (it is in the codebase, not wired to a test now). A connector can
be checked on its own (is the output parsed correctly?) without a security oracle.

**Evidence.** Empirical: a connector returns every result and the test decides — ext.1.5.testssl partitions
testssl.sh's findings into FAIL, notes and ignored by severity; ext.0.1.ffuf treats the paths that answered as its
results.

**Possible developments.** The same connector can serve new domains (for example nuclei templates for OWASP API10,
unsafe consumption of APIs).

**In the docs.** [`add-an-external-test.md`](../02-guides/03-extending/03-add-an-external-test.md).

### D2.P4 Connector life cycle by injection

**Definition.** The external test registry injects shared connectors into the test instances before execution: one
`is_available()` check per tool, then either `_injected_connector` (tool available) or `_skip_reason_from_registry`
(tool missing: the test returns SKIP at once).

**Consequences.** With N tests on one tool, availability is checked once and one log line is written instead of N;
the connector instance is shared.

**Evidence.** Empirical: one availability entry per tool in the discovery log, whatever the number of tests using it.

**Possible developments.** A connector pool holding persistent connections to tools run as services.

**In the docs.** [`add-an-external-test.md`](../02-guides/03-extending/03-add-an-external-test.md).

### D2.P5 Authentication: method and placement (changed since the thesis)

**Definition.** `src/tests/helpers/auth.py` is the one entry point for credentials. Since the thesis two things are
kept apart: the **method**, how a credential is obtained (`auth_type`: `basic`, `static_token`, `login`, one class
each in `AUTH_METHODS`), and the **placement**, where and how it is sent (header, query or cookie, name, prefix),
resolved once per run from the specification's security schemes and `send_as`. `acquire_tokens()` obtains each
role's credential once and stores it in `TestContext`; `auth_parts()` gives the request parts for a role. The thesis
had two Forgejo-oriented helpers (`auth_forgejo.py`, `auth_jwt_login.py`) and every test wrote `Bearer` itself.

**Consequences.** A new method is a class and an entry in `AUTH_METHODS`, with no change to the tests. N tests
calling `acquire_tokens()` cause one login per role. A credential that cannot be obtained gives the test ERROR
(`AuthenticationSetupError`); a placement that cannot be resolved stops the run before any test (exit 10).

**Evidence.** Empirical: Forgejo (`login`, `token` prefix on its declared scheme) and crAPI (`login`, bearer scheme)
run with the same tests.

**Possible developments.** OAuth2 client credentials, SSO, mTLS as further methods.

**In the docs.** D5, [configuration](../03-reference/01-configuration.md).

### D2.P6 Category A/B connector classification

**Definition.** Connectors are classified by their role for a guarantee: **Cat A** (needed for full coverage of a
HYBRID guarantee: the native test covers part, the tool the rest) and **Cat B** (optional: the guarantee is covered
natively, the tool widens detection); **Cat C** tools were evaluated and discarded.

**Consequences.** The classification orders development: Cat A connectors complete a guarantee (testssl.sh for 1.5),
Cat B ones only widen it. An enabled but missing Cat A tool gives its external test SKIP, and the native test for the
same guarantee still runs.

**Evidence.** Empirical: ext.0.1.ffuf returns SKIP with a reason when ffuf is missing, while 0.1 still runs.

**Possible developments.** A policy for contributions: a Cat B connector needs no change to the test; a Cat A one
completes a HYBRID guarantee.

**In the docs.** [Native, hybrid and external tools](../04-architecture/03-assessment-model.md#native-hybrid-and-external-tools),
[`tools/`](04-tool-decisions.md).

### D2.P7 Path seed for parametric paths

**Definition.** Paths with parameters (`/repos/{owner}/{repo}/issues/{index}`) are filled from `target.path_seed`,
a map of parameter names to real values on the deployment. `apiguard generate-seed` reads the specification and
writes a template with every parameter name; `src/tests/helpers/path_resolver.py` resolves a path with the seed, and
falls back to `"1"` (`PATH_PARAM_FALLBACK_DEFAULT`) or, for DELETE, to `"apiguard-probe"`
(`PATH_PARAM_FALLBACK_SAFE_DELETE`); constrained parameters such as `{id:[0-9]+}` are read by name.

**Consequences.** Without a seed, a probe on a parametric path often gets `404` and is judged
`NOT_VERIFIABLE/NOT_FOUND_LIKE_UNKNOWN` instead of reaching the authentication check; with a seed the same paths give `ENFORCED/CREDENTIAL_REQUIRED` or
`VIOLATION/SERVED_WITHOUT_CREDENTIAL`. The DELETE fallback is a non-numeric value unlikely to match a real object: a request that slips past the
gateway finds nothing to delete.

**Evidence.** Empirical: test 1.1 on Forgejo with and without `path_seed`.

**Possible developments.** Seeds taken from `example` values in the specification, or from paths found active by
test 0.1: a self-configuring loop.

**In the docs.** [CLI](../03-reference/02-cli.md), [configuration](../03-reference/01-configuration.md).

### D2.P8 Test data catalogues

**Definition.** Attack payloads, wordlists and recognition patterns live in pure-data modules in `src/tests/data/`
(stdlib only, no logic): `ssrf_payloads.py` (73 SSRF payloads in six categories), `auth_payloads.py` (5 malformed
tokens), `shadow_wordlists.py` (shadow API candidates), `inspector_patterns.py` (27 stack trace patterns, 33
sensitive field names). Consumers import them; they import no consumer.

**Consequences.** A new payload (a new cloud metadata endpoint) is one line, with no change to the test logic.
Structures are built once at import (for example the normalised sensitive names as a `frozenset`) for constant-time
lookups. Test 7.2 selects payload categories from configuration.

**Evidence.** By construction (the modules contain only data). Empirical: the number of 7.2 probes follows its
configured categories.

**Possible developments.** The catalogues as a separately reviewed and updated package, useful where attack payloads
must be approved apart from the code.

**In the docs.** The test pages in [`tests/`](../05-tests/README.md).

## D3. Configuration and reproducibility

### D3.P1 Configuration-driven (changed since the thesis)

**Definition.** Every tunable parameter lives in `config.yaml`: infrastructure in its sections, test parameters under
`tests.domain_X.test_X_Y.<param>`. Since the thesis each test declares its parameter model in its own module and
reads it with `self.params(target)`; the `tests:` section is checked against those models. The configuration is
checked as written: unknown and duplicate keys are rejected, `${VAR}` placeholders are interpolated after parsing,
and every run writes `config_used.yaml`, the whole configuration it used, each key marked `# specified` or
`# default`, with secrets as placeholders.

**Consequences.** An operator adapts the tool (timeouts, request counts, payload categories, prepared resources)
without touching the code. A run can be repeated from its own `config_used.yaml`: the defaults hidden in the code
become visible.

**Evidence.** By construction (`src/config/`). Empirical: `validate-config --show-config` prints what a run would use.

**Possible developments.** Distribution as a container or package where the operator brings only a configuration;
profiles per environment.

**In the docs.** D9, [configuration](../03-reference/01-configuration.md),
[Test parameters](../04-architecture/02-data-model.md#test-parameters-declared-by-the-test).

### D3.P2 Single sources of truth

**Definition.** Each kind of fact has one source: the tests' own declarations for the implementation state, read by
`apiguard list-tests` and by the generated catalogue `docs/05-tests/README.md` (the thesis used `PROJECT_status.md`,
then `roadmap.md`, both hand-written), `config.yaml` for operational parameters, the `AttackSurface` built from the specification
for the target's topology, and `src/config/loader.py` as the only reader of the environment. Since the thesis the two
documented exceptions are gone (the tool-as-a-service variable and the Docker URL override, see
[Removed](#properties-removed-since-the-thesis)): no other module reads `os.environ`.

**Consequences.** Every test works on the same view of the endpoints. The path of each credential, from `.env` or the
CI environment to the configuration, is one and auditable; `.env` never overrides variables already set.

**Evidence.** By construction: searching `src/` for `os.environ` and `os.getenv` finds only `loader.py`.

**Possible developments.** A "diff assessment": two attack surfaces of successive runs compared to find endpoints
added or removed between API versions.

**In the docs.** [Three sources of truth](../04-architecture/02-data-model.md#three-sources-of-truth),
[Secrets](../04-architecture/04-security-model.md#secrets).

### D3.P3 Knowledge and privilege gradient (changed since the thesis)

**Definition.** Each test declares its strategy (`BLACK_BOX`, `GREY_BOX`, `WHITE_BOX`): what the tester has, and so
what the test may use. The registry filters on the strategies enabled in `execution.strategies`. The thesis coupled
strategy and priority (P0 black box, P1-P2 grey box, P3 white box) as a recommendation; the owner decided that they
are independent: the priority says how important a guarantee is, the strategy what the test needs.

**Consequences.** A black box run simulates an outside attacker and needs no account; a white box run needs the
administrator account or the gateway's Admin API. The thesis's "documented deviations" are no longer deviations: 7.2
is P0 and GREY_BOX because SSRF on Forgejo is reachable only when authenticated; 1.5 and 6.2 are BLACK_BOX because
TLS and response headers can be observed from outside.

**Evidence.** By construction (`TestInfo.strategy`). Empirical: the strategy matrix generated from the declarations.

**Possible developments.** Graduated assessments: P0 at every deploy, P0 and P1 at every release, everything at a
periodic review.

**In the docs.** [`02-methodology.md`](02-methodology.md#knowledge-and-privilege-gradient),
[Strategies](../04-architecture/03-assessment-model.md#strategies-knowledge-and-privilege-of-the-tester).

### D3.P4 Reproducibility

**Definition.** The same configuration on the same unchanged target gives the same results: tests run strictly in
sequence, in a deterministic order (discovery sorted by test ID, topological sort), on an immutable `TargetContext`.

**Consequences.** An assessment repeated a week later on an unchanged target gives equivalent output, timestamps and
generated IDs aside: a condition for an assurance tool, since a result that cannot be repeated is not evidence.

**Evidence.** By construction (sorting in the registries, `src/core/dag.py`). Empirical, since the thesis:
`scripts/compare_reports.py` compares two reports; fresh labs give identical results run after run (for example
test 1.1 on 2026-10-06, with the detail names of the time: 78 `AUTH_BYPASS`, 63 `INCONCLUSIVE_PARAMETRIC`,
311 `ENFORCED` on two independent Forgejo
labs).

**Possible developments.** With traceability (D5.P1), two `evidence.json` of the same target compared over time to
find security regressions between releases.

**In the docs.** [Pipeline](../04-architecture/01-overview.md#pipeline).

### D3.P5 No external state at runtime

**Definition.** The tool depends on no database, broker, external cache or persistent connection besides the target's
HTTP API and, when configured, the gateway's Admin API. State lives in memory (`TargetContext`, `TestContext`) or in
local files under the output directory.

**Consequences.** The tool runs wherever Python 3.11+ reaches the target, with no service to set up. This is what makes
its exit codes reliable in CI: there is no external service whose readiness must be checked first.

**Evidence.** By construction: no database or broker client among the dependencies in `pyproject.toml`.

**Possible developments.** A multi-target mode would need an external store to coordinate parallel assessments: an
opt-in extension, not an implicit requirement.

**In the docs.** [Packaging](../04-architecture/01-overview.md#packaging).

## D4. Robustness and security

### D4.P1 Streaming evidence store

**Definition.** `EvidenceStore` does not accumulate records in memory: for each native test it writes a JSONL file
in `evidence_tmp/` record by record, with a flush; in Phase 7 the files are merged in time order into `evidence.json`
and the directory is removed.

**Consequences.** Test 1.1 can produce hundreds of failure records without loss. The thesis's earlier version, a
bounded `deque`, silently evicted the oldest records, leaving `evidence_ref` values pointing at nothing: a broken
audit trail. If a run stops between Phase 5 and Phase 7, the JSONL files stay on disk, readable.

**Evidence.** Empirical: 1.1 on Forgejo stores more than 100 records with every `evidence_ref` resolving in
`evidence.json`.

**Possible developments.** JSONL can be ingested directly by log aggregators (Elasticsearch, Splunk, Loki).

**In the docs.** [Dual audit trail](../04-architecture/02-data-model.md#dual-audit-trail),
[evidence format](../03-reference/05-evidence-format.md).

### D4.P2 Centralised redaction (changed since the thesis)

**Definition.** Redaction is not left to the code that produces data. Two central mechanisms: `pin_artifact()`
sanitises tool output before it is stored, by key (a word-boundary pattern on 9 names such as `token`, `password`,
`api_key`, `authorization`, `secret`, `auth`), by value (strings shaped like a JWT) and by prefix (`Bearer `,
`Basic `, `Token `, `token `); and, since the thesis, the run's secret registry, which holds every configured
password, token and Admin API header value and masks them in every output when they are 8 characters or longer.

**Consequences.** A connector that forgets to mask a field does not leak it. A JWT under an arbitrary key is still
masked. A new pattern is one change in one place.

**Evidence.** Empirical: searching the outputs of the lab runs for each lab password, token and Admin API key finds
none.

**Possible developments.** Patterns configurable for unusual naming (`X-Custom-Auth`).

**In the docs.** [Secrets](../04-architecture/04-security-model.md#secrets), [Outputs](../04-architecture/04-security-model.md#outputs).

### D4.P3 Errors isolated per test

**Definition.** `execute()` never propagates an exception to the engine: an unexpected error becomes a
`TestResult(ERROR)` inside the test (`_error()`), and the engine calls `execute()` without a handler around it.

**Consequences.** A test that fails unexpectedly gives ERROR and the run goes on with the next one; no test can stop
another. Robustness is a property of the contract, not a defence in the engine.

**Evidence.** By construction (`src/engine.py`, the test bases). Empirical only when an unexpected error happens.

**Possible developments.** Distributed execution: a remote worker can send back a `TestResult(ERROR)` without its
failure reaching the engine.

**In the docs.** [Errors](../04-architecture/01-overview.md#errors).

### D4.P4 Exception hierarchy mapped to phases

**Definition.** Every exception of the tool derives from `ToolBaseError`, with a defined phase: `ConfigurationError`
(Phase 1), `TestDefinitionError` (after Phase 1, added since the thesis), `OpenAPILoadError` (Phase 2),
`DAGCycleError` (Phase 4) stop startup; `SecurityClientError`, `AuthenticationSetupError`, `ExternalToolError`
(Phase 5) become ERROR in the test; `TeardownError` (Phase 6) is a warning. `GatewayAdapterError` sits next to the
adapter base; `SeedGeneratorFetchError` and `SeedGeneratorParseError` belong to the `generate-seed` command only, and
never reach the assessment pipeline. A missing tool is not an exception: it gives SKIP.

**Consequences.** Callers catch exactly what they mean (`ConfigurationError`, or any `ToolBaseError`); bare
`except Exception: pass` is forbidden. A setup failure (credential not obtained) is told apart from a transport
failure. Gateway readers turn `GatewayAdapterError` into "not accessible", and the tests SKIP or add a note.

**Evidence.** By construction (`src/core/exceptions.py` and the two other files).

**Possible developments.** New phases add classes (for example a report rendering error) without touching the
existing handlers.

**In the docs.** [Errors](../04-architecture/01-overview.md#errors), [exit codes](../03-reference/03-exit-codes.md).

### D4.P5 Graceful degradation (changed since the thesis)

**Definition.** The tool degrades at several levels: a missing external tool gives SKIP for its tests; a test whose
needs the configuration does not meet (administrator or user account, gateway, revocable login) is recorded as SKIP
before it runs, with the reason (`TestInfo.needs`, since the thesis); `external_tools.enabled: false` schedules no
external test.

**Consequences.** A run without an Admin API, or in CI without external tools, gives partial but correct results
instead of cascading errors; each SKIP says why, and the engine warns about unmet needs before the first test.

**Evidence.** Empirical: on crAPI, 1.4 returns SKIP because its login cannot revoke a credential.

**Possible developments.** Use where binaries cannot be installed: native tests only.

**In the docs.** [Selecting tests](../04-architecture/03-assessment-model.md#selecting-tests).

### D4.P6 Best-effort teardown

**Definition.** Whatever a test creates on the target is registered in `TestContext` as soon as it is created; in
Phase 6 the engine drains the register in LIFO order and sends each delete request. Since the thesis what a test
creates and how it is deleted are prepared resources declared in `config.yaml` (D6). A failed deletion is logged as a
warning (`TeardownError`) and does not invalidate the results.

**Consequences.** The target is left as it was found; LIFO deletes the objects created last first, so an object created
inside another is removed before its container. A failure is an operational warning naming what to remove by hand.

**Evidence.** Empirical: after the lab runs, the leftover check finds nothing created by the tool.

**Possible developments.** Retries with backoff for targets that rate-limit their delete endpoints.

**In the docs.** [Teardown](../04-architecture/01-overview.md#teardown), D6.

### D4.P7 Safe HTTP probing

**Definition.** Test 1.1 does not reduce a response to PASS or FAIL: it judges each probe
`ENFORCED/CREDENTIAL_REQUIRED` (`401`/`403`), `VIOLATION/SERVED_WITHOUT_CREDENTIAL` (`2xx` without credentials) or
one of several `NOT_VERIFIABLE` outcomes (not found on a parametric path or not, a request validated without a
credential, a redirect, rate limited, server error, transport error), and separates paths without parameters from
parametric ones. Destructive methods are treated apart: a parametric DELETE uses the safe fallback `"apiguard-probe"`, a DELETE
without parameters (for example `/api/delete-all`) is never sent and is judged
`NOT_VERIFIABLE/DESTRUCTIVE_NOT_PROBED`.

**Consequences.** The tool does not destroy data even when the gateway lets unauthenticated requests through. "The
gateway does not protect this endpoint" (a FAIL with HTTP evidence) is kept apart from "this could not be checked"
(reported, not counted): counting every `404` as a failure would give false positives unacceptable for assurance.

**Evidence.** Empirical: 1.1's oracle states on Forgejo.

**Possible developments.** A confidence score of the assessment from the share of inconclusive probes.

**In the docs.** [Oracles and verdicts](../04-architecture/03-assessment-model.md#oracles-and-verdicts), the 1.1 test page.

### D4.P8 Fail-fast on P0

**Definition.** With `execution.fail_fast: true`, Phase 5 stops after the first P0 test that returns FAIL or ERROR.
Both stop the run: an ERROR on a P0 check is an incomplete perimeter check, as blocking in a CI gate as a confirmed
violation.

**Consequences.** A pipeline stops at the first critical problem without waiting for the whole assessment. Unlike
the exit code (D6.P1), which reports after the run, fail-fast decides whether to stop early; teardown and the report
still run, and the tests not started are listed in the report's `not_run`.

**Evidence.** By construction (`AssessmentEngine._check_fail_fast()`).

**Possible developments.** A configurable predicate (per domain or priority range).

**In the docs.** [Fail-fast](../04-architecture/03-assessment-model.md#fail-fast).

### D4.P9 Result invariants enforced by the type

**Definition.** Three invariants of `TestResult` are enforced when it is built, by a Pydantic `model_validator`:
FAIL requires at least one finding, PASS requires none, SKIP requires a `skip_reason`.

**Consequences.** An inconsistent result cannot be built, let alone reach the report; the validator is the single
point that enforces the status-evidence contract, not a convention every caller must remember. It is distinct from
the meaning of Finding and InfoNote (D5.P2) and from error isolation (D4.P3).

**Evidence.** By construction (`TestResult.validate_status_finding_consistency()`).

**Possible developments.** Further invariants (for example a recorded duration) without changing the callers.

**In the docs.** [Results](../04-architecture/02-data-model.md#results).

## D5. Quality and observability

### D5.P1 Traceability to the methodology

**Definition.** Each test carries the references of the guarantee it checks, in its `TestInfo`: the ID that matches
the methodology (`X.Y`), the CWE and tags (OWASP, RFC); each Finding carries its `references`. The report shows them
next to the result.

**Consequences.** An analyst can go from a finding to the methodology's guarantee, the OWASP category, the CWE and
the RFC: the report is a traceable document, not an opaque output.

**Evidence.** Empirical: any report with a FAIL.

**Possible developments.** Compliance scores computed from the tags and CWEs of passed and failed tests (OWASP ASVS,
NIST SP 800-53).

**In the docs.** [Guarantees, domains, tests](../04-architecture/03-assessment-model.md#guarantees-domains-tests).

### D5.P2 Finding and InfoNote

**Definition.** A **Finding** is a violation (only in FAIL, counted, with references and evidence); an **InfoNote**
is context the analyst must know but that is not a violation (a compensating control, a sub-test that could not run,
an ambiguous result, an item to verify by hand). A PASS cannot hold findings.

**Consequences.** Test 4.3 can pass on a compensating control (passive health checks instead of a circuit breaker)
and explain it in a note, without weakening "a PASS has no findings".

**Evidence.** Empirical: 4.3 on the Kong lab.

**Possible developments.** Notes for partial compliance, instead of a fifth status that would complicate
aggregation.

**In the docs.** [Oracles and verdicts](../04-architecture/03-assessment-model.md#oracles-and-verdicts).

### D5.P3 One authoritative function per operation

**Definition.** Operations that would otherwise be duplicated have one authoritative place:
`_relativize_display_path()` in `connectors/base.py` for paths in displayed commands, the role constants
(`ROLE_ADMIN`, `ROLE_USER_A`, `ROLE_USER_B`), `pin_artifact()` and the secret registry for redaction,
`response_inspector.py` for response inspection (used by 6.2; the thesis listed 2.5, 6.1 and 6.3, which do not exist
yet), and, since the thesis, `EXIT_CODES` for the meaning of each exit code (report, console, `run --help` and the
reference).

**Consequences.** A change of format, a new role or a new pattern is one change, picked up everywhere.

**Evidence.** By construction: one definition of each, imported elsewhere.

**Possible developments.** Roles as an enumeration, so that an undeclared role is an error rather than `None`.

**In the docs.** [`coding-rules.md`](../02-guides/03-extending/01-coding-rules.md).

### D5.P4 Structured logging without credentials

**Definition.** Logging uses `structlog` with key-value events; `print()` is forbidden. Credential values are never
logged: log events carry identifiers, methods, paths and status codes, and the HTTP client logs no headers or bodies.

**Consequences.** Logs are machine-readable (ELK, Loki, `jq`) and a leaked log exposes no token or password.

**Evidence.** By construction: no `print(` in `src/`; log calls checked for credential values.

**Possible developments.** Filtering by test ID, domain or priority as structured fields.

**In the docs.** [Secrets](../04-architecture/04-security-model.md#secrets).

### D5.P5 Report split by domain and source

**Definition.** The report builder groups results by domain (`DomainSummary`) and, within each domain, separates
native rows from external ones by their `source`.

**Consequences.** An analyst sees at once whether a FAIL in domain 1 came from a native test (with an HTTP request
that can be replayed) or from a tool (with its raw output).

**Evidence.** Empirical: a report with 1.5 and ext.1.5.testssl in domain 1.

**Possible developments.** Reports per audience: native failures only for an executive summary, everything for a
technical review.

**In the docs.** [report schema](../03-reference/04-report-schema.md).

## D6. CI/CD and developer experience

### D6.P1 Exit codes with a meaning (changed since the thesis)

**Definition.** The process exit code reflects the run, defined once in `EXIT_CODES`: `0` clean, `1` at least one
FAIL, `2` invalid invocation, `3` at least one ERROR and no FAIL, `10` infrastructure error that stops the run, `130`
and `143` interrupted (SIGINT, SIGTERM). FAIL prevails over ERROR. The thesis had ERROR as `2`.

**Consequences.** A pipeline can gate on the exit code alone. `10` tells "the assessment did not start" from "it ran
and found problems".

**Evidence.** By construction (`EXIT_CODES` in `src/core/models/enums.py`). Empirical: an invalid configuration gives `10`.

**Possible developments.** The thesis proposed a reserved `3` for "FAIL only on P2/P3"; `3` is now ERROR, so such a
policy would need another code or a priority option.

**In the docs.** [exit codes](../03-reference/03-exit-codes.md).

### D6.P2 Development cache for external tools

**Definition.** With `external_tools.<tool>.dev_mode: true`, an external test reads the tool's output from a local
cache (`<label>_output.json` in the tools output directory, written by an earlier real run) instead of running the
tool.

**Consequences.** Iterating on an external test's oracle takes seconds instead of a full tool run (testssl.sh takes
tens of seconds). It is off by default; a cache hit is visible (no tool version, zero execution time). It must never
be used in a real assessment.

**Evidence.** Empirical: a second run with `dev_mode` starts no subprocess.

**Possible developments.** A snapshot mode for the whole pipeline: regression tests of the oracles without network.

**In the docs.** [`add-an-external-test.md`](../02-guides/03-extending/03-add-an-external-test.md),
[External tools](../04-architecture/04-security-model.md#external-tools).

### D6.P3 Two layers of type safety

**Definition.** Two independent layers: **mypy strict** before execution (`strict = true` with the Pydantic plugin in
`pyproject.toml`, part of `hatch run dev:check`, on GitHub too since the thesis), and **Pydantic v2 validators** at
the system boundaries at runtime (configuration, connector output, results).

**Consequences.** A wrong type in internal code is caught by mypy; invalid data from outside (for example an enabled
tool without `timeout_seconds`) is caught when the configuration loads, with the key named, not in the middle of a
run.

**Evidence.** By construction: `hatch run dev:check` passes; `validate-config` rejects an invalid configuration with
the key's path.

**Possible developments.** A `py.typed` marker (PEP 561) so that external test packages get the same checks.

**In the docs.** [`coding-rules.md`](../02-guides/03-extending/01-coding-rules.md).

## D7. Packaging and deployment

### D7.P1 Binary resolution

**Definition.** `BaseSubprocessConnector` looks for its binary first in the project's tools directory
(`./tools/<LOCAL_TOOLS_SUBDIR>/<BINARY_NAME>`, when the connector sets a subdirectory) and then on `PATH`
(`shutil.which`). The thesis had a third channel, the tool reached as an HTTP service; it was removed (see
[Removed](#properties-removed-since-the-thesis)).

**Consequences.** The same connector works with a pinned copy installed by `install_tools.sh` and with a system
installation, with no deployment-specific code. No binary found means `is_available()` is false and the test is SKIP.

**Evidence.** By construction (`_resolve_binary()`).

**Possible developments.** Tools as long-running services shared by several runs, if a working design is made.

**In the docs.** [External tools](../04-architecture/04-security-model.md#external-tools).

### D7.P2 Optional dependency for a non-required tool (changed since the thesis)

**Definition.** A tool that is not required for the core to run is declared as an optional extra in
`[project.optional-dependencies]`, not among the required dependencies, and its connector imports the library only
inside `run()`, so the package still imports when the extra is not installed. Today the only such extra is
`schemathesis` (`pip install "apiguard-assurance[schemathesis]"`).

**History (sslyze).** The original instance of this property was sslyze, whose transitive `nassl` is AGPL v3: it was
an optional extra so a standard installation carried no AGPL code. In the test review sslyze was removed entirely
(AGPL, and no added value over testssl.sh for guarantee 1.5), which resolves the licence concern at the source
rather than isolating it in an extra. The project's own licence is still undecided (`pyproject.toml` leaves it
unspecified on purpose; the choice is tracked in `roadmap.md`).

**Evidence.** By construction: a non-required tool is absent from `[project] dependencies` and present among the
optional ones.

**Possible developments.** The same pattern for any heavy or licence-restricted component.

**In the docs.** [Packaging](../04-architecture/01-overview.md#packaging), [compatibility](../03-reference/06-compatibility.md).

## Properties added since the thesis

The decisions taken after the thesis are recorded in
[`design-decisions.md`](../04-architecture/05-design-decisions.md); each is also a property of the tool:

| Property | Definition | Decision |
|---|---|---|
| Configuration by connection | Each party the tool talks to has one section of the same shape (address, timeouts, `tls` block, what it needs): `target` (the API), `specification`, `gateway` (`adapter`, `admin`, `health`); `execution` keeps only what the run does. | D1 |
| Certificate trust per connection | Each connection has its own `tls` block (private authorities, inspecting proxies, client certificates), independent of the others. | D2 |
| The tool downloads the specification | The specification is downloaded by the tool with the settings of `specification` (certificates, timeout), not by prance's own HTTP client. | D3 |
| Labs at the highest protection level | The labs exercise the paths real systems need: one certificate authority generated at start (no private key in the repository), every connection verified, Admin APIs over HTTPS (APISIX with a client certificate), the backend reachable only through the gateway. | D4 |
| Method and placement of a credential | How a credential is obtained and where it is sent are separate (D2.P5). | D5 |
| Prepared resources | What a test creates on the target, and how it is deleted, is declared in configuration and used by name. | D6 |
| Neutral gateway concepts | Tests read concepts (timeouts, circuit breakers, signing policies...), not one gateway's objects (D1.P6). | D7 |
| A test is self-contained | A test module holds its declaration, its parameter model and its documentation (D2.P1). | D8 |
| The configuration as written and as used | Keys checked as written; every run writes the configuration it used (D3.P1). | D9 |

## Properties removed since the thesis

| Thesis property | What it was | Why it is gone |
|---|---|---|
| D7.P3 Deployment-transparent URL (`effective_base_url`) | An environment variable (`APIGUARD_TARGET_EFFECTIVE_URL`) overriding the target URL when the tool ran in Docker Compose. | Never functional; removed (CHANGELOG). The target URL is the configured one. |
| Channel 2 of D7.P1 (tool as an HTTP service) | A `<TOOL>_SERVICE_URL` variable to reach an external tool as a service instead of a binary. | Never functional; removed (CHANGELOG). A missing tool gives SKIP. |

## Summary

| Domain | Properties |
|---|---|
| D1 Architecture and design | P1 API agnosticism, P2 unidirectional dependencies, P3 split state, P4 two test hierarchies, P5 three-tier connectors, P6 gateway adapters |
| D2 Extensibility and maintainability | P1 test discovery, P2 DAG scheduling, P3 data separated from evaluation, P4 connector injection, P5 authentication method and placement, P6 Cat A/B, P7 path seed, P8 test data catalogues |
| D3 Configuration and reproducibility | P1 configuration-driven, P2 single sources of truth, P3 knowledge and privilege gradient, P4 reproducibility, P5 no external state |
| D4 Robustness and security | P1 streaming evidence, P2 centralised redaction, P3 errors isolated per test, P4 exception hierarchy, P5 graceful degradation, P6 best-effort teardown, P7 safe probing, P8 fail-fast, P9 result invariants |
| D5 Quality and observability | P1 traceability, P2 Finding and InfoNote, P3 one authoritative function, P4 structured logging, P5 report split |
| D6 CI/CD and developer experience | P1 exit codes, P2 development cache, P3 two layers of type safety |
| D7 Packaging and deployment | P1 binary resolution, P2 optional licence-restricted dependency |

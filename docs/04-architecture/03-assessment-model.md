# Assessment Model

> **Audience:** analysts, integrators, contributors · **Status:** v0.1.0 · **Source of truth:** test class metadata
> (`src/tests/`, `src/external_tests/`), `src/config/schema/tool_config.py` (`ExecutionConfig`), `src/engine.py`,
> `src/core/models/results.py`; methodology concepts from
> [`06-knowledge/03-methodology.md`](../06-knowledge/03-methodology.md) · **Verified:** 2026-10-20

How the tool organises, selects and judges its checks. Per-test details: [`tests/`](../05-tests/README.md).

## Guarantees, domains, tests

The methodology ([framework](../06-knowledge/03-methodology.md)) defines **29 security guarantees in 8 domains** (0 API discovery and inventory, 1 identity and
authentication, 2 authorization, 3 data integrity, 4 availability and resilience, 5 visibility and auditing,
6 configuration and hardening, 7 business logic and sensitive flows). A test verifies one guarantee:

- native test `X.Y` = guarantee `Y` of domain `X`, implemented in Python (`BaseTest`);
- external test `ext.X.Y.tool` = the same guarantee checked with an external tool (`ExternalToolTest` +
  connector). Several tools may cover one guarantee.

The tool implements 29 native and 3 external tests across the 8 domains (`apiguard list-tests`).

## Strategies (knowledge and privilege of the tester)

The strategy says what the tester has, and so what a test may use: only a `WHITE_BOX` test reads the gateway
configuration or acts as administrator; the others observe responses (the gradient and its rationale:
[framework](../06-knowledge/03-methodology.md#knowledge-and-privilege-gradient)). Each test is labelled with the
access it needs to run in full (`src/core/models/enums.py`, `TestStrategy`).

| Strategy | Tester has |
|---|---|
| `BLACK_BOX` | an external user: network access and the OpenAPI specification only, no credentials |
| `GREY_BOX` | a normal user: credentials of an ordinary account (`user_a`) |
| `WHITE_BOX` | a super user: the API's administrator account (`admin`), or internal access (gateway Admin API, files, internal systems) |

Among the WHITE_BOX tests, 1.4 needs the admin account; 3.3, 4.2, 4.3 and 6.4 the gateway Admin API (6.4 sub-test A
needs only the network). The tests by strategy and priority are in the table under [Priorities](#priorities).

## Priorities

A guarantee's priority says how important it is: how serious a violation is for an API in general (the criterion,
after the OWASP risk rating: [framework](../06-knowledge/03-methodology.md#priorities)).

| Priority | Importance |
|---|---|
| P0 Critical | the top risks of the OWASP API Security Top 10, and the perimeter controls every gateway must enforce |
| P1 High | business-critical controls |
| P2 Medium | application logic and defence in depth |
| P3 Low | best practice and compliance |

The implemented tests by strategy and priority (generated from the tests' declarations):

<!-- [[[cog import generate_docs as g; cog.out(g.strategy_matrix()) ]]] -->

| Strategy | P0 | P1 | P2 | P3 |
|---|---|---|---|---|
| `BLACK_BOX` | `0.1`, `0.2`, `0.3`, `1.1`, `4.1`, `ext.0.1.ffuf` | `2.4`, `4.4`, `7.1`, `7.4` | `1.5`, `6.4`, `ext.1.5.testssl`, `ext.3.1.schemathesis` | `6.2` |
| `GREY_BOX` | `1.2`, `1.3`, `2.2`, `7.2` | `1.7`, `2.1`, `2.5`, `7.3` | `6.1` | `1.6` |
| `WHITE_BOX` | `0.4` | `4.2`, `4.3`, `5.1` | `1.4`, `5.2` | `3.3` |

<!-- [[[end]]] -->

**Priority and strategy are independent.** The priority says how serious a violation of the guarantee is
(criterion above); the strategy says what the tester needs to run the test. A critical test can need
credentials (7.2 is P0 and GREY_BOX) and a configuration audit can be important (4.2 and 4.3 are P1 and WHITE_BOX).

## Selecting tests

Configured in `execution` ([`reference/configuration.md`](../03-reference/01-configuration.md#execution)):

1. `test_ids` non-empty → only the listed IDs, native or external (a listed test of a disabled tool still does not
   run). Priority and strategy filters ignored.
2. Otherwise `min_priority` keeps tests with `priority <= min_priority`, and `strategies` keeps the tests, native
   and external, whose strategy is listed.
3. External tests are scheduled only if their tool is enabled (`external_tools`).
4. Prerequisites (`depends_on`, `requires_pass`) order the run; a test whose prerequisite is not met, including
   one left out by the selection, returns SKIP ([dependencies between tests](#dependencies-between-tests)).

A test declares what it needs from the configuration (`TestInfo.needs`: `ADMIN_ACCOUNT`, `USER_ACCOUNT`, `GATEWAY`,
`REVOCABLE_LOGIN`; and its parameters marked needed to run). When one is missing the engine records the test as
SKIP before running it, with the reason (`src/core/test_needs.py`), and warns about it before the first test; 6.4
needs no gateway and skips its sub-test B without one. The strategy says who the tester is; the needs say what the
configuration must hold.

## Dependencies between tests

A test declares two lists of prerequisites (`src/core/dag.py`). Both make the prerequisites run first.

| Attribute | Use it when | The test runs if each prerequisite | Otherwise |
|---|---|---|---|
| `depends_on` | the test **uses data** that only the prerequisite produces (`TestContext` shared data) | completed: `PASS` or `FAIL` | `SKIP` |
| `requires_pass` | the test is **meaningful only if** the prerequisite holds (checking details of a mechanism that does not work proves nothing) | returned `PASS` | `SKIP` |

A prerequisite not in the run (left out by `test_ids`, `min_priority`, `strategies`, or a disabled tool) counts as
not met: the prerequisite is never added to the run automatically. The `SKIP` reason names it, for example
`Prerequisite not met: it is meaningful only if 1.1 passes; 1.1 returned FAIL.`, and a skip propagates to the tests
that depend on the skipped one. The test is not executed.

Declare a prerequisite only when one of the two cases is true. Tokens are not a reason: every test that needs one
calls `acquire_tokens()` (`src/tests/helpers/auth.py`), which obtains each role's credential once and reuses the one
stored in `TestContext`, in any order. No test declares a prerequisite today. A prerequisite that names no existing test, or
the test itself, stops the tool at startup (exit `10`).

## Oracles and verdicts

Every test judges what it observes against its own **oracle**: the source of truth for that guarantee (for example
the OpenAPI specification for 1.1, the gateway configuration for 4.2, the transport-security requirements (HTTP
to HTTPS redirect, HSTS) for 1.5). Each test page
states its oracle. The oracles are checked against the methodology and the standards it cites; when an oracle is
judged reliable, its verdict is trusted.

Anything that differs from the oracle is reported. The tool's job is to **find** the differences; deciding whether
a difference is intended belongs to the analyst. Example: the Forgejo specification declares every endpoint as
protected, while Forgejo serves public data without credentials; test 1.1 reports those reads as findings, because
they differ from the specification. If they are intended, the specification is what needs fixing.

## Outcomes

| Status | Meaning | Exit code effect |
|---|---|---|
| `PASS` | The guarantee holds for what was tested. | none |
| `FAIL` | The guarantee is violated; at least one Finding with evidence. | → 1 |
| `INCONCLUSIVE` | The run finished but verified nothing: no violation and no case enforced, only not-verifiable or not-applicable cases. Not a pass. | → 3 if no FAIL |
| `ERROR` | The check could not be completed (transport failure, rejected credentials, tool failure, unexpected exception). | → 3 if no FAIL |
| `SKIP` | A precondition is missing; `skip_reason` says which. Not a pass. | none |

The status is computed from the sub-tests, not chosen by the test (`combine_sub_tests`; a violation makes it FAIL,
a verified case PASS, a not-verifiable case INCONCLUSIVE). A PASS is bounded by what the test covers: it carries
`coverage` (`COMPLETE`, or `PARTIAL` when some cases were not verifiable), and each test page lists the methodology
sub-tests that are not implemented and the test's known limitations.

**Finding vs InfoNote.** A Finding is a violation, with references (the standard and its identifier: OWASP, ASVS, WSTG, NIST, RFC; by
default the test's) and, for an HTTP probe, an
`evidence_ref` to the proving transaction (set by `_judge()`); a finding from a gateway-configuration audit references the gateway concept it read instead. An InfoNote is context the analyst must know but that is not a
violation: a compensating control, a sub-test that could not run, an ambiguous result (e.g. SSRF probe timeout),
an item requiring manual verification.

**Transaction judgement.** Each judged HTTP transaction in a test's audit trail carries four fields: a `category`
(what the response is, common to every test: `SERVED`, `NOT_FOUND`, `UNAUTHENTICATED`, ...), the `sub_test` it
belongs to, an `outcome` (what it means for the guarantee: `VIOLATION`, `ENFORCED`, `NOT_VERIFIABLE`,
`NOT_APPLICABLE`) and a test-specific `detail` (e.g. `AUTH_BYPASS`, `PATH_NOT_FOUND`), read together as
`outcome/detail` (`VIOLATION/AUTH_BYPASS`). Categories and outcomes are common to all tests; the details are
defined per test and listed on each test page. A request that is not judged (a login, an object created for the
test) carries a null `outcome`.

**Reference responses: calibration and positive controls.** An oracle that reads an HTTP response needs to know
what the target answers in two baseline cases, or it mistakes one thing for another (a `404` because the endpoint
does not exist, read as "access enforced"). The run builds these **reference responses** once and shares them
through `TestContext.references` (`src/core/references.py`), each probe pinned in evidence:

- **Calibration** (`CalibrationPoint`): what "does not exist here" looks like. Two requests to random sibling paths
  of the same shape (`sibling_pattern`), with the judged request's method and credential; when both answer alike
  the point is *reliable* and carries a fingerprint. A judged response that matches it is "not there", not
  "refused". `gateway_refusal()` is the special case: what the gateway answers when none of its routes matches.
- **Positive control** (`PositiveControl`): whether a request works with a valid credential (a `2xx`). It proves
  the operation exists and the credential is valid, so a later `403` / `404` means the control is enforced, not
  that the endpoint is missing. The caller chooses the credential of the role the endpoint is meant for.

A verdict that rests on reference responses records their `record_id`s in the finding's `supporting_refs`, so the
reader sees the baseline the judgement stood on. This is why a test reports `NOT_VERIFIABLE` rather than a false
PASS when calibration is unreliable or a positive control does not work.

## Fail-fast

`execution.fail_fast: true` stops Phase 5 after the first **P0** test that returns FAIL or ERROR. Teardown and
reporting still run; tests not yet started are listed in the report's `not_run` with reason `fail_fast`.

## Native, hybrid and external tools

The tool research classifies each guarantee and each candidate tool ([`06-knowledge/`](../06-knowledge/05-tool-decisions.md)):

| Term | Meaning |
|---|---|
| NATIVE | Python covers the guarantee; an external tool would add no value. |
| NATIVE + optional | Native, with an optional Cat B tool as complement. |
| HYBRID | Python covers part of the guarantee; Cat A external tools cover the rest. |
| Cat A tool | Connector to implement; needed for full coverage of a HYBRID guarantee (implemented: nuclei, testssl.sh). |
| Cat B tool | Optional connector, a native fallback exists. |
| Cat C tool | Evaluated and discarded (abandoned, out of scope, or no added value). |

If a Cat A tool is enabled but not installed, its test returns SKIP; the native test for the same guarantee still
runs.

## Rules every test follows

The contract the block-6 review built every test on; the code and the test pages cite these by number ("rule N").

| # | Rule | In the code |
|---|---|---|
| 1 | **Two steps of judgement.** A response gets a category from a closed list (IANA-based); each test maps categories to an outcome (`VIOLATION`, `ENFORCED`, `NOT_VERIFIABLE`, `NOT_APPLICABLE`) with a detail (`UPPER_SNAKE_CASE`): that table is its oracle. | `src/core/response_category.py`, `src/core/models/enums.py`, `BaseTest._judge` |
| 2 | **Sub-tests and computed status.** A test declares its sub-tests; each judgement belongs to one; the status is computed from the counters (FAIL > PASS complete or partial > INCONCLUSIVE > SKIP), never chosen; a finding exactly with a `VIOLATION`. | `TestInfo.sub_tests`, `AssessmentTest._record`, `_finish`, `src/core/models/results.py` |
| 3 | **Reference responses.** A verdict that depends on "does this exist, is this refused" rests on calibration (random siblings) and, where a credential exists, a positive control; a reference that cannot decide gives `NOT_VERIFIABLE`. | `src/core/references.py`, `TestContext.references` |
| 4 | **Transport errors** (timeout, refused, TLS, protocol) are recorded and judged `NOT_VERIFIABLE`, never skipped. | `SecurityClientError.record`, `TransportError` |
| 5 | **Derive first, configure on top.** What a test probes comes from the specification (named derivation rules, Phase 2) and the gateway, then the configuration adds or corrects; no destructive request on a derived candidate the configuration has not confirmed; sampling by a stated rule, never "the first N". | `src/discovery/derivation.py`, `AttackSurface.derived` |
| 6 | **Evidence and confidence.** Every finding has its proof (`evidence_ref`) and the references it rests on (`supporting_refs`); confidence `CERTAIN`, `FIRM` or `TENTATIVE` by stated criteria; no severity. | `Finding`, `BaseTest._judge` |
| 7 | **Effect.** `READ_ONLY`, `CHANGES_DATA` or `STRESSES_TARGET`, declared; the run order follows it; who creates cleans up or states what is left. | `TestInfo.effect`, `src/core/dag.py` |
| 8 | **Standards.** The guarantee's other standards in `TestInfo.references`, each the standard and its official identifier (ASVS 5.0.0 L2, WSTG with its version, OWASP API Top 10 2023, RFC, NIST SP), each verified on its source. | `src/core/models/standards.py` |
| 9 | **Three situations on the labs.** A test is trusted once seen giving the right answer where the weakness is present, where it is absent, and where the check cannot be made; a case the labs lack is produced by the crAPI case of the category, the tool's configuration, or a documented change to a lab's gateway configuration. | the page's "Validation" section |
| 10 | **One question, one test.** Data two tests need is written once and shared (path variants, sensitive paths); the gateway's own answer is recognised by the references, not by lists of gateways. | `src/core/path_variants.py`, `src/core/sensitive_paths.py` |
| 11 | **External tools.** The oracle is the tool's check, not its severity (kept as information); only results on the target count; the tool's own problems are `NOT_VERIFIABLE`; the command shown for manual verification runs. | `src/external_tests/` |
| 12 | **Needs and strategy.** What a test needs is declared (`TestInfo.needs`), with a minimum strategy per need; the gateway reaches only the tests that declare it. | `src/core/test_metadata.py` |

## See also

- [`overview.md`](01-overview.md) · [`security-model.md`](04-security-model.md)
- [`reference/exit-codes.md`](../03-reference/03-exit-codes.md)

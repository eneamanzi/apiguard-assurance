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

v0.1.0 implements 15 native and 3 external tests covering 15 of the 29 guarantees (domain 5 has none).

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
| `BLACK_BOX` | `0.1`, `ext.0.1.ffuf` | - | - | - |
| `GREY_BOX` | - | - | - | - |
| `WHITE_BOX` | - | `4.2` | - | - |

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
| `ERROR` | The check could not be completed (transport failure, rejected credentials, tool failure, unexpected exception). | → 3 if no FAIL |
| `SKIP` | A precondition is missing; `skip_reason` says which. Not a pass. | none |

A PASS is bounded by what the test covers: each test page lists the methodology sub-tests that are not
implemented and the test's known limitations.

**Finding vs InfoNote.** A Finding is a violation, with references (the standard and its identifier: OWASP, ASVS, WSTG, NIST, RFC; by
default the test's) and, for HTTP tests, an
`evidence_ref` to the proving transaction (not yet for 4.1 and 7.2, Q-50). An InfoNote is context the analyst must know but that is not a
violation: a compensating control, a sub-test that could not run, an ambiguous result (e.g. SSRF probe timeout),
an item requiring manual verification.

**Oracle states.** Each HTTP transaction in a test's audit trail carries an `oracle_state` label set by the test
(e.g. `ENFORCED`, `BYPASS`, `INCONCLUSIVE_PARAMETRIC`). Labels are defined per test; their meaning is listed on
each test page.

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
| Cat A tool | Connector to implement; needed for full coverage of a HYBRID guarantee (implemented: nuclei, testssl.sh, sslyze). |
| Cat B tool | Optional connector, a native fallback exists. |
| Cat C tool | Evaluated and discarded (abandoned, out of scope, or no added value). |

If a Cat A tool is enabled but not installed, its test returns SKIP; the native test for the same guarantee still
runs.

## See also

- [`overview.md`](01-overview.md) · [`security-model.md`](04-security-model.md)
- [`reference/exit-codes.md`](../03-reference/03-exit-codes.md)

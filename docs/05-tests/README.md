# Test Catalogue

> **Audience:** analysts, integrators, contributors · **Status:** v0.1.0 · **Source of truth:** each test's
> declaration (`info = TestInfo(...)`) in `src/tests/` and `src/external_tests/`; the table is generated from it
> (`scripts/generate_docs.py`, `hatch run dev:gen`; checked by `hatch run dev:check`).

Layout mirrors the code: native tests in `domain-N/` (`src/tests/domain_N/`),
external-tool tests in `external/domain-N/` (`src/external_tests/`). One page per test explains what it checks, how, its outcomes, its effects on the
target, and how it relates to the methodology.

<!-- [[[cog import generate_docs as g; cog.out(g.catalogue()) ]]] -->

24 tests: 22 native, 2 external.

| ID | Name | Pri. | Strategy | Effect | CWE | Needs | Page |
|---|---|---|---|---|---|---|---|
| **Domain 0 - API Discovery and Inventory Management** | | | | | | | |
| `0.1` | Undeclared Methods, Undocumented Versions and Gateway Route Drift | P0 | BLACK_BOX | STRESSES_TARGET | CWE-912 | `GATEWAY` (optional) | [0.1](domain-0/0-1-shadow-api-discovery.md) |
| `ext.0.1.ffuf` | Undocumented Paths Answer (ffuf path search, re-verified) | P0 | BLACK_BOX | STRESSES_TARGET | CWE-912 | - | [ext.0.1.ffuf](external/domain-0/ext-0-1-ffuf.md) |
| `0.2` | Paths Without a Route | P0 | BLACK_BOX | READ_ONLY | CWE-183 | `GATEWAY` (optional) | [0.2](domain-0/0-2-paths-without-a-route.md) |
| `0.3` | Deprecated Operations Still Served | P0 | BLACK_BOX | READ_ONLY | - | `USER_ACCOUNT` (optional) | [0.3](domain-0/0-3-deprecated-operations.md) |
| `0.4` | Backend Reachable Without the Gateway | P0 | WHITE_BOX | READ_ONLY | CWE-420 | `GATEWAY` | [0.4](domain-0/0-4-backend-without-the-gateway.md) |
| **Domain 1 - Identity and Authentication** | | | | | | | |
| `1.1` | Credential Required on Documented Operations | P0 | BLACK_BOX | CHANGES_DATA | CWE-306 | - | [1.1](domain-1/1-1-credential-required.md) |
| `1.2` | Credential Cryptographically Valid | P0 | GREY_BOX | READ_ONLY | CWE-347 | `USER_ACCOUNT` | [1.2](domain-1/1-2-credential-cryptographically-valid.md) |
| `1.3` | Credential Expiry | P0 | GREY_BOX | READ_ONLY | CWE-613 | `USER_ACCOUNT` | [1.3](domain-1/1-3-credential-expiry.md) |
| `1.4` | Credential Revocation | P2 | WHITE_BOX | CHANGES_DATA | CWE-613 | `USER_ACCOUNT`, `REVOCABLE_LOGIN` | [1.4](domain-1/1-4-credential-revocation.md) |
| `1.5` | Credentials Over an Insecure Channel | P2 | BLACK_BOX | READ_ONLY | CWE-319 | - | [1.5](domain-1/1-5-credentials-over-an-insecure-channel.md) |
| `ext.1.5.testssl` | TLS Stack Analysis (testssl.sh) | P2 | BLACK_BOX | READ_ONLY | CWE-326 | - | [ext.1.5.testssl](external/domain-1/ext-1-5-testssl.md) |
| `1.6` | Session Cookie Safety | P3 | GREY_BOX | READ_ONLY | CWE-1004 | `USER_ACCOUNT` | [1.6](domain-1/1-6-session-cookie-safety.md) |
| `1.7` | Authentication Endpoints Resist Guessing | P1 | GREY_BOX | STRESSES_TARGET | CWE-307 | `USER_ACCOUNT` | [1.7](domain-1/1-7-authentication-resistance.md) |
| **Domain 2 - Authorization and Access Control** | | | | | | | |
| `2.1` | Function-Level Authorization | P1 | GREY_BOX | READ_ONLY | CWE-285 | `USER_ACCOUNT`, `ADMIN_ACCOUNT` (optional) | [2.1](domain-2/2-1-function-level-authorization.md) |
| `2.2` | Object-Level Authorization | P1 | GREY_BOX | CHANGES_DATA | CWE-639 | `USER_ACCOUNT`, `SECOND_USER_ACCOUNT`, `owned_object_resources` | [2.2](domain-2/2-2-object-level-authorization.md) |
| `2.4` | Authorization Consistency | P1 | BLACK_BOX | READ_ONLY | CWE-285 | - | [2.4](domain-2/2-4-authorization-consistency.md) |
| `2.5` | Object Property-Level Authorization | P1 | GREY_BOX | CHANGES_DATA | CWE-213 | `USER_ACCOUNT`, `owned_object_resources` | [2.5](domain-2/2-5-object-property-authorization.md) |
| **Domain 3 - Data Integrity** | | | | | | | |
| - | no test implemented | | | | | | |
| **Domain 4 - Availability and Resilience** | | | | | | | |
| `4.1` | Rate Limiting | P0 | BLACK_BOX | STRESSES_TARGET | CWE-770 | `GATEWAY` (optional) | [4.1](domain-4/4-1-rate-limiting.md) |
| `4.2` | Timeout Configuration Audit -- Prevention of Resource Lock | P1 | WHITE_BOX | READ_ONLY | CWE-400 | `GATEWAY` | [4.2](domain-4/4-2-timeout-config-audit.md) |
| `4.3` | Circuit Breaker Audit | P1 | WHITE_BOX | READ_ONLY | CWE-400 | `GATEWAY` | [4.3](domain-4/4-3-circuit-breaker-audit.md) |
| `4.4` | Request Size Limits | P1 | BLACK_BOX | STRESSES_TARGET | CWE-400 | `GATEWAY` (optional) | [4.4](domain-4/4-4-request-size-limits.md) |
| **Domain 5 - Visibility and Auditing** | | | | | | | |
| - | no test implemented | | | | | | |
| **Domain 6 - Configuration and Hardening** | | | | | | | |
| `6.1` | Error and Information Disclosure | P2 | GREY_BOX | READ_ONLY | CWE-209 | `USER_ACCOUNT` | [6.1](domain-6/6-1-information-disclosure.md) |
| `6.2` | Security Headers Audit | P3 | BLACK_BOX | READ_ONLY | - | - | [6.2](domain-6/6-2-security-headers-audit.md) |
| `6.4` | Hardcoded Credentials Audit | P2 | BLACK_BOX | READ_ONLY | CWE-798 | `GATEWAY` (optional) | [6.4](domain-6/6-4-hardcoded-credentials-audit.md) |
| **Domain 7 - Business Logic and Sensitive Flows** | | | | | | | |
| - | no test implemented | | | | | | |

Needs: what the test needs from the configuration (credentials of a role, a gateway, a parameter); without it the engine records SKIP without running the test. An optional need is used when configured; without it the test runs and the sub-tests that use it are not applicable. What each test needs from a target, measured on the labs: [Test portability](../03-reference/06-compatibility.md#test-portability).

<!-- [[[end]]] -->

## Dependencies and execution order

No test declares a prerequisite (`depends_on`, `requires_pass`: [dependencies between
tests](../04-architecture/03-assessment-model.md#dependencies-between-tests)). Tests are scheduled
with a topological sort over native and external tests together: among the tests whose prerequisites are done,
the declared effect decides (`READ_ONLY` first, then `CHANGES_DATA`, then `STRESSES_TARGET`), then the test ID.
Execution is sequential.

## Reading the IDs

- `X.Y`: native test for guarantee `Y` of domain `X` in the methodology.
- `ext.X.Y.tool`: external-tool test for the same guarantee; several tools may cover one guarantee.
- Guarantee numbers follow the methodology (29 guarantees in 8 domains); missing numbers are not implemented yet
  ([roadmap](../project/roadmap.md)).

## Page structure

Each page has the same sections: summary table, what it checks, how it works, outcomes (PASS/FAIL/SKIP/ERROR),
oracle states (the values in `transaction_log[].oracle_state`), prerequisites and effects on the target,
configuration, coverage against the methodology, why it exists, limitations.

## See also

- [`../reference/configuration.md`](../03-reference/01-configuration.md#tests) - per-test parameters
- [`../reference/report-schema.md`](../03-reference/04-report-schema.md) - how results are serialised
- [`../06-knowledge/04-guarantees.md`](../06-knowledge/04-guarantees.md) - the full methodology

# Test Catalogue

> **Audience:** analysts, integrators, contributors · **Status:** v0.1.0 · **Source of truth:** test class
> metadata (`test_id`, `test_name`, `domain`, `priority`, `strategy`, `cwe_id`, `depends_on`) in `src/tests/` and
> `src/external_tests/`; table extracted from the code on 2026-10-05.

18 tests: 15 native, 3 external. Layout mirrors the code: native tests in `domain-N/` (`src/tests/domain_N/`),
external-tool tests in `external/domain-N/` (`src/external_tests/`). One page per test explains what it checks, how, its outcomes, its effects on the
target, and how it relates to the methodology.

| ID | Name | Pri. | Strategy | CWE | Needs | Page |
|---|---|---|---|---|---|---|
| **Domain 0 - API Discovery and Inventory Management** | | | | | | |
| `0.1` | All Exposed Endpoints Are Documented and Authorized | P0 | BLACK_BOX | CWE-1059 | spec | [0.1](domain-0/0-1-shadow-api-discovery.md) |
| `ext.0.1.nuclei` | Shadow API Discovery via nuclei | P0 | BLACK_BOX | CWE-200 | nuclei | [ext.0.1.nuclei](external/domain-0/ext-0-1-nuclei.md) (guarantee 0.1 covered in part: ffuf and katana planned) |
| `0.2` | Gateway Deny-by-Default on Unregistered Paths | P0 | BLACK_BOX | CWE-284 | spec | [0.2](domain-0/0-2-deny-by-default.md) |
| `0.3` | Deprecated APIs Are Disabled or Under Enhanced Monitoring | P0 | BLACK_BOX | CWE-1059 | spec with `deprecated` | [0.3](domain-0/0-3-deprecated-api-enforcement.md) |
| **Domain 1 - Identity and Authentication** | | | | | | |
| `1.1` | Only Authenticated Requests Access Protected Resources | P0 | BLACK_BOX | CWE-306 | spec with `security` | [1.1](domain-1/1-1-authentication-required.md) |
| `1.4` | Revoked Token Rejected After Deletion | P2 | GREY_BOX | CWE-613 | admin credentials, **Forgejo** | [1.4](domain-1/1-4-token-revocation.md) |
| `1.5` | Credentials Not Transmitted via Insecure Channels | P2 | WHITE_BOX | CWE-319 | - | [1.5](domain-1/1-5-insecure-credential-transport.md) |
| `ext.1.5.testssl` | TLS Stack Analysis (testssl.sh) | P2 | WHITE_BOX | CWE-326 | testssl.sh | [ext.1.5](external/domain-1/ext-1-5-tls-analysis.md) |
| `ext.1.5.sslyze` | TLS Stack Analysis (sslyze) | P2 | WHITE_BOX | CWE-326 | sslyze | [ext.1.5](external/domain-1/ext-1-5-tls-analysis.md) |
| `1.6` | Secure Session Management in Distributed Architectures | P3 | WHITE_BOX | CWE-614 | - | [1.6](domain-1/1-6-secure-session-management.md) |
| **Domain 2 - Authorization and Access Control** | | | | | | |
| `2.1` | Only Authorized Users Access Privileged Endpoints | P2 | GREY_BOX | CWE-285 | user_a credentials | [2.1](domain-2/2-1-rbac-enforcement.md) |
| **Domain 3 - Data Integrity** | | | | | | |
| `3.3` | HMAC Authentication Configuration Does Not Allow Replay or Weak Algorithms | P3 | WHITE_BOX | CWE-326 | Admin API (Kong) | [3.3](domain-3/3-3-hmac-config-audit.md) |
| **Domain 4 - Availability and Resilience** | | | | | | |
| `4.1` | Rate Limiting -- Resource Exhaustion Prevention | P0 | BLACK_BOX | CWE-400 | spec | [4.1](domain-4/4-1-rate-limiting.md) |
| `4.2` | Timeout Configuration Audit -- Prevention of Resource Lock | P1 | WHITE_BOX | CWE-400 | Admin API (Kong) | [4.2](domain-4/4-2-timeout-config-audit.md) |
| `4.3` | Circuit Breaker Audit -- Dual-Check a 3 Livelli | P1 | WHITE_BOX | CWE-400 | Admin API (Kong) | [4.3](domain-4/4-3-circuit-breaker-audit.md) |
| **Domain 5 - Visibility and Auditing** | | | | | | |
| - | no test implemented | | | | | [roadmap](../project/roadmap.md) |
| **Domain 6 - Configuration and Hardening** | | | | | | |
| `6.2` | Security Headers Configured Appropriately | P3 | WHITE_BOX | CWE-16 | - | [6.2](domain-6/6-2-security-headers-audit.md) |
| `6.4` | Service Credentials Not Hardcoded or Exposed | P2 | WHITE_BOX | CWE-798 | Admin API optional | [6.4](domain-6/6-4-hardcoded-credentials-audit.md) |
| **Domain 7 - Business Logic and Sensitive Flows** | | | | | | |
| `7.2` | Server-Side Request Forgery (SSRF) Prevention | P0 | GREY_BOX | CWE-918 | user_a credentials | [7.2](domain-7/7-2-ssrf-prevention.md) |

"Needs" lists what the test requires beyond `target.base_url` and the specification; without it the test returns
SKIP (or, for external tools that are disabled, is not scheduled). "Admin API (Kong)" means `target.admin_api_url`
plus `target.gateway_adapter: kong`.

## Dependencies and execution order

Only two declared dependencies: `1.4` and `2.1` depend on `1.1`. All other tests have none. Tests are scheduled
with a topological sort over native and external tests together; within a batch the order is lexicographic by
test ID. Execution is sequential.

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

- [`../reference/configuration.md`](../reference/configuration.md#tests) - per-test parameters
- [`../reference/report-schema.md`](../reference/report-schema.md) - how results are serialised
- [`../knowledge/methodology/methodology.it.md`](../knowledge/methodology/methodology.it.md) - the full methodology

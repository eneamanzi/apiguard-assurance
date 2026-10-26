# 7.3 Race Conditions in Critical Operations

> **Audience:** analysts, contributors · **Status:** new in the test review (branch `test-review`, 2026-10-26) ·
> **Source of truth:**
> [`src/tests/domain_7/test_7_3_race_conditions.py`](../../../src/tests/domain_7/test_7_3_race_conditions.py) ·
> **Verified:** 2026-10-26

<!-- [[[cog import generate_docs as g; cog.out(g.test_header("7.3", page=cog.inFile)) ]]] -->

|  |  |
|---|---|
| Test ID | `7.3` |
| Name | Race Conditions in Critical Operations |
| Domain | 7 - Business Logic and Sensitive Flows |
| Priority / strategy | P1 / GREY_BOX |
| Effect | STRESSES_TARGET |
| CWE | CWE-362 |
| Standards | `OWASP ASVS v5.0.0-15.4.2` |
| Tags | `business-logic`, `concurrency` |
| Prerequisites | none |
| Needs | `USER_ACCOUNT`, `race_operation` |
| Parameters | [`tests.domain_7.test_7_3`](../../03-reference/01-configuration.md#testsdomain_7test_7_3) |

<!-- [[[end]]] -->

**Same group:** tests `7.1`, `7.2`, `7.4` (business logic and advanced threats).

## 1. Guarantee

An operation that must take effect at most once (redeem a single-use coupon, submit one order, apply a referral,
withdraw a balance) serializes concurrent attempts. A PASS promises that firing the operation many times at the same
instant took effect no more than its allowed maximum. The threat (CWE-362, TOCTOU): a check-then-act that is not
atomic lets simultaneous requests all pass the check and all act, so the one-only effect happens several times.

## 2. Sub-tests and coverage of the methodology

| Sub-test | Methodology (guarantee 7.3) |
|---|---|
| `concurrent_requests_safe` | "fire N identical requests concurrently; a once-only operation must let at most one take effect" |
| left out | idempotency-key honouring (needs a declared key semantics); ordering/consistency across different operations |

## 3. Inputs

`race_operation` (no default): `path` (may hold a resource's values), `method` (default `POST`), an optional `body`,
a `role` (default `user_a`), and an optional prepared `resource` created once before the burst. `concurrency`
(default 15) and `max_successful` (default 1: strictly once-only; raise for a bounded quota).

Configure `race_operation` **only** for an operation whose number of successes must be bounded. A plain create that
legitimately makes N objects from N requests is not a race and must not be configured here.

## 4. Preconditions and reference responses

The operation (and its resource, if any) must be callable as the role. There is no reference response: the burst is
judged on how many of the N concurrent requests succeeded.

## 5. Probes

`concurrency` identical requests fired at the same instant from native threads (the HTTP client is thread-safe for
requests); the records are judged afterwards on the main thread. Effect `STRESSES_TARGET` (the test runs after the
others, rule 7) and it changes data on the target: announce it on a shared target.

## 6. Oracle

**`concurrent_requests_safe`**

| Case | Outcome / detail | Confidence |
|---|---|---|
| at most `max_successful` of the N requests succeeded (`2xx`) | `ENFORCED/CONCURRENCY_SERIALIZED` | - |
| more than `max_successful` succeeded | `VIOLATION/RACE_DOUBLE_EFFECT` | CERTAIN |
| none succeeded (the operation did not run) | `NOT_VERIFIABLE/OPERATION_FAILED` | - |

## 7. Outcomes

SKIP without `race_operation`. FAIL when too many concurrent requests take effect; PASS when the operation is
serialized.

## 8. Findings

"Race condition: `<method> <path>` took effect `<n>` times", `evidence_ref` one of the successful concurrent
requests.

## 9. Effects on the target

`STRESSES_TARGET`: a concurrent burst of the real operation (which, by definition, changes data). Runs last.

## 10. Per gateway

Independent of the adapter: the concurrency is driven from outside.

## 11. Configuration

| Parameter | What it is | Default |
|---|---|---|
| `race_operation` | the once-only operation (`path`, `method`, `body`, `role`, `resource`) | none (SKIP) |
| `concurrency` | how many requests are fired at once | 15 |
| `max_successful` | the largest number of successes allowed without a race | 1 |

## 12. Validation

Runs of 2026-10-26:

| Lab | Status | Basis |
|---|---|---|
| Forgejo + Kong, crAPI + Kong, Forgejo + APISIX | **SKIP** | no once-only operation declared (`race_operation` unset): honest SKIP |

Rule 9: the live branches (`VIOLATION/RACE_DOUBLE_EFFECT`, `ENFORCED/CONCURRENCY_SERIALIZED`) are lab-unproven and
listed in the Deferred follow-ups, together with a check of the HTTP client's thread-safety on a real concurrent run
(crAPI's coupon-apply flow is a candidate, once a valid coupon code is seeded).

## 13. Remediation

Make the check-then-act atomic: a database transaction with the right isolation, a unique constraint, an idempotency
key, or a lock on the resource (CWE-362, ASVS v5.0.0-15.4.2).

## 14. Limitations

- The oracle counts `2xx` successes; an operation that returns `2xx` but whose effect is itself idempotent at the
  data layer is not distinguishable from a serialized one (which is the correct, safe reading).
- Thread-level concurrency reaches the server closely but not with a hardware guarantee of simultaneity.

## 15. Sources

- OWASP ASVS v5.0.0-15.4.2 (Safe Concurrency, TOCTOU): https://github.com/OWASP/ASVS/blob/v5.0.0/5.0/en/0x24-V15-Secure-Coding-and-Architecture.md
- CWE-362 Concurrent Execution using Shared Resource with Improper Synchronization: https://cwe.mitre.org/data/definitions/362.html

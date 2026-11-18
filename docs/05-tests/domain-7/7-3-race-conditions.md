# 7.3 Race Conditions in Critical Operations

> **Audience:** analysts, contributors · **Source of truth:**
> [`src/tests/domain_7/test_7_3_race_conditions.py`](../../../src/tests/domain_7/test_7_3_race_conditions.py)

<!-- [[[cog import generate_docs as g; cog.out(g.test_header("7.3", page=cog.inFile)) ]]] -->

|  |  |
|---|---|
| Test ID | `7.3` |
| Name | Race Conditions in Critical Operations |
| Domain | 7 - Business Logic and Sensitive Flows |
| Priority / strategy | P1 / GREY_BOX |
| Effect | STRESSES_TARGET |
| CWE | CWE-362 |
| Standards | `OWASP ASVS v5.0.0-15.4.2`, `OWASP ASVS v5.0.0-2.3.4` |
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

## 2. Test

### 2.1 Sub-tests and coverage of the methodology

| Sub-test | Methodology (guarantee 7.3) |
|---|---|
| `concurrent_requests_safe` | "fire N identical requests concurrently; a once-only operation must let at most one take effect" |
| left out | idempotency-key honouring (needs a declared key semantics); ordering/consistency across different operations |

### 2.2 Preconditions and reference responses

The operation (and its resource, if any) must be callable as the role. There is no reference response: the burst is
judged on how many of the N concurrent requests succeeded.

### 2.3 Probes

`concurrency` identical requests fired at the same instant from native threads, released together by a barrier; the HTTP client may be called from several threads (its cookie jar keeps nothing); the records are judged afterwards on the main thread. Effect `STRESSES_TARGET` (the test runs after the
others, rule 7) and it changes data on the target: announce it on a shared target.

## 3. Oracle

<!-- [[[cog import generate_docs as g; cog.out(g.oracle_table("7.3")) ]]] -->

| Case | Outcome / detail | Confidence |
|---|---|---|
| at most `max_successful` of the concurrent requests were accepted (`2xx`) and the others refused with an answer that says something | `ENFORCED/CONCURRENCY_SERIALIZED` | - |
| more than `max_successful` were accepted (acceptances, not effects) | `VIOLATION/RACE_DOUBLE_EFFECT` | FIRM |
| none was accepted, and no answer was one that says nothing: the operation refused every attempt | `NOT_VERIFIABLE/OPERATION_FAILED` | - |
| the prepared resource could not be created | `NOT_VERIFIABLE/OBJECT_NOT_CREATED` | - |

<!-- [[[end]]] -->

<!-- [[[cog import generate_docs as g; cog.out(g.uninformative_answers("7.3", page=cog.inFile)) ]]] -->

The answers that say nothing about the guarantee by themselves, one rule for every test ([assessment model](../../04-architecture/03-assessment-model.md#answers-that-say-nothing-about-the-guarantee)), generated from the code:

| Answer | Sub-tests | Outcome / detail |
|---|---|---|
| `UPSTREAM_UNAVAILABLE` | every sub-test | `NOT_VERIFIABLE/UPSTREAM_UNAVAILABLE` |
| `RATE_LIMITED` | every sub-test | `NOT_VERIFIABLE/RATE_LIMITED` |
| `SERVER_ERROR` | every sub-test | `NOT_VERIFIABLE/SERVER_ERROR` |
| `NO_RESPONSE` | every sub-test | `NOT_VERIFIABLE/NO_RESPONSE` |

<!-- [[[end]]] -->

## 4. Validation

### 4.1 Oracle cases

<!-- [[[cog import generate_docs as g; cog.out(g.oracle_validation("7.3", page=cog.inFile)) ]]] -->

Every case of the oracle, produced on a lab and judged by the code: E1, [oracle validation](../../../experiments/README.md), campaign at commit `fc60b6f`. 7 of 8 produced cases gave the declared outcome; 0 no lab can produce.

| Case | Lab, how it is produced | Result |
|---|---|---|
| `concurrent_requests_safe/ENFORCED/CONCURRENCY_SERIALIZED` | crapi-kong: a route POST ~/workshop/api/shop/apply_coupon$ whose pre-function answers the first of the 15 simultaneous applications 200 and every other one 400 'Coupon code is already claimed by you' | OK |
| `concurrent_requests_safe/VIOLATION/RACE_DOUBLE_EFFECT/FIRM` | crapi-kong: the lab as built, freshly reset: the coupon APIGUARD-RACE is created and its 15 simultaneous applications as user_a are all accepted (200) | DIFFERENT |
| `concurrent_requests_safe/NOT_VERIFIABLE/OPERATION_FAILED` | crapi-kong: a temporary route on POST /workshop/api/shop/apply_coupon answers every application 400 'Coupon code is already claimed by you' (the answer crAPI gives once user_a has claimed the coupon) | OK |
| `concurrent_requests_safe/NOT_VERIFIABLE/OBJECT_NOT_CREATED` | crapi-kong: a route POST ~/community/api/v2/coupon/new-coupon$ on community-service answers 403 itself, so the prepared resource coupon is not created | OK |
| `*/NOT_VERIFIABLE/UPSTREAM_UNAVAILABLE` | crapi-kong: a route POST ~/workshop/api/shop/apply_coupon$ whose pre-function answers every application 503 | OK |
| `*/NOT_VERIFIABLE/RATE_LIMITED` | crapi-kong: a route POST ~/workshop/api/shop/apply_coupon$ whose pre-function answers every application 429 | OK |
| `*/NOT_VERIFIABLE/SERVER_ERROR` | crapi-kong: a route POST ~/workshop/api/shop/apply_coupon$ whose pre-function answers every application 500 | OK |
| `*/NOT_VERIFIABLE/NO_RESPONSE` | crapi-kong: a route POST ~/workshop/api/shop/apply_coupon$ whose pre-function waits 7 s before proxying, with the run's target.read_timeout 5.0 | OK |

<!-- [[[end]]] -->

### 4.2 Results on the labs

<!-- [[[cog import generate_docs as g; cog.out(g.lab_results("7.3", page=cog.inFile)) ]]] -->

No E2 campaign yet ([experiments](../../../experiments/README.md)).

<!-- [[[end]]] -->

## 5. Limitations

- The barrier releases the threads together, but each still opens its own connection (TCP and TLS) when it sends:
  the requests reach the server within the time of a handshake, not at one instant, and a race narrower than that
  can be missed. Opening the connections beforehand would mean extra requests to the target.
- The oracle counts `2xx` acceptances, not effects: an operation that answers `2xx` to a duplicate it does not apply
  (idempotent at the data layer) looks like a race and is reported `RACE_DOUBLE_EFFECT`. That is why the finding is
  FIRM and asks to confirm the effect on the target's own state (this line said the opposite).
- Thread-level concurrency reaches the server closely but not with a hardware guarantee of simultaneity.

## 6. Sources

- OWASP ASVS v5.0.0-15.4.2 (Safe Concurrency, TOCTOU): https://github.com/OWASP/ASVS/blob/v5.0.0/5.0/en/0x24-V15-Secure-Coding-and-Architecture.md
- CWE-362 Concurrent Execution using Shared Resource with Improper Synchronization: https://cwe.mitre.org/data/definitions/362.html

## 7. Inputs

`race_operation` (no default): `path`, `method` (default `POST`), an optional `body`, a `role` (default `user_a`),
and an optional prepared `resource` created once before the burst, whose values and `{random}` may fill the path and
the body: a resource that creates a coupon named `APIGUARD-RACE-{random}` and a body that applies
`"APIGUARD-RACE-{random}"` fire every run on a fresh coupon (a once-only operation is used up by the run that
tests it). `concurrency`
(default 15) and `max_successful` (default 1: strictly once-only; raise for a bounded quota).

Configure `race_operation` **only** for an operation whose number of successes must be bounded. A plain create that
legitimately makes N objects from N requests is not a race and must not be configured here.

## 8. Outcomes

SKIP without `race_operation`. FAIL when too many concurrent requests take effect; PASS when the operation is
serialized.

## 9. Findings

<!-- [[[cog import generate_docs as g; cog.out(g.finding_titles("7.3")) ]]] -->

- "Race condition: <method> <path> accepted <count> times"

<!-- [[[end]]] -->

`evidence_ref` one of the accepted concurrent requests.

## 10. Effects on the target

`STRESSES_TARGET`: a concurrent burst of the real operation (which, by definition, changes data). Runs last.

## 11. Per gateway

Independent of the adapter: the concurrency is driven from outside.

## 12. Configuration

<!-- [[[cog import generate_docs as g; cog.out(g.test_params("7.3", page=cog.inFile)) ]]] -->

Section [`tests.domain_7.test_7_3`](../../03-reference/01-configuration.md#testsdomain_7test_7_3) of `config.yaml`:

| Key | Type | Default | Description |
|---|---|---|---|
| `race_operation` | object \| null | none, **needed to run** | The once-only operation to probe for a race condition. No default: unset, the engine records the test as SKIP before it runs. |
| `race_operation.path` | string | required | Path of the once-only operation. With a resource, may hold its values and its {random} as {name}. |
| `race_operation.method` | string | `POST` | HTTP method of the operation (default POST). |
| `race_operation.body` | object \| null | none | JSON body sent on every concurrent request (optional). With a resource, may hold its values and its "{random}" (the value its create request used, so the burst names what was just created: a coupon code), in quotes. |
| `race_operation.role` | string | `user_a` | Role whose credential performs the operation (default user_a). |
| `race_operation.resource` | string \| null | none | Optional prepared resource (resources: in config.yaml) created once before the burst; its values and its {random} fill the path and the body, and it is removed at teardown. |
| `concurrency` | int 2-50 | `15` | How many identical requests are fired at the same instant. |
| `max_successful` | int ≥1 | `1` | The largest number of concurrent requests that may succeed without a race. 1 for a strictly once-only operation (the default); raise it for a bounded quota. |

<!-- [[[end]]] -->

## 13. Remediation

Make the check-then-act atomic: a database transaction with the right isolation, a unique constraint, an idempotency
key, or a lock on the resource (CWE-362, ASVS v5.0.0-15.4.2).

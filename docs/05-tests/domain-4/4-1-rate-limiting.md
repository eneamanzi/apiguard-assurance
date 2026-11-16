# 4.1 Rate Limiting

> **Audience:** analysts, contributors · **Status:** rewritten in the test review (2026-10-23) ·
> **Source of truth:**
> [`src/tests/domain_4/test_4_1_rate_limiting.py`](../../../src/tests/domain_4/test_4_1_rate_limiting.py) ·
> **Verified:** 2026-11-15

<!-- [[[cog import generate_docs as g; cog.out(g.test_header("4.1", page=cog.inFile)) ]]] -->

|  |  |
|---|---|
| Test ID | `4.1` |
| Name | Rate Limiting |
| Domain | 4 - Availability and Resilience |
| Priority / strategy | P0 / BLACK_BOX |
| Effect | STRESSES_TARGET |
| CWE | CWE-770 |
| Standards | `OWASP API4:2023`, `OWASP ASVS v5.0.0-2.4.1`, `NIST SP 800-204, Section 4.5` |
| Tags | `resource-consumption`, `rate-limiting` |
| Prerequisites | none |
| Needs | `GATEWAY` (optional) |
| Parameters | [`tests.domain_4.test_4_1`](../../03-reference/01-configuration.md#testsdomain_4test_4_1) |

<!-- [[[end]]] -->

**Same group:** tests `4.2`, `4.3`, `4.4` (resource-consumption limits).

## 1. Guarantee

The gateway limits the request rate: past a limit it answers `429 Too Many Requests`, and the limit is keyed to the
real connection, not to a header an attacker controls. A PASS promises a burst met a 429, and that spoofing
a spoofed client address did not slip past it. The threat (OWASP API4:2023): an unlimited endpoint lets a loop exhaust the
backend or brute-force a credential. ASVS v5.0.0-2.4.1 (anti-automation controls).

## 2. Sub-tests and coverage of the methodology

| Sub-test | Methodology (guarantee 4.1) |
|---|---|
| `limit_enforced` | "limit enforcement: send past the limit, expect 429" |
| `ip_spoofing_resisted` | "header spoofing resistance: a randomised X-Forwarded-For per call must not bypass the limit", with the same random address also in `X-Real-IP`, `X-Client-IP`, `True-Client-IP` and `Forwarded` (`for=<address>`, RFC 7239), since 2026-11-05: one burst covers every header a gateway or a backend may take the client address from |
| left out | Retry-After reset (needs a real wait, slow); per-user vs per-IP (needs the counter reasoning of two users against one limit); token-bucket burst shape (a timing detail of the limit) |

## 3. Inputs

The documented GET endpoint to flood (derived: the shortest documented GET, or `probe_path`). With a gateway
(`Need.GATEWAY`, optional), its rate limits (`rate_limits()`: requests per window of seconds, section 10) and its
routes, both kept as evidence. A limit counts only when it may apply to the probe: for every route that may serve
the path (a path that matches it, a method list that is empty or holds GET), the enabled limits on every request,
on the route's backend and on the route (`src/tests/helpers/route_limits.py`). The route matching is a superset of
the gateway's own (a regular expression is searched anywhere in the path; hosts and headers are not compared), so
more routes count, never fewer.

The burst budget is `max_burst`, unless every such route has limits counted per window: then the requests that
exceed the largest of them within one window, at most `max_burst`. A burst may straddle a window boundary (Kong's
windows are calendar periods, APISIX's start at the first request counted), and a run shorter than a window touches
at most two windows, so the budget is twice the window's count plus one: then one window holds more than the count,
wherever the boundaries fall. Until 2026-11-15 the budget was the smallest number anywhere in a rate-limiting
plugin plus 5, read from the configuration text values; it was never read (those hold strings, and both gateways
state a limit as a number), and had it been, it could come from a route the probe does not use.

## 4. Preconditions and reference responses

None beyond the attack surface. The 429 is the reference: `limit_enforced` is the baseline that `ip_spoofing_resisted`
is judged against (a limit must exist before a bypass means anything).

## 5. Probes

A burst of up to the budget of GETs, stopping at the first 429; then, only if the first burst met a 429, the same
burst with a random client address per request, in those five headers. No credential. Effect `STRESSES_TARGET`: the test runs after all
others (rule 7), and the burst stops at the 429 so a working limit is not flooded past its threshold.

## 6. Oracle

**`limit_enforced`**

| Case | Outcome / detail | Confidence |
|---|---|---|
| a 429 within the budget | `ENFORCED/RATE_LIMITED` | - |
| no 429 within the budget, and no limit read, or a route that may serve the path without one | `VIOLATION/NO_RATE_LIMIT`, the finding saying no limit applies at or below the budget (and naming the route) | FIRM: a limit above the budget, or one the adapter does not read, would not be seen |
| no 429, and the burst went past every limit that may apply within one of its windows (`answered > count × (⌊burst seconds / window⌋ + 2)`), each counted on a counter shared by every node | `VIOLATION/NO_RATE_LIMIT`, the finding naming the limits | CERTAIN: the limit is configured and not enforced |
| the same, with a limit counted per node (both gateways' `local` policy) | `VIOLATION/NO_RATE_LIMIT`, the finding adding "unless the gateway runs several nodes that each count their own requests" | FIRM: a burst spread over several nodes does not exceed a per-node count |
| no 429, and a limit that may apply was not provably exceeded: its count above `max_burst`, a window too short for the burst's pace, or a limit not counted per window (APISIX's `limit-req`, which delays requests instead of refusing them) | `NOT_VERIFIABLE/LIMIT_NOT_REACHED`, with a note naming the limits (until 2026-11-15 `LIMIT_ABOVE_BUDGET`, for the first reason only) | - |
| three answers in a row that say nothing (the table below; a `429` is this test's verdict); a single one does not stop the burst (until 2026-11-05 a single 5xx from the third request on did) | `NOT_VERIFIABLE/` the reason of the last (until 2026-11-16 always `UPSTREAM_UNAVAILABLE`) | - |
| the same run of `503` after served answers: a limit that rejects with `503` instead of `429` (some gateways' default, APISIX's `limit-count` among them) looks exactly like a backend going down | `NOT_VERIFIABLE/LIMIT_OR_UNAVAILABLE` (seen on a scratch server answering `503` after 5 requests, 2026-11-05) | - |

**`ip_spoofing_resisted`**

| Case | Outcome / detail | Confidence |
|---|---|---|
| the spoofed burst still meets a 429 | `ENFORCED/SPOOF_RESISTED` | - |
| it floods the full budget without a 429 | `VIOLATION/IP_SPOOF_BYPASS` | CERTAIN |
| the plain burst found no limit | `NOT_APPLICABLE/NO_LIMIT_TO_BYPASS` | - |

<!-- [[[cog import generate_docs as g; cog.out(g.uninformative_answers("4.1", page=cog.inFile)) ]]] -->

The answers that say nothing about the guarantee by themselves, one rule for every test ([assessment model](../../04-architecture/03-assessment-model.md#answers-that-say-nothing-about-the-guarantee)), generated from the code:

| Answer | Sub-tests | Outcome / detail |
|---|---|---|
| `UPSTREAM_UNAVAILABLE` | every sub-test | `NOT_VERIFIABLE/UPSTREAM_UNAVAILABLE` |
| `RATE_LIMITED` | every sub-test | judged by the oracle above: a `429` is the rate limit this test looks for: the burst stops at it. |
| `SERVER_ERROR` | every sub-test | `NOT_VERIFIABLE/SERVER_ERROR` |
| `NO_RESPONSE` | every sub-test | `NOT_VERIFIABLE/NO_RESPONSE` |

<!-- [[[end]]] -->

## 7. Outcomes

SKIP without a documented GET. FAIL on no limit or a spoofing bypass; PASS when a 429 arrives and spoofing is
resisted.

## 8. Findings

"No rate limit on `<path>`" (no limit read, or a route without one) / "Rate limit not enforced on `<path>`" (every
limit that may apply exceeded, naming them; since 2026-11-15) / "Rate limit bypassed by spoofing the client address
on `<path>`" (which of the five headers is not told apart), `evidence_ref` the burst's last request; with a gateway,
its rate limits and routes are kept as evidence too.

## 9. Effects on the target

`STRESSES_TARGET`: a burst of requests (stops at the first 429). Runs last. No credential, no data changed.

## 10. Per gateway

The 429 is observed from outside; the limits read through the adapter size the burst and decide the confidence
(`rate_limits()`, mapping in the [adapter guide](../../02-guides/03-extending/04-add-a-gateway-adapter.md)):

- **Kong** `rate-limiting`: `second` to `year`, each a window (a month counted as 28 days, a year as 365, their
  shortest lengths); a counter shared by every node with `policy` `cluster` or `redis` and `sync_rate` -1, per node
  with `local` (the default). A plugin bound to a consumer is left out (it does not apply to an anonymous burst).
- **APISIX** `limit-count`: `count` per `time_window`; shared with a Redis policy and `sync_interval` -1, per node
  with `local` (the default). `limit-req` is reported without a window. APISIX's `limit-count` rejects with `503` by
  default: the burst then records `LIMIT_OR_UNAVAILABLE` (section 6); with `rejected_code: 429` it records
  `RATE_LIMITED`.

## 11. Configuration

<!-- [[[cog import generate_docs as g; cog.out(g.test_params("4.1", page=cog.inFile)) ]]] -->

Section [`tests.domain_4.test_4_1`](../../03-reference/01-configuration.md#testsdomain_4test_4_1) of `config.yaml`:

| Key | Type | Default | Description |
|---|---|---|---|
| `max_burst` | int ≥2 | `150` | The largest burst the test sends: the burst when the gateway's limits cannot be read, and the cap of the one sized from them. The burst stops at the first 429. |
| `probe_path` | string | `""` | The documented path to flood; empty derives the shortest documented GET. A read path, so the flood changes nothing. |

<!-- [[[end]]] -->

## 12. Validation

Runs of 2026-10-23:

| Lab | Status | Basis |
|---|---|---|
| Forgejo + Kong, Forgejo + APISIX | **FAIL** | 150 requests to the shortest documented GET, no 429: no rate limit configured (a real gap of the default labs) |
| crAPI + Kong | **FAIL**, on its own and in a full assessment after a reset (2026-11-04, 2026-11-05) | 150 requests to `/workshop/api/mechanic/` without a 429. Until 2026-11-03 a full assessment reported **INCONCLUSIVE**: the workshop service had been taken out of rotation by then (the paragraph below) |
| Forgejo + Kong, with the plugin below | **PASS** | the 6th request answers 429 (`limit_enforced`), and the same burst with a random X-Forwarded-For still meets the 429 (`ip_spoofing_resisted`: Kong keys on the real connection) |

**The case the labs lack, and how to undo it.** Add a global `rate-limiting` plugin (minute: 5, policy: local) to
`test-environments/forgejo-kong/kong/kong.yml`, then `cd test-environments/forgejo-kong && docker compose --env-file
../../.env up -d --force-recreate --wait kong`; undo with `git checkout` of that file and the same command. The lab
was checked back to FAIL afterwards. Rule 9: both sides proven. `IP_SPOOF_BYPASS` is not exercised on a lab (Kong
resisted the spoof); it was shown on 2026-11-05 on a scratch server limiting to 5 requests per client and taking the
client from `X-Real-IP`, a header the burst did not send until that day: `limit_enforced` PASS, `ip_spoofing_resisted`
FAIL, CERTAIN, each spoofed request carrying the same random address in the five headers.

**The third situation, measured on 2026-10-29 without being produced on purpose.** On crAPI the burst meets an
unavailable backend: `limit_enforced` records one `NOT_VERIFIABLE/UPSTREAM_UNAVAILABLE` and the test reports
INCONCLUSIVE with no finding, instead of reading the missing 429 as a violation. Narrowed down the same day: run on
its own on a freshly reset lab the burst answers 150 times without a 429 and the test reports **FAIL**, while in a
full assessment of the same reset lab it reports **INCONCLUSIVE**, because by the time the stressing tests run
crAPI's workshop service no longer answers through the gateway. The cause was found on 2026-11-04, and it was not
load: test 7.2's SSRF probes hung on crAPI's outbound call, and three timeouts made Kong's passive health check take
the workshop out of rotation. Since 7.2 stops at its first unanswered payload, a full
assessment reaches this test with the workshop in service and reports FAIL. Nothing changes on the Forgejo labs. That is rule 4 working: a gateway that cannot reach its backend says nothing about rate limiting, so
the test refuses to conclude rather than call the missing 429 a violation.

**What each branch has been seen doing** (rule 9). Proven on a lab: `NO_RATE_LIMIT` with no limit read (all
three), `RATE_LIMITED` and `SPOOF_RESISTED` (Forgejo + Kong with the plugin above), and, on 2026-11-14 with
the current code, `NO_LIMIT_TO_BYPASS` (Forgejo + Kong as configured: `ip_spoofing_resisted` records its only not
applicable case) and `UPSTREAM_UNAVAILABLE` (Forgejo + Kong with the `forgejo` container stopped, the
specification read from a file: Kong answers `503`, INCONCLUSIVE, no finding). Seen on a scratch server only:
`LIMIT_OR_UNAVAILABLE`, `IP_SPOOF_BYPASS`.

**The limits read from the gateway, 2026-11-15** (4.1 alone, plugins added to the `forgejo-service` of the
Forgejo + Kong `kong.yml` or to the API route of the APISIX `setup.sh`, each undone with `git checkout` and the lab
recreated):

| Variant | Result |
|---|---|
| none (the labs as configured) | **FAIL** FIRM: the finding names `forgejo-api-route` as a route that may serve `/api/v1/orgs` with no limit stated |
| Kong `rate-limiting` `minute: 5`, `policy: local` | **PASS**: budget 11 (2 × 5 + 1), a 429 at the 6th request, the spoof resisted |
| the same with `policy: redis` on an unreachable Redis (`127.0.0.1:6390`) and `fault_tolerant: true` | **FAIL** CERTAIN, "configured and not enforced": 11 requests in under 0.1 s without a 429, and Kong logged `[rate-limiting] failed to get usage: connection refused` for each and proxied it, as its documentation states for `fault_tolerant` |
| `minute: 5`, `policy: local`, with a `pre-function` answering `GET /api/v1/orgs` with 200 before the limit counts | **FAIL** FIRM, the finding adding the several-nodes reserve (a per-node counter) |
| `minute: 200`, `policy: local` | **INCONCLUSIVE**, `LIMIT_NOT_REACHED`: 150 requests (the cap) cannot exceed 200 in a window, the note names the plugin |
| APISIX `limit-count` `count: 5`, `time_window: 60`, `rejected_code: 429` | **PASS**: read as 5 per 60 s, not shared (`local`), budget 11 |
| APISIX `limit-req` `rate: 100`, `burst: 50`, `key: remote_addr` | **INCONCLUSIVE**, `LIMIT_NOT_REACHED`: the 150 requests took 1.6 s instead of 0.4 s (delayed, never refused), the note naming the plugin "not a count per window"; until that day such a gateway would have been reported FIRM `NO_RATE_LIMIT` |

Not produced on a lab: the per-node case of a gateway with several nodes (the labs run one; the FIRM row was
exercised through the `pre-function` above).

## 13. Remediation

Configure a rate-limiting plugin on the gateway, keyed to the authenticated user and the real connection (not a
client header), with a `Retry-After` on the 429 (OWASP API4:2023, ASVS v5.0.0-2.4.1).

## 14. Limitations

- The budget bounds the burst: a limit higher than `max_burst` (150 by default) is not reached. When the adapter
  reads it, the test says `LIMIT_NOT_REACHED`; when it cannot (no gateway configured, a limit the adapter does not
  know, such as a third-party plugin), the gateway is reported `NO_RATE_LIMIT` with FIRM confidence and a finding
  that says "at or below 150 requests". Raise `max_burst` to look further.
- CERTAIN needs a counter shared by every node: with both gateways' default `local` policy the finding is FIRM,
  since several nodes behind a load balancer each count only their share of the burst (Kong's documentation:
  "Less accurate ... it diverges" when scaling nodes; APISIX: "Each APISIX instance maintains its own counters").
- The route matching that decides which limits apply compares paths and methods only, not hosts or headers: a
  route the probe does not reach can count, which makes the verdict more cautious (FIRM or `LIMIT_NOT_REACHED`),
  never more certain.
- Retry-After reset and the per-user-vs-per-IP distinction are not tested.
- A limit whose count is above the burst budget (`max_burst`) is not reached, whatever its window: what decides is
  the count, not the period (an hourly limit of 1000 is missed, one of 100 is found; until 2026-11-05 this line
  blamed the window). A very short window can be missed the other way: a burst slower than `count` requests per
  window never exceeds it, and the test says `LIMIT_NOT_REACHED` rather than a violation.

## 15. Sources

- OWASP API4:2023 Unrestricted Resource Consumption: https://owasp.org/API-Security/editions/2023/en/0xa4-unrestricted-resource-consumption/
- OWASP ASVS v5.0.0-2.4.1 (anti-automation controls): https://github.com/OWASP/ASVS/blob/v5.0.0/5.0/en/0x11-V2-Validation-and-Business-Logic.md
- NIST SP 800-204 section 4.5 (rate limiting for microservices): https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-204.pdf
- CWE-770 Allocation of Resources Without Limits or Throttling: https://cwe.mitre.org/data/definitions/770.html

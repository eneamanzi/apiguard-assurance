# 4.1 Rate Limiting

> **Audience:** analysts, contributors · **Status:** rewritten in the test review (2026-10-23), again with its oracle in code (2026-11-16) ·
> **Source of truth:**
> [`src/tests/domain_4/test_4_1_rate_limiting.py`](../../../src/tests/domain_4/test_4_1_rate_limiting.py) ·
> **Verified:** 2026-11-16

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
| Needs | `GATEWAY` (optional), `USER_ACCOUNT` (optional) |
| Parameters | [`tests.domain_4.test_4_1`](../../03-reference/01-configuration.md#testsdomain_4test_4_1) |

<!-- [[[end]]] -->

**Same group:** tests `4.2`, `4.3`, `4.4` (resource-consumption limits).

## 1. Guarantee

The gateway limits the request rate: past a limit it refuses the request (`429 Too Many Requests`, or the status
its limit is configured to answer with), and the limit is keyed to the real connection, not to a header an attacker
controls. A PASS promises a burst was refused, and that a spoofed client address did not slip past the refusal.
The threat (OWASP API4:2023): an unlimited endpoint lets a loop exhaust the backend or brute-force a credential.
ASVS v5.0.0-2.4.1 (anti-automation controls against excessive calls).

## 2. Sub-tests and coverage of the methodology

| Sub-test | Methodology (guarantee 4.1) |
|---|---|
| `limit_enforced` | "limit enforcement: send past the limit, expect 429" |
| `ip_spoofing_resisted` | "header spoofing resistance: a randomised X-Forwarded-For per call must not bypass the limit", with the same random address also in `X-Real-IP`, `X-Client-IP`, `True-Client-IP` and `Forwarded` (`for=<address>`, RFC 7239), since 2026-11-05: one burst covers every header a gateway or a backend may take the client address from |
| left out | Retry-After reset (needs a real wait, slow); per-user vs per-IP (needs the counter reasoning of two users against one limit); token-bucket burst shape (a timing detail of the limit) |

## 3. Inputs

The documented GET endpoint to flood (derived: the shortest documented GET, one without a security requirement
first; or `probe_path`). With a gateway (`Need.GATEWAY`, optional), its rate limits (`rate_limits()`: requests per
window of seconds and the status a refused request gets, section 10) and its routes, both kept as evidence. A limit
counts only when it may apply to the probe: for every route that may serve the path (a path that matches it, a
method list that is empty or holds GET), the enabled limits on every request, on the route's backend and on the
route (`src/tests/helpers/route_limits.py`). The route matching is a superset of the gateway's own (a regular
expression is searched anywhere in the path; hosts and headers are not compared), so more routes count, never fewer.

How long a burst runs: at most `max_burst` requests, and less when every route that may serve the path has limits
counted per window. The burst then stops as soon as it provably put more than each limit's count in one of its
windows (`answered > count × (⌊burst seconds / window⌋ + 2)`): a run shorter than a fixed window touches at most two
windows, and each further window length it lasts adds one (Kong's windows are calendar periods, APISIX's start at
the first request counted), so wherever the boundaries fall one window holds more than the count. Until 2026-11-16
the burst was sized in advance as twice the largest count plus one, which assumed a burst shorter than the window: a
slower burst against a short window ended unproven (`LIMIT_NOT_REACHED`) where going on would have proven it.

## 4. Preconditions and reference responses

None beyond the attack surface; user_a's credential is used when configured (`Need.USER_ACCOUNT`, optional). A
burst every answer of which refused it (`401`, `403`) says nothing about the limit: the backend may have refused
requests the limit counted, or the gateway may have refused them before its limit ran (Kong and APISIX run
authentication, ACL and IP restriction before their rate limits: plugin priorities read in the labs' Kong 3.9.3 and
APISIX, 2026-11-16). The burst is then sent again with user_a's credential, and that one is judged. Until
2026-11-16 the refused burst was judged as it was: on a gateway that authenticates before its limit, a configured
limit read as "configured and not enforced", CERTAIN. The refusal of the plain burst (its status) is the reference
the spoofed burst is judged against: a limit must exist before a bypass means anything.

## 5. Probes

A burst of GETs (section 3), stopping at the first refusal: a `429`, or, once the burst had answers with another
status, the status the gateway states for a limit that may apply (APISIX refuses with `503` by default). After a
refused burst, the same with user_a's credential. Then, only if the plain burst was refused, the same burst with a
random client address per request in `X-Forwarded-For`, `X-Real-IP`, `X-Client-IP`, `True-Client-IP` and
`Forwarded` (`for=<address>`, RFC 7239), and, if that one is never refused, one plain request right after it: refused
again, the limit still holds for the real connection while the spoofed requests passed. Effect `STRESSES_TARGET`:
the test runs after all others (rule 7), and each burst stops at its refusal, so a working limit is not flooded past
its threshold.

## 6. Oracle

<!-- [[[cog import generate_docs as g; cog.out(g.oracle_table("4.1")) ]]] -->

**`limit_enforced`**

| Case | Outcome / detail | Confidence |
|---|---|---|
| the burst meets a `429`, or, after answers with another status, the status the gateway states for a limit that may apply (APISIX's default `503`) | `ENFORCED/RATE_LIMITED` | - |
| no refusal, and the burst exceeded every limit read for the routes that may serve the path within one of its windows, each counted on a counter every node shares: the limit is configured and not enforced | `VIOLATION/NO_RATE_LIMIT` | CERTAIN |
| no refusal within `max_burst`, and no limit read or a route that may serve the path without one (no limit of fewer than half the burst per window as long as the burst; a higher one is not seen); or every limit read exceeded, one counted per node | `VIOLATION/NO_RATE_LIMIT` | FIRM |
| no refusal within `max_burst`, and a limit that may apply was not provably exceeded: its count above the cap, a window too short for the burst's pace, or not a count per window | `NOT_VERIFIABLE/LIMIT_NOT_REACHED` | - |
| three `503` in a row after answers that said something: a limit refusing with `503` that the gateway does not state, or a backend going down | `NOT_VERIFIABLE/LIMIT_OR_UNAVAILABLE` | - |
| every answer refused the burst (`401`, `403`), perhaps before the limit counted it, and no user_a account to send it again | `NOT_VERIFIABLE/NO_CREDENTIAL_TO_RETRY` | - |
| the burst sent again with user_a's credential is refused all the same | `NOT_VERIFIABLE/REFUSED_BEFORE_LIMIT` | - |

**`ip_spoofing_resisted`**

| Case | Outcome / detail | Confidence |
|---|---|---|
| the burst with a random client address per request meets the refusal the plain burst met | `ENFORCED/SPOOF_RESISTED` | - |
| it is never refused, and a plain request right after it is: the limit counts the address a header claims | `VIOLATION/IP_SPOOF_BYPASS` | CERTAIN |
| it is never refused, and neither is a plain request right after it (the limit's window may have ended during the burst) | `VIOLATION/IP_SPOOF_BYPASS` | FIRM |
| the plain burst found no limit (`NO_RATE_LIMIT`) | `NOT_APPLICABLE/NO_LIMIT_TO_BYPASS` | - |
| the plain burst could not tell whether a limit applies (`limit_enforced` not verifiable) | `NOT_VERIFIABLE/NO_LIMIT_SEEN` | - |

<!-- [[[end]]] -->

History of the cases. `LIMIT_NOT_REACHED` was `LIMIT_ABOVE_BUDGET` until 2026-11-15, for a limit above the cap only.
`LIMIT_OR_UNAVAILABLE` was seen on a scratch server answering `503` after 5 requests (2026-11-05); until 2026-11-16
it needed served answers before the `503`, now any answer that says something (a `401` from the backend shows it
was reachable too). Until 2026-11-16: a `503` refusal the gateway states (APISIX's default) ended as
`LIMIT_OR_UNAVAILABLE`; the FIRM finding without a limit read said "no limit at or below" the burst, while a burst
can straddle two windows and only a limit below half of it is surely exceeded; `ip_spoofing_resisted` recorded
`NOT_APPLICABLE/NO_LIMIT_TO_BYPASS` also when `limit_enforced` was not verifiable (a limit may exist), and
`IP_SPOOF_BYPASS` was CERTAIN without the plain request after the spoofed burst. Until 2026-11-05 a single 5xx from
the third request on stopped the burst; until 2026-11-16 a run that said nothing was always named
`UPSTREAM_UNAVAILABLE`.

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

SKIP without a documented GET. FAIL on no limit or a spoofing bypass; PASS when the burst is refused and spoofing is
resisted; INCONCLUSIVE when a limit is not provably exceeded, the backend fails, or the burst is refused without a
credential to send it again.

## 8. Findings

<!-- [[[cog import generate_docs as g; cog.out(g.finding_titles("4.1")) ]]] -->

- "Rate limit not enforced on <path>"
- "Rate limit bypassed by spoofing the client address on <path>"
- "No rate limit on <path>"

<!-- [[[end]]] -->

"No rate limit" when no limit is read, or a route that may serve the path has none; "Rate limit not enforced" when
every limit that may apply was exceeded, naming them (since 2026-11-15). `evidence_ref` the burst's last request;
with a gateway, its rate limits and routes are kept as evidence too.

## 9. Effects on the target

`STRESSES_TARGET`: up to three bursts (plain, with user_a's credential when the first is refused, spoofed when the
plain one is refused) and one more request; each stops at its refusal. Runs last. No data changed.

## 10. Per gateway

The refusal is observed from outside; the limits read through the adapter decide when a burst is enough, which
status is a refusal, and the confidence (`rate_limits()`, mapping in the
[adapter guide](../../02-guides/03-extending/04-add-a-gateway-adapter.md)):

- **Kong** `rate-limiting`: `second` to `year`, each a window (a month counted as 28 days, a year as 365, their
  shortest lengths); a counter shared by every node with `policy` `cluster` or `redis` and `sync_rate` -1, per node
  with `local` (the default); the refusal status `error_code` (default `429`). A plugin bound to a consumer is left
  out (it does not apply to an anonymous burst).
- **APISIX** `limit-count`: `count` per `time_window`; shared with a Redis policy and `sync_interval` -1, per node
  with `local` (the default). `limit-req` is reported without a window. Both refuse with `rejected_code`, `503` by
  default: read, it is the refusal (since 2026-11-16, `RATE_LIMITED`); without a gateway configured, a run of `503`
  after other answers records `LIMIT_OR_UNAVAILABLE`.

## 11. Configuration

<!-- [[[cog import generate_docs as g; cog.out(g.test_params("4.1", page=cog.inFile)) ]]] -->

Section [`tests.domain_4.test_4_1`](../../03-reference/01-configuration.md#testsdomain_4test_4_1) of `config.yaml`:

| Key | Type | Default | Description |
|---|---|---|---|
| `max_burst` | int ≥2 | `150` | The largest burst the test sends: the burst when the gateway's limits cannot be read, and the cap of the one sized from them. The burst stops at the first 429. |
| `probe_path` | string | `""` | The documented path to flood; empty derives the shortest documented GET. A read path, so the flood changes nothing. |

<!-- [[[end]]] -->

## 12. Validation

**Runs of 2026-11-16, after the review** (4.1 alone; each variant undone and the lab checked back, Kong variants on
`forgejo-service` of the Forgejo + Kong `kong.yml`, the APISIX one on the API route of `setup.sh`):

| Variant | Result |
|---|---|
| the three labs as configured | **FAIL** FIRM on each. Forgejo: `/api/v1/orgs`, 150 requests. crAPI: the probe is now `/workshop/api/mechanic/receive_report`, the shortest GET without a security requirement (it was `/workshop/api/mechanic/`, answering `401`); it answers `400` (its required query parameters are not sent), so nothing is created, and the finding names `workshop-route` with no limit and "no limit of 74 requests or fewer per window of 0.6 s or longer" |
| Kong `rate-limiting` `minute: 5`, `local` | **PASS**: a `429` at the 4th request (the run's earlier requests to the service counted too), the spoofed burst refused at once |
| the same with `policy: redis` on an unreachable Redis, `fault_tolerant: true` | **FAIL** CERTAIN, "configured and not enforced": the burst stopped at 11 requests, the first count that proves the limit exceeded |
| `minute: 200` | **INCONCLUSIVE**: `LIMIT_NOT_REACHED` after 150 requests, and `ip_spoofing_resisted` `NO_LIMIT_SEEN` (until that day `NOT_APPLICABLE`) |
| `probe_path: /api/v1/user` (Forgejo answers `401` without a credential), no limit | **FAIL** FIRM: 150 refused requests, then 150 with user_a's credential, served |
| the same, user_a removed from the configuration | **INCONCLUSIVE**: `NO_CREDENTIAL_TO_RETRY`, `NO_LIMIT_SEEN` |
| the same with `minute: 5` | **PASS**: the backend's `401` answers were counted, a `429` at the 4th |
| a route for `/api/v1/orgs` with `key-auth` and `rate-limiting` `minute: 5` | **INCONCLUSIVE**: 150 requests refused by Kong's `key-auth`, 150 more with user_a's Forgejo token refused alike: `REFUSED_BEFORE_LIMIT`. Until that day the refused burst was judged as it was: `NO_RATE_LIMIT` on a gateway whose limit sits behind its authentication |
| `minute: 5`, `limit_by: ip`, Kong started with `KONG_TRUSTED_IPS=0.0.0.0/0,::/0` and `KONG_REAL_IP_HEADER=X-Forwarded-For` (a compose override; the lab's file untouched) | **FAIL** CERTAIN, `IP_SPOOF_BYPASS`: the plain burst refused at the 5th request, the spoofed one served 11 requests, and the plain request after it refused (`429`) again. First seen on a real gateway (until then on a scratch server only) |
| APISIX `limit-count` `count: 5`, `time_window: 60`, no `rejected_code` (`503`) | **PASS**: the `503` after four served answers is the refusal the gateway states. Until that day this ended as `LIMIT_OR_UNAVAILABLE` |
| the same with the `gateway` section removed from the configuration | **INCONCLUSIVE**, `LIMIT_OR_UNAVAILABLE`: four served answers, then three `503` |

Not produced: `IP_SPOOF_BYPASS` FIRM (the limit's window ending during the spoofed burst), and the per-node FIRM row
(seen on 2026-11-15 through a `pre-function`, below; its logic did not change).

**Earlier runs** (the paragraphs and tables below) are kept for their history; their budgets and details are those
of their day.

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

- `max_burst` bounds the burst, and the burst is sequential: a limit whose count is above `max_burst` is not
  reached, whatever its window (an hourly limit of 1000 is missed, one of 100 is found), and a burst slower than
  `count` requests per window never exceeds it. When the adapter reads the limit, the test says
  `LIMIT_NOT_REACHED`; when it cannot (no gateway configured, a limit the adapter does not know, such as a
  third-party plugin), the gateway is reported `NO_RATE_LIMIT` FIRM, and the finding says which limits are surely
  absent: fewer than half the burst (74 requests with the default 150) per window as long as the burst. Raise
  `max_burst` to look further.
- CERTAIN needs a counter shared by every node: with both gateways' default `local` policy the finding is FIRM,
  since several nodes behind a load balancer each count only their share of the burst (Kong's documentation:
  "Less accurate ... it diverges" when scaling nodes; APISIX: "Each APISIX instance maintains its own counters").
- The route matching that decides which limits apply compares paths and methods only, not hosts or headers: a
  route the probe does not reach can count, which makes the verdict more cautious (FIRM or `LIMIT_NOT_REACHED`),
  never more certain.
- A burst refused with user_a's credential too is not judged (`REFUSED_BEFORE_LIMIT`); without user_a configured, a
  refused burst is not judged either (`NO_CREDENTIAL_TO_RETRY`), also when the backend refused requests the limit had
  counted (crAPI's `401`). With the credential, the limits the gateway applies to that account count as well; a
  limit applied to anonymous clients only is then not seen.
- A `503` refusal is recognised only when the gateway's limits are read: without them it cannot be told from a
  backend going down (`LIMIT_OR_UNAVAILABLE`).
- The spoofed burst covers the five headers above, not a header a gateway is configured to read under another name.
- Retry-After reset and the per-user-vs-per-IP distinction are not tested.
- When a limit that may apply states `503` as its refusal (APISIX's default), a backend going down in the middle of
  the burst, after other answers, reads as the limit's refusal (`RATE_LIMITED`).

## 15. Sources

- OWASP API4:2023 Unrestricted Resource Consumption: https://owasp.org/API-Security/editions/2023/en/0xa4-unrestricted-resource-consumption/
- OWASP ASVS v5.0.0-2.4.1 (anti-automation controls): https://github.com/OWASP/ASVS/blob/v5.0.0/5.0/en/0x11-V2-Validation-and-Business-Logic.md
- NIST SP 800-204 section 4.5 (rate limiting for microservices): https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-204.pdf
- CWE-770 Allocation of Resources Without Limits or Throttling: https://cwe.mitre.org/data/definitions/770.html

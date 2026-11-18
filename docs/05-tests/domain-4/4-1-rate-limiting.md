# 4.1 Rate Limiting

> **Audience:** analysts, contributors · **Source of truth:**
> [`src/tests/domain_4/test_4_1_rate_limiting.py`](../../../src/tests/domain_4/test_4_1_rate_limiting.py)

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

## 2. Test

### 2.1 Sub-tests and coverage of the methodology

| Sub-test | Methodology (guarantee 4.1) |
|---|---|
| `limit_enforced` | "limit enforcement: send past the limit, expect 429" |
| `ip_spoofing_resisted` | "header spoofing resistance: a randomised X-Forwarded-For per call must not bypass the limit", with the same random address also in `X-Real-IP`, `X-Client-IP`, `True-Client-IP` and `Forwarded` (`for=<address>`, RFC 7239): one burst covers every header a gateway or a backend may take the client address from |
| left out | Retry-After reset (needs a real wait, slow); per-user vs per-IP (needs the counter reasoning of two users against one limit); token-bucket burst shape (a timing detail of the limit) |

### 2.2 Preconditions and reference responses

None beyond the attack surface; user_a's credential is used when configured (`Need.USER_ACCOUNT`, optional). A
burst every answer of which refused it (`401`, `403`) says nothing about the limit: the backend may have refused
requests the limit counted, or the gateway may have refused them before its limit ran (Kong and APISIX run
authentication, ACL and IP restriction before their rate limits: plugin priorities read in the labs' Kong 3.9.3 and
APISIX 3.19). The burst is then sent again with user_a's credential, and that one is judged. The refusal of the plain burst (its status) is the reference
the spoofed burst is judged against: a limit must exist before a bypass means anything.

### 2.3 Probes

A burst of GETs (section 7), stopping at the first refusal: a `429`, or, once the burst had answers with another
status, the status the gateway states for a limit that may apply (APISIX refuses with `503` by default). After a
refused burst, the same with user_a's credential. Then, only if the plain burst was refused, the same burst with a
random client address per request in `X-Forwarded-For`, `X-Real-IP`, `X-Client-IP`, `True-Client-IP` and
`Forwarded` (`for=<address>`, RFC 7239), and, if that one is never refused, one plain request right after it: refused
again, the limit still holds for the real connection while the spoofed requests passed. Effect `STRESSES_TARGET`:
the test runs after all others (rule 7), and each burst stops at its refusal, so a working limit is not flooded past
its threshold.

## 3. Oracle

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

`LIMIT_OR_UNAVAILABLE` needs, before the `503`, an answer that says something (a `401` from the backend shows it
was reachable too).
<!-- [[[cog import generate_docs as g; cog.out(g.uninformative_answers("4.1", page=cog.inFile)) ]]] -->

The answers that say nothing about the guarantee by themselves, one rule for every test ([assessment model](../../04-architecture/03-assessment-model.md#answers-that-say-nothing-about-the-guarantee)), generated from the code:

| Answer | Sub-tests | Outcome / detail |
|---|---|---|
| `UPSTREAM_UNAVAILABLE` | every sub-test | `NOT_VERIFIABLE/UPSTREAM_UNAVAILABLE` |
| `RATE_LIMITED` | every sub-test | judged by the oracle above: a `429` is the rate limit this test looks for: the burst stops at it. |
| `SERVER_ERROR` | every sub-test | `NOT_VERIFIABLE/SERVER_ERROR` |
| `NO_RESPONSE` | every sub-test | `NOT_VERIFIABLE/NO_RESPONSE` |

<!-- [[[end]]] -->

## 4. Validation

### 4.1 Oracle cases

<!-- [[[cog import generate_docs as g; cog.out(g.oracle_validation("4.1", page=cog.inFile)) ]]] -->

Every case of the oracle, produced on a lab and judged by the code: E1, [oracle validation](../../../experiments/README.md), campaign at commit `fc60b6f`. 15 of 15 produced cases gave the declared outcome; 0 no lab can produce.

| Case | Lab, how it is produced | Result |
|---|---|---|
| `limit_enforced/ENFORCED/RATE_LIMITED` | forgejo-kong: rate-limiting minute 5, policy local, on a route GET ~/api/v1/orgs$ (the probe): the burst meets a 429 at the 6th request | OK |
| `limit_enforced/VIOLATION/NO_RATE_LIMIT/CERTAIN` | forgejo-kong: rate-limiting minute 5 on forgejo-service with policy redis on an unreachable Redis (127.0.0.1:6390), sync_rate -1, fault_tolerant true: Kong proxies every request, the burst stops unrefused at 11 | OK |
| `limit_enforced/VIOLATION/NO_RATE_LIMIT/FIRM` | forgejo-kong: the lab as built: no rate limit, 150 requests to GET /api/v1/orgs all served | OK |
| `limit_enforced/NOT_VERIFIABLE/LIMIT_NOT_REACHED` | forgejo-kong: rate-limiting minute 200, policy local, on forgejo-service: 150 requests (the cap) cannot exceed 200 in a window | OK |
| `limit_enforced/NOT_VERIFIABLE/LIMIT_OR_UNAVAILABLE` | forgejo-apisix: APISIX limit-count count 5, time_window 60, no rejected_code (503), on a route GET /api/v1/orgs; the run without its gateway section: five served answers, then three 503 | OK |
| `limit_enforced/NOT_VERIFIABLE/NO_CREDENTIAL_TO_RETRY` | forgejo-kong: the probe set to /api/v1/user (Forgejo answers 401 without a credential) and user_a removed from the run's configuration | OK |
| `limit_enforced/NOT_VERIFIABLE/REFUSED_BEFORE_LIMIT` | forgejo-kong: a route ~/api/v1/orgs$ with key-auth before rate-limiting minute 5: 150 requests refused 401 by key-auth, 150 more with user_a's Forgejo token refused alike | OK |
| `ip_spoofing_resisted/ENFORCED/SPOOF_RESISTED` | forgejo-kong: the same run as RATE_LIMITED: Kong keys the limit on the TCP peer, the spoofed burst meets the 429 at once | OK |
| `ip_spoofing_resisted/VIOLATION/IP_SPOOF_BYPASS/CERTAIN` | forgejo-kong: rate-limiting hour 5, limit_by ip, on the probe's route, Kong recreated with KONG_TRUSTED_IPS=0.0.0.0/0,::/0 and KONG_REAL_IP_HEADER=X-Forwarded-For: the plain burst refused, the spoofed one served, the plain request after it refused 429 again | OK |
| `ip_spoofing_resisted/VIOLATION/IP_SPOOF_BYPASS/FIRM` | forgejo-kong: a route GET ~/api/v1/orgs$ whose pre-function answers 429 to the 4th request without X-Forwarded-For and passes every other request to Forgejo: the plain burst is refused, the spoofed burst (which carries X-Forwarded-For) never is, and the plain request after it is served, as when the limit's window ended | OK |
| `ip_spoofing_resisted/NOT_APPLICABLE/NO_LIMIT_TO_BYPASS` | forgejo-kong: the lab as built: the plain burst found no limit (NO_RATE_LIMIT) | OK |
| `ip_spoofing_resisted/NOT_VERIFIABLE/NO_LIMIT_SEEN` | forgejo-kong: the same run as LIMIT_NOT_REACHED (rate-limiting minute 200 on forgejo-service) | OK |
| `*/NOT_VERIFIABLE/UPSTREAM_UNAVAILABLE` | forgejo-kong: the forgejo container stopped (the specification read from a local copy): Kong answers 502/503 from the first request, three in a row | OK |
| `*/NOT_VERIFIABLE/SERVER_ERROR` | forgejo-kong: a route GET ~/api/v1/orgs$ (the probe) whose pre-function answers 500: three 500 in a row | OK |
| `*/NOT_VERIFIABLE/NO_RESPONSE` | forgejo-kong: a route GET ~/api/v1/orgs$ whose pre-function sleeps 7 s before Forgejo answers, with the run's read timeout at 5 s: three requests in a row without an answer | OK |

<!-- [[[end]]] -->

### 4.2 Results on the labs

<!-- [[[cog import generate_docs as g; cog.out(g.lab_results("4.1", page=cog.inFile)) ]]] -->

No E2 campaign yet ([experiments](../../../experiments/README.md)).

<!-- [[[end]]] -->

## 5. Limitations

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

## 6. Sources

- OWASP API4:2023 Unrestricted Resource Consumption: https://owasp.org/API-Security/editions/2023/en/0xa4-unrestricted-resource-consumption/
- OWASP ASVS v5.0.0-2.4.1 (anti-automation controls): https://github.com/OWASP/ASVS/blob/v5.0.0/5.0/en/0x11-V2-Validation-and-Business-Logic.md
- NIST SP 800-204 section 4.5 (rate limiting for microservices): https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-204.pdf
- CWE-770 Allocation of Resources Without Limits or Throttling: https://cwe.mitre.org/data/definitions/770.html

## 7. Inputs

The documented GET endpoint to flood (derived: the shortest documented GET, one without a security requirement
first; or `probe_path`). With a gateway (`Need.GATEWAY`, optional), its rate limits (`rate_limits()`: requests per
window of seconds and the status a refused request gets, section 11) and its routes, both kept as evidence. A limit
counts only when it may apply to the probe: for every route that may serve the path (a path that matches it, a
method list that is empty or holds GET), the enabled limits on every request, on the route's backend and on the
route (`src/tests/helpers/route_limits.py`). The route matching is a superset of the gateway's own (a regular
expression is searched anywhere in the path; hosts and headers are not compared), so more routes count, never fewer.

How long a burst runs: at most `max_burst` requests, and less when every route that may serve the path has limits
counted per window. The burst then stops as soon as it provably put more than each limit's count in one of its
windows (`answered > count × (⌊burst seconds / window⌋ + 2)`): a run shorter than a fixed window touches at most two
windows, and each further window length it lasts adds one (Kong's windows are calendar periods, APISIX's start at
the first request counted), so wherever the boundaries fall one window holds more than the count. 
## 8. Outcomes

SKIP without a documented GET. FAIL on no limit or a spoofing bypass; PASS when the burst is refused and spoofing is
resisted; INCONCLUSIVE when a limit is not provably exceeded, the backend fails, or the burst is refused without a
credential to send it again.

## 9. Findings

<!-- [[[cog import generate_docs as g; cog.out(g.finding_titles("4.1")) ]]] -->

- "Rate limit not enforced on <path>"
- "Rate limit bypassed by spoofing the client address on <path>"
- "No rate limit on <path>"

<!-- [[[end]]] -->

"No rate limit" when no limit is read, or a route that may serve the path has none; "Rate limit not enforced" when
every limit that may apply was exceeded, naming them. `evidence_ref` the burst's last request;
with a gateway, its rate limits and routes are kept as evidence too.

## 10. Effects on the target

`STRESSES_TARGET`: up to three bursts (plain, with user_a's credential when the first is refused, spoofed when the
plain one is refused) and one more request; each stops at its refusal. Runs last. No data changed.

## 11. Per gateway

The refusal is observed from outside; the limits read through the adapter decide when a burst is enough, which
status is a refusal, and the confidence (`rate_limits()`, mapping in the
[adapter guide](../../02-guides/03-extending/04-add-a-gateway-adapter.md)):

- **Kong** `rate-limiting`: `second` to `year`, each a window (a month counted as 28 days, a year as 365, their
  shortest lengths); a counter shared by every node with `policy` `cluster` or `redis` and `sync_rate` -1, per node
  with `local` (the default); the refusal status `error_code` (default `429`). A plugin bound to a consumer is left
  out (it does not apply to an anonymous burst).
- **APISIX** `limit-count`: `count` per `time_window`; shared with a Redis policy and `sync_interval` -1, per node
  with `local` (the default). `limit-req` is reported without a window. Both refuse with `rejected_code`, `503` by
  default: read, it is the refusal; without a gateway configured, a run of `503`
  after other answers records `LIMIT_OR_UNAVAILABLE`.

## 12. Configuration

<!-- [[[cog import generate_docs as g; cog.out(g.test_params("4.1", page=cog.inFile)) ]]] -->

Section [`tests.domain_4.test_4_1`](../../03-reference/01-configuration.md#testsdomain_4test_4_1) of `config.yaml`:

| Key | Type | Default | Description |
|---|---|---|---|
| `max_burst` | int ≥2 | `150` | The largest burst the test sends: the burst when the gateway's limits cannot be read, and the cap of the one sized from them. The burst stops at the first 429. |
| `probe_path` | string | `""` | The documented path to flood; empty derives the shortest documented GET. A read path, so the flood changes nothing. |

<!-- [[[end]]] -->

## 13. Remediation

Configure a rate-limiting plugin on the gateway, keyed to the authenticated user and the real connection (not a
client header), with a `Retry-After` on the 429 (OWASP API4:2023, ASVS v5.0.0-2.4.1).

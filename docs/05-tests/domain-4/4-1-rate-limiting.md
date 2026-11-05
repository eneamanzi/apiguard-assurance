# 4.1 Rate Limiting

> **Audience:** analysts, contributors · **Status:** rewritten in the test review (2026-10-23) ·
> **Source of truth:**
> [`src/tests/domain_4/test_4_1_rate_limiting.py`](../../../src/tests/domain_4/test_4_1_rate_limiting.py) ·
> **Verified:** 2026-10-23

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

The documented GET endpoint to flood (derived: the shortest documented GET, or `probe_path`). The burst budget is
the gateway's configured rate-limit plus a margin when the adapter can read it (`config_values`, `Need.GATEWAY`
optional), else `max_burst`. **In practice it is `max_burst`**: both supported gateways state a limit as a number
(Kong's `rate-limiting.minute`, APISIX's `limit-count.count`, checked on their schemas 2026-11-03), and the
configuration scan collects strings only (section 10).

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
| no 429 within the budget, no configured limit read | `VIOLATION/NO_RATE_LIMIT`, the finding saying no limit applies at or below the budget | FIRM: a limit above the budget would not be seen |
| no 429 within the budget, which went past a configured limit that was read | `VIOLATION/NO_RATE_LIMIT`, the finding naming the configured limit | CERTAIN: the limit is configured and not enforced |
| a configured limit was read above `max_burst`, so the capped burst cannot reach it | `NOT_VERIFIABLE/LIMIT_ABOVE_BUDGET` | - |
| three failing answers in a row (5xx, unavailable, no answer); a single one does not stop the burst (until 2026-11-05 a single 5xx from the third request on did) | `NOT_VERIFIABLE/UPSTREAM_UNAVAILABLE` | - |
| the same run of `503` after served answers: a limit that rejects with `503` instead of `429` (some gateways' default, APISIX's `limit-count` among them) looks exactly like a backend going down | `NOT_VERIFIABLE/LIMIT_OR_UNAVAILABLE` (seen on a scratch server answering `503` after 5 requests, 2026-11-05) | - |

**`ip_spoofing_resisted`**

| Case | Outcome / detail | Confidence |
|---|---|---|
| the spoofed burst still meets a 429 | `ENFORCED/SPOOF_RESISTED` | - |
| it floods the full budget without a 429 | `VIOLATION/IP_SPOOF_BYPASS` | CERTAIN |
| the plain burst found no limit | `NOT_APPLICABLE/NO_LIMIT_TO_BYPASS` | - |

## 7. Outcomes

SKIP without a documented GET. FAIL on no limit or a spoofing bypass; PASS when a 429 arrives and spoofing is
resisted.

## 8. Findings

"No rate limit on `<path>`" / "Rate limit bypassed by spoofing the client address on `<path>`" (which of the five headers is not told apart), `evidence_ref` the
burst's last request.

## 9. Effects on the target

`STRESSES_TARGET`: a burst of requests (stops at the first 429). Runs last. No credential, no data changed.

## 10. Per gateway

Independent of the adapter: the 429 is observed from outside. The configured limit would size the burst, but
neither adapter delivers it: the configuration scan collects only string values (it was built for test 6.4's
credential search), and Kong and APISIX both state a rate limit as a number. Making the scan collect numbers was
not done: `_configured_limit` takes the smallest positive number of the plugin's configuration, which on Kong's
`rate-limiting` would also see its Redis port and timeouts.

## 11. Configuration

<!-- [[[cog import generate_docs as g; cog.out(g.test_params("4.1", page=cog.inFile)) ]]] -->

Section [`tests.domain_4.test_4_1`](../../03-reference/01-configuration.md#testsdomain_4test_4_1) of `config.yaml`:

| Key | Type | Default | Description |
|---|---|---|---|
| `max_burst` | int ≥2 | `150` | The largest burst the test sends before concluding there is no rate limit, when the gateway's configured limit cannot be read. The burst stops at the first 429. |
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

## 13. Remediation

Configure a rate-limiting plugin on the gateway, keyed to the authenticated user and the real connection (not a
client header), with a `Retry-After` on the 429 (OWASP API4:2023, ASVS v5.0.0-2.4.1).

## 14. Limitations

- The budget bounds the burst: a limit higher than `max_burst` (150 by default) is not reached, so a gateway that
  does limit, but above that rate, is reported `NO_RATE_LIMIT` with FIRM confidence and a finding that says "at or
  below 150 requests". Raise `max_burst` to look further; the gateway's configuration cannot supply the limit
  (section 10).
- Retry-After reset and the per-user-vs-per-IP distinction are not tested.
- A limit whose count is above the burst budget (`max_burst`) is not reached, whatever its window: what decides is
  the count, not the period (an hourly limit of 1000 is missed, one of 100 is found; until 2026-11-05 this line
  blamed the window).

## 15. Sources

- OWASP API4:2023 Unrestricted Resource Consumption: https://owasp.org/API-Security/editions/2023/en/0xa4-unrestricted-resource-consumption/
- OWASP ASVS v5.0.0-2.4.1 (anti-automation controls): https://github.com/OWASP/ASVS/blob/v5.0.0/5.0/en/0x11-V2-Validation-and-Business-Logic.md
- NIST SP 800-204 section 4.5 (rate limiting for microservices): https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-204.pdf
- CWE-770 Allocation of Resources Without Limits or Throttling: https://cwe.mitre.org/data/definitions/770.html

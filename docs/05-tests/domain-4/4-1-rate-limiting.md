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
`X-Forwarded-For` did not slip past it. The threat (OWASP API4:2023): an unlimited endpoint lets a loop exhaust the
backend or brute-force a credential. ASVS v5.0.0-2.4.1 (anti-automation controls).

## 2. Sub-tests and coverage of the methodology

| Sub-test | Methodology (guarantee 4.1) |
|---|---|
| `limit_enforced` | "limit enforcement: send past the limit, expect 429" |
| `ip_spoofing_resisted` | "header spoofing resistance: a randomised X-Forwarded-For per call must not bypass the limit" |
| left out | Retry-After reset (needs a real wait, slow); per-user vs per-IP (needs the counter reasoning of two users against one limit); token-bucket burst shape (a timing detail of the limit) |

## 3. Inputs

The documented GET endpoint to flood (derived: the shortest documented GET, or `probe_path`). The burst budget is
the gateway's configured rate-limit (read through `config_values` where available, `Need.GATEWAY` optional) plus a
margin, else `max_burst`.

## 4. Preconditions and reference responses

None beyond the attack surface. The 429 is the reference: `limit_enforced` is the baseline that `ip_spoofing_resisted`
is judged against (a limit must exist before a bypass means anything).

## 5. Probes

A burst of up to the budget of GETs, stopping at the first 429; then, only if the first burst met a 429, the same
burst with a random `X-Forwarded-For` per request. No credential. Effect `STRESSES_TARGET`: the test runs after all
others (rule 7), and the burst stops at the 429 so a working limit is not flooded past its threshold.

## 6. Oracle

**`limit_enforced`**

| Case | Outcome / detail | Confidence |
|---|---|---|
| a 429 within the budget | `ENFORCED/RATE_LIMITED` | - |
| no 429 within the budget | `VIOLATION/NO_RATE_LIMIT` | CERTAIN |
| the endpoint answers 5xx / unavailable | `NOT_VERIFIABLE/UPSTREAM_UNAVAILABLE` | - |

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

"No rate limit on `<path>`" / "Rate limit bypassed by spoofing X-Forwarded-For on `<path>`", `evidence_ref` the
burst's last request.

## 9. Effects on the target

`STRESSES_TARGET`: a burst of requests (stops at the first 429). Runs last. No credential, no data changed.

## 10. Per gateway

Independent of the adapter: the 429 is observed from outside; the configured limit is read through the adapter when
available, to size the burst.

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
| Forgejo + Kong, crAPI + Kong, Forgejo + APISIX | **FAIL** | 150 requests to the shortest documented GET, no 429: no rate limit configured (a real gap of the default labs) |
| Forgejo + Kong, with the plugin below | **PASS** | the 6th request answers 429 (`limit_enforced`), and the same burst with a random X-Forwarded-For still meets the 429 (`ip_spoofing_resisted`: Kong keys on the real connection) |

**The case the labs lack, and how to undo it.** Add a global `rate-limiting` plugin (minute: 5, policy: local) to
`test-environments/forgejo-kong/kong/kong.yml`, then `cd test-environments/forgejo-kong && docker compose --env-file
../../.env up -d --force-recreate --wait kong`; undo with `git checkout` of that file and the same command. The lab
was checked back to FAIL afterwards. Rule 9: both sides proven; `IP_SPOOF_BYPASS` and the transport reasons are not
exercised (Kong resisted the spoof; a gateway trusting X-Forwarded-For would show the bypass).

## 13. Remediation

Configure a rate-limiting plugin on the gateway, keyed to the authenticated user and the real connection (not a
client header), with a `Retry-After` on the 429 (OWASP API4:2023, ASVS v5.0.0-2.4.1).

## 14. Limitations

- The budget bounds the burst: a limit higher than the budget is reported as "no limit" (raise `max_burst` or let
  the gateway config supply the limit).
- Retry-After reset and the per-user-vs-per-IP distinction are not tested.
- A rate limit expressed per hour or per day is not reached by a short burst.

## 15. Sources

- OWASP API4:2023 Unrestricted Resource Consumption: https://owasp.org/API-Security/editions/2023/en/0xa4-unrestricted-resource-consumption/
- OWASP ASVS v5.0.0-2.4.1 (anti-automation controls): https://github.com/OWASP/ASVS/blob/v5.0.0/5.0/en/0x11-V2-Validation-and-Business-Logic.md
- NIST SP 800-204 section 4.5 (rate limiting for microservices): https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-204.pdf
- CWE-770 Allocation of Resources Without Limits or Throttling: https://cwe.mitre.org/data/definitions/770.html

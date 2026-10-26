# 4.4 Request Size Limits

> **Audience:** analysts, contributors · **Status:** new in the test review (2026-10-23) ·
> **Source of truth:**
> [`src/tests/domain_4/test_4_4_request_size_limits.py`](../../../src/tests/domain_4/test_4_4_request_size_limits.py) ·
> **Verified:** 2026-10-23

<!-- [[[cog import generate_docs as g; cog.out(g.test_header("4.4", page=cog.inFile)) ]]] -->

|  |  |
|---|---|
| Test ID | `4.4` |
| Name | Request Size Limits |
| Domain | 4 - Availability and Resilience |
| Priority / strategy | P1 / BLACK_BOX |
| Effect | STRESSES_TARGET |
| CWE | CWE-400 |
| Standards | `OWASP API4:2023`, `OWASP ASVS v5.0.0-2.4.1`, `RFC 9110, Section 15.5.14` |
| Tags | `resource-consumption`, `size-limit` |
| Prerequisites | none |
| Needs | `GATEWAY` (optional) |
| Parameters | [`tests.domain_4.test_4_4`](../../03-reference/01-configuration.md#testsdomain_4test_4_4) |

<!-- [[[end]]] -->

**Same group:** tests `4.1`, `4.2`, `4.3` (resource-consumption limits).

## 1. Guarantee

The gateway rejects an oversized request body with `413` before routing it. A PASS promises an oversized body was
refused. The threat (OWASP API4:2023): without a limit, a large body ties up memory and bandwidth and can exhaust the
backend. ASVS v5.0.0-2.4.1 (controls against excessive resource use).

## 2. Sub-tests and coverage of the methodology

| Sub-test | Methodology (new guarantee) |
|---|---|
| `oversized_body_rejected` | send a body above the limit, expect 413 before it is processed |

## 3. Inputs

The documented write endpoint to probe (derived: the shortest documented POST/PUT/PATCH, or `probe_path`). The size
sent is the gateway's configured body-size limit plus a margin (read through `config_values`, `Need.GATEWAY`
optional), else `body_size_bytes`.

## 4. Preconditions and reference responses

None beyond the attack surface. The request is unauthenticated: the gateway rejects an oversized body by size before
the backend's authentication, so a 413 is the gateway's size control and any other answer means it forwarded the
body.

## 5. Probes

One POST with a body of the chosen size, no credential. Effect `STRESSES_TARGET` (a large body); runs last. No data
is changed (unauthenticated: the backend would reject it on auth, but the gateway's size check comes first).

## 6. Oracle (`oversized_body_rejected`)

| Case | Outcome / detail | Confidence |
|---|---|---|
| the body answers `413` | `ENFORCED/SIZE_LIMIT_ENFORCED` | - |
| the gateway's configured limit was read and the body above it is not rejected | `VIOLATION/NO_SIZE_LIMIT` | CERTAIN |
| no configured limit readable; a body of the default size is not rejected | `VIOLATION/NO_SIZE_LIMIT` | FIRM (a larger limit may exist) |
| the endpoint answers 5xx / unavailable | `NOT_VERIFIABLE/UPSTREAM_UNAVAILABLE` | - |

## 7. Outcomes

SKIP without a documented write endpoint. FAIL when the oversized body is forwarded, PASS on a 413.

## 8. Findings

"Oversized body not rejected: `<path>`", `evidence_ref` the probe request.

## 9. Effects on the target

`STRESSES_TARGET`: one oversized body. Unauthenticated, nothing created.

## 10. Per gateway

Independent of the adapter: the 413 is the gateway's; the configured size limit is read through the adapter when
available, to send a body just above it.

## 11. Configuration

| Parameter | What it is | Derived when left out |
|---|---|---|
| `body_size_bytes` | the body size when the limit is not readable (default 2 MB) | - |
| `probe_path` | the write path to probe | the shortest documented write |

## 12. Validation

Runs of 2026-10-23:

| Lab | Status | Basis |
|---|---|---|
| Forgejo + Kong, crAPI + Kong, Forgejo + APISIX | **FAIL** | a 2 MB body to the shortest documented write is forwarded (not 413): no body-size limit on the gateway (FIRM: a larger limit may exist) |
| Forgejo + Kong, with the plugin below | **PASS** | a `request-size-limiting` plugin (1 MB) answers 413 to the 2 MB body |

**The case the labs lack, and how to undo it.** Add a global `request-size-limiting` plugin (`allowed_payload_size:
1`) to `test-environments/forgejo-kong/kong/kong.yml`, reload Kong (`docker compose ... up -d --force-recreate --wait
kong`); undo with `git checkout` and the same command. The lab was checked back to FAIL. Rule 9: both sides proven.

## 13. Remediation

Configure a request-size limit on the gateway (Kong `request-size-limiting`, Nginx `client_max_body_size`) so an
oversized body is rejected with 413 before it reaches the backend (OWASP API4:2023, ASVS v5.0.0-2.4.1).

## 14. Limitations

- Without a readable configured limit, the test asserts only "no limit at the tested size" (FIRM): a limit above the
  tested size is not detected (raise `body_size_bytes`).
- Only the request body is checked, not the response size or header size.
- A backend that happens to reject the body for another reason before the gateway's size check would read as a limit
  only if it answers 413.
- The probe prefers a write that requires authentication (unauthenticated -> 401, nothing created). Where only a
  public write exists and the gateway has no size limit, a body under the limit could be processed and create an
  object: the oversized probe is still rejected by any size limit, but the absence of one on a public write is a
  creation risk.

## 15. Sources

- OWASP API4:2023 Unrestricted Resource Consumption: https://owasp.org/API-Security/editions/2023/en/0xa4-unrestricted-resource-consumption/
- OWASP ASVS v5.0.0-2.4.1 (anti-automation / resource-consumption controls): https://github.com/OWASP/ASVS/blob/v5.0.0/5.0/en/0x11-V2-Validation-and-Business-Logic.md
- RFC 9110 section 15.5.14 (413 Content Too Large): https://www.rfc-editor.org/rfc/rfc9110.html#section-15.5.14
- CWE-400 Uncontrolled Resource Consumption: https://cwe.mitre.org/data/definitions/400.html

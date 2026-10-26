# 7.1 Sensitive Business Flow Protection

> **Audience:** analysts, contributors · **Status:** new in the test review (branch `test-review`, 2026-10-26) ·
> **Source of truth:**
> [`src/tests/domain_7/test_7_1_sensitive_flow_protection.py`](../../../src/tests/domain_7/test_7_1_sensitive_flow_protection.py) ·
> **Verified:** 2026-10-26

<!-- [[[cog import generate_docs as g; cog.out(g.test_header("7.1", page=cog.inFile)) ]]] -->

|  |  |
|---|---|
| Test ID | `7.1` |
| Name | Sensitive Business Flow Protection |
| Domain | 7 - Business Logic and Sensitive Flows |
| Priority / strategy | P1 / BLACK_BOX |
| Effect | CHANGES_DATA |
| CWE | CWE-799 |
| Standards | `OWASP API6:2023`, `OWASP ASVS v5.0.0-2.4.1` |
| Tags | `business-logic`, `anti-automation` |
| Prerequisites | none |
| Needs | `sensitive_flow` |
| Parameters | [`tests.domain_7.test_7_1`](../../03-reference/01-configuration.md#testsdomain_7test_7_1) |

<!-- [[[end]]] -->

**Same group:** tests `7.2`, `7.3`, `7.4` (business logic and advanced threats).

## 1. Guarantee

A high-value business flow (OTP request, coupon redemption, sign-up, password reset) resists automated abuse: the
server throws an anti-automation control in the way (a CAPTCHA or human-verification challenge, or an aggressive
throttle). A PASS promises a burst of submissions met such a control. The threat (OWASP API6:2023): a script drives
the flow at machine speed for mass sign-up, OTP flooding or coupon draining.

## 2. Sub-tests and coverage of the methodology

| Sub-test | Methodology (guarantee 7.1) |
|---|---|
| `anti_automation_present` | "a sensitive flow must not be drivable by a script: a CAPTCHA / challenge or an aggressive throttle must appear" |
| left out | the *kind* of control (CAPTCHA vs device check vs step-up) is not distinguished; proof-of-work and risk scoring are not probed |

**Boundary (rule 10):** infrastructure rate limiting on any endpoint is **4.1**; this is the business-flow control on
a *declared* sensitive flow, where even a modest automated rate is abuse and the control may be a CAPTCHA, not only a
`429`. Login brute force / enumeration is **1.7**.

## 3. Inputs

`sensitive_flow` (no default): `path`, `method` (default `POST`), an optional `body`, and an optional `role` (omit
for an anonymous flow, the common case). `burst_size` (default 12) bounds the burst.

## 4. Preconditions and reference responses

None beyond the flow being reachable. There is no reference response: the burst is judged on whether a control
appears within it.

## 5. Probes

Up to `burst_size` identical submissions of the flow, stopping at the first control. Effect `CHANGES_DATA`: the burst
drives the real flow (announce it on a shared target); the burst is kept small.

## 6. Oracle

**`anti_automation_present`**

| Case | Outcome / detail | Confidence |
|---|---|---|
| a `429` (throttle) within the burst | `ENFORCED/ANTI_AUTOMATION_THROTTLE` | - |
| a `4xx` whose body is a CAPTCHA / human-verification challenge | `ENFORCED/ANTI_AUTOMATION_CHALLENGE` | - |
| the whole burst accepted, no control | `VIOLATION/NO_ANTI_AUTOMATION` | CERTAIN |
| the flow never returns a usable response | `NOT_VERIFIABLE/FLOW_UNAVAILABLE` | - |

## 7. Outcomes

SKIP without `sensitive_flow`. FAIL when no control appears; PASS when a throttle or a challenge is met.

## 8. Findings

"No anti-automation control on `<method> <path>`", `evidence_ref` the burst's last request.

## 9. Effects on the target

`CHANGES_DATA`: a small burst of the real flow (e.g. password-reset requests trigger OTP mail). No object is created
by the test itself.

## 10. Per gateway

Independent of the adapter: the control is observed from outside.

## 11. Configuration

| Parameter | What it is | Default |
|---|---|---|
| `sensitive_flow` | the flow to probe (`path`, `method`, `body`, `role`) | none (SKIP) |
| `burst_size` | how many submissions before concluding there is no control | 12 |

## 12. Validation

Runs of 2026-10-26:

| Lab | Status | Basis |
|---|---|---|
| crAPI + Kong | **FAIL** | 12 `POST /identity/api/auth/forget-password` all accepted with no throttle and no challenge: crAPI's forgot-password flow has no anti-automation (`VIOLATION/NO_ANTI_AUTOMATION`) |
| Forgejo + Kong, Forgejo + APISIX | **SKIP** | no sensitive business flow declared (`sensitive_flow` unset): honest SKIP |

Rule 9: the `VIOLATION` side is proven on crAPI; the `ENFORCED` sides (a `429` throttle, a CAPTCHA challenge) are
lab-unproven and listed in the Deferred follow-ups (a target with a CAPTCHA or a hard throttle on the flow).

## 13. Remediation

Put an anti-automation control on the flow: a CAPTCHA or human-verification challenge after a few attempts, or a
step-up, plus a flow-specific throttle keyed to the authenticated user and the real connection (OWASP API6:2023,
ASVS v5.0.0-2.4.1).

## 14. Limitations

- The burst is small and sequential: a control that triggers only after many attempts, or a per-hour cap, may be
  missed.
- The kind of control is inferred from the status and body keywords; an unusual challenge body may read as no
  control.

## 15. Sources

- OWASP API6:2023 Unrestricted Access to Sensitive Business Flows: https://owasp.org/API-Security/editions/2023/en/0xa6-unrestricted-access-to-sensitive-business-flows/
- OWASP ASVS v5.0.0-2.4.1 (anti-automation controls): https://github.com/OWASP/ASVS/blob/v5.0.0/5.0/en/0x11-V2-Validation-and-Business-Logic.md
- CWE-799 Improper Control of Interaction Frequency: https://cwe.mitre.org/data/definitions/799.html

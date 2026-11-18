# 7.1 Sensitive Business Flow Protection

> **Audience:** analysts, contributors · **Source of truth:**
> [`src/tests/domain_7/test_7_1_sensitive_flow_protection.py`](../../../src/tests/domain_7/test_7_1_sensitive_flow_protection.py)

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

## 2. Test

### 2.1 Sub-tests and coverage of the methodology

| Sub-test | Methodology (guarantee 7.1) |
|---|---|
| `anti_automation_present` | "a sensitive flow must not be drivable by a script: a CAPTCHA / challenge or an aggressive throttle must appear" |
| left out | the *kind* of control (CAPTCHA vs device check vs step-up) is not distinguished; proof-of-work and risk scoring are not probed |

**Boundary (rule 10):** infrastructure rate limiting on any endpoint is **4.1**; this is the business-flow control on
a *declared* sensitive flow, where even a modest automated rate is abuse and the control may be a CAPTCHA, not only a
`429`. Login brute force / enumeration is **1.7**.

### 2.2 Preconditions and reference responses

None beyond the flow being reachable. There is no reference response: the burst is judged on whether a control
appears within it.

### 2.3 Probes

Up to `burst_size` identical submissions of the flow, stopping at the first control. Effect `CHANGES_DATA`: the burst
drives the real flow (announce it on a shared target); the burst is kept small.

## 3. Oracle

<!-- [[[cog import generate_docs as g; cog.out(g.oracle_table("7.1")) ]]] -->

| Case | Outcome / detail | Confidence |
|---|---|---|
| a `429` within the burst | `ENFORCED/ANTI_AUTOMATION_THROTTLE` | - |
| a challenge: a WAF's challenge header on any answer, or a `400`, `401`, `403`, `409`, `422` asking for a CAPTCHA (words such as `challenge` or `too many` only after a submission was served) | `ENFORCED/ANTI_AUTOMATION_CHALLENGE` | - |
| every submission of the burst answered `2xx`, no throttle and no challenge: accepted, which does not show that none was throttled silently | `VIOLATION/NO_ANTI_AUTOMATION` | FIRM |
| the first submission was refused without a challenge: the burst did not exercise the flow | `NOT_VERIFIABLE/FLOW_NOT_ACCEPTED` | - |
| served, then refused without a `429` or a challenge: an unrecognised throttle or a business refusal | `NOT_VERIFIABLE/REFUSED_AFTER_SERVED` | - |

<!-- [[[end]]] -->

<!-- [[[cog import generate_docs as g; cog.out(g.uninformative_answers("7.1", page=cog.inFile)) ]]] -->

The answers that say nothing about the guarantee by themselves, one rule for every test ([assessment model](../../04-architecture/03-assessment-model.md#answers-that-say-nothing-about-the-guarantee)), generated from the code:

| Answer | Sub-tests | Outcome / detail |
|---|---|---|
| `UPSTREAM_UNAVAILABLE` | every sub-test | `NOT_VERIFIABLE/UPSTREAM_UNAVAILABLE` |
| `RATE_LIMITED` | every sub-test | judged by the oracle above: a `429` is the anti-automation throttle this test looks for (`ANTI_AUTOMATION_THROTTLE`). |
| `SERVER_ERROR` | every sub-test | `NOT_VERIFIABLE/SERVER_ERROR` |
| `NO_RESPONSE` | every sub-test | `NOT_VERIFIABLE/NO_RESPONSE` |

<!-- [[[end]]] -->

## 4. Validation

### 4.1 Oracle cases

<!-- [[[cog import generate_docs as g; cog.out(g.oracle_validation("7.1", page=cog.inFile)) ]]] -->

Every case of the oracle, produced on a lab and judged by the code: E1, [oracle validation](../../../experiments/README.md), campaign at commit `fc60b6f`. 8 of 8 produced cases gave the declared outcome; 0 no lab can produce.

| Case | Lab, how it is produced | Result |
|---|---|---|
| `anti_automation_present/ENFORCED/ANTI_AUTOMATION_THROTTLE` | forgejo-kong: the scratch flow POST /api/v1/markdown as user_a, with rate-limiting minute 5, policy local, on a route POST ~/api/v1/markdown$: five served, the sixth 429 | OK |
| `anti_automation_present/ENFORCED/ANTI_AUTOMATION_CHALLENGE` | forgejo-kong: the scratch flow POST /api/v1/markdown as user_a, on which a route answers 202 with x-amzn-waf-action: challenge at the first submission | OK |
| `anti_automation_present/VIOLATION/NO_ANTI_AUTOMATION/FIRM` | crapi-kong: the lab as built: 12 POST /identity/api/auth/forget-password, all accepted, no throttle and no challenge | OK |
| `anti_automation_present/NOT_VERIFIABLE/FLOW_NOT_ACCEPTED` | forgejo-kong: a scratch flow POST /api/v1/orgs with no role: Forgejo answers every submission 401, nothing is created | OK |
| `anti_automation_present/NOT_VERIFIABLE/REFUSED_AFTER_SERVED` | forgejo-kong: the scratch flow POST /api/v1/markdown as user_a, on a route whose pre-function lets the first three submissions reach Forgejo and answers the next ones 403 with no challenge words | OK |
| `*/NOT_VERIFIABLE/UPSTREAM_UNAVAILABLE` | forgejo-kong: the scratch flow POST /api/v1/markdown as user_a, on a route whose pre-function lets the first three submissions reach Forgejo and answers the next ones 503 | OK |
| `*/NOT_VERIFIABLE/SERVER_ERROR` | forgejo-kong: the scratch flow POST /api/v1/markdown as user_a, on a route whose pre-function lets the first three submissions reach Forgejo and answers the next ones 500 | OK |
| `*/NOT_VERIFIABLE/NO_RESPONSE` | forgejo-kong: the scratch flow POST /api/v1/markdown as user_a, on a route whose pre-function lets the first three submissions reach Forgejo and makes the next ones wait 7 s, with the run's target.read_timeout 5.0 | OK |

<!-- [[[end]]] -->

### 4.2 Results on the labs

<!-- [[[cog import generate_docs as g; cog.out(g.lab_results("7.1", page=cog.inFile)) ]]] -->

No E2 campaign yet ([experiments](../../../experiments/README.md)).

<!-- [[[end]]] -->

## 5. Limitations

- The burst is small and sequential: a control that triggers only after many attempts, or a per-hour cap, may be
  missed.
- The kind of control is inferred from the status and body keywords; an unusual challenge body may read as no
  control.

## 6. Sources

- OWASP API6:2023 Unrestricted Access to Sensitive Business Flows: https://owasp.org/API-Security/editions/2023/en/0xa6-unrestricted-access-to-sensitive-business-flows/
- OWASP ASVS v5.0.0-2.4.1 (anti-automation controls): https://github.com/OWASP/ASVS/blob/v5.0.0/5.0/en/0x11-V2-Validation-and-Business-Logic.md
- CWE-799 Improper Control of Interaction Frequency: https://cwe.mitre.org/data/definitions/799.html

## 7. Inputs

`sensitive_flow` (no default): `path`, `method` (default `POST`), an optional `body`, and an optional `role` (omit
for an anonymous flow, the common case). `burst_size` (default 12) bounds the burst.

## 8. Outcomes

SKIP without `sensitive_flow`. FAIL when no control appears; PASS when a throttle or a challenge is met.

## 9. Findings

<!-- [[[cog import generate_docs as g; cog.out(g.finding_titles("7.1")) ]]] -->

- "No anti-automation control on <method> <path>"

<!-- [[[end]]] -->

`evidence_ref` the burst's last request.

## 10. Effects on the target

`CHANGES_DATA`: a small burst of the real flow (e.g. password-reset requests trigger OTP mail). No object is created
by the test itself.

## 11. Per gateway

Independent of the adapter: the control is observed from outside.

## 12. Configuration

<!-- [[[cog import generate_docs as g; cog.out(g.test_params("7.1", page=cog.inFile)) ]]] -->

Section [`tests.domain_7.test_7_1`](../../03-reference/01-configuration.md#testsdomain_7test_7_1) of `config.yaml`:

| Key | Type | Default | Description |
|---|---|---|---|
| `sensitive_flow` | object \| null | none, **needed to run** | The sensitive business flow to probe for an anti-automation control (a CAPTCHA, a human-verification challenge, an aggressive throttle). No default: unset, the engine records the test as SKIP before it runs. |
| `sensitive_flow.path` | string | required | Path of the sensitive flow. |
| `sensitive_flow.method` | string | `POST` | HTTP method of the flow (default POST). |
| `sensitive_flow.body` | object \| null | none | JSON body submitted on every request (optional). |
| `sensitive_flow.role` | string \| null | none | Role whose credential drives the flow. Omit for an anonymous flow (sign-up, OTP request, password reset), the common case. |
| `burst_size` | int ≥2 | `12` | How many identical submissions the burst sends before concluding there is no anti-automation control. Kept small: the burst drives the real flow. |

<!-- [[[end]]] -->

## 13. Remediation

Put an anti-automation control on the flow: a CAPTCHA or human-verification challenge after a few attempts, or a
step-up, plus a flow-specific throttle keyed to the authenticated user and the real connection (OWASP API6:2023,
ASVS v5.0.0-2.4.1).

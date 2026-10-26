# 1.7 Authentication Endpoints Resist Guessing

> **Audience:** analysts, contributors · **Status:** new in the test review (2026-10-22) ·
> **Source of truth:**
> [`src/tests/domain_1/test_1_7_authentication_resistance.py`](../../../src/tests/domain_1/test_1_7_authentication_resistance.py) ·
> **Verified:** 2026-10-22

<!-- [[[cog import generate_docs as g; cog.out(g.test_header("1.7", page=cog.inFile)) ]]] -->

|  |  |
|---|---|
| Test ID | `1.7` |
| Name | Authentication Endpoints Resist Guessing |
| Domain | 1 - Identity and Authentication |
| Priority / strategy | P1 / GREY_BOX |
| Effect | STRESSES_TARGET |
| CWE | CWE-307 |
| Standards | `OWASP API2:2023`, `OWASP ASVS v5.0.0-6.3.8`, `OWASP ASVS v5.0.0-6.3.1`, `CWE-204`, `CWE-208`, `NIST SP 800-63B, Section 3.2.2` |
| Tags | `authentication`, `brute-force` |
| Prerequisites | none |
| Needs | `USER_ACCOUNT` |
| Parameters | none |

<!-- [[[end]]] -->

**Same group:** tests `1.1` and `1.6`. New guarantee, not in the methodology's catalogue.

## 1. Guarantee

The endpoint that authenticates a caller does not say whether an account exists, and does not let a caller go on
guessing for free. Both make an online password attack cheap: the first tells an attacker which accounts are worth
attacking, the second lets them try.

A PASS promises that the two failed attempts were answered alike and that attempts were limited within the bound
below, from the address this run came from. It promises nothing about the strength of the passwords themselves,
nothing about what the error message discloses beyond the existence of the account (test `6.1`), and nothing about
the general request budget of the API (test `4.1`).

## 2. Sub-tests and coverage of the methodology

| Sub-test | Question |
|---|---|
| `account_enumeration` | a failed authentication for an account that exists is answered differently from one for an account that cannot, by what it says or by how long it takes |
| `repeated_attempts` | consecutive failed attempts are slowed, blocked or answered `429` |

## 3. Inputs

The login request the operator already declares, as the create request of their login resource
(`credentials.login_resource`): its method, path, body and authentication, with the placeholders `{username}` and
`{password}`. This test fills those with values of its own instead of the role's account, so it needs no knowledge
of the target's login and no parameter of its own. The role's account name comes from the configuration.

## 4. Preconditions and reference responses

Its own comparison, not the shared references: the three readings of each case must agree with each other before
the two cases are compared, so that a body carrying a request id or a timestamp is reported as unstable instead of
as a disclosure.

## 5. Probes

1. **three failed attempts with the operator's own account** and a random wrong password, and three with an
   account that cannot exist. That name **keeps the shape of the operator's own**: random characters alone where
   the account is a plain name, and random characters before the same `@domain` where it is an address, so that a
   target which validates the form of a name, or accepts only its own domain, does not answer differently for a
   reason that has nothing to do with the account (corrected 2026-10-22; the labs use both shapes, `user-a` on
   Forgejo and an address on crAPI). Three readings because one reading of a duration is noise; the median is
   kept;
2. **up to 101 further failed attempts against the account that cannot exist.** NIST SP 800-63B-4 section 3.2.2
   requires a verifier to limit consecutive failed attempts "to no more than 100", so the bound is one past the
   published limit and reaching the end is a departure from a rule rather than from an opinion. The number is a
   constant of the module, not a parameter (owner, 2026-10-22);
3. **nothing is sent against a real account more than once per reading.** Account lockout is not probed: see the
   limitations.

## 6. Oracle

| Case | Outcome / detail | Confidence |
|---|---|---|
| the two cases answer the same, and the medians are within the factor | `ENFORCED/NO_DISCREPANCY` | - |
| the bodies differ once the submitted name is masked, the same way on every reading | `VIOLATION/EXISTENCE_DISCLOSED_BY_ANSWER` (CWE-204) | CERTAIN: the two answers are the proof |
| the bodies match and the median for the account that exists is at least 3 times the other | `VIOLATION/EXISTENCE_DISCLOSED_BY_TIMING` (CWE-208) | FIRM: a duration is noisy, and both medians are given |
| the three readings of one case do not agree | `NOT_VERIFIABLE/ANSWER_NOT_STABLE` | - |
| both medians are under 5 ms | `ENFORCED/TIMING_TOO_SMALL`: the ratio of two very small durations says nothing | - |
| the wrong password is accepted | `NOT_VERIFIABLE/WRONG_PASSWORD_ACCEPTED` | - |
| a `429` within the bound | `ENFORCED/ATTEMPTS_LIMITED` | - |
| answers become slow within the bound | `ENFORCED/ATTEMPTS_SLOWED` | - |
| 101 attempts answered as quickly as the first | `VIOLATION/ATTEMPTS_NOT_LIMITED` | FIRM |
| unavailable, no response, server error | `NOT_VERIFIABLE/` the reason | - |

**How a deliberate delay is told from ordinary variation.** The baseline is the median of the first 10 answers; an
answer counts as slowed only when it is at least 3 times that baseline **and** at least 250 ms, and only when two
in a row are. Measured on crAPI (2026-10-22): against a baseline of 4.6 ms a single answer of 30.75 ms was read as
a limit, which is a PASS claimed where there is no control.

**Why the shared fingerprint is not used here.** For a JSON body it keeps the keys and not their values, and crAPI
answers both cases with the same four keys and a different `message`, which it did not see. This test compares the
body itself, with the submitted name masked and runs of digits collapsed, so that an answer echoing what was sent
does not look like a disclosure.

## 7. Outcomes

SKIP when no login request can be built: `credentials.login_resource` is not configured, its create request
authenticates with a credential rather than with an account, or the role has no username and password.

## 8. Findings

One per disclosure and one for the missing limit: "The login answer says whether the account exists", "The login
takes longer for an account that exists" (with both medians and the number of readings), "Failed authentication
attempts are not limited" (with the bound and what NIST requires). `evidence_ref` the attempt for the account that
exists, `supporting_refs` the attempt for the one that cannot.

## 9. Effects on the target

`STRESSES_TARGET`: 6 failed attempts for the comparison and up to 101 more, all but three of them against an
account that cannot exist. The run order puts this test last (rule 7). On a target that logs or alerts on failed
authentication, this test will appear in those logs, which is the point of test `5.2`.

## 10. Per gateway

Independent of the gateway: a rate limit may be applied by the gateway or by the application, and either shows up
as a `429` or as a growing delay.

## 11. Configuration

None. The login request comes from the operator's own `resources` section.

## 12. Validation

Runs of 2026-10-22, the three tests of the group together:

| Lab | Status | Basis |
|---|---|---|
| Forgejo + Kong and + APISIX | FAIL, 3 findings | the answer differs (`user's password is invalid` against `user does not exist`), the medians are 383 to 439 ms against 3 ms, and 101 attempts bring no limit |
| crAPI + Kong | FAIL, 3 findings | the answer differs (`Invalid Credentials` against `Given Email is not registered! `), the medians are 94 ms against 5 ms, and 101 attempts bring no limit |
| Forgejo + Kong, with the rate limit below | **PASS on `repeated_attempts`**: 1 enforced | `ATTEMPTS_LIMITED`, a `429` at the 21st attempt, while `account_enumeration` still reports its 2 violations |
| Forgejo + Kong, with the delay below | the same, `ATTEMPTS_SLOWED` | the answers go from 8 ms to 605 ms from the 31st attempt on |
| Forgejo + Kong, with the scratch configuration below | **INCONCLUSIVE**, 2 not verifiable | `WRONG_PASSWORD_ACCEPTED` in both sub-tests: the test verified nothing and says so instead of reporting a PASS |

**The three cases the labs lack, and how to undo them.** No lab limits failed attempts, and none accepts a wrong
password. The first two are routes added in `test-environments/forgejo-kong/kong/kong.yml`, inside
`services[forgejo-service].routes`, covering the login paths of every account (the repeated attempts go to an
account that does not exist, so its path holds a random name):

```yaml
      - name: review-login-limit-route
        paths:
          - /api/v1/users
        strip_path: false
        preserve_host: false
        protocols:
          - https
        https_redirect_status_code: 301
        plugins:
          - name: rate-limiting
            config:
              minute: 20          # lets the six probes of the comparison through
              policy: local
              limit_by: ip
              hide_client_headers: false
              fault_tolerant: true
```

For the delay, the same route with `pre-function` instead, which only waits and lets the request go on, so that the
real login still works:

```yaml
          - name: pre-function
            config:
              access:
                - |
                  local store = ngx.shared.kong
                  local seen = store:incr("zqxv_login_attempts", 1, 0)
                  if seen and seen > 30 then
                    ngx.sleep(0.6)
                  end
```

Then `docker compose --env-file ../../.env up -d --force-recreate --wait kong`, and undo with `git checkout` and
the same command. A `pre-function` that answers instead of waiting breaks the real login, and the engine then makes
this test ERROR with that reason, which is the correct behaviour and was seen (2026-10-22).

The third case needs no change to the lab, only a scratch configuration whose login resource is a public endpoint
that ignores the account: `path: /api/v1/version`, `method: GET`, `auth: none`, `body: null`,
`values: {credential: version}`. Every attempt is then answered `200`, and the test records
`WRONG_PASSWORD_ACCEPTED`. (With `auth: basic` instead, Forgejo validates the credential even on a public endpoint
and answers `401`, which is itself worth knowing.)

**What each branch has been seen doing** (rule 9). Proven on a lab: `EXISTENCE_DISCLOSED_BY_ANSWER`,
`EXISTENCE_DISCLOSED_BY_TIMING`, `ATTEMPTS_NOT_LIMITED`, and with the cases above `ATTEMPTS_LIMITED`,
`ATTEMPTS_SLOWED` and `WRONG_PASSWORD_ACCEPTED` in both sub-tests. Still unproven: `NO_DISCREPANCY` and
`TIMING_TOO_SMALL` (they need a target that answers two failed attempts alike, which no lab does and no stock
gateway plugin reproduces without faking the login itself), `ANSWER_NOT_STABLE` (a login whose body changes by
itself), the SKIP reasons and the transport reasons.

## 13. Remediation

Answer a failed authentication the same way whether the account exists or not, and take the same time doing it
(verify a dummy hash when there is no account). Limit consecutive failures per account and per caller, with a
`429` or a growing delay.

## 14. Limitations

- **Account lockout is not probed.** It can only be measured by failing repeatedly against a real account, which
  would lock the operator's own test account and break every later test. What is measured is therefore the limit
  the endpoint applies per caller.
- A target that limits only after more than 100 consecutive failures is reported as not limiting: beyond that
  number it is already outside NIST SP 800-63B-4 section 3.2.2.
- The timing oracle is a median of three readings over the network this run came from: on a loaded target or a
  distant one it is weaker, which is why it is FIRM and never CERTAIN.
- Only the login the operator declares is probed. Another authentication endpoint (a password reset, a one-time
  code) is not, unless it is the configured login.

## 15. Sources

- OWASP API2:2023 Broken Authentication: https://owasp.org/API-Security/editions/2023/en/0xa2-broken-authentication/
- OWASP ASVS v5.0.0-6.3.8, this test written out: "Verify that valid users cannot be deduced from failed
  authentication challenges, such as by basing on error messages, HTTP response codes, or different response
  times"; and v5.0.0-6.3.1, the controls against credential stuffing and password brute force:
  https://github.com/OWASP/ASVS/blob/v5.0.0/5.0/en/0x15-V6-Authentication.md
- NIST SP 800-63B-4 section 3.2.2 Rate Limiting (Throttling), "limit consecutive failed authentication attempts
  ... to no more than 100": https://pages.nist.gov/800-63-4/sp800-63b.html
- CWE-307 Improper Restriction of Excessive Authentication Attempts: https://cwe.mitre.org/data/definitions/307.html
- CWE-204 Observable Response Discrepancy: https://cwe.mitre.org/data/definitions/204.html
- CWE-208 Observable Timing Discrepancy: https://cwe.mitre.org/data/definitions/208.html

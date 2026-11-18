# 1.7 Authentication Endpoints Resist Guessing

> **Audience:** analysts, contributors · **Source of truth:**
> [`src/tests/domain_1/test_1_7_authentication_resistance.py`](../../../src/tests/domain_1/test_1_7_authentication_resistance.py)

<!-- [[[cog import generate_docs as g; cog.out(g.test_header("1.7", page=cog.inFile)) ]]] -->

|  |  |
|---|---|
| Test ID | `1.7` |
| Name | Authentication Endpoints Resist Guessing |
| Domain | 1 - Identity and Authentication |
| Priority / strategy | P1 / GREY_BOX |
| Effect | STRESSES_TARGET |
| CWE | CWE-307 |
| Standards | `OWASP API2:2023`, `OWASP ASVS v5.0.0-6.3.8`, `OWASP ASVS v5.0.0-6.3.1`, `CWE-204`, `CWE-208`, `NIST SP 800-63B-4, Section 3.2.2` |
| Tags | `authentication`, `brute-force` |
| Prerequisites | none |
| Needs | `USER_ACCOUNT`, `GATEWAY` (optional) |
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

## 2. Test

### 2.1 Sub-tests and coverage of the methodology

| Sub-test | Question |
|---|---|
| `account_enumeration` | a failed authentication for an account that exists is answered differently from one for an account that cannot, by what it says or by how long it takes |
| `repeated_attempts` | consecutive failed attempts are slowed, blocked or answered `429` |

### 2.2 Preconditions and reference responses

Its own comparison, not the shared references: the three readings of each case must agree with each other before
the two cases are compared, so that a body carrying a request id or a timestamp is reported as unstable instead of
as a disclosure.

### 2.3 Probes

1. **three failed attempts with the operator's own account** and a random wrong password, and three with an
   account that cannot exist. That name **keeps the shape of the operator's own**: random characters alone where
   the account is a plain name, and random characters before the same `@domain` where it is an address, so that a
   target which validates the form of a name, or accepts only its own domain, does not answer differently for a
   reason that has nothing to do with the account. Three readings because one reading of a duration is noise; the median is
   kept;
2. **up to 101 further failed attempts against the account that cannot exist.** The bound is one past the 100
   consecutive failures NIST SP 800-63B-4 section 3.2.2 allows "on a single subscriber account", so that "no limit
   appeared" rests on a published number. NIST's rule is per account, and an account that cannot exist is not
   one: what an unlimited series shows is the absence of a limit per caller, the control against credential
   stuffing and brute force of ASVS v5.0.0-6.3.1. The number is a constant of the module, not a parameter. A block is recognised by
   the answer changing and staying changed, so that a body carrying a request id is never taken for one;
3. **nothing is sent against a real account more than once per reading.** Account lockout is not probed: see the
   limitations.

## 3. Oracle

<!-- [[[cog import generate_docs as g; cog.out(g.oracle_table("1.7")) ]]] -->

**`account_enumeration`**

| Case | Outcome / detail | Confidence |
|---|---|---|
| the masked bodies of the two cases differ, the same way on every reading | `VIOLATION/EXISTENCE_DISCLOSED_BY_ANSWER` | CERTAIN |
| the same, one case answering `500` on every reading (a transient is possible) | `VIOLATION/EXISTENCE_DISCLOSED_BY_ANSWER` | FIRM |
| the existing account's median is 3 times the other's, or every reading of it 40 ms slower than every other one (one median at least 5 ms) | `VIOLATION/EXISTENCE_DISCLOSED_BY_TIMING` | FIRM |
| the bodies agree and the durations do not tell the accounts apart | `ENFORCED/NO_DISCREPANCY` | - |
| the bodies agree and both medians are under 5 ms | `ENFORCED/TIMING_TOO_SMALL` | - |
| the readings of one case do not agree, and the durations do not tell the accounts apart | `NOT_VERIFIABLE/ANSWER_NOT_STABLE` | - |
| the wrong password for the existing account got a `2xx` | `NOT_VERIFIABLE/WRONG_PASSWORD_ACCEPTED` | - |

**`repeated_attempts`**

| Case | Outcome / detail | Confidence |
|---|---|---|
| a `429`, or the refusal status a gateway limit states (APISIX's `503`) after other answers, within the attempts | `ENFORCED/ATTEMPTS_LIMITED` | - |
| three consecutive answers alike and unlike the normal one, by status or masked body | `ENFORCED/ATTEMPTS_BLOCKED` | - |
| two answers in a row at least 3 times the baseline and at least 250 ms | `ENFORCED/ATTEMPTS_SLOWED` | - |
| 101 attempts answered as the first was, with no growing delay | `VIOLATION/ATTEMPTS_NOT_LIMITED` | FIRM |

<!-- [[[end]]] -->

<!-- [[[cog import generate_docs as g; cog.out(g.uninformative_answers("1.7", page=cog.inFile)) ]]] -->

The answers that say nothing about the guarantee by themselves, one rule for every test ([assessment model](../../04-architecture/03-assessment-model.md#answers-that-say-nothing-about-the-guarantee)), generated from the code:

| Answer | Sub-tests | Outcome / detail |
|---|---|---|
| `UPSTREAM_UNAVAILABLE` | every sub-test | `NOT_VERIFIABLE/UPSTREAM_UNAVAILABLE` |
| `RATE_LIMITED` | `account_enumeration` | `NOT_VERIFIABLE/RATE_LIMITED` |
| `RATE_LIMITED` | `repeated_attempts` | judged by the oracle above: a `429` to repeated failed attempts is the limit this sub-test looks for (`ATTEMPTS_LIMITED`). |
| `SERVER_ERROR` | `repeated_attempts` | `NOT_VERIFIABLE/SERVER_ERROR` |
| `SERVER_ERROR` | `account_enumeration` | judged by the oracle above: a `500` on every reading for one account and on none for the other is a status that tells them apart (ASVS v5.0.0-6.3.8 names response codes): compared like any answer, FIRM. |
| `NO_RESPONSE` | every sub-test | `NOT_VERIFIABLE/NO_RESPONSE` |

<!-- [[[end]]] -->

## 4. Validation

### 4.1 Oracle cases

<!-- [[[cog import generate_docs as g; cog.out(g.oracle_validation("1.7", page=cog.inFile)) ]]] -->

Every case of the oracle, produced on a lab and judged by the code: E1, [oracle validation](../../../experiments/README.md), campaign at commit `fc60b6f`. 15 of 15 produced cases gave the declared outcome; 0 no lab can produce.

| Case | Lab, how it is produced | Result |
|---|---|---|
| `account_enumeration/VIOLATION/EXISTENCE_DISCLOSED_BY_ANSWER/CERTAIN` | forgejo-kong: the lab as built: Forgejo answers a wrong password for user-a 401 'user's password is invalid' and an account that cannot exist 401 'user does not exist', the same on every reading | OK |
| `account_enumeration/VIOLATION/EXISTENCE_DISCLOSED_BY_ANSWER/FIRM` | forgejo-kong: a temporary route on POST ~/api/v1/users/zqxv[0-9a-f]+/tokens$ answers 500 itself, so the account that cannot exist (a zqxv name) gets 500 on every reading while user-a gets Forgejo's 401 | OK |
| `account_enumeration/VIOLATION/EXISTENCE_DISCLOSED_BY_TIMING/FIRM` | forgejo-kong: the lab as built: Forgejo verifies the password hash only for user-a, medians about 400 ms against a few ms | OK |
| `account_enumeration/ENFORCED/NO_DISCREPANCY` | forgejo-kong: a temporary route on POST ~/api/v1/users/[^/]+/tokens$ lets the engine's login through, then waits 50 ms and answers 401 'invalid credentials' to every failed attempt (both accounts alike, in the same time, medians above 5 ms); after 20 requests it answers 423 'account locked' | OK |
| `account_enumeration/ENFORCED/TIMING_TOO_SMALL` | forgejo-kong: a temporary route on POST ~/api/v1/users/[^/]+/tokens$ lets the engine's login through and answers every failed attempt 401 'invalid credentials' itself, in less than 5 ms | OK |
| `account_enumeration/NOT_VERIFIABLE/ANSWER_NOT_STABLE` | forgejo-kong: a temporary route on POST ~/api/v1/users/[^/]+/tokens$ lets the engine's login through and answers every failed attempt 401 with a body cycling over three words, in less than 5 ms | OK |
| `account_enumeration/NOT_VERIFIABLE/WRONG_PASSWORD_ACCEPTED` | forgejo-kong: the run's login resource is the public GET /api/v1/version, auth none, no body, credential read from 'version': every attempt is answered 200 | OK |
| `repeated_attempts/ENFORCED/ATTEMPTS_LIMITED` | forgejo-kong: a temporary route on POST ~/api/v1/users/[^/]+/tokens$ with rate-limiting, 20 a minute per IP: the login and the six comparison attempts pass, a later attempt gets Kong's 429 | OK |
| `repeated_attempts/ENFORCED/ATTEMPTS_BLOCKED` | forgejo-kong: the same run as NO_DISCREPANCY: from the 21st request on the route the attempts are answered 423 'account locked', three alike in a row after the 401s | OK |
| `repeated_attempts/ENFORCED/ATTEMPTS_SLOWED` | forgejo-kong: a temporary route on POST ~/api/v1/users/[^/]+/tokens$ whose pre-function counts the requests and, past the 30th, waits 0.6 s before letting the request go on to Forgejo | OK |
| `repeated_attempts/VIOLATION/ATTEMPTS_NOT_LIMITED/FIRM` | forgejo-kong: the lab as built: Forgejo answers the 101 attempts against an account that cannot exist alike, with no limit | OK |
| `*/NOT_VERIFIABLE/UPSTREAM_UNAVAILABLE` | forgejo-kong: a temporary route on POST ~/api/v1/users/[^/]+/tokens$ lets the engine's login through and answers 503 to every failed attempt: the first reading of account_enumeration is 503, and repeated_attempts records the same reason | OK |
| `*/NOT_VERIFIABLE/RATE_LIMITED` | forgejo-kong: a temporary route on POST ~/api/v1/users/[^/]+/tokens$ lets the engine's login through and answers 429 to every failed attempt: account_enumeration records RATE_LIMITED (repeated_attempts then judges the 429 itself, ATTEMPTS_LIMITED) | OK |
| `*/NOT_VERIFIABLE/SERVER_ERROR` | forgejo-kong: the same run as EXISTENCE_DISCLOSED_BY_ANSWER/FIRM: the first repeated attempt against the zqxv account gets 500, which repeated_attempts does not judge | OK |
| `*/NOT_VERIFIABLE/NO_RESPONSE` | forgejo-kong: a temporary route on POST ~/api/v1/users/[^/]+/tokens$ lets the engine's login through and sleeps 7 s before answering the failed attempts, with the run's target.read_timeout at 5.0: both sub-tests record NO_RESPONSE | OK |

<!-- [[[end]]] -->

### 4.2 Results on the labs

<!-- [[[cog import generate_docs as g; cog.out(g.lab_results("1.7", page=cog.inFile)) ]]] -->

No E2 campaign yet ([experiments](../../../experiments/README.md)).

<!-- [[[end]]] -->

## 5. Limitations

- **Account lockout is not probed.** It can only be measured by failing repeatedly against a real account, which
  would lock the operator's own test account and break every later test. What is measured is therefore the limit
  the endpoint applies per caller.
- A target that limits only after more than 100 consecutive failures is reported as not limiting: 101 is the
  bound, borrowed from NIST SP 800-63B-4 section 3.2.2's per-account limit.
- A block whose answer is different every time (a body with a request id and no change of status) is not
  recognised, and the series ends in `ATTEMPTS_NOT_LIMITED`: recognising it would also take noise for a block.
- The timing oracle is a median of three readings over the network this run came from: on a loaded target or a
  distant one it is weaker, which is why it is FIRM and never CERTAIN.
- Only the login the operator declares is probed. Another authentication endpoint (a password reset, a one-time
  code) is not, unless it is the configured login.

## 6. Sources

- OWASP API2:2023 Broken Authentication: https://owasp.org/API-Security/editions/2023/en/0xa2-broken-authentication/
- OWASP ASVS v5.0.0-6.3.8, this test written out: "Verify that valid users cannot be deduced from failed
  authentication challenges, such as by basing on error messages, HTTP response codes, or different response
  times"; and v5.0.0-6.3.1, the controls against credential stuffing and password brute force:
  https://github.com/OWASP/ASVS/blob/v5.0.0/5.0/en/0x15-V6-Authentication.md
- NIST SP 800-63B-4 section 3.2.2 Rate Limiting (Throttling), "limit consecutive failed authentication attempts
  using a specific authenticator on a single subscriber account to no more than 100" (the source of the bound; a
  per-account rule, not probed): https://pages.nist.gov/800-63-4/sp800-63b.html
- CWE-307 Improper Restriction of Excessive Authentication Attempts: https://cwe.mitre.org/data/definitions/307.html
- CWE-204 Observable Response Discrepancy: https://cwe.mitre.org/data/definitions/204.html
- CWE-208 Observable Timing Discrepancy: https://cwe.mitre.org/data/definitions/208.html

## 7. Inputs

The login request the operator already declares, as the create request of their login resource
(`credentials.login_resource`): its method, path, body and authentication, with the placeholders `{username}` and
`{password}`. This test fills those with values of its own instead of the role's account, so it needs no knowledge
of the target's login and no parameter of its own. The role's account name comes from the configuration.

## 8. Outcomes

SKIP when no login request can be built: `credentials.login_resource` is not configured, its create request
authenticates with a credential rather than with an account, or the role has no username and password.

## 9. Findings

<!-- [[[cog import generate_docs as g; cog.out(g.finding_titles("1.7")) ]]] -->

- "Failed authentication attempts are not limited"
- "The login answer says whether the account exists"
- "The login takes longer for an account that exists"

<!-- [[[end]]] -->

`evidence_ref` the existing account's answer, `supporting_refs` the other's; for the attempts, the last one and the first.

## 10. Effects on the target

`STRESSES_TARGET`: 6 failed attempts for the comparison and up to 101 more, all but three of them against an
account that cannot exist. Those three carry a wrong password for **the operator's own account**, so on a target
that locks an account after a few failures they can count towards that lockout; the 101 cannot, which is why they
go to an account that does not exist. The run order puts this test last (rule 7). On a target that logs or alerts on failed
authentication, this test will appear in those logs and may raise an alert; whether it does is guarantee 5.2, which
no test of the tool can check from outside.

## 11. Per gateway

Independent of the gateway: a rate limit may be applied by the gateway or by the application, and either shows up
as a `429` or as a growing delay.

## 12. Configuration

None. The login request comes from the operator's own `resources` section.

## 13. Remediation

Answer a failed authentication the same way whether the account exists or not, and take the same time doing it
(verify a dummy hash when there is no account). Limit consecutive failures per account and per caller, with a
`429` or a growing delay.

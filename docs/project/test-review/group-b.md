# Group B: guarantees 1.1, 1.6, 1.7 (working file)

> **Audience:** the owner and me, during the review. Method: the six phases in
> [`test-review.md`](../test-review.md) (How we work).

| Phase | State |
|---|---|
| 1. Collection | done 2026-10-22 (below) |
| 2. Design | done 2026-10-22, agreed by the owner (its decisions are in 2.6) |
| 3. Code | done 2026-10-22 |
| 4. Proof | done 2026-10-22, the three labs, plus three cases produced on the Forgejo + Kong lab for 1.6 |
| 5. Self-review | done 2026-10-22, four corrections (2.7) |
| 6. Documentation | done 2026-10-22; the owner's commit left |

**The design is now the three test pages:**
[`1.1`](../../05-tests/domain-1/1-1-credential-required.md),
[`1.6`](../../05-tests/domain-1/1-6-session-cookie-safety.md),
[`1.7`](../../05-tests/domain-1/1-7-authentication-resistance.md). What stays here is the collection of phase 1,
the boundary between the three questions, and the review.

The three guarantees share the credential (what a request carries and what the target does without it), the login
endpoint and its answers, and the path variants. 1.1 exists on `main`, 1.6 exists and has never run on a lab, 1.7
is new.

---

## Phase 1: collection (2026-10-22)

Read or measured today on the three running labs, read-only except where said. Nothing was created; the probes that
send a wrong password are counted below and the accounts were checked to still work.

### 1.1 What the specifications declare, and what that is worth

| Specification | Security declaration | Operations |
|---|---|---|
| Forgejo (Swagger 2.0) | a **global** `security` list of seven schemes (`BasicAuth`, `Token`, `AccessToken`, `AuthorizationHeaderToken`, `SudoParam`, `SudoHeader`, `TOTPHeader`) | 473, **every one of them inheriting it**; not one declares its own `security`, and not one declares `security: []` |
| crAPI 1.1.6 (OpenAPI 3.0.1) | `bearerAuth`, declared **per operation** | 35 declare security, **9 declare `security: []`** (sign-up, login, forget-password, the `check-otp` versions, login-with-token) |

This difference is the whole design problem of 1.1, and the old test's results measure it
(`outputs/baseline/`, the tool before the review):

| Lab | Old 1.1 | What the findings are |
|---|---|---|
| Forgejo + Kong and + APISIX | FAIL, **78 findings**, 473 probed, 311 enforced | every one is a genuinely public endpoint: `/api/v1/licenses`, `/api/v1/licenses/{name}`, `/api/v1/gitignore/templates`, `/api/v1/label/templates`, `/api/v1/orgs`, `/api/v1/orgs/{org}`, `/api/v1/orgs/{org}/labels`, ... Forgejo's specification says they need a credential because its global list applies to everything; they do not |
| crAPI + Kong | FAIL, **2 findings**, 35 probed, 32 enforced | both real: `GET /workshop/api/shop/orders/{order_id}` answers `200` unauthenticated (crAPI challenge 14, an order that belongs to a user) and so does `GET /workshop/api/shop/return_qr_code` |

**Conclusion carried into the design:** a per-operation declaration is a statement of intent and can be trusted; a
document-wide default says nothing about any single operation. Whether a document distinguishes the two is a
property of the document, and it can be measured in one pass: crAPI distinguishes (9 operations declare
`security: []`), Forgejo does not (no operation declares anything of its own).

### 1.1 Malformed credentials and header case

`GET /api/v1/user` (Forgejo) and `GET /identity/api/v2/vehicle/vehicles` (crAPI), one request per case:

| Case | Forgejo | crAPI |
|---|---|---|
| no header | 401 `token is required` | 401 `Invalid Token` |
| `Authorization: token ` (empty), `Bearer ` (empty), an arbitrary string | 401 | 401 |
| `Authorization: Bearer null` | 401 `user does not exist [uid: 0, name: ]` | 401 |
| `authorization` and `AUTHORIZATION` (lowercase, uppercase) with a wrong value | 401 | 401 |
| `X-Original-URL: /api/v1/version` | 401 | 401 |

No bypass on either lab: every malformed credential is refused. Forgejo's **message** changes between cases
(`token is required` against `user does not exist`), which is not a bypass; what it discloses is test `6.1`'s
question.

### 1.1 Path variants (measured in group A, phase 1)

12 variants of each lab's canonical documented path: no variant answered `2xx` on any lab. Kong normalises
`/api/v1/./user` and `/api/v1/x/../user` and routes them to the endpoint, which answers `401` as the canonical path
does; APISIX does not normalise them, so Forgejo answers `404`. On crAPI the canonical
`/identity/api/v2/user/dashboard` answers `404` unauthenticated while the trailing-slash, uppercase, `;x=1` and
`.json` variants answer `401`.

### 1.6 What the labs set at login

| Lab | Login | `Set-Cookie` |
|---|---|---|
| Forgejo | an API token created with Basic Auth (`POST /api/v1/users/{username}/tokens`); authenticated `GET /api/v1/user` checked as well | **none**. Forgejo's web login does set a cookie, but the gateway routes only `/api` and `/swagger.v1.json`, so the web login is not reachable through the target |
| crAPI | `POST /identity/api/auth/login` answers `200` with `{"token", "type": "Bearer", "message", "mfaRequired"}` | **none** |

So no lab sets a session cookie, which is why the old 1.6 skipped on all three (it looked for cookie names from a
fixed list: `session`, `sid`, `PHPSESSID`, `JSESSIONID`, ...). A SKIP is the honest answer here, and the situation
"the weakness is there" needs a deliberate change to a lab (below).

### 1.7 User enumeration: a real weakness on both labs

One request per case; the same status code in every case, so a status-based check sees nothing.

| Lab | Account exists, wrong password | Account does not exist |
|---|---|---|
| crAPI | 401 `{"message":"Invalid Credentials"}`, **102 ms** | 401 `{"message":"Given Email is not registered! "}`, **14 ms** |
| Forgejo | 401 `{"message":"user's password is invalid [uid: 2, name: user-a]"}`, **395-431 ms** | 401 `{"message":"user does not exist [uid: 0, name: ...]"}`, **9-12 ms** |

Two independent oracles: the message differs, and the answer is 7 times slower (crAPI) to 40 times slower
(Forgejo) for an account that exists, because the password hash is only verified when there is one. The accounts
were checked afterwards and still work.

### 1.7 Repeated attempts: no resistance on either lab

12 consecutive failed logins against a **nonexistent** account (so that no real account could be locked):

| Lab | Result |
|---|---|
| crAPI | 12 × 401, 10 to 18 ms each, no `429`, no delay, no block |
| Forgejo | 12 × 401, 7 to 11 ms each, the same |

So 1.7 has its "weakness is there" case on both labs, and the "enforced" case needs a rate-limiting plugin on the
login route (a change to a lab's gateway configuration, written on the page with how to undo it, as guarantee 0.1
did).

### 1.7 and 1.6: what is not measured by hand

**Account lockout** was not probed and will not be: it can only be measured by failing repeatedly against a real
account, which would lock the operator's own test account and break every later test. The page says so.

---

## Phase 2: design

### 2.1 The boundary: which question belongs to which test

| Question | Test |
|---|---|
| **does a documented operation answer without any credential, or with a malformed one?** | **`1.1`** |
| **does the target set session cookies, and are they safe and renewed at login?** | **`1.6`** |
| **do the authentication endpoints tell whether an account exists, and do they resist repeated attempts?** | **`1.7`** |
| is a forged credential rejected? an expired one? | `1.2`, `1.3` (group C) |
| is a revoked credential rejected? | `1.4` (group C) |
| is the **right role** required, not just any credential? | `2.1` |
| do equivalent paths to one operation enforce the same controls? | `2.4` |
| does the API limit the request rate in general? | `4.1` |
| does an error message disclose internal information (Forgejo's `uid: 2`)? | `6.1` |
| does something answer a path the gateway has no route for? | `0.2` |

Three consequences: 1.1 never asks whether the credential is *valid* beyond being present and well formed (that is
1.2 and 1.3); 1.7 does not measure the general request budget (4.1) and does not judge what a message discloses
beyond the existence of the account (6.1); 1.6 says nothing about revocation (1.4).

### 2.2 What is shared

- **The path variants** (topic 7b point 1): written once in a new `src/core/path_variants.py`, with its sources, and
  applied by every test whose control is decided on the path. 1.1 declares them as a sub-test; 2.1 will use the same
  list.
- **The login artefacts** (piece 6): 1.6 reads the login's `Set-Cookie` from them instead of logging in again.
- **The positive control**: 1.1 needs it to tell "this operation refuses everyone" from "this operation refuses the
  credential we hold".
- **The calibration**: 1.1 needs it to tell a `404` that means "no such object" from one that means "no such
  endpoint".

### 2.3 Test `1.1`: Credential Required

**Declaration.** `1.1`, name "Credential Required on Documented Operations", P0, GREY_BOX (it needs a credential for
the positive control), effect `CHANGES_DATA` (the writes, below), **CWE-306** "Missing Authentication for Critical
Function" (Base, allowed for mapping; checked 2026-10-22), standards `API2:2023`, `ASVS v5.0.0` chapter V6,
`NIST SP 800-63B` (to verify on its source, section 4.3.1 of revision 4), needs `USER_ACCOUNT`.

**Sub-tests.**

| Sub-test | Question |
|---|---|
| `no_credential` | a documented operation answers a request that carries no credential |
| `malformed_credential` | it answers one that carries a credential that cannot be valid (an empty value, an arbitrary string), and the same with the header name in other cases |
| `path_variants` | it answers a variant of its path (case, trailing slash, double slash, dot segments, encoded separators, `;` parameter) |

**The oracle, and the specification's declaration.** For each documented operation:

| Case | Outcome / detail | Confidence |
|---|---|---|
| refused without a credential (401, 403) | `ENFORCED/CREDENTIAL_REQUIRED` | - |
| answers `2xx` without a credential, and the operation declares its own `security` | `VIOLATION/SERVED_WITHOUT_CREDENTIAL` | FIRM |
| answers `2xx` without a credential, and the document declares `security` only globally | `VIOLATION/SERVED_WITHOUT_CREDENTIAL` | **TENTATIVE**, and the finding says that the declaration is the document's default, so the operation may be public and undeclared |
| the operation declares `security: []` | `NOT_APPLICABLE/DECLARED_PUBLIC` | - |
| answers like a random sibling (the object does not exist) | `NOT_VERIFIABLE/NOT_FOUND_LIKE_UNKNOWN` | - |
| the positive control does not work (our credential is refused everywhere) | `NOT_VERIFIABLE/CREDENTIAL_NOT_WORKING` | - |
| unavailable, rate limited, no response, server error | `NOT_VERIFIABLE/` the reason (the old test counted 14 endpoints answering `503` as a PASS) | - |

**The mismatch is always reported** (owner, 2026-10-22). I had proposed counting the globally declared ones as
`NOT_VERIFIABLE` with one note, to keep Forgejo's 78 out of the findings; the owner's objection holds: the
specification declaring everything protected while some endpoints are public *is* a disagreement worth reporting,
and burying it would also bury a real regression, since an endpoint that lost its authentication on such a target
would land in the same silent heap. So the outcome is the same in both cases and **the specificity of the
declaration sets the confidence**: FIRM when the operation says it of itself, TENTATIVE when only the document's
default applies. A reader sorts by confidence, which is what confidence is for (topic 5).

**One measurement per run tells the reader which world they are in:** whether any operation declares its own
`security` (including `security: []`). crAPI does, Forgejo does not. It goes in a note of the result, once, so that
78 TENTATIVE findings are read for what they are.

**Probes.** Every documented operation, not a sample (the methodology asks for it): one request without a
credential. A read keeps `path_seed`, so that it reaches the control instead of a 404.

**Writes are probed, on random values** (decided by the precedent of 0.1, owner 2026-10-21: "more discovery is
better, with cleanup"). An operation whose method writes is sent on a path whose parameters are random values of the
declared type (`random_sibling_path`), never on the operator's resources, so that a write which gets through finds
no object of theirs to act on; anything it creates (a `2xx` with a `Location`) is deleted at once, and what cannot
be deleted is stated in the result. The effect becomes `CHANGES_DATA`, which puts the test after the read-only ones
in the run order. The alternative, not sending writes at all, would leave the most dangerous half of the surface
unchecked.

The malformed credentials and the path variants are applied to a sample chosen by a stated rule: the operations
proven to require a credential, one per first path segment, because a variant is interesting only where the control
exists.

### 2.4 Test `1.6`: Session Cookies

**Declaration.** `1.6`, name "Session Cookie Safety", P3, GREY_BOX, effect `READ_ONLY`, **CWE-1004** "Sensitive Cookie
Without 'HttpOnly' Flag", with `CWE-614` (no `Secure`), `CWE-1275` (no or a bad `SameSite`) and `CWE-384` (session
fixation) among the references, each finding citing the one that fits it (owner, 2026-10-22: name the entry).
Standards `API2:2023`, `ASVS v5.0.0` chapter V3 (to verify its numbering in 5.0.0), needs `USER_ACCOUNT`.

**Sub-tests.**

| Sub-test | Question |
|---|---|
| `cookie_attributes` | every cookie the login sets carries `Secure`, `HttpOnly` and a `SameSite` value |
| `session_renewed` | a cookie obtained before the login is not still valid as the session afterwards (session fixation, ASVS V3.2.1) |

**Oracle.** Per cookie: all three attributes present → `ENFORCED/COOKIE_SAFE`; one missing →
`VIOLATION/COOKIE_WITHOUT_<attribute>` at CERTAIN (the header is the proof). For `session_renewed`: the value of the
cookie set before the login compared with the one after → different → `ENFORCED/SESSION_RENEWED`; identical →
`VIOLATION/SESSION_NOT_RENEWED` at FIRM. No cookie at login → SKIP with the reason, which is what the three labs
give.

**What it drops from the old test:** the fixed list of cookie names (`session`, `sid`, `JSESSIONID`, ...). Every
cookie a login sets is judged, whatever its name: a name list skips the one that matters.

### 2.5 Test `1.7`: Authentication Endpoint Resistance

**Declaration.** `1.7`, name "Authentication Endpoints Resist Guessing", P1 (proposed), GREY_BOX, effect
`STRESSES_TARGET`, **CWE-307** "Improper Restriction of Excessive Authentication Attempts" (Base), with `CWE-204`
(Observable Response Discrepancy) and `CWE-208` (Observable Timing Discrepancy) among the references, the
enumeration findings citing those two. Standards `API2:2023`, `ASVS v5.0.0` chapter V6 (to verify),
`NIST SP 800-63B` section 5.2.2 (rate limiting, to verify), needs `USER_ACCOUNT`.

**Sub-tests.**

| Sub-test | Question |
|---|---|
| `account_enumeration` | the answer to a failed authentication says whether the account exists, by its content or by how long it takes |
| `repeated_attempts` | repeated failed attempts are slowed, blocked or answered `429` |

**Probes, and their safety.**

- enumeration: **one** failed attempt with the operator's own account and a wrong password, and one with a random
  account that cannot exist. Compared by the shape of the answer (the fingerprint of
  `src/core/references.py`) and by their durations, each measured three times to have a median rather than one
  reading;
- repeated attempts: a bounded number (proposed: 15) of failed attempts against the **random, nonexistent**
  account, never against a real one. This measures what the endpoint does per address, which is what can be
  measured without locking anybody out;
- **account lockout is not probed**, and the page says why: it can only be measured by failing repeatedly against a
  real account, which would lock the operator's test account and break every later test.

**Oracle.**

| Case | Outcome / detail | Confidence |
|---|---|---|
| the two failed attempts answer the same shape, and their durations are within the noise | `ENFORCED/NO_DISCREPANCY` | - |
| the shapes differ | `VIOLATION/EXISTENCE_DISCLOSED_BY_ANSWER` | CERTAIN: the two answers are the proof |
| the shapes match but the durations differ by more than the stated factor | `VIOLATION/EXISTENCE_DISCLOSED_BY_TIMING` | FIRM: timing is noisy, the medians are given |
| a `429`, a growing delay or a block appears within the bounded attempts | `ENFORCED/ATTEMPTS_LIMITED`, with what appeared | - |
| every attempt answers the same way, as fast as the first | `VIOLATION/ATTEMPTS_NOT_LIMITED` | FIRM |
| the login endpoint cannot be found in the specification or the resources | SKIP with the reason | - |

**Where the login endpoint comes from:** the prepared login resource (`credentials.login_resource`), which the
operator already declares for every lab, and its method and path. No new parameter.

### 2.7 What phases 3 to 5 added to the design

| # | Change | Why |
|---|---|---|
| 1 | **The engine obtains the credential of every account a test declares** (`NEED_ROLES` in `src/core/test_needs.py`, used in `_execute_single_test`), as it already gave the gateway to the tests that declare it; a login that fails makes that test ERROR with the reason | Owner, 2026-10-22: a declared need should be provided, not merely checked. 1.6 had been patched to log in for itself, and the problem was not the partial selection: in a full run too, nothing guarantees that an earlier test has logged in. Every later test loses three lines and an error branch; group C has three tests that all need a credential |
| 2 | **1.1 carries no credential at all** (BLACK_BOX, no needs), and asks no positive control | Asking one per violation suppressed 24 true cases on Forgejo: the lab's token is issued with narrower scopes than anonymous access, so the operation refused it while serving an anonymous request. The verdict is about the absence of a credential, which is observed directly: rule 3 does not apply to it |
| 3 | **1.1 separates three answers it had lumped together**: `VALIDATED_WITHOUT_CREDENTIAL` (a `400`, so validation ran before authentication, which NIST SP 800-228 REC-API-14 advises against), `NOT_FOUND_OWN_ANSWER` and `REDIRECTED` | The 10 cases it called "not served" were 5 of each kind, and the `400` ones are a different fact worth naming |
| 4 | **1.7 compares the body itself**, with the submitted name masked and digits collapsed, after checking that the three readings of each case agree | The shared fingerprint keeps the keys of a JSON body and not their values, and crAPI answers both cases with the same four keys and a different `message`: the enumeration was caught only by the timing, and by hand I had seen the messages differ |
| 5 | **1.7 tells a deliberate delay from ordinary variation**: the baseline is the median of the first 10 answers, an answer counts as slowed only at 3 times that baseline **and** at least 250 ms, and only when two in a row are | On crAPI a single answer of 30.75 ms against a baseline of 4.6 ms was read as a limit: a PASS claimed where there is no control, which is the worst kind of error |
| 6 | **1.6 judges only the cookie attributes**; session fixation is left out and named in the limitations | It needs a login that can be repeated while carrying a cookie, which the resource mechanism does not do, and a form login with a CSRF token is not generic. Approximating it by comparing two unrelated visits would prove nothing |
| 7 | `EndpointRecord.auth_declaration` (`OPERATION` or `DOCUMENT`) in the surface, set by the discovery | The confidence of 1.1 rests on it, and the information was being lost: `requires_auth` alone does not say whether the operation declared it |
| 8 | `src/core/path_variants.py`, the shared list of path variants with its sources | Topic 7b point 1: written once, used by 1.1 now and by 2.1 later |
| 9 | **1.1 sends a credential that cannot be valid where and how the target expects a credential** (`credential_placement`), not always as `Authorization: Bearer ...` | Found on the owner's question about agnosticism: Forgejo expects `Authorization: token <value>`, so every `Bearer` probe was refused for being the wrong scheme and never reached the check it was meant to test. Now the probes go as `token ...` on Forgejo and `Bearer ...` on crAPI, each from that target's own declaration |
| 10 | **1.7's impossible account keeps the shape of the operator's own** (random characters alone, or random characters before the same `@domain`) | Same question: the name was always shaped as an address, so on a target that validates the form of a name, or accepts only its own domain, the two cases would have differed for a reason that has nothing to do with the account, and the test would have reported a disclosure that is not one |

### 2.8 Results on the labs (phase 4, 2026-10-22)

| Lab | `1.1` | `1.6` | `1.7` |
|---|---|---|---|
| Forgejo + Kong | FAIL 78, all TENTATIVE | SKIP (the login sets no cookie) | FAIL 3 |
| crAPI + Kong | **FAIL 2, FIRM** (challenge 14 and `return_qr_code`) | SKIP | FAIL 3 |
| Forgejo + APISIX | FAIL 78, all TENTATIVE | SKIP | FAIL 3 |

1.1 on crAPI also records 9 `DECLARED_PUBLIC` (the operations marked `security: []`), which is the mechanism
working: the document says which operations are public, so the test leaves them alone.

For 1.6, three cases were produced on the Forgejo + Kong lab by having the gateway add a cookie to the login
response (the exact configuration and how to undo it are on the test page): without the attributes FAIL 3, with
them PASS complete, with `SameSite=None` FAIL 1. The lab was restored and checked back to its usual results.

A regression run of every native test on the branch (0.1, 0.2, 0.3, 0.4, 1.1, 1.6, 1.7, 4.2) gives the same results
as before the engine change, in the order the effects dictate: the read-only tests, then 1.1 (`CHANGES_DATA`), then
0.1 and 1.7 (`STRESSES_TARGET`).


### 2.6 Decided (owner, 2026-10-22)

1. **1.1 reports every mismatch**, with the confidence set by how specific the declaration is (2.3 above). My
   proposal to hide the globally declared ones is dropped.
2. **1.1 probes writes**, on random values, with cleanup, following the precedent of 0.1; the test declares
   `CHANGES_DATA`.
3. **1.7's budget is a constant** of the module: 15 failed attempts against a nonexistent account plus 6 for the
   enumeration comparison. No new configuration key (the review has been removing knobs, not adding them); if a
   real target ever needs a different bound, it becomes a parameter then, with that case as its reason.
4. **The CWE of each test** is named above: `CWE-306` for 1.1, `CWE-1004` for 1.6 with `CWE-614`, `CWE-1275` and
   `CWE-384` among its references, `CWE-307` for 1.7 with `CWE-204` and `CWE-208`. Each entry was read on its MITRE
   page for its level and whether MITRE allows mapping to it.
5. **1.6 gets a case on a lab.** Forgejo's web login does set a session cookie but is not reachable through the
   gateway, so a route to it is added to the Forgejo + Kong lab for the proof, written on the test page with the
   exact configuration and how to undo it, and undone afterwards (as guarantee 0.1 did for its two cases).

### Changes outside this group's own files, deferred

Deferred to the list in [`test-review.md`](../test-review.md) ("Documentation changes to apply later"):

- `06-knowledge/04-guarantees.md`: sections 1.1 and 1.6 aligned with what is implemented (1.6 keeps only the cookie
  attributes, with the reasons for the items left out); **1.7 added** as a new guarantee.
- `04-architecture/01-overview.md`, `02-data-model.md`, `03-assessment-model.md`,
  `02-guides/03-extending/02-add-a-native-test.md`: the engine provides a declared account need, so a test no
  longer calls `acquire_tokens` itself; `EndpointRecord.auth_declaration`; `src/core/path_variants.py`.
- `03-reference/06-compatibility.md` (Test portability), `roadmap.md` (1.1 and 1.6 rewritten, 1.7 added),
  `CHANGELOG.md`, the usage guides.
- `OPEN_QUESTIONS.md`: the Q-29 items for 1.1 (the 14 endpoints answering `503` counted as a PASS, only `2xx`
  treated as a bypass, the credential always sent as `Bearer`) and for 1.6 (the fixed list of cookie names) are
  answered; Q-30's item on unauthenticated writes is answered by the random-value probe.

# Group C: guarantees 1.2, 1.3, 1.4 (working file)

> **Audience:** the owner and me, during the review. Method: the six phases in
> [`test-review.md`](../test-review.md) (How we work).

| Phase | State |
|---|---|
| 1. Collection | done 2026-10-22 (below) |
| 2. Design | done 2026-10-22; owner chose native, no key parameter, 1.4 not crAPI-specific |
| 3. Code | done 2026-10-22 |
| 4. Proof | done 2026-10-22, the three labs, plus a case on the Forgejo + Kong lab for 1.4 |
| 5. Self-review | done 2026-10-22 (the anchor fix, below) |
| 6. Documentation | done 2026-10-22; the owner's commit left |

**The design is now the three test pages:**
[`1.2`](../../05-tests/domain-1/1-2-credential-cryptographically-valid.md),
[`1.3`](../../05-tests/domain-1/1-3-credential-expiry.md),
[`1.4`](../../05-tests/domain-1/1-4-credential-revocation.md). What stays here is the collection, the boundary,
the decisions and the review.

### Decided (owner, 2026-10-22)

1. **Native, not jwt_tool.** The key-based JWT attacks cannot run on a target that exposes no key (ours, and the
   common case): not by us, not by jwt_tool. The key-free attacks are a short closed list our Python covers. So no
   jwt_tool install, and no `jwt_forge.py` yet.
2. **No key parameter.** The key-based cases stay `NOT_VERIFIABLE/NEEDS_KEY_MATERIAL`, named, rather than faked.
3. **1.4 not crAPI-specific**: revocation by the login's own mechanism (deletion/logout), password-change
   revocation left to a configured flow.

### What phases 3 to 5 added

| # | Change | Why |
|---|---|---|
| 1 | `src/core/jwt_tokens.py`: read a JWT and build the three key-free variants (alg:none, tampered, stripped), pure stdlib, no signing | 1.2 and 1.3 read and (1.2) degrade the token; no crypto library, no dependency |
| 2 | `src/tests/helpers/anchor.py`: a derived anchor, a documented read that answers 2xx **with** the credential and non-2xx **without** it | 1.2 and 1.4 need to tell "degraded/revoked credential refused" from "public endpoint"; the old 1.4 used a configured endpoint |
| 3 | **The anchor must refuse a no-credential request**, not only serve a credentialled one | Found producing 1.4's violation case: `/api/v1/orgs` is public on Forgejo while the spec marks it protected, and answered 401 only to an *invalid* token, which is not revocation. The two-sided anchor fixes 1.4 and sharpens 1.2 |
| 4 | 1.2/1.3 reference the exact ASVS entries read on the source: 9.1.1 (verify signature), 9.1.2 (algorithm allowlist), 9.2.1 (validity span), 7.3.2 (absolute lifetime) | rule 8 |

### Results on the labs (phase 4, 2026-10-22)

| Lab | `1.2` | `1.3` | `1.4` |
|---|---|---|---|
| crAPI + Kong | **FAIL** (alg:none accepted, challenge 15) | **FAIL** (7-day lifetime, TENTATIVE) | SKIP (no revocation) |
| Forgejo + Kong, Forgejo + APISIX | SKIP (opaque token) | SKIP (opaque token) | **PASS** (deleted token refused) |

1.2's tampered and stripped variants are correctly refused on crAPI, so the server verifies the signature but
trusts `alg: none`. 1.4's violation branch was produced on the Forgejo + Kong lab (an endpoint that trusts any
token), written on the test page and undone; the full native regression on the branch is unchanged, in the order
the effects dictate.

### Out of reach, with the reason

| Branch | Why |
|---|---|
| 1.2 algorithm confusion, re-signing | need the public or signing key; no target gives us one |
| 1.3 `NO_EXP_CLAIM`, `LIFETIME_BOUNDED`, `NO_IAT_CLAIM` | need a JWT issuer we control; the labs issue only crAPI's fixed 7-day token or an opaque one |
| 1.4 password-change revocation | a target-specific reset/OTP flow, left to a configured path |

### Changes outside this group's own files, deferred

Deferred to the list in [`test-review.md`](../test-review.md):

- `06-knowledge/04-guarantees.md`: 1.2, 1.3, 1.4 aligned with what is implemented (the key-based cases marked as
  needing key material the target must supply).
- `06-knowledge/05-tool-decisions.md`: jwt_tool recorded as not used for 1.2/1.3 on a keyless target, with the
  reasoning; the native `jwt_forge.py` stays "planned, for when a key is supplied".
- `04-architecture/*`: `src/core/jwt_tokens.py` and `src/tests/helpers/anchor.py` as shared infrastructure.
- `03-reference/06-compatibility.md` (1.2/1.3 need a JWT target; 1.4 needs a revocable login), `roadmap.md`,
  `CHANGELOG.md`.
- `OPEN_QUESTIONS.md`: Q-32 (token valid after a password change) noted as a target-specific flow for a later
  review; the 1.4 `protected_endpoint` parameter removed (derived anchor).

The three guarantees share one thing: a credential the test obtained by a normal login, which it then presents in
a degraded form (invalid, expired, revoked) and expects to be refused. 1.2 and 1.3 are about a JSON Web Token (JWT)
and its cryptography; 1.4 is about the lifecycle of any credential and is stateful, not cryptographic.

---

## Phase 1: collection (2026-10-22)

Read or measured today on the running labs, read-only.

### What kind of credential each lab issues

| Lab | Credential | Shape |
|---|---|---|
| crAPI | a real **JWT**, header `{"alg":"RS256"}`, claims `exp`, `iat`, `role`, `sub` | three dot-separated segments, RSA signature |
| Forgejo | an **opaque API token** (sha1), created by `POST /api/v1/users/{username}/tokens` | not a JWT: nothing to decode, no claims, no signature to attack |

**This splits the group by target.** 1.2 (cryptographic validity) and 1.3 (expiry) have a subject only where the
credential is a JWT, so on Forgejo they are `NOT_APPLICABLE` with that reason, not SKIP: the guarantee is about a
JWT and this target issues none. 1.4 (revocation) applies to both, by different mechanisms (below).

### crAPI's JWT, and what can and cannot be done to it

- **Lifetime** `exp - iat` = **604800 s = 7 days.** NIST SP 800-63B-4 recommends access tokens of 5-15 minutes; a
  7-day access token is a weakness we can read straight off the token, with no forging at all.
- **No public JWKS** found at the usual paths (`/.well-known/jwks.json` → 404; the `/identity/...` variants → 401,
  i.e. the identity service refusing an unknown path, not a key set). So the public key is not offered to us.
- **We do not have the signing key** (crAPI's RSA private key is inside the identity service).

What this means for the forging the methodology describes:

| Manipulation (methodology 1.2 / 1.3) | Needs | Possible on our labs? |
|---|---|---|
| `alg: none`, empty or stripped signature | nothing: re-encode the header, drop the signature | **yes, natively** |
| tampered payload with the original signature | nothing: change a claim, keep the third segment | **yes, natively** |
| algorithm confusion (RS256 verified as HS256 with the public key as the HMAC secret) | the **public** key (JWKS) | no: crAPI exposes none |
| expired `exp`, future `exp`, negative `exp`, clock-skew leeway | a token **re-signed** with a chosen claim → the **signing** key | no: we do not have it, and neither would jwt_tool |
| `kid` mismatch, key rotation | a JWKS with two keys and the signing key | no |

So the cases that need no key test the single most important thing (**does the server verify the signature at
all**), and they are fully agnostic: they work on any JWT target. The cases that need the signing key cannot be
done by anyone, us or any tool, unless the operator supplies the key, which our labs do not.

### 1.4 revocation, on each lab

| Lab | Revocation mechanism | Old 1.4 result |
|---|---|---|
| Forgejo | the API token can be **deleted** (`DELETE /api/v1/users/{username}/tokens/{id}`), which revokes it | PASS: the token gives `401` after deletion |
| crAPI | **no logout**; the JWT is stateless. The spec has `reset-password` and `forget-password` (both behind the OTP flow), no token-invalidation endpoint | SKIP: `Need.REVOCABLE_LOGIN` not met |

crAPI challenge, flagged in Q-32: a JWT stays valid after a password change (a stateless-JWT revocation failure).
Reaching it needs the OTP reset flow, which the lab routes through MailHog.

### The methodology's tool, read on its source

`docs/06-knowledge/05-tool-decisions.md`: 1.2 and 1.3 are HYBRID with **jwt_tool** (Category A, mandatory). Its
stated value: "a community-maintained catalogue of JWT attacks; keeping an equivalent catalogue up to date in
Python would mean continuous maintenance of applied cryptography." It also notes a native `jwt_forge.py` helper for
context-aware cases, "planned, it does not exist." jwt_tool is **not installed** (`install_tools.sh` has no slot
for it). 1.4: no external tool, "stateful Python logic on the `TestContext`" (as the old test does).

---

## Phase 2: design

### The boundary (one question, one test)

| Question | Test |
|---|---|
| **is a cryptographically invalid credential refused?** (unsigned, tampered, stripped, confused algorithm) | **`1.2`** |
| **is a credential's expiry declared and sane, and an expired one refused?** | **`1.3`** |
| **is a revoked credential refused?** (after deletion / logout / password change) | **`1.4`** |
| is a credential required at all? malformed-but-well-formed refused? | `1.1` (done) |
| does the login disclose which accounts exist? | `1.7` (done) |
| is the credential sent only over TLS? | `1.5` (group D) |

So 1.2 never asks whether the token has expired (1.3) nor whether it was revoked (1.4); 1.3 asks only about time;
1.4 asks only about an explicit revocation, taking the token's own validity for granted.

### The decision that is the owner's: jwt_tool, or native (resolved: native)

Collection changed the premise behind the methodology's "jwt_tool for 1.2/1.3". jwt_tool's value is a maintained
catalogue of JWT attacks **and** minting arbitrary tokens from a key. But on a target that exposes no JWKS and whose
signing key we do not hold (our labs, and the common case), the key-based attacks cannot run at all, by us or by
jwt_tool; and the key-free attacks are a short, closed list that our Python covers exactly and agnostically. This is
the same test the owner set for 0.1 (is the tool genuinely built for a job we cannot match?) giving, this time, the
opposite answer to fuzzing: the job that a tool does better here only exists when the operator supplies a key.

**My recommendation.** Native for what needs no key, now; defer the key-based path to an optional helper that runs
only when the operator supplies the signing key (the methodology's `jwt_forge.py`), and do not install jwt_tool
speculatively. Concretely:

- **1.2 native**, the signature-verification attacks that need no key: `alg: none`, tampered payload with the
  original signature, stripped signature. Each expects `401`. When the operator supplies a JWKS or a key (a new
  optional input), the algorithm-confusion and wrong-key cases are added; without it they are
  `NOT_VERIFIABLE/NEEDS_KEY_MATERIAL`, named so the report is honest about what was not tried.
- **1.3 native, mostly without forging**: read `exp` and `iat` from the obtained token and judge (a) an expiry is
  declared at all, (b) the lifetime is within a bound (a finding on crAPI's 7 days). "An expired token is actually
  refused" needs a token with a past `exp`, which needs the key: `NOT_VERIFIABLE/NEEDS_KEY_MATERIAL` unless the
  operator supplies it.
- **1.4 native**, stateful, as the old test: obtain a token, revoke it (delete / logout, per the configured login
  resource), reuse it, expect `401`; plus the password-change case where the configuration describes that flow.

The alternative the owner may prefer: install jwt_tool as Category A says, and use it for the key-free cases too
(it would run the same attacks). It adds an install and a connector, and buys nothing on a keyless target, but it
keeps the methodology's catalogue for the day a key is supplied. **I need your decision here before writing code.**

A practical note, not a reason by itself: crafting and sending forged authentication tokens by hand has repeatedly
been stopped by the safety classifier in this session. Inside the test, with logging, run as a tool, this is the
ordinary behaviour of a security-assurance tool; if the classifier still stops me mid-run, you can run the test
locally and send me the output, as we agreed earlier.

### Compact design, pending that decision

**1.2 Credential Cryptographically Valid.** P0, GREY_BOX (needs a valid JWT: `USER_ACCOUNT`), effect `READ_ONLY`,
CWE to pick on its page (candidates: CWE-347 Improper Verification of Cryptographic Signature, which fits exactly).
Standards API2:2023, RFC 8725 section 3, ASVS v5.0.0 chapter V9 (to verify its numbering). Sub-tests
`unsigned_rejected`, `tampered_rejected`, `stripped_rejected`, and `algorithm_confusion` (the last
`NOT_VERIFIABLE/NEEDS_KEY_MATERIAL` without a JWKS). Oracle: each degraded token expects a refusal; a `2xx` is
`VIOLATION` at CERTAIN; the token is first confirmed to work unmodified (positive control) so that a refusal is
known to be about the manipulation. `NOT_APPLICABLE/NOT_A_JWT` when the credential is opaque (Forgejo).

**1.3 Credential Expiry.** P0, GREY_BOX, `READ_ONLY`, CWE-613 (Insufficient Session Expiration). Standards
API2:2023, RFC 7519 section 4.1.4, ASVS v5.0.0 V9, NIST SP 800-63B-4 section 4 (lifetime). Sub-tests
`expiry_declared` (the token carries `exp`), `lifetime_bounded` (within a configurable maximum, default from NIST's
15 minutes for an access token; crAPI's 7 days is the finding), `expired_rejected`
(`NOT_VERIFIABLE/NEEDS_KEY_MATERIAL` without the key). `NOT_APPLICABLE/NOT_A_JWT` on Forgejo.

**1.4 Credential Revocation.** P2, strategy by the login (revoking by deletion is WHITE_BOX today via
`Need.REVOCABLE_LOGIN`), effect `CHANGES_DATA` (it revokes a credential it created). Standards API2:2023, RFC 7009,
RFC 7519 section 4.1.7, ASVS v5.0.0 V7/V9. Sub-tests `rejected_after_revocation` (delete/logout then reuse) and, where
the configuration describes it, `rejected_after_password_change`. This is the old 1.4 rebuilt on the new base, with
the crAPI password-change case added if its OTP flow can be driven generically (open question for its own review).

### Open points for the owner (resolved; see "Decided" at the top)

1. **jwt_tool or native** (the decision above). My recommendation: native now, jwt_tool/`jwt_forge.py` deferred to
   when a key is supplied.
2. **A new input for the signing key / JWKS.** The key-based cases need the operator to supply a key or a JWKS URL.
   I would add it only if you choose to cover those cases now; otherwise they stay `NEEDS_KEY_MATERIAL`. This is a
   new configuration parameter, so it is yours to approve.
3. **1.4 and crAPI's password change.** Driving the OTP reset flow (through MailHog on the lab, through a real
   mailbox on a real target) is target-specific. I propose 1.4 covers revocation by the configured login's own
   mechanism (deletion/logout) and leaves password-change revocation to a configured flow, not hard-coded.

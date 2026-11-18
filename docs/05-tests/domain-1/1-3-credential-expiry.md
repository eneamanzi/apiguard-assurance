# 1.3 Credential Expiry

> **Audience:** analysts, contributors · **Source of truth:**
> [`src/tests/domain_1/test_1_3_credential_expiry.py`](../../../src/tests/domain_1/test_1_3_credential_expiry.py), [`src/core/jwt_tokens.py`](../../../src/core/jwt_tokens.py)

<!-- [[[cog import generate_docs as g; cog.out(g.test_header("1.3", page=cog.inFile)) ]]] -->

|  |  |
|---|---|
| Test ID | `1.3` |
| Name | Credential Expiry |
| Domain | 1 - Identity and Authentication |
| Priority / strategy | P0 / GREY_BOX |
| Effect | READ_ONLY |
| CWE | CWE-613 |
| Standards | `OWASP API2:2023`, `RFC 7519, Section 4.1.4`, `OWASP ASVS v5.0.0-9.2.1`, `OWASP ASVS v5.0.0-7.3.2` |
| Tags | `authentication`, `jwt` |
| Prerequisites | none |
| Needs | `USER_ACCOUNT` |
| Parameters | none |

<!-- [[[end]]] -->

**Same group:** tests `1.2` and `1.4`.

## 1. Guarantee

A credential declares an expiry, keeps its lifetime within a sane bound, and is refused once the expiry has passed.
The credential must be a JSON Web Token; an opaque token (Forgejo's) carries no claims to read and the test is
`NOT_APPLICABLE` there.

A PASS of the claim checks promises that the token declares an expiry and that its lifetime is not excessive. It
does not promise that an expired token is actually refused: minting one needs the signing key, which the target
does not give us, so that case is reported `NEEDS_KEY_MATERIAL`.

## 2. Test

### 2.1 Sub-tests and coverage of the methodology

| Sub-test | Methodology (guarantee 1.3) |
|---|---|
| `expiry_declared` | the token carries an `exp` claim (RFC 7519); without one it never expires |
| `lifetime_bounded` | the span `exp - iat` is not excessive (the "5-15 minutes" concern; reported as a measured value, not a fixed line) |
| `expired_rejected` | "expired token → 401": needs a token with a past `exp`, hence the signing key |
| left out | clock-skew leeway, future `exp`, negative `exp`: each needs a re-signed token (the key) |

### 2.2 Preconditions and reference responses

None: the evidence is the claims of a token already obtained.

### 2.3 Probes

None. The token's `exp` and `iat` are read. An expired token is not minted (it needs the key); the reference time
for any later such check is logged in a note.

## 3. Oracle

<!-- [[[cog import generate_docs as g; cog.out(g.oracle_table("1.3")) ]]] -->

**`expiry_declared`**

| Case | Outcome / detail | Confidence |
|---|---|---|
| the token carries a numeric `exp` | `ENFORCED/EXP_DECLARED` | - |
| the token carries no `exp` (only server-side state, unseen, could end it) | `VIOLATION/NO_EXP_CLAIM` | TENTATIVE |
| `exp` is not a NumericDate | `NOT_VERIFIABLE/EXP_NOT_NUMERIC` | - |
| user_a's credential is not a JWT | `NOT_APPLICABLE/NOT_A_JWT` | - |

**`lifetime_bounded`**

| Case | Outcome / detail | Confidence |
|---|---|---|
| `exp` minus `iat`, or minus the login's time without `iat`, is at most 24 hours | `ENFORCED/LIFETIME_BOUNDED` | - |
| the same span is over 24 hours | `VIOLATION/LIFETIME_EXCESSIVE` | TENTATIVE |
| no `iat`, and a configured token (no login to date it) | `NOT_VERIFIABLE/NO_IAT_CLAIM` | - |
| `exp` is not after the start | `NOT_VERIFIABLE/EXP_NOT_AFTER_IAT` | - |
| `exp` is not a NumericDate | `NOT_VERIFIABLE/EXP_NOT_NUMERIC` | - |
| no `exp`: nothing to bound (the declared sub-test reports it) | `NOT_APPLICABLE/NO_EXPIRY_TO_BOUND` | - |
| user_a's credential is not a JWT | `NOT_APPLICABLE/NOT_A_JWT` | - |

**`expired_rejected`**

| Case | Outcome / detail | Confidence |
|---|---|---|
| a JWT: an expired one cannot be minted without the signing key | `NOT_VERIFIABLE/NEEDS_KEY_MATERIAL` | - |
| user_a's credential is not a JWT | `NOT_APPLICABLE/NOT_A_JWT` | - |

<!-- [[[end]]] -->

## 4. Validation

### 4.1 Oracle cases

<!-- [[[cog import generate_docs as g; cog.out(g.oracle_validation("1.3", page=cog.inFile)) ]]] -->

Every case of the oracle, produced on a lab and judged by the code: E1, [oracle validation](../../../experiments/README.md), campaign at commit `fc60b6f`. 13 of 13 produced cases gave the declared outcome; 0 no lab can produce.

| Case | Lab, how it is produced | Result |
|---|---|---|
| `expiry_declared/ENFORCED/EXP_DECLARED` | crapi-kong: the lab as built: crAPI's login returns a JWT with a numeric exp | OK |
| `expiry_declared/VIOLATION/NO_EXP_CLAIM/TENTATIVE` | crapi-kong: user_a's credential is a configured static token, a fictitious unsigned JWT with payload {sub: apiguard-lab, iat: 1700000000} and no exp (the test only reads it, it sends it nowhere) | OK |
| `expiry_declared/NOT_VERIFIABLE/EXP_NOT_NUMERIC` | crapi-kong: user_a's credential is a configured static token, a fictitious unsigned JWT with payload {sub: apiguard-lab, iat: 1700000000, exp: "tomorrow"} | OK |
| `expiry_declared/NOT_APPLICABLE/NOT_A_JWT` | forgejo-kong: the lab as built: Forgejo's API token is opaque (sha1), not a JWT | OK |
| `lifetime_bounded/ENFORCED/LIFETIME_BOUNDED` | crapi-kong: user_a's credential is a configured static token, a fictitious unsigned JWT with iat 1700000000 and exp one hour later | OK |
| `lifetime_bounded/VIOLATION/LIFETIME_EXCESSIVE/TENTATIVE` | crapi-kong: the lab as built: crAPI's JWT lives 7 days (exp - iat) | OK |
| `lifetime_bounded/NOT_VERIFIABLE/NO_IAT_CLAIM` | crapi-kong: user_a's credential is a configured static token (no login to date it), a fictitious unsigned JWT with exp 1700003600 and no iat | OK |
| `lifetime_bounded/NOT_VERIFIABLE/EXP_NOT_AFTER_IAT` | crapi-kong: user_a's credential is a configured static token, a fictitious unsigned JWT with iat 1700003600 and exp 1700000000 (before iat) | OK |
| `lifetime_bounded/NOT_VERIFIABLE/EXP_NOT_NUMERIC` | crapi-kong: the same static token as expiry_declared/EXP_NOT_NUMERIC (exp "tomorrow"): one run records both sub-tests | OK |
| `lifetime_bounded/NOT_APPLICABLE/NO_EXPIRY_TO_BOUND` | crapi-kong: the same static token as expiry_declared/NO_EXP_CLAIM (no exp): one run records both sub-tests | OK |
| `lifetime_bounded/NOT_APPLICABLE/NOT_A_JWT` | forgejo-kong: the lab as built: Forgejo's API token is opaque (sha1), not a JWT | OK |
| `expired_rejected/NOT_VERIFIABLE/NEEDS_KEY_MATERIAL` | crapi-kong: the lab as built: crAPI's token is a JWT and the tool has no signing key | OK |
| `expired_rejected/NOT_APPLICABLE/NOT_A_JWT` | forgejo-kong: the lab as built: Forgejo's API token is opaque (sha1), not a JWT | OK |

<!-- [[[end]]] -->

### 4.2 Results on the labs

<!-- [[[cog import generate_docs as g; cog.out(g.lab_results("1.3", page=cog.inFile)) ]]] -->

No E2 campaign yet ([experiments](../../../experiments/README.md)).

<!-- [[[end]]] -->

## 5. Limitations

- Whether an expired token is actually refused is not tried: it needs the signing key, reported
  `NEEDS_KEY_MATERIAL`.
- The lifetime bound is a heuristic reported at TENTATIVE confidence, because the token's purpose (access or
  refresh) cannot be read from it.
- An opaque token is not examined: its lifetime is managed at the server, out of view.
- An opaque token's `expires_in` (RFC 6749 section 5.1) is not read: an opaque token is `NOT_A_JWT`.
- A configured static token whose `exp` has passed is not sent to check that it is refused.

## 6. Sources

- OWASP API2:2023 Broken Authentication: https://owasp.org/API-Security/editions/2023/en/0xa2-broken-authentication/
- RFC 7519 section 4.1.4 (the `exp` claim): https://www.rfc-editor.org/rfc/rfc7519.html#section-4.1.4
- OWASP ASVS v5.0.0-9.2.1 (validity time span) and v5.0.0-7.3.2 (absolute maximum lifetime): https://github.com/OWASP/ASVS/blob/v5.0.0/5.0/en/0x18-V9-Self-contained-Tokens.md
- CWE-613 Insufficient Session Expiration: https://cwe.mitre.org/data/definitions/613.html

## 7. Inputs

The role's valid JWT (the `USER_ACCOUNT` need). The test reads its `exp` and `iat` claims; it sends no request of
its own. No configuration parameter.

## 8. Outcomes

SKIP when every sub-test is `NOT_APPLICABLE` (opaque token). Otherwise FAIL on a missing or excessive expiry, with
`expired_rejected` INCONCLUSIVE (`NEEDS_KEY_MATERIAL`) where no key is supplied.

## 9. Findings

<!-- [[[cog import generate_docs as g; cog.out(g.finding_titles("1.3")) ]]] -->

- "The credential declares no expiry"
- "The credential's lifetime is long"

<!-- [[[end]]] -->

`evidence_ref` the login response that returned the token (none for a configured token).

## 10. Effects on the target

`READ_ONLY`, and no request at all: the token was obtained by the login the engine already performed.

## 11. Per gateway

Independent of the gateway: the claims are the issuer's, read from the token.

## 12. Configuration

None.

## 13. Remediation

Issue short-lived access tokens with an `exp` claim and renew them with a refresh token; enforce the `exp` on every
request (ASVS v5.0.0-9.2.1) and set an absolute maximum lifetime (ASVS v5.0.0-7.3.2).

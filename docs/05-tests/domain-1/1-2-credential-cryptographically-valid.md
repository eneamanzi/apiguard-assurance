# 1.2 Credential Cryptographically Valid

> **Audience:** analysts, contributors · **Source of truth:**
> [`src/tests/domain_1/test_1_2_credential_cryptographically_valid.py`](../../../src/tests/domain_1/test_1_2_credential_cryptographically_valid.py), [`src/core/jwt_tokens.py`](../../../src/core/jwt_tokens.py)

<!-- [[[cog import generate_docs as g; cog.out(g.test_header("1.2", page=cog.inFile)) ]]] -->

|  |  |
|---|---|
| Test ID | `1.2` |
| Name | Credential Cryptographically Valid |
| Domain | 1 - Identity and Authentication |
| Priority / strategy | P0 / GREY_BOX |
| Effect | READ_ONLY |
| CWE | CWE-347 |
| Standards | `OWASP API2:2023`, `OWASP ASVS v5.0.0-9.1.1`, `OWASP ASVS v5.0.0-9.1.2`, `RFC 8725, Section 2.1` |
| Tags | `authentication`, `jwt` |
| Prerequisites | none |
| Needs | `USER_ACCOUNT` |
| Parameters | none |

<!-- [[[end]]] -->

**Same group:** tests `1.3` and `1.4`.

## 1. Guarantee

A credential whose signature does not hold is refused. The credential must be a JSON Web Token (JWT); a target that
issues an opaque token (Forgejo's sha1 API token) has no signature to attack, and the test is `NOT_APPLICABLE`
there.

A PASS promises that the key-free forgeries tried were refused. It promises nothing about whether the token has
expired (`1.3`) or been revoked (`1.4`), and it cannot speak to the attacks that need key material the target does
not give us (below).

## 2. Test

### 2.1 Sub-tests and coverage of the methodology

| Sub-test | Methodology (guarantee 1.2) |
|---|---|
| `unsigned_rejected` | "unsigned tokens accepted (`alg: none`)", with `none` written as `none`, `None`, `NONE` and `nOnE` in turn until one is accepted (a check that compares the exact string `none` lets the others through to a library that ignores case) |
| `tampered_rejected` | "payload not verified": a claim added (`apiguard_tampered`), the original signature kept; the identity is left as it is, so a refusal can only be the signature check |
| `stripped_rejected` | "signature stripping" |
| `algorithm_confusion` | "algorithm confusion (RS256 to HS256)": needs the public key, and this test neither fetches one nor implements the attack, so the case is always reported `NEEDS_KEY_MATERIAL` |
| left out | key rotation, `kid` mismatch: need a JWKS with the signing key, which no target gives us |

### 2.2 Preconditions and reference responses

The anchor is the precondition: without a documented read that genuinely requires the credential, the test is
`NOT_VERIFIABLE/NO_WORKING_ANCHOR`. The genuine token is sent to the anchor first (logged as the positive step), so
that "the degraded token was refused" is read against "the genuine one is accepted here".

### 2.3 Probes

Three variants of the genuine token, each built with no key (`src/core/jwt_tokens.py`): the algorithm set to
`none` with an empty signature; a claim changed with the original signature kept; the signature segment emptied.
Each is sent to the anchor, in the same place and with the same scheme as the genuine credential. The
algorithm-confusion and re-signing cases are not sent: they need the public or the signing key.

## 3. Oracle

<!-- [[[cog import generate_docs as g; cog.out(g.oracle_table("1.2")) ]]] -->

**`unsigned_rejected`**

| Case | Outcome / detail | Confidence |
|---|---|---|
| the token with `alg` set to `none` (any spelling) and no signature is served (`2xx`) at the anchor with the genuine token's answer | `VIOLATION/ACCEPTED_ALG_NONE` | CERTAIN |
| the token with `alg` set to `none` (any spelling) and no signature is served (`2xx`) with another answer (an error envelope may be a 200) | `VIOLATION/ACCEPTED_ALG_NONE` | FIRM |
| the token with `alg` set to `none` (any spelling) and no signature is refused (`400`, `401`, `403`) | `ENFORCED/REFUSED` | - |
| the token with `alg` set to `none` (any spelling) and no signature gets another answer (a redirect, `404`, ...) | `NOT_VERIFIABLE/NOT_A_REFUSAL` | - |
| no documented read accepts the genuine token and refuses no credential | `NOT_VERIFIABLE/NO_WORKING_ANCHOR` | - |
| user_a's credential is not a JWT | `NOT_APPLICABLE/NOT_A_JWT` | - |
| no token value was stored for user_a (not reached: the engine provides it) | `NOT_VERIFIABLE/NO_TOKEN_VALUE` | - |

**`tampered_rejected`**

| Case | Outcome / detail | Confidence |
|---|---|---|
| the token with a claim added and the original signature is served (`2xx`) at the anchor with the genuine token's answer | `VIOLATION/ACCEPTED_TAMPERED_PAYLOAD` | CERTAIN |
| the token with a claim added and the original signature is served (`2xx`) with another answer (an error envelope may be a 200) | `VIOLATION/ACCEPTED_TAMPERED_PAYLOAD` | FIRM |
| the token with a claim added and the original signature is refused (`400`, `401`, `403`) | `ENFORCED/REFUSED` | - |
| the token with a claim added and the original signature gets another answer (a redirect, `404`, ...) | `NOT_VERIFIABLE/NOT_A_REFUSAL` | - |
| no documented read accepts the genuine token and refuses no credential | `NOT_VERIFIABLE/NO_WORKING_ANCHOR` | - |
| user_a's credential is not a JWT | `NOT_APPLICABLE/NOT_A_JWT` | - |
| no token value was stored for user_a (not reached: the engine provides it) | `NOT_VERIFIABLE/NO_TOKEN_VALUE` | - |

**`stripped_rejected`**

| Case | Outcome / detail | Confidence |
|---|---|---|
| the token with its signature emptied is served (`2xx`) at the anchor with the genuine token's answer | `VIOLATION/ACCEPTED_STRIPPED_SIGNATURE` | CERTAIN |
| the token with its signature emptied is served (`2xx`) with another answer (an error envelope may be a 200) | `VIOLATION/ACCEPTED_STRIPPED_SIGNATURE` | FIRM |
| the token with its signature emptied is refused (`400`, `401`, `403`) | `ENFORCED/REFUSED` | - |
| the token with its signature emptied gets another answer (a redirect, `404`, ...) | `NOT_VERIFIABLE/NOT_A_REFUSAL` | - |
| no documented read accepts the genuine token and refuses no credential | `NOT_VERIFIABLE/NO_WORKING_ANCHOR` | - |
| user_a's credential is not a JWT | `NOT_APPLICABLE/NOT_A_JWT` | - |
| no token value was stored for user_a (not reached: the engine provides it) | `NOT_VERIFIABLE/NO_TOKEN_VALUE` | - |

**`algorithm_confusion`**

| Case | Outcome / detail | Confidence |
|---|---|---|
| a JWT and a working anchor: the attack needs the public key, not fetched | `NOT_VERIFIABLE/NEEDS_KEY_MATERIAL` | - |
| no working anchor | `NOT_VERIFIABLE/NO_WORKING_ANCHOR` | - |
| user_a's credential is not a JWT | `NOT_APPLICABLE/NOT_A_JWT` | - |
| no token value was stored for user_a (not reached) | `NOT_VERIFIABLE/NO_TOKEN_VALUE` | - |

<!-- [[[end]]] -->

<!-- [[[cog import generate_docs as g; cog.out(g.uninformative_answers("1.2", page=cog.inFile)) ]]] -->

The answers that say nothing about the guarantee by themselves, one rule for every test ([assessment model](../../04-architecture/03-assessment-model.md#answers-that-say-nothing-about-the-guarantee)), generated from the code:

| Answer | Sub-tests | Outcome / detail |
|---|---|---|
| `UPSTREAM_UNAVAILABLE` | every sub-test | `NOT_VERIFIABLE/UPSTREAM_UNAVAILABLE` |
| `RATE_LIMITED` | every sub-test | `NOT_VERIFIABLE/RATE_LIMITED` |
| `SERVER_ERROR` | every sub-test | `NOT_VERIFIABLE/SERVER_ERROR` |
| `NO_RESPONSE` | every sub-test | `NOT_VERIFIABLE/NO_RESPONSE` |

<!-- [[[end]]] -->

## 4. Validation

### 4.1 Oracle cases

<!-- [[[cog import generate_docs as g; cog.out(g.oracle_validation("1.2", page=cog.inFile)) ]]] -->

Every case of the oracle, produced on a lab and judged by the code: E1, [oracle validation](../../../experiments/README.md), campaign at commit `fc60b6f`. 25 of 25 produced cases gave the declared outcome; 4 no lab can produce.

| Case | Lab, how it is produced | Result |
|---|---|---|
| `unsigned_rejected/VIOLATION/ACCEPTED_ALG_NONE/CERTAIN` | crapi-kong: the lab as built: crAPI's workshop answers GET /workshop/api/mechanic/ (the anchor) 200 to the token with alg 'none' (first spelling) and an empty signature, with the genuine token's answer | OK |
| `unsigned_rejected/VIOLATION/ACCEPTED_ALG_NONE/FIRM` | crapi-kong: a temporary route GET ~/workshop/api/mechanic/$ whose counter passes the first two requests (the genuine token, the request without a credential) to crAPI and answers every later one (the degraded tokens) 200 with a JSON body of another shape | OK |
| `unsigned_rejected/ENFORCED/REFUSED` | crapi-kong: a temporary route GET ~/workshop/api/mechanic/$ whose counter passes the first two requests to crAPI and answers every later one (all four spellings of alg none) 401 | OK |
| `unsigned_rejected/NOT_VERIFIABLE/NOT_A_REFUSAL` | crapi-kong: a temporary route GET ~/workshop/api/mechanic/$ whose counter passes the first two requests to crAPI and answers every later one 404 | OK |
| `unsigned_rejected/NOT_VERIFIABLE/NO_WORKING_ANCHOR` | crapi-kong: the run reads a local copy of crAPI's specification with every operation marked security: [], so no documented read is a candidate anchor | OK |
| `unsigned_rejected/NOT_APPLICABLE/NOT_A_JWT` | forgejo-kong: the lab as built: Forgejo's API token is opaque (sha1), not three base64url segments | OK |
| `unsigned_rejected/NOT_VERIFIABLE/NO_TOKEN_VALUE` | not producible (code): every auth method stores a value for a configured role, `basic` included (`base64(username:password)` in src/tests/helpers/auth_static.py), and without the role the engine skips the test for its need; measured 2026-11-15 with `auth_type: basic`: `NOT_A_JWT`, SKIP | - |
| `tampered_rejected/VIOLATION/ACCEPTED_TAMPERED_PAYLOAD/CERTAIN` | crapi-kong: a temporary route GET ~/workshop/api/mechanic/$ answering 200 (same body) to any request with an Authorization header and 401 to one without: the tampered token gets the genuine token's answer | OK |
| `tampered_rejected/VIOLATION/ACCEPTED_TAMPERED_PAYLOAD/FIRM` | crapi-kong: a temporary route GET ~/workshop/api/mechanic/$ whose counter passes the first two requests to crAPI and answers every later one 200 with a JSON body of another shape | OK |
| `tampered_rejected/ENFORCED/REFUSED` | crapi-kong: the lab as built: crAPI refuses the token with a claim added and the original signature (401) | OK |
| `tampered_rejected/NOT_VERIFIABLE/NOT_A_REFUSAL` | crapi-kong: a temporary route GET ~/workshop/api/mechanic/$ whose counter passes the first two requests to crAPI and answers every later one 404 | OK |
| `tampered_rejected/NOT_VERIFIABLE/NO_WORKING_ANCHOR` | crapi-kong: the run reads a local copy of crAPI's specification with every operation marked security: [] | OK |
| `tampered_rejected/NOT_APPLICABLE/NOT_A_JWT` | forgejo-kong: the lab as built: Forgejo's API token is opaque | OK |
| `tampered_rejected/NOT_VERIFIABLE/NO_TOKEN_VALUE` | not producible (code): every auth method stores a value for a configured role, `basic` included (`base64(username:password)` in src/tests/helpers/auth_static.py), and without the role the engine skips the test for its need; measured 2026-11-15 with `auth_type: basic`: `NOT_A_JWT`, SKIP | - |
| `stripped_rejected/VIOLATION/ACCEPTED_STRIPPED_SIGNATURE/CERTAIN` | crapi-kong: a temporary route GET ~/workshop/api/mechanic/$ answering 200 (same body) to any request with an Authorization header and 401 to one without: the token with its signature emptied gets the genuine token's answer | OK |
| `stripped_rejected/VIOLATION/ACCEPTED_STRIPPED_SIGNATURE/FIRM` | crapi-kong: a temporary route GET ~/workshop/api/mechanic/$ whose counter passes the first two requests to crAPI and answers every later one 200 with a JSON body of another shape | OK |
| `stripped_rejected/ENFORCED/REFUSED` | crapi-kong: the lab as built: crAPI refuses the token with its signature emptied (401) | OK |
| `stripped_rejected/NOT_VERIFIABLE/NOT_A_REFUSAL` | crapi-kong: a temporary route GET ~/workshop/api/mechanic/$ whose counter passes the first two requests to crAPI and answers every later one 404 | OK |
| `stripped_rejected/NOT_VERIFIABLE/NO_WORKING_ANCHOR` | crapi-kong: the run reads a local copy of crAPI's specification with every operation marked security: [] | OK |
| `stripped_rejected/NOT_APPLICABLE/NOT_A_JWT` | forgejo-kong: the lab as built: Forgejo's API token is opaque | OK |
| `stripped_rejected/NOT_VERIFIABLE/NO_TOKEN_VALUE` | not producible (code): every auth method stores a value for a configured role, `basic` included (`base64(username:password)` in src/tests/helpers/auth_static.py), and without the role the engine skips the test for its need; measured 2026-11-15 with `auth_type: basic`: `NOT_A_JWT`, SKIP | - |
| `algorithm_confusion/NOT_VERIFIABLE/NEEDS_KEY_MATERIAL` | crapi-kong: the lab as built: crAPI issues a JWT and the anchor GET /workshop/api/mechanic/ works; the attack is not tried | OK |
| `algorithm_confusion/NOT_VERIFIABLE/NO_WORKING_ANCHOR` | crapi-kong: the run reads a local copy of crAPI's specification with every operation marked security: [] | OK |
| `algorithm_confusion/NOT_APPLICABLE/NOT_A_JWT` | forgejo-kong: the lab as built: Forgejo's API token is opaque | OK |
| `algorithm_confusion/NOT_VERIFIABLE/NO_TOKEN_VALUE` | not producible (code): every auth method stores a value for a configured role, `basic` included (`base64(username:password)` in src/tests/helpers/auth_static.py), and without the role the engine skips the test for its need; measured 2026-11-15 with `auth_type: basic`: `NOT_A_JWT`, SKIP | - |
| `*/NOT_VERIFIABLE/UPSTREAM_UNAVAILABLE` | crapi-kong: a temporary route GET ~/workshop/api/mechanic/$ whose counter passes the genuine token and the request without a credential to crAPI and answers the degraded tokens 503 | OK |
| `*/NOT_VERIFIABLE/RATE_LIMITED` | crapi-kong: the same counter route answering the degraded tokens 429 | OK |
| `*/NOT_VERIFIABLE/SERVER_ERROR` | crapi-kong: the same counter route answering the degraded tokens 500 | OK |
| `*/NOT_VERIFIABLE/NO_RESPONSE` | crapi-kong: the same counter route sleeping 7 s on the degraded tokens before proxying, with the run's read timeout at 5 s | OK |

<!-- [[[end]]] -->

### 4.2 Results on the labs

<!-- [[[cog import generate_docs as g; cog.out(g.lab_results("1.2", page=cog.inFile)) ]]] -->

No E2 campaign yet ([experiments](../../../experiments/README.md)).

<!-- [[[end]]] -->

## 5. Limitations

- Only the key-free forgeries are tried. Algorithm confusion, a token re-signed with a chosen claim, `kid` and key
  rotation need key material, and are reported `NEEDS_KEY_MATERIAL` rather than passed. **This is a limit of the
  test, not always of the target**: a signing key is never exposed, but a public key often is, and crAPI publishes
  one (section 4). The test does not fetch a JWKS and does not implement those attacks, by the decision in
  section 12.
- A target that issues an opaque token is not examined here (its validation is the server's business).
- The anchor is a documented read; an API with no protected documented read cannot be tested this way.
- One anchor is used, the first documented read the genuine token is accepted on: behind one gateway each service may verify tokens itself (crAPI has three), and the others are not tried.

## 6. Sources

- OWASP API2:2023 Broken Authentication: https://owasp.org/API-Security/editions/2023/en/0xa2-broken-authentication/
- OWASP ASVS v5.0.0-9.1.1 and v5.0.0-9.1.2 (Self-contained Tokens): https://github.com/OWASP/ASVS/blob/v5.0.0/5.0/en/0x18-V9-Self-contained-Tokens.md
- RFC 8725 section 2.1 (JSON Web Token Best Current Practices): https://www.rfc-editor.org/rfc/rfc8725.html#section-2.1
- CWE-347 Improper Verification of Cryptographic Signature: https://cwe.mitre.org/data/definitions/347.html
- OWASP crAPI challenge 15 (forge a JWT): https://github.com/OWASP/crAPI/blob/main/docs/challenges.md

## 7. Inputs

The role's valid JWT (the engine obtains it from the `USER_ACCOUNT` need). An **anchor**: a documented read that
answers 2xx with the genuine token and is refused (401 or 403) without it, so that a refusal of a
degraded token is about the degradation and not about a public endpoint. No configuration parameter.

## 8. Outcomes

SKIP when every sub-test is `NOT_APPLICABLE` (the credential is opaque: Forgejo). Otherwise FAIL on any accepted
forgery, PASS when all were refused, with `algorithm_confusion` INCONCLUSIVE where no key is exposed.

## 9. Findings

<!-- [[[cog import generate_docs as g; cog.out(g.finding_titles("1.2")) ]]] -->

- "Invalid token accepted: <label>"

<!-- [[[end]]] -->

`evidence_ref` the answer to the forged token; `supporting_refs` the anchor accepted with the genuine token and refused without one.

## 10. Effects on the target

`READ_ONLY`: the anchor is a read, and each forged token is sent to it once. Nothing is created or changed.

## 11. Per gateway

Independent of the gateway: the JWT is validated by the gateway or by the application, and the test judges the
answer. crAPI's identity service validates the JWT itself.

## 12. Configuration

None. Covering the key-based attacks would need the operator to supply a signing key or a JWKS (a new input);
that input is not planned, so those cases stay `NEEDS_KEY_MATERIAL`.

## 13. Remediation

Verify every token's signature against the issuer's key before trusting its claims, and accept only the algorithms
on an allowlist (never `none`): ASVS v5.0.0-9.1.1 and 9.1.2.

# 1.2 Credential Cryptographically Valid

> **Audience:** analysts, contributors · **Status:** new in the test review (2026-10-22) ·
> **Source of truth:**
> [`src/tests/domain_1/test_1_2_credential_cryptographically_valid.py`](../../../src/tests/domain_1/test_1_2_credential_cryptographically_valid.py),
> [`src/core/jwt_tokens.py`](../../../src/core/jwt_tokens.py) · **Verified:** 2026-10-22

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

**Same group:** tests `1.3` and `1.4` (the review of guarantees 1.2, 1.3 and 1.4 together).

## 1. Guarantee

A credential whose signature does not hold is refused. The credential must be a JSON Web Token (JWT); a target that
issues an opaque token (Forgejo's sha1 API token) has no signature to attack, and the test is `NOT_APPLICABLE`
there.

A PASS promises that the key-free forgeries tried were refused. It promises nothing about whether the token has
expired (`1.3`) or been revoked (`1.4`), and it cannot speak to the attacks that need key material the target does
not give us (below).

## 2. Sub-tests and coverage of the methodology

| Sub-test | Methodology (guarantee 1.2) |
|---|---|
| `unsigned_rejected` | "unsigned tokens accepted (`alg: none`)", with `none` written as `none`, `None`, `NONE` and `nOnE` in turn until one is accepted (since 2026-11-05: a check that compares the exact string `none` lets the others through to a library that ignores case) |
| `tampered_rejected` | "payload not verified": a claim added (`apiguard_tampered`), the original signature kept; the identity is left as it is, so a refusal can only be the signature check (until 2026-11-04 the subject was changed, and a server that does not verify would refuse an unknown user anyway) |
| `stripped_rejected` | "signature stripping" |
| `algorithm_confusion` | "algorithm confusion (RS256 to HS256)": needs the public key, and this test neither fetches one nor implements the attack, so the case is always reported `NEEDS_KEY_MATERIAL` |
| left out | key rotation, `kid` mismatch: need a JWKS with the signing key, which no target gives us |

## 3. Inputs

The role's valid JWT (the engine obtains it from the `USER_ACCOUNT` need). An **anchor**: a documented read that
answers 2xx with the genuine token and is refused (401 or 403) without it (`src/tests/helpers/anchor.py`; until
2026-11-04 any non-2xx counted), so that a refusal of a
degraded token is about the degradation and not about a public endpoint. No configuration parameter.

## 4. Preconditions and reference responses

The anchor is the precondition: without a documented read that genuinely requires the credential, the test is
`NOT_VERIFIABLE/NO_WORKING_ANCHOR`. The genuine token is sent to the anchor first (logged as the positive step), so
that "the degraded token was refused" is read against "the genuine one is accepted here".

## 5. Probes

Three variants of the genuine token, each built with no key (`src/core/jwt_tokens.py`): the algorithm set to
`none` with an empty signature; a claim changed with the original signature kept; the signature segment emptied.
Each is sent to the anchor, in the same place and with the same scheme as the genuine credential. The
algorithm-confusion and re-signing cases are not sent: they need the public or the signing key.

## 6. Oracle

| Case | Outcome / detail | Confidence |
|---|---|---|
| the variant is refused (non-2xx) | `ENFORCED/REFUSED` | - |
| the variant answers 2xx where the genuine token does | `VIOLATION/ACCEPTED_<variant>` | CERTAIN: the server did not verify the signature |
| the credential is not a JWT | `NOT_APPLICABLE/NOT_A_JWT` | - |
| no anchor requires the credential | `NOT_VERIFIABLE/NO_WORKING_ANCHOR` | - |
| the placement carries no single token value | `NOT_VERIFIABLE/NO_TOKEN_VALUE` | - |
| algorithm confusion, no public key | `NOT_VERIFIABLE/NEEDS_KEY_MATERIAL` | - |

<!-- [[[cog import generate_docs as g; cog.out(g.uninformative_answers("1.2", page=cog.inFile)) ]]] -->

The answers that say nothing about the guarantee by themselves, one rule for every test ([assessment model](../../04-architecture/03-assessment-model.md#answers-that-say-nothing-about-the-guarantee)), generated from the code:

| Answer | Sub-tests | Outcome / detail |
|---|---|---|
| `UPSTREAM_UNAVAILABLE` | every sub-test | `NOT_VERIFIABLE/UPSTREAM_UNAVAILABLE` |
| `RATE_LIMITED` | every sub-test | `NOT_VERIFIABLE/RATE_LIMITED` |
| `SERVER_ERROR` | every sub-test | `NOT_VERIFIABLE/SERVER_ERROR` |
| `NO_RESPONSE` | every sub-test | `NOT_VERIFIABLE/NO_RESPONSE` |

<!-- [[[end]]] -->

## 7. Outcomes

SKIP when every sub-test is `NOT_APPLICABLE` (the credential is opaque: Forgejo). Otherwise FAIL on any accepted
forgery, PASS when all were refused, with `algorithm_confusion` INCONCLUSIVE where no key is exposed.

## 8. Findings

One per accepted forgery: "Invalid token accepted: `<variant>`", with the anchor and the status; `evidence_ref` the
request carrying the forged token, which is pinned.

## 9. Effects on the target

`READ_ONLY`: the anchor is a read, and each forged token is sent to it once. Nothing is created or changed.

## 10. Per gateway

Independent of the gateway: the JWT is validated by the gateway or by the application, and the test judges the
answer. crAPI's identity service validates the JWT itself.

## 11. Configuration

None. Covering the key-based attacks would need the operator to supply a signing key or a JWKS (a new input);
that input is not planned (owner, 2026-10-22: native, no speculative jwt_tool and no key parameter; confirmed
2026-10-27), so those cases stay `NEEDS_KEY_MATERIAL`.

## 12. Validation

Runs of 2026-10-22, the three tests of the group together:

| Lab | Status | Basis |
|---|---|---|
| crAPI + Kong | **FAIL, 1 finding** | `alg: none` accepted at the anchor `GET /workshop/api/mechanic/` (HTTP 200): crAPI's identity service honours an unsigned token (OWASP crAPI challenge 15, "forge a JWT"). The tampered and stripped variants are correctly refused (401), so the server does verify the signature for those but trusts `alg: none`. `algorithm_confusion` is `NEEDS_KEY_MATERIAL`, and not because the key is unavailable: crAPI publishes an RSA public key at `GET /identity/api/auth/jwks.json` (checked 2026-10-29), so the attack is testable in principle and this test does not try it, by the decision in section 11 |
| Forgejo + Kong, Forgejo + APISIX | SKIP | the API token is opaque: `NOT_APPLICABLE/NOT_A_JWT` on every sub-test |
| any | ENFORCED | a target that refuses all three: not on the labs (crAPI accepts `alg: none`) |

**The tampered and stripped tokens accepted, produced on 2026-11-14** (crAPI + Kong after a reset, a temporary
route in its `kong.yml`, undone with `git checkout` and the lab checked back to 1 finding). A route
`~/workshop/api/mechanic/$` with a `pre-function` answering `200` to any request carrying an `Authorization`
header and `401` to one without it. The anchor rule accepts that endpoint (it answers 2xx to the genuine token and
refuses no credential), and the test reports **FAIL**, 3 findings: `ACCEPTED_ALG_NONE`,
`ACCEPTED_TAMPERED_PAYLOAD`, `ACCEPTED_STRIPPED_SIGNATURE`. Before that run this section said such an endpoint would
be rejected by the anchor rule; it is not, because the rule asks for a refusal without a credential, not for a
check of the credential's value.

**What each branch has been seen doing** (rule 9). Proven on a lab: `ACCEPTED_ALG_NONE` (crAPI, with the first
spelling, `none`, so the other three are not sent: 2026-11-05), `REFUSED` (crAPI's tampered and stripped),
`NEEDS_KEY_MATERIAL` (crAPI), `NOT_A_JWT` (Forgejo), and `ACCEPTED_TAMPERED_PAYLOAD` and
`ACCEPTED_STRIPPED_SIGNATURE` (the case above), and `NO_WORKING_ANCHOR` (2026-11-15, crAPI + Kong, its
specification saved with every operation marked `security: []`, so no read genuinely requires the credential).
The transport reasons on 2026-11-15, crAPI + Kong, a temporary route on the anchor `GET ~/workshop/api/mechanic/$`
whose counter lets the genuine token and the request without a credential through and answers the degraded tokens
`503`, `429`, `500`, or sleeps 7 s (the run's `target.read_timeout: 5.0`): `UPSTREAM_UNAVAILABLE`, `RATE_LIMITED`,
`SERVER_ERROR`, `NO_RESPONSE`. Every branch of this test has been seen except `NO_TOKEN_VALUE`, which is not
reachable (every auth method stores a value for a
configured role, `basic` included, `base64(username:password)` in `src/tests/helpers/auth_static.py`, and without
the role the engine skips the test for its need; measured 2026-11-15 with `auth_type: basic`: `NOT_A_JWT`, SKIP).

## 13. Remediation

Verify every token's signature against the issuer's key before trusting its claims, and accept only the algorithms
on an allowlist (never `none`): ASVS v5.0.0-9.1.1 and 9.1.2.

## 14. Limitations

- Only the key-free forgeries are tried. Algorithm confusion, a token re-signed with a chosen claim, `kid` and key
  rotation need key material, and are reported `NEEDS_KEY_MATERIAL` rather than passed. **This is a limit of the
  test, not always of the target**: a signing key is never exposed, but a public key often is, and crAPI publishes
  one (section 12). The test does not fetch a JWKS and does not implement those attacks, by the decision in
  section 11.
- A target that issues an opaque token is not examined here (its validation is the server's business).
- The anchor is a documented read; an API with no protected documented read cannot be tested this way.

## 15. Sources

- OWASP API2:2023 Broken Authentication: https://owasp.org/API-Security/editions/2023/en/0xa2-broken-authentication/
- OWASP ASVS v5.0.0-9.1.1 and v5.0.0-9.1.2 (Self-contained Tokens): https://github.com/OWASP/ASVS/blob/v5.0.0/5.0/en/0x18-V9-Self-contained-Tokens.md
- RFC 8725 section 2.1 (JSON Web Token Best Current Practices): https://www.rfc-editor.org/rfc/rfc8725.html#section-2.1
- CWE-347 Improper Verification of Cryptographic Signature: https://cwe.mitre.org/data/definitions/347.html
- OWASP crAPI challenge 15 (forge a JWT): https://github.com/OWASP/crAPI/blob/main/docs/challenges.md

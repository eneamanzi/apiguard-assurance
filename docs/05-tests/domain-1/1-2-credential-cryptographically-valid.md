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
| `unsigned_rejected` | "unsigned tokens accepted (`alg: none`)" |
| `tampered_rejected` | "payload not verified": a claim changed, the original signature kept |
| `stripped_rejected` | "signature stripping" |
| `algorithm_confusion` | "algorithm confusion (RS256 to HS256)": needs the public key, reported `NEEDS_KEY_MATERIAL` where none is exposed |
| left out | key rotation, `kid` mismatch: need a JWKS with the signing key, which no target gives us |

## 3. Inputs

The role's valid JWT (the engine obtains it from the `USER_ACCOUNT` need). An **anchor**: a documented read that
answers 2xx with the genuine token and non-2xx without it (`src/tests/helpers/anchor.py`), so that a refusal of a
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
| unavailable, rate limited, no response, server error | `NOT_VERIFIABLE/` the reason | - |

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
that is deferred until it is needed, and those cases stay `NEEDS_KEY_MATERIAL` meanwhile (owner, 2026-10-22: native,
no speculative jwt_tool and no key parameter now).

## 12. Validation

Runs of 2026-10-22, the three tests of the group together:

| Lab | Status | Basis |
|---|---|---|
| crAPI + Kong | **FAIL, 1 finding** | `alg: none` accepted at the anchor `GET /workshop/api/mechanic/` (HTTP 200): crAPI's identity service honours an unsigned token (OWASP crAPI challenge 15, "forge a JWT"). The tampered and stripped variants are correctly refused (401), so the server does verify the signature for those but trusts `alg: none`. `algorithm_confusion` is `NEEDS_KEY_MATERIAL` (no JWKS) |
| Forgejo + Kong, Forgejo + APISIX | SKIP | the API token is opaque: `NOT_APPLICABLE/NOT_A_JWT` on every sub-test |
| any | ENFORCED | a target that refuses all three: not on the labs (crAPI accepts `alg: none`) |

**What each branch has been seen doing** (rule 9). Proven on a lab: `ACCEPTED_ALG_NONE` (crAPI), `REFUSED`
(crAPI's tampered and stripped), `NEEDS_KEY_MATERIAL` (crAPI), `NOT_A_JWT` (Forgejo). `ACCEPTED_TAMPERED` and
`ACCEPTED_STRIPPED` are the same code path as `ACCEPTED_ALG_NONE` (the anchor answers 2xx to the degraded token),
proven through it; producing them on the lab would need an endpoint that honours any token, which the test's own
anchor rule would then reject as not genuinely protected. Still unproven: `NO_WORKING_ANCHOR`, `NO_TOKEN_VALUE`,
the transport reasons.

## 13. Remediation

Verify every token's signature against the issuer's key before trusting its claims, and accept only the algorithms
on an allowlist (never `none`): ASVS v5.0.0-9.1.1 and 9.1.2.

## 14. Limitations

- Only the key-free forgeries are tried. Algorithm confusion, a token re-signed with a chosen claim, `kid` and key
  rotation need key material the target does not give us, and are reported `NEEDS_KEY_MATERIAL` rather than passed.
- A target that issues an opaque token is not examined here (its validation is the server's business).
- The anchor is a documented read; an API with no protected documented read cannot be tested this way.

## 15. Sources

- OWASP API2:2023 Broken Authentication: https://owasp.org/API-Security/editions/2023/en/0xa2-broken-authentication/
- OWASP ASVS v5.0.0-9.1.1 and v5.0.0-9.1.2 (Self-contained Tokens): https://github.com/OWASP/ASVS/blob/v5.0.0/5.0/en/0x18-V9-Self-contained-Tokens.md
- RFC 8725 section 2.1 (JSON Web Token Best Current Practices): https://www.rfc-editor.org/rfc/rfc8725.html#section-2.1
- CWE-347 Improper Verification of Cryptographic Signature: https://cwe.mitre.org/data/definitions/347.html
- OWASP crAPI challenge 15 (forge a JWT): https://github.com/OWASP/crAPI/blob/main/docs/challenges.md

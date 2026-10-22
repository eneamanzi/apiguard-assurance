# 1.3 Credential Expiry

> **Audience:** analysts, contributors · **Status:** new in the test review (branch `test-review`, 2026-10-22) ·
> **Source of truth:**
> [`src/tests/domain_1/test_1_3_credential_expiry.py`](../../../src/tests/domain_1/test_1_3_credential_expiry.py),
> [`src/core/jwt_tokens.py`](../../../src/core/jwt_tokens.py) · **Verified:** 2026-10-22

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

## 2. Sub-tests and coverage of the methodology

| Sub-test | Methodology (guarantee 1.3) |
|---|---|
| `expiry_declared` | the token carries an `exp` claim (RFC 7519); without one it never expires |
| `lifetime_bounded` | the span `exp - iat` is not excessive (the "5-15 minutes" concern; reported as a measured value, not a fixed line) |
| `expired_rejected` | "expired token → 401": needs a token with a past `exp`, hence the signing key |
| left out | clock-skew leeway, future `exp`, negative `exp`: each needs a re-signed token (the key) |

## 3. Inputs

The role's valid JWT (the `USER_ACCOUNT` need). The test reads its `exp` and `iat` claims; it sends no request of
its own. No configuration parameter.

## 4. Preconditions and reference responses

None: the evidence is the claims of a token already obtained.

## 5. Probes

None. The token's `exp` and `iat` are read. An expired token is not minted (it needs the key); the reference time
for any later such check is logged in a note.

## 6. Oracle

| Case | Outcome / detail | Confidence |
|---|---|---|
| no `exp` claim | `VIOLATION/NO_EXP_CLAIM` | FIRM: the token never expires on its own |
| `exp` present | `ENFORCED/EXP_DECLARED` | - |
| `exp - iat` over the bound (24 hours) | `VIOLATION/LIFETIME_EXCESSIVE`, the finding carrying the measured span | TENTATIVE: the token's purpose cannot be read from it |
| `exp - iat` within the bound | `ENFORCED/LIFETIME_BOUNDED` | - |
| no usable `iat` | `NOT_VERIFIABLE/NO_IAT_CLAIM` | - |
| the past-expiry case | `NOT_VERIFIABLE/NEEDS_KEY_MATERIAL` | - |
| the credential is not a JWT | `NOT_APPLICABLE/NOT_A_JWT` | - |

The 24-hour bound is a heuristic, not a line ASVS draws (ASVS v5.0.0-7.3.2 asks for an absolute maximum "according
to risk analysis"), so its finding is TENTATIVE and carries the measured lifetime for the reader to judge. It is a
constant of the module, not a parameter (owner, 2026-10-22).

## 7. Outcomes

SKIP when every sub-test is `NOT_APPLICABLE` (opaque token). Otherwise FAIL on a missing or excessive expiry, with
`expired_rejected` INCONCLUSIVE (`NEEDS_KEY_MATERIAL`) where no key is supplied.

## 8. Findings

"The credential declares no expiry" (FIRM), or "The credential's lifetime is long" (TENTATIVE, with the span);
`evidence_ref` the login record that carries the token.

## 9. Effects on the target

`READ_ONLY`, and no request at all: the token was obtained by the login the engine already performed.

## 10. Per gateway

Independent of the gateway: the claims are the issuer's, read from the token.

## 11. Configuration

None.

## 12. Validation

Runs of 2026-10-22, the three tests of the group together:

| Lab | Status | Basis |
|---|---|---|
| crAPI + Kong | **FAIL, 1 finding (TENTATIVE)** | the JWT declares `exp` (PASS on `expiry_declared`), but its lifetime `exp - iat` is **7 days**, far past any access-token guidance (`LIFETIME_EXCESSIVE`). `expired_rejected` is `NEEDS_KEY_MATERIAL` |
| Forgejo + Kong, Forgejo + APISIX | SKIP | the API token is opaque: `NOT_APPLICABLE/NOT_A_JWT` |
| any | ENFORCED | a JWT declaring `exp` with a short lifetime: not on the labs (crAPI's is 7 days) |

**What each branch has been seen doing** (rule 9). Proven on a lab: `EXP_DECLARED`, `LIFETIME_EXCESSIVE`,
`NEEDS_KEY_MATERIAL`, `NOT_A_JWT`. Unproven, because they need a JWT issuer we control (the labs issue only crAPI's
fixed 7-day token or an opaque one): `NO_EXP_CLAIM`, `LIFETIME_BOUNDED`, `NO_IAT_CLAIM`. They are the same
read-a-claim code path; a scratch target issuing such a token would exercise them.

## 13. Remediation

Issue short-lived access tokens with an `exp` claim and renew them with a refresh token; enforce the `exp` on every
request (ASVS v5.0.0-9.2.1) and set an absolute maximum lifetime (ASVS v5.0.0-7.3.2).

## 14. Limitations

- Whether an expired token is actually refused is not tried: it needs the signing key, reported
  `NEEDS_KEY_MATERIAL`.
- The lifetime bound is a heuristic reported at TENTATIVE confidence, because the token's purpose (access or
  refresh) cannot be read from it.
- An opaque token is not examined: its lifetime is managed at the server, out of view.

## 15. Sources

- OWASP API2:2023 Broken Authentication: https://owasp.org/API-Security/editions/2023/en/0xa2-broken-authentication/
- RFC 7519 section 4.1.4 (the `exp` claim): https://www.rfc-editor.org/rfc/rfc7519.html#section-4.1.4
- OWASP ASVS v5.0.0-9.2.1 (validity time span) and v5.0.0-7.3.2 (absolute maximum lifetime): https://github.com/OWASP/ASVS/blob/v5.0.0/5.0/en/0x18-V9-Self-contained-Tokens.md
- CWE-613 Insufficient Session Expiration: https://cwe.mitre.org/data/definitions/613.html

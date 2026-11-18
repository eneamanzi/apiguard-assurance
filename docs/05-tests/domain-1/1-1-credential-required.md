# 1.1 Credential Required on Documented Operations

> **Audience:** analysts, contributors · **Source of truth:**
> [`src/tests/domain_1/test_1_1_credential_required.py`](../../../src/tests/domain_1/test_1_1_credential_required.py)

<!-- [[[cog import generate_docs as g; cog.out(g.test_header("1.1", page=cog.inFile)) ]]] -->

|  |  |
|---|---|
| Test ID | `1.1` |
| Name | Credential Required on Documented Operations |
| Domain | 1 - Identity and Authentication |
| Priority / strategy | P0 / BLACK_BOX |
| Effect | CHANGES_DATA |
| CWE | CWE-306 |
| Standards | `OWASP API2:2023`, `OWASP ASVS v5.0.0-8.2.1`, `CWE-288`, `NIST SP 800-228, Section 3.2.1`, `RFC 9110, Section 5.1` |
| Tags | `authentication`, `access-control` |
| Prerequisites | none |
| Needs | - |
| Parameters | none |

<!-- [[[end]]] -->

**Same group:** tests `1.6` and `1.7`.

## 1. Guarantee

An operation the specification declares as needing a credential refuses a request that carries none, one that
carries a credential which cannot be valid, and the same under another spelling of its own path.

A PASS promises that every operation the test could judge refused such a request. It promises nothing about whether
the credential is genuine beyond being present and well formed (a forged credential is test `1.2`, an expired one
`1.3`, a revoked one `1.4`), nothing about **which** credential should be accepted (test `2.1`), and nothing about
a path the gateway has no route for (test `0.2`).

## 2. Test

### 2.1 Sub-tests and coverage of the methodology

| Sub-test | Methodology (guarantee 1.1) |
|---|---|
| `no_credential` | "no token": every documented protected operation, not a sample |
| `malformed_credential` | "empty and malformed token" and "header case variations" |
| `path_variants` | "path normalisation", from the shared list (`src/core/path_variants.py`) |

### 2.2 Preconditions and reference responses

The calibration of each operation's own siblings, so that a `404` meaning "no such object" is not read as "the
operation is not there".

**No positive control.** The question is what the target does when a request carries no credential, which is
observed directly. A positive control per violation, to rule out "this operation refuses everyone", would hide true
cases: a token issued with narrower scopes than anonymous access is refused by an operation that serves an
anonymous request (24 such operations on Forgejo + Kong).

### 2.3 Probes

1. every documented operation to which a security requirement applies: one request with no credential. A read is
   sent on the path filled from `path_seed`;
2. **a write is sent on a path whose parameters are random values of the declared type**, never on the operator's
   resources, so that a write which gets through finds no object of theirs to act on. What it creates (a `2xx` with
   a `Location`) is deleted at once; what cannot be deleted is named in a note;
3. on a sample of the operations proven to require a credential: five credentials that cannot be valid and the
   eight path variants. **A credential that cannot be valid is sent where and how the target expects a credential**
   (`credential_placement`, resolved from the configuration and the specification): nothing after the prefix,
   `null`, an arbitrary string, and the last of those with the header's name in lower and in upper case. A value
   sent under another scheme would be refused for being the wrong scheme and would prove nothing about whether the
   content is checked: Forgejo expects `Authorization: token <value>`, so a `Bearer` probe never reaches its check
  . A placement in a query parameter sends the three values there and has no header name
   to vary, so three cases instead of five; one in a cookie sends them in the `Cookie` header. Where
   no placement is configured, the fallback is `Authorization` with `Bearer`. The sample is one operation per first path segment, which is what
   separates the services behind one gateway, and only operations whose method changes nothing: these sub-tests
   send several requests on the operator's own seeded paths.

## 3. Oracle

<!-- [[[cog import generate_docs as g; cog.out(g.oracle_table("1.1")) ]]] -->

**`no_credential`**

| Case | Outcome / detail | Confidence |
|---|---|---|
| refused without a credential (`401`, `403`) | `ENFORCED/CREDENTIAL_REQUIRED` | - |
| served (`2xx`) without a credential, unlike a random path, the operation declaring its own requirement | `VIOLATION/SERVED_WITHOUT_CREDENTIAL` | FIRM |
| the same, the requirement being the document's default | `VIOLATION/SERVED_WITHOUT_CREDENTIAL` | TENTATIVE |
| served exactly as a random path is (a catch-all) | `NOT_VERIFIABLE/SERVED_LIKE_UNKNOWN` | - |
| an `OPTIONS` answered `2xx` with no body (an `Allow` list, no data) | `NOT_VERIFIABLE/OPTIONS_ANSWERED` | - |
| a redirect, not followed | `NOT_VERIFIABLE/REDIRECTED` | - |
| an invalid-request `4xx`: validated without a credential | `NOT_VERIFIABLE/VALIDATED_WITHOUT_CREDENTIAL` | - |
| another answer (`404`, `405`, ...), like a random sibling's | `NOT_VERIFIABLE/NOT_FOUND_LIKE_UNKNOWN` | - |
| another answer, unlike a random sibling's or with an unreliable calibration | `NOT_VERIFIABLE/NOT_FOUND_OWN_ANSWER` | - |
| the operation declares `security: []` | `NOT_APPLICABLE/DECLARED_PUBLIC` | - |
| no security requirement applies, neither the document's nor the operation's | `NOT_APPLICABLE/NO_SECURITY_DECLARED` | - |

**`malformed_credential`**

| Case | Outcome / detail | Confidence |
|---|---|---|
| a credential that cannot be valid is not served (refused, `400`, ...) | `ENFORCED/CREDENTIAL_REFUSED` | - |
| a credential that cannot be valid is served (`2xx`) where none is refused | `VIOLATION/ACCEPTED_<kind>`, the kind one of `EMPTY_CREDENTIAL`, `WORD_NULL`, `ARBITRARY_STRING`, `EMPTY_CREDENTIAL_IN_QUERY`, `WORD_NULL_IN_QUERY`, `ARBITRARY_STRING_IN_QUERY`, `HEADER_LOWERCASE`, `HEADER_UPPERCASE` | CERTAIN |
| no read operation was proven to require a credential | `NOT_VERIFIABLE/NO_PROVEN_CONTROL` | - |

**`path_variants`**

| Case | Outcome / detail | Confidence |
|---|---|---|
| a variant answers a redirect: that spelling serves nothing | `ENFORCED/VARIANT_REDIRECTED` | - |
| a variant is refused or not routed | `ENFORCED/VARIANT_NOT_SERVED` | - |
| a variant is served (`2xx`) without a credential where the path itself is refused | `VIOLATION/SERVED_AS_<kind>`, the kind one of `UPPER_SEGMENT`, `TRAILING_SLASH`, `DOUBLE_SLASH`, `DOT_SEGMENT`, `DOT_DOT_SEGMENT`, `ENCODED_SLASH`, `DOUBLE_ENCODED`, `PATH_PARAMETER` | CERTAIN |
| a variant is served exactly as a random path spelled the same way (a catch-all) | `NOT_VERIFIABLE/VARIANT_LIKE_UNKNOWN` | - |
| no read operation was proven to require a credential | `NOT_VERIFIABLE/NO_PROVEN_CONTROL` | - |

<!-- [[[end]]] -->

<!-- [[[cog import generate_docs as g; cog.out(g.uninformative_answers("1.1", page=cog.inFile)) ]]] -->

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

<!-- [[[cog import generate_docs as g; cog.out(g.oracle_validation("1.1", page=cog.inFile)) ]]] -->

Every case of the oracle, produced on a lab and judged by the code: E1, [oracle validation](../../../experiments/README.md), campaign at commit `fc60b6f`. 37 of 37 produced cases gave the declared outcome; 0 no lab can produce.

| Case | Lab, how it is produced | Result |
|---|---|---|
| `no_credential/ENFORCED/CREDENTIAL_REQUIRED` | forgejo-kong: the lab as built: GET /api/v1/user (and 133 other operations) answers 401 to a request with no credential | OK |
| `no_credential/VIOLATION/SERVED_WITHOUT_CREDENTIAL/FIRM` | crapi-kong: the lab as built: GET /workshop/api/shop/orders/{order_id} and GET /workshop/api/shop/return_qr_code declare their own security and answer 200 with no credential (crAPI challenge 14) | OK |
| `no_credential/VIOLATION/SERVED_WITHOUT_CREDENTIAL/TENTATIVE` | forgejo-kong: the lab as built: 78 genuinely public operations (/api/v1/licenses, /api/v1/orgs, ...) answer 200 with no credential while only the document's global security applies | OK |
| `no_credential/NOT_VERIFIABLE/SERVED_LIKE_UNKNOWN` | forgejo-kong: a temporary Kong route ~/api/v1/[^/]+$ answers 200 with the same body to every method, so GET /api/v1/user is served exactly as its random sibling /api/v1/zqxv<hex> | OK |
| `no_credential/NOT_VERIFIABLE/OPTIONS_ANSWERED` | forgejo-kong: the run reads a local copy of Forgejo's specification with an added OPTIONS /user (inheriting the global security), and a temporary Kong route OPTIONS ~/api/v1/user$ answers 204 with no body | OK |
| `no_credential/NOT_VERIFIABLE/REDIRECTED` | forgejo-kong: a temporary Kong route on the protected read times/user-a (GET /api/v1/repos/{owner}/{repo}/times/{user}, filled from path_seed) answers 302 itself | OK |
| `no_credential/NOT_VERIFIABLE/VALIDATED_WITHOUT_CREDENTIAL` | forgejo-kong: the lab as built: 5 Forgejo operations answer 400 for a missing query parameter before asking for a credential | OK |
| `no_credential/NOT_VERIFIABLE/NOT_FOUND_LIKE_UNKNOWN` | forgejo-kong: the lab as built: parametric writes sent on random values get Forgejo's 404, as their random siblings do | OK |
| `no_credential/NOT_VERIFIABLE/NOT_FOUND_OWN_ANSWER` | forgejo-kong: the lab as built: 5 Forgejo operations answer a 404 of their own, unlike their random siblings' | OK |
| `no_credential/NOT_APPLICABLE/DECLARED_PUBLIC` | crapi-kong: the lab as built: crAPI marks 9 operations `security: []` | OK |
| `no_credential/NOT_APPLICABLE/NO_SECURITY_DECLARED` | forgejo-kong: the run reads a local copy of Forgejo's specification with its global security set to [] (no operation declares its own): no requirement applies to any operation | OK |
| `malformed_credential/ENFORCED/CREDENTIAL_REFUSED` | forgejo-kong: the lab as built: GET /api/v1/user refuses the five malformed values sent as 'Authorization: token ...' with 401 | OK |
| `malformed_credential/VIOLATION/ACCEPTED_EMPTY_CREDENTIAL/CERTAIN` | forgejo-kong: a temporary Kong route ~/api/v1/user$ answers 200 to any request carrying an Authorization header and 401 to one without | OK |
| `malformed_credential/VIOLATION/ACCEPTED_WORD_NULL/CERTAIN` | forgejo-kong: a temporary Kong route ~/api/v1/user$ answers 200 to any request carrying an Authorization header and 401 to one without | OK |
| `malformed_credential/VIOLATION/ACCEPTED_ARBITRARY_STRING/CERTAIN` | forgejo-kong: a temporary Kong route ~/api/v1/user$ answers 200 to any request carrying an Authorization header and 401 to one without | OK |
| `malformed_credential/VIOLATION/ACCEPTED_EMPTY_CREDENTIAL_IN_QUERY/CERTAIN` | forgejo-kong: the credential placed in the query (scheme AccessToken, no prefix), and a temporary Kong route ~/api/v1/user$ answers 200 to any request carrying the query parameter access_token and 401 to one without | OK |
| `malformed_credential/VIOLATION/ACCEPTED_WORD_NULL_IN_QUERY/CERTAIN` | forgejo-kong: the credential placed in the query (scheme AccessToken, no prefix), and a temporary Kong route ~/api/v1/user$ answers 200 to any request carrying the query parameter access_token and 401 to one without | OK |
| `malformed_credential/VIOLATION/ACCEPTED_ARBITRARY_STRING_IN_QUERY/CERTAIN` | forgejo-kong: the credential placed in the query (scheme AccessToken, no prefix), and a temporary Kong route ~/api/v1/user$ answers 200 to any request carrying the query parameter access_token and 401 to one without | OK |
| `malformed_credential/VIOLATION/ACCEPTED_HEADER_LOWERCASE/CERTAIN` | forgejo-kong: a temporary Kong route ~/api/v1/user$ answers 200 to any request carrying an Authorization header (read case-insensitively) and 401 to one without | OK |
| `malformed_credential/VIOLATION/ACCEPTED_HEADER_UPPERCASE/CERTAIN` | forgejo-kong: a temporary Kong route ~/api/v1/user$ answers 200 to any request carrying an Authorization header (read case-insensitively) and 401 to one without | OK |
| `malformed_credential/NOT_VERIFIABLE/NO_PROVEN_CONTROL` | forgejo-kong: the run reads a local copy of Forgejo's specification with its global security set to []: no operation is proven to require a credential, so nothing is sampled | OK |
| `path_variants/ENFORCED/VARIANT_REDIRECTED` | crapi-kong: the lab as built: the workshop service answers 301 to the variants of /workshop/api/mechanic | OK |
| `path_variants/ENFORCED/VARIANT_NOT_SERVED` | forgejo-kong: the lab as built: every variant of GET /api/v1/user is refused (401) by Forgejo after Kong's normalisation | OK |
| `path_variants/VIOLATION/SERVED_AS_UPPER_SEGMENT/CERTAIN` | forgejo-kong: a pre-function on the /api route (and on a temporary route /) answers 200 when the raw path is one of the eight variants of /api/v1/user, here /api/v1/USER | OK |
| `path_variants/VIOLATION/SERVED_AS_TRAILING_SLASH/CERTAIN` | forgejo-kong: a pre-function on the /api route (and on a temporary route /) answers 200 when the raw path is /api/v1/user/ | OK |
| `path_variants/VIOLATION/SERVED_AS_DOUBLE_SLASH/CERTAIN` | forgejo-kong: a pre-function on the /api route (and on a temporary route /) answers 200 when the raw path (kong.request.get_raw_path) is //api/v1/user | OK |
| `path_variants/VIOLATION/SERVED_AS_DOT_SEGMENT/CERTAIN` | forgejo-kong: a pre-function on the /api route (and on a temporary route /) answers 200 when the raw path is /api/v1/./user | OK |
| `path_variants/VIOLATION/SERVED_AS_DOT_DOT_SEGMENT/CERTAIN` | forgejo-kong: a pre-function on the /api route (and on a temporary route /) answers 200 when the raw path is /api/v1/zqxv/../user | OK |
| `path_variants/VIOLATION/SERVED_AS_ENCODED_SLASH/CERTAIN` | forgejo-kong: a pre-function on the /api route (and on a temporary route /) answers 200 when the raw path is /api%2fv1%2fuser | OK |
| `path_variants/VIOLATION/SERVED_AS_DOUBLE_ENCODED/CERTAIN` | forgejo-kong: a pre-function on the /api route (and on a temporary route /) answers 200 when the raw path is /api%252fv1%252fuser | OK |
| `path_variants/VIOLATION/SERVED_AS_PATH_PARAMETER/CERTAIN` | forgejo-kong: a pre-function on the /api route (and on a temporary route /) answers 200 when the raw path is /api/v1/user;zqxv=1 | OK |
| `path_variants/NOT_VERIFIABLE/VARIANT_LIKE_UNKNOWN` | forgejo-kong: a temporary Kong route answers the same 200 to /api/v1/USER (the upper-case variant of the sampled /api/v1/user) and to the random paths /api/v1/zqxv<hex> its calibration asks; /api/v1/user itself still answers 401 | OK |
| `path_variants/NOT_VERIFIABLE/NO_PROVEN_CONTROL` | forgejo-kong: the run reads a local copy of Forgejo's specification with its global security set to []: no operation is proven to require a credential, so nothing is sampled | OK |
| `*/NOT_VERIFIABLE/UPSTREAM_UNAVAILABLE` | forgejo-kong: a temporary Kong route on the protected read times/user-a answers 503 itself | OK |
| `*/NOT_VERIFIABLE/RATE_LIMITED` | forgejo-kong: a temporary Kong route on the protected read times/user-a answers 429 itself | OK |
| `*/NOT_VERIFIABLE/SERVER_ERROR` | forgejo-kong: a temporary Kong route on the protected read times/user-a answers 500 itself | OK |
| `*/NOT_VERIFIABLE/NO_RESPONSE` | forgejo-kong: a temporary Kong route on the protected read times/user-a sleeps 7 s before proxying, and the run's read timeout is 5 s | OK |

<!-- [[[end]]] -->

### 4.2 Results on the labs

<!-- [[[cog import generate_docs as g; cog.out(g.lab_results("1.1", page=cog.inFile)) ]]] -->

No E2 campaign yet ([experiments](../../../experiments/README.md)).

<!-- [[[end]]] -->

## 5. Limitations

- A parametric operation whose answer is the same as a random sibling's cannot be judged: 251 of Forgejo's
  judgements, mostly writes, which are deliberately sent on random values.
- A write is judged only where the control runs before the application looks the object up; where the lookup comes
  first the answer is "no such object" and says nothing.
- A `400` to an unauthenticated request shows that validation runs before authentication, which NIST SP 800-228
  REC-API-14 advises against; the test counts it apart and does not call it a violation of this guarantee.
- A redirect is not followed.
- Whether the right role is required, not merely some credential, is test `2.1`'s question.

## 6. Sources

- OWASP API2:2023 Broken Authentication: https://owasp.org/API-Security/editions/2023/en/0xa2-broken-authentication/
- OWASP ASVS v5.0.0-8.2.1, "function-level access is restricted to consumers with explicit permissions":
  https://github.com/OWASP/ASVS/blob/v5.0.0/5.0/en/0x17-V8-Authorization.md
- OWASP ASVS v5.0.0-6.3.4, "no undocumented pathways ... security controls and authentication strength are enforced
  consistently" (the path variants): https://github.com/OWASP/ASVS/blob/v5.0.0/5.0/en/0x15-V6-Authentication.md
- NIST SP 800-228 section 3.2.1 (REC-API-11, "the robust authentication and correct processing of authentication
  credentials"): https://doi.org/10.6028/NIST.SP.800-228
- RFC 9110 section 5.1 (header names are case-insensitive): https://www.rfc-editor.org/rfc/rfc9110.html#section-5.1
- CWE-306 Missing Authentication for Critical Function: https://cwe.mitre.org/data/definitions/306.html

Two references that look close are not this test's: `ASVS v5.0.0-6.2.1` is the minimum length of a password, and
`NIST SP 800-63B-4 section 3.2.2` is throttling, which is test `1.7`'s. Each reference of this page was read on its
source.

## 7. Inputs

- the documented operations and, per operation, whether a security requirement applies and **where it is declared**
  (`requires_auth`, `auth_declaration`);
- `path_seed`, to fill the parameters of a read so that it reaches the control instead of a 404;
- the shared path variants.

No configuration parameter, and no credential of its own.

## 8. Outcomes

No SKIP of its own (it needs no credential and no gateway). How a sub-test's status follows from its judgements
is rule 2 of the [assessment model](../../04-architecture/03-assessment-model.md#rules-every-test-follows).

## 9. Findings

<!-- [[[cog import generate_docs as g; cog.out(g.finding_titles("1.1")) ]]] -->

- "Served without a credential: <method> <path>"
- "Credential that cannot be valid accepted: <method> <path>"
- "Path variant served without a credential: <method> <path>"

<!-- [[[end]]] -->

Each names the method and path; `evidence_ref` the answer, with the anchor's records as support where the finding rests on them.

## 10. Effects on the target

`CHANGES_DATA`: a write sent without a credential is a write, and on a target that does not enforce the credential
it goes through. Every parametric write is sent on random values, so no object of the operator's is addressed;
anything created is deleted at once and what is left is named in a note. The run order puts this test after the
read-only ones (rule 7).

## 11. Per gateway

Independent of the gateway: the control may live in the gateway or in the application, and the test judges the
answer. A gateway that normalises the path before applying its policy (Kong, for dot segments) and one that does
not (APISIX) both pass `path_variants` as long as the variant is not served.

## 12. Configuration

None.

## 13. Remediation

Enforce the credential at the gateway or in the application for every operation that needs one, and declare the
public ones with `security: []` in the specification: on a document that declares security only globally, a public
operation and a missing control look the same to any reader, human or machine.

# 1.1 Credential Required on Documented Operations

> **Audience:** analysts, contributors · **Status:** rewritten in the test review (2026-10-22) ·
> **Source of truth:**
> [`src/tests/domain_1/test_1_1_credential_required.py`](../../../src/tests/domain_1/test_1_1_credential_required.py) ·
> **Verified:** 2026-10-22

<!-- [[[cog import generate_docs as g; cog.out(g.test_header("1.1", page=cog.inFile)) ]]] -->

|  |  |
|---|---|
| Test ID | `1.1` |
| Name | Credential Required on Documented Operations |
| Domain | 1 - Identity and Authentication |
| Priority / strategy | P0 / BLACK_BOX |
| Effect | CHANGES_DATA |
| CWE | CWE-306 |
| Standards | `OWASP API2:2023`, `OWASP ASVS v5.0.0-8.2.1`, `OWASP ASVS v5.0.0-6.3.4`, `NIST SP 800-228, Section 3.2.1`, `RFC 9110, Section 5.1` |
| Tags | `authentication`, `access-control` |
| Prerequisites | none |
| Needs | - |
| Parameters | none |

<!-- [[[end]]] -->

**Same group:** tests `1.6` and `1.7` (the review of guarantees 1.1, 1.6 and 1.7 together).

## 1. Guarantee

An operation the specification declares as needing a credential refuses a request that carries none, one that
carries a credential which cannot be valid, and the same under another spelling of its own path.

A PASS promises that every operation the test could judge refused such a request. It promises nothing about whether
the credential is genuine beyond being present and well formed (a forged credential is test `1.2`, an expired one
`1.3`, a revoked one `1.4`), nothing about **which** credential should be accepted (test `2.1`), and nothing about
a path the gateway has no route for (test `0.2`).

## 2. Sub-tests and coverage of the methodology

| Sub-test | Methodology (guarantee 1.1) |
|---|---|
| `no_credential` | "no token": every documented protected operation, not a sample |
| `malformed_credential` | "empty and malformed token" and "header case variations" |
| `path_variants` | "path normalisation", from the shared list (`src/core/path_variants.py`) |

## 3. Inputs

- the documented operations and, per operation, whether a security requirement applies and **where it is declared**
  (`requires_auth`, `auth_declaration`);
- `path_seed`, to fill the parameters of a read so that it reaches the control instead of a 404;
- the shared path variants.

No configuration parameter, and no credential of its own.

## 4. Preconditions and reference responses

The calibration of each operation's own siblings, so that a `404` meaning "no such object" is not read as "the
operation is not there".

**No positive control.** The question is what the target does when a request carries no credential, which is
observed directly. An earlier version asked one per violation, to rule out "this operation refuses everyone": it
suppressed 24 true cases on Forgejo + Kong (2026-10-22), because the lab's token is issued with narrower scopes
than anonymous access, so the operation refused it while serving an anonymous request.

## 5. Probes

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
   (corrected 2026-10-22). Where no placement is configured, the fallback is `Authorization` with `Bearer`. The sample is one operation per first path segment, which is what
   separates the services behind one gateway, and only operations whose method changes nothing: these sub-tests
   send several requests on the operator's own seeded paths.

## 6. Oracle

**What the specification's declaration is worth sets the confidence.** The OpenAPI rule makes an operation's own
`security` a statement about that operation and the document's global `security` a default that may never have been
thought about. Measured 2026-10-22: crAPI declares per operation (9 of its operations are marked public with
`security: []`), Forgejo's 473 operations all inherit one global list and none declares anything of its own.

| Case | Outcome / detail | Confidence |
|---|---|---|
| refused without a credential (401, 403) | `ENFORCED/CREDENTIAL_REQUIRED` | - |
| answers `2xx` without a credential, the operation declaring its own requirement | `VIOLATION/SERVED_WITHOUT_CREDENTIAL` | FIRM |
| answers `2xx` without a credential, the requirement being the document's default | `VIOLATION/SERVED_WITHOUT_CREDENTIAL`, the finding saying the operation may be public and undeclared | TENTATIVE |
| the operation declares `security: []` | `NOT_APPLICABLE/DECLARED_PUBLIC` | - |
| no security requirement anywhere | `NOT_APPLICABLE/NO_SECURITY_DECLARED` | - |
| answers like a random sibling of its path | `NOT_VERIFIABLE/NOT_FOUND_LIKE_UNKNOWN` | - |
| answers "not found" in its own shape | `NOT_VERIFIABLE/NOT_FOUND_OWN_ANSWER` | - |
| answers `400` or `422`: the request was validated without a credential | `NOT_VERIFIABLE/VALIDATED_WITHOUT_CREDENTIAL` | - |
| answers `3xx`, not followed | `NOT_VERIFIABLE/REDIRECTED` | - |
| unavailable, rate limited, no response, server error | `NOT_VERIFIABLE/` the reason (the old test counted 14 endpoints answering `503` as a PASS) | - |
| a credential that cannot be valid is accepted | `VIOLATION/ACCEPTED_<case>` | CERTAIN |
| a path variant is served without a credential | `VIOLATION/SERVED_AS_<kind>` | CERTAIN |
| a variant is refused or not routed | `ENFORCED/VARIANT_NOT_SERVED` | - |

A note states once whether the document declares security per operation, so that a heap of TENTATIVE findings is
read for what it is.

## 7. Outcomes

No SKIP of its own (it needs no credential and no gateway). A sub-test is PASS complete when every judgement is
enforced, PASS partial when some case could not be judged, INCONCLUSIVE when none could.

## 8. Findings

One per operation: "Served without a credential: `<method> <path>`", with the status, where the requirement is
declared and what each of the two cases means; one per accepted malformed credential and per served variant, with
the header or the spelling that passed. `evidence_ref` the probe, `supporting_refs` the calibration where one was
used.

## 9. Effects on the target

`CHANGES_DATA`: a write sent without a credential is a write, and on a target that does not enforce the credential
it goes through. Every parametric write is sent on random values, so no object of the operator's is addressed;
anything created is deleted at once and what is left is named in a note. The run order puts this test after the
read-only ones (rule 7).

## 10. Per gateway

Independent of the gateway: the control may live in the gateway or in the application, and the test judges the
answer. A gateway that normalises the path before applying its policy (Kong, for dot segments) and one that does
not (APISIX) both pass `path_variants` as long as the variant is not served.

## 11. Configuration

None. The old test's parameters are gone with it.

## 12. Validation

Runs of 2026-10-22, the three tests of the group together:

| Lab | Status | Basis |
|---|---|---|
| crAPI + Kong | FAIL, **2 findings at FIRM** | `GET /workshop/api/shop/orders/{order_id}` and `GET /workshop/api/shop/return_qr_code` answer `200` with no credential, and both declare their own security requirement (crAPI challenge 14). 24 enforced, 9 `DECLARED_PUBLIC` (the operations marked `security: []`), 8 like an unknown sibling; malformed credentials 15 enforced (sent as `Authorization: Bearer ...`, crAPI's own scheme), variants 23 enforced |
| Forgejo + Kong and + APISIX | FAIL, **78 findings at TENTATIVE** | 78 operations answer `200` with no credential while the specification declares security for the whole document and marks nothing public: `/api/v1/licenses`, `/api/v1/gitignore/templates`, `/api/v1/orgs`, ... all of them genuinely public. 134 enforced, 251 like an unknown sibling, 5 with their own `404`, 5 validated without a credential (`400` for a missing query parameter: the application validates before authenticating, which NIST SP 800-228 REC-API-14 asks to be the other way round); malformed credentials 5 enforced (sent as `Authorization: token ...`, Forgejo's own scheme), variants 8 enforced |
| any | ENFORCED everywhere | a target whose declared operations all refuse: not on the labs |

The old test reported the same 78 on Forgejo and the same 2 on crAPI, with no distinction between them and with 14
endpoints answering `503` counted as a PASS.

**The two cases the labs lack, and how to undo them.** No lab serves a path variant without a credential, and
none accepts a credential that cannot be valid, so both were produced on the Forgejo + Kong lab. In
`test-environments/forgejo-kong/kong/kong.yml`, inside `services[forgejo-service].routes`:

```yaml
      # A route that answers the upper-case variant of the sampled endpoint.
      - name: review-variant-served-route
        paths:
          - /api/v1/USER
        strip_path: false
        preserve_host: false
        protocols:
          - https
        https_redirect_status_code: 301
        plugins:
          - name: request-termination
            config:
              status_code: 200
              content_type: "application/json"
              body: '{"login":"user-a"}'
      # An endpoint that requires the credential header to be there and never
      # looks at what it holds. The regex is anchored so that it does not also
      # catch /api/v1/users/... (Kong matches a path as a string).
      - name: review-any-credential-route
        paths:
          - '~/api/v1/user$'
        strip_path: false
        preserve_host: false
        protocols:
          - https
        https_redirect_status_code: 301
        plugins:
          - name: pre-function
            config:
              access:
                - |
                  if kong.request.get_header("authorization") then
                    return kong.response.exit(200, { login = "user-a" })
                  end
                  return kong.response.exit(401, { message = "token is required" })
```

Then `cd test-environments/forgejo-kong && docker compose --env-file ../../.env up -d --force-recreate --wait
kong`; undo with `git checkout test-environments/forgejo-kong/kong/kong.yml` and the same command. With the first,
`path_variants` reports 1 violation at CERTAIN (`SERVED_AS_UPPER_SEGMENT`, `/api/v1/USER` answering `200` while
`/api/v1/user` answers `401`) and 7 enforced; with the second, `malformed_credential` reports all five violations
(`ACCEPTED_EMPTY_CREDENTIAL`, `ACCEPTED_WORD_NULL`, `ACCEPTED_ARBITRARY_STRING`, `ACCEPTED_HEADER_LOWERCASE`,
`ACCEPTED_HEADER_UPPERCASE`), which is the whole oracle of that sub-test. The lab was checked back to its usual
results afterwards (2026-10-22).

**What each branch has been seen doing** (rule 9). Proven on a lab: `CREDENTIAL_REQUIRED`,
`SERVED_WITHOUT_CREDENTIAL` at both confidences, `DECLARED_PUBLIC`, `NO_SECURITY_DECLARED`,
`NOT_FOUND_LIKE_UNKNOWN`, `NOT_FOUND_OWN_ANSWER`, `VALIDATED_WITHOUT_CREDENTIAL`, `CREDENTIAL_REFUSED`,
`VARIANT_NOT_SERVED`, and with the two cases above every `ACCEPTED_<case>` and `SERVED_AS_UPPER_SEGMENT`. Still
unproven: the other seven `SERVED_AS_<kind>` details (the same code path as the one proven, one per variant),
`REDIRECTED` and the transport reasons.

## 13. Remediation

Enforce the credential at the gateway or in the application for every operation that needs one, and declare the
public ones with `security: []` in the specification: on a document that declares security only globally, a public
operation and a missing control look the same to any reader, human or machine.

## 14. Limitations

- A parametric operation whose answer is the same as a random sibling's cannot be judged: 251 of Forgejo's
  judgements, mostly writes, which are deliberately sent on random values.
- A write is judged only where the control runs before the application looks the object up; where the lookup comes
  first the answer is "no such object" and says nothing.
- A `400` to an unauthenticated request shows that validation runs before authentication, which NIST SP 800-228
  REC-API-14 advises against; the test counts it apart and does not call it a violation of this guarantee.
- A redirect is not followed.
- Whether the right role is required, not merely some credential, is test `2.1`'s question.

## 15. Sources

- OWASP API2:2023 Broken Authentication: https://owasp.org/API-Security/editions/2023/en/0xa2-broken-authentication/
- OWASP ASVS v5.0.0-8.2.1, "function-level access is restricted to consumers with explicit permissions":
  https://github.com/OWASP/ASVS/blob/v5.0.0/5.0/en/0x17-V8-Authorization.md
- OWASP ASVS v5.0.0-6.3.4, "no undocumented pathways ... security controls and authentication strength are enforced
  consistently" (the path variants): https://github.com/OWASP/ASVS/blob/v5.0.0/5.0/en/0x15-V6-Authentication.md
- NIST SP 800-228 section 3.2.1 (REC-API-11, "the robust authentication and correct processing of authentication
  credentials"): https://doi.org/10.6028/NIST.SP.800-228
- RFC 9110 section 5.1 (header names are case-insensitive): https://www.rfc-editor.org/rfc/rfc9110.html#section-5.1
- CWE-306 Missing Authentication for Critical Function: https://cwe.mitre.org/data/definitions/306.html

Two references of an earlier version were wrong and are recorded here as a warning: `ASVS v5.0.0-6.2.1` is the
minimum length of a password, and `NIST SP 800-63B-4 section 3.2.2` is throttling, which is test `1.7`'s. Each
reference of this page was read on its source on 2026-10-22.

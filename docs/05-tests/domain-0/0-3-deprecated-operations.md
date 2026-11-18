# 0.3 Deprecated Operations Still Served

> **Audience:** analysts, contributors · **Source of truth:**
> [`src/tests/domain_0/test_0_3_deprecated_operations.py`](../../../src/tests/domain_0/test_0_3_deprecated_operations.py)

<!-- [[[cog import generate_docs as g; cog.out(g.test_header("0.3", page=cog.inFile)) ]]] -->

|  |  |
|---|---|
| Test ID | `0.3` |
| Name | Deprecated Operations Still Served |
| Domain | 0 - API Discovery and Inventory Management |
| Priority / strategy | P0 / BLACK_BOX |
| Effect | READ_ONLY |
| CWE | none |
| Standards | `OWASP API9:2023`, `RFC 9745`, `RFC 8594`, `RFC 9110, Section 15.5.11`, `NIST SP 800-228, Section 3.1.1` |
| Tags | `inventory`, `deprecation` |
| Prerequisites | none |
| Needs | `USER_ACCOUNT` (optional) |
| Parameters | none |

<!-- [[[end]]] -->

**Same group:** tests `0.2` and `0.4`.

## 1. Guarantee

An operation the specification marks `deprecated: true` is either switched off, answering `410 Gone`, or still
served while declaring its own deadline: a `Sunset` date in the future (RFC 8594), and ideally the `Deprecation`
date that RFC 9745 made a Standards Track header in March 2025. NIST SP 800-228 section 2.1 states the risk:
deprecated APIs "may have been replaced or superseded by newer systems but have not yet been entirely removed" and
"risk falling behind the latest security policies and protections".

A PASS promises that every deprecated operation the test could reach is handled that way. It promises nothing about
operations the specification does not mark deprecated (an undocumented older version is test `0.1`'s question) and
nothing about what an operation returns.

## 2. Test

### 2.1 Sub-tests and coverage of the methodology

| Sub-test | Methodology (guarantee 0.3) |
|---|---|
| `deprecated_operations` | all three methodology sub-tests, judged per operation: "deprecated endpoint accessibility", "Sunset header presence", "post-sunset enforcement" |
| left out | the differential sub-tests (two versions of one operation): test `2.4`'s question. An operation the server flags as deprecated while the specification does not: it is this guarantee's question, but finding it needs a probe of the whole documented surface, which this test does not make (see the limitations) |

### 2.2 Preconditions and reference responses

- the **calibration** of the operation's own siblings, with the same method and credential condition: an answer that
  differs from a random sibling's is the operation's own, one that matches says only that nothing is there;
- no positive control: the only verdict that rests on a refusal is `NOT_VERIFIABLE`, which claims nothing.

### 2.3 Probes

1. every deprecated operation whose method is safe (`GET`, `HEAD`) and whose path can be filled: one request
   without a credential;
2. the same request with the `user_a` credential when the first was refused (401, 403);
3. a deprecated operation whose method writes is **not** sent: the test is `READ_ONLY`. Those operations are counted
   `WRITE_METHOD_NOT_PROBED` and named in a note.

## 3. Oracle

<!-- [[[cog import generate_docs as g; cog.out(g.oracle_table("0.3")) ]]] -->

| Case | Outcome / detail | Confidence |
|---|---|---|
| `410 Gone` | `ENFORCED/SWITCHED_OFF` | - |
| `405` or `501`: the method is no longer available on the path | `ENFORCED/METHOD_SWITCHED_OFF` | - |
| served or validated (`2xx`, `4xx` invalid) unlike a random sibling, with neither `Deprecation` nor `Sunset` | `VIOLATION/DEPRECATED_WITHOUT_SUNSET` | FIRM |
| served unlike a random sibling, with `Deprecation` and no `Sunset` | `VIOLATION/DEPRECATION_WITHOUT_SUNSET` | FIRM |
| served unlike a random sibling, with a `Sunset` date that has passed | `VIOLATION/PAST_SUNSET_STILL_SERVED` | FIRM |
| served unlike a random sibling, with a `Sunset` date in the future | `ENFORCED/SUNSET_DECLARED` | - |
| served unlike a random sibling, with a `Sunset` that is not an HTTP-date | `NOT_VERIFIABLE/SUNSET_NOT_A_DATE` | - |
| a path without parameters answers like a random sibling: the operation is gone | `NOT_APPLICABLE/NOT_SERVED` | - |
| a path with parameters answers like a random object: the operation gone, or the seeded object not found | `NOT_VERIFIABLE/OBJECT_OR_OPERATION_ABSENT` | - |
| refused (`401`, `403`) without a credential and with user_a's, or without and no user_a account | `NOT_VERIFIABLE/REFUSED_BEFORE_ANSWER` | - |
| a redirect, a `404` unlike a random sibling, or an answer of no class | `NOT_VERIFIABLE/ANSWER_NOT_INTERPRETED` | - |
| the calibration of the operation's siblings is unreliable | `NOT_VERIFIABLE/CALIBRATION_UNRELIABLE` | - |
| the operation's method writes: not sent | `NOT_VERIFIABLE/WRITE_METHOD_NOT_PROBED` | - |
| a path parameter has no value in `path_seed` | `NOT_VERIFIABLE/PATH_NOT_FILLABLE` | - |

<!-- [[[end]]] -->

<!-- [[[cog import generate_docs as g; cog.out(g.uninformative_answers("0.3", page=cog.inFile)) ]]] -->

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

<!-- [[[cog import generate_docs as g; cog.out(g.oracle_validation("0.3", page=cog.inFile)) ]]] -->

Every case of the oracle, produced on a lab and judged by the code: E1, [oracle validation](../../../experiments/README.md), campaign at commit `fc60b6f`. 18 of 18 produced cases gave the declared outcome; 0 no lab can produce.

| Case | Lab, how it is produced | Result |
|---|---|---|
| `deprecated_operations/ENFORCED/SWITCHED_OFF` | forgejo-kong: a temporary Kong route on the deprecated read as the test fills it (times/user-a) answers 410 itself | OK |
| `deprecated_operations/ENFORCED/METHOD_SWITCHED_OFF` | forgejo-kong: a temporary Kong route on the deprecated read (times/user-a) answers 405 itself | OK |
| `deprecated_operations/VIOLATION/DEPRECATED_WITHOUT_SUNSET/FIRM` | forgejo-kong: the lab as built: GET /api/v1/repos/{owner}/{repo}/times/{user}, filled from path_seed, answers 200 unlike a random sibling, with neither Deprecation nor Sunset | OK |
| `deprecated_operations/VIOLATION/DEPRECATION_WITHOUT_SUNSET/FIRM` | forgejo-kong: a temporary Kong route on the deprecated read (times/user-a) adds 'Deprecation: @1688169599' to Forgejo's answer | OK |
| `deprecated_operations/VIOLATION/PAST_SUNSET_STILL_SERVED/FIRM` | forgejo-kong: a temporary Kong route on the deprecated read (times/user-a) adds 'Sunset: Wed, 01 Jan 2020 00:00:00 GMT' to Forgejo's answer | OK |
| `deprecated_operations/ENFORCED/SUNSET_DECLARED` | forgejo-kong: a temporary Kong route on the deprecated read (times/user-a) adds 'Sunset: Sat, 31 Dec 2099 23:59:59 GMT' to Forgejo's answer | OK |
| `deprecated_operations/NOT_VERIFIABLE/SUNSET_NOT_A_DATE` | forgejo-kong: a temporary Kong route on the deprecated read (times/user-a) adds 'Sunset: soon' to Forgejo's answer | OK |
| `deprecated_operations/NOT_APPLICABLE/NOT_SERVED` | forgejo-kong: the run reads a local copy of Forgejo's specification with one added operation without path parameters, GET /api/v1/apiguard-deprecated-probe marked deprecated, that Forgejo does not serve: it answers 404 like its random sibling | OK |
| `deprecated_operations/NOT_VERIFIABLE/OBJECT_OR_OPERATION_ABSENT` | forgejo-kong: a temporary Kong route on times/<any> (the deprecated read and its random siblings) answers the same fixed 404 itself | OK |
| `deprecated_operations/NOT_VERIFIABLE/REFUSED_BEFORE_ANSWER` | forgejo-kong: a temporary Kong route on the deprecated read (times/user-a) answers 401 itself, with or without user_a's credential | OK |
| `deprecated_operations/NOT_VERIFIABLE/ANSWER_NOT_INTERPRETED` | forgejo-kong: a temporary Kong route on the deprecated read (times/user-a) answers 302 to https://localhost:8443/ itself | OK |
| `deprecated_operations/NOT_VERIFIABLE/CALIBRATION_UNRELIABLE` | forgejo-kong: a temporary Kong route on times/<any> (the deprecated read and its random siblings) answers 404 with a body of one of two shapes, alternating, so the two calibration siblings differ | OK |
| `deprecated_operations/NOT_VERIFIABLE/WRITE_METHOD_NOT_PROBED` | forgejo-kong: the lab as built: three deprecated operations write (POST /org/{org}/repos, DELETE and PATCH .../comments/{id}) and are not sent | OK |
| `deprecated_operations/NOT_VERIFIABLE/PATH_NOT_FILLABLE` | forgejo-kong: the run's target.path_seed is emptied, so the deprecated read's path parameters have no value | OK |
| `*/NOT_VERIFIABLE/UPSTREAM_UNAVAILABLE` | forgejo-kong: a temporary Kong route on the deprecated read (times/user-a) answers 503 itself | OK |
| `*/NOT_VERIFIABLE/RATE_LIMITED` | forgejo-kong: a temporary Kong route on the deprecated read (times/user-a) answers 429 itself | OK |
| `*/NOT_VERIFIABLE/SERVER_ERROR` | forgejo-kong: a temporary Kong route on the deprecated read (times/user-a) answers 500 itself | OK |
| `*/NOT_VERIFIABLE/NO_RESPONSE` | forgejo-kong: a temporary Kong route on the deprecated read (times/user-a) sleeps 7 s before proxying, and the run's read timeout is 5 s | OK |

<!-- [[[end]]] -->

### 4.2 Results on the labs

<!-- [[[cog import generate_docs as g; cog.out(g.lab_results("0.3", page=cog.inFile)) ]]] -->

No E2 campaign yet ([experiments](../../../experiments/README.md)).

<!-- [[[end]]] -->

## 5. Limitations

- Only operations the specification marks `deprecated: true` are examined. An operation deprecated in fact but not
  in the document is invisible here, and so is the mirror case (the server sends `Deprecation` while the
  specification does not mark it): finding that needs a probe of the whole documented surface.
- A deprecated operation whose method writes is not probed.
- A parametric path needs a value in `path_seed` for each of its parameters.
- No primary CWE: the catalogue holds no entry describing an API operation still served after being deprecated
 . The guarantee rests on the standards above.

## 6. Sources

- OWASP API9:2023 Improper Inventory Management: https://api-security.owasp.org/editions/2023/en/0xa9-improper-inventory-management/
- RFC 9745, The Deprecation HTTP Response Header Field: https://www.rfc-editor.org/rfc/rfc9745.html
- RFC 8594, The Sunset HTTP Header Field: https://www.rfc-editor.org/rfc/rfc8594.html
- RFC 9110 section 15.5.11, 410 Gone: https://www.rfc-editor.org/rfc/rfc9110.html#section-15.5.11
- NIST SP 800-228 sections 2.1 and 3.1.1 (REC-API-4.4): https://doi.org/10.6028/NIST.SP.800-228

## 7. Inputs

- the operations the specification marks deprecated (`AttackSurface`, `is_deprecated`);
- `path_seed`, to fill the parameters of a deprecated path;
- the `user_a` credential when one is configured (optional need), for an operation that refuses without it.

## 8. Outcomes

SKIP when the specification marks no operation `deprecated: true`: the absence of a declaration is not evidence that
no deprecated functionality is served, and that question belongs to test `0.1`.

## 9. Findings

<!-- [[[cog import generate_docs as g; cog.out(g.finding_titles("0.3")) ]]] -->

- "Deprecated operation still served: <where>"
- "Operation served after its sunset: <where>"

<!-- [[[end]]] -->

`evidence_ref` the operation's answer; `supporting_refs` the calibration of its siblings.

## 10. Effects on the target

`READ_ONLY`: one request per deprecated read-only operation, two when the first was refused. An operation whose
method writes is never sent.

## 11. Per gateway

Independent of the gateway: both headers come from the application, and a gateway adding them in a response
transformation is a correct way of satisfying the guarantee.

## 12. Configuration

None. Everything comes from the specification and `path_seed`.

## 13. Remediation

Switch the operation off and answer `410 Gone`, or declare `Deprecation` (RFC 9745) and `Sunset` (RFC 8594) with a
future date and a `Link` to the replacement.

# 0.3 Deprecated Operations Still Served

> **Audience:** analysts, contributors · **Status:** rewritten in the test review (2026-10-22) ·
> **Source of truth:**
> [`src/tests/domain_0/test_0_3_deprecated_operations.py`](../../../src/tests/domain_0/test_0_3_deprecated_operations.py) ·
> **Verified:** 2026-11-16

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

## 2. Sub-tests and coverage of the methodology

| Sub-test | Methodology (guarantee 0.3) |
|---|---|
| `deprecated_operations` | all three methodology sub-tests, judged per operation: "deprecated endpoint accessibility", "Sunset header presence", "post-sunset enforcement" |
| left out | the differential sub-tests (two versions of one operation): test `2.4`'s question. An operation the server flags as deprecated while the specification does not: it is this guarantee's question, but finding it needs a probe of the whole documented surface, which this test does not make (see the limitations) |

## 3. Inputs

- the operations the specification marks deprecated (`AttackSurface`, `is_deprecated`);
- `path_seed`, to fill the parameters of a deprecated path;
- the `user_a` credential when one is configured (optional need), for an operation that refuses without it.

## 4. Preconditions and reference responses

- the **calibration** of the operation's own siblings, with the same method and credential condition: an answer that
  differs from a random sibling's is the operation's own, one that matches says only that nothing is there;
- no positive control: the only verdict that rests on a refusal is `NOT_VERIFIABLE`, which claims nothing.

## 5. Probes

1. every deprecated operation whose method is safe (`GET`, `HEAD`) and whose path can be filled: one request
   without a credential;
2. the same request with the `user_a` credential when the first was refused (401, 403);
3. a deprecated operation whose method writes is **not** sent: the test is `READ_ONLY`. Those operations are counted
   `WRITE_METHOD_NOT_PROBED` and named in a note.

## 6. Oracle

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

Until 2026-11-16 a `404` unlike a random sibling's (a framework's page where the handler's JSON was expected) was "still served", FIRM: now only a served or validated answer (`2xx`, `4xx` invalid) is the operation running; and a path with parameters answering like a random object was `NOT_APPLICABLE/NOT_SERVED`, although the seeded object may only be missing: now `NOT_VERIFIABLE/OBJECT_OR_OPERATION_ABSENT`.

<!-- [[[cog import generate_docs as g; cog.out(g.uninformative_answers("0.3", page=cog.inFile)) ]]] -->

The answers that say nothing about the guarantee by themselves, one rule for every test ([assessment model](../../04-architecture/03-assessment-model.md#answers-that-say-nothing-about-the-guarantee)), generated from the code:

| Answer | Sub-tests | Outcome / detail |
|---|---|---|
| `UPSTREAM_UNAVAILABLE` | every sub-test | `NOT_VERIFIABLE/UPSTREAM_UNAVAILABLE` |
| `RATE_LIMITED` | every sub-test | `NOT_VERIFIABLE/RATE_LIMITED` |
| `SERVER_ERROR` | every sub-test | `NOT_VERIFIABLE/SERVER_ERROR` |
| `NO_RESPONSE` | every sub-test | `NOT_VERIFIABLE/NO_RESPONSE` |

<!-- [[[end]]] -->

## 7. Outcomes

SKIP when the specification marks no operation `deprecated: true`: the absence of a declaration is not evidence that
no deprecated functionality is served, and that question belongs to test `0.1`.

## 8. Findings

<!-- [[[cog import generate_docs as g; cog.out(g.finding_titles("0.3")) ]]] -->

- "Deprecated operation still served: <where>"
- "Operation served after its sunset: <where>"

<!-- [[[end]]] -->

`evidence_ref` the operation's answer; `supporting_refs` the calibration of its siblings.

## 9. Effects on the target

`READ_ONLY`: one request per deprecated read-only operation, two when the first was refused. An operation whose
method writes is never sent.

## 10. Per gateway

Independent of the gateway: both headers come from the application, and a gateway adding them in a response
transformation is a correct way of satisfying the guarantee.

## 11. Configuration

None. Everything comes from the specification and `path_seed`.

## 12. Validation

**2026-11-16, after the review** (0.1 to 0.4 on the three labs as configured): both Forgejo labs **FAIL** (`DEPRECATED_WITHOUT_SUNSET`, 3 writes not probed), crAPI SKIP (no operation marked deprecated), as before.


Runs of 2026-10-22, the three tests of the group together:

| Lab | Status | Basis |
|---|---|---|
| Forgejo + Kong, Forgejo + APISIX | FAIL, 1 finding | the specification marks four operations deprecated; `GET /api/v1/repos/{owner}/{repo}/times/{user}`, filled from the lab's `path_seed`, answers `200` unlike a random sibling and sends neither `Deprecation` nor `Sunset`. The other three write (`POST /org/{org}/repos`, `DELETE` and `PATCH .../comments/{id}`) and are named in a note |
| crAPI + Kong | SKIP | crAPI 1.1.6 marks no operation `deprecated: true` |
| any | ENFORCED | an operation answering `410`, or carrying a future `Sunset`: not on the labs |

All four deprecated operations of the reference lab have parameters in their path, and the old test excluded every
path holding `{`, which is why the violation the lab holds had never been seen.

**The cases the labs lack, produced on 2026-11-15** (Forgejo + Kong, one temporary route at a time added to
`forgejo-service` in `kong/kong.yml`, undone with `git checkout` and the lab checked back). The route matches the
deprecated read as the test fills it, `~/api/v1/repos/[^/]+/[^/]+/times/user-a$`, and carries a `pre-function`:
in its `header_filter` phase it adds a header to Forgejo's answer, in its `access` phase it answers itself.

| The route | Result |
|---|---|
| adds `Sunset: Sat, 31 Dec 2099 23:59:59 GMT` | PASS partial, `SUNSET_DECLARED` |
| adds `Sunset: Wed, 01 Jan 2020 00:00:00 GMT` | FAIL, `PAST_SUNSET_STILL_SERVED` (FIRM) |
| adds `Deprecation: @1688169599` | FAIL, `DEPRECATION_WITHOUT_SUNSET` (FIRM) |
| adds `Sunset: soon` | INCONCLUSIVE, `SUNSET_NOT_A_DATE` |
| answers `410` | PASS partial, `SWITCHED_OFF` |
| answers `405` | PASS partial, `METHOD_SWITCHED_OFF` |
| answers `302` to `https://localhost:8443/` | INCONCLUSIVE, `ANSWER_NOT_INTERPRETED` |
| answers `401`, with or without the credential | INCONCLUSIVE, `REFUSED_BEFORE_ANSWER` |
| answers `429`, `500`, `503` | INCONCLUSIVE, `RATE_LIMITED`, `SERVER_ERROR`, `UPSTREAM_UNAVAILABLE` |
| sleeps 7 s (the run's `target.read_timeout: 5.0`) | INCONCLUSIVE, `NO_RESPONSE` |
| on `~/api/v1/repos/[^/]+/[^/]+/times/[^/]+$` (its random siblings too), answers `404` alike | INCONCLUSIVE, `NOT_SERVED` |
| on the same pattern, answers `404` with a body of one of two shapes at random | INCONCLUSIVE, `CALIBRATION_UNRELIABLE` |

**What each branch has been seen doing** (rule 9). Every branch of this test has been seen: on the labs as they
stand `DEPRECATED_WITHOUT_SUNSET`, `WRITE_METHOD_NOT_PROBED` and the SKIP; `PATH_NOT_FILLABLE` with the run's
`target.path_seed` emptied (2026-11-15); every other one with the routes of the table above.

## 13. Remediation

Switch the operation off and answer `410 Gone`, or declare `Deprecation` (RFC 9745) and `Sunset` (RFC 8594) with a
future date and a `Link` to the replacement.

## 14. Limitations

- Only operations the specification marks `deprecated: true` are examined. An operation deprecated in fact but not
  in the document is invisible here, and so is the mirror case (the server sends `Deprecation` while the
  specification does not mark it): finding that needs a probe of the whole documented surface.
- A deprecated operation whose method writes is not probed.
- A parametric path needs a value in `path_seed` for each of its parameters.
- No primary CWE: the catalogue holds no entry describing an API operation still served after being deprecated
  (the whole dictionary of CWE 4.20 was searched on 2026-10-22; CWE-1104 is limited to third-party components and
  CWE-1059 is prohibited for mapping). The guarantee rests on the standards above.

## 15. Sources

- OWASP API9:2023 Improper Inventory Management: https://api-security.owasp.org/editions/2023/en/0xa9-improper-inventory-management/
- RFC 9745, The Deprecation HTTP Response Header Field: https://www.rfc-editor.org/rfc/rfc9745.html
- RFC 8594, The Sunset HTTP Header Field: https://www.rfc-editor.org/rfc/rfc8594.html
- RFC 9110 section 15.5.11, 410 Gone: https://www.rfc-editor.org/rfc/rfc9110.html#section-15.5.11
- NIST SP 800-228 sections 2.1 and 3.1.1 (REC-API-4.4): https://doi.org/10.6028/NIST.SP.800-228

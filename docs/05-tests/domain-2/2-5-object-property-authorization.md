# 2.5 Object Property-Level Authorization

> **Audience:** analysts, contributors · **Status:** new in the test review (2026-10-23) ·
> **Source of truth:**
> [`src/tests/domain_2/test_2_5_object_property_authorization.py`](../../../src/tests/domain_2/test_2_5_object_property_authorization.py),
> [`src/tests/helpers/owned_object.py`](../../../src/tests/helpers/owned_object.py) · **Verified:** 2026-10-23

<!-- [[[cog import generate_docs as g; cog.out(g.test_header("2.5", page=cog.inFile)) ]]] -->

|  |  |
|---|---|
| Test ID | `2.5` |
| Name | Object Property-Level Authorization |
| Domain | 2 - Authorization and Access Control |
| Priority / strategy | P1 / GREY_BOX |
| Effect | CHANGES_DATA |
| CWE | CWE-213 |
| Standards | `OWASP API3:2023`, `OWASP ASVS v5.0.0-14.2.6`, `OWASP ASVS v5.0.0-8.2.2`, `NIST SP 800-53, Section 3` |
| Tags | `authorization`, `excessive-data`, `mass-assignment` |
| Prerequisites | none |
| Needs | `USER_ACCOUNT`, `owned_object_resources` |
| Parameters | [`tests.domain_2.test_2_5`](../../03-reference/01-configuration.md#testsdomain_2test_2_5) |

<!-- [[[end]]] -->

**Same group:** tests `2.1`, `2.2`, `2.4` (authorization).

## 1. Guarantee

The API exposes only the properties a user may see, and accepts only the properties a user may set. A PASS promises
that an object's response carried no sensitive field, and that an object created with extra privileged fields ignored
them. The threat is Broken Object Property Level Authorization (OWASP API3:2023): excessive data exposure (a
`passwordHash` in the response) and mass assignment (a client sets `role` or `owner` through the body). ASVS
v5.0.0-14.2.6 (return only the minimum sensitive data), v5.0.0-8.2.2.

## 2. Sub-tests and coverage of the methodology

| Sub-test | Methodology (guarantee 2.5) |
|---|---|
| `no_sensitive_field` | "sensitive field presence: the response must not contain password, passwordHash, ssn, creditCard, apiKey" |
| `mass_assignment` | "mass assignment protection: an object created passing a field that is not the token's is created ignoring the body's value" |
| folded in | "role-based field filtering": a field a user must not see is caught by its name in `no_sensitive_field`, for any role; labelling an "admin-only non-sensitive" field generically is not reliable |
| left out | nested-object filtering beyond the scan depth; UUID entropy (not an authorization question) |

## 3. Inputs

A disposable object owned by user_a, created through a configured `resources:` resource (`owned_object_resources`,
the same as test 2.2). For mass assignment the create body is extended with unique string sentinels
(`src/tests/helpers/resources.py`, `extra_body`).

## 4. Preconditions and reference responses

user_a is required. The object is created and read back as user_a. A sensitive field is judged by its name; a mass
assignment by reading the object back and finding a unique sentinel, so the verdict rests on the response itself.

## 5. Probes

Create the object as user_a, read it, scan its field names for sensitive ones; create a second object injecting
ownership fields (`role`, `owner`, `user_id`, ... each a unique string sentinel), read it back, and see whether a
sentinel was kept. Both objects are deleted. CHANGES_DATA.

## 6. Oracle

**`no_sensitive_field`**

| Case | Outcome / detail | Confidence |
|---|---|---|
| a field whose name is sensitive is in the response | `VIOLATION/SENSITIVE_FIELD` | FIRM (the name is a heuristic) |
| no sensitive field | `ENFORCED/NO_SENSITIVE_FIELD` | - |
| the object could not be read | `NOT_VERIFIABLE/OBJECT_NOT_READABLE` | - |

**`mass_assignment`**

| Case | Outcome / detail | Confidence |
|---|---|---|
| an injected sentinel was kept in the object | `VIOLATION/MASS_ASSIGNMENT` | CERTAIN (the unique sentinel was read back) |
| no sentinel kept | `ENFORCED/NO_MASS_ASSIGNMENT` | - |
| the object could not be read | `NOT_VERIFIABLE/OBJECT_NOT_READABLE` | - |

Only unique **string** sentinels are injected: a boolean such as `admin: true` reflected in a response cannot be told
from a field that is legitimately true (the owner's own permissions), which would be a false positive.

## 7. Outcomes

SKIP without user_a or `owned_object_resources`. Otherwise FAIL on a sensitive field or a mass assignment, PASS when
neither is found.

## 8. Findings

"Response carries sensitive field(s): `<names>`"; "Object bound client-controlled field(s): `<names>`". The object
read is in the transaction log.

## 9. Effects on the target

`CHANGES_DATA`: creates two disposable objects owned by user_a (one plain, one with injected fields) and deletes
both.

## 10. Per gateway

Independent of the adapter: property filtering and body binding are the application's.

## 11. Configuration

<!-- [[[cog import generate_docs as g; cog.out(g.test_params("2.5", page=cog.inFile)) ]]] -->

Section [`tests.domain_2.test_2_5`](../../03-reference/01-configuration.md#testsdomain_2test_2_5) of `config.yaml`:

| Key | Type | Default | Description |
|---|---|---|---|
| `owned_object_resources` | list | empty, **needed to run** | The config.yaml `resources:` resources that each create a disposable object owned by user_a (the same as test 2.2); each is checked in turn. Without any the test cannot run. |

<!-- [[[end]]] -->

## 12. Validation

Runs of 2026-10-23:

| Lab | Status | Basis |
|---|---|---|
| Forgejo + Kong, Forgejo + APISIX | **PASS** | the repo response carries no sensitive field; a repo created with injected `role`/`owner`/... sentinels keeps none of them |
| crAPI + Kong | **FAIL**, 1 finding | the order response carries **`card_number`** (excessive data exposure, a real crAPI weakness); the injected sentinels are not kept (`mass_assignment` ENFORCED) |

Rule 9: `no_sensitive_field` is proven on both sides, VIOLATION on crAPI (the order's `card_number`) and ENFORCED on
Forgejo. `mass_assignment` is ENFORCED on both labs; its VIOLATION branch is not present on these objects (its
matcher was exercised by the false-positive fix below). A self-review caught and fixed that false positive: a boolean
sentinel matched the repo's legitimate `permissions.admin: true`; the matcher now uses unique string sentinels only.

## 13. Remediation

Filter responses server-side to the fields the consumer may see (ASVS v5.0.0-14.2.6); bind only an allowlist of
request fields, never the whole body (mass assignment, CWE-915).

## 14. Limitations

- Sensitive fields are judged by name (a heuristic): an oddly-named sensitive field is missed, a harmless field with
  a sensitive-looking name is a FIRM, not CERTAIN, finding.
- Mass assignment probes a fixed set of common ownership field names with string sentinels; a boolean-only privileged
  field, or a field name outside the set, is not caught (to avoid false positives).
- The scan descends a few levels into the response; a deeply nested sensitive field is missed.
- The object comes from `owned_object_resources` and always will: deriving candidate objects from the target is not
  planned (2026-10-27), so without a configured resource the test is SKIP (the same boundary as test 2.2).

## 15. Sources

- OWASP API3:2023 Broken Object Property Level Authorization: https://owasp.org/API-Security/editions/2023/en/0xa3-broken-object-property-level-authorization/
- OWASP ASVS v5.0.0-14.2.6 (minimum sensitive data), v5.0.0-8.2.2: https://github.com/OWASP/ASVS/blob/v5.0.0/5.0/en/0x23-V14-Data-Protection.md
- CWE-213 Exposure of Sensitive Information Due to Incompatible Policies: https://cwe.mitre.org/data/definitions/213.html
- CWE-915 Improperly Controlled Modification of Dynamically-Determined Object Attributes (mass assignment): https://cwe.mitre.org/data/definitions/915.html

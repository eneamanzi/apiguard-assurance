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
| Standards | `OWASP API3:2023`, `OWASP ASVS v5.0.0-15.3.1`, `OWASP ASVS v5.0.0-15.3.3`, `OWASP ASVS v5.0.0-8.2.3`, `CWE-915`, `NIST SP 800-53r5, Section 3.1` |
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
v5.0.0-14.2.6 (return only the minimum sensitive data), v5.0.0-8.2.3 (field-level access, the requirement ASVS
writes for broken object property level authorization), CWE-915.

## 2. Sub-tests and coverage of the methodology

| Sub-test | Methodology (guarantee 2.5) |
|---|---|
| `no_sensitive_field` | "sensitive field presence: the response must not contain password, passwordHash, ssn, creditCard, apiKey" |
| `mass_assignment` | "mass assignment protection: an object created passing a field that is not the token's is created ignoring the body's value" |
| folded in | "role-based field filtering": a field a user must not see is caught by its name in `no_sensitive_field`, for any role; labelling an "admin-only non-sensitive" field generically is not reliable |
| left out | nested-object filtering beyond the scan depth; UUID entropy (not an authorization question) |

## 3. Inputs

A disposable object owned by user_a, created through a configured `resources:` resource (`owned_object_resources`,
the same as test 2.2). For mass assignment the create body is extended with a string sentinel unlikely to appear by chance
(`src/tests/helpers/resources.py`, `extra_body`).

## 4. Preconditions and reference responses

user_a is required. The object is created and read back as user_a. A sensitive field is judged by its name and its
value. A short marker (`pwd`, `hash`, `ssn`, `cvv`, `salt`) must be a whole word of the name (`user_ssn` matches,
`classname` does not); a longer one may be part of it, separators ignored (`passwordhash`, `accessToken`,
`API-Key`). As for the value, a null, empty or masked one (mask characters with at most four in clear, as `XXXXXXXXXXXX0796`) discloses
nothing. A mass assignment is judged by reading the object back and finding a unique sentinel, so the verdict rests on
the response itself; it needs the read-back to show at least one of the injected field names.

## 5. Probes

Create the object as user_a, read it, scan its field names for sensitive ones; create a second object injecting
ownership fields (`role`, `owner`, `user_id`, ... each carrying that sentinel; a bound field is recognised by its own name in the read-back object), read it back, and see whether a
sentinel was kept. Both objects are deleted when their resource has a delete request. An object whose resource has no delete request (a crAPI order), or whose delete fails, stays on the target and is named in a note of the result (until 2026-11-04 only in the log). CHANGES_DATA.

## 6. Oracle

<!-- [[[cog import generate_docs as g; cog.out(g.oracle_table("2.5")) ]]] -->

**`no_sensitive_field`**

| Case | Outcome / detail | Confidence |
|---|---|---|
| a sensitive-named field holds a value: a string not empty or masked, or a number for a card, SSN or CVV | `VIOLATION/SENSITIVE_FIELD` | FIRM |
| no sensitive field holds a value | `ENFORCED/NO_SENSITIVE_FIELD` | - |
| no documented read, or the read is not served | `NOT_VERIFIABLE/OBJECT_NOT_READABLE` | - |
| the prepared resource did not create the object | `NOT_VERIFIABLE/OBJECT_NOT_CREATED` | - |

**`mass_assignment`**

| Case | Outcome / detail | Confidence |
|---|---|---|
| an injected field (one the configured body does not set) is read back holding the sentinel | `VIOLATION/MASS_ASSIGNMENT` | FIRM |
| an injected field name is shown without the sentinel | `ENFORCED/NO_MASS_ASSIGNMENT` | - |
| the create with the injected fields is refused as invalid while the plain one works: unknown fields rejected, or a field bound with a wrong-typed value | `NOT_VERIFIABLE/INJECTED_CREATE_REFUSED` | - |
| the read-back shows none of the injected field names | `NOT_VERIFIABLE/FIELDS_NOT_EXPOSED` | - |
| the resource's create body is not a JSON object | `NOT_VERIFIABLE/FIELDS_NOT_INJECTED` | - |
| no documented read, or the read is not served | `NOT_VERIFIABLE/OBJECT_NOT_READABLE` | - |
| the prepared resource did not create the object | `NOT_VERIFIABLE/OBJECT_NOT_CREATED` | - |

<!-- [[[end]]] -->

Until 2026-11-16: a sensitive-named field was a finding whatever its value, so `has_password: true`, `secret_scanning: {...}` or `max_tokens: 4096` were excessive exposure: now only a string value (not masked), or a number under a card, SSN or CVV name, and not a name about a credential (`password_expires_at`); the mass-assignment sentinel replaced a key the configured body sets, and a reflected field was CERTAIN, although the API may let the client set it: now FIRM, and only the keys the body does not set are injected; a create refused as invalid because of the injected fields was `OBJECT_NOT_CREATED`: now `INJECTED_CREATE_REFUSED` (not verifiable: unknown fields rejected, or a bound field given a wrong-typed value, which the string sentinels cannot tell apart). ASVS 15.3.1 (only the required fields) and 15.3.3 (mass assignment) replace 14.2.6 (L3).

<!-- [[[cog import generate_docs as g; cog.out(g.uninformative_answers("2.5", page=cog.inFile)) ]]] -->

The answers that say nothing about the guarantee by themselves, one rule for every test ([assessment model](../../04-architecture/03-assessment-model.md#answers-that-say-nothing-about-the-guarantee)), generated from the code:

| Answer | Sub-tests | Outcome / detail |
|---|---|---|
| `UPSTREAM_UNAVAILABLE` | every sub-test | `NOT_VERIFIABLE/UPSTREAM_UNAVAILABLE` |
| `RATE_LIMITED` | every sub-test | `NOT_VERIFIABLE/RATE_LIMITED` |
| `SERVER_ERROR` | every sub-test | `NOT_VERIFIABLE/SERVER_ERROR` |
| `NO_RESPONSE` | every sub-test | `NOT_VERIFIABLE/NO_RESPONSE` |

<!-- [[[end]]] -->

## 7. Outcomes

SKIP without user_a or `owned_object_resources`. Otherwise FAIL on a sensitive field or a mass assignment, PASS when
neither is found.

## 8. Findings

<!-- [[[cog import generate_docs as g; cog.out(g.finding_titles("2.5")) ]]] -->

- "Response carries sensitive field(s): <fields>"
- "Object bound client-controlled field(s): <fields>"

<!-- [[[end]]] -->

`evidence_ref` the read-back; the titles name the fields.

## 9. Effects on the target

`CHANGES_DATA`: creates two disposable objects owned by user_a (one plain, one with injected fields) and deletes
both; an object that cannot be deleted (a crAPI order) stays and is named in a note of the result.

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

**2026-11-16, after the review** (domain 2 on the three labs as configured): Forgejo labs **PASS**, crAPI **PASS** partial (`FIELDS_NOT_EXPOSED`), as before.


Runs of 2026-10-23; the rows were measured again on 2026-11-04 (2.5 alone), after the corrections of the external
audit:

| Lab | Status | Basis |
|---|---|---|
| Forgejo + Kong, Forgejo + APISIX | **PASS** | the repo response carries no sensitive field; a repo created with injected `role`/`owner`/... sentinels shows `owner` (the real owner, not the sentinel) and none of the sentinel values |
| crAPI + Kong | **PASS** partial | the order response carries `card_number`, masked (`XXXXXXXXXXXX0796`, shown to its own owner): no exposure. The order shows none of the injected field names (its owner is `user`), so `mass_assignment` is `FIELDS_NOT_EXPOSED` |

Until 2026-11-04 crAPI was reported FAIL on that masked number, and `mass_assignment` ENFORCED on an order that
shows none of the injected fields: both corrected.

Rule 9: `no_sensitive_field` is proven ENFORCED on both labs; its VIOLATION branch was seen on crAPI only through
the masked number, now excluded, so it is unproven on a lab. `mass_assignment` is ENFORCED on Forgejo and
`FIELDS_NOT_EXPOSED` on crAPI; its VIOLATION branch is not present on these objects (its matcher was exercised by
the false-positive fix below), and `FIELDS_NOT_INJECTED` is not reached by the labs' resources. A self-review caught and fixed that false positive: a boolean
sentinel matched the repo's legitimate `permissions.admin: true`; the matcher now accepts a string sentinel only.

**What each branch has been seen doing** (rule 9). Proven on a lab: `NO_SENSITIVE_FIELD` (Forgejo, crAPI),
`NO_MASS_ASSIGNMENT` (both Forgejo labs), `FIELDS_NOT_EXPOSED` (crAPI), `OBJECT_NOT_CREATED` (crAPI after about ten
runs without a reset, [compatibility](../../03-reference/06-compatibility.md#what-the-tool-detects-measured-against-a-vulnerable-target)).
On 2026-11-15, Forgejo + Kong with temporary routes on `forgejo-service` in `kong/kong.yml` (undone with `git
checkout`, the lab checked back), the object read being `GET ~/api/v1/repos/user-a/[^/]+$`:
- `SENSITIVE_FIELD` (FIRM): the read answered `200` with an object holding `"salt": "lab-dummy-value"`;
- `OBJECT_NOT_READABLE`: the read answered `404`, on both sub-tests;
- `NO_RESPONSE`: the read slept 7 s (the run's `target.read_timeout: 5.0`), on both sub-tests;
- `MASS_ASSIGNMENT` (CERTAIN): a `pre-function` on `POST /api/v1/user/repos` kept the create body in Kong's
  shared memory (the request still reached Forgejo), and the read answered that body back, so the injected
  sentinels came back from the object.

`FIELDS_NOT_INJECTED` was seen on 2026-11-15 (Forgejo + Kong, the run's `repository` resource given the body
`"not-an-object"`). Every branch of this test has been seen.

## 13. Remediation

Filter responses server-side to the fields the consumer may see (ASVS v5.0.0-14.2.6); bind only an allowlist of
request fields, never the whole body (mass assignment, CWE-915).

## 14. Limitations

- Sensitive fields are judged by name (a heuristic): an oddly-named sensitive field is missed, a harmless field with
  a sensitive-looking name is a FIRM, not CERTAIN, finding.
- Mass assignment probes a fixed set of common ownership field names with string sentinels; a boolean-only privileged
  field, or a field name outside the set, is not caught (to avoid false positives).
- The scan descends three levels into the response and reads the first five items of each list; a deeper sensitive
  field, or one only in a later list item, is missed.
- The object comes from `owned_object_resources` and always will: deriving a candidate object from the target was
  designed and measured against the three labs on 2026-10-29 and found none, because establishing ownership cannot
  be made target-agnostic (the measurement and what it means are in
  [test 2.2's limitations](2-2-object-level-authorization.md#14-limitations)). Without a configured resource this
  test gives no verdict.

## 15. Sources

- OWASP API3:2023 Broken Object Property Level Authorization: https://owasp.org/API-Security/editions/2023/en/0xa3-broken-object-property-level-authorization/
- OWASP ASVS v5.0.0-14.2.6 (minimum sensitive data), v5.0.0-8.2.3 (field-level access, BOPLA): https://github.com/OWASP/ASVS/blob/v5.0.0/5.0/en/0x23-V14-Data-Protection.md
- CWE-213 Exposure of Sensitive Information Due to Incompatible Policies: https://cwe.mitre.org/data/definitions/213.html
- CWE-915 Improperly Controlled Modification of Dynamically-Determined Object Attributes (mass assignment): https://cwe.mitre.org/data/definitions/915.html

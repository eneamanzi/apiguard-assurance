# 2.5 Object Property-Level Authorization

> **Audience:** analysts, contributors · **Source of truth:**
> [`src/tests/domain_2/test_2_5_object_property_authorization.py`](../../../src/tests/domain_2/test_2_5_object_property_authorization.py), [`src/tests/helpers/owned_object.py`](../../../src/tests/helpers/owned_object.py)

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

## 2. Test

### 2.1 Sub-tests and coverage of the methodology

| Sub-test | Methodology (guarantee 2.5) |
|---|---|
| `no_sensitive_field` | "sensitive field presence: the response must not contain password, passwordHash, ssn, creditCard, apiKey" |
| `mass_assignment` | "mass assignment protection: an object created passing a field that is not the token's is created ignoring the body's value" |
| folded in | "role-based field filtering": a field a user must not see is caught by its name in `no_sensitive_field`, for any role; labelling an "admin-only non-sensitive" field generically is not reliable |
| left out | nested-object filtering beyond the scan depth; UUID entropy (not an authorization question) |

### 2.2 Preconditions and reference responses

user_a is required. The object is created and read back as user_a. A sensitive field is judged by its name and its
value. A short marker (`pwd`, `hash`, `ssn`, `cvv`, `salt`) must be a whole word of the name (`user_ssn` matches,
`classname` does not); a longer one may be part of it, separators ignored (`passwordhash`, `accessToken`,
`API-Key`). As for the value, a null, empty or masked one (mask characters with at most four in clear, as `XXXXXXXXXXXX0796`) discloses
nothing. A mass assignment is judged by reading the object back and finding a unique sentinel, so the verdict rests on
the response itself; it needs the read-back to show at least one of the injected field names.

### 2.3 Probes

Create the object as user_a, read it, scan its field names for sensitive ones; create a second object injecting
ownership fields (`role`, `owner`, `user_id`, ... each carrying that sentinel; a bound field is recognised by its own name in the read-back object), read it back, and see whether a
sentinel was kept. Both objects are deleted when their resource has a delete request. An object whose resource has no delete request (a crAPI order), or whose delete fails, stays on the target and is named in a note of the result. CHANGES_DATA.

## 3. Oracle

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

<!-- [[[cog import generate_docs as g; cog.out(g.uninformative_answers("2.5", page=cog.inFile)) ]]] -->

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

<!-- [[[cog import generate_docs as g; cog.out(g.oracle_validation("2.5", page=cog.inFile)) ]]] -->

Every case of the oracle, produced on a lab and judged by the code: E1, [oracle validation](../../../experiments/README.md), campaign at commit `fc60b6f`. 15 of 15 produced cases gave the declared outcome; 0 no lab can produce.

| Case | Lab, how it is produced | Result |
|---|---|---|
| `no_sensitive_field/VIOLATION/SENSITIVE_FIELD/FIRM` | forgejo-kong: a route answers the repository's read 200 with an object holding "salt": "lab-dummy-value" | OK |
| `no_sensitive_field/ENFORCED/NO_SENSITIVE_FIELD` | forgejo-kong: the lab as built: user_a's private repository, read back, carries no sensitive field | OK |
| `no_sensitive_field/NOT_VERIFIABLE/OBJECT_NOT_READABLE` | forgejo-kong: a route answers the repository's read 404 to everyone | OK |
| `no_sensitive_field/NOT_VERIFIABLE/OBJECT_NOT_CREATED` | forgejo-kong: the repository resource's create body is given a name Forgejo refuses (spaces), so both creates answer 422 | OK |
| `mass_assignment/VIOLATION/MASS_ASSIGNMENT/FIRM` | forgejo-kong: a pre-function on POST /api/v1/user/repos keeps the create body in Kong's shared memory (the request still reaches Forgejo) and the repository's read answers that body back, so the injected sentinels come back | OK |
| `mass_assignment/ENFORCED/NO_MASS_ASSIGNMENT` | forgejo-kong: the lab as built: the repository created with injected role/owner/... shows owner (the real owner), not the sentinel | OK |
| `mass_assignment/NOT_VERIFIABLE/INJECTED_CREATE_REFUSED` | forgejo-kong: a pre-function on POST /api/v1/user/repos answers 422 to a create body holding the sentinel apiguard-mass-probe and passes the plain create to Forgejo | OK |
| `mass_assignment/NOT_VERIFIABLE/FIELDS_NOT_EXPOSED` | crapi-kong: the lab as built: the crAPI order read back shows none of the injected field names (its owner is `user`) | OK |
| `mass_assignment/NOT_VERIFIABLE/FIELDS_NOT_INJECTED` | forgejo-kong: the repository resource's create body is the JSON string "not-an-object", so no field can be merged into it | OK |
| `mass_assignment/NOT_VERIFIABLE/OBJECT_NOT_READABLE` | forgejo-kong: a route answers the repository's read 404 to everyone | OK |
| `mass_assignment/NOT_VERIFIABLE/OBJECT_NOT_CREATED` | forgejo-kong: the repository resource's create body is given a name Forgejo refuses (spaces): the plain create fails too, so the injected create's refusal is OBJECT_NOT_CREATED | OK |
| `*/NOT_VERIFIABLE/UPSTREAM_UNAVAILABLE` | forgejo-kong: a route answers the repository's read 503 to everyone: both read-backs unavailable | OK |
| `*/NOT_VERIFIABLE/RATE_LIMITED` | forgejo-kong: a route answers the repository's read 429 to everyone: both read-backs throttled | OK |
| `*/NOT_VERIFIABLE/SERVER_ERROR` | forgejo-kong: a route answers the repository's read 500 to everyone: both read-backs fail | OK |
| `*/NOT_VERIFIABLE/NO_RESPONSE` | forgejo-kong: a route makes the repository's read sleep 7 s, past the run's 5 s read timeout | OK |

<!-- [[[end]]] -->

### 4.2 Results on the labs

<!-- [[[cog import generate_docs as g; cog.out(g.lab_results("2.5", page=cog.inFile)) ]]] -->

No E2 campaign yet ([experiments](../../../experiments/README.md)).

<!-- [[[end]]] -->

## 5. Limitations

- Sensitive fields are judged by name (a heuristic): an oddly-named sensitive field is missed, a harmless field with
  a sensitive-looking name is a FIRM, not CERTAIN, finding.
- Mass assignment probes a fixed set of common ownership field names with string sentinels; a boolean-only privileged
  field, or a field name outside the set, is not caught (to avoid false positives).
- The scan descends three levels into the response and reads the first five items of each list; a deeper sensitive
  field, or one only in a later list item, is missed.
- The object comes from `owned_object_resources` and always will: deriving a candidate object from the target was
  designed and measured against the three labs and found none, because establishing ownership cannot
  be made target-agnostic (the measurement and what it means are in
  [test 2.2's limitations](2-2-object-level-authorization.md#5-limitations)). Without a configured resource this
  test gives no verdict.

## 6. Sources

- OWASP API3:2023 Broken Object Property Level Authorization: https://owasp.org/API-Security/editions/2023/en/0xa3-broken-object-property-level-authorization/
- OWASP ASVS v5.0.0-14.2.6 (minimum sensitive data), v5.0.0-8.2.3 (field-level access, BOPLA): https://github.com/OWASP/ASVS/blob/v5.0.0/5.0/en/0x23-V14-Data-Protection.md
- CWE-213 Exposure of Sensitive Information Due to Incompatible Policies: https://cwe.mitre.org/data/definitions/213.html
- CWE-915 Improperly Controlled Modification of Dynamically-Determined Object Attributes (mass assignment): https://cwe.mitre.org/data/definitions/915.html

## 7. Inputs

A disposable object owned by user_a, created through a configured `resources:` resource (`owned_object_resources`,
the same as test 2.2). For mass assignment the create body is extended with a string sentinel unlikely to appear by chance
(`src/tests/helpers/resources.py`, `extra_body`).

## 8. Outcomes

SKIP without user_a or `owned_object_resources`. Otherwise FAIL on a sensitive field or a mass assignment, PASS when
neither is found.

## 9. Findings

<!-- [[[cog import generate_docs as g; cog.out(g.finding_titles("2.5")) ]]] -->

- "Response carries sensitive field(s): <fields>"
- "Object bound client-controlled field(s): <fields>"

<!-- [[[end]]] -->

`evidence_ref` the read-back; the titles name the fields.

## 10. Effects on the target

`CHANGES_DATA`: creates two disposable objects owned by user_a (one plain, one with injected fields) and deletes
both; an object that cannot be deleted (a crAPI order) stays and is named in a note of the result.

## 11. Per gateway

Independent of the adapter: property filtering and body binding are the application's.

## 12. Configuration

<!-- [[[cog import generate_docs as g; cog.out(g.test_params("2.5", page=cog.inFile)) ]]] -->

Section [`tests.domain_2.test_2_5`](../../03-reference/01-configuration.md#testsdomain_2test_2_5) of `config.yaml`:

| Key | Type | Default | Description |
|---|---|---|---|
| `owned_object_resources` | list | empty, **needed to run** | The config.yaml `resources:` resources that each create a disposable object owned by user_a (the same as test 2.2); each is checked in turn. Without any the test cannot run. |

<!-- [[[end]]] -->

## 13. Remediation

Filter responses server-side to the fields the consumer may see (ASVS v5.0.0-14.2.6); bind only an allowlist of
request fields, never the whole body (mass assignment, CWE-915).

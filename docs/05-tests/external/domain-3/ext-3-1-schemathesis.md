# ext.3.1.schemathesis Input Validation

> **Audience:** analysts, contributors · **Source of truth:**
> [`src/external_tests/ext_test_3_1_input_validation_schemathesis.py`](../../../../src/external_tests/ext_test_3_1_input_validation_schemathesis.py), [`src/connectors/schemathesis.py`](../../../../src/connectors/schemathesis.py)

<!-- [[[cog import generate_docs as g; cog.out(g.test_header("ext.3.1.schemathesis", page=cog.inFile)) ]]] -->

|  |  |
|---|---|
| Test ID | `ext.3.1.schemathesis` |
| Name | Input Validation (Schemathesis) |
| Domain | 3 - Data Integrity |
| Priority / strategy | P2 / BLACK_BOX |
| Effect | STRESSES_TARGET |
| CWE | CWE-20 |
| Standards | `OWASP ASVS v5.0.0-2.2.1`, `OWASP ASVS v5.0.0-16.5.3`, `NIST SP 800-53r5, Section 3.19` |
| Tags | `input-validation`, `injection`, `fuzzing` |
| Prerequisites | none |
| Needs | `USER_ACCOUNT` (optional) |
| Parameters | none |
| Tool | `schemathesis` ([`external_tools.schemathesis`](../../../03-reference/01-configuration.md#external_tools)) |

<!-- [[[end]]] -->

**Tool:** Schemathesis (Python, the `[schemathesis]` extra). **Same guarantee:** 3.1 input validation.

## 1. Guarantee

Every input is validated against its type, format, range and pattern before the business logic. A PASS promises
that no generated input, valid or invalid, made any of the operations Schemathesis reached answer a server error.
The threat (CWE-20, ASVS v5.0.0-2.2.1, NIST SP 800-53r5 SI-10): an input that reaches code unable to handle it.
What the test measures is only that: a `5xx`, with the request that causes it. The OWASP API Top 10 2023 has no category for the validation of a client's input (API10:2023 is the API's
trust in data it consumes from third-party APIs, which this test does not exercise), so the guarantee rests on the
three references above.

## 2. Test

### 2.1 Sub-tests and coverage of the methodology

| Sub-test | Methodology (guarantee 3.1) |
|---|---|
| `input_validated` | Schemathesis generates valid and invalid inputs from the spec and runs `not_a_server_error` |
| left out on purpose | `response_schema_conformance` (the responses against the specification: the documentation, not the input; it reported crAPI's order endpoint answering `order` where the spec says `orders`); `negative_data_rejection` (every invalid input rejected: on Forgejo it reported 9 endpoints without parameters, `/api/v1/version` among them, for answering `200` to a nameless extra header and query parameter, `-H '0: ' '...?=false'`, which an HTTP server may ignore; its other findings could not be told apart from those) |
| left out | the deep injection confirmation (sqlmap, NoSQLMap, Dalfox, commix, SSTImap), not planned; writes with a credential (see Probes) |

### 2.2 Preconditions and reference responses

Schemathesis must be installed (else SKIP). No reference responses: the tool's own checks are the oracle (rule 11).

### 2.3 Probes

`schemathesis run <spec> --base-url <base><base path> --data-generation-method all --checks not_a_server_error --request-timeout <ms>`
generates valid and invalid requests per operation (bounded by `max_examples`). The base URL carries the
specification's own base path (Forgejo's `/api/v1`), because Schemathesis takes the base path from the base URL and
drops the one in the specification. Effect `STRESSES_TARGET` (many generated requests), run last.

**Two ways of running it**:

- **with user_a's credential**, when it is configured and travels in a header or a cookie: `-H '<name>: <value>'`
  (shown `[REDACTED]` in the displayed command), `--include-method GET` and `--set-path <name>=<value>` for every
  entry of `path_seed`. Only reads are sent: a generated write with a valid credential would create, change or
  delete data the tool cannot clean up. The operator's resources fill the path parameters, so that a read addresses
  an object that exists instead of a random name answering `404`. The credential is replaced by
  `[REDACTED: user_a token]` everywhere in the tool's output before it is stored;
- **without a credential** otherwise, or when the credential travels in the query (Schemathesis has no option for
  it): every method, no `path_seed` (a generated `DELETE` would address the operator's resources). The writes it
  generates are refused where the API requires a credential.

A note in the result says which run it was, and the message of a run with the credential ends: "Reads only, with
user_a's credential: writes were not sent, because with a valid credential they would create, change or delete
data the tool cannot clean up."

## 3. Oracle (`input_validated`)

<!-- [[[cog import generate_docs as g; cog.out(g.oracle_table("ext.3.1.schemathesis")) ]]] -->

| Case | Outcome / detail | Confidence |
|---|---|---|
| an operation answers a server error (`500`, ...) to a generated input | `VIOLATION/INPUT_NOT_VALIDATED` | FIRM |
| no failure, and at least one operation was checked | `ENFORCED/INPUT_VALIDATED` | - |
| every generated request to an operation got a `4xx`: never reached | `NOT_VERIFIABLE/ONLY_4XX` | - |
| Schemathesis reports an operation as errored or skipped | `NOT_VERIFIABLE/OPERATION_NOT_CHECKED` | - |
| an operation's failing cases quote only `501`: the method is not served | `NOT_VERIFIABLE/NOT_IMPLEMENTED` | - |
| no failure, and no operation was checked | `NOT_VERIFIABLE/NOTHING_CHECKED` | - |

<!-- [[[end]]] -->

<!-- [[[cog import generate_docs as g; cog.out(g.uninformative_answers("ext.3.1.schemathesis", page=cog.inFile)) ]]] -->

The answers that say nothing about the guarantee by themselves, one rule for every test ([assessment model](../../../04-architecture/03-assessment-model.md#answers-that-say-nothing-about-the-guarantee)), generated from the code:

| Answer | Sub-tests | Outcome / detail |
|---|---|---|
| `UPSTREAM_UNAVAILABLE` | every sub-test | `NOT_VERIFIABLE/UPSTREAM_UNAVAILABLE` |
| `RATE_LIMITED` | every sub-test | judged by the oracle above: Schemathesis's check counts a `429` as any 4xx: an operation that answers only 4xx is `ONLY_4XX`. |
| `SERVER_ERROR` | every sub-test | judged by the oracle above: a `500` to a generated input is what this test reports (Schemathesis's `not_a_server_error` check). |
| `NO_RESPONSE` | every sub-test | `NOT_VERIFIABLE/NO_RESPONSE` |

<!-- [[[end]]] -->

## 4. Validation

### 4.1 Oracle cases

<!-- [[[cog import generate_docs as g; cog.out(g.oracle_validation("ext.3.1.schemathesis", page=cog.inFile)) ]]] -->

Every case of the oracle, produced on a lab and judged by the code: E1, [oracle validation](../../../../experiments/README.md), campaign at commit `fc60b6f`. 8 of 8 produced cases gave the declared outcome; 0 no lab can produce.

| Case | Lab, how it is produced | Result |
|---|---|---|
| `input_validated/VIOLATION/INPUT_NOT_VALIDATED/FIRM` | crapi-kong: crAPI as built, with user_a's credential (reads only): GET /workshop/api/shop/orders/{order_id} answers 500 to a generated input | OK |
| `input_validated/ENFORCED/INPUT_VALIDATED` | forgejo-kong: Forgejo + Kong as built, with user_a's credential (reads only): the GET operations reached answer no server error | OK |
| `input_validated/NOT_VERIFIABLE/ONLY_4XX` | forgejo-kong: same run as INPUT_VALIDATED: the organization, admin and notification reads answer 403 to user_a's token (repository and user scopes) on every generated request | OK |
| `input_validated/NOT_VERIFIABLE/OPERATION_NOT_CHECKED` | forgejo-kong: unauthenticated (user_a not configured), target.base_url on a closed port (the specification still read through Kong): Schemathesis reports every operation errored | OK |
| `input_validated/NOT_VERIFIABLE/NOT_IMPLEMENTED` | forgejo-kong: with user_a's credential (reads only), a temporary route GET ~/api/v1/version$ answers 501 itself: every failing case of that operation quotes only [501] | OK |
| `input_validated/NOT_VERIFIABLE/NOTHING_CHECKED` | forgejo-kong: unauthenticated (user_a not configured), the forgejo container stopped, the specification read from a copy: every operation gets Kong's 503, none is checked | OK |
| `*/NOT_VERIFIABLE/UPSTREAM_UNAVAILABLE` | forgejo-kong: same run as NOTHING_CHECKED: the forgejo container stopped, every operation's failing cases quote only Kong's 503 | OK |
| `*/NOT_VERIFIABLE/NO_RESPONSE` | forgejo-kong: with user_a's credential (reads only), a temporary route GET ~/api/v1/version$ waits 7 s before proxying: every generated request to it exceeds request_timeout_seconds (5 s), so its failing cases quote only the timeout (a deprecated operation would not do: Schemathesis runs with --exclude-deprecated) | OK |

<!-- [[[end]]] -->

### 4.2 Results on the labs

<!-- [[[cog import generate_docs as g; cog.out(g.lab_results("ext.3.1.schemathesis", page=cog.inFile)) ]]] -->

No E2 campaign yet ([experiments](../../../../experiments/README.md)).

<!-- [[[end]]] -->

## 5. Limitations

- **A failure is judged by its test cases.** Schemathesis lists, per operation, the test cases that failed, each
  with the command that reproduces it. A case quoting only `502`, `503` or `504` is set aside as an unavailable
  backend; the operation is a finding on its other cases, and the finding quotes each with its command.
- **The inputs are generated at random on every run** (Hypothesis), so the same target and configuration can give
  different results from one run to the next (the Forgejo labs reached 56 operations in one run, 89 in another). A
  finding is a real request the target answered with a server error (its reproduction is in the finding); a PASS
  says only that the inputs drawn in that run, on the operations reached, were all handled. Raising `max_examples`
  draws more.
- Each generated request is given `request_timeout_seconds` (default 5) to answer; a slower one counts as failed.
- Writes are never tested with a credential: a validation gap in a write behind the credential is not seen. With
  the credential, a write is not tested at all (crAPI's `check-otp` `500`s are found only by the unauthenticated
  run).
- The credential's own permissions limit what is reached: the Forgejo labs' token has the `repository` and `user`
  scopes, so organization, admin and notification reads answer `403` (`ONLY_4XX`); so do the paths whose parameters
  `path_seed` does not cover (`{index}`, `{sha}`, ...).
- The command line of the tool, credential included, is visible to the other users of the machine while it runs
  (`-H`); it is never written to the outputs or the logs (a timeout no longer chains the command into the logged
  traceback).
- Only server errors are findings: an invalid input the API accepts without failing is not reported (Sub-tests). Deep injection confirmation
  (sqlmap, NoSQLMap, Dalfox, commix) is not planned either.
- Bounded by `max_examples`: a validation gap that needs a specific generated value may be missed at a low setting.
- Schemathesis flags a server error; whether a flagged input actually executes an injection is outside what this
  test can say: it reports a suspicious response, never a confirmed injection.

## 6. Sources

- NIST SP 800-53 Rev.5 SI-10 (information input validation): https://csrc.nist.gov/projects/cprt/catalog#/cprt/framework/version/SP_800_53_5_1_1/home
- OWASP ASVS v5.0.0-2.2.1 (input validated against expectations): https://github.com/OWASP/ASVS/blob/v5.0.0/5.0/en/0x11-V2-Validation-and-Business-Logic.md
- CWE-20 Improper Input Validation: https://cwe.mitre.org/data/definitions/20.html
- Schemathesis: https://schemathesis.readthedocs.io/

## 7. Inputs

The OpenAPI specification (`target.get_openapi_source()`, a URL or local file), the base URL, and
`target.tls.ca_bundle`. `external_tools.schemathesis.max_examples` bounds the generated cases per operation. When
the configuration has the user_a account (optional need `USER_ACCOUNT`, the engine logs in before the test), its
credential and the operator's resources (`target.path_seed`).

## 8. Outcomes

SKIP without Schemathesis. FAIL on any failing operation; PASS when at least one operation was reached and none
failed (`partial` when some could not be judged, which on the labs is always: most operations need a credential);
INCONCLUSIVE when nothing could be checked.

## 9. Findings

<!-- [[[cog import generate_docs as g; cog.out(g.finding_titles("ext.3.1.schemathesis")) ]]] -->

- "<_FINDING_TITLE>: <operation>"

<!-- [[[end]]] -->

`evidence_ref` Schemathesis's output artifact; at most 20 operations get a finding, the others are only counted in the message.

## 10. Effects on the target

`STRESSES_TARGET`: many generated requests, unauthenticated, and they include the writes the specification
declares. **Whether data is created depends on the target, not on this test**: on the three labs nothing was, because
every operation served without a credential there is a `GET` (measured by test 1.1: 78 findings, all
`GET`), but an API with an unauthenticated write will have it exercised. The declaration stays `STRESSES_TARGET`
because that is the last slot in the run order (rule 7) and the vocabulary has no value that says both; an operator
who cannot accept a write on the target disables the external tools (`external_tools.enabled: false`).

## 11. Per gateway

Independent of the gateway: the validation is the application's; Schemathesis addresses the API through the base URL.

## 12. Configuration

Under `external_tools.schemathesis`: `enabled`, `timeout_seconds` (required when enabled), `max_examples` (generated
cases per operation, default 5), `request_timeout_seconds` (how long each generated request may take, default 5; a
slower one counts as failed).

## 13. Remediation

Validate every input against its type, format, range and pattern (allow-list) at the edge, returning a clean 400 on
a bad input, and never a 500 (CWE-20, ASVS v5.0.0-2.2.1, NIST SP 800-53r5 SI-10).

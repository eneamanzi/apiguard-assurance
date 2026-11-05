# ext.3.1.schemathesis Input Validation

> **Audience:** analysts, contributors · **Status:** new in the test review (2026-10-23) ·
> **Source of truth:**
> [`src/external_tests/ext_test_3_1_input_validation_schemathesis.py`](../../../../src/external_tests/ext_test_3_1_input_validation_schemathesis.py),
> [`src/connectors/schemathesis.py`](../../../../src/connectors/schemathesis.py) · **Verified:** 2026-10-23

<!-- [[[cog import generate_docs as g; cog.out(g.test_header("ext.3.1.schemathesis", page=cog.inFile)) ]]] -->

|  |  |
|---|---|
| Test ID | `ext.3.1.schemathesis` |
| Name | Input Validation (Schemathesis) |
| Domain | 3 - Data Integrity |
| Priority / strategy | P2 / BLACK_BOX |
| Effect | STRESSES_TARGET |
| CWE | CWE-20 |
| Standards | `OWASP ASVS v5.0.0-2.2.1`, `NIST SP 800-53r5, Section 3.19` |
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

## 2. Sub-tests and coverage of the methodology

| Sub-test | Methodology (guarantee 3.1) |
|---|---|
| `input_validated` | Schemathesis generates valid and invalid inputs from the spec and runs `not_a_server_error` |
| left out on purpose (owner decisions 2026-11-04) | `response_schema_conformance` (the responses against the specification: the documentation, not the input; it reported crAPI's order endpoint answering `order` where the spec says `orders`); `negative_data_rejection` (every invalid input rejected: on Forgejo it reported 9 endpoints without parameters, `/api/v1/version` among them, for answering `200` to a nameless extra header and query parameter, `-H '0: ' '...?=false'`, which an HTTP server may ignore; its other findings could not be told apart from those) |
| left out | the deep injection confirmation (sqlmap, NoSQLMap, Dalfox, commix, SSTImap), not planned (2026-10-27); writes with a credential (see Probes) |

## 3. Inputs

The OpenAPI specification (`target.get_openapi_source()`, a URL or local file), the base URL, and
`target.tls.ca_bundle`. `external_tools.schemathesis.max_examples` bounds the generated cases per operation. When
the configuration has the user_a account (optional need `USER_ACCOUNT`, the engine logs in before the test), its
credential and the operator's resources (`target.path_seed`).

## 4. Preconditions and reference responses

Schemathesis must be installed (else SKIP). No reference responses: the tool's own checks are the oracle (rule 11).

## 5. Probes

`schemathesis run <spec> --base-url <base><base path> --data-generation-method all --checks not_a_server_error --request-timeout <ms>`
generates valid and invalid requests per operation (bounded by `max_examples`). The base URL carries the
specification's own base path (Forgejo's `/api/v1`), because Schemathesis takes the base path from the base URL and
drops the one in the specification. Effect `STRESSES_TARGET` (many generated requests), run last.

**Two ways of running it** (owner decision 2026-11-04; until then it always ran unauthenticated):

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

## 6. Oracle (`input_validated`)

| Case | Outcome / detail | Confidence |
|---|---|---|
| no operation answered a server error, and at least one was reached | `ENFORCED/INPUT_VALIDATED` | - |
| an operation answered a server error to a generated input | `VIOLATION/INPUT_NOT_VALIDATED` (one per operation, up to 20 reported), quoting each failing test case with its reproduction command | FIRM (the tool observed it) |
| an operation's only failing test cases quote `502`, `503` or `504` (an unavailable backend) | `NOT_VERIFIABLE/UPSTREAM_UNAVAILABLE`, no finding | - |
| every generated request to an operation got a `4xx` (Schemathesis's warning "returned only 4xx responses"): never reached: without a credential, the one Schemathesis makes up for the declared security schemes answers `401` (Forgejo); with user_a's, every generated input of that operation was refused | `NOT_VERIFIABLE/ONLY_4XX` | - |
| Schemathesis reports an operation as errored or skipped | `NOT_VERIFIABLE/OPERATION_NOT_CHECKED` | - |
| no operation was checked at all | `NOT_VERIFIABLE/NOTHING_CHECKED` | - |
| the tool could not connect / timed out | ERROR (the base class handles it) | - |

## 7. Outcomes

SKIP without Schemathesis. FAIL on any failing operation; PASS when at least one operation was reached and none
failed (`partial` when some could not be judged, which on the labs is always: most operations need a credential);
INCONCLUSIVE when nothing could be checked.

## 8. Findings

"Server error on a generated input: `<METHOD> <path>`", quoting each failing test case and the command that
reproduces it; `evidence_ref` the tool output artifact, which keeps Schemathesis's messages whole.

## 9. Effects on the target

`STRESSES_TARGET`: many generated requests, unauthenticated, and they include the writes the specification
declares. **Whether data is created depends on the target, not on this test**: on the three labs nothing was, because
every operation served without a credential there is a `GET` (measured by test 1.1 on 2026-10-29, 78 findings, all
`GET`), but an API with an unauthenticated write will have it exercised. The declaration stays `STRESSES_TARGET`
because that is the last slot in the run order (rule 7) and the vocabulary has no value that says both; an operator
who cannot accept a write on the target disables the external tools (`external_tools.enabled: false`).

## 10. Per gateway

Independent of the gateway: the validation is the application's; Schemathesis addresses the API through the base URL.

## 11. Configuration

Under `external_tools.schemathesis`: `enabled`, `timeout_seconds` (required when enabled), `max_examples` (generated
cases per operation, default 5), `request_timeout_seconds` (how long each generated request may take, default 5; a
slower one counts as failed).

## 12. Validation

Runs of 2026-11-04, after the corrections of that day (only `not_a_server_error`, the cases judged one by one,
`ONLY_4XX`):

| Lab | Status | Basis |
|---|---|---|
| crAPI + Kong, with user_a's credential | **FAIL**, 2 findings | `GET /workshop/api/shop/orders/0` and `GET /workshop/api/mechanic/receive_report?mechanic_code=...` answer `500` to a generated input, each with the command that reproduces it (the second needs a credential: unauthenticated it was never reached) |
| crAPI + Kong, unauthenticated (the run before) | **FAIL**, 4 findings | `POST .../check-otp` (v2, v3), `POST /identity/api/auth/v2.7/user/login-with-token` and `GET /workshop/api/shop/orders/{order_id}` answer `500`; 16 operations answered only `503` once Schemathesis's own `500`s had made Kong's health check take the backend out (`UPSTREAM_UNAVAILABLE`). The `POST` ones are not tested by the authenticated run (reads only) |
| Forgejo + Kong, Forgejo + APISIX, with user_a's credential | **PASS** partial | the 241 `GET` operations, reached in 110 to 211 of them depending on the run (an operation counts as reached when one of its 3 random requests gets past a `4xx`), none answering a server error. Unauthenticated the same day: 56 and 89 of 469 |
| any | a credential Schemathesis does not filter | the run's credential appears nowhere in the outputs: checked on crAPI (no `eyJ...` string in the report, the evidence, the artifact or the log) |

The same day, before those corrections, the test counted all 469 Forgejo operations as checked, and reported
findings it did not measure: on Forgejo, endpoints without parameters "accepting" a nameless extra parameter, and
on crAPI a response not matching the specification, all titled "Input not validated".

**What these runs corrected** (an external audit, 2026-11-03). On both Forgejo labs the base URL lacked `/api/v1`,
so every generated request missed the API: measured with Schemathesis limited to `GET`, all 241 operations answered
only `4xx` before the fix and 142 after it (the rest are reached; the 142 need a credential this unauthenticated
test does not carry). The test reported PASS throughout. On crAPI, 24 of the 27 failures of 2026-11-03 were Kong's
`503` once its health check had marked the backend unhealthy, each reported as a finding; and only valid data was
generated, so `negative_data_rejection` never had an invalid request to judge.

Rule 9: VIOLATION on crAPI (real `500`s), ENFORCED on Forgejo, `UPSTREAM_UNAVAILABLE` on crAPI, `ONLY_4XX` on all
three. Not seen: `OPERATION_NOT_CHECKED` and `NOTHING_CHECKED`.

## 13. Remediation

Validate every input against its type, format, range and pattern (allow-list) at the edge, returning a clean 400 on
a bad input, and never a 500 (CWE-20, ASVS v5.0.0-2.2.1, NIST SP 800-53r5 SI-10).

## 14. Limitations

- **A failure is judged by its test cases.** Schemathesis lists, per operation, the test cases that failed, each
  with the command that reproduces it. A case quoting only `502`, `503` or `504` is set aside as an unavailable
  backend; the operation is a finding on its other cases, and the finding quotes each with its command. Until
  2026-11-04 the message was cut at 500 characters, which dropped the commands and could mix a `503` case into a
  finding (crAPI's `return_qr_code`: shown as "Server error [503]" while the finding rested on its second case).
- **The inputs are generated at random on every run** (Hypothesis), so the same target and configuration can give
  different results from one run to the next (on 2026-11-04 the Forgejo labs reached 56 and 89 operations). A
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

## 15. Sources

- NIST SP 800-53 Rev.5 SI-10 (information input validation): https://csrc.nist.gov/projects/cprt/catalog#/cprt/framework/version/SP_800_53_5_1_1/home
- OWASP ASVS v5.0.0-2.2.1 (input validated against expectations): https://github.com/OWASP/ASVS/blob/v5.0.0/5.0/en/0x11-V2-Validation-and-Business-Logic.md
- CWE-20 Improper Input Validation: https://cwe.mitre.org/data/definitions/20.html
- Schemathesis: https://schemathesis.readthedocs.io/

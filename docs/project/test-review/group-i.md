# Group I: guarantees 6.1, 6.2, 6.3, 6.4 (working file)

> **Audience:** the owner and me, during the review. Method: the six phases in
> [`test-review.md`](../test-review.md) (How we work).

| Phase | State |
|---|---|
| 1. Collection | done 2026-10-23 (below) |
| 2. Design | done 2026-10-23; owner decisions below |
| 3. Code | done 2026-10-23 (6.1, 6.2, 6.4; 6.3 deferred) |
| 4. Proof | done 2026-10-23 (three labs) |
| 5. Self-review | done 2026-10-23 (sampling added, below) |
| 6. Documentation | done 2026-10-23 |

### Results and review (2026-10-23)

| Lab | 6.1 | 6.2 | 6.4 |
|---|---|---|---|
| Forgejo + Kong, Forgejo + APISIX | **PASS** | **PASS** | **PASS** |
| crAPI + Kong | **PASS** | **FAIL** (headers inconsistent across services) | **PASS** |

New `6.1` (error/info disclosure, uses the `response_inspector` helpers) and rewritten `6.2` (headers, HSTS removed to
1.5, CORS added) and `6.4` (hard-coded credentials, ported to the new base). A new shared sampling helper
(`src/tests/helpers/sampling.py`, one documented operation per service prefix, rule 5) is used by 6.1 and 6.2.

**Self-review:** 6.1/6.2 first checked a single endpoint; the methodology of 6.2 asks for consistency across
endpoints. Added the service-prefix sampling. It immediately paid off: crAPI 6.2 went from PASS to **FAIL**, finding
that the security headers are present on some crAPI services and absent on others (an inconsistency a single-endpoint
check missed). Rule 9 for 6.2: ENFORCED on Forgejo, VIOLATION on crAPI, agnostic, no lab change.

**VIOLATION branches of 6.1 and 6.4 are lab-unproven.** The labs leak nothing; injecting a leak through Kong proved
fiddly (Kong strips user:password from a service URL, and a DB-less config carries few scannable values, the review's
own note). The detectors are deterministic (`response_inspector`, credential regexes), and 6.2 proves the
header-reading path end-to-end. Offered to wire a live demo later.

**6.3 (smuggling) is deferred** and kept as a separate open guarantee (owner, 2026-10-23: group I's marker covers
6.1/6.2/6.4; 6.3 stays open).

ASVS verified on source (v5.0.0): 3.4.3/3.4.4/3.4.6 (headers), 13.3.1 (secrets), 13.4.2/13.4.6 (debug/version),
16.5.1 (generic error). Corrections applied: 13.4.2 is debug-mode (not error detail), 13.4.1 is .git metadata
(dropped from 6.4), 3.4.6 is frame-ancestors (X-Frame-Options obsolete).

### Decided (owner, 2026-10-23)

1. **6.3 (smuggling) deferred** to a later block: group I is 6.1, 6.2, 6.4 now.
2. **6.4 stays one test, two sub-tests** (the guarantee is one; no id split).
3. **Lab changes announced** where rule 9 needs a leaked/missing header to be shown.
4. 6.2 internal scope confirmed: drop HSTS (1.5) and Permissions-Policy (not in ASVS 3.4), add CORS, no primary CWE.

Group I is what a response lets out: 6.1 error/info disclosure, 6.2 security headers, 6.3 layer-7 hardening
(smuggling, CORS, timeouts), 6.4 hard-coded or exposed credentials. They share response inspection
(`src/tests/helpers/response_inspector.py`, the B9 helpers, so far unused) and the gateway's config.

## Phase 1: collection (2026-10-23)

### The guarantees (methodology, read on `04-guarantees.md`)

| # | Guarantee | Question | References |
|---|---|---|---|
| 6.1 | errors/responses disclose no internals | does a provoked error leak a stack trace, a debug field, a version header? | API8:2023, ASVS V13.4.2/V13.4.6/V16.5.1, CWE-209 |
| 6.2 | security headers are set | are X-Content-Type-Options, X-Frame-Options/CSP, CORS set correctly? | API8:2023, ASVS V3.4.x |
| 6.3 | the gateway is hardened at layer 7 | does it reject an ambiguous CL+TE request (smuggling)? are layer-7 timeouts bounded? | API8:2023, CWE-444, ASVS V14.5.3 |
| 6.4 | service credentials are not hard-coded/exposed | does a debug endpoint leak secrets? does the gateway config hold a secret? | API8:2023, CWE-798, ASVS V13.3.x |

### What exists and what the helpers give

- **6.2 on `main`:** X-Content-Type-Options, X-Frame-Options, CSP, Permissions-Policy, **and HSTS** (2 sub-tests).
  Review: HSTS now belongs to 1.5 (done); CORS should join 6.2; Permissions-Policy is not in ASVS 3.4;
  X-Frame-Options is superseded by CSP `frame-ancestors`; its primary `CWE-16` is a prohibited mapping category.
- **6.4 on `main`:** sub-test A (debug endpoint paths -> env exposure, empirical) and sub-test B (scan the gateway's
  `config_values` for secrets, white box). Review: it is two tests in one; sub-test B scans nothing on Kong DB-less;
  `gateway_block_body_fragment` defaults to Kong's message.
- **6.1, 6.3:** new. The response-inspection helpers are ready and unused: `contains_stack_trace`,
  `extract_debug_fields`, `find_leaky_headers`, `find_missing/invalid_security_headers`, `auth_errors_are_uniform`
  (`src/tests/helpers/response_inspector.py`).

### Boundaries already settled elsewhere (rule 10)

- **HSTS** -> 1.5 (done); 6.2 drops it.
- **Path normalization variants** -> 0.2 and 1.1 (done); 6.3 drops them.
- **Authentication-error enumeration** -> 1.7 (done); 6.1 drops it (keeps the other error types).
- **CORS** -> 6.2 (review decision); 6.3 drops it.
- **Debug endpoints** (`/actuator/env`): the path that exposes env/secrets -> 6.4; a debug **field** inside a normal
  response -> 6.1; a shadow path that merely answers -> 0.1.

## Phase 2: design (presented 2026-10-23)

### The boundary (rule 10)

| Question | Test |
|---|---|
| does a provoked error or a normal response leak a stack trace, a debug field, or a version/leaky header? | **6.1** |
| are the defensive security headers (content-type, framing/CSP, CORS) present and sound? | **6.2** |
| does the gateway reject an ambiguous CL+TE request (smuggling), and bound its layer-7 timeouts? | **6.3** |
| does a debug endpoint leak secrets, or the gateway config hold one? | **6.4** |

### Compact design

**6.1 Error and Information Disclosure.** GREY_BOX (a credential to reach authenticated endpoints), READ_ONLY,
CWE-209. Sub-tests: `no_stack_trace` (provoke errors: a type-mismatch path param, a missing required field, malformed
JSON, each response has no stack-trace/SQL/path/class/version marker, `contains_stack_trace`), `no_debug_field` (a
normal response carries no `_debug`/`_sql`/`_internal` field, `extract_debug_fields`), `no_leaky_header`
(`X-Powered-By` absent, `Server` not a version, internal `X-*` removed, `find_leaky_headers`). Provoked on documented
endpoints, derived. Oracle: a marker present -> VIOLATION (FIRM, a keyword heuristic); none -> ENFORCED.

**6.2 Security Headers.** BLACK_BOX, READ_ONLY. ASVS V3.4.x. HSTS removed (1.5). Sub-tests: `content_type_options`
(`nosniff`, V3.4.4), `framing_protection` (CSP `frame-ancestors` or X-Frame-Options, V3.4.3/V3.4.6),
`cors_not_wildcard` (not `Access-Control-Allow-Origin: *` with `Allow-Credentials: true`, a critical CORS
misconfiguration). Permissions-Policy dropped (not in ASVS 3.4). Checked on a documented response and on a sample for
consistency. Primary CWE: none (CWE-16 is prohibited); rests on the ASVS references. Confidence CERTAIN (a header is
observed).

**6.3 Layer-7 Hardening.** The smuggling probe needs an **ambiguous CL+TE request**, which the SecurityClient (httpx)
cannot send; it needs a raw socket. Sub-tests: `smuggling_rejected` (a request with both `Content-Length` and
`Transfer-Encoding: chunked` -> expect 400, RFC 9110, CWE-444), `layer7_timeouts_bounded` (the gateway's header/body
timeouts read through the adapter, bounded; `Need.GATEWAY`). CORS and path normalization are elsewhere. This is the
heaviest test (a raw socket, and a smuggling probe can desync a gateway): its approach is a decision below.

**6.4 Hard-coded / Exposed Credentials.** Sub-test A `debug_endpoint_no_secret` (BLACK_BOX, a debug path leaks no
secret, empirical) and sub-test B `gateway_config_no_secret` (WHITE_BOX, scan `config_values` for a high-entropy
secret). The review flags it as two tests in one; whether to split (a new test id) is a decision below. CWE-798.

### Decisions for the owner (phase-2 go-ahead)

1. **6.3 smuggling: how, or defer?** The CL+TE probe needs a raw socket (a documented exception to the
   SecurityClient-only rule, as 1.5 used httpx), and a smuggling request can momentarily desync a gateway. Options:
   (a) a native raw-socket probe sending one ambiguous request and reading the status (my recommendation, bounded and
   grounded; the timeouts sub-test reads the gateway config); (b) an external tool (`http2smugl`), a new install; (c)
   defer 6.3 to a later block. Your call.
2. **6.4: one test or split in two?** The review notes it is two tests (a debug-endpoint probe, black box; a config
   secret scan, white box). Splitting gives each its own id and strategy but changes the test ids (6.4 -> 6.4 + a new
   one). My recommendation: **keep one test, two sub-tests** (the guarantee is one: credentials not exposed), unless
   you want the id split. Your call.
3. **6.2 scope** (my internal calls, flagged): drop HSTS (1.5) and Permissions-Policy (not in ASVS 3.4), add CORS,
   no primary CWE (CWE-16 is prohibited). Confirm or correct.
4. **Lab changes for rule 9:** showing a leaked header / a missing security header / a smuggling-vulnerable backend
   needs a documented, reversible gateway change, announced. Confirm, or config/crAPI-only.

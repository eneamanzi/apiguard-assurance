# Group F: guarantees 3.1, 3.3 (working file)

> **Audience:** the owner and me, during the review. Method: the six phases in
> [`test-review.md`](../test-review.md) (How we work).

| Phase | State |
|---|---|
| 1. Collection | done 2026-10-23 (below) |
| 2. Design | done 2026-10-23; owner decisions below |
| 3. Code | done 2026-10-23 |
| 4. Proof | done 2026-10-23 (three labs + an announced Kong change for 3.3) |
| 5. Self-review | done 2026-10-23 |
| 6. Documentation | done 2026-10-23 |

### Results (2026-10-23)

3.1 (`ext.3.1.schemathesis`, Schemathesis, unauthenticated): crAPI **FAIL** (20 operations return 500 on a generated input, e.g. `check-otp`, `reset-password`), Forgejo + APISIX **PASS**. 3.3: **PASS** on all labs (compliant hmac-sha256 policy with a 300 s window), **FAIL** with an announced, reverted Kong change (hmac-sha1 + 600 s). Both rule-9 sides proven. Deferred: deep-injection tools (sqlmap/NoSQLMap/Dalfox/commix), an authenticated Schemathesis run, and verifying ASVS 4.1.5 (WebFetch rate-limited).

Group F is data integrity: 3.1 every input is validated (injection), 3.3 data in transit is protected beyond TLS
(HMAC request signing). (3.2 is merged into 6.1, done.) They share the request body and the signature over it.

### Decided (owner, 2026-10-23)

1. **3.1 uses Schemathesis** (one external tool, a Python library, schema-driven) as `ext.3.1.schemathesis`; the deep
   injection-confirmation tools (sqlmap, NoSQLMap, Dalfox, commix, SSTImap) are deferred follow-ups. Announce the
   install.
2. **3.3 absence of HMAC signing -> NOT_APPLICABLE with a note** (an advanced optional control, a gap to assess); a
   present-but-weak algorithm or unbounded replay -> VIOLATION.
3. Lab changes announced where rule 9 needs them.

## Phase 1: collection (2026-10-23)

### The guarantees

- **3.1** (OWASP API10:2023, CWE-20, ASVS v5.0.0-2.2.1): every input (body, query, path, header) is validated
  against its type, format, range, length and pattern before the business logic. Failures: SQL/NoSQL/command
  injection, type confusion, oversized payloads. Methodology tools (HYBRID): Schemathesis, nuclei, sqlmap, NoSQLMap,
  Dalfox, commix, SSTImap.
- **3.3** (ASVS v5.0.0-4.1.5, NIST SP 800-107): an application-level integrity mechanism beyond TLS (an HMAC request
  signature) with a strong algorithm (SHA-256+) and replay protection (a bounded timestamp window or a nonce).
  "White box, configuration audit"; an advanced, non-standard control, so its **absence is a documented gap to
  assess**, not necessarily a failure.

### What exists and what the gateway exposes

- **3.3 on `main`:** audits the `signing_policies` concept (algorithms vs a forbidden list, the replay window). Review
  defects (Q-29): only the first matching policy audited; the page names Kong's `hmac-auth` plugin; Kong 3.9
  `hmac-auth` defaults include `hmac-sha1`. The concept model gives `algorithms`, `replay_window_seconds`,
  `body_signed`, `required_signed_headers` per policy.
- **3.1:** new. The specification gives each field's type (to send a wrong type); the sensitive-path / payload work is
  ours. The heavy injection tools are not connected.

### Boundaries (rule 10)

- **Oversized payload / size limit** -> 4.4 (done); 3.1 drops it.
- **A stack trace on an error** -> 6.1 (done); 3.1 checks the rejection (a 400), not the error body's content.
- **The signature over the body** -> 3.3; the body's validation -> 3.1.

## Phase 2: design (presented 2026-10-23)

### Compact design

**3.1 Input Validation.** The deep injection confirmation (does a payload actually execute SQL?) is a tool's job
(sqlmap, NoSQLMap, Schemathesis) and is risky on a live backend. A **safe, native, spec-driven** check now, deferring
the heavy suite:

- GREY_BOX (user_a), effect **READ_ONLY** (probes query/path parameters and headers, not write bodies, so nothing is
  created). CWE-20. Sub-tests:
  - `type_rejected`: for a documented operation with a typed query/path parameter, send a value of the wrong type
    (a string where the schema says integer) -> expect a `400`/`422`; a `2xx` means the type is not validated
    (VIOLATION), a `500` means the bad input reached the logic (VIOLATION);
  - `injection_rejected`: send a bounded set of injection markers (SQL `' OR '1'='1`, NoSQL `{"$gt":""}`, command
    `; id`, CRLF `%0d%0aX-Injected: 1`) in query/path parameters and a header -> expect a `400`/rejection; a `500`,
    or a response that **reflects** the marker or an injected header, is a VIOLATION.
- Write-body injection and deep confirmation (sqlmap/NoSQLMap/Schemathesis) are a **deferred follow-up** (they change
  data and need the heavy tools), noted honestly.

**3.3 Request Signing Audit.** WHITE_BOX, `Need.GATEWAY`, READ_ONLY, CWE-347 (or a related). Rewrite of the `main`
test on the new base, reading `signing_policies`:

- audit **every** enabled policy (not just the first);
- `algorithm_strong`: no algorithm weaker than SHA-256 (forbid `hmac-sha1`, `hmac-md5`) -> a weak one is VIOLATION;
- `replay_protected`: a bounded replay window (<= 5 minutes) or a nonce -> unbounded/absent is VIOLATION;
- no signing policy configured -> `NOT_APPLICABLE/NO_SIGNING` with a note (an advanced control; its absence is a gap
  to assess against the threat model, not a hard failure), per the methodology.

### Decisions for the owner (phase-2 go-ahead)

1. **3.1: native-safe now + heavy tools deferred, or connect the tool suite now?** My recommendation: the native,
   spec-driven, READ_ONLY check (type confusion + injection markers on query/path/header), with the deep body
   injection (sqlmap, NoSQLMap, Schemathesis) a deferred follow-up. It is agnostic, safe (no write-body payloads) and
   catches the obvious validation gaps; the deep tools are a large install and change data. Your call.
2. **3.3 absence:** no signing policy -> `NOT_APPLICABLE` with a note (my recommendation, per the methodology: an
   advanced control, absence is a gap to assess), rather than a hard VIOLATION. Confirm.
3. **Lab changes for rule 9:** 3.3's weak-algorithm / unbounded-replay violation needs an announced Kong `hmac-auth`
   change (the lab's dummy is compliant); 3.1's injection violation may appear on crAPI (challenges 12, 13) or need a
   lab change. Confirm announced lab changes where needed.

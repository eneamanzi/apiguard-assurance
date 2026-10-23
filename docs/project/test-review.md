# Test Review (working file)

> **Audience:** project owner, Claude Code · **Status:** working file of step 3 of [`plan.md`](plan.md) (created
> 2026-10-19, reorganised 2026-10-21 for the review of the guarantees). When the step ends its conclusions move to
> the permanent documentation (test pages, roadmap, design decisions, `OPEN_QUESTIONS.md`) and this file and
> `test-review/` are removed (git keeps them).

## Purpose

Review every implemented test and design every missing one, as if starting from a blank page: the current code is
the starting material, not a constraint. The goal is a tool whose verdicts an enterprise user can trust on any API
behind any gateway; the labs (Forgejo + Kong, crAPI + Kong, Forgejo + APISIX) prove it. crAPI is used as a
positive case for **categories** of weakness (BOLA, mass assignment, SSRF, ...): a test is designed on the
category, from what the tool knows of any API (the OpenAPI specification and `config.yaml`); nothing specific to
crAPI enters the code.

## Where we are (updated 2026-10-21)

- **Branch:** `test-review` (from `main` at `4b185f8`, 2026-10-20); `main` keeps the old tool. Baseline of the old
  tool (native tests only) in `outputs/baseline/<lab>/`, not in git.
- **Done:** phase 0, the common part every test rests on (2026-10-19 to 2026-10-21): the rules below, built in the
  code and checked on the labs (history at the end of this file). Committed by the owner.
- **On the branch now:** only test 4.2 (the pilot of the common part); the other tests are on `main` and return one
  at a time, rewritten.
- **Done:** guarantee 0.1 (2026-10-22): `ext.0.1.ffuf` (ffuf searches, the test re-verifies every candidate against the calibration) and `0.1` rewritten (undeclared methods, undocumented versions, gateway route drift). `ext.0.1.nuclei` removed. Both proven on the three labs; a self-review after the first runs fixed two weaknesses (a PASS that claimed more than was verified, a version group of POST paths skipped): [draft](test-review/0-1.md).
- **Done:** group A (2026-10-22): `0.2` (paths without a route), `0.3` (deprecated operations still served) and
  `0.4` (backend reachable without the gateway, new). All six phases through; the three labs give the three
  situations of rule 9 between them; the self-review after the first run removed three false findings:
  [draft](test-review/group-a.md).
- **Done:** group B (2026-10-22): `1.1` (credential required, rewritten), `1.6` (session cookie safety, rewritten)
  and `1.7` (authentication endpoints resist guessing, new). All six phases through; the self-review removed a
  guard that suppressed 24 true cases and a false PASS on repeated attempts: [draft](test-review/group-b.md).
  **Common part:** the engine now obtains the credential of every account a test declares as a need, as it already
  gave the gateway to the tests that declare it (owner, 2026-10-22); `EndpointRecord.auth_declaration`;
  `src/core/path_variants.py`.
- **Done:** group C (2026-10-22): `1.2` (cryptographic validity), `1.3` (expiry) and `1.4` (revocation, rewritten).
  Owner chose native over jwt_tool: the key-based JWT attacks cannot run on a target that exposes no key (ours, and
  the common case), while the key-free ones our Python covers (`src/core/jwt_tokens.py`). crAPI accepts an
  `alg: none` token (challenge 15) and issues a 7-day token; Forgejo's opaque token makes 1.2/1.3 not applicable
  and 1.4 passes. A self-review fixed the anchor (it must refuse a no-credential request, not only serve a
  credentialled one): [draft](test-review/group-c.md).
- **Done:** group D (2026-10-22): `1.5` (credentials over an insecure channel, rewritten) and `ext.1.5.testssl`
  (TLS handshake scan, rewritten). Owner chose one external TLS test (testssl) over two: `ext.1.5.sslyze` is removed
  as an always-on test, the sslyze connector stays as an enable-able alternative. The native test now probes a
  documented API path (not `/`), which fixes a false FAIL on HSTS, and reads the redirect's `Location` scheme. All
  three labs PASS (TLS clean, redirect enforced, HSTS compliant); the three rule-9 situations were proven by tool
  configuration (plain-HTTP target, and a withheld `ca_bundle` for an untrusted chain), so no gateway change was
  needed. ASVS references corrected on the source (3.4.1 HSTS, 12.1.1/12.2.1 TLS): [draft](test-review/group-d.md).
- **Done:** group E (authorization, 2026-10-23): 2.1 (BFLA), 2.4 (version-sibling consistency), 2.2 (BOLA) and 2.5 (object property level). New `privileged_endpoints` derivation rule, `Need.SECOND_USER_ACCOUNT`, and a disposable-owned-object helper reusing `resources:`. Proven on both labs, agnostically: crAPI FAIL (2.1 BFLA, 2.2 BOLA on an order, 2.5 `card_number` exposed), Forgejo enforced. A config-declared disposable `order` resource gives crAPI the owned object (no code specific to a target). [draft](test-review/group-e.md).
- **Done:** group G (resource-consumption limits, 2026-10-23): 4.1 rate limiting, 4.2 timeouts (pilot), 4.3 circuit
  breaker, 4.4 size limits (new). On both gateways; 4.1/4.4 FAIL on the default labs (no rate/size plugin), the
  enforced side proven with an announced, reverted Kong plugin change. [draft](test-review/group-g.md).
- **Done:** group I (2026-10-23): 6.1 (error/info disclosure, new), 6.2 (security headers, rewritten: HSTS to 1.5, CORS added, consistency by sampling), 6.4 (hard-coded credentials, rewritten). crAPI 6.2 FAIL (headers inconsistent across services, caught by sampling); the rest PASS. **6.3 (smuggling) deferred, kept open.** [draft](test-review/group-i.md).
- **Done:** group H (2026-10-23): 5.1 (request logging, a gateway config audit: a logging plugin enabled -> enforced, none -> violation; the log-content checks deferred, they need log access), 5.2 (alerting, SKIP from outside: needs the SIEM's rules and a webhook). 5.1 FAIL on the default labs (no logging plugin), enforced side proven with an announced, reverted Kong http-log plugin. [draft](test-review/group-h.md).
- **Order of the rest** (Claude's choice, owner 2026-10-23): G done, then **I** (6.1-6.4), H (5.1-5.2), F (3.1, 3.3),
  J (7.x) -- reuse-first, the tool-heavy groups last. **Next: group F (3.1, 3.3).**
  `privileged_endpoints` (admin/management segment); 2.1 (BFLA) FAIL on crAPI (user_a reaches the management plane),
  PASS on Forgejo; 2.4 (version-sibling consistency) PASS on crAPI, SKIP on Forgejo (only /api/v1). Self-review:
  destructive privileged ops surfaced not omitted; 2.4 calibrates the version once (242 probes -> 1).
  [draft](test-review/group-e.md). **Next: 2.2 + 2.5** (BOLA, object property level) after the owner's commit.
- **Open, recorded here:** the SSRF listener (7.2), the reference probes on a backend that fails with 5xx (1.1); the
  documentation changes listed below.

## How we work

**Order: by group of guarantees (owner, 2026-10-22).** It replaces the order of 2026-10-21 (first the 15
guarantees of the existing tests, then the 16 missing ones, then the unconnected external tools), which was followed
for guarantee 0.1. The reason for the change, after that first review: the boundary between two tests of the same
domain ("one question, one test", rule 10) can only be decided by designing both, so the old order decided each
boundary twice and reopened the test written first; and one run on the three labs costs almost the same for one test
or for four, because its cost is the fixed part (startup, discovery, authentication).

A **group** is a set of guarantees that share their concepts (reference responses, gateway concepts, roles), the
facts to collect from the labs, and often the external tool. Existing and missing guarantees are mixed: what decides
a group is what its members share, not whether a test for them exists on `main`.

| Group | Guarantees | What they share |
|---|---|---|
| A ok | 0.2, 0.3, 0.4 | the gateway routes, the specification, the code written for 0.1 |
| B ok | 1.1, 1.6, 1.7 | the positive control, credential placement, the authentication endpoints |
| C ok | 1.2, 1.3, 1.4 | the token lifecycle, jwt_tool, the login artefacts |
| D ok | 1.5 | TLS, testssl and sslyze (both already connected) |
| E ok | 2.1, 2.2, 2.4, 2.5 | two roles, own and other users' objects, equivalent paths |
| F | 3.1, 3.3 | the request body and the signature over it |
| G ok | 4.1, 4.2, 4.3, 4.4 | resource limits, the gateway plugin configuration, vegeta |
| H ok | 5.1, 5.2 | the gateway's logs and alerts (5.2 SKIP from outside; content/alert checks deferred) |
| I ok | 6.1, 6.2, 6.4 | what a response lets out: errors, headers, secrets |
| I (6.3) | 6.3 | layer-7 smuggling: split from I, deferred and open (see Deferred follow-ups) |
| J | 7.1, 7.2, 7.3, 7.4 | business flows, the outbound listener, races |

**The six phases of a group.** Always the same, in this order.

| Phase | What it produces |
|---|---|
| 1. Collection | one read-only pass over the three labs gathering the raw facts the whole group needs (routes, specification fields, what each lab answers in the cases at issue), saved in the group's draft |
| 2. Design | `test-review/group-<letter>.md`: the **boundary table** (which question belongs to which test) and, per test, a compact design (declaration, sub-tests, probes, oracle, effects, open points) on the facts of phase 1. Compact, not the finished page: group A's drafts held three full pages that phase 6 rewrote and this file then dropped. **The owner's go-ahead is given here, once for the group** |
| 3. Code | the group's tests written in sequence; reported per test, not per file |
| 4. Proof | one run per lab with all the group's tests |
| 5. Self-review | the results reread against the boundary table; the fixes recorded in the draft |
| 6. Documentation | the test pages (the full template, from the compact design and what the runs showed), `hatch run dev:check`, and the group's own draft left holding the collection and the review; the pages that describe the tool as a whole go to "Documentation changes to apply later" and are rewritten once at the end; then the owner's commit |

Inside a design approved in phase 2 the code is written without a file-by-file go-ahead. Everything else holds: no
commit, no hand-made request that changes a lab without asking first, no new configuration parameter without
stopping.

**Start from the guarantee, not from the test** (owner, 2026-10-21). For each guarantee the question is how best to
verify it: our code alone, an external tool alone, or both, each covering a different part. A native test does not
need an external companion, nor an external test a native one; the tool is not bound to the methodology's list
(`docs/06-knowledge/05-tool-decisions.md`): a better one is searched for and compared. Where a tool is built for the
job (path fuzzing, TLS handshakes, JWT attacks), it is used, not reimplemented: our code adds only what the tool
cannot know (the specification, the calibration, the roles, the derived knowledge). An external tool always runs
inside our test, which launches it and judges its results (the methodology's rule, the rules of piece 10).

**Each review.**

- **Draft:** `test-review/group-<letter>.md` holds the boundary table and, per test, the future page (template
  below) followed by a review box. Each page replaces the one in `docs/05-tests/` only when the code is written and
  verified on the labs. (Guarantee 0.1, reviewed before the groups, has its own `test-review/0-1.md`.)
- **Review box:** the guarantee and its standards (checked on their sources); problems found (code line, lab run);
  research (tools and sources); options and the recommendation; the owner's decision; the changes (code,
  configuration, documentation, labs); done when.
- **Rules:** facts verified against the code, a run or a cited source; proposals marked as such; one group at a
  time; the owner decides and closes questions; the design is presented and agreed before code is written.
- **Done when:** the test is back on the branch, `hatch run dev:check` passes, it gives the expected answer on the
  labs in the three situations (rule 9 below), its page and the files that follow it are updated; then a commit
  (the owner's).
- **Files that follow a test** (besides its page): [`roadmap.md`](roadmap.md), the "Test portability" table of
  [`compatibility.md`](../03-reference/06-compatibility.md#test-portability),
  [`assessment-model.md`](../04-architecture/03-assessment-model.md), the usage guides
  ([`read-the-report.md`](../02-guides/01-usage/03-read-the-report.md),
  [`configure-a-target.md`](../02-guides/01-usage/01-configure-a-target.md),
  [`select-tests.md`](../02-guides/01-usage/02-select-tests.md)), `CHANGELOG.md`; generated by `hatch run dev:gen`: the
  catalogue, the page header, the parameter tables, `config.example.yaml`.

## Rules every test applies

Decided in phase 0 and built in the code (detail and reasons in the history at the end).

| # | Rule | In the code |
|---|---|---|
| 1 | **Two steps of judgement.** A response gets a category from a closed list (12, IANA registry); each test maps categories to an outcome `VIOLATION`, `ENFORCED`, `NOT_VERIFIABLE`, `NOT_APPLICABLE` with a detail (`UPPER_SNAKE_CASE`): that table is its oracle | `src/core/response_category.py`, `src/core/models/enums.py`, `BaseTest._judge` |
| 2 | **Sub-tests and computed status.** A test declares its sub-tests; each judgement belongs to one; the status is computed from the counters (FAIL > PASS complete or partial > INCONCLUSIVE > SKIP), never chosen; a finding exactly with a `VIOLATION` | `TestInfo.sub_tests`, `AssessmentTest._record`, `_finish`, `src/core/models/results.py` |
| 3 | **Reference responses.** A verdict that depends on "does this exist, is this refused" rests on calibration (random siblings by sibling pattern, typed values) and, where a credential exists, a positive control; `response_facts()` gives category and existence; a reference that cannot decide gives `NOT_VERIFIABLE` | `src/core/references.py`, `context.references` |
| 4 | **Transport errors** (timeout, refused, TLS, protocol) are recorded and judged `NOT_VERIFIABLE`, never skipped | `SecurityClientError.record`, `TransportError` |
| 5 | **Derive first, configure on top.** What a test probes comes from the specification (named derivation rules, Phase 2) and the gateway, then the configuration adds or corrects; a rule is added with the test that uses it and proven on the labs; no destructive request on a derived candidate the configuration has not confirmed; sampling by a stated rule, never "the first N" | `src/discovery/derivation.py`, `AttackSurface.derived` |
| 6 | **Evidence and confidence.** Every finding has its proof (`evidence_ref`) and the references it rests on (`supporting_refs`); confidence `CERTAIN`, `FIRM` or `TENTATIVE` by the stated criteria, per detail, on the test page; no severity | `Finding`, `BaseTest._judge` |
| 7 | **Effect.** `READ_ONLY`, `CHANGES_DATA` or `STRESSES_TARGET`, declared; the run order follows it; who creates cleans up or states what is left | `TestInfo.effect`, `src/core/dag.py` |
| 8 | **Standards.** The other standards of the guarantee in `TestInfo.references`, each the standard and its official identifier (ASVS 5.0.0 level L2, WSTG with its version, API Top 10 2023, Top 10:2025, RFC, NIST SP); each verified on its source in the review | `src/core/models/standards.py` |
| 9 | **Three situations on the labs.** A test is trusted once seen giving the right answer where the weakness is there, where it is not, and where the check cannot be made; a case the labs lack: the crAPI case of the category, the tool's configuration, or a change to a lab's gateway configuration written on the page with how to undo it | the page's "Validation" section |
| 10 | **One question, one test.** Data two tests need is written once and shared (path variants, sensitive paths); the gateway's own answer is recognised by the references, not by lists of gateways | topic 7b |
| 11 | **External tools.** The oracle is the tool's check, not its severity (kept as information); only results on the target count, others in a note; the tool's own problems are `NOT_VERIFIABLE`; the tool is pointed at the API; the command shown for manual verification runs | piece 10, `src/external_tests/` |
| 12 | **Needs and strategy.** What a test needs is declared (`TestInfo.needs`), with a minimum strategy per need; the gateway reaches only the tests that declare it; login artefacts kept per role for the tests that read them | `src/core/test_metadata.py`, `context.login_artefact` |

## Page template

Proposed 2026-10-19. Compared with the current pages (sections: what it checks, how it
works, outcomes, oracle states, prerequisites and effects, configuration, coverage against the methodology, why it
exists, limitations) and with how two scanners document a check: Burp (severity and confidence certain / firm /
tentative, issue background, remediation) and ZAP (risk, confidence, solution, references, CWE, payload and
evidence per alert).

Updated with the decisions of topics 1-9 (topic 10, 2026-10-20). The rules common to every test (categories,
outcomes, computed status, complete and partial PASS, confidence criteria, reference responses, ordering by
effect) are written once in `docs/04-architecture/03-assessment-model.md`; a page links to them and states only what is
its own.

| # | Section | Content |
|---|---|---|
| - | Generated header | ID, name, domain, priority and strategy, CWE, standards, tags, needs, parameters, plus the declared effect and sub-tests |
| 1 | Guarantee | what a PASS promises and what it does not; the threat; the OWASP category; the ASVS L2 requirements it checks |
| 2 | Sub-tests and coverage of the methodology | the declared sub-tests (the same names as in the code and the report); each methodology sub-test implemented, partial, or left out with the reason |
| 3 | Inputs | specification fields and derivation rules used (topic 4), configuration keys, gateway concepts, external tools |
| 4 | Preconditions and reference responses | what must hold to give a verdict; which calibration and positive controls the test uses, with which role |
| 5 | Probes | the requests, their number, their order (destructive ones last), sampling rule if any |
| 6 | Oracle | per sub-test, the table category (or tool check) → `OUTCOME/DETAIL` → confidence |
| 7 | Outcomes | only what is the test's own: its SKIP reasons and what makes each sub-test PASS, FAIL or INCONCLUSIVE |
| 8 | Findings | title, content, confidence, `evidence_ref` and `supporting_refs` |
| 9 | Effects on the target | the declared effect (`READ_ONLY`, `CHANGES_DATA`, `STRESSES_TARGET`), what it creates or changes, cleanup, interference |
| 10 | Per gateway | Kong, APISIX, others |
| 11 | Configuration | parameters (what is derived when they are left out) and examples |
| 12 | Validation | per lab: expected status and its basis, in the three situations (weakness there, not there, not verifiable); the change to a lab's gateway configuration a case needs (and how to undo it), the crAPI case of the category |
| 13 | Remediation | what to do on FAIL (gateway, application) |
| 14 | Limitations | what the test cannot detect |
| 15 | Sources | references in the format of `src/core/models/standards.py`, each verified on its source |

## The guarantees

Status: **to review** (a test exists on `main`), **to design** (no test), **in review**, **done** (back on the
branch, proven on the labs). "Methodology" is the classification of `05-tool-decisions.md` (NATIVE, NATIVE +
optional, HYBRID) and its tools: a starting point, revisited in each review.

### Step 1: the guarantees of the existing tests

| # | Guarantee | Tests on `main` | Methodology | Status |
|---|---|---|---|---|
| 1 | **0.1** Every exposed endpoint is documented (Shadow API Discovery) | `ext.0.1.ffuf` (new), `0.1` (rewritten); `ext.0.1.nuclei` removed | ffuf for the search, our code for the specification | done 2026-10-22, proven on the three labs ([draft](test-review/0-1.md)) |
| 2 | **0.2** The gateway rejects unregistered paths (Deny-by-Default) | `0.2` rewritten (Paths Without a Route) | our code; cherrybomb not used | done 2026-10-22, group A ([draft](test-review/group-a.md)) |
| 3 | **0.3** Deprecated APIs are switched off or flagged (Deprecated APIs) | `0.3` rewritten (Deprecated Operations Still Served) | our code; oasdiff not used | done 2026-10-22, group A ([draft](test-review/group-a.md)) |
| 4 | **1.1** Only authenticated requests reach protected resources (Authentication Required) | `1.1` rewritten (Credential Required on Documented Operations) | our code | done 2026-10-22, group B ([draft](test-review/group-b.md)) |
| 5 | **1.4** Revoked credentials are rejected (Token Revocation) | `1.4` rewritten (Credential Revocation) | our code; derived anchor | done 2026-10-22, group C ([draft](test-review/group-c.md)) |
| 6 | **1.5** Credentials never travel on insecure channels (Insecure Credential Transport, TLS) | `1.5` rewritten (Credentials Over an Insecure Channel), `ext.1.5.testssl` rewritten; `ext.1.5.sslyze` removed as an always-on test | HYBRID: native HTTP layer + testssl.sh (one TLS scanner; sslyze connector kept, enable-able) | done 2026-10-22, group D ([draft](test-review/group-d.md)) |
| 7 | **1.6** Sessions are managed securely (Secure Session Management) | `1.6` rewritten (Session Cookie Safety) | our code | done 2026-10-22, group B ([draft](test-review/group-b.md)) |
| 8 | **2.1** Only authorised users reach privileged functions (Function-Level Authorization, BFLA; 2.3 merged) | `2.1` rewritten | our code; derived `privileged_endpoints` | done 2026-10-23, group E ([draft](test-review/group-e.md)) |
| 9 | **3.3** Request signing does not allow replay or weak algorithms (HMAC Config Audit) | `3.3` | NATIVE | to review |
| 10 | **4.1** Rate limiting prevents resource exhaustion (Rate Limiting) | `4.1` rewritten | our code; native burst, limit read from the gateway (vegeta not used) | done 2026-10-23, group G ([draft](test-review/group-g.md)) |
| 11 | **4.2** Timeouts prevent resource lock (Timeout Config Audit) | `4.2` (the pilot) | NATIVE, gateway audit | done 2026-10-23, group G |
| 12 | **4.3** The system degrades gracefully (Circuit Breaker Audit) | `4.3` rewritten | NATIVE, gateway audit (passive health check = Kong's breaker) | done 2026-10-23, group G ([draft](test-review/group-g.md)) |
| 13 | **6.2** Security headers are configured (Security Headers Audit; with CORS) | `6.2` rewritten | NATIVE; sampled across services | done 2026-10-23, group I ([draft](test-review/group-i.md)) |
| 14 | **6.4** Service credentials are not hard-coded or exposed (Hardcoded Credentials Audit) | `6.4` rewritten | NATIVE (debug probe + gateway config scan) | done 2026-10-23, group I ([draft](test-review/group-i.md)) |
| 15 | **7.2** The system prevents SSRF (SSRF Prevention) | `7.2` | HYBRID: nuclei, interactsh | to review |

### Step 2: the missing guarantees

| Guarantee | Methodology | Status |
|---|---|---|
| **0.4** The backend is reachable only through the gateway (new) | our code (`0.4`, new) | done 2026-10-22, group A ([draft](test-review/group-a.md)) |
| **1.2** Credentials are cryptographically valid (forged JWT) | our code (`1.2`, new); jwt_tool not used (keyless target) | done 2026-10-22, group C ([draft](test-review/group-c.md)) |
| **1.3** Expired credentials are rejected | our code (`1.3`, new); jwt_tool not used | done 2026-10-22, group C ([draft](test-review/group-c.md)) |
| **1.7** Authentication endpoints resist brute force and user enumeration (new) | our code (`1.7`, new) | done 2026-10-22, group B ([draft](test-review/group-b.md)) |
| **2.2** Users access only their own objects (BOLA) | our code; disposable owned object via `resources:` | done 2026-10-23, group E ([draft](test-review/group-e.md)) |
| **2.4** Equivalent paths to an operation enforce the same controls (Authorization Consistency, new) | our code; derived `version_siblings` | done 2026-10-23, group E ([draft](test-review/group-e.md)) |
| **2.5** Object property level authorization: excessive data, mass assignment | our code; same owned object | done 2026-10-23, group E ([draft](test-review/group-e.md)) |
| **3.1** Every input is validated (injection) | HYBRID: Schemathesis, nuclei; sqlmap, NoSQLMap, Dalfox, commix, SSTImap | to design |
| **4.4** Requests have size limits (Request Size Limits, new) | our code (empirical 413 + gateway config) | done 2026-10-23, group G ([draft](test-review/group-g.md)) |
| **5.1** Every request is logged with its metadata | NATIVE, gateway config audit | done 2026-10-23, group H ([draft](test-review/group-h.md)) |
| **5.2** Anomalous security events raise alerts | SKIP from outside (needs SIEM/webhook) | done 2026-10-23, group H ([draft](test-review/group-h.md)); behavioural checks deferred |
| **6.1** Errors disclose no internal information | NATIVE (response inspection) | done 2026-10-23, group I ([draft](test-review/group-i.md)) |
| **6.3** The gateway is hardened against layer-7 attacks (smuggling) | raw-socket CL+TE probe (native) or http2smugl | **open**: split from group I, deferred (owner 2026-10-23) |
| **7.1** Sensitive business flows resist automated abuse | NATIVE | to design |
| **7.3** Critical operations are protected from race conditions | HYBRID: vegeta | to design |
| **7.4** External services are consumed safely (webhooks) | HYBRID: interactsh | to design |

### Notes per guarantee (inputs for the reviews)

What is already known, collected from the overview of 2026-10-19 (A-D, in the history), `OPEN_QUESTIONS.md` (Q-24,
Q-29, Q-30, Q-32, Q-50) and the runs of phase 0; each review moves its notes into its draft.

- **0.1:** the wordlist is fixed (37 paths with `/api` prefixes; crAPI's services live under `/identity`,
  `/community`, `/workshop`: the derived `service_prefixes` give them, piece 7); undeclared methods probed on 3
  endpoints only (Q-29) and sent without credentials, writes included (Q-30); no calibration (B1); sensitive paths in
  three places (A3, topic 7b point 3). ext.0.1.nuclei: only `info` on the three labs, `http-missing-security-headers`
  on `/`, a result on `localhost:22` (piece 10). Methodology: ffuf for path brute force (not implemented), katana for
  single-page applications; the owner (2026-10-21): fuzzing is a tool's job, not ours.
- **0.2:** Kong matches a route's path as a string prefix: route `/api` also forwards `/api-docs`, `/api-doc` to
  Forgejo, which answers 404 (seen in the 0.1 runs, 2026-10-21; APISIX `/api/*` matches by segment): a case for
  "the gateway forwards paths it has no route for"; false FAIL on APISIX without its identifier (Q-29, 2026-10-14); `gateway_server_identifiers` and the
  normalization variants leave (topic 7b points 1, 4); the encoded variant almost never sent; only `200` counts.
- **0.3:** reads only `deprecated: true` (SKIP on every lab); crAPI's version siblings (`v2`/`v3` of `check-otp`,
  challenge 3) are a case (topic 4); the "differential" sub-tests move to 2.4; an unparseable `Sunset` counts as
  compliant (Q-29).
- **1.1:** PASS with 14 endpoints answering `503` (Q-29, 2026-10-14; now `NOT_VERIFIABLE`); only `2xx` is a bypass;
  credential always sent as `Bearer` (C5, topic 7d); unauthenticated writes and `DELETE` on `path_seed` (Q-30);
  path normalization variants become its sub-test (topic 7b); count reads and writes in the message (Q-29); resources
  it creates itself instead of `path_seed` (topic 6); crAPI challenge 14 is its case.
- **1.4:** PASS with a credential the target rejects (no positive control, Q-29); any non-`2xx` is PASS; WHITE_BOX or
  GREY_BOX (phase 0b); token after a password change: a crAPI case (Q-32).
- **1.5:** HSTS only on `/`, outside the API (Q-29, piece 10); the redirect checked by status, not by `Location`;
  Kong's redirect drops the port (Q-29); the HTTP probe not recorded (Q-50); `includeSubDomains` (topic 7b point 2).
  testssl: HIGH `cert_revocation` on every lab (private CA); sslyze: TLS 1.0/1.1 only a note (Q-29), the recorded
  command does not run, `timeout_seconds` has no effect (Q-24).
- **1.6:** SKIP on every lab (no session cookies); the login artefacts now give the login's `Set-Cookie` (piece 6);
  Forgejo's web login sets a cookie, its API login does not (topic 9 note).
- **2.1:** a `404` counts as enforced, so a wrong admin path gives PASS (Q-29); admin paths from configuration while
  the specification has them (topic 4); crAPI `/workshop/api/management/users/all` answers `200` to user A (piece 3,
  BFLA); method confusion and role hierarchy missing (Q-32); 2.3 merged in.
- **3.3:** only the first matching plugin audited (Q-29); configuration only (topic 7c); Kong 3.9.0 `hmac-auth`
  defaults include hmac-sha1 (Q-29); the page names Kong's plugin.
- **4.1:** one endpoint, budget fixed by `max_requests`, not derived from the configured limit (Q-29, B7); no
  `evidence_ref` (Q-50); exhausts the rate-limit budget of later tests (Q-30; a `STRESSES_TARGET` test now runs after the others, topic 6); `Retry-After` and a
  request rate (topic 6, deferred).
- **4.2:** the pilot of the common part; its standards (API4:2023, NIST SP 800-204A 4.3, ASVS v5.0.0-16.5.2) to verify
  on their sources.
- **4.3:** Level 2 passes if one upstream has a passive health check (Q-29); Kong has no circuit-breaker plugin,
  passive health checks are its circuit breakers (Q-29); a non-numeric value reported as "Not Found" (Q-29).
- **6.2:** `X-Frame-Options` obsolete for CSP `frame-ancestors`, `Referrer-Policy` and `Cross-Origin-Opener-Policy`
  not checked, `Permissions-Policy` not in ASVS 3.4 (topic 8); HSTS leaves to 1.5; CORS joins (phase 0b); its primary
  `CWE-16` is a prohibited category (topic 8).
- **6.4:** two tests in one (debug paths, gateway configuration secrets); sub-test B scans nothing on Kong DB-less
  (Q-29); `gateway_block_body_fragment` defaults to Kong's message (Q-29, topic 7b point 4).
- **7.2:** judges acceptance (`200`/`201`), not an outbound call (B6, Q-29): a probable false PASS on crAPI
  challenge 11; one aggregate finding (Q-50); `fixed_path` cleans up nothing (Q-30); makes Kong exclude crAPI's
  workshop (Q-30); `ssrf_request_timeout_ms` has no effect (Q-24); the listener (topic 7c, provisional).

### crAPI challenges by category

crAPI v1.1.6 `docs/challenges.md` (https://github.com/OWASP/crAPI/blob/v1.1.6/docs/challenges.md); the lab leaves
out the chatbot (challenges 16-18). Guarantees as revised in phase 0b.

| Challenge | Category | Guarantee | Old tool |
|---|---|---|---|
| 14 endpoint without authentication | unauthenticated access | 1.1 | found (FAIL, 2 findings) |
| 11 SSRF | SSRF | 7.2 | probable false PASS (B6) |
| 7 delete another user's video via an admin endpoint | BFLA | 2.1 (with 2.3) | 2.1 not configured on crAPI (SKIP) |
| 15 forge a JWT | JWT validation | 1.2 | not implemented |
| 1, 2 another user's vehicle, mechanic reports | BOLA | 2.2 | not implemented |
| 8, 9, 10 order and video properties | mass assignment | 2.5 | not implemented |
| 4, 5 other users' data, internal video property | excessive data exposure | 2.5 | not implemented |
| 3 another user's password reset (OTP) | brute force via an older version | 1.7, 2.4 | not implemented |
| 6 layer 7 DoS on "contact mechanic" | business flow abuse | 7.1 | not implemented |
| 12, 13 NoSQL and SQL injection | injection | 3.1 | not implemented |
| (Q-32) token valid after a password change | credential lifecycle | 1.4 | not implemented |

## Deferred follow-ups (after all tests)

Things left for after every test is developed (owner, 2026-10-23): not open questions (the owner does not need to
decide them), just work to pick up at the end. Mostly VIOLATION branches a lab does not exhibit (the detector is
sound, a live case was not produced) and external tools not yet wired.

| Item | Test(s) | Why deferred |
|---|---|---|
| **6.3 smuggling** (a new guarantee): a raw-socket CL+TE probe and the layer-7 timeout audit | 6.3 | split from group I and deferred (owner 2026-10-23) |
| Produce a **live VIOLATION** on a lab (announced gateway change) for the branches proven only by the detector's logic: a leaked header / stack trace (6.1), a debug/config secret (6.4), a version that drops auth (2.4), a bound mass-assignment field (2.5), a gateway with no breaker/health check (4.3) | 6.1, 6.4, 2.4, 2.5, 4.3 | the labs do not exhibit them; a clean injection fought the gateway (Kong strips URL credentials, header-injection fiddly). Detectors are deterministic; 6.2/others prove the reading path |
| **Key-based JWT attacks** (algorithm confusion, expired/forged `exp`): a `jwt_forge.py` helper run only when the operator supplies a signing key or JWKS | 1.2, 1.3 | no target gives key material (NEEDS_KEY_MATERIAL) |
| **Password-change revocation** (crAPI's stateless-JWT challenge, Q-32): a configured OTP/reset flow | 1.4 | target-specific flow (MailHog on the lab) |
| 2.2/2.5 coverage **option (b)**: derive candidate object endpoints (list a collection, take an owned id) instead of only the configured `owned_object_resources` | 2.2, 2.5 | owner chose (a) now; (b) is a later, more automatic coverage |
| Wire the **external tools** not yet connected where a review chose native/deferred: vegeta (4.1, native burst used instead), jwt_tool (1.2/1.3, keyless), sslyze (1.5, testssl used; the connector stays), trufflehog/gitleaks (6.4), http2smugl (6.3), interactsh / an out-of-band listener (7.2/7.4), Schemathesis/nuclei/sqlmap (3.1) | various | connected with the guarantee that needs them, or when a key/listener is available |
| 5.1 **log-content** checks (fields, redaction, real IP, injection) and 5.2 **behavioural alert** checks (brute-force alert, dedup, threshold) | 5.1, 5.2 | need read access to the logs and an alert webhook the tool can observe |

## Documentation changes to apply later

The documentation is being reworked in another conversation (owner, 2026-10-20); this review does not edit it.
What the review decides for the documentation is collected here and applied after that work is done.

| Where | Change | From |
|---|---|---|
| `docs/04-architecture/03-assessment-model.md` | the rules common to every test: categories, outcomes, computed status, complete and partial PASS, confidence criteria, reference responses, ordering by effect | topics 1-6, 10 |
| `docs/04-architecture/02-data-model.md` | `supporting_refs`, outcomes and sub-test counters in the result, derived knowledge on the `AttackSurface`, login artefacts and references in `TestContext`, `TestInfo` effect and sub-tests | topics 3-7 |
| `docs/03-reference/04-report-schema.md`, `05-evidence-format.md`, `03-exit-codes.md` | status `INCONCLUSIVE` (exit `3`), PASS complete or partial, the references and derived-knowledge sections, `ref_...` records (the generated tables are done; the prose around them, the example of a report) | topics 3, 5 |
| `CHANGELOG.md` | every piece of phase 0c, among them the security fix of piece 6 (several `Set-Cookie`: only the first value was redacted) | phase 0c |
| `docs/02-guides/01-usage/03-read-the-report.md` | the "Standards" row of a test and the references of a finding (`references[].text`; `jq` on `standard` and `id`) | piece 8 |
| `docs/02-guides/01-usage/03-read-the-report.md` | how to read a finding's confidence and supporting references, the "Reference Responses" section, a partial PASS, INCONCLUSIVE | pieces 1, 3, 4 |
| `docs/project/roadmap.md` | 6.1 and 7.1 missing from Milestone 2; strategies in its tables differ from the declarations (1.4, 1.5, 1.6, 6.2, ext.1.5.*) | overview D |
| the catalogue of the guarantees (`docs/06-knowledge/04-guarantees.md`, translated to English) | the conclusions of phase 0b, applied **from this conversation** once the English version exists (owner, 2026-10-20) | phase 0b |
| every test page | the new template, when its test is rewritten | phase 1, 2 |
| `docs/02-guides/03-extending/02-add-a-native-test.md`, `03-add-an-external-test.md` | how a test declares effect and sub-tests, records outcomes, uses the references; the example code of the native guide (still `_make_*`, `_log_transaction`, `oracle_state`) and the external guide's "typical oracle"; the generated tables and the sentences next to them are already updated (piece 1) | topics 3, 6, 7 |
| `docs/02-guides/03-extending/01-coding-rules.md` | the top-level except returns `self._error(exc)` (line 55 still names `_make_error`); a `SecurityClientError` of one probe is judged NOT_VERIFIABLE with `exc.record`, not turned into ERROR | pieces 1, 2 |
| `docs/04-architecture/02-data-model.md`, `03-assessment-model.md`, `docs/02-guides/01-usage/03-read-the-report.md` | `oracle_state` replaced by `sub_test`, `category`, `outcome`, `detail` (data model "Extra" row, "Oracle states" paragraph, the `jq` example) | piece 1 |
| `docs/04-architecture/01-overview.md`, `02-data-model.md` | Phase 2 derives knowledge (`src/discovery/derivation.py`, `AttackSurface.derived`), how a rule is added | piece 7 |
| `docs/04-architecture/01-overview.md`, `02-data-model.md`, `03-assessment-model.md`, `docs/02-guides/03-extending/02-add-a-native-test.md` | the reference responses (`src/core/references.py`, `TestContext.references`, sibling patterns, `response_facts()`), how a test asks for them, their cost | piece 3 |
| `docs/04-architecture/01-overview.md`, `02-data-model.md`, `03-assessment-model.md`, `docs/02-guides/03-extending/02-add-a-native-test.md` | the needs fix a minimum strategy (`NEED_MINIMUM_STRATEGY`); the gateway reaches only the tests that declare `Need.GATEWAY` (the `TargetContext` is no longer the same object for every test) | piece 1b |
| `docs/06-knowledge/04-guarantees.md` | sections 0.2 and 0.3 aligned with what is implemented; **0.4 added** as a new guarantee (a backend answers only through the gateway) | group A |
| `docs/06-knowledge/05-tool-decisions.md` | 0.1: nuclei no longer used, ffuf implemented; 0.2: cherrybomb not used (it reads the specification, not the gateway's routes); 0.3: oasdiff not used (it compares two specifications, which the target does not serve, and reports on documents rather than on the running API) | guarantees 0.1, group A |
| `docs/03-reference/06-compatibility.md` | Test portability: 0.2 and 0.3 need only the specification and the target URL; 0.4 needs the gateway's admin plane and reports what the network the run started on allows | group A |
| `docs/project/roadmap.md` | 0.2 and 0.3 rewritten, 0.4 added; `ext.0.1.nuclei` removed and `ext.0.1.ffuf` implemented | guarantees 0.1, group A |
| `CHANGELOG.md` | `SecurityClient.request(origin=...)`, `TestInfo.cwe` optional, `ReferenceResponses.gateway_refusal()`, `random_token()`; the removed parameter `tests.domain_0.test_0_2.gateway_server_identifiers` | group A |
| `OPEN_QUESTIONS.md` | the Q-29 items for 0.2 (the `Server` header check, the fixed list of nonexistent paths) and 0.3 (an unparseable `Sunset` counted as compliant) are answered | group A |
| `docs/06-knowledge/04-guarantees.md` | sections 1.1 and 1.6 aligned with what is implemented (1.6 keeps only the cookie attributes); **1.7 added** as a new guarantee | group B |
| `docs/04-architecture/01-overview.md`, `02-data-model.md`, `03-assessment-model.md`, `docs/02-guides/03-extending/02-add-a-native-test.md` | the engine provides a declared account need (a test no longer calls `acquire_tokens` itself); `EndpointRecord.auth_declaration`; the shared path variants (`src/core/path_variants.py`) | group B |
| `docs/03-reference/06-compatibility.md`, `docs/project/roadmap.md`, `CHANGELOG.md` | 1.1 and 1.6 rewritten, 1.7 added; what each needs from a target | group B |
| `docs/06-knowledge/04-guarantees.md` | 1.2, 1.3, 1.4 aligned; the key-based JWT cases marked as needing key material the target must supply | group C |
| `docs/06-knowledge/05-tool-decisions.md` | jwt_tool not used for 1.2/1.3 on a keyless target (the attacks it adds cannot run without a key); native `jwt_forge.py` stays planned, for when a key is supplied | group C |
| `docs/04-architecture/*` | `src/core/jwt_tokens.py` (read and degrade a JWT) and `src/tests/helpers/anchor.py` (a derived, two-sided anchor) as shared infrastructure | group C |
| `docs/03-reference/06-compatibility.md`, `docs/project/roadmap.md`, `CHANGELOG.md` | 1.4 rewritten, 1.2 and 1.3 added; what each needs (a JWT target; a revocable login) | group C |
| `docs/06-knowledge/04-guarantees.md` | 1.5 aligned: the HTTP redirect/HSTS checks are native, the TLS handshake is testssl; the ASVS references corrected (HSTS 3.4.1, TLS 12.1.1/12.2.1) | group D |
| `docs/06-knowledge/05-tool-decisions.md` | 1.5: one TLS scanner (testssl.sh), not two; sslyze kept as an enable-able connector, not an always-on test; the choice and its reason | group D |
| `docs/04-architecture/03-assessment-model.md` | `SecurityClient.request(origin=...)` used to probe and record the plain-HTTP request (a test may send to another origin) | group D |
| `docs/03-reference/06-compatibility.md`, `docs/project/roadmap.md`, `CHANGELOG.md` | 1.5 rewritten and `ext.1.5.testssl` rewritten; `ext.1.5.sslyze` removed as a test; 1.5 needs only the target URL (and `http_url` for a non-standard HTTP port); the removed parameters `http_probe_enabled`, `expected_redirect_status_codes`, `http_probe_timeout_seconds`, `testssl_timeout_seconds` | group D |
| `OPEN_QUESTIONS.md` | the Q-29 items for 1.5 (HSTS on `/` only, the redirect checked by status not `Location`, the HTTP probe not recorded) and the Q-24 item (sslyze `timeout_seconds`) and Q-50 (1.5 HTTP probe recorded) are answered | group D |
| `docs/06-knowledge/04-guarantees.md` | 2.1 aligned (BFLA, 2.3 merged in); 2.4 added (version-sibling consistency); the privileged endpoints derived, not listed | group E |
| `docs/04-architecture/*` | the derivation rule `privileged_endpoints` as shared knowledge; a test reads the rule name as a string, never imports discovery | group E |
| `docs/03-reference/06-compatibility.md`, `docs/project/roadmap.md`, `CHANGELOG.md` | 2.1 rewritten, 2.4 added; 2.1 needs user_a (admin optional), 2.4 needs only the spec | group E |
| `docs/06-knowledge/04-guarantees.md` | 2.2 added (BOLA), 2.5 added (object property level: excessive data + mass assignment, role filtering folded into the sensitive-field scan); 2.3 merged into 2.1 | group E |
| `docs/04-architecture/02-data-model.md`, `docs/02-guides/03-extending/02-add-a-native-test.md` | `Need.SECOND_USER_ACCOUNT` (user_b); the disposable-owned-object helper (`src/tests/helpers/owned_object.py`) and `create_resource(extra_body=...)`; a test resolves an object's by-id operations from a resource's `values` | group E |
| `docs/03-reference/06-compatibility.md`, `docs/project/roadmap.md`, `CHANGELOG.md` | 2.2 and 2.5 added; both need user_a and `owned_object_resources` (2.2 also user_b); the new `Need` and the new `tests.domain_2.*` parameters | group E |
| `OPEN_QUESTIONS.md` | B3 (a second ordinary account) is answered: `Need.SECOND_USER_ACCOUNT` used by 2.2; crAPI covered by a disposable `order` resource (real BOLA and excessive-data findings) | group E |
| `docs/06-knowledge/04-guarantees.md` | 4.1/4.2/4.3 aligned with what is implemented; **4.4 added** (request size limits) | group G |
| `docs/06-knowledge/05-tool-decisions.md` | 4.1: vegeta not used (a native burst finds the 429 and the spoofing bypass; the limit is read from the gateway) | group G |
| `docs/03-reference/06-compatibility.md`, `docs/project/roadmap.md`, `CHANGELOG.md` | 4.1/4.3 rewritten, 4.4 added; 4.1/4.4 read the gateway limit (optional `Need.GATEWAY`) and send a burst / an oversized body (STRESSES_TARGET); new `tests.domain_4.*` parameters | group G |

## History: how the common part was decided (phase 0, 2026-10-19 to 2026-10-21)

Kept as written at the time (the decisions and their evidence); the rules in force are summarised in "Rules every
test applies" above. Piece 9 and the provisional parts of topics 5 and 9 were later revised: the revision is
written where the decision is.

### Overview of the current tests (2026-10-19)
Read: the 15 native tests, the 2 external test modules, `src/tests/base.py`, `src/core/assessment_test.py`,
`src/core/test_metadata.py`, the helpers and data in `src/tests/`, the gateway concepts. What repeats across tests
or is missing for several of them; each point feeds a phase 0a topic.
#### A. The same thing done in several places
| # | What | Where | Difference |
| A1 | Path normalization variants | 0.2 sub-check 2; 1.1 phase C | 0.2: 4 variants (trailing slash, double slash, uppercase, encoded last segment), `GET`, only `200` is a bypass, one path; 1.1: 3 variants, the declared method, any `2xx`, one anchor |
| A2 | HSTS | 1.5 sub-test 2 (on `/` only); 6.2 sub-tests 1-2 | same parameter `hsts_min_max_age_seconds` in both; a missing `includeSubDomains` is a FAIL finding in 1.5 (`test_1_5:582`) and only a debug log in 6.2 |
| A3 | Debug and actuator paths | 0.1 wordlist (`/api/actuator/env`, `/debug`, `/metrics`, ...); 6.4 sub-test A (`debug_endpoint_paths`); ext.0.1.nuclei (tags `exposure`, `panel`) | three lists of the same kind of path, three oracles |
| A4 | Recognising the gateway's own answer | 0.2 `gateway_server_identifiers` (Server header); 6.4 `gateway_block_body_fragment` (Kong's body by default) | two parameters for one fact; 0.1 and 2.1 judge a `404` without knowing who answered it |
| A5 | The `Server` header | 0.2 (backend identified); 6.2 (version disclosed) | two readings of one header |
| A6 | Status code sets | every test has its own | "active" in 0.1 includes 3xx and 5xx, in 0.3 it does not; "enforced" is 401/403 in 1.1, 403/404 in 2.1 |
| A7 | Choice of the endpoints to probe | 0.1 (first N in spec order), 0.2 (one authenticated non-parametric), 1.1 (first enforced non-parametric), 4.1 (first non-parametric `GET`), 6.2 (first usable `GET` and a sample) | no shared criterion; each choice decides what the verdict covers |
| A8 | Transport errors | 0.1, 0.2, 0.3, 1.1 | logged with structlog only: absent from the transaction log and the result, so coverage lost to them is invisible |
#### B. Capabilities several tests need and nobody provides
| # | Capability | Who needs it | Today |
| B1 | Calibration (how gateway and application answer an unknown path, an unknown method, a missing and an invalid credential) | 0.1, 0.2, 1.1, 2.1, 6.4 | none; false PASS and false FAIL recorded in Q-29 (2.1 PASS on a path crAPI does not have; 0.2 false FAIL on APISIX without its identifier) |
| B2 | Positive control of a credential (a request that must succeed for each role) | 1.4, 2.1, 7.2, the 2.x tests | none; with a credential the target rejects, 1.4 and 2.1 gave PASS (Q-29, 2026-10-14) |
| B3 | A second ordinary account | 2.2 (BOLA), 2.3, 2.4, 7.3 | `ROLE_USER_B` exists (`src/core/context.py:68`), the labs configure it (crAPI: `user_b_username`), no test uses it and no `Need` names it |
| B4 | What the login returns (token, cookies) | 1.6, 1.2, 1.3 | the auth helpers obtain it, no test reads it; 1.6 looks for session cookies with unauthenticated `GET`s and is SKIP on all three labs |
| B5 | Knowledge derived from the specification | 0.1, 0.3, 2.1, 2.2, 3.1, 7.2 | version siblings: the crAPI spec has `/identity/api/auth/v2/check-otp` and `v3`, `v2.7` and `v4.0` of `login-with-token`, none marked `deprecated`, while 0.3 reads only `deprecated: true` (SKIP on all labs); admin endpoints come from configuration in 2.1 (the crAPI spec has `/identity/api/v2/admin/videos/{video_id}` and `/workshop/api/management/users/all`); the URL-accepting endpoint of 7.2 comes from configuration; the 0.1 wordlist is fixed, with `/api` prefixes (crAPI paths start with `/identity`, `/community`, `/workshop`) |
| B6 | An out-of-band listener (a URL the tool controls, to see whether the target calls it) | 7.2, ext.7.2.interactsh, 7.4, blind cases of 3.1 | 7.2 judges acceptance (`200`/`201`), not an outbound request: on crAPI every payload got 503/504 and counted as blocked, on an endpoint that is a documented SSRF (Q-29) |
| B7 | Gateway concepts beyond the current seven (backend timeouts, circuit breakers, health checks, request signing policies, routes, configuration values, live target health) | 4.1 (configured limit), 1.1 (authentication per route), 6.2 (header plugins), 3.1 / 6.3 (validation, size limits), 5.1 (logging), 2.1 (ACL) | the black-box tests cannot be confirmed from the configuration; the 4.1 budget is not derived from the configured limit (Q-29) |
| B8 | Empirical confirmation of a configuration audit | 3.3, 4.2, 4.3 | configuration read only; the methodology's empirical sub-tests (slow backend, replay of a signed request) are not implemented (Q-32) |
| B9 | Response inspection helpers | 6.1, 2.5, user enumeration | `contains_stack_trace`, `contains_sensitive_fields`, `extract_debug_fields`, `check_security_headers`, `auth_errors_are_uniform` (`src/tests/helpers/response_inspector.py`) are used by no test |
#### C. Results, evidence, execution
| # | Point | Today |
|---|---|---|
| C1 | Severity and confidence | `Finding` has no severity by design (`src/core/models/results.py:39`, the analyst judges); the external tests decide FAIL or note from the tool's severity (nuclei critical/high/medium, testssl and sslyze critical/high): two rules; no test states a confidence |
| C2 | Evidence (Q-50) | the audits already pin the concept they read and point their findings to it (`BaseTest._record_gateway_concept`: 3.3, 4.2, 4.3, 6.4 sub-test B), so the Q-50 item on audits may be superseded (to verify); still open: 1.5 HTTP probe (`httpx`, `evidence_ref=None`), 4.1, 7.2 aggregate finding, several `Set-Cookie` |
| C3 | The inconclusive part | 1.1 counts it in its message; no test turns it into a note or a status when it hides part of the surface (Q-29: 1.1 PASS with 14 endpoints answering 503) |
| C4 | Order and interference | sequential, lexicographic by ID (`docs/05-tests/README.md`): the 4.1 burst runs before 6.2, 6.4, 7.2; 7.2 can make Kong exclude crAPI's workshop service (Q-30); no pacing, no rule "disruptive tests last"; `TestContext.set_shared` exists, no test shares data (no `depends_on` declared) |
| C5 | Credential placement | 1.1 sub-check B sends `Authorization: <value>` with `Bearer` values (`test_1_1:845`) whatever placement the run declares (Forgejo: `token` prefix; others: a header or a query parameter); overlaps the future 1.2 |
#### D. Declarations and references (for phase 0b)
- Strategies in the roadmap tables differ from the declarations: roadmap 1.4 GREY_BOX, 1.5, 1.6, 6.2, ext.1.5.*
  WHITE_BOX; `TestInfo`: 1.4 WHITE_BOX, 1.5, 1.6, 6.2, ext.1.5.* BLACK_BOX.
- The roadmap's Milestone 2 lists neither 6.1 nor 7.1, which the methodology has; domain 5 has no test.
- Some ASVS references carry no version (`OWASP-ASVS-V6.3`, `OWASP-ASVS-V8.3.1` next to
  `OWASP-ASVS-v5.0.0-V8.3.1`); ASVS 5.0 renumbered the chapters of 4.x.
- Standards: OWASP API Security Top 10 latest edition 2023 (https://api-security.owasp.org/, checked
  2026-10-19); OWASP Top 10:2025 for web applications (https://owasp.org/Top10/2025/; A10 Mishandling of Exceptional
  Conditions, SSRF folded into A01).
### Phase 0a: topics

In this order; each ends with the owner's decision, written under it.

1. **Calibration and gateway recognition** (A4, A5, B1).
2. **Positive controls** of credentials and objects (B2, B3).
3. **Response classification**: a shared vocabulary of outcomes, inconclusive answers made visible, transport errors
   recorded (A6, A8, C3).
4. **Inputs from the specification versus configuration**: endpoint selection and sampling, knowledge derived from
   the spec (A7, B5).
5. **Findings**: evidence (Q-50), confidence, the severity rule of the external tests (C1, C2).
6. **Effects on the target, order, interference** (Q-30, C4).
7. **Shared capabilities to build and where they live**: normalization, HSTS and debug paths written once (A1-A3),
   login artefacts (B4), out-of-band listener (B6), new gateway concepts and empirical confirmation (B7, B8), the
   unused helpers (B9), credential placement in probes (C5).
8. **Standards and references**: which standards, which versions, the reference format.
9. **Validation on the labs**: secure and vulnerable variants, the crAPI categories, the tests that SKIP on every
   lab (0.3, 1.6) (Q-51).
10. **The page template** above.

#### Topic 1 evidence: calibration and positive control spike (2026-10-20)

A script outside the repository (session scratch, not kept) on the three labs, `GET` only plus the crAPI login,
user_a credential (Forgejo: Basic, no token created). Calibration: two random sibling paths without credential and
one with an invalid credential under every static prefix of the documented paths; fingerprint = status,
content-type, `Server`, body shape (JSON keys, or text with numbers, hex and UUIDs replaced).

| Measure | Forgejo + Kong | crAPI + Kong | Forgejo + APISIX |
|---|---|---|---|
| Calibration points | 128 | 100 | 128 |
| Points where two random probes differ | 0 | 0 | 0 |
| Distinct "unknown path" answers | 8 | 6 | 8 |
| Protected `GET` endpoints | 242 | 14 | 242 |
| No-credential answer identical to an unknown path | 33 | 4 | 33 |
| ... of which the valid credential proves the endpoint exists | 1 | 2 (`/identity/api/v2/vehicle/vehicles`, `/community/api/v2/community/posts/recent`: `401 Invalid Token` as any unknown path) | 1 |
| Positive control failed (valid credential not `2xx`) | 97 (`404` 77, `403` 13, `400` 5, `405` 2) | 4 | 97 |
| Counted ENFORCED by 1.1 today without a working positive control | 35 | 4 | 35 |
| Rejected with a non-standard status (no credential `404`, valid `200`) | 0 | 1 (`/identity/api/v2/user/dashboard`) | 0 |
| `BYPASS` today, confirmed reachable | 78 (public reads, e.g. `/api/v1/licenses`, in a spec with global `security`) | 2 (challenge 14) | 78 |

Found on the way: Kong matches route prefixes, so a random name starting with `api` (`/apiguard-cal-...`) reached
Forgejo through the `/api` route; two of the four "nonexistent" paths of 0.2 (`/apiguard-shadow-probe-789`,
`/api/nonexistent-apiguard-probe-abc-456`) reach the backend on Kong. Calibration names must not share a prefix
with a route. The 0.1 wordlist verdicts do not change on these labs once that is fixed.

#### Topics 1 and 2: decision (owner, 2026-10-20)

**Reference responses (differential oracle).** A response is judged against reference responses the tool
obtains at run time from the target itself, never from a catalogue of applications or gateways:

- **calibration** (no credential needed): random sibling paths under the parent of the path judged, with no
  credential and with an invalid one, tell what "does not exist here" looks like;
- **positive control** (a credential needed): the same request with a valid credential of the right role tells
  whether the endpoint exists and works;
- the calibration points come from the target's own specification (the static prefixes of its paths), each
  calibrated when a test first needs it and kept for the run; two neutral random names per point (no prefix a
  route could match), a point whose two answers differ is not used;
- the positive control prevails: when it succeeds the endpoint exists; when neither reference can decide, the
  verdict is "not verifiable" and is shown, never counted as enforced;
- the role of the positive control is the test's choice: it gives the credential (piece 3, 2026-10-21);
- **recorded and auditable** (owner, 2026-10-20): every reference request is kept as evidence, the run's
  references (point, fingerprint, stable or not) are saved with the outputs, and every verdict that depends on a
  reference points to it; where the mechanism lives in the code and its output format: topics 5 and 7.

Owner note for the 1.1 review: an endpoint declared protected in the specification and public in reality is
reported (bypass or specification error, the same fact); the analyst reading the report decides which.

#### Topic 3: decision (owner, 2026-10-20)

**Two steps of judgement.**

1. **What the response is** (common to every test): one category from a closed list, assigned by shared rules
   and the reference responses (topics 1-2), with whether the positive control proved the endpoint exists (yes,
   no, not done). Built on RFC 9110 §15 and the IANA registry
   (https://www.iana.org/assignments/http-status-codes/http-status-codes.xhtml, read 2026-10-20); an unregistered
   code counts as the x00 of its class (RFC 9110 §15). A reference can correct a misleading status (crAPI dashboard:
   `404` without credential, `200` with one → `UNAUTHENTICATED`, marked non-standard).

   | Category | Codes |
   |---|---|
   | `SERVED` | every 2xx (200-208, 226) |
   | `REDIRECT` | 300, 301, 302, 303, 305, 307, 308 |
   | `UNAUTHENTICATED` | 401, 407, 511 |
   | `FORBIDDEN` | 403 |
   | `NOT_FOUND` | 404, 410 |
   | `METHOD_NOT_ALLOWED` | 405, 501 |
   | `INVALID_REQUEST` | 400, 406, 409, 411-417, 421-426, 428, 431 |
   | `RATE_LIMITED` | 429 |
   | `SERVER_ERROR` | 500, 505-508, 510 |
   | `UPSTREAM_UNAVAILABLE` | 502, 503, 504 |
   | `NO_RESPONSE` | no response: timeout, connection refused, TLS error, connection reset |
   | `OTHER` | rare codes never decisive alone: 1xx, 304, 306, 402, 408, 418, 451 (306 and 418 are "Unused" in the registry) |

2. **What it means for the guarantee** (each test): a small table, category → `OUTCOME/DETAIL`; the table is the
   test's oracle and appears in the "Oracle" section of its page. Outcomes, closed: `VIOLATION`, `ENFORCED`,
   `NOT_VERIFIABLE`, `NOT_APPLICABLE` (SARIF 2.1.0 `kind`: `fail`, `pass`, `open`, `notApplicable`); the detail is
   chosen by the test (e.g. `VIOLATION/AUTH_BYPASS`, `NOT_VERIFIABLE/PATH_NOT_FOUND`).

**Transport errors** are recorded as transactions (request sent, no response, reason) and count as
`NOT_VERIFIABLE`.

**Sub-tests.** Each test declares its sub-tests (short names, the same rows as the "Coverage of the methodology"
section of its page); each outcome belongs to one; the result carries, per sub-test, the four counters (violation,
enforced, not verifiable with the reasons, not applicable) and a status.

**Status.** SKIP when something needed to start is missing; ERROR when the test breaks (sub-tests already done are
kept). Otherwise computed, never chosen by the test:

- sub-test: violation > 0 → FAIL; else enforced > 0 → PASS; else not verifiable > 0 → INCONCLUSIVE; else SKIP
  (nothing to apply to);
- test: a sub-test FAIL → FAIL; else a sub-test PASS → PASS; else a sub-test INCONCLUSIVE → INCONCLUSIVE; else SKIP;
- a PASS is **complete** when nothing applicable stayed unverified, **partial** otherwise (a sub-test INCONCLUSIVE,
  or not verifiable cases inside a PASS); the report shows it next to the status.

`INCONCLUSIVE` is a new status (contract 1.0, report schema); it uses the existing exit code `3` ("at least one
verification did not complete and no test returned FAIL").

#### Topic 4: decision (owner, 2026-10-20)

**Derive first, configure on top.** What a test probes comes first from what the tool can derive, then from the
configuration, which adds, removes or corrects. Precedence, highest first:

1. the configuration, written by the user;
2. facts read from the gateway (routes, through the adapter, when the Admin API is available);
3. facts declared in the specification (`security`, `deprecated`, `format: uri`, request schemas, `example` values);
4. heuristics on the specification (names such as an `admin` segment, version siblings such as `v2` and `v3` of
   the same path), each a named rule.

- Everything derived is listed in the outputs with its rule (e.g. "admin paths: 28, rule: `admin` segment"), next
  to the reference responses (topic 5 decides the format).
- Nothing destructive (`DELETE`, writes) is sent on a derived candidate the configuration has not confirmed.
- A test covers every case it applies to, or a sample chosen by a shared, stated rule (e.g. one per prefix and
  method), written in its coverage; never "the first N of the list".
- Lives in Phase 2 (discovery): the derived knowledge is added to the `AttackSurface` (core models), tests read it
  without importing `discovery/`.
- Each rule is proven on the labs (the crAPI case of its category, Forgejo as the negative); a rule that does not
  hold on them is not adopted.
- Evidence (2026-10-20): Forgejo spec 28 `/admin` paths; crAPI `/identity/api/v2/admin/videos/{video_id}`,
  `/workshop/api/management/users/all`; crAPI `contact_mechanic.mechanic_api` has no URL-like name but an URL
  `example`; 33 Forgejo properties have `url` in the name, almost all response fields (a name rule alone is wrong).
- Cascade, to settle test by test: the `AttackSurface` model and `data-model.md`; parameters that become optional or
  change meaning (each flagged to the owner before it changes); the needs (`TestInfo.needs`) and the "Test
  portability" table; a report section for the derived knowledge; the Ideas item "prepared resources proposed from
  the specification" (roadmap). `path_seed` keyed by name only (Q-29): in the 1.1 review.

#### Topic 5: decision (owner, 2026-10-20)

- **Evidence.** A finding keeps `evidence_ref` (the main transaction) and gains `supporting_refs` (the reference
  responses and positive controls its verdict rests on). Reference requests go to `evidence.json` (IDs `ref_...`);
  the summary of the references and of the derived knowledge (topic 4) is a section of `apiguard_report.json` and of
  the HTML report. The open Q-50 cases follow the rule already decided: 1.5 HTTP probe recorded, 4.1 absence points
  to the last request, 7.2 one finding per payload, every `Set-Cookie` kept. The Q-50 item on configuration audits
  is superseded: 3.3, 4.2, 4.3 and 6.4 sub-test B already pin the concept they read and point their findings to it
  (`BaseTest._record_gateway_concept`).
- **Confidence**, three levels, a column of the oracle table (each detail has its level, written on the test page;
  the test does not choose case by case). The owner asks for levels on solid ground, so each level has an objective
  criterion:
  - `CERTAIN`: the violation is the observed behaviour itself (a header missing, a configuration value read from
    the gateway) or is proven by contrast with a reference of the same request (same content with and without
    credential);
  - `FIRM`: observed directly, but its meaning rests on one stated assumption (0.1: a path that answers unlike an
    unknown one exists, but may be harmless);
  - `TENTATIVE`: rests on a heuristic or an indirect sign (a keyword, a timing, a candidate derived by a heuristic
    rule, topic 4).

  Each level is checked on the labs: a `CERTAIN` finding that turns out false on a lab is a defect of the oracle,
  and the detail is lowered or the oracle fixed. Severity stays out (the analyst's judgement, design decision).
- **External tests** map each tool result to the four outcomes through their own oracle table (threshold on the
  test page); the tool's severity stays in the finding as information (`tool_severity`). **Provisional** (owner):
  to prove with concrete runs of the three tools on the labs (what each tool returns, whether the mapping holds)
  before it is adopted; the runs are planned in phase 0c, with the owner's go (external tools, targeted tests only).
  Proved in piece 10 (2026-10-21): the tool's severity cannot be the oracle; the rules adopted are there.

#### Topic 6: decision (owner, 2026-10-20)

- The worst effect of interference (a false verdict, e.g. 1.1 PASS with 14 endpoints answering `503`) is already
  removed by topic 3: `UPSTREAM_UNAVAILABLE` and `RATE_LIMITED` are `NOT_VERIFIABLE`, the status becomes a partial
  PASS or INCONCLUSIVE with the reason. Interference can lower coverage, not falsify the report.
- Each test declares its **effect**: `READ_ONLY`, `CHANGES_DATA` (creates, modifies, deletes), `STRESSES_TARGET`
  (bursts, payloads that can degrade the target). `GET` is not assumed safe (crAPI `convert_video`,
  `receive_report`).
- The engine runs `READ_ONLY` first, then `CHANGES_DATA`, then `STRESSES_TARGET`; by ID within a group, prerequisites
  respected.
- Cleanup: who creates cleans up, or declares in the report what was left (Q-30; to apply to 7.2 `fixed_path`).
- Not adopted: a health check between tests (the reference responses and the categories already show a degraded
  target). Effects left by a previous run cannot be prevented, only seen and stated.
- Deferred: honouring `Retry-After` or a request rate limit (as nuclei `-rate-limit`, ffuf `-rate`): a new
  parameter, proposed in phase 0c or the 4.1 review. Possible later use of the effect: running only `READ_ONLY` tests
  on a production system.
- To evaluate in the 1.1 review (blank-slate improvement): a test that changes data works on resources it creates
  itself (prepared resources) when the target allows it, instead of the shared `path_seed` resources; this isolates
  tests better than ordering.

#### Topic 7a: where the decided mechanisms live (owner, 2026-10-20)

| Mechanism | Where | Why |
|---|---|---|
| Categories (topic 3, step 1) | a new module in `core/`: response (and references) → category | one rule for every test; `core/` knows no test |
| Outcomes, details, sub-tests, computed status (topic 3) | models in `core/models/results.py`; the base of every test (`core/assessment_test.py`) collects the outcomes and computes counters and status; sub-tests declared in `TestInfo` | no test chooses its status; external tests take the same path |
| Reference responses (topics 1-2) | a class in `core/`, created by the engine with the client and the store, reached through `TestContext` as a typed attribute of its own (not the generic `set_shared` space) | run state that grows (the cache of calibrated points), like the tokens already in `TestContext`; `execute()` keeps its signature |
| Positive control | the mechanics in the reference class; the credential given by the test helpers (`tests/helpers/auth.py`) | `core/` does not know how to log in |
| Evidence of the references (topic 5) | `evidence.json` through the store (`ref_...`); the summary built by the report in Phase 7 | the report reads context and store, not tests |
| Derived knowledge (topic 4) | `discovery/` (Phase 2), named rules; results added to the endpoints of the `AttackSurface` (`core/models/surface.py`) | tests read the `AttackSurface` without importing `discovery/` |
| Effect and order (topic 6) | a field of `TestInfo`; the ordering of Phase 4 (`core/dag.py`) | the order is computed there today |

No new engine phase: calibration happens on demand during Phase 5. Considered and not adopted: the client computing
the category when it receives a response (it would have to know the references and what the test is judging).
The role of the positive control: the test's choice (piece 3).

#### Topic 7b: one question, one test (owner, 2026-10-20)

Rule: one question is answered by one test; data two tests need (variants, path lists) is written once and shared.

1. **Path normalization variants** (today 0.2 sub-check 2 and 1.1 phase C, different variants and oracles): a
   technique, not a guarantee. Generated in one shared place; every test whose control is decided on the path
   applies them to its own probes as a declared sub-test (1.1 authentication, 2.1 admin paths); 0.2 drops them. The
   list is widened with sources in the 1.1 review (Q-32: double encoding, `../`; also `;` in the path, `%2e`).
2. **HSTS** (today 1.5 and 6.2, `includeSubDomains` FAIL in one and a debug log in the other, the same parameter
   twice): checked by 1.5 only, one parameter; 6.2 drops it. In the 1.5 review: whether a missing
   `includeSubDomains` is a violation (RFC 6797, ASVS), and HSTS checked on API responses, not only on `/` (Q-29).
3. **Sensitive paths** (today the 0.1 wordlist, 6.4 `debug_endpoint_paths`, nuclei templates): one catalogue with
   its sources, written as suffixes (`actuator/env`, `.env`, `debug`) combined with the prefixes derived from the
   specification (topic 4), so crAPI gets `/workshop/actuator/env`; 0.1 asks "exists and undocumented", 6.4 asks
   "shows credentials"; nuclei stays the external complement.
4. **Recognising the gateway's answer** (0.2 `gateway_server_identifiers`, 6.4 `gateway_block_body_fragment`):
   given by the reference responses (topic 1); whether the two parameters are removed is decided in the 0.2 and 6.4
   reviews (parameter change, owner's confirmation).
5. **`Server` header** (0.2 backend identification, 6.2 version disclosure): 0.2 no longer needs it (point 4);
   6.2 keeps the version question.

#### Topic 7c: missing capabilities (owner, 2026-10-20)

- **Login artefacts:** the login helper keeps the whole login response per role (all headers, every `Set-Cookie`,
  body, credential) in two places with two jobs: in memory, in a typed place of `TestContext`, for the tests that
  read it (1.6 cookie attributes, SKIP on every lab today; 1.2 JWT validity; 1.3 expiry); and as a pinned
  evidence record (`evidence.json`, secrets redacted as today), so a finding of 1.6, 1.2 or 1.3 can point to the
  login response it judged (topic 5). Considered and not adopted: evidence only (the tests would read redacted
  values) or memory only (no proof in the outputs).
- **Out-of-band listener for SSRF: provisional, to look at later** (owner). A listener built into the tool (as
  ZAP's Callbacks, https://zaproxy.org/blog/2021-08-23-oast-with-owasp-zap/; Burp Collaborator with a local and a
  public address, https://portswigger.net/burp/documentation/desktop/settings/project/collaborator), interactsh as
  the external test already planned; a callback received is `CERTAIN`, none received is `NOT_VERIFIABLE`, never
  `ENFORCED` (egress filtering, unreachable tool). Two new parameters (listen address, address the target uses).
  Not proven on the labs: to verify in the 7.2 review.
- **New gateway concepts** (rate-limit configuration, authentication per route, request validation, logging, ACL,
  CORS, ...): none added in advance; each is added when the test that uses it is reviewed or designed, checked
  against the Kong and APISIX documentation.
- **Empirical confirmation of configuration audits** (3.3, 4.2, 4.3): reading the configuration is the highest
  confidence about the configuration (`CERTAIN`); a behavioural proof is added only where it is possible without
  installing anything on the target's side; decided test by test.

#### Topic 7d: unused helpers, credential placement in probes (2026-10-20)

- **Unused helpers** of `src/tests/helpers/response_inspector.py` (`contains_stack_trace`, `extract_debug_fields`,
  `contains_sensitive_fields`, `auth_errors_are_uniform`, `check_security_headers`): kept, not used as they are;
  each is reviewed (rules, sources, the categories and outcomes of topic 3) when the test that needs it is designed:
  6.1, 2.5, a user-enumeration check (to place in phase 0b); `check_security_headers` against the functions 6.2
  uses, in the 6.2 review.
- **Malformed credentials** (1.1 sends `Authorization: Bearer ...` whatever the run's placement, `test_1_1:845`):
  sent where and as the real credential is sent (`auth_parts`), values chosen by the kind of credential; JWT attacks
  (signature removed, `alg: none`, forged signature) belong to 1.2, not 1.1 (one question, one test).

#### Topic 8: standards and references (owner, 2026-10-20)

| Standard | Version | Role |
|---|---|---|
| CWE (MITRE) | latest | the weakness; one primary per test, only IDs MITRE allows for mapping |
| OWASP API Security Top 10 | 2023 (latest, https://api-security.owasp.org/) | the test's category |
| OWASP ASVS | 5.0.0 | the requirements the oracles come from; **level L2** for every oracle that depends on the level (owner), written on the test page |
| OWASP WSTG | 4.2 (latest stable; 5.0 in development) | test procedures, where they exist |
| RFCs | current | protocol facts |
| NIST SP 800-204, 800-63B-4, 800-52 Rev. 2 | current | supporting (gateway and microservices, authentication, TLS) |
| OWASP Top 10 | 2025 | secondary mapping |

- **One format per standard**, a check that rejects any other. Refined in piece 8 (owner, 2026-10-21): a reference is
  a pair, the standard and the identifier exactly as the standard prescribes it (`CWE-285`, `API5:2023`, `A01:2025`,
  `v5.0.0-3.4.1`, `WSTG-v42-ATHN-01`; RFC and NIST SP, which prescribe no compact form for a section, the number and
  a separate section), shown with the standard's name where the identifier does not say it (`OWASP ASVS
  v5.0.0-3.4.1`), instead of one string with prefixes of our own.
- **Every reference is verified on its source in the review of its test** (owner: in each review, look up the
  test's standards); one that cannot be found is removed. A configurable ASVS level is not adopted now (can be added
  later without rework).
- Found 2026-10-20 (code, 100+ reference strings): many formats for the same standard; ASVS IDs without a version
  (`OWASP-ASVS-V6.3`, `V13.3.1`, `V8.3.1`), probably 4.0 numbering; `CIS-Benchmark-API-GW-Controls-2.3` (0.2) and
  `CIS-API-Gateway-Controls-2.1`: no CIS benchmark for API gateways found; 6.2's primary `CWE-16` is a category whose
  mapping is PROHIBITED (https://cwe.mitre.org/data/definitions/16.html). For the reviews: ASVS 5.0.0 3.4.1 asks HSTS
  on all responses, max-age of at least one year, all subdomains from L2 (1.5); 3.4.6 calls `X-Frame-Options`
  obsolete in favour of CSP `frame-ancestors`, and 3.4.5 `Referrer-Policy`, 3.4.8 `Cross-Origin-Opener-Policy` are
  not checked by 6.2, which requires `Permissions-Policy` that ASVS 3.4 does not list (6.2).

#### Topic 9: validation on the labs (owner, 2026-10-20)

- A test is trusted only once it has been seen giving the right answer in **three situations**: the weakness is
  there (FAIL), it is not (PASS), the check cannot be made (INCONCLUSIVE, where it makes sense, e.g. 2.1 on a path
  the target does not have). Each draft's "Validation" section lists the lab, the expected status and its basis
  (lab design, a known crAPI weakness of the category, or observed).
- Missing cases come, in this order, from: the decisions already taken (version siblings give 0.3 a crAPI case,
  topic 4; the login artefacts may give 1.6 one, 7c); the known crAPI weaknesses by category; **gateway
  configuration variants inside the existing labs** (e.g. Kong with and without rate limiting), never new labs or
  copies of a lab.
- ~~A variant is written as a **difference** from the lab's base gateway configuration and built from it when the
  lab starts.~~ Replaced (owner, 2026-10-21, piece 9): no mechanism. When a test needs a case its labs lack, its
  page ("Validation") writes the exact change to the lab's gateway configuration and the command that loads it,
  and how to undo it (`git checkout` of the file, the same command): one configuration, no copy, nothing to
  maintain. Where the tool's configuration gives the case (a threshold, as for 4.2), that is used. Whether to
  automate the cases is decided in step 4 of `plan.md` (E2E suite, Q-51), with what it then needs.
- The validation tables are the input of step 4 of `plan.md` (E2E suite, Q-51), where automating them is decided.
- Note for the 1.6 review: Forgejo's API login (Basic) sets no session cookie, its web login does; whether that is a
  valid case is decided there.

### Phase 0b: the base

#### Catalogue against OWASP API Security Top 10 2023 (2026-10-20)

| OWASP risk | Guarantees |
|---|---|
| API1 BOLA | 2.2 |
| API2 Broken Authentication | 1.1-1.6, new 1.7 |
| API3 Broken Object Property Level Authorization | 2.5 (with mass assignment) |
| API4 Unrestricted Resource Consumption | 4.1, 4.2, 4.3, new 4.4 |
| API5 Broken Function Level Authorization | 2.1 (with 2.3) |
| API6 Sensitive Business Flows | 7.1 |
| API7 SSRF | 7.2 |
| API8 Security Misconfiguration | 0.2, 6.1-6.4 (CORS in 6.2) |
| API9 Improper Inventory Management | 0.1, 0.3, new 0.4 |
| API10 Unsafe Consumption of APIs | 7.4 |

**Decided (owner, 2026-10-20):**

1. New **1.7** "authentication endpoints resist brute force and user enumeration" (API2; crAPI challenge 3; helper
   `auth_errors_are_uniform`).
2. New **0.4** "the backend is reachable only through the gateway" (CWE-288; the roadmap Ideas item).
3. New **4.4** "requests and responses have size limits" (API4: body size, page size).
4. **CORS** (ASVS 5.0.0 3.4.2, API8): a sub-test of 6.2, not a new guarantee.
5. **2.3 merged into 2.1** (both API5; 2.1 already lists method confusion among its sub-tests).
6. **Mass assignment moves from 2.2 to 2.5**, which becomes "object property level authorization" (read: excessive
   data; write: mass assignment), as API3; crAPI challenges 4, 5, 8, 9, 10.
7. **2.4 redefined:** "when several paths lead to the same operation, all enforce the same controls"
   (authentication, authorization, rate limit). Equivalent paths found with the version-sibling rule of topic 4
   (crAPI `/identity/api/auth/v2/check-otp` without the rate limit of `v3`, challenge 3); a weaker path is a
   violation. The "differential" sub-tests of 0.3 move here; 0.3 keeps "old versions are switched off or flagged".

- Reference errors in the catalogue: 3.1 cites API10:2023 (unsafe consumption, not input validation); 0.2 cites a
  CIS API gateway benchmark that cannot be found; the others are checked in each review (topic 8).
- Out of scope, stated: supply chain (OWASP Top 10:2025 A03), except the version disclosed in headers (6.2) and known
  CVEs found by nuclei. Idea, not planned: controls fail closed when a dependency fails (Top 10:2025 A10).

#### Priorities and strategies (owner, 2026-10-20; revisable in each test's review)

Criterion of `docs/06-knowledge/03-methodology.md` (Priorities): the OWASP Risk Rating factors used by the API
Security Top 10 2023. Official ratings read from the source pages (OWASP/API-Security, editions/2023): API1 easy,
widespread, easy, moderate; API2 easy, common, easy, severe; API3 easy, common, easy, moderate; API4 average,
widespread, easy, severe; API5 easy, common, easy, severe; API6 easy, widespread, average, moderate; API7 easy,
common, easy, moderate; API8 easy, widespread, easy, severe; API9 easy, widespread, average, moderate; API10 easy,
common, average, severe (exploitability, prevalence, detectability, technical impact).

| Guarantee | Before | Now | Why |
|---|---|---|---|
| 2.2 BOLA | P1 | P0 | API1, the top risk (easiest, most widespread, easiest to detect) |
| 2.1 function level (with 2.3) | P2 (2.3 P1) | P1 | API5 severe; needs a valid credential, so not P0 |
| 2.5 object properties (with mass assignment) | P2 | P1 | the write side (mass assignment) changes data a user must not change |
| 3.1 input validation | P2 | P1 | SQL and NoSQL injection, severe impact (crAPI 12, 13; Top 10:2025 A05) |
| 0.4 backend only through the gateway (new) | - | P0 | perimeter control: bypassing it bypasses every gateway control |
| 1.7 brute force and enumeration (new) | - | P1 | API2 severe; partly mitigated by 4.1 (P0) |
| 4.4 size limits (new) | - | P1 | API4, as 4.2 |

Unchanged: P0 0.1, 0.2, 0.3, 1.1, 1.2, 1.3, 4.1, 7.2 (SSRF kept P0: in a cloud it reaches the instance metadata and
its keys); P1 2.4, 4.2, 4.3, 5.1, 6.3; P2 1.4, 1.5, 5.2, 6.1, 6.4, 7.1, 7.3, 7.4 (7.4 kept P2: another control,
the third-party service, stands in front); P3 1.6, 3.3, 6.2.

Strategies (owner's rule: BLACK_BOX external user, GREY_BOX user with credentials, WHITE_BOX internal access): 0.4
WHITE_BOX (backend addresses read from the gateway); 1.7 BLACK_BOX; 1.4 WHITE_BOX today (admin account), GREY_BOX
if user_a revokes its own credential: decided in the 1.4 review.

#### External tools (read 2026-10-20 from the GitHub releases and PyPI)

| Tool | Roadmap version | Latest (date) | Note |
|---|---|---|---|
| nuclei | 3.8.0 | 3.11.1 (2026-08-08) | in use |
| nuclei-templates | 10.4.3 | 10.5.0 (2026-10-05) | in use |
| testssl.sh | 3.2.x | 3.2.4 (2026-07-12) | in use |
| sslyze | 6.3.1 | 6.3.1 (2026-03-29) | in use |
| jwt_tool | 2.3.0 | 2.3.0 (2025-05-01) | last push 2025-05-01: check maintenance before relying on it for 1.2 |
| ffuf | 2.1.0 | 2.3.0 (2026-09-09) | |
| katana | 1.6.1 | 1.8.0 (2026-10-05) | |
| vegeta | 12.13.0 | 12.13.0 (2025-10-31) | |
| interactsh | 1.3.1 | 1.4.1 (2026-09-30) | |
| schemathesis | 4.18.1 | 4.32.2 (2026-10-20) | |

None archived. Updating the pinned versions and whether each tool is still needed: decided when the test that uses
it is designed or reviewed.

### Phase 0c: how the common part is built (2026-10-20)

#### Method

The new version is built on a **new branch** (`test-review`) in the usual folder, not alongside the old code
(owner, 2026-10-20: nothing old carried along; a plain branch preferred to a second folder).

- `main` stays as it is: the old tool. Before the first piece, the old tool is run **once** on each lab from `main`
  and its reports are kept as the baseline; every later check compares the new reports with it
  (`scripts/compare_reports.py`). The old tool does not change, so it does not need to stay open.
- On the branch every file is changed in place, keeping what is useful, with **no backward compatibility**: an old
  function or rule goes as soon as nothing uses it.
- Each test is rewritten **once**, directly on the new base, when it is reviewed (phase 1) or designed (phase 2);
  until then it does not run on the branch (the baseline holds its old results).
- When every test is rewritten and verified on the labs, the branch is merged into `main`; the old version stays only
  in the git history. Abandoning the branch leaves `main` untouched.
- The owner creates the branch (Claude gives the command) after the documentation work is committed, so the branch
  starts from a clean base. Work is committed before switching between `main` and the branch.
- **On the branch, a test not yet rewritten is removed together with its page** (owner, 2026-10-21: `git rm` of the
  15 native test modules, the 2 external test modules and their 17 pages in `docs/05-tests/`; helpers, data,
  connectors and the external-test template kept). A test comes back rewritten, starting from its `main` version
  (`git show main:<path>`), with its page (the draft), its parameters and its "Test portability" row. Meanwhile the
  lab configurations do not load on the branch (they hold the parameters of absent tests, rejected as unknown keys):
  checkpoints use scratch copies with the rewritten tests only.
- **Before the merge into `main`:** the catalogue lists every test again (plus the new ones), the three lab
  configurations load and run as written, and no document points to a page or test that is not there.
- Considered and not adopted: a second folder (`git worktree`): the same branch, but untracked files (`.env`,
  `tools/`, lab certificates) and Claude Code's project memory would have to be copied or linked; the baseline
  reports make it unnecessary.
- Considered and not adopted: files named `*.new.py` (not importable; the tool would find every test twice and stop
  on duplicate IDs; two copies of everything in one codebase); converting every test at once (each test would be
  touched twice, before and during its review, and a change that large cannot be checked step by step);
  building piece by piece in `main` with backward compatibility (old and new together for weeks).

#### Baseline of the old tool (2026-10-20)

Commit 4b185f8 (`main` = `test-review` before any change), native tests only (the lab configurations with
`external_tools.enabled: false` and `output.directory: outputs/baseline/<lab>`), each lab reset before and after.
Reports in `outputs/baseline/<lab>/` (not in git: keep the folder until the merge).

| Test | Forgejo + Kong | Forgejo + APISIX | crAPI + Kong |
|---|---|---|---|
| 0.1 | FAIL 2 | FAIL 2 | FAIL 12 |
| 0.2 | PASS | PASS | PASS |
| 0.3 | SKIP | SKIP | SKIP |
| 1.1 | FAIL 78 | FAIL 78 | FAIL 2 |
| 1.4 | PASS | PASS | SKIP |
| 1.5 | FAIL 1 | FAIL 1 | FAIL 1 |
| 1.6 | SKIP | SKIP | SKIP |
| 2.1 | PASS | PASS | SKIP |
| 3.3 | PASS | PASS | PASS |
| 4.1 | FAIL 2 | FAIL 2 | FAIL 2 |
| 4.2 | PASS | PASS | PASS |
| 4.3 | PASS | PASS | PASS |
| 6.2 | PASS | PASS | FAIL 1 |
| 6.4 | PASS | PASS | PASS |
| 7.2 | FAIL 1 | FAIL 1 | PASS (90 s) |
| Exit | 1, 84 findings | 1, 84 findings | 1, 18 findings |

Numbers are finding counts. To look at in the reviews: crAPI 0.1's 12 findings are all "undeclared HTTP method
accepted" with `401` under `/identity/api` (`GET`/`PUT`/`PATCH`/`DELETE` on `reset-password`, `change-email`,
`verify-email-token`), where crAPI answers `401` to any path, existing or not (topic 1 evidence): false positives
the reference responses remove; crAPI 7.2 PASS is the probable false PASS of Q-29.

#### Order of the common pieces

Each piece rests on the ones before it; for each, the detailed plan (files, contract changes, lab check, done when)
is written when it starts.

| # | Piece | From | Contract change |
|---|---|---|---|
| 1 | Categories, outcomes `OUTCOME/DETAIL`, sub-tests, computed status, complete and partial PASS | topic 3 | status `INCONCLUSIVE` (report schema), sub-test counters in the result |
| 1b | `TestInfo` checks that the declared strategy grants what the needs require (`USER_ACCOUNT` at least `GREY_BOX`; `ADMIN_ACCOUNT`, `GATEWAY`, `REVOCABLE_LOGIN` `WHITE_BOX`; otherwise `TestDefinitionError`); whether the engine gives the gateway only to `WHITE_BOX` tests (6.4 reads it without declaring it) | `plan.md` step 1 ("before any test is touched") | a wrongly declared test stops the start |
| 2 | Transport errors recorded as transactions | topic 3 | a transaction without a response |
| 3 | Reference responses: calibration and positive control, `ref_...` evidence, report section | topics 1, 2, 5 | new report section, new evidence records |
| 4 | `supporting_refs` and confidence in findings | topic 5 | two finding fields |
| 5 | Declared effect and the new test order | topic 6 | order of the results |
| 6 | Login artefacts kept (memory and evidence) | 7c | new evidence records |
| 7 | Derived knowledge: the mechanism only (rules come with the tests that use them) | topic 4 | `AttackSurface` fields, report section |
| 8 | One format for standard references, checked in `dev:check` | topic 8 | reference strings |
| 9 | ~~Lab gateway variants written as differences~~ dropped: the change is written on the test page | topic 9 | none |
| 10 | External tests on the four outcomes: proof runs on the labs, then the mapping | topic 5 (provisional) | none expected |

Every piece is checked with `hatch run dev:check` and on the labs with the tests already rewritten; piece 10 runs
the external tools only with the owner's go.

#### Piece 1: done (2026-10-21)

- Files: `src/core/models/enums.py` (`INCONCLUSIVE`, `Coverage`, `ResponseCategory`, `Outcome`, exit code texts),
  `src/core/response_category.py` (new), `src/core/models/results.py` (`SubTestResult`, `status_from_counts`,
  `combine_sub_tests`, `TestResult.coverage` and `sub_tests`, exit code `3` for INCONCLUSIVE),
  `src/core/models/http.py` (`oracle_state` replaced by `category`, `sub_test`, `outcome`, `detail`),
  `src/core/test_metadata.py` (`sub_tests`, at least one), `src/core/assessment_test.py` (`_record`, `_finish`,
  `_skip`, `_error`; the `_make_*` helpers removed), `src/tests/base.py` (`_judge`, `_step`, `category_of`;
  `_log_transaction` removed), `src/external_tests/base.py` and `_template_ext_test.py`, `src/engine.py` and
  `src/core/dag.py` (fail-fast and `depends_on` with INCONCLUSIVE), `src/cli_console.py`, `src/report/builder.py`,
  `src/report/renderer.py`, `src/report/templates/report.html`, `scripts/compare_reports.py`,
  `scripts/generate_docs.py` (`SubTestResult` in the schema page); the generated tables of the two "add a test"
  guides; the "Status semantics" of `03-reference/04-report-schema.md`.
- Pilot: 4.2 back on the new base (oracle of v0.1.0, three sub-tests), with its `main` page and the oracle sections
  updated. Checked on the three labs (scratch configurations with 4.2 only): PASS complete as in the baseline
  (Forgejo + Kong 6 judgements on 2 backends, Forgejo + APISIX 3 on 1, crAPI 12 on 4); with
  `max_read_timeout_ms: 1`, FAIL with 2 findings on `read_timeout`, exit 1, both findings pointing to the stored
  concept read.
- Not exercised on a lab yet: INCONCLUSIVE and partial PASS (no rewritten test can produce them before the
  reference responses, piece 3); checked on the models (`status_from_counts`, `combine_sub_tests`, the validators)
  with every combination of counters.

#### Piece 1b: done (2026-10-21)

- `src/core/test_metadata.py`: `STRATEGY_RANK` and `NEED_MINIMUM_STRATEGY` (`USER_ACCOUNT` GREY_BOX;
  `ADMIN_ACCOUNT`, `GATEWAY`, `REVOCABLE_LOGIN` WHITE_BOX); a declaration below the minimum of one of its needs
  is rejected (a `TestDefinitionError` at start, naming the test).
- `src/engine.py`: the gateway reaches only the tests that declare `Need.GATEWAY` (the others get the
  `TargetContext` with `gateway` set to none). Chosen over "only `WHITE_BOX` tests" (`plan.md`): what a test
  declares is exactly what it can use. 6.4, which read the gateway without declaring it, is split in its review
  (the part that reads the gateway becomes a test of its own declaring `GATEWAY`).
- Checked: the declaration rule on five cases (three rejected, two accepted, script outside the repository); 4.2
  PASS on the three labs as before. The gateway rule is exercised by the first rewritten test that does not
  declare `GATEWAY`.

#### Piece 2: done (2026-10-21)

- `src/core/models/enums.py`: `TransportError` (`timeout`, `connection_failed`, `tls_error`, `protocol_error`).
- `src/core/models/http.py`: `EvidenceRecord` and `TransactionSummary` have `response_status_code` null and
  `transport_error` set when no response arrived (a record has one or the other, checked).
- `src/core/exceptions.py`: `SecurityClientError.record`, the request as sent without a response.
- `src/core/client.py`: `transport_error_of()` (the reason from the last exception), `_build_failed_record()`
  (request side recorded and redacted as for a response); the record attached to every `SecurityClientError`.
- `src/report/templates/report.html`: "no response (<reason>)" in the status cell of the transaction log and CSV.
- How a test uses it: `except SecurityClientError as exc: self._judge(exc.record, store, <sub-test>,
  Outcome.NOT_VERIFIABLE, "NO_RESPONSE")` (category NO_RESPONSE).
- Checked with the tool's client against real failures (script outside the repository): a closed port of the lab
  host gives `connection_failed`, a non-routable address `timeout` (1 s), the lab with the system trust only
  `tls_error`; each record judged NOT_VERIFIABLE/NO_RESPONSE, the test INCONCLUSIVE ("3 not verifiable"). 4.2
  unchanged on the three labs.

#### Piece 3: done (2026-10-21)

- `src/core/references.py` (new): `ReferenceResponses`, one per run, reached through `TestContext.references`:
  - calibration per (sibling pattern, method, credential label), probed on first use with two random values
    `zqxv<hex>`. The sibling pattern (`sibling_pattern()`): a path with parameters keeps its template with `{*}` in
    place of every parameter (`/api/v1/repos/{*}/{*}`: an object that does not exist, on the same route); a path
    without parameters gets `{*}` as its last segment (`/api/v1/{*}`). Same method as the judged request, no body
    (a limit). A probe rate limited, unanswered or refused by an unavailable upstream, or two probes that differ,
    make the point unreliable; a judged response of those kinds is not compared (`UNRELIABLE`);
  - positive control per (method, path, credential label); the test gives the credential (`Credential`: label,
    headers, query parameters, built by the test helpers), so the role is the test's choice;
  - every request a pinned `ref_NNN` record; `summary()` for the report;
  - `response_facts()`: the category judged and the existence (`PROVEN`, `NOT_PROVEN`, `NOT_CHECKED`) from the
    status and the references; one correction only, `NOT_FOUND` with a working positive control becomes
    `UNAUTHENTICATED` (no credential carried) or `FORBIDDEN` (one carried), marked non-standard (crAPI dashboard);
    existence `PROVEN`, `INDICATED`, `NOT_PROVEN`, `NOT_CHECKED` (self-review below).
- `src/core/context.py`: `attach_references()`, `references`. `src/engine.py`: the references created after the
  TLS preflight, given to the report. `src/report/builder.py`: `ReferencesSummary` in `ReportData.references`;
  `src/report/templates/report.html`: the "Reference Responses" section (patterns, method, credential, reliable,
  status, answer shape, records; positive controls). `scripts/generate_docs.py` and
  `03-reference/04-report-schema.md`: `ReferencesSummary`, `CalibrationPoint`, `Fingerprint`, `PositiveControl`.
- Correction found by the checks: the first design calibrated a parametric path under its parent
  (`/api/v1/repos/<random>`), a different route from `/repos/{owner}/{repo}`: a repository that does not exist
  came out "proven to exist". Replaced by the sibling pattern above.
- Checked (scripts outside the repository, the class itself, the three labs):
  - 32/32 properties of `ReferenceResponses`: every sibling pattern of the specifications reliable (258 Forgejo,
    20 crAPI, GET without credential); the root answered by the gateway itself (Kong's and APISIX's own 404); the
    12 undeclared-method probes of crAPI 0.1 `SAME_AS_UNKNOWN` (the false findings disappear); Forgejo's wordlist
    differs only at `/api/internal` (403) and `/api/swagger` (200), the 2 findings of the baseline; crAPI dashboard
    and vehicles; `/api/v1/user`; nonexistent and real admin paths; GET and DELETE distinct; patterns of different
    depth distinct; the cache sends no request twice; a closed port unreliable; every request `ref_NNN`, pinned;
  - `response_facts()`: 312 combinations (13 statuses, 4 comparisons, 3 controls, 2 credential conditions)
    against the rules written again independently, 0 mismatches, the correction in exactly the 16 expected; 28
    real cases on the three labs as expected (among them a repository with real values `PROVEN`, with random
    values `NOT_PROVEN`, the mixed path `/repos/{owner}/{repo}/issues` both ways, the crAPI bypass of challenge 14
    `SERVED`/`PROVEN`, the crAPI workshop backend's HTML 404 `NOT_PROVEN`, a closed port `NO_RESPONSE`/`NOT_CHECKED`);
  - a report rendered from real crAPI references shows the section, its patterns and records; 4.2 on the three
    labs carries an empty references section.
- Self-review of `response_facts()` (owner: "everything depends on that rule"), 2026-10-21. The dangerous direction
  is a false "exists", which would turn a not verifiable case into a verified one. Two changes:
  - **random values of the declared type**: the sibling pattern carries the type of each parameter from the
    specification (`ParameterInfo.schema_type`, `schema_format`): `{*integer}` (13 digits), `{*uuid}`, `{*}` (a
    string); parameters inside a segment (`v{version}`, `{id}.json`) keep the text around them. Proven needed on
    crAPI: an order that does not exist (`order_id` integer) answers 500; a string sibling answers 404 (the old
    design concluded "exists"); integer siblings answer 500, the conclusion is `NOT_PROVEN`;
  - **two levels of existence**: `PROVEN` (the positive control worked, a direct proof) and `INDICATED` (the answer
    differs from an unknown sibling's, an indirect proof resting on one assumption), so that a verdict states how
    strong its basis is (confidence, piece 4: `CERTAIN` against `FIRM`).
  - Limit, recorded: an API answering 200 with an error page ("soft error") could make a positive control look
    successful; to handle when a real case shows it.
- Re-checked: 312 combinations of `response_facts()` (0 mismatches), 8 pattern shapes (typed values, recovered
  positions), 32 real cases (21 on the two Forgejo labs, 11 on crAPI, among them a nonexistent order, video and
  vehicle with typed siblings), 32/32 properties of `ReferenceResponses`.
- **Effect on the target, found by the checks:** a backend that fails on an identifier it does not know (crAPI
  answers 500 for a missing order) counts the reference probes as failures, and a gateway with passive health
  checks may exclude the service (Kong excluded crAPI's workshop: every later request answered 503, judged
  `UNRELIABLE` by the references, as designed). The reference requests belong to the effect `STRESSES_TARGET`
  when they can hit such endpoints; whether to stop calibrating a backend's patterns after its first 5xx is
  decided in the 1.1 review. The crAPI lab was reset after the check.
- Found: crAPI `/workshop/api/management/users/all` answers 200 to user_a (an ordinary account): broken function
  level authorization, a positive case for 2.1 on crAPI.
- Cost to measure in the 1.1 review: one calibration (two requests) per sibling pattern judged, once per run;
  Forgejo's specification has 258 patterns.
- With the first test that needs it (phase 1): the test helper that builds a `Credential` from the run's
  placement (`tests/helpers/auth.py`, `auth_parts`).

#### Piece 4: done (2026-10-21)

- `src/core/models/enums.py`: `Confidence` (`CERTAIN`, `FIRM`, `TENTATIVE`, the criteria of topic 5).
- `src/core/models/results.py`: `Finding.confidence`, required (no default: a test cannot forget it),
  `Finding.supporting_refs` (the `ref_NNN` records a verdict rests on).
- `src/core/references.py`: `confidence_of(existence)` (PROVEN `CERTAIN`, INDICATED `FIRM`, otherwise `TENTATIVE`)
  and `reference_ids()`. `src/tests/base.py`: `_judge(..., references=...)` copies the references' records into
  the finding's `supporting_refs`.
- 4.2: every finding `CERTAIN` (a value read from the gateway configuration). The external-test template: `FIRM` as
  an example, the level per tool decided in piece 10.
- Report: a confidence badge on each finding card and the supporting references (also in the copied text);
  `Finding` in the generated schema.
- Checked: 4.2 unchanged on the three labs, its findings `CERTAIN` with the lowered threshold; a real crAPI finding
  (order 1 served without a credential, challenge 14) judged through the test base with its references: facts
  `SERVED`/`PROVEN`, confidence `CERTAIN`, `evidence_ref` and `supporting_refs` (`ref_001`, `ref_002` the typed
  siblings, `ref_003` the positive control) all stored in `evidence.json`, shown by the HTML report; a finding
  without confidence rejected.

#### Piece 5: done (2026-10-21)

- `src/core/test_metadata.py`: `Effect` (`READ_ONLY`, `CHANGES_DATA`, `STRESSES_TARGET`) and `EFFECT_RANK`;
  `TestInfo.effect`, required (no default).
- `src/core/dag.py`: one run order instead of levels: among the tests whose prerequisites are done, the lowest
  rank (the engine gives the effect's) first, then the test ID; the sequence is then cut into batches where a test
  depends on one of the current batch (a test's prerequisites are always in earlier batches). Ordering only within
  a topological level was not enough: a `STRESSES_TARGET` test of an early level would still run before an
  unrelated `READ_ONLY` test of a later one.
- `src/engine.py` passes the effect ranks; the effect is carried into `TestResult.effect` and the report row;
  the catalogue and the page header show it; `docs/05-tests/README.md` states the order.
- 4.2 `READ_ONLY`; the external-test template `STRESSES_TARGET` (a scanner).
- Checked (the scheduler itself, script outside the repository): no prerequisites (stress with a low ID, read-only
  with a high one) runs read-only, changes, stress; a read-only test depending on a data-changing one runs after it
  and still before the stress test; a realistic set orders `0.1`, `6.2`, `1.1`, `4.1`, `7.2` (today 4.1 runs before
  6.2 and 7.2); a cycle still stops the start; a declaration without effect is rejected. 4.2 unchanged on the three
  labs, effect `READ_ONLY` in the report.

#### Piece 6: done (2026-10-21)

- `src/core/models/http.py`: `EvidenceRecord.response_set_cookies`, every `Set-Cookie` of a response in order,
  values redacted (names and attributes kept). RFC 6265 forbids folding several `Set-Cookie` into one value; a
  mapping kept only one (the Q-50 item "every `Set-Cookie` in 1.6's evidence").
- `src/core/client.py`: the list filled from `httpx`'s `get_list`; the mapping's `set-cookie` entry rebuilt from
  the redacted list. **Security fix found by the check:** `httpx` folds the cookies into one string and the
  redaction redacted only the first, so the values of the second and later cookies reached `evidence.json` in clear
  (present in v0.1.0; no lab sends two cookies, so it never showed).
- `src/core/context.py`: `LoginArtefact` (role, login resource, the login request and its response; the credential
  is not repeated, it stays the role's token), `TestContext.set_login_artefact()` and `login_artefact()`;
  `src/tests/helpers/auth_login.py` keeps it when it logs in. A finding that rests on it pins the record.
- Checked (scripts outside the repository): a local HTTP server answering three `Set-Cookie` (a real server, not a
  mock): all three kept, values redacted, attributes and `Expires` (with its comma) kept, the mapping redacted cookie
  by cookie; on the three labs, the real engine phases 1-3 and the real login helper for user_a: artefact kept
  (Forgejo `forgejo-token` 201, crAPI `crapi-login` 200), the body in memory carries the credential, the pinned
  record in `evidence.json` with the credential redacted, the real teardown removed the Forgejo tokens (none left).
  No lab answers a login, nor any page, with a session cookie: 1.6 needs a lab variant (topic 9). 4.2 unchanged.
- During the checks Claude created one token by hand on the Forgejo + Kong lab (a `curl` to see whether token
  creation sets cookies) without announcing it; it was deleted at once (none left).

#### Piece 7: done (2026-10-21)

- `src/core/models/surface.py`: `DerivationBasis` (`DECLARED`, `HEURISTIC`), `DerivedFact` (rule, basis, the
  endpoint or the whole API, value, why), `AttackSurface.derived`, `derived_facts(rule)`, `derived_for(method,
  path)`.
- `src/discovery/derivation.py` (new): named rules (`DerivationRule`), `RULES`, `derive_knowledge()` run by the
  engine in Phase 2 after the surface is built; no request to the target. One rule, the first phase 1 needs (0.1):
  `service_prefixes` (HEURISTIC), the static prefixes where the operations live: per first segment, the longest
  common prefix of the paths' directories, cut before a version segment (`v1`, `v2.7`: the version is something to
  explore), and `/` when the prefix is a collection of objects (a documented path or the direct parent of a
  parameter). Every other rule comes with the test that uses it.
- Report: `ReportData.derived` and the "Derived Knowledge" section (rule, basis, endpoint or whole API, value,
  why); `DerivedFact` in the generated schema.
- Checked: on the labs (a real run) Forgejo `/api`, crAPI `/identity/api`, `/community/api`, `/workshop/api`; on
  four spec shapes the labs lack (script outside the repository): resources at the root `/`, version only `/`,
  several services with mixed versions `/auth` and `/billing/api`, a deep service `/company/platform/api`. Two
  corrections found on the way: the first version kept `/community/api/v2` (all its paths are v2) next to
  `/identity/api` (v2 and v3), so the version cut was added; it returned `/users`, `/orders` for an API at the root,
  so a collection prefix counts as the root.

#### Piece 8: done (2026-10-21)

- Research first (owner's question: do the standards prescribe a format?): CWE, the two OWASP Top 10 lists, ASVS
  and WSTG prescribe one; ASVS and WSTG ask documents, reports and tools to always write the version; RFC 7322 names
  an RFC ("RFC 9110") but prescribes no compact form for a section; NIST names its publications (`SP 800-63B-4`),
  not their sections. The sources are listed in `docs/03-reference/04-report-schema.md` ("Reference").
- `src/core/models/standards.py` (new): `Standard` (CWE, OWASP_API_TOP10, OWASP_TOP10, ASVS, WSTG, RFC, NIST_SP),
  `STANDARD_FORMATS` (name, pattern, example, prefix shown, example section), `Reference(standard, id, section)`
  checked on construction with the expected format and an example in the message, `Reference.text` (computed, in
  the JSON), `duplicate_references()`. A standard not in the list (the CIS benchmark of 0.2 and 1.1, which was not
  found) is rejected: it is added when a test needs it and its source is found.
- `TestInfo.references` (the standards of the guarantee besides the primary CWE, which is not repeated);
  `TestInfo.tags` only topics (`TAG_PATTERN`, lowercase words joined by hyphens), so a standard written as a tag
  stops the start. `Finding.references`, `InfoNote.references` and `TestResult.references` are `Reference`s; a
  finding without references of its own cites the test's (`AssessmentTest._record`). `_judge`'s parameter for the
  reference responses renamed `reference_responses`, so "references" means standards only.
- Report: the "Standards" row of each test, `ref.text` on findings and notes, the copied text of a finding; the test
  pages' header gets a "Standards" row; `Reference` and the table of formats generated in the report schema.
- 4.2 and the external template moved to the new form; 4.2's references (`API4:2023`, NIST SP 800-204A section
  4.3, ASVS `v5.0.0-16.5.2`) are verified on their sources in the 4.2 review.
- Checked: 66/66 cases (script outside the repository): 20 valid references of every standard, 29 malformed ones (the
  old forms, missing version, `v4.2` in WSTG, uppercase `V`, a section where the standard takes none, a standard
  not in the list, a misspelt field) rejected with their reason; the JSON round trip (the report is re-read for
  redaction); tags holding a standard, repeated references, the primary CWE repeated; a finding inherits the test's
  references or keeps its own. Test discovery on a package outside the repository stops with `TestDefinitionError`
  naming the module for a malformed reference and for a standard in the tags (the same discovery `dev:check` runs
  to generate the documentation). 4.2: PASS on the three labs, FAIL with the lowered threshold; the report shows the
  three references on the test and on both findings.

#### Piece 9: dropped (2026-10-21)

- Built and then removed: a one-shot service per Kong lab applying a decK patch file (`kong/variants/<name>.yaml`)
  to `kong.yml` at every start, `patch` calls after `apisix/setup.sh`, and a check in `dev:check` (decK applies a
  patch whose selector matches nothing without an error, so the lab silently stays the base). Owner: too much to
  maintain for what it gives; it is not needed now. Kept from it, for step 4 if the cases are automated: decK
  `file patch` (https://developer.konghq.com/deck/file/manipulation/patch/) is Kong's own tool for such
  differences, with that silent no-match; APISIX's Admin API `PATCH` changes only the attributes given and
  answers 404 for a missing object (https://apisix.apache.org/docs/apisix/admin-api/). Nothing of it is left
  in the repository; the running labs were not touched.

#### Piece 10: done (2026-10-21)

The three tools observed on the three labs, with the commands the old tool records (nuclei v3.8.0, testssl.sh 3.2.3,
sslyze 6.3.1): Forgejo + Kong from the run of 2026-10-20 (`outputs/forgejo/tools/`, the only one: the baseline ran
native tests only), crAPI + Kong and Forgejo + APISIX run by hand on 2026-10-21 (owner's go), sslyze on all three;
the labs healthy afterwards. Raw outputs outside the repository.

| Tool | Forgejo + Kong | crAPI + Kong | Forgejo + APISIX |
|---|---|---|---|
| nuclei | 13 `info`: `http-missing-security-headers` x11 on `/`, `swagger-api` (`/api/swagger`), `ssh-sha1-hmac-algo` on `localhost:22` | 11 `info`, all `http-missing-security-headers` on `/` | 12 `info`: the same 11 on `/`, `swagger-api` |
| testssl | HIGH `cert_revocation`, MEDIUM `security_headers`, LOW `HSTS` not offered, `FS_KEMs`, `DNS_CAArecord`, WARN `engine_problem` | the same | the same, plus LOW `FS_TLS12_sig_algs` |
| sslyze (raw: no severity) | TLS 1.2 and 1.3 only, no known vulnerability, chain valid only with the lab CA, no HSTS on `/` | the same | the same |

What a threshold on the tool's severity gets wrong (the old rule: nuclei medium or above, testssl and sslyze high or
above is FAIL):

1. **Results outside the target.** nuclei probed `localhost:22`, the host's SSH, not the API (seen once, on
   2026-10-20). The HTTP results are on `/`, where no route of any lab exists: the gateway's own 404, without the
   security headers its routes add (checked: `/` has no `Strict-Transport-Security` on the three labs, an API path
   has it). The missing HSTS of testssl and sslyze is the same `/`.
2. **Results about the tool.** testssl's WARN `engine_problem` (its OpenSSL lacks an engine) says a check could not be
   made, not that the target is weak.
3. **No severity at all.** sslyze returns facts; the old connector gave them severities of its own (`hsts_missing`
   MEDIUM). The severity of nuclei and testssl is the tool's general judgement, not the guarantee's: testssl's HIGH
   `cert_revocation` (no CRL or OCSP URI) is normal for a private CA and decides FAIL of 1.5 on every lab.
4. **No case of a violation for nuclei**: on the labs it finds only `info`; the positive case of ext.0.1.nuclei is
   found in its review.
5. **The command shown for manual verification must run**: the old sslyze connector records `sslyze --regular ...`,
   an option sslyze 6 no longer has (the tool calls sslyze as a library, so its own scan works).

Rules adopted for every external test (applied when each is rewritten in phase 1; no common code is needed now: the
base already records the four outcomes, `src/external_tests/_template_ext_test.py`):

- **The oracle is the tool's check, not its severity.** Each test maps the identifiers of the tool's checks it uses
  (testssl `id`, nuclei `template-id`, sslyze scan result fields) to an outcome and a detail, in its oracle table;
  a check it does not map is not judged. The tool's severity is kept in the finding as information.
- **Only the target counts.** A result on another host or port, or on a path outside the API (the service prefixes
  derived in Phase 2, piece 7), is not judged; it is listed in a note.
- **The tool's own problems are NOT_VERIFIABLE** (a check the tool could not make, an engine missing, a timeout),
  never a finding.
- **The tool is pointed at the API, not at `/`**, where a test can (nuclei `-u`, the HTTP headers of sslyze); what the
  native tests already check (headers: 6.2, HSTS: 1.5) is not judged twice.
- **The command recorded for manual verification is one that runs** with the installed version.

### Progress of phase 0

| Item | Status | Decision |
|---|---|---|
| Phase 0a topics 1-2 | done (2026-10-20) | reference responses: calibration and positive control (above) |
| Phase 0a topic 3 | done (2026-10-20) | two steps of judgement, outcomes, sub-tests, computed status (above) |
| Phase 0a topic 4 | done (2026-10-20) | derive first, configure on top; precedence; stated sampling (above) |
| Phase 0a topic 5 | done (2026-10-20); external tests proved in piece 10 (2026-10-21) | `supporting_refs`; confidence with criteria; external tests on the four outcomes, to prove on the labs (above) |
| Phase 0a topic 6 | done (2026-10-20) | effect declared (three values), one ordering rule, cleanup (above) |
| Phase 0a topic 7a, 7b | done (2026-10-20) | placement of the mechanisms; one question, one test (above) |
| Phase 0a topic 7c, 7d | done (2026-10-20), listener provisional | login artefacts; concepts when needed; helpers; credential placement (above) |
| Phase 0a topic 8 | done (2026-10-20) | standards with versions, one format, ASVS L2, references verified in each review (above) |
| Phase 0a topic 9 | done (2026-10-20) | three situations per test; variants as differences inside the labs (above) |
| Phase 0a topic 10 | done (2026-10-20) | page template updated with topics 1-9; common rules in `assessment-model.md` (above) |
| Phase 0b | done (2026-10-20) | catalogue against API Top 10 2023 (3 new, 2 merges, 2.4 redefined), tools' versions, priorities (above); the catalogue text is edited after its translation |
| Phase 0c | done (2026-10-21): pieces 1 to 8 and 10, 9 dropped | new branch, baseline reports from `main`, no backward compatibility; 10 pieces in order (above) |

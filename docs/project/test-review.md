# Test-by-test review: how it is done

> **Audience:** project owner, Claude · **Status:** in progress, started 2026-10-27 · **Temporary.** This file tracks
> a pass over the 32 tests. Its conclusions live in each test's page (`docs/05-tests/`), in `CHANGELOG.md` and, for a
> design ruling, in `docs/04-architecture/05-design-decisions.md`. When the pass is over the file is deleted; nothing
> is archived.

The question the pass answers, for one test at a time: **does this test verify what it claims, and does it earn its
place?** A test that does not is removed, not weakened. A test that is finished is finished: it does everything it
says it does, every branch of its oracle has been seen, and its page is true.

## What the pass is made of

Four cross-cutting passes, done once, and then 28 units of per-test work. The cross-cutting ones come first where
every test depends on them.

| Pass | Why it is not per test |
|---|---|
| **A. The shared foundation** | `status_from_counts` and `combine_sub_tests` turn sub-test outcomes into a status: a flaw there is a flaw in every test. Then `AssessmentTest`, the 2,001 lines of `src/tests/helpers/` (`response_inspector`, `resources`, `path_resolver`, the `auth*` family), the HTTP client, and the two gateway adapters. Reviewing this per test means reviewing it 29 times |
| **B. The 79 citations** | The suite declares 107 citations but only 79 distinct ones (OWASP API Top 10, ASVS, WSTG, NIST SP, RFC, CWE). Each is checked once on the source: the identifier exists, it says what we claim, the section is right, and it is the most apt reference and not merely a plausible one. Two tests declare no CWE (`0.3`, `6.2`): decide whether one applies |
| **C. crAPI as external ground truth** | crAPI declares its own vulnerabilities, so the measure is not ours. Build the matrix: declared vulnerability → the test that should catch it → did it? An empty cell is either a real gap in our test or a vulnerability legitimately outside the perimeter, and the pass must say which |
| **D. Suite-level checks** | Inherited from the v0.1.0 audit, where they already paid off: idempotence (byte-equal verdicts on two runs), independence from test order, the live teardown check, the credential scan in the logs and evidence, docstring completeness |

## The per-test checklist

Fourteen checks in four blocks. The last two of block "what it declares" and the whole of block "what it verifies"
are where the trial found its defects.

**What it declares**

1. `TestInfo` against behaviour: `effect`, `needs`, `optional_needs`, `strategy`, `sub_tests`, `priority`. A test
   declared `READ_ONLY` that writes is a broken contract, whatever its oracle does.
2. The citations of this test, from pass B.
3. Semantics of the names: does the sub-test's name promise what the probe actually measures?

**What it verifies**

4. Fidelity to the guarantee: what the methodology asks, what the test does, and whether the page's "left out" row
   is complete and honest.
5. Enumeration of every branch the oracle can emit (the suite has about 175 `outcome`/`detail` pairs, 153 distinct;
   three tests compose theirs at runtime, so they are enumerated by hand).
6. For every branch, the positive side: a case where it **must** fire.
7. For every branch, the negative side: a case where it **must not** fire. Two questions. Can it say `VIOLATION`
   where nothing is wrong (a false alarm)? Can it say `ENFORCED` or PASS where the guarantee is broken (a **false
   assurance**, the worse of the two in a security tool)? Where the signal is ambiguous, is there a control or a
   baseline?
8. Triage of each "left out": why it was not done, whether it can be done now, and whether leaving it out is
   acceptable. The answer goes in the page as a permanent limit, never as a promise.
9. **The adapter and the helpers this test reads through**, not only the test. The trial's worst defect lived in the
   gap between a gateway's filled-in defaults and the concept the adapter built, and no reading of the test alone
   would have found it.

**How it behaves**

10. Failure modes: timeout, 5xx, upstream down, configuration absent or partial, a login that is not 2xx. Each must
    degrade to `NOT_VERIFIABLE` or SKIP, never to a verdict.
11. Determinism: same input, same verdict; no dependence on timing, on execution order, or on a value specific to
    one lab.
12. Effects and teardown, checked live: the teardown undoes what the test created, and is idempotent.

**What it is worth**

13. Evidence: from the `transaction_log` and the findings, can a reader redo the check by hand? Are credentials
    `[REDACTED]`?
14. **The text the user reads**, on every gateway the test supports: the findings and the notes, as the report
    prints them. The trial found a note stating a Kong fact on an APISIX run. A wrong sentence is a wrong result.

## The branch rule

Every branch of every oracle ends in exactly one of three states, and there is no fourth:

1. **observed** in a real run, with the lab and the way the case was produced written in the page's Validation
   section;
2. **unreachable** on that gateway or target, declared with the reason (as `NOT_STATED` is on Kong for test 4.2);
3. **accepted on the detector's logic alone**, declared as such in the page, with why producing it live was not
   worth it.

Producing a case may need an announced change to a lab, undone and verified afterwards, or a harness that is not a
lab change at all: the trial reached `NOT_VERIFIABLE` by reading the real Kong through a filtering proxy, and SKIP by
pointing the admin URL at a closed port.

## Order and grouping

Tests that share machinery are reviewed together, so it is studied once: `0.1` with `ext.0.1.ffuf`, `1.5` with
`ext.1.5.testssl`, `2.2` with `2.5`, `5.1` with `5.2`. That makes 28 units for 32 tests. After the tests of a
domain, one domain-level look: do its tests overlap, do they leave a gap, do two of them report the same thing twice
to the reader (`0.1` and ffuf, `6.1` and `6.2`)?

## Progress

| Unit | State |
|---|---|
| `4.3` | **done** (2026-10-27): 3 defects fixed, 5 branches observed, page and CHANGELOG updated |
| `0.1` + `ext.0.1.ffuf`, `0.2`, `0.3`, `0.4` | to do |
| `1.1`, `1.2`, `1.3`, `1.4`, `1.5` + `ext.1.5.testssl`, `1.6`, `1.7` | to do |
| `2.1`, `2.2` + `2.5`, `2.4` | to do |
| `3.3`, `ext.3.1.schemathesis` | to do |
| `4.1`, `4.2`, `4.4` | to do |
| `5.1` + `5.2` | to do |
| `6.1`, `6.2`, `6.4` | to do |
| `7.1`, `7.2`, `7.3`, `7.4` | to do |
| Pass A, the verdict arithmetic | **done** (2026-10-28): 2 defects fixed (`complete` coverage over a sub-test that verified nothing; `sub_tests` empty against the report schema) |
| Pass A, the two gateway adapters | **done** (2026-10-28): all 7 concepts checked on both adapters against each gateway's own schema, on the 3 labs; 4 defects fixed (the Kong `url` field that does not exist, strings inside arrays skipped by the scanner, the breaker field names, the unstable order of the configuration values) |
| Pass A, the helpers | **done** (2026-10-28): `response_inspector` (5 dead functions and a duplicated data list removed), `resources` (verified live; led to the engine's Phase 6 defect), the `auth*` family (no cross-role leak: verified on a full run, 2.2 uses two distinct credentials and the admin control appears in 6 reference records), `path_resolver` (a dead safety constant removed and the design property corrected), `anchor`, `sampling` and `owned_object` (fully used, nothing found) |
| Pass A, the HTTP client | **done** (2026-10-28): 2 defects fixed (the cookie jar carried between requests; a non-idempotent request retried after a read timeout). Redaction verified by searching the 13 secrets of `.env` in the report, the evidence, the HTML and `config_used.yaml`: 0 in clear. `AssessmentTest` was covered by the verdict-arithmetic step |
| **Pass A is complete** (2026-10-28) | 8 defects fixed: 2 in the verdict arithmetic, 4 in the gateway adapters, 1 in the engine's teardown, 2 in the HTTP client. Four of them produced a wrong result or a false reassurance, two left traces on a target. Dead code: 2 data modules, 11 functions and 9 constants, found by a sweep over all 1,250 module-level symbols; 6 false claims corrected in the documents. Closing battery: the full 32-test assessment matches the documented baseline (15/9/8, 89 findings, exit 1), 0 invariant breaks on the three labs, two consecutive assessments byte-equal on every status, coverage and finding count (audit check 58), 0 secrets in clear, labs left untouched |
| **Pass B (citations) is complete** (2026-10-28) | 140 citations, 105 distinct, each verified on its source, and for ASVS, CWE, the RFCs, the OWASP categories and the NIST sections on the **text** of the source, not its title. One version fixed per standard (ASVS v5.0.0, API Top 10 2023, Top 10 2025, WSTG v4.2, CWE 4.20), pinned in `StandardFormat` so another version is refused when a reference is built; the NIST revision is now part of every identifier. 10 citations named the wrong thing and were replaced. The worst: test 6.4's §5.4, which exists in neither publication it was attributed to; test 7.2's `800-204 §3.2.2`, in a publication that never mentions SSRF; test 2.2's `800-162 §2.2`, which never mentions object attributes while §2.3 does. Settled the same way: `ext.1.5.testssl` moved from API2:2023 to API8:2023 (it carries no credential and judges a TLS stack), and the native 1.5 cites both. Nothing is left open |
| **Pass C (crAPI as ground truth) is complete** (2026-10-29) | The 18 challenges crAPI declares at the commit its images come from, each mapped to what the tool did, measured on a reset lab: 4 caught outright, 1 class caught on another endpoint, 1 endpoint found and deliberately not exploited, 1 attempted without a verdict, 4 missed, 4 out of scope, 3 absent from the deployment. The matrix is in `docs/03-reference/06-compatibility.md`. Two findings: the lab wears out (the order's credit) and `maintainer-commands.md` said no reset was needed; and the four misses share one cause |
| Pass D (suite-level) | to do |

## Open questions, to settle in their own unit

- ~~Deriving candidate objects from the target~~ **settled on 2026-10-29, and it stays out.** The capability was
  designed (a derivation rule pairing a listable collection with its by-id operations, an ownership cross-check
  between the two roles, reads only on an object the tool did not create) and then probed against the three labs
  before being written: it found **no owned object on any of them**, so its measured benefit today is zero against
  about 260 lines, a change to the `NEEDED_TO_RUN` contract and 215 noisy derived facts on Forgejo. The measurement
  is recorded where it belongs, in the limitations of tests 2.2 and 2.5 and in the crAPI matrix of
  `06-compatibility.md`, and it says something worth more than the feature: establishing ownership cannot be made
  target-agnostic.

- **6.1 declares `READ_ONLY` and sends a method that writes.** It picks the shortest documented write operation and
  sends it a malformed JSON body: on the reference lab that is `POST /api/v1/orgs`, an endpoint that creates, and
  the lab answered `403` (the token lacks the scope). The page states "one malformed request (rejected, nothing
  created)", which is a fact about the target, not a property of the tool, while the effects table an operator reads
  before pointing the tool at production says `READ_ONLY` means no state changes. Decide: keep `READ_ONLY` and state
  the dependency plainly, or declare `CHANGES_DATA`.
- **6.1 and 4.4 resolve a write path with the seed.** Both exclude DELETE and send a body built to be refused, but a
  parametric `PUT`/`PATCH` with no seed entry addresses object `"1"` of a real collection. Test 1.1 avoids this with
  `random_sibling_path`. Decide per test whether the probe needs a path that exists (6.1 wants the parser to run,
  4.4 wants the gateway's size limit to apply) or whether a random sibling would do.
- **The evidence does not record the headers that were actually sent.** `EvidenceRecord.request_headers` holds the
  dict the test passed, while `05-evidence-format.md` describes it as the request's headers with "cookie values
  replaced with typed placeholders": the headers the transport adds (`host`, `user-agent`, `accept`, and until
  2026-10-28 `cookie`) are absent, so a reader cannot replay the request exactly from the evidence. Decide: record
  `response.request.headers` (truthful, slightly larger evidence) or narrow the documented description.

- **6.4, a PASS on an empty scan.** `_audit_gateway_config` records `ENFORCED/CONFIG_NO_SECRET` whenever no value
  matched, including when the adapter returned **no values at all**: the verdict then rests on having examined
  nothing. The adapter fixes of 2026-10-28 make an empty answer unlikely (11 to 25 values on the labs), but a
  gateway with no services and no plugins would still pass this way. Proposal: no value read means
  `NOT_VERIFIABLE`, never `ENFORCED`.
- **3.3, how to produce its VIOLATION cheaply.** Both gateways default `hmac-auth` to a list of algorithms that
  includes **`hmac-sha1`** (Kong: `GET /schemas/plugins/hmac-auth`; APISIX: `GET /apisix/admin/plugins/hmac-auth`,
  both read 2026-10-28). A plugin left at its defaults therefore violates `algorithm_strong`, so that branch is one
  announced lab change away, with no new machinery.
- **0.4, the backend address.** Kong's `/upstreams/{name}/health` carries the **resolved IP** of each target in
  `data.addresses[]`, which the adapter drops: the concept keeps only the hostname (`forgejo:3000`). On a target
  where that hostname does not resolve from where the tool runs, 0.4 cannot try the direct access it is built to
  try. Decide in that unit whether the concept should carry the address too.
- **`HealthCounters` is produced and never read.** The APISIX adapter fills it from the Control API; no test reads
  `.counters` (only 0.4 reads `target_health`, for the addresses). Either a test uses it or the field goes.
- **Kong consumers' credentials are never scanned.** `ConfigValueKind.CLIENT_CREDENTIAL` is declared in the model
  and produced by the APISIX adapter (consumer plugin values), never by the Kong adapter: a Kong consumer's
  `key-auth`, `hmac-auth` or `basic-auth` secret is outside what test 6.4 can see, which on a production Kong is
  where the secrets are. The lab has no consumers, so nothing is wrong on the labs. Decide: add the credential
  endpoints to the Kong reader, or state the gap in the test page and in the compatibility table.

- **6.2, the CORS sub-test.** With no `Access-Control-Allow-Origin` on any sampled response the test records
  `NOT_APPLICABLE/NO_CORS`. A response to an arbitrary `Origin` that carries no such header is evidence that the
  origin is not allowed, which is the guarantee `cors_not_wildcard` is named for, so `ENFORCED` looks like the
  honest judgement and `NOT_APPLICABLE` understates it. Found while reviewing the verdict arithmetic (2026-10-28);
  it is why 6.2 now reports PASS `partial` on both Forgejo labs.

## What the trial on 4.3 cost and found

One test of 197 lines, whose page was marked verified four days earlier: three defects fixed and five branches
produced. The false pass on Kong (an `active` health-check record that exists with zero intervals read as a
configured check) made the `VIOLATION` branch unreachable, which is why no lab had ever produced it. The lesson that
changed this checklist: read the adapter, read the note text, and run every gateway the test supports, not one.

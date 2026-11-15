# Paper plan (working file)

> Working file for the research paper drawn from APIGuard Assurance. It holds the decisions taken, the outline and
> the work still to do. It will be moved or removed when the paper is written; nothing here is documentation of
> the tool. Every fact the paper states is checked against the code (the code decides what the tool does), then
> against the documentation, never written from memory.

## Decisions (owner)

| Date | Decision |
|---|---|
| 2026-11-13 | No venue chosen yet: write everything, cut later. |
| 2026-11-13 | The earlier article is kept aside, to avoid biasing this one; it is used at the end to check what is new. |
| 2026-11-13 | Three contributions; the first two on the same level (below). |
| 2026-11-13 | Integrating external tools is an implementation feature, not a goal of the paper. |
| 2026-11-13 | The knowledge and privilege gradient defines what a test requires (the least access the tester needs), not where the oracle takes its truth. |
| 2026-11-14 | No single running example: each concept is illustrated with a short example from a different test, so no test is privileged. |
| 2026-11-14 | No table of every test's oracle in the oracles section: the section explains the common mechanisms. |
| 2026-11-14 | Related work goes in section 2, with the background. |
| 2026-11-14 | A short card per test is written first; the pattern of the card is fixed when the first ones are written. |
| 2026-11-14 | "Where each guarantee is enforced" (gateway, backend, both) is worth having, but is decided together: Claude proposes each one with the sentence of the code or documentation that supports it, the owner decides. |
| 2026-11-15 | E1 reports the final validated state only: what validation finds is fixed until every produced branch gives the expected verdict; the paper does not recount the defects. |

## The message and the contributions

The message: we verify the security of the boundary formed by an API and the gateway that exposes it, on the running
system, through a catalogue of guarantees and an explicit oracle for each check.

1. **The API-gateway boundary and its guarantees.** The security of that boundary, verified on the running system.
   The catalogue covers both sides, API and gateway.
2. **The oracles.** How each guarantee is judged: every test has its own oracle and its source of truth; reference
   responses calibrate the judgement on what the target itself answers; a verdict says when it cannot decide.
3. **Implementation and validation.** The tool, target-agnostic and gateway-agnostic, and the experiments that show
   the oracles judge correctly and that the method works on different targets.

## How the catalogue was built (owner, 2026-11-14)

There was no formal procedure. The guarantees were collected from the known weaknesses, vulnerabilities and
guarantees of APIs and gateways, aligned with the NIST API guidelines (SP 800-204 series, SP 800-228) and the OWASP
API Security Top 10, then classified in domains; new guarantees can always be added. To write in section 3, and to
support with the mapping of the guarantees to the standards (work list).

## Outline

### 1. Introduction
- Context: APIs exposed through a gateway.
- The problem: research on API testing tests the application, standards say what to protect but not how to verify
  it, and a response seen through a gateway may be the gateway's and not the backend's. **To be confirmed** by the
  systematic literature search and a full reading of NIST SP 800-228 before it is written as a fact.
- The three contributions, the structure of the paper.

### 2. Background and related work
- 2.1 From the cloud to the boundary: systems move to microservices, which expose and exchange their functions
  through APIs, centralised and managed behind a gateway; the boundary forms there, and its security depends on both
  sides. Source: `docs/06-knowledge/01-state-of-the-art.md` section 1.
- 2.2 The standards: the ones the tests cite, read from the code (`TestInfo.references`, each verified on its
  source, rule 8).
- 2.3 Related work: API testing and fuzzing, security oracles, the oracle problem and oracle assessment, static
  architectural rules, test-based certification, industry tools (list below).

### 3. Methodology: the boundary and its guarantees (contribution 1)
What we want verified; the how is in section 4.
- 3.1 The model of the boundary (figure): tester, TLS, gateway (routes, policies per route), backend, administration
  plane; what each strategy can observe.
- 3.2 What a guarantee is and its parts (references, concept, failure scenarios, prerequisites, test logic), and how
  the catalogue was built (above).
- 3.3 The catalogue: a compact table in the body, one row per guarantee (ID, sentence, priority, strategy, test or
  not); the full detail in an appendix or in the published repository.
- 3.4 The columns explained: the gradient (what the tester must have), the priority, the standards. All read from
  the code.
- 3.5 The guarantees without a test (2.3, 5.2, 6.3): kept, declared as not implemented, with the reason their entry
  gives. Leaving them out is the owner's choice.
- Short card per test (pattern to fix).

### 4. The oracles (contribution 2)
- 4.1 Oracle and source of truth: what the observation is compared with (the specification for 1.1, the
  methodology's thresholds applied to the gateway configuration for 4.2, the transport-security requirements for
  1.5). A methodological concept, made concrete by the tests' criteria.
- 4.2 The judgement: every test records an outcome from one set (violation, enforced, not verifiable, not
  applicable) with a detail; the 22 native tests that judge HTTP responses first give the response a category; the
  other 6 judge a token (1.3), cookies (1.6) or the gateway configuration (3.3, 4.2, 4.3, 5.1). Source:
  `src/core/response_category.py`, `src/core/assessment_test.py`.
- 4.3 Reference responses (a strong point): calibration (what "nothing exists here" looks like), positive control
  (the same request works with a valid credential), the gateway's own refusal (what the gateway answers when no route
  matches). Source: `src/core/references.py`, rule 3.
- 4.4 Verdicts: computed from the sub-tests, never chosen; PASS complete or partial; confidence; the evidence of each
  finding. Source: `src/core/models/results.py` (`combine_sub_tests`), rules 2 and 6.
- 4.5 Oracles on the configuration: neutral concepts the adapters translate for each gateway; a value the
  configuration does not set is judged at the gateway's default, which the adapter states. Source:
  `src/core/gateway/concepts.py`, design decision D7.
- 4.6 Oracles of external tools: the tool's own judgement decides, translated into the same outcomes (rule 11).
- Each mechanism illustrated by a short example from a different test.

### 5. Implementation (contribution 3, first part)
- The sources: the OpenAPI specification and the configuration (opening point; it links to the oracles).
- Target-agnostic: no path or behaviour of an application in the code.
- The pipeline (the seven phases of a run) and the modules, with a figure. Source: `docs/04-architecture/01-overview.md`.
- Gateway adapters: the gateway as an abstract concept.
- Safety towards the target, as a design choice for real systems (declared effects, no destructive request on a
  derived endpoint); its cost goes in section 7.
- Selection by needs, secret redaction, TLS per connection.
- Outputs: structured report, `evidence.json`, `config_used.yaml`, exit codes: reproducibility, CI/CD, automatic
  analysis.
- Extensibility, briefly.

### 6. Experiments and results (contribution 3, second part)
The goal is not to say whether a target is secure, but to show that the method can be implemented, that it verifies
the boundary and that the oracles judge correctly: always expected against obtained.
- 6.1 Setup: the three labs and why they are built that way.
- E1 The oracles judge correctly: correct and deliberately broken configurations, expected verdict against obtained,
  oracle case by oracle case (see the branch inventory in the work list).
- E2 Portability: the same tests on the three labs with no code change; per test and lab, the outcome or the SKIP
  with its reason.
- E3 A target with known weaknesses: crAPI publishes its 18 challenges (expected values written by others); how many
  of those in scope are found, and false positives (the finding classification in `LAB_FINDINGS.md` reports none).
  Optional: EvoMaster's published results on crAPI, with the caveat that the conditions differ.
- 6.5 Threats to validity: the labs are ours, one person validated, some tools are random, the crAPI lab wears out.

### 7. Limits and lessons
- Ownership of an object cannot be established without knowing the target (measured on the three labs), hence a
  configured object for 2.2 and 2.5, and four crAPI challenges missed.
- Safety towards the target against coverage: some things are named and not verified (crAPI challenge 7).
- Specialist tools explore more objects; the catalogue covers more guarantees; integration joins the two.

### 8. Conclusions and future work

### Abstract: written last.

## Figures and tables
1. The model of the boundary (section 3).
2. The path of a judgement: response, category, references, outcome, verdict (section 4).
3. The pipeline (section 5).
4. The compact catalogue.
5. The mapping to the standards.
6. Results of E1, E2, E3.

## Work list
- [x] `docs/06-knowledge/03-guarantees.md`: 29 guarantees with a test (5.2 added), CIS reference removed (2026-11-14).
- [x] `docs/06-knowledge/02-methodology.md`: the strategy is the least access a test needs, not a limit on what it
      uses (`src/core/test_metadata.py`, `NEED_MINIMUM_STRATEGY`) (2026-11-14).
- [x] `CHANGELOG.md`: entry for the two corrections above, under Fixed (2026-11-14).
- [ ] Branch inventory for E1: per test, the cases of its oracle table (section 6 of its page) against what its
      Validation section (12) shows seen on a lab. 11 of the 28 native pages already list it
      ("What each branch has been seen doing": 0.1-0.4, 1.1-1.4, 1.6, 1.7, 4.2); the other 17 need it derived from
      their validation tables. Decided 2026-11-14: the result goes into each test page (the same paragraph the 11
      pages have, facts from its Validation section only), one page at a time; this file keeps only the tally.
      Done for the 17 pages (2026-11-14): every native page now has the paragraph. Ambiguous items are marked
      "To re-verify" in the page with their reason (owner, 2026-11-14), never resolved by inference.
      Tally of the 17 pages (named items; a group such as "the transport reasons" counts as one): 62 proven on a
      lab, 10 seen only off the labs (scratch server, stand-in Admin API, proxy), 82 still unproven, 7 to re-verify:
      1.5 `NO_TLS`, 2.4 `SIBLING_REFUSED`, 3.3 `WEAK_ALGORITHM`, 4.1 `UPSTREAM_UNAVAILABLE` and
      `NO_LIMIT_TO_BYPASS`, 6.4 the `NOT_APPLICABLE` case, 7.2 which `SSRF_BLOCKED_*` details.
- [x] Branch inventory of the 11 pages that already had the paragraph and of the 3 external test pages
      (2026-11-14): checked against their own sections 6 and 12 and, where they disagree, against the code; missing
      branches named, ambiguous ones marked "To re-verify". Tally of these 14 pages: 76 proven on a lab, 3 seen only
      off the labs, 78 still unproven, 9 to re-verify: 0.1 `NO_PATH_IN_GROUP`; 0.4 `BACKEND_UNREACHABLE` and
      `ADDRESS_ANSWERS_DIRECTLY`; 1.1 `NO_SECURITY_DECLARED`; 1.2 `ACCEPTED_TAMPERED` and `ACCEPTED_STRIPPED`;
      1.7 `EXISTENCE_DISCLOSED_BY_TIMING` (section 6 and the code disagree); ffuf `TOOL_CALIBRATION_FAILED`;
      Schemathesis `UPSTREAM_UNAVAILABLE`.
      **All 31 test pages**: 138 proven on a lab, 13 seen only off the labs, 160 still unproven, 16 to re-verify.
- [x] The 16 items to re-verify, verified on the labs (2026-11-14, targeted runs, configurations in the scratchpad,
      every lab change undone with `git checkout` and the lab checked back): 15 resolved and written in their
      pages (13 seen with the current code; 0.1 `NO_PATH_IN_GROUP` unreachable by construction; 6.4's
      not-applicable case no longer in the code). Also seen in the same runs: 2.4 `SIBLING_REFUSED`,
      `VERSION_DROPS_AUTH`, `DOCUMENTED_NOT_PROTECTED`; 0.4 `BACKEND_UNREACHABLE` with the current code; and, with
      the `forgejo` container stopped, the "backend unavailable" branches of 0.1, 0.2, 1.1, 2.4, 4.1, 6.2, 6.4 and
      Schemathesis. The crAPI lab was reset first (it was stopped).
- [x] The six behaviours below, fixed on 2026-11-15 (owner's go-ahead; 1.7: the code's two channels kept, the
      page and the spurious enforced records corrected), each produced again on a lab, regression on the three
      labs unchanged; CHANGELOG under Fixed:
  1. 1.7: section 6 says `EXISTENCE_DISCLOSED_BY_TIMING` applies only when the bodies match, the code compares the
     durations after `EXISTENCE_DISCLOSED_BY_ANSWER` too (unchanged since 2026-10-22, its comment before
     `TIMING_TOO_SMALL` says "the bodies agree"). Either the page or the code is wrong.
  2. 2.4: the absence rule (three siblings answering `404` means the version is absent) took an existing v2 for an
     absent one, because the first three pairs on Forgejo are `activitypub` reads that answer `404` in v1 too.
  3. 0.4: with the backend stopped the test is PASS (`BACKEND_UNREACHABLE`): the gateway's `503` counts as an answer,
     and a down backend reads as an isolated one.
  4. 6.2: with the backend stopped the test is PASS partial, judging the headers of Kong's own `503`.
  5. Schemathesis: a "Response timeout" was reported as a server error (a false finding) with the backend stopped.
  6. 1.1: with a specification that declares no security at all, the note says every operation "inherits the
     document's global `security`".
- [ ] **Branch campaign** (owner, 2026-11-15): produce on the labs every branch still unproven that the labs can
      give, fix what does not give the expected verdict, write each result in its page (rule 9 paragraph). The
      list below is taken from the pages' "Still unproven" (2026-11-15); a branch is ticked in its page, not here.
  - **Group 1, the tool's configuration or a scratch specification only (no lab change):** 1.5
    `HTTP_LISTENER_UNKNOWN`, `HTTP_PORT_UNREACHABLE`, `HTTP_PORT_NO_ANSWER`; 0.3 `PATH_NOT_FILLABLE`; 0.4
    `NO_PROBE_PATH`, `ADDRESSES_NOT_READABLE`; 1.4 the SKIP for no credential placement; 2.1
    `NO_PRIVILEGED_ENDPOINT`, `PUBLIC_ENDPOINT`; 2.4 `NO_VERSION_SIBLING`; 4.4 `NO_CREDENTIAL_TO_RETRY`; 5.1
    `CONCEPT_NOT_ACCESSIBLE`; 6.1 `NO_READ_ENDPOINT`, `NO_ENDPOINT`, `NO_ERROR_PROBE`; 6.4 `NO_GATEWAY`,
    `CONFIG_NOT_READABLE`.
  - **Group 2, a temporary change to the Forgejo + Kong gateway (route, plugin, header), one test at a time:**
    1.5 `WEAK_REDIRECT`, `TEMPORARY_REDIRECT`, `HTTP_SERVED_CLEARTEXT`, `HTTP_PROCESSED_CLEARTEXT`, `HSTS_MISSING`,
    `HSTS_MAX_AGE_LOW`, `HSTS_NO_SUBDOMAINS`; 6.2 `MISSING`, `CORS_ORIGIN_REFLECTED`, `CORS_WILDCARD_CREDENTIALS`;
    6.1 `STACK_TRACE`, `DEBUG_FIELD`, `LEAKY_HEADER`; 6.4 `DEBUG_SECRET`, `CONFIG_SECRET` at TENTATIVE, a secret
    reference left unreported; 0.3 `SWITCHED_OFF`, `METHOD_SWITCHED_OFF`, `SUNSET_DECLARED`,
    `PAST_SUNSET_STILL_SERVED`, `DEPRECATION_WITHOUT_SUNSET`, `SUNSET_NOT_A_DATE`, `ANSWER_NOT_INTERPRETED`,
    `REFUSED_BEFORE_ANSWER`, `NOT_SERVED`; 0.2 `SERVED_WITHOUT_ROUTE`, `CATCH_ALL_ROUTE`, `COVERED_BY_ROUTE`; 2.1
    `REFUSED_HIDDEN`; 2.2 `BOLA_MODIFY`, `BOLA_DELETE`, `BOLA_READ_SUBRESOURCE`, `NOT_A_REFUSAL`,
    `OWNER_NOT_SERVED`; 2.5 `SENSITIVE_FIELD`; 4.1 `NO_RATE_LIMIT` past a read limit, `LIMIT_ABOVE_BUDGET`; 4.4
    `NO_SIZE_LIMIT` past a read limit; the transport reasons that a slow route (timeout) or a rate limit (429)
    produce.
  - **Group 3, a temporary change to the APISIX lab:** 3.3 `REPLAY_UNBOUNDED` (`clock_skew: 0`); 4.2 `ABOVE_LIMIT`
    from an APISIX default; 0.1 `ROUTE_DISABLED`; 3.3 `NO_SIGNING`.
  - **Group 4, to study one by one** (they may need a scratch server or a specification change): 2.1
    `METHOD_CONFUSION`, `METHODS_CONSISTENT`; 2.5 `MASS_ASSIGNMENT`, `FIELDS_NOT_INJECTED`; 0.2
    `REFUSAL_UNSTABLE`, `REFUSALS_INDISTINGUISHABLE`; 1.7 `TIMING_TOO_SMALL`, `ANSWER_NOT_STABLE`; the
    `CALIBRATION_UNSTABLE` of 0.1, 2.4 and ffuf; 7.x's remaining reasons.
  - **Not producible without new infrastructure** (to declare, with the reason, in the paper): 1.3's five claim
    branches (a JWT issuer we control); 7.1 `ANTI_AUTOMATION_CHALLENGE` (a CAPTCHA); 7.2's confirmed SSRF (no
    out-of-band listener, by decision); 4.2 `NOT_CONFIGURED`, `NOT_STATED` and 0.1 `ROUTES_NOT_SUPPORTED` (no
    supported gateway gives them); testssl's weak protocol or cipher (a gateway offering TLS 1.0/1.1).
- [ ] With the owner: which unproven branches are worth producing on a lab (the VIOLATION ones first), for the
      separate chat.
      Then the unseen cases are produced on a lab in a separate chat (documented configuration change, only that
      test run, change undone).
- [ ] "Where each guarantee is enforced": proposal per guarantee with its supporting sentence, decided with the owner.
- [ ] Mapping of the guarantees to OWASP API Top 10 2023, ASVS 5.0.0, NIST SP 800-228 (from `TestInfo.references`).
- [ ] Systematic literature search (databases, queries, inclusion criteria) and full reading of the key papers.
- [ ] Full reading of NIST SP 800-228 (update of 2026-03-13).
- [ ] Short card per test: write the first ones, fix the pattern.

## Related work found so far (to read in full)
- Golmohammadi, Zhang, Arcuri, "Testing RESTful APIs: A Survey", ACM TOSEM 2024 (arXiv 2212.14604).
- Atlidakis, Godefroid, Polishchuk, "Checking Security Properties of Cloud Service REST APIs", ICST 2020.
- Deng et al., "Nautilus: Automated RESTful API Vulnerability Detection", USENIX Security 2023.
- Corradini, Pasqua, Ceccato, "Automated Black-Box Testing of Mass Assignment Vulnerabilities in RESTful APIs",
  ICSE 2023.
- Corradini, Ceccato, Ghafari, "Automated Testing of Broken Authentication Vulnerabilities in Web APIs with
  AuthREST", arXiv 2509.10320, 2025.
- Arcuri, Sahin, Zhang, "Fuzzing for Detecting Access Policy Violations in REST APIs", ISSRE 2025; extended in
  Sahin, Zhang, Arcuri, arXiv 2604.00702, 2026 (crAPI among its targets: only F100 and F903 found on it).
- Mai, Pastore, Goknil, Briand, "Metamorphic Security Testing for Web Systems", ICST 2020; Bayati Chaleshtari et
  al., TSE 2023.
- Schneider et al., automatic rule checking for microservices, ACM TOSEM 2025 (static, on models).
- Anisetti, Ardagna, Damiani, Saonara, "A Test-Based Security Certification Scheme for Web Services", ACM TWEB 2013.
- Barr et al., "The Oracle Problem in Software Testing: A Survey", IEEE TSE 2015.
- Jahangirova, Clark, Harman, Tonella, "Oracle Assessment and Improvement", ISSTA 2016.
- Abinaya et al., "Security testing of RESTful APIs: Approaches and research challenges", Computer Science Review
  2026 (paywalled, not read).
- Tanveer et al., "Towards Secure APIs: A Survey on RESTful API Vulnerability Detection", CMC 2025.
- NIST SP 800-228, Guidelines for API Protection for Cloud-Native Systems (2025, update 2026-03-13).
- Industry and tools: OWASP WSTG 4.12, 42Crunch conformance scan, Kong `deck file lint`, ffuf auto-calibration,
  Gauntlt, BDD-Security, DefectDojo.

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
| 2026-11-16 | Test cards are prepared as appendix material, not as a mandatory section of the main paper. Each compact card contains identity and references; the guarantee; preconditions and reference responses; sub-tests paired with their probes; oracle and outcomes, with more detail for ENFORCED and VIOLATION; validation; and only relevant evidence or limitations. The main paper explains the common structure, uses selected tests as examples, and presents validation results in aggregate. |
| 2026-11-16 | Oracles are part of the methodology, not only of the experiments: Section 3 defines source of truth, reference responses, response categories, outcomes, undecidable answers, verdict aggregation, confidence, and evidence. The experiments validate that these oracles produce the expected outcomes; they do not define the oracle model. |
| 2026-11-16 | Skeleton: 1 Introduction, 2 Background and related work, 3 Methodology, 4 Implementation, 5 Evaluation, 6 Discussion (limits and lessons), 7 Conclusions and future work, appendix with the test cards. One Methodology section holds boundary, guarantees and oracles (not split in two); Implementation and Evaluation are separate sections. |
| 2026-11-16 | Order inside Methodology, as in `apiguard-paper/sections/3-methodology.tex`: 3.1 boundary, 3.2 guarantees, 3.3 from guarantees to test instances, 3.4 oracle-based judgement, 3.5 catalogue. The method first, then its instance, which leads to the implementation. Contribution 1 is 3.1, 3.2 and 3.5, contribution 2 is 3.3 and 3.4; the introduction points each contribution to its subsections. (An order with the catalogue in 3.3 was noted earlier the same day and withdrawn.) |
| 2026-11-16 | The contributions are stated with what is specific to each (below); no separate list of objectives beside them. |
| 2026-11-16 | Implementation is organised by the requirements the method puts on a tool, each with the choice that meets it, not as a list of features. |
| 2026-11-16 | Related work ends with a positioning table; the catalogue is supported by the mapping to the standards and by the count of OWASP API Top 10 categories covered. |
| 2026-11-16 | E2 also reports what changes when only the gateway changes (same application, two gateways). |
| 2026-11-17 | E1 is built on two points that answer "the authors validated their own tests": (A) the expected outcome of every case is read before the run from the oracle the test declares in its code (one row per case, its page generated from it), never fixed after seeing the result; (B) the cases tried are the failure scenarios of the guarantees and the branches of the declared oracles, not cases chosen freely. Scripted variants (C) and a blind check by a second person on a sample (D) are paused. |

## The message and the contributions

The message: we verify the security of the boundary formed by an API and the gateway that exposes it, on the running
system, through a catalogue of guarantees and an explicit oracle for each check.

1. **The API-gateway boundary and its guarantees.** A model of the boundary and a catalogue of 32 security
   guarantees in 8 domains that covers both sides, API and gateway. Each guarantee is stated as a property a test can
   confirm, refute or leave undecided, is traced to the standards that ask for it, and declares the least access
   its check needs. The catalogue holds checks that testing the API alone cannot make: timeouts, circuit breakers,
   log shipping and request signing read from the gateway, the refusal of paths without a route, a backend that
   answers without the gateway.
2. **An oracle model common to every test.** A declared source of truth for each guarantee; a judgement calibrated
   on reference responses the target itself gives; a closed set of outcomes that includes "not verifiable"; a
   verdict computed from the outcomes and bounded by its coverage; a proof for every finding.
3. **Implementation and validation.** A tool of 31 tests and two gateway adapters, with nothing of an application or
   of a gateway in the tests, and a validation in three parts: the branches of each oracle produced on a lab (those
   the labs cannot produce are listed with their reason), the same tests on three combinations of API and gateway,
   the weaknesses OWASP crAPI publishes.

The goal, in one sentence: to verify, on the running system, whether an API and the gateway that exposes it respect
a set of security requirements, and to say for each one whether it holds, is violated or could not be decided.

## How the catalogue was built (owner, 2026-11-14)

There was no formal procedure. The guarantees were collected from the known weaknesses, vulnerabilities and
guarantees of APIs and gateways, aligned with the NIST API guidelines (SP 800-204 series, SP 800-228) and the OWASP
API Security Top 10, then classified in domains; new guarantees can always be added. To write in section 3, and to
support with the mapping of the guarantees to the standards (work list).

## Outline

How to read it: each point lists what to say, an example to use (from a different test each time, decision of
2026-11-14) and where the fact comes from. A point marked **To confirm**, **To decide** or **To measure** is not
written in the paper until it is closed. Numbers were read on 2026-11-16 from `apiguard list-tests --json` (working
tree) and from the pages named; they are counted again before submission.

### 1. Introduction

Purpose: in one page the reader knows the problem, what is done, what is new and how it is shown.

- **P1 Context.** Services expose their functions through APIs, and the APIs are published through a gateway: a
  single point of entry that terminates TLS, authenticates, limits the rate and routes each request to a backend.
  Some protections are therefore the gateway's, some the application's, some of both.
  Source: `docs/06-knowledge/01-state-of-the-art.md` section 1.1 (the mechanism, the layers).
- **P2 Problem.** Three statements, each **to confirm** by the literature search and the full reading of NIST SP
  800-228 before it is written as a fact:
  1. the standards (OWASP API Security Top 10, ASVS, NIST) say what must be protected, not how to verify it on a
     running system;
  2. research on API testing judges the application, mostly with oracles such as a server error or a response that
     does not conform to the schema, and leaves out what the gateway is responsible for;
  3. through a gateway a response does not say which component produced it, so a judgement needs more than the
     status code.
- **P3 Goal**, one sentence: to verify, on the running system, whether an API and the gateway that exposes it
  respect a set of security requirements, and to say for each one whether it holds, is violated or could not be
  decided.
- **P4 Contributions**: the three of "The message and the contributions", each pointing to its sections
  (1: 3.1, 3.2, 3.5; 2: 3.3, 3.4; 3: sections 4 and 5).
- **P5 What the evaluation shows**, one sentence per experiment with its number (**to measure**, section 5).
- **P6 Structure of the paper.**

### 2. Background and related work

Purpose: the concepts the reader needs, the standards the method rests on, and what others have done.

- **2.1 The API gateway and the boundary.**
  - What a gateway is: a specialised reverse proxy, the single entry point; the layers a request crosses (TLS
    termination, authentication, authorization, rate limiting, routing, communication with the backend, often plain
    HTTP on the internal network).
  - The risks the gateway itself adds: a wrong setting exposes a weakness no single service shows; the trust
    boundary after TLS termination; configurations that drift between instances; the backend trusts the gateway only
    if it cannot be reached directly (OWASP Microservices Security Cheat Sheet; NIST SP 800-228 section 4.1: a
    perimeter gateway "can be bypassed ... which in turn bypasses the policy checks that are enforced by that
    gateway", quoted in guarantee 0.4).
  - Hence "the boundary": the API and its gateway taken together, as an external client meets them.
  - Scope, one sentence: REST APIs described by an OpenAPI specification, behind an API gateway. The thesis also
    surveys Kubernetes ingress, service mesh, serverless and five other protocols: out of scope here.
  - The OpenAPI specification, briefly: the declared surface (operations, parameters, security requirements,
    `deprecated`), which the method uses as an input and as a source of truth.
  - Source: `docs/06-knowledge/01-state-of-the-art.md` sections 1.1 and 2.1; `docs/06-knowledge/03-guarantees.md`
    (0.4).
- **2.2 The standards.**
  - Which ones the tests cite, and what each is for: OWASP API Security Top 10 2023 (the risks), OWASP ASVS 5.0.0
    (the requirements), OWASP WSTG v4.2 (testing techniques), NIST SP (800-228, 800-204, 800-204A, 800-63B-4,
    800-53r5, 800-52r2, 800-92, 800-162, 800-107r1), RFC (9110, 7519, 8725, 7009, 6797, 6265, 8594, 9745, 6151), CWE.
  - One version of each standard is cited, and every reference carries the standard's own identifier, verified on
    its source (rule 8). Declared today: 41 ASVS, 29 OWASP API Top 10, 18 NIST SP, 12 RFC, 4 WSTG references, plus
    one CWE per test where one applies.
  - Source: `src/core/models/standards.py`; `TestInfo.references` of each test (`apiguard list-tests --json`).
- **2.3 Related work**, by group (papers in "Related work found so far", each **to read in full** first):
  1. testing and fuzzing of REST APIs (the survey of Golmohammadi et al.; RESTler; EvoMaster; Schemathesis);
  2. security oracles for APIs (RESTler's checkers; Nautilus; mass assignment, ICSE 2023; AuthREST; EvoMaster's
     access-policy oracles; metamorphic security testing);
  3. the oracle problem and oracle assessment (Barr et al.; Jahangirova et al.);
  4. static rules on architecture models (Schneider et al.);
  5. test-based security certification (Anisetti et al.);
  6. industry tools and guides (OWASP WSTG, 42Crunch conformance scan, Kong `deck file lint`, ffuf
     auto-calibration, Gauntlt, BDD-Security, DefectDojo).
- **Positioning table**, at the end of 2.3 (decided 2026-11-16): one row per approach, columns proposed: what it
  takes as input; whether it judges gateway-side guarantees; whether it reads the gateway configuration; which
  oracles it uses; whether a verdict can say "not decided". Each cell is written only after reading that paper; a
  claim about another tool is checked test by test before it is stated.
- **Closing paragraph: what is missing**, in the words P2 ends up with after the literature search.

### 3. Methodology (contributions 1 and 2)

Purpose: what is verified and how an observation becomes a judgement that can be defended. Structure as in
`apiguard-paper/sections/3-methodology.tex`: the method first (3.1 to 3.4), then its instance, the catalogue (3.5).

- **3.1 The API-gateway boundary** (figure 1).
  - **The object.** The running system an external client meets: not the API alone, not the gateway alone. We do
    not evaluate a particular application or gateway product.
  - **The components**, as the figure shows them:
    - the tester, in one of three positions (3.5, strategy);
    - the TLS channel between tester and gateway, which the gateway terminates. From outside it is observable (the
      handshake, the redirect from plain HTTP, HSTS: tests 1.5 and `ext.1.5.testssl`); the leg from gateway to
      backend is not;
    - the gateway: its routes and the policies attached to them;
    - the backend: the application that serves the requests the gateway forwards;
    - the gateway's administration plane, which makes its configuration readable (white box only);
    - the OpenAPI specification: the declared surface, against which the exposed surface is compared.
  - **Observation and enforcement** (the paragraph left open in the `.tex`). A protection is enforced by the
    gateway, by the backend or by both, but from outside the tester sees a response, not who produced it. Two
    consequences:
    1. a guarantee is stated on what the boundary does, not on a component. Example, test 4.4: an oversized body is
       "refused before it is processed, by the gateway or else by the application"; a `413` does not prove the
       gateway refused it (4.4's page, Limitations);
    2. when who answered matters, it is established by evidence, never assumed: a reference response recognises the
       gateway's own answer when no route matches (`gateway_refusal`, 3.4), and the white-box audits read the
       gateway's configuration directly. Example, test 0.2: a path without a route counts as refused by the gateway
       only when the gateway's refusal differs from the backend's own refusal; when the two cannot be told apart
       the outcome is `NOT_VERIFIABLE/REFUSALS_INDISTINGUISHABLE`, not a pass.
  - **What a result claims.** A result covers the guarantees and cases actually assessed: a missing prerequisite or
    an answer that cannot decide is reported as such, never as a pass. A verdict is relative to where the run was
    made from. Example, test 0.4: "not reachable from here" is not proof that the backend is isolated.
  - **Transition:** the boundary cannot be assessed as one property, so its required properties are stated one by
    one, as guarantees.
  - Source: `docs/04-architecture/03-assessment-model.md` (strategies, outcomes); guarantees 0.4 and 4.4 in
    `docs/06-knowledge/03-guarantees.md`.
- **3.2 Security guarantees.**
  - **Definition.** A property that an API exposed through a gateway must hold, stated so that a test can confirm
    it, refute it or leave it undecided ("only authenticated requests reach protected resources").
  - **Why guarantees and not attacks.** The guarantee states the property to preserve; attacks and probes are the
    means to test it. Each guarantee carries the standards that ask for it, so a result is read against a
    requirement, not against a list of attacks tried.
  - **The five parts**, the same for every guarantee: references; concept (what it protects and where it is
    enforced); failure scenarios; assumptions and prerequisites (what the tester has, what the target must offer);
    test logic (the checks that confirm or refute it, each against an oracle).
  - **Example, guarantee 0.2** (deny by default): references OWASP API8:2023 and NIST SP 800-228 section 3.2.1
    (REC-API-13); concept: the gateway rejects a request whose path matches no registered route; failure scenarios:
    a permissive catch-all route, a path variant the gateway does not recognise and the backend normalises, a
    case mismatch; prerequisites: none (black box); test logic: invented paths and variants of known paths must be
    refused. This is the guarantee as the catalogue states it; its test asks two of these questions (random paths at
    the root, paths just outside each route) and leaves path normalisation to tests 1.1 and 2.1 (0.2's page,
    section 2). The paper says which text it quotes.
  - Source: `docs/06-knowledge/02-methodology.md` (Guarantees); `docs/06-knowledge/03-guarantees.md` (0.2).
- **3.3 From guarantees to test instances.**
  - **The chain:** guarantee, sub-test, probe and reference responses, observation, oracle, outcome.
  - **Test and guarantee.** A test verifies one guarantee; a guarantee may have a native test and tests that run an
    external tool. Today: 31 tests (28 native, 3 external) for 29 guarantees.
  - **Sub-tests.** A test declares its sub-tests, the independent checks a guarantee divides into; every judgement
    belongs to one (rule 2). 63 sub-tests are declared today. Example, test 2.2: `cross_user_read`,
    `cross_user_modify`, `cross_user_delete`. Each page says which checks of the guarantee the test leaves out.
  - **Probes: derive first, configure on top** (rule 5). What a test probes comes from the specification, by named
    derivation rules (service prefixes, version siblings, privileged endpoints), and from the gateway; the
    configuration then adds or corrects. No destructive request is sent to a candidate that was only derived, and a
    sample is taken by a stated rule, never "the first N".
  - **Reference responses** are requests too, but not sub-tests: they tell how to read the probe's answer (3.4).
    Example, test 4.4: when the oversized body gets `401`, the test retries with a valid credential and with a
    forged one, to learn whether the body got past the authentication check.
  - **Needs.** A test declares what it needs from the configuration (an account, a second account, a gateway, a
    prepared object). A required need that is missing gives SKIP before the test runs, with the reason; an optional
    one only makes the sub-tests that use it not applicable.
  - **Pointer:** one compact card per test in the appendix.
  - Source: `docs/04-architecture/03-assessment-model.md` (rules 2, 5, 12; Needs); `src/discovery/derivation.py`;
    the pages of tests 2.2 and 4.4.
- **3.4 Oracle-based judgement** (figure 2: response, category, references, outcome, verdict). The common
  mechanisms only; no table of every test's oracle (decision of 2026-11-14).
  - **(a) A source of truth per guarantee.** Every test judges against its own oracle. Examples: the OpenAPI
    specification for 1.1, the gateway configuration for 4.2, the transport-security requirements (redirect to
    HTTPS, HSTS) for 1.5. Anything that differs is reported: finding the difference is the tool's job, deciding
    whether it is intended is the analyst's. Example: Forgejo's specification declares one security requirement
    for the whole document, Forgejo serves public data without a credential, and test 1.1 reports those reads; if
    they are intended, the specification is what needs fixing. The oracle of 1.1 keeps the two cases apart: served
    without a credential is FIRM when the operation declares its own requirement, TENTATIVE when the requirement is
    only the document's default.
  - **(b) Two steps** (rule 1). First, a response gets one of twelve categories from its HTTP status alone, the
    same for every test (`SERVED`, `REDIRECT`, `UNAUTHENTICATED`, `FORBIDDEN`, `NOT_FOUND`, `METHOD_NOT_ALLOWED`,
    `INVALID_REQUEST`, `RATE_LIMITED`, `SERVER_ERROR`, `UPSTREAM_UNAVAILABLE`, `NO_RESPONSE`, `OTHER`). Then the
    test maps the category, with what else it observed, to one of four outcomes (`ENFORCED`, `VIOLATION`,
    `NOT_VERIFIABLE`, `NOT_APPLICABLE`) and a detail of its own (`VIOLATION/SERVED_WITHOUT_CREDENTIAL`). That table
    is the test's oracle; it is declared in the test's code, one row per case, and its page is generated from it.
  - **(c) Reference responses** (rule 3). An oracle that reads an HTTP response must know what the target answers
    in two baseline cases, or it takes one thing for another (a `404` because the endpoint does not exist, read as
    "access enforced").
    - Calibration: what "does not exist here" looks like. Two requests to random sibling paths of the same shape,
      with the judged request's method and credential; when both answer alike the point is reliable. A judged
      response that matches it is "not there", not "refused". The gateway's answer when no route matches is the
      special case.
    - Positive control: a request with a valid credential that is served proves the operation exists and the
      credential works, so a later `403` or `404` means the control is enforced.
    - They are built once per run, kept in the evidence, and cited by the finding that rests on them. When a
      reference cannot decide, the outcome is `NOT_VERIFIABLE`, not a pass.
    - Example, test 2.2: user_a must be served its own object, or user_b's refusal says nothing; the object is also
      read with a forged credential, so that a refusal of user_b is told apart from a credential not accepted.
  - **(d) Answers that say nothing** (rule 4). Four categories say nothing about any guarantee by themselves: the
    gateway could not reach the backend, the request was refused for its rate, the application failed, nothing
    answered. Every test records them `NOT_VERIFIABLE`, by one rule written once: a backend that is down is never
    read as a refusal. A test whose question is that very answer declares the exception with its reason: a `429` is
    the verdict of 4.1, a `500` is what 6.1 provokes and what Schemathesis looks for. Nine tests declare one today
    (0.4, 1.5, 1.7, 4.1, 6.1, 7.1, 7.2, `ext.0.1.ffuf`, `ext.3.1.schemathesis`).
  - **(e) From outcomes to a verdict** (rule 2). The status is computed from the sub-tests, never chosen by the
    test: a violation gives FAIL; otherwise a verified case gives PASS; only not-verifiable or not-applicable cases
    give INCONCLUSIVE, which is not a pass; a missing precondition gives SKIP; a check that could not be completed
    gives ERROR. A PASS carries its coverage: `complete` only when every declared sub-test verified something,
    `partial` otherwise. A test may declare essential sub-tests: test 7.2 is INCONCLUSIVE when neither its
    cloud-metadata nor its private-address class was seen refused, because payloads rejected only for being
    malformed do not show the control.
  - **(f) Findings, confidence, evidence** (rule 6). A finding exists exactly with a violation; a note is context
    that is not a violation. Every finding names the record that proves it and the references it rests on, and
    states a confidence by fixed criteria: CERTAIN (the violation is the observed behaviour itself, or is proven by
    a reference of the same request), FIRM (observed directly, its meaning rests on one stated assumption),
    TENTATIVE (a heuristic or an indirect sign). No severity: how serious it is for the business is the analyst's
    judgement. Example, test 4.4: a body above a limit read from the gateway and not rejected is CERTAIN; with no
    readable limit it is FIRM, since a larger limit may exist.
  - **(g) Configuration oracles.** Where testing from outside is indirect, slow or would need an elaborate attack
    to show what the configuration states (a backend timeout, a circuit breaker, an allowed signing algorithm),
    the oracle reads the configuration: the same configuration gives the same verdict, and the value read is the
    evidence. The gateway is read through neutral concepts, each answering read, not supported (the gateway has no
    such concept: SKIP) or not accessible (it exists but could not be read: INCONCLUSIVE). Example, test 4.2: the
    connect, read and write timeouts of each backend against 5 s, 30 s and 30 s. To say plainly: NIST SP 800-204A
    asks for timeouts (SM-DR9, section 4.3) and sets no value, so the bounds are the method's parameters, not the
    standard's. A value the configuration sets above the bound is CERTAIN; one left to the gateway's default, which
    the adapter states, is FIRM; one neither set nor stated is `NOT_VERIFIABLE`.
  - **(h) External-tool oracles** (rule 11). The oracle is the tool's own judgement of the target, never a
    re-reading of its output: a named check decides (Schemathesis), a rating decides (testssl.sh), or the tool only
    proposes candidates and the test verifies each one itself (ffuf). The tool's own problems are `NOT_VERIFIABLE`.
    Same outcomes and verdicts as the native tests.
  - Source: `docs/04-architecture/03-assessment-model.md` (Oracles and verdicts, Outcomes, Answers that say
    nothing, Rules); `src/core/response_category.py`, `src/core/references.py`, `src/core/models/enums.py`
    (`Confidence`); `docs/04-architecture/05-design-decisions.md` (D7); the pages of tests 2.2, 4.4, 7.2.
- **3.5 Organisation and conditions of the catalogue** (table: the compact catalogue).
  - **How it was built**: "How the catalogue was built" above. It is the instance of the method this work uses, not
    a universal or complete taxonomy; a guarantee can be added.
  - **Size.** 32 guarantees in 8 domains: discovery and inventory, authentication, authorization, data integrity,
    availability and resilience, visibility and auditing, configuration and hardening, business logic and sensitive
    flows. Three were added during the test review and are not in the thesis: 0.4, 1.7, 4.4.
  - **Support from the standards** (table: the mapping). Each of the ten categories of the OWASP API Security Top
    10 2023 is declared by at least one test: API1 2.2; API2 1.1 to 1.7; API3 2.5; API4 4.1 to 4.4; API5 2.1; API6
    7.1; API7 7.2; API8 0.2, 0.4, 1.5, 2.4, 6.1, 6.2, 6.4; API9 0.1, 0.3, 2.4; API10 7.4 (as context: its text
    names data received from other APIs, not webhooks). Four tests declare no category of it (3.3, 5.1, 7.3,
    `ext.3.1.schemathesis`): the Top 10 has none for the validation of a client's input, for example. NIST SP
    800-228 is cited by 0.2, 0.3, 0.4, 1.1.
  - **Strategy:** the least knowledge and privilege a test needs to run in full. Black box: the network and the
    specification. Grey box: also one or two ordinary accounts. White box: also the administrator account or the
    gateway's configuration. It is a minimum, not a limit: five black-box tests also read the gateway when one is
    configured. Tests today: 15 black box, 10 grey box, 6 white box. A check that only observes the effect of a
    configuration is not a configuration audit: security headers (6.2) are judged from the responses, so black box.
  - **Prerequisites and effects on the target**, separate from the strategy: what the target must offer for the
    check to mean anything (an object each account owns, an operation that accepts a URL, a revocable credential),
    and what the check does to it. Declared effects today: 16 tests read only, 8 change data, 7 stress the target.
  - **Priority:** how serious a violation is for an API in general, after the factors of the OWASP Risk Rating
    Methodology; not how hard the check is, nor which strategy it needs. P0 to P3; guarantees with a test: 10 P0,
    11 P1, 5 P2, 3 P3. Priority and strategy are independent: 7.2 is P0 and grey box, 4.2 is P1 and white box.
  - **Guarantees without a test** (2.3, 5.2, 6.3): kept, to make the scope explicit; unassessed, not passed. Why:
    2.3 needs tokens with granular scopes; 5.2 needs an alert receiver the tool can observe; 6.3's request
    smuggling needs a raw-socket client. Part of 2.3 and 6.3 is covered by tests 2.2, 6.2 and 4.2.
  - **Table columns:** ID, the guarantee in one sentence, domain, priority, strategy, standards, test. **To
    decide** with the owner, guarantee by guarantee: the column "where it is enforced" (gateway, backend, both).
  - Source: `docs/06-knowledge/02-methodology.md`; `docs/06-knowledge/03-guarantees.md`; `docs/05-tests/README.md`;
    `apiguard list-tests --json`.

### 4. Implementation (contribution 3, first part)

Purpose: show that the method can be built, through the requirements it puts on a tool and the choice that meets
each one (decided 2026-11-16: not a list of features). One short opening paragraph: a command-line tool in Python;
its inputs are the OpenAPI specification and one configuration file; a test is native (it sends its own requests)
or runs an external tool (three are wired: testssl.sh, ffuf, Schemathesis), with the same outcomes (one sentence:
integrating tools is not a goal of the paper).

- **R1 Nothing of an application in the code.**
  - The surface is built at run time from the specification (Swagger 2.0, OpenAPI 3.0 and 3.1), and shared
    knowledge is derived from it once, by named rules.
  - What only the target can tell is configuration: how a credential is obtained and how it is sent, kept apart,
    the placement taken from the specification's security schemes; and prepared resources: one create request, the
    values taken from its response, an optional delete request. A login and the objects a test needs are written
    that way. Example: crAPI's login is about eight lines of configuration.
  - Source: `docs/04-architecture/01-overview.md` (design principles, Phase 2);
    `docs/04-architecture/05-design-decisions.md` (D5, D6, D10).
- **R2 Nothing of a gateway in the tests.**
  - A test asks for a neutral concept (backend timeouts, health checks, circuit breakers, signing policies, routes,
    configuration values, target health, log shipping, rate limits, body-size limits); an adapter translates the
    gateway's Admin API into it. Two adapters: Kong and Apache APISIX.
  - An adapter answers with the effective configuration (the defaults the gateway applies included) and in one
    unit whatever the gateway's; each concept is read once per run and kept as evidence.
  - Supporting another gateway is writing an adapter.
  - Source: `docs/04-architecture/05-design-decisions.md` (D7); `src/core/gateway/`.
- **R3 Usable on a real system.**
  - Every test declares its effect, and the run order follows it: read-only tests first, then those that change
    data, then those that stress the target; tests run one at a time.
  - What a test creates is registered and deleted at the end, in reverse order, also after an interruption.
  - No destructive request on an endpoint that was only derived: it is named in the report and not sent. A request
    that is not idempotent is retried only when the failure proves it never reached the application.
  - Secrets are masked in every output (one sentence).
  - Source: `docs/04-architecture/03-assessment-model.md` (rules 5, 7); `docs/04-architecture/01-overview.md`
    (SecurityClient, Teardown); `docs/04-architecture/04-security-model.md`.
- **R4 A result that can be checked and repeated.**
  - Every request a test sends is in the report's transaction log, with its category, sub-test, outcome and detail.
    `evidence.json` holds the complete transactions that prove each finding, the reference responses and the raw
    output of external tools; each record is enough to repeat the request. A finding points to its record.
  - The run writes the configuration it used, every key marked as specified or default, and can be run again from
    it. Measured on Forgejo + Kong: the second run gave the same tests, statuses, findings, outcomes and exit code.
  - The report is structured (JSON, and HTML for reading), and the exit code tells a violation from a run that
    could not decide, for use in a pipeline (one sentence).
  - Exit codes, for the one sentence: `0` no violation and at least one test ran; `1` a guarantee is violated; `3` a
    verification did not complete (ERROR or INCONCLUSIVE, or every test SKIP); `10` the assessment did not run, no
    security verdict.
  - Source: `docs/04-architecture/05-design-decisions.md` (D9); `docs/03-reference/03-exit-codes.md`,
    `04-report-schema.md`, `05-evidence-format.md`.
- **Architecture** (figure 3): the seven phases of a run (initialization, OpenAPI discovery, context construction,
  discovery and scheduling of the tests, execution, teardown, reporting), in one paragraph. Extensibility in one
  sentence: a test is one module that holds its declaration, its parameters and its oracle.
  Source: `docs/04-architecture/01-overview.md` (Pipeline); D8.

### 5. Evaluation (contribution 3, second part)

Purpose: not to say whether a target is secure, but to show that the oracles judge correctly, that the method does
not depend on one API or one gateway, and what it finds on weaknesses someone else declared. Always expected
against obtained. **To decide:** whether E1 to E3 are stated as questions (RQ1 to RQ3) in the introduction.
**To measure:** every number of this section comes from one new full run per lab, each lab reset first, on the
commit the paper cites; the figures below are of 2026-11-05 and earlier than later corrections.

- **5.1 Setup.**
  - Three labs, one factor changed at a time: Forgejo behind Kong (the reference); OWASP crAPI behind Kong with the
    same gateway configuration (only the API changes); Forgejo behind Apache APISIX with a gateway configuration of
    the same intent (only the gateway changes).
  - Versions, every image pinned: Forgejo 14.0.5, Kong 3.9.3 (DB-less), APISIX 3.19.0 with etcd 3.5.34, crAPI
    1.1.6 (images by digest, release commit `700f03d`).
  - Built as a protected deployment: no backend publishes a port, the API and the Admin APIs are reached over
    verified HTTPS, the Admin APIs listen on the loopback address only (APISIX's with a mandatory client
    certificate).
  - Why these targets: Forgejo is the reference target of the thesis, chosen against stated requirements (a
    complete specification, token authentication, roles, pure REST, self-hostable, open source); why it and not the
    other candidates is not recorded, so the paper does not say. crAPI is vulnerable by design and publishes its
    weaknesses. APISIX was chosen because its concepts are the closest to Kong's, it has a real circuit-breaker
    plugin and its Admin API is protected by a key.
  - How a run is made: the tool's version and commit, the configuration of each lab, a reset before each run.
  - Source: `docs/03-reference/06-compatibility.md` (Test lab); `docs/06-knowledge/06-target-selection.md`; D4, D7.
- **5.2 E1: the oracles judge correctly.**
  - Method: a test is trusted once seen giving the right answer in three situations: the weakness present, the
    weakness absent, the check not possible (rule 9). A situation the labs lack is produced by crAPI's case, by the
    tool's configuration, or by a documented temporary change to a lab's gateway, undone afterwards.
  - **Where the expected values come from** (decision of 2026-11-17), the answer to "the authors validated their
    own tests":
    - (A) the expected outcome of each case is the row of the oracle the test declares in its code, read before the
      run; the test page is generated from that declaration, so the expectation is public and fixed;
    - (B) the cases are not chosen freely: they are the failure scenarios of each guarantee (written in the
      catalogue, from the standards) and the rows of its declared oracle. Each scenario or row is either produced
      on a lab, with the variant that produced it, or listed as not producible, with its reason.
  - Sentence ready to use: "The expected outcome of every case was fixed before execution: it is the row of the
    oracle the test declares, and the cases are the failure scenarios of the guarantees, not cases chosen to
    succeed."
  - **How a case is produced, and how it is reported** (2026-11-17). The labs as built give only some cases; the
    others were produced by fault injection: a documented, temporary change, undone after the run of that test
    alone. Kinds of change used: a route or plugin added to or removed from the lab's gateway; a gateway route that
    forces an answer (`200`, `400`, `404`, `429`, `500`, `503`, a delay); the backend container stopped; the
    specification saved without some operations; the tool's own configuration. The result is one table of counts
    per test: cases declared; seen on a lab as built; seen on a documented variant; seen off the labs (scratch
    server, stand-in Admin API); not producible, with the reason. On the final commit every case seen gives the
    outcome its oracle declares; that statement is made, and it is not presented as an accuracy figure, since a
    case that disagreed was corrected (objection 10).
  - Example of how a branch is produced, test 2.2: a temporary route on the lab's gateway answers `200` to user_b's
    modify, and the test reports the violation; one that answers `400` gives "not a refusal"; one that hides the
    object from its owner gives "owner not served".
  - The shared rule of 3.4 (d) verified once for all tests: every test run under a gateway answering `503`, `429`
    and `500`; and, with the backend container stopped, the tests whose probes then meet the gateway's own answer.
  - What cannot be produced, with its reason, in three groups: 9 guards the code cannot reach, 9 that need a
    feature Kong and APISIX lack, 4 of environment or decision. Cases of this kind: a JWT issuer we control (1.3),
    a CAPTCHA (7.1), a confirmed server-side request (7.2, no out-of-band listener by decision), a gateway offering
    TLS 1.0 (testssl.sh). Which case is in which group is read from the pages when the list is written.
  - Only the final validated state is reported (decision of 2026-11-15).
  - **To decide** (work list): the form of the result. Proposal on the table: per test the two sides of its oracle
    seen on a lab, the shared rule once, the list of what cannot be produced. **To measure:** the final tally of
    branches (seen on a lab, seen off the labs, not producible), from each page's Validation section.
  - Source: each test page, section 12 ("What each branch has been seen doing"); the work list below.
- **5.3 E2: the same tests on another API and another gateway.**
  - One table: test by lab, the status or the SKIP with its reason. No code changes between labs: only the
    configuration.
  - What had to be configured per lab (the login, the prepared resources, the gateway section), as a measure of
    the cost of a new target.
  - Why a test is SKIP: the target does not have the thing. On Forgejo: 1.2 and 1.3 (its token is opaque, not a
    JWT), 1.6 (no session cookie), 2.4 (one API version), 7.1, 7.3, 7.4 (nothing configured). On crAPI: 0.3 (no
    deprecated operation), 1.4 (no revocation), 1.6, 7.4.
  - Same application, two gateways: the application's results are the same, the gateway's are the gateway's.
    Example of 2026-11-05: test 0.2 failed with Kong (a route prefix matched as a string, so `/api-x` reached the
    backend) and passed with APISIX (which matches segment by segment). **To measure** again: test 0.2 changed on
    2026-11-15.
  - Differences between the two gateways that cannot be removed (APISIX's `hmac-auth` has no `hmac-sha384`; its
    health checks probe healthy nodes too; a `308` where Kong answers `301`).
  - Source: `LAB_FINDINGS.md`; `docs/03-reference/06-compatibility.md` (Test portability, Test lab).
- **5.4 E3: weaknesses declared by someone else.**
  - crAPI declares 18 challenges in 11 categories: the expected values are not ours.
  - The table, challenge by challenge: what the tool did and the verdict.
  - The count of 2026-11-05: 3 absent from the deployment (the chatbot is left out), 4 outside the tool's scope
    (injection confirmation, business invariants), 11 remaining: caught outright 3, 6, 14, 15; 7 named and not
    exploited because the operation is destructive; 11 attempted and not concludable; missed 1, 2, 5, 10.
    **To re-verify:** challenge 4. Its row says "missed" (test 2.5 reads the configured order, whose card number is
    masked: PASS since 2026-11-04), while the paragraph under the table says its weakness class was caught on
    another endpoint. The two disagree; the page is corrected before the number is used.
  - False positives: every finding on the three labs classified by where it comes from (the application, the lab's
    setup, the specification); none is a behaviour the target does not have. The 78 findings of test 1.1 on Forgejo
    are true differences from the specification and not vulnerabilities, reported as TENTATIVE: to say plainly.
  - Optional: EvoMaster's published results on crAPI, with the caveat that the conditions differ.
  - Source: `docs/03-reference/06-compatibility.md` (What the tool detects); `LAB_FINDINGS.md`.
- **5.5 Threats to validity.**
  - The labs are ours, and so are their gateway configurations: the findings that come from the lab's setup show
    that the tool sees what a gateway leaves open, not how common that is.
  - One person validated the oracles.
  - Two gateways, the second chosen because its concepts are close to the first's; two applications.
  - Some results move between runs: Schemathesis generates its inputs at random; test 4.4 on crAPI depends on a
    race; the crAPI lab wears out (each run spends credit, and after about ten runs two findings disappear until a
    reset), so every measure is taken right after a reset.
  - A verdict is relative to where the run was made from (0.4).

### 6. Discussion: limits and lessons

Purpose: what the work does not do and what was learnt. Limits of the method here; validity of the experiments in
5.5.

- **Whose object it is cannot be established without knowing the target.** Deriving an owned object from the
  target was designed and tried on the three labs with reads only, and found none: a fresh deployment has no owned
  object to list, and the collections that do return identifiers are public. So tests 2.2 and 2.5 ask for a
  configured object, and the four crAPI challenges missed (1, 2, 5, 10) are on objects that were not configured.
  Source: test 2.2's page, Limitations; `docs/03-reference/06-compatibility.md`.
- **Safety towards the target against coverage.** Some things are named and not verified: a destructive operation
  on a derived endpoint (crAPI challenge 7); test 7.2 stops at the first payload left without an answer, so as not
  to take the backend out of service; an accepted URL is not confirmed as a call, for lack of an out-of-band
  listener.
- **The judgement is as good as its source of truth.** A specification that does not say which operations are
  public gives findings that are true and not weaknesses (test 1.1 on Forgejo). Candidate point, **to confirm**
  with the owner.
- **Specialist tools explore more objects; the catalogue covers more guarantees; integration joins the two.** To
  write only after the related work is read (every comparative claim checked).

### 7. Conclusions and future work

- What was done, in the words of the three contributions, with the numbers of section 5.
- Future work, candidates **to confirm** with the owner (each is a limit stated above, not a plan of the tool):
  other gateways through new adapters; an out-of-band listener to confirm server-side requests; the guarantees
  without a test; exposure patterns and protocols outside the scope of 2.1.

### Appendix: test cards

One compact card per test, pattern fixed on 2026-11-16 (Decisions): identity and references; the guarantee;
preconditions and reference responses; sub-tests with their probes; oracle and outcomes; validation; the relevant
limitation. Written: 4.4 (`apiguard-paper/sections/appendix.tex`). Each card is taken from the test's page and its
declaration, not from the guarantees catalogue.

### Abstract: written last.

## Writing aids

Help for the writing, not content to decide: terms to keep the same everywhere, sentences that can be taken as they
are or reworked, the proof behind each claim, and what the paper must not claim. Every sentence states only what
the outline above sources.

### Terms (one word per concept, the same in every section)

| Term | Meaning, usable as its definition |
|---|---|
| boundary | the API and the gateway that exposes it, taken together as an external client meets them |
| guarantee | a security property the boundary must hold, stated so that a test can confirm it, refute it or leave it undecided |
| catalogue | the set of guarantees this work uses, grouped in domains |
| test | the automated verification of one guarantee |
| sub-test | one independent check a test divides its guarantee into; it has its own outcome |
| probe | a request sent to obtain the observation a sub-test judges |
| reference response | the target's answer in a known case (a path that does not exist, a request with a valid credential), used to read a probe's answer |
| source of truth | what a guarantee is judged against: the specification, the gateway's configuration, a requirement of a standard, a reference response |
| oracle | the rule that turns an observation into an outcome, given the source of truth |
| category | what a response is, from its status code alone; the same list for every test |
| outcome | what an observation means for the guarantee: enforced, violation, not verifiable, not applicable |
| verdict | the result of a whole test, computed from its outcomes: pass, fail, inconclusive, error, skip (the code calls it status) |
| coverage | whether a pass rests on every sub-test (complete) or only on some (partial) |
| finding | a reported violation, with its proof and its confidence |
| confidence | how sure a finding is: certain, firm, tentative; not how serious |
| strategy | the least knowledge and privilege a test needs: black box, grey box, white box |
| need | what a test requires from the configuration to run (an account, a gateway, a prepared object) |
| effect | what a test does to the target: reads only, changes data, stresses it |

Proposal, owner to confirm: "outcome" only for a sub-test's judgement and "verdict" only for a test's result, never
swapped; "gateway" always the API gateway; "administration plane" for the gateway's Admin API; "lab" for each of the
three deployments.

### Sentences ready to use

**Introduction**
- APIs are commonly published through an API gateway, which terminates TLS, authenticates callers, limits the
  request rate and routes each request to a backend service.
- The security of what a client reaches therefore depends on two components at once: the application that
  implements the API and the gateway that exposes it.
- We call this pair, as an external client meets it, the API-gateway boundary.
- This paper presents a method to verify, on the running system, whether the boundary respects a set of security
  requirements, and to state for each one whether it holds, is violated or could not be decided.
- We do not evaluate a particular application or gateway product: the method takes the OpenAPI specification and a
  configuration, and the same tests run on different APIs and gateways.
- Problem statements, drafts **to confirm** (outline, 1 P2): "Standards state what an API must protect, not how to
  verify it on a running system." "Work on API testing mostly judges the application, and treats the gateway as a
  transparent channel." "A response observed through a gateway does not say which component produced it."

**Background**
- An API gateway is a reverse proxy placed in front of one or more backend services as their single point of entry.
- Its policies, such as authentication or rate limiting, are attached to routes: a request that reaches a backend
  outside a route, or without passing through the gateway, reaches it without them.
- We consider REST APIs described by an OpenAPI specification and published through an API gateway; other exposure
  patterns and protocols are outside the scope of this work.

**Methodology, 3.1**
- The object of the assessment is the boundary of the running system, not the API or the gateway in isolation.
- From outside, the tester observes a response, not the component that produced it.
- A guarantee is therefore stated on what the boundary does, and a result is attributed to a component only when a
  reference response or the gateway's configuration supports it.
- A result covers only what was assessed: a missing prerequisite or an answer that cannot decide is reported as
  such and is never counted as a pass.

**Methodology, 3.2**
- A security guarantee is a property that an API exposed through a gateway must hold, stated so that a test can
  confirm it, refute it or leave it undecided.
- The method starts from guarantees rather than from attacks: the guarantee states the property to preserve, while
  probes and attack inputs are means to test it.
- Every guarantee is described by the same five parts: its references, its concept, its failure scenarios, its
  assumptions and prerequisites, and its test logic.

**Methodology, 3.3**
- A test verifies one guarantee and divides it into sub-tests, each an independent check with its own outcome.
- What a test probes is derived from the OpenAPI specification and, when one is configured, from the gateway; the
  configuration adds only what the target alone can tell.
- Reference responses are requests as well, but they are not checks: they tell how the answer to a probe must be
  read.
- A test declares what it needs; when a need is missing the test is skipped before it runs, and the reason is
  reported.

**Methodology, 3.4**
- Each test judges what it observes against a declared source of truth.
- Anything that differs from the source of truth is reported: finding the difference is the method's job, deciding
  whether it is intended is the analyst's.
- Judgement takes two steps. A response first receives a category from its status code alone, common to every
  test; the test then maps what it observed to one of four outcomes.
- The same status code can mean opposite things: a `404` may be a refusal, or a path that simply does not exist.
  Two requests to random sibling paths show what "does not exist" looks like on this target.
- A refusal is evidence only if the request would otherwise have been served: a positive control, the same request
  with a valid credential, shows that the operation exists and the credential works.
- Four kinds of answer say nothing about any guarantee: the gateway could not reach the backend, the request was
  refused for its rate, the application failed, or nothing answered. They are recorded as not verifiable, so a
  backend that is down is never read as a refusal.
- The verdict of a test is computed from the outcomes of its sub-tests and is never chosen by the test.
- An inconclusive verdict is not a pass: the run finished and verified nothing.
- A pass is bounded by its coverage: it is complete only when every sub-test verified something.
- Every finding names the request that proves it and states how sure the judgement is. It carries no severity: how
  serious a violation is for the business is the analyst's judgement.
- Where testing from outside would be indirect or slow, the oracle reads the gateway's configuration: the same
  configuration gives the same verdict, and the value read is the evidence.
- For an external tool, the oracle is the tool's own judgement of the target, not a re-reading of its output.

**Methodology, 3.5**
- The catalogue contains 32 guarantees in eight domains; 29 have a test.
- It was assembled from known weaknesses of APIs and gateways and from the requirements of OWASP and NIST. It is
  the instance of the method used in this work, not a complete taxonomy, and a guarantee can be added.
- Every category of the OWASP API Security Top 10 2023 is cited by at least one test.
- Strategy is the least access a test needs, and priority is how serious a violation is; the two are independent.
- Guarantees without a test stay in the catalogue as unassessed, not as passed.

**Implementation**
- The tool takes two inputs: the OpenAPI specification of the API and one configuration file.
- No path, payload or behaviour of a specific application appears in the code: what only the target can tell is
  configuration.
- A test asks the gateway for a neutral concept, such as the timeouts of a backend; an adapter translates the
  gateway's administration interface into it.
- Each test declares its effect on the target, and a run executes the read-only tests first.
- A run writes the configuration it used and can be repeated from it.

**Evaluation**
- The evaluation does not ask whether a target is secure. It asks whether the oracles give the expected outcome,
  whether the same tests run on a different API and a different gateway, and what the method finds on weaknesses
  declared by a third party.
- The three labs differ by one factor at a time: the second changes only the API, the third only the gateway.
- A test is considered validated once it has been seen giving the expected outcome where the weakness is present,
  where it is absent and where the check cannot be made.
- The expected values of the third experiment are not ours: OWASP crAPI publishes the weaknesses it contains.

**Discussion**
- Whether an object belongs to a user cannot be established without knowledge of the target.
- Safety towards the target has a cost in coverage: some operations are named in the report and not sent.

### Each claim and its proof

A claim without a row here, or whose proof is not ready, is not written.

| Claim | Where it is shown | State |
|---|---|---|
| The catalogue covers the API side and the gateway side | catalogue table with "where it is enforced"; the tests that read the gateway (0.4, 3.3, 4.2, 4.3, 5.1 need it; 0.1, 0.2, 4.1, 4.4, 6.4 use it when configured) | the column is to decide |
| Every guarantee is traced to a standard | mapping table, from `TestInfo.references` | data ready |
| Every OWASP API Top 10 2023 category is covered | mapping table | verified 2026-11-16 |
| The oracles judge correctly | E1 | tally to measure |
| An answer that says nothing is never read as a verdict | E1, the shared rule under `503`, `429`, `500` | done 2026-11-16; to report |
| The tests hold nothing of an application or of a gateway | E2: three labs, configuration only | to measure again |
| The same application gives another result with another gateway | E2, test 0.2 | to measure again |
| The method finds weaknesses declared by others | E3, crAPI's 18 challenges | challenge 4 to re-verify |
| No finding is a behaviour the target does not have | classification of every finding by origin | figures of 2026-11-05, to measure again |
| A run can be repeated | the second run from `config_used.yaml` on Forgejo + Kong | measured (D9) |

### What the paper does not claim

- Not that a target is secure: a pass holds for what was tested, with its coverage.
- Not that the catalogue is complete or a standard taxonomy.
- Not that the tool finds more than specialist tools: any comparison is checked test by test first.
- Not that gateways are commonly misconfigured: the labs' gateway configurations are ours.
- Not that a refusal came from the gateway, unless a reference response or the configuration shows it.
- Not thresholds as a standard's: where a bound is the method's own (4.2's timeouts), it is said.
- Not the history of the defects found while validating (decision of 2026-11-15).

### Objections a reviewer is likely to raise (2026-11-17, owner to decide which to address)

Ranked by how hard each would be to answer once the paper is written.

1. **Which version was validated?** The branches were produced from 2026-11-14 to 2026-11-16, and the code changed
   in between (the shared rule of 2026-11-16, 0.2 on 2026-11-15). E1 reports the final state, so its evidence must
   be of one commit, the one the paper cites. To decide: re-run the variants on that commit, or say which commit
   each was seen on. (Owner, 2026-11-17: kept, to be checked in a separate chat.)
2. **What is counted in E1?** Today's tally counts "named items", with groups counted as one; a reviewer can call
   it arbitrary. The unit could be the row of the declared oracle (A), which comes from the code: 395 rows today.
   Five tests declare none yet (3.3, 5.1 and the three external ones; the review of every test is in progress), so
   the unit holds only once every test declares its oracle. Not a list of 395 items in the paper: E1 gives totals
   (cases declared, seen on a lab, seen off the labs, not producible with reason), by outcome and by test, and the
   detail stays in the test pages. Rows today, by outcome: 185 NOT_VERIFIABLE, 98 VIOLATION, 71 ENFORCED, 41
   NOT_APPLICABLE. Owner, 2026-11-17: that split has no meaning a reader can use. It describes how the oracles are
   written (many ways of abstaining are named one by one), not what happens on a target, so it is **not reported
   as a result**. E1 reports only how many declared cases were exercised and how; how often a run cannot decide is
   measured on the runs (verdicts per lab), not on the declared rows.
3. **The thresholds are the authors' choice.** Several verdicts depend on a number: 4.2's 5/30/30 s, 1.7's 101
   attempts, 4.1's burst of 150, 4.4's body size without a readable limit. Owner, 2026-11-17: they are taken from a
   standard where one gives a value, and can be changed by an expert case by case. Checked in
   `config.example.yaml`: 4.1 `max_burst`, 4.2 `max_*_timeout_ms`, 4.4 `body_size_bytes`, 3.3's replay window are
   parameters; 1.7 has none (its 101 is one past the 100 failures NIST SP 800-63B-4 section 3.2.2 allows, fixed in
   the code). To address: one table with each threshold, its source (a standard, or the method's own choice, said
   plainly) and whether it is a parameter.
4. **No comparison with another tool.** Software-engineering venues expect a baseline. Options: compare on crAPI
   with results others published (EvoMaster's, under different conditions); or run one existing tool on the same
   labs; or argue in the positioning table that no tool answers the same question. Owner decision; every
   comparative claim is checked test by test. Recommendation (2026-11-17): no run of another tool; the positioning
   table, and on crAPI the results others published, with the caveat that conditions differ.
5. **Only labs, built by the authors.** No real deployment. Forgejo is a real application, but the gateway
   configurations are ours. Not a defect to fix: building one's own labs is the usual way, and the threats say
   what it limits. What already answers it: one factor changed at a time, the expected values of E3 written by
   others, the labs built from the official guides of each product (compatibility page, Test lab).
6. **Two gateways, both open source and self-hosted.** Managed gateways (AWS, Azure) are paid services and were
   not available. To state as scope, with the adapter as the extension point.
7. **What do the confidence levels mean?** A level is deterministic: each row of an oracle has its own, fixed in
   the code, so the same observation always gets the same level. What it is not: a measured probability. CERTAIN
   does not mean "true in 100% of cases on a sample"; it means the violation is the behaviour observed itself. To
   say so in 3.4, so that no one reads the levels as precision figures.
8. **Cost of a run.** Duration and number of requests per lab: the report has them
   (`assessment_duration_seconds`, `duration_ms` per test and per request). One line in E2, from the new runs.
9. **Availability.** A method paper without the tool and the labs is hard to check. Owner, 2026-11-17: not decided
   whether the code is published. If not, the paper describes the labs precisely enough to be rebuilt (versions,
   gateway configuration), and says the material is available on request, if that is the choice.

### Further objections (2026-11-17)

10. **E1 agrees 100% by construction.** E1 reports the final state, after every case that disagreed was fixed
    (decision of 2026-11-15), so "expected equals obtained" holds by construction and a reviewer can say E1 measures
    nothing. To decide with the owner, without reopening the decision: E1 reported as a measure of coverage (how
    many declared cases were exercised, how many cannot be), not of accuracy; the accuracy against values not
    ours is E3. Optionally, the number of defects the validation found and fixed, as one figure without their
    story, shows the validation had power (this would amend the decision of 2026-11-15: owner's call).
11. **"The tool often does not decide."** A reader who sees many NOT_VERIFIABLE cases may think so. The answer is
    measured on the runs: of 2026-11-05, 1 or 2 INCONCLUSIVE tests per lab out of 31 (`LAB_FINDINGS.md`; to measure
    again). Abstaining is a design choice: an answer that cannot decide is said, never turned into a pass. Owner,
    2026-11-17: it is the basic logic of the method; only the measured figure is reported, no defence needed.
12. **What "no false positive" means.** "Every finding is a behaviour the target really has" is a claim about the
    observation. A reviewer reads "false positive" as "reported as a weakness, and it is not one", and the 78
    TENTATIVE findings of 1.1 on Forgejo are true differences from the specification but not weaknesses. The paper
    defines the term before using it, and reports the findings by origin (application, lab setup, specification)
    rather than claiming zero false positives. Proposal (2026-11-17): keep the term, defined once ("a finding whose
    observed behaviour the target does not have"); report separately the findings that are true and are not
    weaknesses (the 78 of 1.1, a specification that declares no public operation).
13. **The crAPI denominator.** 7 of the 18 challenges are set aside (3 absent from the lab, 4 out of scope). A
    reviewer may read it as leaving out what the tool misses. To report both counts, over 18 and over the 11 in
    scope, each exclusion with its reason, recorded as a non-goal before the measure. Checked 2026-11-17: the 3
    absent are the chatbot (LLM) challenges, left out of the lab because the chatbot needs an OpenAI key; the 4 out
    of scope are injection confirmation (12, 13) and business invariants (8, 9), non-goals of the tool. Both
    exclusions are genuine; the point is only to show the two counts, so that nothing looks hidden.
14. **Priorities are the authors' judgement.** P0 to P3 follow the OWASP risk-rating factors but are assigned by the
    authors. To say that a priority orders the run and never changes a verdict. Checked 2026-11-17: a priority is
    how important a guarantee is for an API in general, not the severity for one business (the methodology leaves
    that to the analyst, and a finding carries no severity). It is fixed in each test's declaration; the
    configuration does not reassign it, it only selects by it (`execution.min_priority`, `test_ids`).
15. **Overlap with the earlier article.** Venues check prior publication. The earlier article is compared at the
    end (decision of 2026-11-13); the venue's policy on extended versions is read when the venue is chosen.

### Abstract, the five slots (written last)

1. Context: APIs are published through gateways; security depends on both.
2. Problem: the statement P2 ends up with.
3. Approach: a catalogue of guarantees for the boundary and an oracle model common to every test.
4. Implementation and evaluation: the tool, the three labs, crAPI, with the three numbers of section 5.
5. What follows from it: a result that says what holds, what is violated and what could not be decided.

### Still missing from the paper's frame (owner to decide)

- **Title.** Candidates: "Verifying Security Guarantees at the API-Gateway Boundary with Explicit Oracles";
  "Assessing the Security of APIs Exposed Through a Gateway: Guarantees, Oracles and a Tool"; "APIGuard Assurance:
  Oracle-Based Security Assessment of the API-Gateway Boundary".
- **Keywords.**
- **Availability.** Whether the tool and the labs are published with the paper, and where.
- **Authorisation.** One sentence: every experiment ran on the authors' own labs; the tool sends attack traffic and
  is to be used only on systems one is authorised to test.
- **Declaration on Generative AI.** The CEUR template requires it (`apiguard-paper/venues/ceur/CHECKLIST.md`).

## Figures and tables
1. The model of the boundary (section 3).
2. The path of a judgement: response, category, references, outcome, verdict (section 3).
3. The pipeline (section 4).
4. The compact catalogue (section 3.5).
5. The mapping to the standards (section 3.5).
6. The positioning table (section 2.3).
7. Results of E1, E2, E3 (section 5).

## Work list
- [x] `docs/06-knowledge/03-guarantees.md`: 29 guarantees with a test (5.2 added), CIS reference removed (2026-11-14).
- [x] `docs/06-knowledge/02-methodology.md`: the strategy is the least access a test needs, not a limit on what it
      uses (`src/core/test_metadata.py`, `NEED_MINIMUM_STRATEGY`) (2026-11-14).
- [x] `CHANGELOG.md`: entry for the two corrections above, under Fixed (2026-11-14).
- [x] Branch inventory for E1: per test, the cases of its oracle table (section 6 of its page) against what its
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
- [x] **Branch campaign** (owner, 2026-11-15): produce on the labs every branch still unproven that the labs can
      give, fix what does not give the expected verdict, write each result in its page (rule 9 paragraph). The
      list below is taken from the pages' "Still unproven" (2026-11-15); a branch is ticked in its page, not here.
  - Owner decision found by the campaign: the Forgejo labs' login token has no `read:admin` scope, so test 2.1's
    admin positive control never confirms an operation on them (2.1's page). Adding the scope to the labs'
    `forgejo-token` resource would make it work, and change those labs' 2.1 results.
  - Progress (2026-11-15): group 1 done; group 2 done (0.2, 0.3, 1.5, 2.1, 2.2, 2.5, 6.1, 6.2 seen; 4.1 and 4.4
    "limit read" branches unreachable with the supported gateways); group 3 done (`REPLAY_UNBOUNDED` unreachable
    with APISIX 3.19); group 4 in progress: 0.2, 2.1 method branches and every `CALIBRATION_UNSTABLE` seen.
    Every page says what it saw, how, and what is unreachable. Pending: 6.4's three planted-secret branches.
  - Campaign closed (2026-11-15): no page has a branch "still unproven"; each is seen on a lab, seen off the labs,
    or stated not reachable / not producible with its reason. Decided and done: 0.2 fixed (regex catch-all), 3.3
    kept (owner: a policy is configured even on a disabled route), 2.1 labs given `read:admin`, 6.4 done with
    fictitious values.
  - Owner decisions of 2026-11-15, done the same day (owner: "4.1 e 4.4 ok", 1.1 "se pensi che rispetti i
    paradigmi del mio tool", 6.4 "ok"); CHANGELOG under Fixed, each produced on the labs:
    1. 4.1 and 4.4 read the gateway's limits through two neutral concepts (`rate_limits()`, requests per window of
       seconds; `body_size_limits()`, bytes), a limit counting only for the routes that may serve the probe. 4.1's
       CERTAIN also needs the limit exceeded within one window and a counter shared by every node (FIRM with
       both gateways' default `local` policy); `LIMIT_ABOVE_BUDGET` became `LIMIT_NOT_REACHED`. Six variants on
       the labs produced every branch, except the per-node case on a gateway with several nodes (the labs run
       one; the FIRM row was exercised another way).
    2. 1.1: the client sends a path with dot segments or a leading `//` as written (a transport that keeps the
       request target); the three `SERVED_AS_*` produced on Forgejo + Kong; the labs' results unchanged.
    3. 6.4: one finding per value per configuration object, naming the other keys.
    4. 4.4's timeout name: settled by the shared rule of 2026-11-16 (`NO_RESPONSE`). 1.7's guard it cannot reach
       (`LOGIN_NOT_ANSWERING`): kept, as every case the labs cannot produce (below).
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
- [x] (Owner, 2026-11-16) The cases not producible on the labs stay as they are, each with its stated reason in its
      page: 9 guards the code cannot reach, 9 needing gateway features Kong and APISIX lack, 4 of environment or
      decision. Earlier item: which unproven branches are worth producing on a lab (the VIOLATION ones first), for the
      separate chat.
      Then the unseen cases are produced on a lab in a separate chat (documented configuration change, only that
      test run, change undone).
- [x] Done 2026-11-16 (CHANGELOG under Fixed): one shared rule for the answers that say nothing (the gateway
      unable to reach the backend, `429`, `500`, no answer), written once in core with each test's exceptions
      declared (`TestInfo.decisive_answers`), and generated in every test page; three tests no longer read a `429` as a
      real answer (4.4, 1.7's enumeration, 0.4); verified with every test under a gateway answering `503`, `429`, `500`,
      and a full regression on the three labs (no change). Eight test pages aligned to their code. CI fixed (Typer 0.29
      broke the CLI-reference generator) and every dependency pinned to its verified version in `pyproject.toml`.
- [ ] **Now (owner, 2026-11-16): the review of every test, methodological and concrete.** Test by test, starting with
      4.4: the oracle declared in the test's code (one line per case) and sections 6 and 8 of its page generated from
      it; in the same pass, whether the guarantee makes sense as stated, whether it is verified as completely and
      sensibly as it can be, whether every case leads to the right verdict.
      Progress: 4.4 done (2026-11-16): oracle declared and page generated; documented method sent; ASVS 2.4.1 dropped;
      chunked body probed (owner: yes); who answers the 413 (owner: "indaga tu"): not distinguishable without signals
      of one gateway (rule 10), so the guarantee says "refused before it is processed, by the gateway or else by the
      application" and the limitation is on the page.
      Domain 4 done (2026-11-16): 4.1, 4.2, 4.3 reviewed with their oracles in code (CHANGELOG), every 4.1 branch but
      two produced on lab variants; shared fixes (concept not accessible, optional account login). Owner question
      open: 4.3 judges the gateway as a whole (one covered backend passes it), 4.2 each backend (withdrawn: the owner
      had already discarded 4.3 per backend on 2026-11-05).
      Then (owner, 2026-11-16): seven read-only review agents, one per group; findings triaged by verification
      value; fixes and one lab run per domain. Every test reviewed (2026-11-16), every oracle in code. Owner questions: 1.5 Kong's 426 decided (owner delegated, 2026-11-16: a protocol refusal is ENFORCED); 1.6 cookie sessions done (owner, 2026-11-16: `cookie:<name>`); 3.3 `content_signed` done (owner delegated, 2026-11-16); 5.1 `secrets_not_shipped` done (owner, 2026-11-17). No owner question left.
      Method from now on (owner, 2026-11-16, tokens and time): per domain, the oracles moved in one pass, the review
      reported as problems only, one lab run per domain, the owner's questions gathered at the end of the domain.
- [ ] Later (owner, 2026-11-16): how E1 presents the validation (proposal: per test the two sides of its oracle seen
      on a lab, the shared rule verified once for all tests, the list of what cannot be produced with its reason).
- [ ] During the writing (owner, 2026-11-16): the items below.
- [ ] "Where each guarantee is enforced": proposal per guarantee with its supporting sentence, decided with the owner.
- [ ] Mapping of the guarantees to OWASP API Top 10 2023, ASVS 5.0.0, NIST SP 800-228 (from `TestInfo.references`).
- [ ] Systematic literature search (databases, queries, inclusion criteria) and full reading of the key papers.
- [ ] Full reading of NIST SP 800-228 (update of 2026-03-13).
- [ ] Short card per test: write the first ones, fix the pattern.
- [ ] Found while filling the outline (2026-11-16):
  - crAPI challenge 4 in `docs/03-reference/06-compatibility.md`: its row says "missed", the paragraph under the
    table says its weakness class was caught on another endpoint. To re-verify and correct before E3 uses the count.
  - One new full run per lab, each reset first, on the commit the paper cites: the figures in `LAB_FINDINGS.md` and
    in the compatibility page are of 2026-11-05, before the corrections of 2026-11-15 and 2026-11-16.
  - Final tally of the oracle branches for E1 (seen on a lab, seen off the labs, not producible), from each page.
  - The positioning table of section 2.3, one row at a time as each paper is read.

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

# Methodology Framework

> **Audience:** analysts, contributors, readers of the research · **Status:** adapted from the thesis methodology
> (chapter 3, now [`03-guarantees.md`](03-guarantees.md)), corrected against the tool · **Source of truth:** the owner's
> decisions of 2026-10-20; for the tool:
> `src/core/test_metadata.py` (`TestInfo`, `Need`), `src/core/models/enums.py` (`TestStrategy`) · **Verified:**
> 2026-10-20

The method behind the tool's checks: what a guarantee is, who the tester is, what a check may use, and how
guarantees are ranked. How the tool applies it (strategy labels, selection, verdicts):
[`architecture/assessment-model.md`](../04-architecture/03-assessment-model.md). The guarantees themselves, one by
one: the [catalogue](03-guarantees.md), whose priorities and strategies are the ones the tests declare.

## Guarantees

The methodology does not start from attacks but from **security guarantees**: properties that an API exposed
through a gateway must hold, each one stated so that a test can confirm or refute it (for example "only
authenticated requests reach protected resources"). Every guarantee belongs to one of eight domains, named as the
reports name them (`DOMAIN_NAMES`, `src/report/builder.py`); the [catalogue](03-guarantees.md) lists the guarantees
of each.

<!-- [[[cog import generate_docs as g; cog.out(g.domain_names_table()) ]]] -->

| `domain` | `domain_name` |
|---|---|
| 0 | API Discovery and Inventory Management |
| 1 | Identity and Authentication |
| 2 | Authorization and Access Control |
| 3 | Data Integrity |
| 4 | Availability and Resilience |
| 5 | Visibility and Auditing |
| 6 | Configuration and Hardening |
| 7 | Business Logic and Sensitive Flows |

<!-- [[[end]]] -->

Each guarantee is described with the same parts:

| Part | Says |
|---|---|
| References | the standards that require it (OWASP API Security Top 10, OWASP ASVS, NIST, RFC) |
| Concept | what the guarantee protects and where it is enforced |
| Failure scenarios | concrete ways it is violated |
| Assumptions and prerequisites | what the tester has, and what the target must offer |
| Test logic | the checks that confirm or refute it, each against an oracle (the source of truth it is judged by) |

## Knowledge and privilege gradient

The checks are not run from one position. The tester moves along a gradient of **knowledge and privilege**,
after the Black Box / Grey Box / White Box classification: what the tester has decides what a check may use, and
so which technique it can apply. Applying the wrong technique to a check gives false negatives (a weakness not
seen from where the check stands) or wasted effort (a long empirical test for something a configuration shows in
seconds).

| Strategy | The tester is | The check may use | So the technique is |
|---|---|---|---|
| Black box | an anonymous attacker probing the perimeter | the network and the OpenAPI specification | observing responses: status, headers, TLS |
| Grey box | an attacker holding legitimate credentials, or a malicious insider | in addition, one or two ordinary accounts, never the administrator | observing responses, also as an authenticated user |
| White box | a super user, or someone with internal access | in addition, the administrator account and the gateway's configuration | in addition, reading the configuration (configuration audit) |

Each strategy includes what the one above it has. A check is labelled with the least strategy that lets it run in
full. Two consequences:

- A check that only observes the effect of a configuration is not a configuration audit. Security headers (6.2)
  and transport security (1.5) are judged from the responses and the TLS handshake, which anyone outside can
  observe, so they are black box.
- A check that reads the gateway configuration, or acts as administrator, is white box whatever the guarantee's
  domain: timeouts (4.2), circuit breakers (4.3), request signing (3.3), credentials in the gateway configuration
  (6.4), revocation of a credential (1.4, which needs the administrator account).

**Why a configuration audit.** Where testing from outside is indirect, slow, or would need an elaborate attack to
show something the configuration states (a backend timeout, a circuit breaker threshold, an allowed signing
algorithm), reading the configuration is deterministic, reproducible and documentable: the same configuration
gives the same verdict, and the value read is the evidence.

In the tool: every test declares its strategy (`TestStrategy`) and its needs (`Need`, listed with the tests that
depend on each one in the [assessment model](../04-architecture/03-assessment-model.md#needs-what-the-configuration-must-hold)).
Every test uses only what its strategy grants, and a need fixes the minimum strategy the test requires
(`src/core/test_metadata.py`).

## Prerequisites and effects on the target

Two further things are independent of the strategy:

- **Prerequisites on the target**: what the target must offer for the check to mean anything, such as an object
  each account owns, an operation that accepts a URL, a login whose credential can be revoked, session cookies. In
  the tool they are the test's needs, the prepared resources in `config.yaml`
  ([`resources`](../03-reference/01-configuration.md#resources)) and the parameters marked needed to run; what each test
  needs from a target, and what happens without it, is in
  [Test portability](../03-reference/06-compatibility.md#test-portability).
- **Effects on the target**: what a check creates, changes or leaves behind, which decides whether it may run in
  production or only in staging. Stated on each test page ([`tests/`](../05-tests/README.md), "Prerequisites and
  effects on the target").

## Priorities

A guarantee's priority says **how important it is**: how serious a violation is for an API in general. It does
not say how hard the check is to automate, nor which strategy it needs: a critical check can need credentials and a
configuration audit can be important.

The ranking follows the factors of the OWASP Risk Rating Methodology, which the OWASP API Security Top 10 2023 uses:
how easy the weakness is to exploit, how widespread and how detectable it is, and its technical impact. Like OWASP,
the priority leaves out the impact on a particular business, which only the organisation can judge.

| Priority | Importance | Typical guarantees |
|---|---|---|
| P0 Critical | the top risks of the OWASP API Security Top 10, and the perimeter controls every gateway must enforce before any authentication | inventory and deny-by-default, authentication required, rate limiting, SSRF |
| P1 High | business-critical controls: their violation exposes privileged operations or the service's availability | destructive operations, consistent authorization, timeouts, circuit breakers |
| P2 Medium | application logic and defence in depth: serious, but behind another control or limited in reach | input validation, error handling, data exposure, service credentials |
| P3 Low | best practice and compliance: hardening whose absence weakens other controls rather than opening a flaw by itself | security headers, request signing beyond TLS, distributed sessions |

Which priority each guarantee has is part of the catalogue; it was checked against this criterion in the block-6
test review (now complete). The tool's declared priorities are authoritative (the generated table in
[`../05-tests/README.md`](../05-tests/README.md), printed by `apiguard list-tests`); the thesis catalogue keeps its
own tags for the record.

In the tool the priority orders the work and nothing else: `execution.min_priority` keeps the tests up to a
priority, and `execution.fail_fast` stops after the first P0 test that fails or errs
([`assessment-model.md`](../04-architecture/03-assessment-model.md#fail-fast)). A Finding carries no severity: how
serious it is for the target's business is the analyst's judgement.

## Sources

OWASP API Security Top 10 2023, its risk rating
([API Security Risks](https://api-security.owasp.org/editions/2023/en/0x10-api-security-risks)) and the
[OWASP Risk Rating Methodology](https://owasp.org/www-community/OWASP_Risk_Rating_Methodology); OWASP ASVS 5.0.0;
NIST SP 800-204 and 800-204A; NIST SP 800-63B-4; RFC 7519, RFC 8725, RFC 9110.

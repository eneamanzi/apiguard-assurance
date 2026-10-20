# Target Selection

> **Audience:** readers of the research, contributors · **Status:** the requirements for the target application of
> the thesis test scenario (chapter 5), adapted to English and to the labs of today · **Original:**
> `git show 694f89a:docs/knowledge/target-selection.it.md` · **Verified:** 2026-10-20

What a target application must offer for the tool to assess it, and the applications considered. The tool itself is
agnostic of the target ([design property D1.P1](design-properties.md)); these requirements describe what makes an
application a *good* target for development and for demonstrating the methodology. What each test needs from a
target, and what happens without it, is in
[Test portability](../reference/compatibility.md#test-portability); the labs are in
[Test lab](../reference/compatibility.md#test-lab).

All candidates are deployed behind an API gateway, configured as the single entry point for the tests of domains 0
and 4 of the methodology.

## Requirements

### Group A: mandatory

| ID | Requirement |
|---|---|
| A1 | A complete OpenAPI or Swagger specification, downloadable and checked in CI. |
| A2 | Bearer token authentication (JWT or OAuth2) with explicit login, logout and refresh endpoints. |
| A3 | Role-based access control with at least three predefined hierarchical roles, configurable without changing code. |
| A4 | A pure REST API (JSON, standard HTTP methods, meaningful status codes). |
| A5 | Self-hostable: deployable on Kubernetes (Helm chart) or Docker Compose. |
| A6 | An OSI-approved open source licence (MIT, Apache 2.0, AGPL). |

### Group B: strongly recommended

| ID | Requirement | Needed for |
|---|---|---|
| B1 | Webhooks or calls to user-configurable external URLs. | SSRF tests |
| B2 | Destructive operations through the API (DELETE on critical resources, with a separate privilege check). | 2.3 |
| B3 | Multi-tenancy or isolation between the resources of different entities. | Realistic BOLA tests |
| B4 | An external session store (Redis or a database) instead of in-process memory. | Multi-replica clusters |

### Group C: to avoid

| ID | Requirement to avoid |
|---|---|
| C1 | A specification generated dynamically without completeness guarantees. |
| C2 | Permission systems based on arbitrary JSON policies instead of predefined roles. |
| C3 | Hybrid non-REST protocols (OCS, HAL+JSON, WebDAV). |
| C4 | Dependencies on mandatory external SaaS services. |

## Candidates

| Application | Outcome |
|---|---|
| Nextcloud | Discarded: its API is not pure REST (OCS), incompatible with the methodology (C3). |
| Gitea / Forgejo | Chosen as the reference target. |
| Mattermost | Considered. |
| Harbor | Considered. |

The thesis records the requirements and the candidates but not the reasons for choosing Forgejo over Mattermost and
Harbor; they are not recorded elsewhere (open question Q-33).

## The labs today

| Lab | Target | Gateway | Why it exists |
|---|---|---|---|
| `forgejo-kong/` | Forgejo | Kong (DB-less) | The reference lab. |
| `crapi-kong/` | OWASP crAPI | Kong, same configuration as the reference lab | A second API: only the API changes between the two labs. |
| `forgejo-apisix/` | Forgejo | Apache APISIX | A second gateway: only the gateway changes with respect to the reference lab. |

The two additions (2026-10-10 to 2026-10-14) exist so that the tool is shown to run, with nothing of either wired in
the code, on an API and a gateway other than Forgejo and Kong
([design decisions D7](../architecture/design-decisions.md#d7-neutral-gateway-concepts)). Where the requirements
above are not met to the letter, the tool does not assume them: for example, Forgejo creates a token through its API
instead of offering the login, logout and refresh endpoints of A2, and crAPI has no revocation of tokens; both are
handled by the login and revocation settings of the
[prepared resources](../reference/configuration.md#resources), and test 1.4 returns SKIP where a target cannot
revoke.

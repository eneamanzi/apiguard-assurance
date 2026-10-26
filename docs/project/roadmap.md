# APIGuard Assurance - Roadmap

> **Audience:** project owner, contributors · **Status:** current (2026-10-26). Single source of truth for what is
> implemented and what is on the backlog. The authoritative list of implemented tests is the tool itself
> (`apiguard list-tests`); this file groups them and records what is deliberately not implemented yet.

- [Legend](#legend)
- [Implemented tests](#implemented-tests)
- [Backlog](#backlog)
- [Connectors](#connectors)

## Legend

| Symbol | Meaning |
|--------|---------|
| `[x]`  | Implemented (verified in `apiguard list-tests`). |
| `[ ]`  | On the backlog: not implemented. |

The symbol describes a **test**, not a guarantee: a guarantee may be covered by a native test and one or more
external tests. Priorities and strategies below are the ones each test declares in its `TestInfo` (the tool prints
them); priority is importance only (`03-methodology.md`), independent of strategy.

**Naming:** native tests `X.Y` (e.g. `2.1`); external tests `ext.X.Y.tool` (e.g. `ext.1.5.testssl`), the tool
suffix keeping the ID unique when several tools cover one guarantee.

---

## Implemented tests

32 tests after the block-6 test review (29 native + 3 external). Strategy / priority as declared.

### Domain 0 - API Discovery & Inventory

| ID | Strategy | Priority | Guarantee |
|----|----------|----------|-----------|
| 0.1 | BLACK_BOX | P0 | Undeclared methods, undocumented versions |
| 0.2 | BLACK_BOX | P0 | Paths without a route |
| 0.3 | BLACK_BOX | P0 | Deprecated operations still served |
| 0.4 | WHITE_BOX | P0 | Backend reachable without the gateway (gateway bypass, CWE-288) |
| ext.0.1.ffuf | BLACK_BOX | P0 | Undocumented paths answer (ffuf path search) |

### Domain 1 - Identity & Authentication

| ID | Strategy | Priority | Guarantee |
|----|----------|----------|-----------|
| 1.1 | BLACK_BOX | P0 | Credential required on documented endpoints |
| 1.2 | GREY_BOX | P0 | Credential cryptographically valid |
| 1.3 | GREY_BOX | P0 | Credential expiry |
| 1.4 | WHITE_BOX | P2 | Credential revocation |
| 1.5 | BLACK_BOX | P2 | Credentials over an insecure channel |
| ext.1.5.testssl | BLACK_BOX | P2 | TLS stack analysis (testssl.sh) |
| 1.6 | GREY_BOX | P3 | Session cookie safety |
| 1.7 | GREY_BOX | P1 | Authentication endpoints resist guessing |

### Domain 2 - Authorization

| ID | Strategy | Priority | Guarantee |
|----|----------|----------|-----------|
| 2.1 | GREY_BOX | P1 | Function-level authorization |
| 2.2 | GREY_BOX | P0 | Object-level authorization (BOLA, API1:2023) |
| 2.4 | BLACK_BOX | P1 | Authorization consistency |
| 2.5 | GREY_BOX | P1 | Object property-level authorization |

### Domain 3 - Data Integrity

| ID | Strategy | Priority | Guarantee |
|----|----------|----------|-----------|
| 3.3 | WHITE_BOX | P3 | Request signing audit |
| ext.3.1.schemathesis | BLACK_BOX | P2 | Input validation (Schemathesis) |

### Domain 4 - Availability & Resilience

| ID | Strategy | Priority | Guarantee |
|----|----------|----------|-----------|
| 4.1 | BLACK_BOX | P0 | Rate limiting |
| 4.2 | WHITE_BOX | P1 | Timeout configuration audit (prevention) |
| 4.3 | WHITE_BOX | P1 | Circuit breaker audit |
| 4.4 | BLACK_BOX | P1 | Request size limits |

### Domain 5 - Observability

| ID | Strategy | Priority | Guarantee |
|----|----------|----------|-----------|
| 5.1 | WHITE_BOX | P1 | Request logging audit |
| 5.2 | WHITE_BOX | P2 | Security alerting audit |

### Domain 6 - Configuration & Hardening

| ID | Strategy | Priority | Guarantee |
|----|----------|----------|-----------|
| 6.1 | GREY_BOX | P2 | Error and information disclosure |
| 6.2 | BLACK_BOX | P3 | Security headers audit |
| 6.4 | BLACK_BOX | P2 | Hardcoded credentials audit |

### Domain 7 - Business Logic & Sensitive Flows

| ID | Strategy | Priority | Guarantee |
|----|----------|----------|-----------|
| 7.1 | BLACK_BOX | P1 | Sensitive business flow protection (anti-automation) |
| 7.2 | GREY_BOX | P0 | Server-side request forgery prevention |
| 7.3 | GREY_BOX | P1 | Race conditions in critical operations |
| 7.4 | BLACK_BOX | P1 | Webhook signature verification |

---

## Backlog

Not implemented yet. Most of these follow from the block-6 test review: detector branches a lab never exhibited (a
live violation was not produced, the detector is sound), external tools not wired where the review chose native or
deferred, and deeper sub-tests the methodology lists. None needs a decision from the owner to exist here; each is
work to pick up.

### New guarantees / tests

| ID | Why not yet |
|----|-------------|
| 2.3 | Candidate authorization test; not designed yet |
| 6.3 (+ `ext.6.3.socket`) | HTTP request smuggling: a raw-socket CL.TE / TE.CL probe and the layer-7 timeout audit; split out and deferred |

### External tools not wired

| Tool / test | Why not wired |
|-------------|---------------|
| `ext.1.2.jwt_tool`, `ext.1.3.jwt_tool` (jwt_tool) | Key-based JWT attacks (algorithm confusion, forged `exp`) need signing-key or JWKS material the target must supply (`NEEDS_KEY_MATERIAL`); a native `jwt_forge.py` helper stays planned for when a key is available |
| `ext.4.1.vegeta`, `ext.7.3.vegeta` (vegeta) | 4.1 uses a native burst and 7.3 a native concurrent burst now; vegeta's precise load / last-byte-sync would be wired when a case needs it |
| `ext.7.2.interactsh`, `ext.7.4.interactsh` (out-of-band listener) | Confirming a blind SSRF outbound call (7.2) and a blind webhook callback / replay (7.4) needs a URL the tool controls; the listener is the heaviest build and fragile on Docker, deferred. Until then 7.2 reports an accepted URL as `NOT_VERIFIABLE/OUTBOUND_NOT_CONFIRMED` |
| `ext.0.1.katana` (katana) | Headless crawling for JS-rendered endpoints, beyond ffuf's wordlist search |
| nuclei (connector present, not wired) | `ext.0.1.nuclei` was replaced by `ext.0.1.ffuf` in the review; the `NucleiConnector` stays in the codebase but no external test uses it. Decision pending: wire a nuclei-based test, or remove the connector (as sslyze was removed) |

### Deeper sub-tests and live cases

| Area | What |
|------|------|
| Live violations | Produce a live VIOLATION on a lab (announced gateway change) for branches proven only by the detector's logic: a leaked header / stack trace (6.1), a debug/config secret (6.4), a version that drops auth (2.4), a bound mass-assignment field (2.5), a gateway with no breaker / health check (4.3); a CAPTCHA/throttle on a sensitive flow (7.1 `ENFORCED`), a once-only operation that serializes (7.3), a webhook that verifies its HMAC (7.4) |
| 1.4 | Password-change revocation (crAPI's stateless-JWT challenge): a configured OTP / reset flow |
| 2.2 / 2.5 | Coverage option (b): derive candidate object endpoints (list a collection, take an owned id) instead of only the configured `owned_object_resources` |
| 3.1 | Deep injection confirmation (sqlmap, NoSQLMap, Dalfox, commix, SSTImap) and an authenticated Schemathesis run (write bodies); Schemathesis is wired unauthenticated now |
| 3.3 | Verify ASVS v5.0.0-4.1.5 on source and add it to the references |
| 5.1 / 5.2 | Log-content checks (fields, redaction, real IP, injection) and behavioural alert checks (brute-force alert, dedup, threshold): need read access to the logs and an alert webhook the tool can observe |

### Ideas (not planned)

- **External tools in containers or as HTTP services.** Run the external tools from containers, or call them as
  services, instead of local binaries; the target would then be reached by a service name. A first, never-wired
  attempt (`effective_base_url`, `<TOOL>_SERVICE_URL`) was removed in 2026-10; to be designed for real if the
  integration into another product needs it.
- **Prepared resources proposed from the specification.** Resources (`config.yaml` `resources:`, the login among
  them) are written by hand today. A command, like `generate-seed` for `path_seed`, could propose them from the
  OpenAPI specification (the login operation, the token field, a create/delete pair for an object): a proposal for
  the user to check, never applied automatically.

### Project decisions

- **Licence (next to settle).** `pyproject.toml` leaves the licence unspecified on purpose. The choice depends on
  the university regulations and on how the product APIGuard is integrated into will be distributed; to settle
  before any public release or distribution.
- **Release 1.0.0.** After an owner review of the usage and integration guides and the entry points (README,
  CONTRIBUTING, index), tag 1.0.0 (the block-6 review changed test IDs and behaviour, so the release follows it).

---

## Connectors

### Implemented and wired

| Connector | Pinned version | Type | Used by |
|-----------|----------------|------|---------|
| testssl.sh | `3.2.3` | subprocess | ext.1.5.testssl |
| ffuf | `2.3.0` | subprocess | ext.0.1.ffuf |
| schemathesis | `>=3.39,<4` (Python extra `[schemathesis]`) | subprocess | ext.3.1.schemathesis |

### Present but not wired

| Connector | Type | Status |
|-----------|------|--------|
| nuclei | subprocess | `NucleiConnector` present; no external test uses it since `ext.0.1.nuclei` was replaced by `ext.0.1.ffuf`. Keep (wire a nuclei test) or remove: decision pending |

### Not implemented

| Connector | Pinned version | Type | Tests | Notes |
|-----------|----------------|------|-------|-------|
| jwt_tool | `2.3.0` | subprocess | ext.1.2.jwt_tool, ext.1.3.jwt_tool | Needs key material; unlocks the key-based JWT cases |
| katana | `1.6.1` | subprocess | ext.0.1.katana | Headless crawling for JS-rendered endpoints |
| vegeta | `12.13.0` | subprocess | ext.4.1.vegeta, ext.7.3.vegeta | Precise load / last-byte-sync |
| interactsh | `1.3.1` | subprocess | ext.7.2.interactsh, ext.7.4.interactsh | Out-of-band server for blind SSRF / consumption |

**Cat B (optional, a native path exists):** cherrybomb (0.2, 2.2), OFFAT (2.2, 2.3), oasdiff (0.3), trufflehog /
gitleaks / detect-secrets (6.4), gau (0.1), http2smugl (ext.6.3.socket). Deferred; wired only if a target needs
what the native path cannot give.

> **Connector decision log:**
> `kiterunner` removed (abandoned) → `ffuf`.
> `crlfuzz` removed (abandoned) → CRLF coverage via nuclei template.
> `smuggler` removed (no official release) → raw socket Python connector for CL.TE / TE.CL.
> `race-the-web` removed (abandoned) → `vegeta` for 4.1 and 7.3.
> `jwtXploiter` removed (unmaintained) → `jwt_tool`.
> `Gopherus` removed (abandoned) → nuclei templates.
> `sslyze` removed (test review): AGPL v3 and no added value over testssl.sh for 1.5.

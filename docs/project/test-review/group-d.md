# Group D: guarantee 1.5 (working file)

> **Audience:** the owner and me, during the review. Method: the six phases in
> [`test-review.md`](../test-review.md) (How we work).

| Phase | State |
|---|---|
| 1. Collection | done 2026-10-22 (below) |
| 2. Design | done 2026-10-22; owner decisions below |
| 3. Code | done 2026-10-22 |
| 4. Proof | done 2026-10-22, the three labs plus two tool-configuration cases (below) |
| 5. Self-review | done 2026-10-22; the design held, no fix needed (below) |
| 6. Documentation | done 2026-10-22; the owner's commit left |

**The pages are now:** [`1.5`](../../05-tests/domain-1/1-5-credentials-over-an-insecure-channel.md) (native) and
[`ext.1.5.testssl`](../../05-tests/external/domain-1/ext-1-5-testssl.md). What stays here is the collection, the
boundary, the decisions and the review.

### Standards verified on the source (rule 8, 2026-10-22)

ASVS 5.0.0 renumbered the chapters: the references first drafted were wrong and were corrected against the source.

| What | Correct ASVS 5.0.0 id | Where |
|---|---|---|
| HSTS (Strict-Transport-Security on all responses, max-age >= 1 year, subdomains for L2+) | **3.4.1** (V3 Web Frontend Security) | native 1.5 (`hsts_present`) |
| TLS on all connectivity to external HTTP services, no cleartext fallback | **12.2.1** (V12 Secure Communication) | native 1.5 (`credential_forced_onto_tls`) |
| only the latest TLS versions enabled (TLS 1.2/1.3) | **12.1.1** (V12 Secure Communication) | ext.1.5.testssl (`tls_configuration`) |

The first draft put HSTS at 12.1.1 and TLS at 14.2.1; 12.1.1 is the TLS-version requirement and V14 is Data
Protection, not TLS. Verified on the v5.0.0 chapter files.

### Results on the labs (phase 4, 2026-10-22)

| Lab | `1.5` native | `ext.1.5.testssl` | Probe path, HTTP answer |
|---|---|---|---|
| forgejo + Kong | **PASS** complete | **PASS** partial | `/api/v1/orgs`: HTTP 301 -> https, HTTPS 200 + HSTS compliant |
| crAPI + Kong | **PASS** complete | **PASS** partial | `/workshop/api/mechanic/`: HTTP 301 -> https, HTTPS 401 + HSTS compliant |
| forgejo + APISIX | **PASS** complete | **PASS** partial | `/api/v1/orgs`: HTTP 301 -> https, HTTPS 200 + HSTS compliant |

`ext.1.5.testssl` is PASS **partial** everywhere: `tls_configuration` ENFORCED (no HIGH/CRITICAL weakness) plus
`CERT_REVOCATION_NOT_CHECKABLE` NOT_VERIFIABLE (the private CA has no OCSP/CRL), with a note. HSTS is confirmed
present and compliant on the API responses of all three labs (collection left it "to confirm"); the HTTP listener
redirects the documented path to HTTPS on all three (Kong drops the port in the `Location`, APISIX keeps it, the
oracle checks the scheme).

**The three situations of rule 9, all without a gateway change.** The weakness-absent side is the three labs above.
The weakness-present side was proven by two **tool-configuration** cases (rule 9 allows the tool's configuration as
a source), so the announced weak-TLS gateway change was not needed:

| Situation | Case | Result |
|---|---|---|
| present, native | `base_url` set to the plain-HTTP listener (`http://localhost:8000`), the specification kept on HTTPS | **1.5 FAIL**, VIOLATION/PLAIN_HTTP |
| present, external | the specification kept on HTTPS, `target.tls` set to `verify: false` (no `ca_bundle`), so testssl scans without `--add-ca` | **ext.1.5.testssl FAIL**, VIOLATION/TLS_WEAKNESS (`cert_chain_of_trust` CRITICAL: the private chain is untrusted) |
| not verifiable | the revocation branch on every lab | NOT_VERIFIABLE/CERT_REVOCATION_NOT_CHECKABLE |

The owner approved a weak-TLS gateway change for the external present-case; a config-only path (withholding the
`ca_bundle`, which makes the private certificate's chain untrusted, a genuine CRITICAL TLS finding) proved the same
oracle branch (HIGH/CRITICAL -> VIOLATION) more cleanly, so the gateway was left untouched.

### Self-review (phase 5, 2026-10-22)

Reread against the boundary table; the design held, no code fix needed.

- The native probe path is the shortest documented one (`/api/v1/orgs`, `/workshop/api/mechanic/`): the choice does
  not change the verdict (every documented path must be forced onto TLS and carry HSTS), and probing a documented
  path instead of `/` is exactly the fix that makes the labs PASS where the old test false-FAILed on `/` (HSTS is on
  the API, absent on the unrouted `/`).
- `security_headers` (MEDIUM) and `engine_problem` (WARN) come back from testssl as notes, not verdicts: HSTS is
  judged by native 1.5 (rule 10, one question one test), and testssl's header line is surfaced as information only.
- A plain-HTTP probe that gets no response is recorded ENFORCED (the HTTP port did not serve the request, so no
  credential crossed a cleartext channel): a reasoned exception to rule 4 for this probe, whose whole question is
  whether the HTTP port serves. A filtered or closed HTTP port therefore reads as enforced (the secure reading); a
  limitation noted on the page.

Group D is one guarantee, 1.5 (credentials never travel on an insecure channel). It already has three tests on
`main`: `1.5` (native: HTTP redirect + HSTS), `ext.1.5.testssl`, `ext.1.5.sslyze`. The review rebuilds them on the
new base and decides the native/external boundary and whether two TLS scanners earn their place.

---

### Decided (owner, 2026-10-22)

1. **One external TLS test, backed by testssl.sh.** `ext.1.5.sslyze` is removed as an always-on test; the sslyze
   connector stays as an enable-able alternative (selected by the existing `external_tools.<tool>.enabled` flags, no
   new parameter), so a target with only sslyze installed still gets its TLS scan.
2. **`cert_revocation` on a private CA -> TENTATIVE with a note**, not FAIL: it is reported but not read as a
   cleartext-interception failure the way a weak protocol is.
3. **Weak-TLS lab variant: yes, announced.** I change one lab's gateway to accept TLS 1.0/1.1 (or a weak cipher),
   run the external test, then undo it and verify the restore; I announce the exact change before touching the lab.

## Phase 1: collection (2026-10-22)

Measured today on the three running labs, read-only (curl, openssl s_client, with the lab CA
`test-environments/pki/ca.crt`).

### The guarantee (methodology 1.5, read on `04-guarantees.md`)

Credentials travel only over TLS 1.2+; the gateway enforces HTTPS (301/308 redirect or port closed) and HSTS;
cipher suites give forward secrecy (ECDHE) and authenticated encryption (AES-GCM). The configuration part (HSTS,
protocols, ciphers, certificate) is checkable statically or with a handshake scan; the redirect behaviour is the
one part that needs an active request (it cannot be read from a configuration). References: OWASP API2:2023,
RFC 9110 section 4.2.2, NIST SP 800-52 Rev.2, OWASP ASVS v5.0.0 V12.1.1, V12.1.2, V14.2.1 (each to verify on its
source in phase 6).

### TLS handshake, per lab (openssl s_client)

| Lab | TLS 1.0 | TLS 1.1 | TLS 1.2 | TLS 1.3 | 1.2 cipher | Certificate |
|---|---|---|---|---|---|---|
| forgejo + Kong (:8443) | refused | refused | up | up | ECDHE-RSA-AES256-GCM-SHA384 | private CA, CN=localhost |
| crAPI + Kong (:9443) | refused | refused | up | up | ECDHE-RSA-AES256-GCM-SHA384 | private CA, CN=localhost |
| forgejo + APISIX (:10443) | refused | refused | up | up | ECDHE-RSA-AES128-GCM-SHA256 | private CA, CN=localhost |

All three are a **clean** TLS configuration: only 1.2/1.3, forward-secret AEAD ciphers. The certificate is signed by
the lab's private CA ("APIGuard Lab CA"), CN=localhost, valid 2026-10-15 to 2027-04-13, with **no OCSP/CRL**
(no authorityInfoAccess, no crlDistributionPoints). With the configured `ca_bundle` the chain validates (verify
code 0); without it the chain is untrusted (a private CA). So the labs give the **weakness-absent** side for
protocols and ciphers; a present weakness needs a lab variant (a gateway listener with TLS 1.0/1.1 or a weak
cipher), documented and undone (rule 9).

### HTTP enforcement, per lab (plain HTTP to the gateway's HTTP listener)

| Lab | HTTP `/` | HTTP on a documented API path | Redirect target |
|---|---|---|---|
| forgejo + Kong (:8000) | 404 (port open, no route) | **301** | `https://localhost/...` (Kong **drops the port**) |
| crAPI + Kong (:9000) | 404 | **301** (e.g. `/identity/api/auth/login`) | `https://localhost/...` (port dropped) |
| forgejo + APISIX (:10000) | 404 | **301** | `https://localhost:10443/...` (port kept) |

Two facts that change the design:

1. **The redirect is path-dependent.** Kong and APISIX redirect to HTTPS only on a path they have a route for; on
   `/` (no route) the HTTP listener answers 404 in cleartext. The current test probes `/`, so it sees the 404 and
   not the 301 that a real credential-bearing path gets. The probe must go to a **documented API path** (where the
   credential actually travels), derived from the surface, not to `/`.
2. **Kong drops the port in the `Location`** (`https://localhost/...`, implicit 443). In the lab this points at a
   port that is not mapped, but the scheme is `https` and the status is a permanent redirect: correct behaviour for
   a real target (443), a lab artifact otherwise. An oracle that reads the `Location` must check the **scheme is
   https**, not the port.

The HTTP listener is open on every lab (the lab maps it to 8000/9000/10000, not 80). Deriving the HTTP URL by only
swapping the scheme on `base_url` gives `http://localhost:8443`, which hits the TLS listener: the lab needs the
`http_url` override (the lab configs carry it, commented, pointing at 8000/9000/10000 and a real path). On a real
target (HTTPS on 443, HTTP on 80) the derivation works without the override.

### HSTS, per lab

| Lab | HSTS on `/` (404) | HSTS on a 200 API path |
|---|---|---|
| forgejo + Kong | **absent** | `max-age=31536000; includeSubDomains` (compliant) |
| crAPI + Kong | absent | to confirm in the run |
| forgejo + APISIX | absent | to confirm in the run |

**HSTS is present and compliant on the API responses, absent on `/`.** The current test checks `/` and so reports a
false FAIL (HSTS missing) while the credential-bearing API paths carry it. Like the redirect, the HSTS check must go
to a documented API response, not `/` (review note, Q-29). Boundary with 6.2: HSTS stays in 1.5 (6.2's review leaves
it here).

### The external tools

- **testssl.sh** is installed by `install_tools.sh` (into `tools/testssl`); the connector is `src/connectors/testssl.py`.
- **sslyze** is a Python library, optional (`pip install apiguard-assurance[sslyze]`, AGPL, Q-11); **not installed in
  this environment** (`sslyze lib: False`), so `ext.1.5.sslyze` would SKIP here until installed. The connector is
  `src/connectors/sslyze.py`.
- Both connectors normalise to the same `TlsFinding` shape (id, severity, finding, cve) and the test maps
  CRITICAL/HIGH -> FAIL, MEDIUM/WARN -> note, lower -> ignored.
- On the labs the scan will report **`cert_revocation` HIGH** (the private CA has no OCSP/CRL): a true gap in the
  abstract, but the expected and normal state of an internal private-CA gateway. The oracle's treatment of this is
  an open point below.

---

## Phase 2: design (presented 2026-10-22)

### The boundary (one question, one test; rule 10)

Group D is one guarantee, so the boundary is internal to 1.5: which part is the native test's and which the
external tool's.

| Question | Where |
|---|---|
| is the credential's request **forced onto TLS** (HTTP redirected to HTTPS or refused before the request is processed)? | **`1.5` native** |
| does an HTTPS response carry a compliant **HSTS** header? | **`1.5` native** (6.2 leaves HSTS here) |
| are the **TLS protocol versions, cipher suites, certificate and known TLS CVEs** sound? | **external** (a handshake scanner's job; we do not reimplement it, rule 11 / "start from the guarantee") |
| is the credential cryptographically valid / expired / revoked? | `1.2` / `1.3` / `1.4` (group C, done) |
| are the security headers other than HSTS configured? | `6.2` (its own review) |

The split is the HYBRID pattern already on `main`, kept because it is the right one: the HTTP-layer checks (redirect,
HSTS) are ours (they need the surface and the calibration, and a scanner pointed at the API does them poorly), while
the TLS handshake is exactly what testssl/sslyze are built for.

### `1.5` native -- Credentials over an insecure channel

- **Strategy** BLACK_BOX (network only). **CWE-319** (Cleartext Transmission). **Effect** READ_ONLY (one HTTP GET to
  a documented path, one HTTPS GET; no change to the target). **Needs** none beyond the target URL (the HTTP probe
  needs no credential; HSTS is checked without one, it must be on every response).
- **Standards** (verify on source in phase 6): API2:2023, RFC 9110 section 4.2.2, NIST SP 800-52 Rev.2,
  ASVS v5.0.0 V12.1.1 (HSTS), V14.2.1 (TLS).
- **Sub-tests:**
  - `credential_forced_onto_tls` -- send a plain-HTTP GET to a **documented API path** (derived from the surface;
    the `http_url` override wins where set, for a non-standard-port lab). Oracle: connection refused / reset ->
    ENFORCED (port closed); 301/308 whose `Location` scheme is **https** -> ENFORCED (CERTAIN); any 2xx, any other
    3xx (302/307, downgrade-able), any 4xx/5xx -> VIOLATION (the request with its credential crossed the cleartext
    channel before any answer), CERTAIN. A transport timeout -> NOT_VERIFIABLE (rule 4).
  - `hsts_present` -- GET a documented API path over HTTPS (not `/`). Oracle: header present, `max-age >=` a bound,
    `includeSubDomains` present -> ENFORCED; header absent -> VIOLATION/HSTS_MISSING (CERTAIN); max-age below the
    bound -> VIOLATION/HSTS_MAX_AGE_LOW (CERTAIN); includeSubDomains absent -> VIOLATION/HSTS_NO_SUBDOMAINS at
    lower confidence (FIRM: best practice, ASVS asks for it but a bounded max-age alone already enforces HTTPS).
- **Plain-HTTP target** (`base_url` is `http://`): both sub-tests -> VIOLATION/PLAIN_HTTP at CERTAIN, no probing
  needed (the worst transport state; never SKIP, which would hide it).
- **Evidence:** the HTTP probe is now sent through the client so it is recorded (fixes Q-50: the old httpx probe had
  `evidence_ref=None`). The derivation of the HTTP URL by scheme-swap is a documented step; the `http_url` override
  is kept for non-standard-port deployments (not a new parameter: it exists today).

### External TLS scan -- one test or two (the owner's decision)

The TLS handshake scan is a tool's job. Today it is **two** always-on tests, `ext.1.5.testssl` and `ext.1.5.sslyze`,
that scan the same host and map to the same oracle; their findings overlap almost entirely. Running both on every
target doubles the scan time and reports the same facts twice.

My recommendation: **one external TLS test backed by testssl.sh** (installed by `install_tools.sh`, actively
maintained, the most comprehensive on protocols/ciphers/CVEs, CVE-tagged), with **sslyze kept as a documented
alternative the operator can enable** (its connector stays; it is not a second always-on test). This follows "start
from the guarantee, pick the best tool, do not reimplement or duplicate it". It removes a test ID (`ext.1.5.sslyze`),
which touches the contract and the report, and it interacts with Q-11 (sslyze AGPL, set aside pending the
distribution model) -- so it is **yours to decide**.

The alternative: keep both as independent tests (status quo), each in the report. It buys a second opinion on the
certificate chain (sslyze's structured validation is stronger) at the cost of a duplicate scan.

### The external test's oracle (whichever tool backs it)

Sub-test `tls_configuration`. Each tool finding -> an outcome by its severity (rule 11; the tool's severity is kept
as information, it is not the oracle by itself):

| Tool finding | Outcome | Confidence |
|---|---|---|
| CRITICAL / HIGH on the target (weak protocol, weak cipher, known CVE, untrusted chain) | VIOLATION/`<id>` | FIRM (the tool observed it on the target; we did not re-derive it) |
| MEDIUM / WARN | a note, ENFORCED unless a VIOLATION is present | - |
| the scan could not connect / timed out | NOT_VERIFIABLE | - |
| no CRITICAL/HIGH finding | ENFORCED/NO_TLS_WEAKNESS | - |

**Open: `cert_revocation` on a private CA.** testssl reports `cert_revocation` HIGH on all three labs (no OCSP/CRL),
which would FAIL every lab. It is a real gap in the abstract but the normal state of an internal private-CA gateway.
Options: (a) keep it FAIL (it is a genuine missing control); (b) map a "revocation cannot be checked" finding to a
lower confidence (TENTATIVE) with a note, so it does not read as a cleartext-exposure failure; (c) when the target
is reached through a configured `ca_bundle` (a private CA, declared by the operator), treat revocation absence as a
note rather than a FAIL. I lean to (b): report it, but at TENTATIVE with the reason, since it is not a credential
interception risk the way a weak protocol is.

### The three situations on the labs (rule 9)

- **Weakness absent:** all three labs (clean 1.2/1.3, redirect enforced on API paths, HSTS compliant on API paths)
  -> native PASS, external ENFORCED (apart from the cert_revocation open point).
- **Weakness present:** (a) native -- a plain-HTTP variant of the target URL (config only, no lab change) gives the
  PLAIN_HTTP violation; and the `/`-vs-API-path contrast is itself the fix we are proving. (b) external -- a gateway
  listener that accepts **TLS 1.0/1.1 or a weak cipher**: a documented change to one lab's gateway TLS config,
  applied and undone, **announced before I touch the lab**. crAPI has no TLS weakness of its own to use here.
- **Not verifiable:** a target the scan cannot connect to (NOT_VERIFIABLE), and the HTTP probe timing out.

### Open points for the owner (phase-2 go-ahead)

1. **One external TLS test or two?** My recommendation: one, backed by testssl.sh, with sslyze kept as an optional
   alternative (connector stays, `ext.1.5.sslyze` removed as an always-on test). This removes a test ID (contract,
   report) and touches Q-11. Your call.
2. **`cert_revocation` on a private CA:** FAIL, or TENTATIVE-with-note (my lean), or a note only when a `ca_bundle`
   is configured. Your call, because it decides whether every private-CA gateway reads as a 1.5 failure.
3. **The weak-TLS lab variant** for the weakness-present side of rule 9: I will change one lab's gateway to accept
   TLS 1.0/1.1 (or a weak cipher), run the external test, and undo it, verifying the lab is restored. I will
   **announce the exact change before I make it** (announce-target-changes). Confirm you want me to prove it this
   way, or prefer a config-only path.

The internal design calls (probe a documented API path instead of `/`, read the `Location` scheme, record the HTTP
probe as evidence, new-base port with sub-tests and confidence) I will make as designed unless you object.

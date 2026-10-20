# Guarantees Catalogue

> **Audience:** readers of the research, contributors · **Status:** the catalogue of the thesis methodology
> (chapter 3), translated from Italian, **not yet aligned with the tool**; it is rewritten guarantee by guarantee in
> the test review (block 6, phase 0b, [`project/plan.md`](../../project/plan.md)) · **Original:**
> `git show 694f89a:docs/knowledge/methodology/methodology.it.md` · **Framework** (gradient, priorities, sources):
> [`framework.md`](framework.md)

> **Read this before relying on the page.** It is the thesis text, and the thesis predates several decisions. In
> particular:
>
> - **Priorities** (the `[P0]`-`[P3]` tags) are as the thesis gave them. They contradict the code in places (1.4 and
>   2.1 are P2 in the tests, P1 in the thesis's closing matrix; 2.2 is P1 in its heading and P2 in its matrix) and
>   will be checked against the importance criterion of [`framework.md`](framework.md#priorities).
> - **"Approach" of each guarantee** (black, grey, white box) is the thesis's, which mixed what the tester has with
>   the technique. The tool's strategy says what the tester has ([`framework.md`](framework.md#knowledge-and-privilege-gradient)):
>   for example 1.5, 1.6 and 6.2 are described here as configuration audits and are black box in the tool.
> - **Test logic** describes what the methodology asks for, not always what the test implements; what a test
>   implements, and what it leaves out, is on its page in [`tests/`](../../tests/README.md) ("Coverage against the
>   methodology").
> - **Construction details of attack inputs** (exact forged tokens, payload strings, step-by-step exploitation)
>   are summarised here by what is checked and the expected result; the full text is in the original.
> - Some sections cite the thesis documents (`TOOLS_catalog.md`, `4-Implementazione.md`) by their old names.

Each guarantee has the same parts: **references** (OWASP API Security Top 10 2023, ASVS 5.0.0, NIST, RFC),
**concept**, **failure scenarios**, **assumptions and prerequisites** (as the thesis wrote them), **test logic** (each
check against its oracle). 29 guarantees in 8 domains; 3.2 was merged into 6.1.

| Priority (thesis) | Guarantees |
|---|---|
| P0 | 0.1, 0.2, 0.3, 1.1, 1.2, 1.3, 4.1, 7.2 |
| P1 | 2.3, 2.4, 4.2, 4.3, 5.1, 6.3 (and 1.4, 2.1, 2.2 in places, see above) |
| P2 | 1.4, 1.5, 2.1, 2.2, 2.5, 3.1, 5.2, 6.1 (+3.2), 6.4, 7.1, 7.3, 7.4 |
| P3 | 1.6, 3.3, 6.2 |

---

## Domain 0. API discovery and inventory management

### 0.1 Every exposed endpoint is documented and authorised `[P0]`

**References:** OWASP API9:2023 Improper Inventory Management, NIST SP 800-204 §3.1, OWASP ASVS 5.0.0 V4.1.1.

**Concept.** Every endpoint active on the gateway corresponds to an entry in the official OpenAPI specification.
Active but undocumented endpoints, called shadow APIs, are an unknown attack surface: they are not subject to
security review, rate limiting or systematic authentication policies. The defence is an authoritative inventory
kept in the gateway's management plane.

**Failure scenarios.**

- **Legacy endpoint not removed.** During the move from API v1 to v2 the team drops the documentation for
  `/api/v1/users` but leaves the route on the gateway; the endpoint stays reachable, with no rate limiting.
- **Undocumented path behind a wildcard route.** The gateway has a catch-all `/*` forwarding everything to the
  backend. Paths such as `/api/internal/config` or `/api/debug/users` are not in the specification but answer
  `200 OK`, because the backend assumes the gateway filters upstream.
- **Inconsistent versioning.** The gateway exposes `/api/v1/`, `/api/v2/`, `/api/v3/` but the specification
  documents only v3; the older versions lack controls added later and escape security review.

**Assumptions and prerequisites (thesis).** Black box: only the base URL and, if public, the specification; no
token. The sub-test "documentation drift via the Admin API" needs read access to the gateway's Admin API (an additional
grey box approach, run if available).

**Test logic.**

- **Path enumeration by fuzzing** with standard API wordlists (SecLists `API-endpoints.txt`). Compare the paths that
  answer `2xx`, `401` or `403` with the documented endpoints; every active path missing from the specification is a
  shadow API. Include case and trailing slash variants.
- **HTTP method discovery.** For each documented endpoint send `OPTIONS` and compare the methods in `Allow` with
  those in the specification. A method that is allowed but undocumented must be checked: if processed (status other
  than `405`), it is unauthorised exposure.
- **Versioning completeness.** Try plausible version combinations (`v1`, `v2`, `v3`, `v1.0`, `version1`) for each
  documented endpoint. Versions that answer `2xx` or `401`/`403` are active; compare with the declared ones and check
  that security policies are the same across versions.
- **Documentation drift via the Admin API.** Fetch the gateway's actual route table (Kong `GET /routes`, AWS
  `get-resources`, Traefik `/api/http/routers`) and compare it programmatically with the specification. A route with
  no counterpart in the specification is configuration drift.

---

### 0.2 The gateway rejects requests to unregistered paths (deny-by-default) `[P0]`

**References:** NIST SP 800-204 §4.1, OWASP ASVS 5.0.0 V4.1.1, CIS Benchmark API Gateway Controls 2.3.

**Concept.** The gateway blocks any request whose path does not match an explicitly registered route, instead of
forwarding it to a default backend or a catch-all service. It acts as the primary enforcement point: `404 Not Found`
or `403 Forbidden` for unregistered paths, without revealing internal topology.

**Failure scenarios.**

- **Permissive wildcard catch-all.** `/*` forwards everything, so paths such as `/actuator/heapdump` (Spring Boot),
  `/debug/pprof` (Go) or `/api/internal/reset-db` are reached from outside.
- **Path normalisation bypass.** The gateway matches `/api/users` exactly but the backend normalises paths. A
  URL-encoded or double-slash variant is not recognised by the gateway, is forwarded, and is processed after the
  backend normalises it, bypassing the controls.
- **Case sensitivity mismatch.** The gateway registers `/api/users` (lowercase); a case-insensitive backend (for
  example Windows IIS) serves `/API/USERS`, which the gateway forwards to the default backend without authentication.

**Assumptions and prerequisites (thesis).** Black box: no token, no knowledge of the infrastructure; arbitrary
requests to invented paths and to variants of known paths.

**Test logic.**

- **Unregistered path rejection.** `GET` to paths guaranteed not to exist. Expected: `404` or `403`, with no stack
  trace, routing logic or backend identifiers in the body.
- **Path normalisation consistency.** For each documented endpoint generate variants (URL-encoded, double-encoded,
  path traversal, double slash, trailing slash, uppercase). If the path is legitimate, every normalised variant must
  apply the same authentication and rate limiting policies; if it does not exist, every variant must give `404`/`403`.
- **Default backend fallback detection.** Send requests to arbitrary paths and look at response headers: backend-specific
  headers (`X-Backend-Server`, `X-Application-Context`) show the request reached the backend, violating deny-by-default.

---

### 0.3 Deprecated APIs are disabled or more closely monitored `[P0]`

**References:** OWASP API9:2023 Improper Inventory Management, NIST SP 800-204 §3.1.3, OWASP ASVS 5.0.0 V4.1.1.

**Concept.** Endpoints marked `deprecated` in the API life cycle are either disabled (`410 Gone`) or subject to
stricter rate limiting and verbose logging during the transition. Deprecated endpoints get less patching and
monitoring while remaining exposed: a critical window.

**Failure scenarios.**

- **Vulnerability not back-ported.** A deprecated v1 holds an injection flaw fixed in v2 but not retroactively, because
  it is "being phased out"; nobody monitors v1 and it stays exploitable for the whole deprecation period.
- **Sunset header without enforcement.** The gateway returns a `Sunset` date but implements no control at that date;
  after it the endpoint keeps working as a "zombie API".

**Assumptions and prerequisites (thesis).** Black box for the accessibility sub-tests (implemented in Milestone 1):
no credentials, only the specification to find endpoints with `deprecated: true`. The differential rate limiting and
logging verbosity sub-tests need grey box (a standard user's token plus read access to the log aggregator or the
Admin API): planned for Milestone 2.

**Test logic.**

- **Deprecated endpoint accessibility.** Extract every endpoint with `deprecated: true`, check for the `Sunset`
  header with a `HEAD` request; if the sunset date has passed, a `GET` must give `410 Gone` (RFC 9110); `200 OK`
  after sunset means the life cycle is not enforced.
- **Differential rate limiting.** For deprecated endpoints still active (before sunset) run a burst of 100 requests
  in 60 seconds. Expected: a rate limit stricter than that of the equivalent non-deprecated endpoint (for example 10
  per minute against 100); equal limits mean equal treatment and no compensating measure.
- **Differential logging verbosity.** Check through the Admin API or the log aggregation system that deprecated
  endpoints log more (source IP, user identity, request body) than standard ones.

---

## Domain 1. Identity and authentication

### 1.1 Only authenticated requests reach protected resources `[P0]`

**References:** OWASP API2:2023 Broken Authentication, NIST SP 800-63B-4 §4.3.1, OWASP ASVS 5.0.0 chapter V6.3.

**Concept.** Every endpoint exposing sensitive data or privileged operations rejects requests without valid
credentials before reaching the business logic. Enforcement (bearer JWT or opaque OAuth2 tokens in `Authorization`)
happens at the gateway or in middleware with deny-by-default logic: a missing or invalid token gives `401
Unauthorized` at once.

**Failure scenarios.**

- **Complete bypass.** The endpoint does not check for `Authorization`; `GET /api/users/profile` without a token
  gives `200 OK` with the user's data.
- **Empty or malformed tokens accepted.** The API checks that the header is present but not its content:
  `Authorization: Bearer` with no token, or `Authorization: invalid-garbage`, are processed as authenticated.
- **Unprotected path normalisation.** The API protects `/api/users` but not `/api/Users` or `/api/users/`, because
  routing does not normalise paths before applying policies.

**Assumptions and prerequisites (thesis).** Black box: no token, no knowledge of the infrastructure; unauthenticated
requests, or with deliberately malformed tokens, to every protected endpoint documented in the specification.

**Test logic.**

- **No token.** Request without `Authorization`. Expected: `401`, with no sensitive data in the body. Run on every
  documented protected endpoint, not on a sample.
- **Empty and malformed token.** `Bearer` with an empty value, `Bearer null`, an arbitrary string. Expected: `401`
  in all cases, identical to a missing header.
- **Header case variations.** `authorization`, `AUTHORIZATION`, mixed case. Expected: `401` without a valid token
  (HTTP header names are case-insensitive, RFC 9110).
- **Path normalisation.** Case, trailing slash, double slash, `..` variants. Expected: all require authentication.

---

### 1.2 Credentials are cryptographically valid `[P0]`

**References:** OWASP API2:2023 Broken Authentication, RFC 8725 §3.2, OWASP ASVS 5.0.0 V9.1.1 and V11.5.1, NIST SP
800-63B-4 §4.3.1.

**Concept.** The gateway or the authentication middleware completely validates JWTs: extracts the signature,
recomputes it with the issuer's public key (RS256/384/512) or the shared secret (HS256/384/512), and compares it
byte by byte. Tokens with algorithm `none`, a tampered payload or signed with the wrong key are rejected with `401`.
Weak or deprecated algorithms are excluded by NIST SP 800-131A.

**Failure scenarios.**

- **Unsigned tokens accepted** (`alg: none`). Some legacy JWT libraries accept them, bypassing verification
  entirely (CVE-2015-9235).
- **Payload not verified.** The API decodes the token and reads the claims without checking the signature: a changed
  user identifier is accepted because the token is syntactically valid.
- **Algorithm confusion** (RS256 to HS256). The issuer signs with a private RSA key and the server validates with the
  public key; if the API accepts both algorithms without constraints, a token signed with the public key as an HMAC
  secret passes validation.

**Assumptions and prerequisites (thesis).** Grey box: at least one valid JWT obtained by a regular login, to read its
header and payload structure; for the algorithm confusion check, the public JWKS endpoint. No administrative access.

**Test logic** (each case with its expected result; construction details are in the original).

- **Unsigned token rejection.** Expected `401`.
- **Tampered payload.** A valid token with a changed claim and the original signature. Expected `401`.
- **Algorithm confusion.** A token whose algorithm differs from the one the issuer uses. Expected `401`: the server
  does not accept arbitrary algorithm switches (RFC 8725).
- **Signature stripping.** A valid token with the signature removed. Expected `401`, not interpreted as an implicit
  `alg: none`.
- **Key rotation resilience.** With a JWKS endpoint exposing two keys (old and new) during a 24 h grace period, a token
  signed with the old key gives `200 OK` within the window and `401` after it; check in the logs that the gateway
  selects the key by the `kid` header, and that the JWKS cache TTL is at most 300 seconds
  (`Cache-Control: max-age=300`).
- **Key ID mismatch.** A token signed with the old key but declaring the new key's `kid`. Expected `401`: the gateway
  checks that the signature matches the key the `kid` names.

---

### 1.3 Credentials are not expired `[P0]`

**References:** OWASP API2:2023 Broken Authentication, RFC 7519 §4.1.4, OWASP ASVS 5.0.0 V9.2.1, NIST SP 800-63B-4 §4.2.

**Concept.** The gateway compares the `exp` claim (Unix timestamp) with the current time and rejects tokens with
`now >= exp`. A leeway of ±60 seconds is acceptable for clock skew between issuer and validator. NIST SP 800-63B-4
recommends access tokens of 5-15 minutes, renewed with refresh tokens.

**Failure scenarios.**

- **`exp` ignored.** The API decodes the token but does not check expiry; a token stolen months ago stays usable.
- **Clock skew exploit.** Issuer and validator clocks differ by 10 minutes: valid tokens are rejected (clock ahead) or
  expired ones accepted (clock behind).

**Assumptions and prerequisites (thesis).** Grey box: the tester can generate or manipulate JWTs with arbitrary `exp`
(the signing key, or a valid token to derive a modified one) and has an authenticated endpoint to test; no
administrative access.

**Test logic.**

- **Expired token** (`exp` an hour in the past). Expected `401`.
- **Valid token** (`exp` a year ahead). Expected `200 OK`.
- **Clock skew** with a declared leeway of 60 s: expired 30 s ago gives `200 OK`; expired 90 s ago gives `401`.
- **Negative expiry** (`exp = -1` or `0`). Expected `401`, without a crash or undefined behaviour.

---

### 1.4 Credentials have not been revoked `[P2]`

**References:** OWASP API2:2023 Broken Authentication, RFC 7009 (OAuth 2.0 Token Revocation), RFC 7519 §4.1.7, OWASP
ASVS 5.0.0 V7.4 and V9, NIST SP 800-63B-4 §5.1.

**Concept.** Cryptographically valid and unexpired tokens that have been explicitly revoked (logout, password change,
reported compromise) are rejected. The implementation strategies (a central blacklist on Redis with the `jti` claim,
a versioning claim on a database, or short-lived tokens with refresh rotation) are architectural choices; the test
checks the resulting behaviour, not the internals.

**Failure scenarios.**

- **Pure stateless JWT without revocation.** The API validates only signature and expiry; after logout the token stays
  valid for the whole `exp` period (for example 15 minutes), so after a compromise the attacker keeps access.
- **Race condition in replication.** The token enters the blacklist on the primary Redis node but asynchronous
  replication adds a delay of 500 ms; in the propagation window a request to a replica not yet updated is accepted.

**Assumptions and prerequisites (thesis).** Grey box: valid credentials to log in, obtain a JWT and reach the logout
and password change endpoints; at least two distinct accounts for the concurrency tests; no access to the internal
session store.

**Test logic.**

- **Token after logout.** Log in, obtain a token, log out, reuse the token at once. Expected `401`.
- **Token after password change.** Log in, change the password (which must bump a token version in the database),
  reuse the old token. Expected `401`.
- **Idempotent logout.** Ten simultaneous logouts of the same token (threads). Expected: all `200 OK`, and the token
  appears in the blacklist exactly once.

---

### 1.5 Credentials are not sent over insecure channels `[P2]`

**References:** OWASP API2:2023, RFC 9110 §4.2.2, NIST SP 800-52 Rev. 2, OWASP ASVS 5.0.0 V12.1.1, V12.1.2 and V14.2.1.

**Concept.** Credentials travel only over TLS 1.2+, and the gateway enforces HTTPS (301/308 redirect) and HSTS. Cipher
suites must give forward secrecy (ECDHE) and authenticated encryption (AES-GCM). The configuration part (HSTS,
headers) is checkable statically; the protocol part needs an active scan.

**Failure scenarios.**

- **Plain HTTP accepted.** The API answers on both `:80` and `:443` with no redirect; a man in the middle downgrades
  the connection and the user sends `Authorization: Bearer token` in clear.
- **TLS 1.0/1.1 supported.** The server accepts deprecated protocols; an attacker forces a downgrade and decrypts
  traffic offline using known weaknesses (BEAST, POODLE).

**Assumptions and prerequisites (thesis).** "White box, configuration audit" (with one empirical test for the HTTP
redirect): access to the server's TLS configuration (`nginx.conf`, `httpd.conf` or the gateway's equivalent), or the
parameters from the infrastructure team. The `testssl.sh` scan needs only network connectivity. (In the tool, 1.5 is
black box: the checks below are observed from outside.)

**Configuration audit (checklist).**

- **[audit]** Enabled protocols are only TLS 1.2 and 1.3 (`ssl_protocols` in Nginx or equivalent must not include
  `TLSv1`, `TLSv1.1`, `SSLv3`); document the exact parameter and value.
- **[audit]** Cipher suites (NIST SP 800-52 Rev. 2): for TLS 1.3 only AEAD suites; for TLS 1.2 only ECDHE with GCM; no
  static RSA key exchange (no forward secrecy).
- **[audit]** The certificate has a future expiry date, comes from a CA trusted by Mozilla, and its CN/SAN matches
  the hostname (for example `openssl s_client -connect host:443 -showcerts`).
- **[audit]** At least 2 SCTs from distinct Certificate Transparency logs, in the certificate or the handshake
  (RFC 6962).
- **[empirical test]** `GET http://host/users/me` over plain HTTP with a valid token. Expected: connection refused
  (port 80 closed) or a `301`/`308` redirect to HTTPS without processing the request. The only active test needed:
  the redirect behaviour cannot be deduced from configuration.
- **[audit]** The HTTPS response carries `Strict-Transport-Security: max-age=31536000; includeSubDomains` (ASVS
  V12.1.1), checkable with one `curl -I`.

---

### 1.6 Sessions are managed securely in distributed architectures `[P3]`

**References:** OWASP API2:2023, OWASP ASVS 5.0.0 V3.2.1, V3.2.3 and V3.2.4, NIST SP 800-63B-4 §4.2, NIST SP 800-204A
§4.3.

**Concept.** Management of hybrid sessions (cookie plus refresh token) in multi-region deployments, where the
consistency of the session store (Redis Cluster, DynamoDB global tables) is critical for cross-node revocation and for
preventing session fixation. Being strongly dependent on the internal architecture, it is only partly checkable from
outside and is treated as an architectural best practice.

**Failure scenario.**

- **Session fixation.** An attacker obtains a pre-authentication session cookie from a public endpoint; the victim logs
  in with the same browser; the gateway does not regenerate the session ID; the attacker's cookie is now authenticated
  as the victim.

**Assumptions and prerequisites (thesis).** "White box, configuration audit": read access to the session store's
configuration (Redis TTL policy, replication mode) and to the cookie settings in the gateway or application
middleware; the one empirical test (session fixation) needs a browser and a valid account. (In the tool, 1.6 is black
box: it checks the cookies a target sets.)

**Configuration audit (checklist).**

- **[audit]** Session cookies are issued with `HttpOnly`, `Secure` and `SameSite=Strict` (ASVS V3.2.3), from the
  `Set-Cookie` header of a login response.
- **[audit]** The session key's TTL in the store matches the JWT lifetime (`exp`): a TTL greater than the JWT's allows
  reuse after expiry.
- **[audit]** The store's replication mode is synchronous, or the asynchronous propagation window is documented and
  accepted as a risk (in Redis Cluster at most 100 ms for high-risk contexts).
- **[empirical test]** Session fixation: capture the pre-authentication cookie, log in, check that the value differs
  after authentication (ASVS V3.2.1). Necessarily empirical: it checks runtime behaviour.
- **[audit]** Session tokens have at least 128 bits of randomness from a CSPRNG (ASVS V3.2.4); it suffices to check
  that the library used produces it by definition.

---

## Domain 2. Authorization and access control

### 2.1 Only authorised users reach privileged endpoints `[P2]`

**References:** OWASP API5:2023 Broken Function Level Authorization, OWASP ASVS 5.0.0 V8.3.1 and V8.2.2, NIST SP
800-53 Rev. 5 AC-3.

**Concept.** After authentication, the gateway or the application middleware performs role-based access control
(RBAC, NIST SP 800-162): every privileged endpoint rejects with `403 Forbidden` the requests of authenticated users
who lack the required role or scope. Authentication proves "who you are"; authorization proves "what you may do".

**Failure scenarios.**

- **Client-side control.** The interface hides the "Delete User" button for non-admins, but the API does not check the
  role; a direct request to `DELETE /api/users/123` succeeds.
- **Inconsistency between HTTP methods.** `GET` and `DELETE` on `/api/users/{id}` require authentication and the admin
  role, but `PATCH` forgets the check; an ordinary user can modify data.

**Assumptions and prerequisites (thesis).** Grey box: valid JWTs for at least two distinct roles (for example `user`
and `admin`), knowledge of the privileged endpoints in the OpenAPI document (methods and roles required), and an
environment to run the calls against.

**Test logic.**

- **Admin endpoint with a user token.** Log in as an ordinary user and call a privileged endpoint. Expected `403`
  (not `401`, since authenticated; not `200`). Repeat for every documented privileged endpoint.
- **HTTP method confusion.** Test every method (GET, POST, PUT, PATCH, DELETE, HEAD, OPTIONS) on each resource;
  each must carry the appropriate authorization check.
- **Role hierarchy.** With a hierarchy such as `superadmin > admin > moderator > user` (NIST SP 800-162), a
  `moderator` reaches `moderator` endpoints but not `admin` ones.

---

### 2.2 Users access only their own data (BOLA prevention) `[P1]`

**References:** OWASP API1:2023 Broken Object Level Authorization, CWE-639, OWASP ASVS 5.0.0 V8.2.2, NIST SP 800-162
§2.2.

**Concept.** The system applies ownership checks at object level: a user can access only the resources they own. BOLA
(number 1 in the OWASP list) appears when the API uses a client-controlled identifier (an ID in the URL or body)
without checking that it matches the authenticated user. The typical backend check is
`WHERE id = {resourceId} AND userId = {tokenUserId}`.

**Failure scenarios.**

- **Sequential enumeration.** With incrementing IDs, an authenticated user calls `GET /api/orders/1`, then 2, up to
  1000 in a loop and downloads every order in the system.
- **Modifying others' objects.** `PATCH /api/orders/100` setting the status to cancelled, from a user who does not
  own order 100.

**Assumptions and prerequisites (thesis).** Grey box: valid JWTs for at least two distinct accounts (userA and userB),
each with at least one resource created and identified; the IDs of each user's resources, obtainable from earlier
GET calls after login.

**Test logic.**

- **Cross-user data access.** userA gets an order; userB requests it. Expected `403` or `404` (not revealing its
  existence, CWE-639).
- **Sequential ID enumeration.** Check the ID of one's own order and test the neighbouring IDs. Expected `403`/`404`;
  repeat on at least 10 consecutive IDs.
- **Modifying others' objects.** userB tries to modify userA's order. Expected `403`; a later GET as userA confirms it
  was not modified.
- **Mass assignment protection.** Create an order passing a `userId` that is not the token's. Expected: the order is
  created with the user from the token, ignoring the body's value.
- **UUID entropy (if applicable).** Create 10 resources and extract the UUIDs. Expected: version 4 (random) or 7
  (time-ordered, preferred for 2026); over 1000 consecutive UUIDs the average Hamming distance between pairs is at
  least 64 bits. Using UUIDs does not remove the need for ownership checks.

---

### 2.3 Destructive operations require appropriate privileges `[P1]`

**References:** OWASP API5:2023, OWASP ASVS 5.0.0 V8.2.1 and V8.1.1, NIST SP 800-53 Rev. 5 AC-6 (least privilege).

**Concept.** Operations with permanent effects (DELETE, PUT on critical resources, financial operations) require
OAuth2 scopes or roles higher than the corresponding read operations. Least privilege (NIST SP 800-53 AC-6) becomes
granular scopes: `read:posts` allows GET, `delete:posts` allows DELETE.

**Failure scenarios.**

- **Delete by a non-owner.** userA owns post 100; userB calls `DELETE /api/posts/100` and succeeds, because the API
  checks only authentication, not ownership.
- **Scope escalation.** An application obtains an OAuth token with `scope: read:profile` and uses it to call
  `DELETE /api/profile`, which should require `delete:profile`.

**Assumptions and prerequisites (thesis).** Grey box: OAuth2 tokens with distinct granular scopes, at least two accounts
for the cross-ownership tests, and the documentation of the scopes each endpoint requires.

**Test logic.**

- **Delete by a non-owner.** Expected `403 Forbidden`.
- **Operation with a read-only token.** A token with scope `read:posts` calling a DELETE. Expected `403` with an
  "insufficient scope" message.
- **Batch delete authorization.** `DELETE /api/posts?ids=1,2,3` where ID 2 belongs to another user. Expected: the whole
  operation fails (`403`) without deleting any of the IDs (transactional behaviour).

---

### 2.4 Authorization policies are consistent across endpoints `[P1]`

**References:** OWASP API8:2023 Security Misconfiguration, OWASP ASVS 5.0.0 V8.1, NIST SP 800-53 Rev. 5 AC-3.

**Concept.** Equivalent endpoints, by API version, response format or alternative representation, apply identical
authorization policies. Consistency is a configuration property of the gateway; its violation often comes from
duplicate routes or misaligned versions, systematically checkable by automated comparison.

**Failure scenarios.**

- **Versioning inconsistency.** `GET /api/v1/users/{id}` requires the admin role; the new `GET /api/v2/users/{id}`
  forgets the check.
- **GraphQL against REST.** The REST endpoint `GET /api/users` requires authentication; the GraphQL endpoint exposes
  the same data without it.

**Assumptions and prerequisites (thesis).** Grey box: the complete OpenAPI specification for every API version, valid
JWTs for users with distinct roles, and knowledge of alternative endpoints (older versions, alternative formats,
convenience aliases) even if not documented in the current version.

**Test logic.**

- **Versioned endpoint parity.** For each v1 endpoint requiring authentication, test v2 and v3 without a token.
  Expected `401`.
- **Alternate format parity.** If `/api/users.json` and `/api/users.xml` exist, both require the same authentication.
- **Alias and convenience endpoints.** Identify endpoints returning similar data by naming pattern: if `/api/me` is
  protected, `/api/current-user` must be too.

---

### 2.5 The API does not expose excessive data `[P2]`

**References:** OWASP API3:2023 Broken Object Property Level Authorization, OWASP ASVS 5.0.0 V8.2.3 and V14.2.6, NIST
SP 800-53 Rev. 5 SC-4.

**Concept.** API responses contain only the fields the authenticated user may see, not the whole database object.
Filtering happens server side, not client side (that would be security by obscurity): an attacker reads the raw HTTP
response and reaches fields the interface hides.

**Failure scenario.**

- **Password hash in the response.** `GET /api/users/me` returns an object with a `passwordHash` field. Even a hash
  should not be exposed: the attacker can try to crack it offline.

**Assumptions and prerequisites (thesis).** Grey box: valid JWTs for at least two distinct roles (standard user and
admin) to check field filtering by role; the OpenAPI specification or the data model documentation, to identify the
sensitive fields that should not be exposed.

**Test logic.**

- **Sensitive field presence.** `GET /api/users/me`: the response must not contain `password`, `passwordHash`, `ssn`,
  `creditCard`, `apiKey` (ASVS V14.2.6).
- **Role-based field filtering.** Fetch an object as admin (it includes a sensitive field), then as an ordinary user:
  the user's response must not contain it (field by field comparison, ASVS V8.2.3).
- **Nested object filtering.** If an order includes a `user` object, it must contain only public fields (id, name),
  not email or phone.

---

## Domain 3. Data integrity

### 3.1 Every input is validated against schema and constraints `[P2]`

**References:** OWASP API10:2023, CWE-20, OWASP ASVS 5.0.0 V2.2.1 and V1.2, NIST SP 800-53 Rev. 5 SI-10.

**Concept.** Every input (body, query parameter, path parameter, header) is validated against the expected type,
format, range, length and pattern before reaching the business logic. The allow-list approach, accepting only
known-good values, prevents SQL injection, NoSQL injection, command injection, type confusion and denial of service
through anomalous payloads. The gateway can apply shallow schema validation (OpenAPI conformance); deep semantic
validation stays in the application.

**Failure scenarios (critical).**

- **SQL injection.** A query parameter carrying a classic always-true condition returns every user.
- **NoSQL injection.** A login body carrying query operators instead of values bypasses authentication in MongoDB.
- **Buffer overflow / out of memory.** An upload of a 10 GB file; the server allocates all its memory and crashes.

**Assumptions and prerequisites (thesis).** Grey box: a valid JWT for a standard user (to test authenticated
endpoints), the OpenAPI specification to know each field's expected type, and a test environment where anomalous
payloads can be sent without affecting production data.

**Test logic.**

- **Injection payloads** for each class (SQL, NoSQL, command). Expected: `400 Bad Request` with a generic message and
  no execution of the injection.
- **Type confusion.** A wrong type for each field (string instead of integer, array instead of string, object instead
  of boolean). Expected `400` stating the expected type.
- **Boundary and size limits.** Payloads over 100 MB, numbers beyond the 32-bit integer range, strings beyond the
  declared maximum, path traversal sequences. Expected `400` or `413 Payload Too Large`; no crash or uncontrolled
  allocation.
- **Encoding and header injection.** Query parameters with line-break characters (CRLF injection), emoji in an
  alphanumeric-only field, Unicode in a strict field. Expected `400` or sanitisation; response headers must contain
  no injected entries.

---

### 3.2 Merged into guarantee 6.1

*(The content on preventing information leakage through error messages and debug data was merged into guarantee 6.1,
"Error handling and information disclosure". The section was removed to avoid structural redundancy.)*

---

### 3.3 Data in transit is protected from tampering (beyond TLS) `[P3]`

**References:** OWASP ASVS 5.0.0 V4.1.5, NIST SP 800-175B Rev. 1, NIST SP 800-107 Rev. 1.

**Concept.** Application-level integrity mechanisms beyond TLS (HMAC request signatures, signed JWT responses, content
hashes) prevent tampering by trusted intermediary proxies and replay attacks. It is an advanced control of
application architecture, not a standard gateway function.

**Failure scenario.**

- **Tampering by a trusted proxy.** A corporate proxy changes the body of `POST /api/transfer` from an amount of 100
  to 1000. Without an HMAC the change is not detected.

**Assumptions and prerequisites (thesis).** "White box, configuration audit": access to the application architecture
documentation, to check whether a signing mechanism is implemented, and to the middleware's configuration files or
source code to check its parameters. The empirical test is indicated only if the mechanism is already implemented and
must be validated.

**Configuration audit (checklist).**

- **[audit]** Check in the documentation or middleware code whether an HMAC request signature is implemented (for
  example AWS Signature V4, or a custom `X-Signature` header with SHA-256). If not, document the absence as an
  architectural gap and assess the risk against the threat model (trusted internal proxies on the path).
- **[audit]** If implemented: the algorithm is SHA-256 or stronger (NIST SP 800-107 Rev. 1) and the shared key has at
  least 256 bits of entropy. MD5 or SHA-1 for HMAC are documented as non-conforming.
- **[audit]** The mechanism protects against replay by a timestamp in the payload with a validity window of at most 5
  minutes, or a single-use nonce with a uniqueness check on Redis. Without either, the mechanism is vulnerable to
  replay however strong the algorithm.
- **[empirical test, only if the mechanism is implemented]** Request tampering: a request with a valid signature, body
  modified keeping the original signature. Expected `400` or `403` ("signature mismatch"). Replay: resend a request
  with its timestamp. Expected `400` ("request expired") after the configured window.

---

## Domain 4. Availability and resilience

### 4.1 The system prevents resource exhaustion through rate limiting `[P0]`

**References:** OWASP API4:2023 Unrestricted Resource Consumption, OWASP ASVS 5.0.0 V2.4.1, NIST SP 800-204 §4.5.

**Concept.** The gateway applies rate limiting to prevent automated abuse (denial of service, brute force, scraping).
The strategies (fixed window, sliding window, token bucket, leaky bucket) are native functions of every production API
gateway. Limits apply per IP, per user ID (after authentication) and per API key. Exceeding the limit produces `429
Too Many Requests` with a `Retry-After` header. This guarantee is separate from 7.1 (business flow protection)
because it concerns infrastructure availability, not application logic.

**Failure scenarios.**

- **No limit on a CPU-intensive endpoint.** `GET /api/reports/export` generates PDF reports; without a rate limit, a
  loop saturates the server's CPU.
- **No limit on the login endpoint.** `POST /api/auth/login` without a limit allows unlimited password brute force.
- **In-memory rate limit (single instance).** The counter is per instance; behind a round-robin load balancer each
  instance sees a fraction of the requests and never reaches the limit.

**Assumptions and prerequisites (thesis).** Black box for enforcement tests and grey box for per-user tests: no
knowledge of the internal architecture is needed; two distinct users' JWTs for the "per user against per IP" test. The
configured limit must be known or derivable from the API documentation or response headers (`X-RateLimit-Limit`).

**Test logic.**

- **Limit enforcement.** Find the documented limit (for example 100 per minute) and send 101 requests in under 60 s.
  Expected: the first 100 give `200 OK`, the 101st `429` (ASVS V2.4.1).
- **Retry-After header.** After the `429`, check `Retry-After` or `X-RateLimit-Reset`; wait the indicated period and
  send a new request. Expected `200 OK` (limit reset).
- **Limit per user against per IP.** userA exceeds the limit and gets `429`; userB from the same IP then sends a
  request. If the limit is per user, userB gets `200 OK` (separate counter); if per IP, `429`. The behaviour must match
  the declared policy.
- **Burst behaviour (token bucket).** If the limit allows bursts (for example 20 instant requests): 20 simultaneous
  requests give `200 OK`, the 21st sent at once gives `429`.
- **Header spoofing resistance.** Requests with a randomised `X-Forwarded-For` on every call. Expected: the gateway
  uses the real address from the TCP connection, not the header's value, for rate limiting; the bypass does not work.

---

### 4.2 The system has timeouts that prevent resource lock `[P1]`

**References:** OWASP API4:2023, CWE-400, NIST SP 800-204A §4.3.

**Concept.** Every I/O operation (database query, external HTTP call, file read) has a configured timeout. Without
one, a thread stays blocked indefinitely if the resource does not answer; blocked threads accumulate, exhaust the
pool and the server can no longer accept new requests.

**Failure scenarios.**

- **No timeout on a database query.** `GET /api/users` runs `SELECT * FROM users`; the database has lock contention
  and the query hangs. 100 simultaneous requests give 100 blocked threads and an exhausted thread pool.
- **External API call without a timeout.** `GET /api/weather` calls an external service that is down and does not
  answer; the default timeout may be 60 s or more, and the user waits that long to see an error.

**Assumptions and prerequisites (thesis).** "White box, configuration audit": read access to the configuration files of
the gateway and application services, or the Admin API to extract the configured timeouts. The empirical test with a
mock service is optional, in staging, to validate that the configured timeout produces the expected behaviour.

**Configuration audit (checklist).**

- **[audit]** In the gateway configuration (Kong `upstream.connect_timeout`, `read_timeout`, `write_timeout`; Nginx
  `proxy_connect_timeout`, `proxy_read_timeout`, `proxy_send_timeout`; AWS API Gateway integration timeout) the
  timeouts are set and below 30 seconds. Expected: `connect_timeout` at most 5 s, `read_timeout` at most 30 s.
  Unset values mean the runtime default (often 60 s or unlimited), to be documented as a gap.
- **[audit]** In the application's connection pool (HikariCP `connectionTimeout`, `idleTimeout`; PgBouncer
  `server_connect_timeout`, `query_timeout`) explicit timeouts exist. Expected: `connectionTimeout` at most 10 s,
  `query_timeout` at most 30 s for standard queries.
- **[audit]** Calls to external services in the application code (Apache HttpClient `setConnectTimeout`, Python
  requests `timeout`, Node.js axios `timeout`) set timeouts explicitly and do not rely on the client's default.
  Expected: at most 15 s for synchronous calls.
- **[optional empirical test, staging only]** A mock service with a programmed 30 s delay; a request to the endpoint
  that calls it. Expected: a response within the configured timeout (for example 10 s) with `503` or `504 Gateway
  Timeout`, not after the mock's full delay.

---

### 4.3 The system degrades gracefully with a circuit breaker `[P1]`

**References:** OWASP API4:2023, OWASP ASVS 5.0.0 V16.5.2, NIST SP 800-204 §4.5.1, Martin Fowler, Circuit Breaker
pattern (2014).

**Concept.** The circuit breaker prevents cascading failure when a downstream service fails, with three states:
**closed** (normal), **open** (the downstream is failing: requests are blocked at once with a cached response or an
error, without waiting for a timeout) and **half-open** (after a timeout, one probe request checks recovery). The
typical trigger is N consecutive failures (for example 5) or a failure percentage in a time window. It is a native
function of advanced gateways (Istio `outlierDetection`, Kong Enterprise, AWS API Gateway integration).

**Failure scenario.**

- **No circuit breaker.** During an incident (database overload) every request waits for the timeout (30 s by
  default). At 100 requests per second, in 30 s the gateway accumulates 3000 pending requests, saturates the thread
  pool (Tomcat: 200 threads by default), and the failure of one dependency cascades to the whole gateway.

**Assumptions and prerequisites (thesis).** "White box, configuration audit" with an optional behavioural test in
staging: read access to the gateway configuration (Admin API or files) to check the circuit breaker parameters. The
graceful degradation test, if needed, requires coordination to disable a dependent service in a non-production
environment.

**Configuration audit (checklist).**

- **[audit]** Through the Admin API or files, the presence of circuit breaker directives (Kong plugin
  `circuit-breaker` or `response-ratelimiting`; Traefik middleware `circuitbreaker`; Istio
  `DestinationRule.trafficPolicy.outlierDetection`; AWS API Gateway integration with retry policy and timeout). The
  total absence of any equivalent is documented as a critical architectural gap (ASVS V16.5.2).
- **[audit]** Extract and check the parameters. Expected: `failure_threshold` (consecutive failures that open the
  circuit) 3-10; `timeout_duration` (time in open state before half-open) 30-120 s; `trigger_codes` (HTTP codes
  counted as failures) include both 5xx and timeouts or refused connections, not only 500.
- **[audit]** Whether the gateway exposes health endpoints reporting circuit breaker state (Kong Admin `/status`;
  Spring Boot Actuator `/actuator/health`; Istio Pilot metrics). Expected: fields such as `circuit_name`, `state`
  (CLOSED/OPEN/HALF_OPEN), `failure_count`. A system with no observability on the circuit breaker cannot be managed in
  an incident.
- **[audit]** Read-only review of the monitoring system's historical metrics (Grafana, CloudWatch, Datadog) for the
  last 30 days, looking for events such as `circuit_breaker_state_change`, `circuit_breaker_trip_count`,
  `rejected_requests_count`. Their total absence over 30 days may mean a too high threshold or a disabled breaker,
  not necessarily a stable system.
- **[optional behavioural test, staging only, coordinated with the team]** Temporarily disable a non-critical
  dependent service and send requests to the endpoint that calls it. Expected: an immediate response (under 1 s) with
  a graceful fallback or `503` with `Retry-After`. A response blocking for the configured timeout before failing
  means the breaker is not active or not in the open state.

---

## Domain 5. Visibility and auditing

### 5.1 Every request is logged with essential metadata `[P1]`

**References:** NIST SP 800-92, NIST SP 800-53 Rev. 5 AU-2, OWASP ASVS 5.0.0 V16.2.1, GDPR Article 30.

**Concept.** The gateway produces structured (JSON) logs for every request with the minimum metadata NIST SP 800-92
requires for incident response and audit: UTC timestamp, request ID, HTTP method and path, the real source IP (not the
proxy's), user ID (if authenticated), status code, response time. Sensitive data (passwords, tokens, SSNs) must be
redacted for GDPR Article 30 conformance.

**Failure scenarios.**

- **Missing logs on security events.** Login failures and authorization denials are not logged; brute force goes
  unnoticed.
- **Sensitive data in clear in logs.** A login body is logged in clear; if the logs are compromised, so are the
  credentials (a GDPR violation).
- **Log injection.** A username containing a line break and a fake critical message injects a false entry that hides
  the real attack or raises false alarms.

**Assumptions and prerequisites (thesis).** Grey box: a valid JWT for authenticated requests and read access to the log
aggregator (Elasticsearch/Kibana, Splunk, CloudWatch Logs, Datadog) to check the entries produced. Without access to
the logs this guarantee cannot be checked empirically from outside.

**Test logic.**

- **Log entry presence.** An authenticated `GET /api/users/me`; the aggregator must show timestamp, request ID,
  method, path, authenticated user ID, status `200` and a response time above 0 ms (ASVS V16.2.1).
- **Sensitive data redaction.** A login with a test password; the log must not contain the password in clear
  (`[REDACTED]` or omitted).
- **Security event logging.** A request to an admin endpoint without a token; expected an entry with status `401`, the
  path, no user and the reason ("missing token").
- **Log injection prevention.** A username containing a line break followed by fake text; expected the username
  escaped or sanitised in the log, and no separate entry generated.
- **Real IP logging.** A request with `X-Forwarded-For` set; the logged IP is the real client's, not the proxy's or
  load balancer's.

---

### 5.2 Anomalous security events trigger real-time alerts `[P2]`

**References:** NIST SP 800-61 Rev. 3 §2.3, OWASP ASVS 5.0.0 V7.1.1, GDPR Article 33.

**Concept.** Security-critical events (brute force, object enumeration, rate limit hits, anomalous traffic spikes)
trigger active alerts to a SIEM or notification channels (PagerDuty, Slack) in real time (NIST SP 800-61 Rev. 3).
Effectiveness depends on the monitoring infrastructure and on the correlation rules, and is only partly checkable from
outside.

**Failure scenarios.**

- **Brute force undetected.** 10,000 password attempts in 10 minutes. Logs exist but no alert; the security team finds
  the breach weeks later.
- **Alert fatigue.** The system alerts on every single `401`; 1000 alerts a day, mostly false positives. The team
  ignores them and misses real events.

**Assumptions and prerequisites (thesis).** Grey box with a configuration audit component: read access to the alert
rules (SIEM, Grafana Alert Manager, CloudWatch alarms) to check thresholds and correlation logic; for the behavioural
tests, a webhook endpoint or notification channel in the test environment to receive the alerts and check their
latency and content.

**Test logic.**

- **Brute-force alert.** 20 login failures in 60 s. Expected: an alert within 10 s of the last failure (via a webhook
  receiver or a log pattern, ASVS V16.3).
- **Alert deduplication.** The same event triggered 10 times. Expected: one alert with an aggregated counter, not 10
  separate ones (prevents spam).
- **Alert threshold verification.** With a configured threshold of 5 failures: 4 failures give no alert, 5 trigger it.
  This checks that the declared threshold matches the real behaviour.

---

## Domain 6. Configuration and hardening

### 6.1 Error handling and information disclosure `[P2]`

**References:** OWASP API8:2023 Security Misconfiguration, OWASP ASVS 5.0.0 V13.4.2, V13.4.6 and V16.5.1, CWE-209, NIST
SP 800-53 Rev. 5 SI-11 and SC-7.

**Concept.** API responses, in error conditions and in normal ones, do not expose internal technical information. Two
vectors: **(1) detailed error messages** containing stack traces, SQL queries, file system paths or library versions
that allow fingerprinting the backend and identifying applicable CVEs; **(2) residual debug data** in production
(`_debug` or `_sql_query` fields, framework versions in an `X-Powered-By` header) that expose the internal
architecture. The principle is fail-secure: generic messages to the client, technical detail in server-side logs.

**Failure scenarios.**

- **Stack trace in the response.** An invalid identifier gives a `500` with a Java exception trace naming the class and
  line: it reveals the framework, its version and file paths.
- **SQL error leak.** A malformed parameter returns the database's syntax error, which confirms SQL injection and
  reveals table names.
- **Debug mode in production.** A `DEBUG=True` flag left after deployment: every error includes environment
  variables, possibly with API keys and database credentials.
- **Differential information in authentication errors.** A different response for "user not found" and "wrong
  password" enables username enumeration.

**Assumptions and prerequisites (thesis).** Grey box: a valid JWT (to test authenticated endpoints) and access to the
raw HTTP responses; no access to internal configuration: every test rests on observing the responses to deliberately
anomalous inputs.

**Test logic.**

- **Stack trace detection on provoked errors.** Requests designed to trigger backend exceptions: a type mismatch, a
  missing required field, malformed JSON, an oversized payload (over 10 MB). Expected: the response contains no
  exception keywords, file system paths, class names or framework versions (ASVS V13.4.2).
- **Debug field detection in a normal response.** A valid request to a CRUD endpoint; analyse the JSON for fields not
  documented in OpenAPI with technical names (`_debug`, `_sql`, `_trace`, `_internal`, `databaseId`, `shardKey`,
  `cacheHit`). Expected: none.
- **Header information leakage.** `X-Powered-By` absent or generic; `Server` generic (`nginx`, not a version and
  distribution); internal `X-*` headers removed by the gateway (ASVS V13.4.6).
- **Error verbosity consistency.** Four error conditions: malformed JSON, a business rule violation, failed
  authentication, denied authorization. All messages have the same level of abstraction; in particular the
  authentication error does not tell "user not found" from "wrong password".
- **Correlation ID in the error response.** Every error carries a correlation ID, so support can retrieve the technical
  detail from internal logs without exposing it to the client.

---

### 6.2 Security headers are configured appropriately `[P3]`

**References:** OWASP API8:2023, OWASP ASVS 5.0.0 V3.4 (3.4.1-3.4.7), RFC 9110, Mozilla Observatory best practices.

**Concept.** The HTTP security headers that form defence in depth against client-side attacks are present and
correct: HSTS (forces HTTPS), X-Content-Type-Options (prevents MIME sniffing), X-Frame-Options (prevents
clickjacking), Content-Security-Policy (prevents XSS), Permissions-Policy (disables risky browser features). They are
static gateway configuration, checkable with one request.

**Failure scenario.**

- **Missing HSTS.** A user types `http://api.example.com`, the browser makes an HTTP request and a man in the middle
  intercepts it (SSL stripping). HSTS prevents it after the first HTTPS visit.

**Assumptions and prerequisites (thesis).** "White box, configuration audit": every check is doable with a single
`curl -I` or by inspecting the gateway configuration; no token or privileged access: the headers must be present on
every response, including those of public endpoints. (In the tool, 6.2 is black box: it observes the response
headers.)

**Configuration audit (checklist).**

- **[audit]** `Strict-Transport-Security: max-age=31536000; includeSubDomains` (ASVS V3.4.1); a `max-age` under one
  year is suboptimal and the absence of the header is non-conforming.
- **[audit]** `X-Frame-Options`: `DENY` or `SAMEORIGIN` (ASVS V3.4.6); `ALLOW-FROM` is deprecated.
- **[audit]** `X-Content-Type-Options: nosniff` (ASVS V3.4.4).
- **[audit]** `Content-Security-Policy` present and without `default-src *`; the minimum acceptable is
  `default-src 'self'` (ASVS V3.4.3). A permissive policy with a wildcard is equivalent to none.
- **[audit]** `Permissions-Policy` disables the browser features the application does not use
  (`geolocation=(), camera=(), microphone=()`).
- **[audit]** Consistency of the headers across all endpoints (public, authenticated, admin): present on one and absent
  on another means selective misconfiguration in the gateway. Method: automated comparison over a representative
  sample.

---

### 6.3 The gateway configuration is hardened against layer-7 exploits `[P1]`

**References:** OWASP API8:2023, OWASP ASVS 5.0.0 V14.2.1 and V14.5.3, RFC 9110 §9.3, CWE-444 (HTTP request smuggling),
NIST SP 800-204 §4.5.1.

**Concept.** The gateway adds an HTTP parsing layer that, if weakly configured, becomes an attack surface for HTTP
request smuggling (CWE-444) and slow-connection denial of service. Smuggling exploits discrepancies between the
gateway's parsing (frontend) and the backend's: `Content-Length` and `Transfer-Encoding: chunked` present together
violate RFC 9110, but different parsers give precedence to one or the other. A hardened gateway rejects ambiguous
headers, normalises paths before applying policies, and applies aggressive layer-7 timeouts (header timeout at most
10 s, body timeout at most 30 s) against slow-connection attacks.

**Failure scenarios.**

- **Frontend/backend desynchronisation.** The gateway uses `Content-Length` and the backend `Transfer-Encoding`: a
  request the gateway reads as one (valid and authenticated) is read by the backend as two, and the second never
  passed through the gateway's authentication checks.
- **Slow connections via long header parsing.** With a 60 s header timeout (an insecure default), thousands of
  connections with partial headers saturate the connection pool for 60 s each.
- **CORS wildcard with credentials.** `Access-Control-Allow-Origin: *` combined with
  `Access-Control-Allow-Credentials: true` violates the CORS specification and may enable cross-origin exfiltration on
  legacy browsers.

**Assumptions and prerequisites (thesis).** Mixed grey box and white box: the smuggling and CORS tests need only
network connectivity (grey box); the timeout and plugin tests need read access to the gateway configuration through
the Admin API or files (white box). The CORS test with browser automation needs a controlled test environment.

**Test logic.**

- **Request smuggling, empirical test.** A request carrying both framing headers. Expected: `400 Bad Request` for
  ambiguous headers (RFC 9110, ASVS V14.5.3); the gateway must not forward it to the backend.
- **[audit] Layer-7 timeouts.** In the gateway configuration (Nginx `client_header_timeout`, `client_body_timeout`;
  Kong `client_header_timeout`; HAProxy `timeout http-request`): header timeout at most 10 s, body timeout at most 30
  s; higher defaults (often 60 s) must be reduced explicitly.
- **[audit] Plugin source and versioning.** List the installed gateway plugins through the Admin API; for each, check
  the provenance from an official repository, version pinning in the configuration, and the absence of high-severity
  CVEs in the vendor's advisories (ASVS V14.2.1).
- **CORS strict enforcement, empirical test.** `Access-Control-Allow-Origin` is a specific allow-list of domains, not
  `*`; with `Access-Control-Allow-Credentials: true` the wildcard violates the CORS specification and is reported as
  critical.
- **Path normalisation and method override, empirical test.** Path variants (double slash, traversal, URL encoding) on
  a protected endpoint without a token: all give `403`, the policy applied after normalisation. If the gateway
  supports `X-HTTP-Method-Override`, the method it recognises must be consistent between gateway and backend.

---

### 6.4 Service credentials are not hard-coded or exposed `[P2]`

**References:** OWASP API8:2023, OWASP ASVS 5.0.0 V13.3.1, V13.3.4 and V13.4.1, CWE-798, NIST SP 800-53 Rev. 5 IA-5(1),
NIST SP 800-204 §5.4.

**Concept.** The credentials the gateway uses (database passwords, API keys, TLS private keys) are managed by a
dedicated secret manager (AWS Secrets Manager, HashiCorp Vault, Azure Key Vault), not hard-coded in configuration files
or Docker images. Static credentials cannot be rotated without a redeploy and, if exposed through path traversal or a
repository leak, give direct access to the backend bypassing the gateway.

**Failure scenarios.**

- **Database password in a configuration file.** A gateway configuration file holds a password in clear; an attacker
  with read-only filesystem access extracts it and connects to the database directly.
- **API key in a Dockerfile.** A live payment key in an `ENV` instruction of an image pushed to a public registry;
  automated bots scan public registries for such patterns within minutes.
- **No rotation policy.** Credentials managed by a secret manager but never rotated: the same secret in use for 3
  years, and a former employee with historical access can still use it after termination (ASVS V13.3.4).

**Assumptions and prerequisites (thesis).** "White box, configuration audit": read access to the gateway's
configuration files, to the Docker images (through the registry or `docker history`) and to the secret manager's audit
trail. The one partly empirical test (debug endpoint exposure) needs network connectivity to the target.

**Configuration audit (checklist).**

- **[audit]** A pattern scan of the accessible gateway configuration files for known credential formats. Expected: no
  match with a high-entropy value (over 20 characters, not a placeholder). Placeholders such as `CHANGE_ME` are
  acceptable; realistic values are critical (ASVS V13.3.1).
- **[empirical test]** Debug endpoint exposure: endpoints such as `/actuator/env`, `/debug/vars`, `/api/config` must not
  expose environment variables. If reachable and returning database passwords or cloud secrets in clear, it is a
  critical direct leak. Environment variables should hold a reference to the secret store, not the value.
- **[audit]** With access to the container registry, `docker history <image>` over the historical layers looking for
  `ENV` or `RUN echo` instructions with credentials. Expected: none in any layer; secrets are injected at runtime by
  the orchestrator (Kubernetes Secrets mounted as volumes, Docker Swarm secrets), not included in the image.
- **[audit]** In the secret manager's audit trail (AWS CloudTrail for Secrets Manager, Vault audit log), critical
  credentials (database password, payment API key) have been rotated at least in the last 90 days (NIST SP 800-53
  IA-5(1), ASVS V13.3.4); no rotation events in 90 days is a non-conformity.

---

## Domain 7. Business logic and sensitive flows

### 7.1 Sensitive business flows are protected from automated abuse `[P2]`

**References:** OWASP API6:2023 Unrestricted Access to Sensitive Business Flows, OWASP Automated Threats OAT-001 to
OAT-021, OWASP ASVS 5.0.0 V2.4.1 and V2.4.2, NIST SP 800-63B-4 §5.2.5.

**Concept.** Distinct from 4.1 (infrastructure rate limiting): it protects the business logic from automated abuse,
not the availability of the service. Generic rate limiting limits request volume; protecting sensitive flows concerns
specific high-value endpoints (payment, account creation, password reset, coupon redemption) that need dedicated
anti-bot mechanisms: CAPTCHA, OTP, behavioural analysis, device fingerprinting. A bot can stay within rate limits and
still cause fraud (for example card testing at 1 request a minute over 10,000 stolen cards).

**Failure scenarios.**

- **Card testing.** `POST /api/payment` without a CAPTCHA and with a generous rate limit (100 per minute): an attacker
  tests 10,000 stolen cards in under 2 hours and finds the valid ones.
- **Account creation bot.** No CAPTCHA on `POST /api/register` allows creating 10,000 accounts an hour for spam or vote
  manipulation.

**Assumptions and prerequisites (thesis).** Grey box: a valid JWT (for payment endpoints that require authentication),
a test environment with a real account (for registration and email verification tests) and knowledge of the
business-critical endpoints to test; no access to internal configuration.

**Test logic.**

- **CAPTCHA on a sensitive endpoint.** A payment request without a CAPTCHA token. Expected `400` "CAPTCHA required"
  (ASVS V2.4.1); with an invalid token `400` "invalid CAPTCHA".
- **Aggressive application-level rate limiting.** On payment or registration endpoints, 5 requests in 60 s (if the
  limit is 1 a minute). Expected: requests 2 to 5 get `429`.
- **Email verification enforcement.** Create an account, do not confirm the email, try to log in. Expected `403` "email
  not verified" or limited access until confirmation.
- **Device fingerprint tracking.** 10 registrations from the same device fingerprint in 10 minutes. Expected: after N
  attempts a stronger CAPTCHA challenge or a temporary block (ASVS V2.4.2).

---

### 7.2 The system prevents server-side request forgery (SSRF) `[P0]`

**References:** OWASP API7:2023 Server Side Request Forgery, CWE-918, OWASP ASVS 5.0.0 V1.3.6, NIST SP 800-204 §3.2.2.

**Concept.** When the API accepts a user-supplied URL and makes a server-side HTTP request to it, an attacker can reach
internal resources (the cloud metadata service at `169.254.169.254`, services on `localhost`, private subnets such as
`10.0.0.0/8`), bypassing the perimeter firewall. The risk is amplified in the cloud, where the AWS, Azure and GCP
metadata endpoints expose temporary IAM credentials. Mitigations are a URL allow-list, a deny-list of private and
link-local ranges, and DNS resolution validated before the request.

**Failure scenarios.**

- **Cloud metadata access.** A fetch endpoint given the metadata service URL returns temporary cloud credentials.
- **Internal service enumeration.** A fetch endpoint given the address of an internal admin service: the service is not
  reachable from the Internet, but the API server can reach it.
- **Deny-list bypass through encoding.** The deny-list blocks `127.0.0.1` but not equivalent forms of the same address
  (abbreviated, hexadecimal, decimal notation), which simple string patterns do not cover.

**Assumptions and prerequisites (thesis).** Black box (for public SSRF endpoints) or grey box (if the endpoint
requires authentication): no knowledge of the internal infrastructure is needed, the test payloads are standard and
publicly documented; a valid standard user JWT for authenticated endpoints.

**Test logic** (the categories checked; the concrete payload catalogue is in the tool's `ssrf_payloads` module).

- **Cloud metadata access.** The metadata service addresses of AWS, GCP and Azure. Expected: `400 Bad Request`
  ("forbidden IP range") or a timeout (ASVS V1.3.6).
- **Private IP range blocking.** Loopback, `localhost` and the RFC 1918 private ranges. Expected: all blocked.
- **Encoding bypass.** Alternative notations of loopback addresses, including the IPv6 loopback. Expected: all blocked
  (robust validation of the resolved address, not a pattern on the string).
- **Protocol allow-list.** Schemes other than HTTP and HTTPS (`file`, `gopher`, `dict`, `ftp`). Expected: `400`
  "unsupported protocol".
- **Redirect following validation.** A public server answering with a `302` redirect to a loopback address. Expected:
  the system re-validates the target after the redirect and blocks it if it is a private address.
- **Domain allow-list enforcement.** If an allow-list of domains exists: an allowed domain gives `200 OK`, any other
  `400` forbidden.

---

### 7.3 Critical operations are idempotent or protected from race conditions `[P2]`

**References:** CWE-362 (race condition), OWASP ASVS 5.0.0 V2.3.3 and V2.3.4, RFC 7231 §4.2.2.

**Concept.** Business-critical operations (payment, fund transfer, inventory deduction) are idempotent, so that
executing the same request N times has the same effect as once, and protected from race conditions. The mechanisms are
application-level (an idempotency key on Redis, a `SERIALIZABLE` database transaction, optimistic locking) and not
directly controlled by the gateway; the tests check the resulting behaviour from outside.

**Failure scenarios.**

- **Double payment charge.** A user clicks "Pay", the request times out on a slow network, the user clicks again: both
  requests are processed and the user is charged twice.
- **Race condition on inventory.** A product has stock 1 and two users buy it at once. Without synchronisation both
  read stock 1 and both deduct it: stock -1 (oversold).

**Assumptions and prerequisites (thesis).** Grey box: valid JWTs for at least two distinct users, a staging environment
where real test orders and transactions can be created (the idempotency test needs a working payment endpoint), and the
ability to send concurrent requests with threads (for the race tests); no database access: the behaviour is observed
through the API.

**Test logic.**

- **Duplicate request with an idempotency key.** A payment with an `Idempotency-Key` gives `201 Created`; the identical
  request repeated gives `200 OK` (the cached result, not `201`) and no second charge. Database check, if accessible: a
  single transaction.
- **Race condition on inventory.** A product with stock 1; two users send an order at the same time (threads).
  Expected: one succeeds and one fails for insufficient stock. Vulnerable: both succeed with stock -1.
- **Withdrawal race condition.** An account with balance 100; two concurrent withdrawals of 100. Expected: one succeeds
  (balance 0), one fails. Vulnerable: both succeed (balance -100).

---

### 7.4 The API consumes external services safely (webhook verification) `[P2]`

**References:** OWASP API10:2023 Unsafe Consumption of APIs, NIST SP 800-161 Rev. 1, OWASP ASVS 5.0.0 V13.2.4 and V4,
NIST SP 800-204 §4.3.

**Concept.** When the API receives webhooks from external providers (payment, CI/CD, CRM) or calls partner APIs, it
verifies cryptographically the authenticity of the data before processing it. An unverified webhook can be forged by an
attacker to trigger privileged operations (for example marking an order as paid without a real transaction). NIST SP
800-161 Rev. 1 recommends a zero-trust approach to all external services, trusted ones included.

**Failure scenarios.**

- **Webhook without signature verification.** A payment provider's webhook is accepted without checking an HMAC; an
  attacker forges the request with any order identifier and the order is marked as paid without a payment.
- **XSS through webhook data.** A webhook carries an issue title with a script; the backend stores it unsanitised and an
  admin viewing the issue list executes it.

**Assumptions and prerequisites (thesis).** Grey box: the signature mechanism the external provider uses (typically
HMAC-SHA256 with a shared secret, documented in the provider's developer portal), the ability to send HTTP requests to
the API's webhook endpoint, and a test environment to check the state of orders or resources after the webhook. For
the XSS test, a browser and access to the admin interface.

**Test logic.**

- **Webhook signature verification.** A webhook with a valid HMAC gives `200 OK`; the same payload with an invalid
  HMAC gives `400`/`403` "signature verification failed" (ASVS V4).
- **Replay attack protection.** Capture a webhook with a valid signature and resend it identically after 10 minutes.
  Expected `400` "request expired" (timestamp check) or `400` "nonce already used".
- **External API response validation.** A mock server returning a malformed response (wrong type, missing field).
  Expected: handled gracefully with type validation; no crash, no propagation of malformed data.
- **External API timeout.** A mock server with a 60 s delay. Expected: a response within the configured timeout (at
  most 10-15 s) with a graceful error; no indefinite hang.
- **Markup injection through a webhook.** A webhook with a valid HMAC whose title field carries markup that executes
  script. Expected: the data are encoded or removed when retrieved through the API; a browser test must not trigger
  script execution.

---

## Closing matrix of the thesis

The thesis closes the catalogue with a risk-based prioritisation matrix that restates the priorities by tier (P0 gateway
core and OWASP top risks, P1 business-critical and advanced gateway features, P2 application logic and defence in depth,
P3 static compliance and best practice), with the criteria of the dual prioritisation. The criteria are in
[`framework.md`](framework.md#priorities); the assignment per guarantee is the table at the top of this page, where the
matrix's differences from the section headings are noted.

*Based on: OWASP API Security Top 10 2023, OWASP ASVS 5.0.0, NIST SP 800-204/204A, NIST SP 800-63B-4, RFC 7519/8725/9110.*

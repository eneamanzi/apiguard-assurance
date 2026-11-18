# 1.6 Session Cookie Safety

> **Audience:** analysts, contributors · **Source of truth:**
> [`src/tests/domain_1/test_1_6_session_cookie_safety.py`](../../../src/tests/domain_1/test_1_6_session_cookie_safety.py)

<!-- [[[cog import generate_docs as g; cog.out(g.test_header("1.6", page=cog.inFile)) ]]] -->

|  |  |
|---|---|
| Test ID | `1.6` |
| Name | Session Cookie Safety |
| Domain | 1 - Identity and Authentication |
| Priority / strategy | P3 / GREY_BOX |
| Effect | READ_ONLY |
| CWE | CWE-1004 |
| Standards | `OWASP API2:2023`, `OWASP ASVS v5.0.0-3.3.1`, `OWASP ASVS v5.0.0-3.3.2`, `OWASP ASVS v5.0.0-3.3.4`, `CWE-614`, `CWE-1275`, `RFC 6265, Section 4.1.2` |
| Tags | `authentication`, `session` |
| Prerequisites | none |
| Needs | `USER_ACCOUNT` |
| Parameters | none |

<!-- [[[end]]] -->

**Same group:** tests `1.1` and `1.7`.

## 1. Guarantee

A session the target keeps in a cookie is kept safely: every cookie a login sets carries `Secure`, `HttpOnly` and a
restricting `SameSite`.

A PASS promises that the cookies this login set carry the three attributes. It promises nothing about a session the
target keeps elsewhere (a token in the body is `1.1`'s and `1.2`'s business), nothing about revocation (`1.4`) and
nothing about session fixation, which this test does not check (see the limitations).

## 2. Test

### 2.1 Sub-tests and coverage of the methodology

| Sub-test | Methodology (guarantee 1.6) |
|---|---|
| `cookie_attributes` | the `[audit]` item "session cookies are issued with `HttpOnly`, `Secure` and `SameSite`, from the `Set-Cookie` header of a login response" |
| left out | the session store's TTL and replication mode (they need the store's configuration, which the tool does not read); the `[empirical test]` session fixation (see the limitations); the randomness of the identifier (a property of the library, not observable from outside) |

### 2.2 Preconditions and reference responses

None: the evidence is the `Set-Cookie` headers of a response that has already been received.

### 2.3 Probes

None. Every cookie of the login response is read, except one the response is clearing (an empty value, `Max-Age`
zero or negative, a past `Expires`): a login often clears a stale cookie, and the attributes of a cookie being
removed say nothing.

**Every cookie is judged, whatever its name.** A fixed list of names (`session`, `sid`, `PHPSESSID`, `JSESSIONID`,
`connect.sid`, ...) would skip exactly the cookie whose name nobody guessed.

## 3. Oracle

<!-- [[[cog import generate_docs as g; cog.out(g.oracle_table("1.6")) ]]] -->

| Case | Outcome / detail | Confidence |
|---|---|---|
| a cookie the login sets has `Secure`, `HttpOnly` (not asked of an anti-CSRF cookie), `SameSite=Strict` or `Lax`, and a `__Host-` or `__Secure-` name | `ENFORCED/COOKIE_SAFE` | - |
| the cookie the configuration reads the credential from (`cookie:<name>`) lacks `Secure` | `VIOLATION/COOKIE_WITHOUT_SECURE` | CERTAIN |
| the cookie the configuration reads the credential from (`cookie:<name>`) lacks `HttpOnly` (its name has neither `csrf` nor `xsrf`) | `VIOLATION/COOKIE_WITHOUT_HTTPONLY` | CERTAIN |
| the cookie the configuration reads the credential from (`cookie:<name>`) lacks a restricting `SameSite` (absent, `None` or another value) | `VIOLATION/COOKIE_WITHOUT_SAMESITE` | CERTAIN |
| the cookie the configuration reads the credential from (`cookie:<name>`) lacks a `__Host-` or `__Secure-` name prefix | `VIOLATION/COOKIE_WITHOUT_PREFIX` | CERTAIN |
| another cookie the login sets (whether it carries the session is not proven: it may be a load balancer's) lacks `Secure` | `VIOLATION/COOKIE_WITHOUT_SECURE` | FIRM |
| another cookie the login sets (whether it carries the session is not proven: it may be a load balancer's) lacks `HttpOnly` (its name has neither `csrf` nor `xsrf`) | `VIOLATION/COOKIE_WITHOUT_HTTPONLY` | FIRM |
| another cookie the login sets (whether it carries the session is not proven: it may be a load balancer's) lacks a restricting `SameSite` (absent, `None` or another value) | `VIOLATION/COOKIE_WITHOUT_SAMESITE` | FIRM |
| another cookie the login sets (whether it carries the session is not proven: it may be a load balancer's) lacks a `__Host-` or `__Secure-` name prefix | `VIOLATION/COOKIE_WITHOUT_PREFIX` | FIRM |

<!-- [[[end]]] -->

## 4. Validation

### 4.1 Oracle cases

<!-- [[[cog import generate_docs as g; cog.out(g.oracle_validation("1.6", page=cog.inFile)) ]]] -->

Every case of the oracle, produced on a lab and judged by the code: E1, [oracle validation](../../../experiments/README.md), campaign at commit `fc60b6f`. 9 of 9 produced cases gave the declared outcome; 0 no lab can produce.

| Case | Lab, how it is produced | Result |
|---|---|---|
| `cookie_attributes/ENFORCED/COOKIE_SAFE` | forgejo-kong: a temporary route /lab-login answers 204 with '__Host-sid=...; Path=/; Secure; HttpOnly; SameSite=Strict' and 'AWSALB=...; Path=/'; the run logs in through it (credential read from cookie:__Host-sid, sent back as cookie __Host-sid) with a copy of the specification without security schemes: __Host-sid has every attribute | OK |
| `cookie_attributes/VIOLATION/COOKIE_WITHOUT_SECURE/CERTAIN` | forgejo-kong: the temporary route /lab-login answers 204 with 'sid=...; Path=/' only, and the run reads the credential from cookie:sid (sent back as cookie sid), specification without security schemes: the session cookie lacks Secure | OK |
| `cookie_attributes/VIOLATION/COOKIE_WITHOUT_HTTPONLY/CERTAIN` | forgejo-kong: the same run as COOKIE_WITHOUT_SECURE/CERTAIN: the session cookie sid lacks HttpOnly | OK |
| `cookie_attributes/VIOLATION/COOKIE_WITHOUT_SAMESITE/CERTAIN` | forgejo-kong: the same run as COOKIE_WITHOUT_SECURE/CERTAIN: the session cookie sid has no SameSite | OK |
| `cookie_attributes/VIOLATION/COOKIE_WITHOUT_PREFIX/CERTAIN` | forgejo-kong: the same run as COOKIE_WITHOUT_SECURE/CERTAIN: the session cookie is named sid, without __Host- or __Secure- | OK |
| `cookie_attributes/VIOLATION/COOKIE_WITHOUT_SECURE/FIRM` | forgejo-kong: the same run as COOKIE_SAFE: the second cookie AWSALB, not the one the credential is read from, lacks Secure | OK |
| `cookie_attributes/VIOLATION/COOKIE_WITHOUT_HTTPONLY/FIRM` | forgejo-kong: the same run as COOKIE_SAFE: AWSALB lacks HttpOnly | OK |
| `cookie_attributes/VIOLATION/COOKIE_WITHOUT_SAMESITE/FIRM` | forgejo-kong: the same run as COOKIE_SAFE: AWSALB has no SameSite | OK |
| `cookie_attributes/VIOLATION/COOKIE_WITHOUT_PREFIX/FIRM` | forgejo-kong: the same run as COOKIE_SAFE: AWSALB has neither __Host- nor __Secure- in its name | OK |

<!-- [[[end]]] -->

### 4.2 Results on the labs

<!-- [[[cog import generate_docs as g; cog.out(g.lab_results("1.6", page=cog.inFile)) ]]] -->

No E2 campaign yet ([experiments](../../../experiments/README.md)).

<!-- [[[end]]] -->

## 5. Limitations

- **Session fixation is not checked.** It needs a login that can be repeated while carrying a cookie obtained
  before it. The prepared-resource mechanism logs in once per role, and a form login with a CSRF token is not
  something the tool can drive in a general way. The check is left out rather than approximated by comparing two
  unrelated visits, which would prove nothing.
- The session store's TTL and its replication mode are not read: the tool does not have the store's configuration.
- Only the login of role `user_a` is read.
- A target that keeps no session in a cookie is skipped, which says nothing about how it keeps its session.
- A credential read from a cookie (`cookie:<name>`) was verified on the Forgejo + Kong lab with a simulated login
  route and a copy of the specification without security schemes: none of the three labs has a
  cookie-session API, so the tests that then send that cookie as the account's credential have not been run against
  a backend that accepts it (the sending path, `send_as`, predates this change).
- Which cookie carries the session is proven only when the configuration reads the credential from it
  (`values.credential: cookie:<name>`); otherwise the value is redacted in the record, a cookie cannot be replayed
  alone to find out, and its findings are FIRM.

## 6. Sources

- OWASP API2:2023 Broken Authentication: https://owasp.org/API-Security/editions/2023/en/0xa2-broken-authentication/
- OWASP ASVS v5.0.0-3.3.1 (`Secure`), v5.0.0-3.3.4 (`HttpOnly` on a cookie scripts must not read) and
  v5.0.0-3.3.2 (`SameSite` "set according to the purpose of the cookie"):
  https://github.com/OWASP/ASVS/blob/v5.0.0/5.0/en/0x12-V3-Web-Frontend-Security.md
- CWE-1004 Sensitive Cookie Without 'HttpOnly' Flag: https://cwe.mitre.org/data/definitions/1004.html
- CWE-614 Sensitive Cookie in HTTPS Session Without 'Secure' Attribute: https://cwe.mitre.org/data/definitions/614.html
- CWE-1275 Sensitive Cookie with Improper SameSite Attribute: https://cwe.mitre.org/data/definitions/1275.html
- CWE-384 Session Fixation (the check left out): https://cwe.mitre.org/data/definitions/384.html
- RFC 6265 section 4.1.2 (the attributes of a cookie): https://www.rfc-editor.org/rfc/rfc6265.html#section-4.1.2

## 7. Inputs

The login artefact of role `user_a` (`TestContext.login_artefact`): the record of the login request and its
response, kept by the engine for the tests that read it. The engine obtains the credential of every account a test
declares as a need before running it, so the artefact is there whenever the role is configured as a login.

**This test sends no request of its own.**

## 8. Outcomes

SKIP, with the reason, when the credential does not come from a login (`credentials.auth_type` is not `login`, so
there is no login response to read), or when the login response set no cookie: a target that keeps no session in a
cookie has nothing to judge here. Both lab applications answer a login with a token in the body.

## 9. Findings

<!-- [[[cog import generate_docs as g; cog.out(g.finding_titles("1.6")) ]]] -->

- "Login cookie without <attribute>: <name>"

<!-- [[[end]]] -->

`evidence_ref` the login response; each finding cites its own CWE and ASVS requirement.

## 10. Effects on the target

`READ_ONLY`, and no request at all: the login has already happened.

## 11. Per gateway

Independent of the gateway, and a gateway that manages the session itself is covered by the same reading: the
cookies it adds to the login response are judged like any other.

## 12. Configuration

None. 
## 13. Remediation

Set `Secure`, `HttpOnly` and `SameSite=Strict` (or `Lax` where a cross-site navigation must keep the session) on
every cookie that carries a session, and renew the identifier when the user authenticates.

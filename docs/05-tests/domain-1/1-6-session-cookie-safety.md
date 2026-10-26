# 1.6 Session Cookie Safety

> **Audience:** analysts, contributors · **Status:** rewritten in the test review (branch `test-review`, 2026-10-22) ·
> **Source of truth:**
> [`src/tests/domain_1/test_1_6_session_cookie_safety.py`](../../../src/tests/domain_1/test_1_6_session_cookie_safety.py) ·
> **Verified:** 2026-10-22

<!-- [[[cog import generate_docs as g; cog.out(g.test_header("1.6", page=cog.inFile)) ]]] -->

|  |  |
|---|---|
| Test ID | `1.6` |
| Name | Session Cookie Safety |
| Domain | 1 - Identity and Authentication |
| Priority / strategy | P3 / GREY_BOX |
| Effect | READ_ONLY |
| CWE | CWE-1004 |
| Standards | `OWASP API2:2023`, `OWASP ASVS v5.0.0-3.3.1`, `OWASP ASVS v5.0.0-3.3.2`, `OWASP ASVS v5.0.0-3.3.4`, `CWE-614`, `CWE-1275`, `CWE-384`, `RFC 6265, Section 4.1.2` |
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

## 2. Sub-tests and coverage of the methodology

| Sub-test | Methodology (guarantee 1.6) |
|---|---|
| `cookie_attributes` | the `[audit]` item "session cookies are issued with `HttpOnly`, `Secure` and `SameSite`, from the `Set-Cookie` header of a login response" |
| left out | the session store's TTL and replication mode (they need the store's configuration, which the tool does not read); the `[empirical test]` session fixation (see the limitations); the randomness of the identifier (a property of the library, not observable from outside) |

## 3. Inputs

The login artefact of role `user_a` (`TestContext.login_artefact`): the record of the login request and its
response, kept by the engine for the tests that read it. The engine obtains the credential of every account a test
declares as a need before running it, so the artefact is there whenever the role is configured as a login.

**This test sends no request of its own.**

## 4. Preconditions and reference responses

None: the evidence is the `Set-Cookie` headers of a response that has already been received.

## 5. Probes

None. Every cookie of the login response is read, except one the response is clearing (an empty value, `Max-Age`
zero or negative, a past `Expires`): a login often clears a stale cookie, and the attributes of a cookie being
removed say nothing.

**Every cookie is judged, whatever its name.** The old test looked for names from a fixed list (`session`, `sid`,
`PHPSESSID`, `JSESSIONID`, `connect.sid`, `_session`, `auth_session`, ...) and skipped on all three labs; a list of
names skips exactly the cookie whose name nobody guessed.

## 6. Oracle

| Case | Outcome / detail | Confidence |
|---|---|---|
| the cookie carries `Secure`, `HttpOnly` and `SameSite=Strict` or `Lax` | `ENFORCED/COOKIE_SAFE` | - |
| `Secure` missing | `VIOLATION/COOKIE_WITHOUT_SECURE` (CWE-614) | CERTAIN: the header as the target sent it |
| `HttpOnly` missing | `VIOLATION/COOKIE_WITHOUT_HTTPONLY` (CWE-1004) | CERTAIN |
| `SameSite` missing, or `SameSite=None` | `VIOLATION/COOKIE_WITHOUT_SAMESITE` (CWE-1275) | CERTAIN |

`SameSite=None` counts as absent: it is a value the standard allows and it restricts nothing. ASVS v5.0.0-3.3.2
asks for a value "set according to the purpose of the cookie", and for a cookie that carries a session `None` is
not such a value.

## 7. Outcomes

SKIP, with the reason, when the credential does not come from a login (`credentials.auth_type` is not `login`, so
there is no login response to read), or when the login response set no cookie: a target that keeps no session in a
cookie has nothing to judge here. Both lab applications answer a login with a token in the body.

## 8. Findings

One per missing attribute, per cookie: "Session cookie without `<attribute>`: `<name>`", with what the attribute
protects against; `evidence_ref` the login record, which is pinned as evidence. Each finding cites the catalogue
entry of its own attribute.

## 9. Effects on the target

`READ_ONLY`, and no request at all: the login has already happened.

## 10. Per gateway

Independent of the gateway, and a gateway that manages the session itself is covered by the same reading: the
cookies it adds to the login response are judged like any other.

## 11. Configuration

None. The old parameter listing cookie names is gone with the old test.

## 12. Validation

Runs of 2026-10-22:

| Lab | Status | Basis |
|---|---|---|
| Forgejo + Kong, Forgejo + APISIX, crAPI + Kong | SKIP | the login sets no cookie: Forgejo's login creates an API token and crAPI's answers with a token in the body |
| Forgejo + Kong, with the case below | **FAIL, 3 findings** | the cookie `lab_session` without any of the three attributes: one finding each, CERTAIN |
| Forgejo + Kong, the same with `Secure; HttpOnly; SameSite=Strict` | **PASS complete** | 1 enforced |
| Forgejo + Kong, the same with `SameSite=None` | **FAIL, 1 finding** | `COOKIE_WITHOUT_SAMESITE`: a value that restricts nothing counts as absent |

**The case, and how to undo it.** No lab keeps a session in a cookie, so the cookie is added by the gateway, which
is what a gateway managing the session itself does. In
`test-environments/forgejo-kong/kong/kong.yml`, inside `services[forgejo-service].routes`, add a route covering the
login path with a response transformation:

```yaml
      - name: review-login-cookie-route
        paths:
          - /api/v1/users/user-a/tokens
        strip_path: false
        preserve_host: false
        protocols:
          - https
        https_redirect_status_code: 301
        plugins:
          - name: response-transformer
            config:
              add:
                headers:
                  - "Set-Cookie: lab_session=zqxv7f3a9c; Path=/"
```

Then `cd test-environments/forgejo-kong && docker compose --env-file ../../.env up -d --force-recreate --wait
kong`. The other two cases are the same line with `; Secure; HttpOnly; SameSite=Strict` and with `; SameSite=None`.
Undo with `git checkout test-environments/forgejo-kong/kong/kong.yml` and the same `docker compose` command; the
lab was checked afterwards to give its usual results (2026-10-22).

**What each branch has been seen doing** (rule 9). Every branch of this test has been seen: `COOKIE_SAFE`, the
three `COOKIE_WITHOUT_*` branches (the cases above), the second SKIP reason on the three labs as they stand, and
the first with a scratch configuration that replaces the login with a static credential
(`credentials.auth_type: static_token`, `user_a_token: "zqxv-not-a-real-token"`): no login response exists, and the
test skips with that reason. No change to a lab is needed for it.

## 13. Remediation

Set `Secure`, `HttpOnly` and `SameSite=Strict` (or `Lax` where a cross-site navigation must keep the session) on
every cookie that carries a session, and renew the identifier when the user authenticates.

## 14. Limitations

- **Session fixation is not checked.** It needs a login that can be repeated while carrying a cookie obtained
  before it. The prepared-resource mechanism logs in once per role, and a form login with a CSRF token is not
  something the tool can drive in a general way. The check is left out rather than approximated by comparing two
  unrelated visits, which would prove nothing.
- The session store's TTL and its replication mode are not read: the tool does not have the store's configuration.
- Only the login of role `user_a` is read.
- A target that keeps no session in a cookie is skipped, which says nothing about how it keeps its session.
- The `__Host-` and `__Secure-` name prefixes that ASVS v5.0.0-3.3.1 and 3.3.3 also ask for are not checked: this
  test reads the attributes, not the name.

## 15. Sources

- OWASP API2:2023 Broken Authentication: https://owasp.org/API-Security/editions/2023/en/0xa2-broken-authentication/
- OWASP ASVS v5.0.0-3.3.1 (`Secure`), v5.0.0-3.3.4 (`HttpOnly` on a cookie scripts must not read) and
  v5.0.0-3.3.2 (`SameSite` "set according to the purpose of the cookie"):
  https://github.com/OWASP/ASVS/blob/v5.0.0/5.0/en/0x12-V3-Web-Frontend-Security.md
- CWE-1004 Sensitive Cookie Without 'HttpOnly' Flag: https://cwe.mitre.org/data/definitions/1004.html
- CWE-614 Sensitive Cookie in HTTPS Session Without 'Secure' Attribute: https://cwe.mitre.org/data/definitions/614.html
- CWE-1275 Sensitive Cookie with Improper SameSite Attribute: https://cwe.mitre.org/data/definitions/1275.html
- CWE-384 Session Fixation (the check left out): https://cwe.mitre.org/data/definitions/384.html
- RFC 6265 section 4.1.2 (the attributes of a cookie): https://www.rfc-editor.org/rfc/rfc6265.html#section-4.1.2

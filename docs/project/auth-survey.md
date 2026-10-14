# Authentication Survey

> **Audience:** project owner, Claude Code · **Status:** working file for step 2 of block 7+8 (how the tool obtains
> and sends credentials to the target API), written 2026-10-11 · **Sources:** the code at the lines cited, the
> OpenAPI specification, the two lab specifications, the links below.

## 1. How the tool works today

```
config.yaml   credentials: auth_type + three accounts (admin, user_a, user_b), each username and password
   |
Phase 3       copied into RuntimeCredentials (src/core/models/runtime.py), a second definition with its own default
   |
tests that log in (1.4, 2.1, 7.2) call acquire_tokens(role) (src/tests/helpers/auth.py)
   |
dispatcher    if auth_type == "forgejo_token": create a Forgejo API token with Basic Auth (auth_forgejo.py),
                                               register it for deletion at teardown
              elif auth_type == "jwt_login":   POST username and password as JSON to login_endpoint, read the
                                               token at token_response_path (auth_jwt_login.py)
   |
TestContext   raw token stored per role
   |
each test     writes its own header: "Authorization: Bearer <token>" (2.1, 7.2, forgejo_resources.py);
              1.4 writes "token <value>" and does Basic Auth and the Forgejo token API by itself
```

Structural problems:

1. Two things under one name: how a credential is **obtained** (login) and how it is **sent** (header). The second is
   not configurable: every test writes `Bearer`.
2. The login methods are an `if`/`elif` on a string: a new method means changing the central code (the gateway
   adapters solve the same problem).
3. Every account is assumed to be "username and password that give a token". API keys issued out of band (no
   login), OAuth 2.0 client credentials, session cookies cannot be configured.
4. The Forgejo login creates real tokens on the target (an effect, removed at teardown); the JSON login does not.
5. Forgejo as default (`auth_type: forgejo_token`) and in messages ("acquire tokens via the Forgejo API",
   `src/tests/base.py` `_requires_credentials`).
6. `auth_type` defined twice (`CredentialsConfig`, `RuntimeCredentials`), with two defaults.
7. Test 1.4 bypasses the mechanism (test review).

## 2. The standard: OpenAPI security schemes

An OpenAPI specification declares how its API authenticates, in `components.securitySchemes` (Swagger 2.0:
`securityDefinitions`). OpenAPI 3.1, Security Scheme Object [1]:

| `type` | Fields | What it means |
|---|---|---|
| `apiKey` | `name`, `in`: `query`, `header` or `cookie` | a key sent in a named header, query parameter or cookie |
| `http` | `scheme` (e.g. `bearer`, `basic`), `bearerFormat` (hint, e.g. `JWT`) | the `Authorization` header with that scheme |
| `mutualTLS` | - | a client certificate |
| `oauth2` | `flows`: `implicit`, `password`, `clientCredentials`, `authorizationCode` | an OAuth 2.0 token obtained with one of the flows |
| `openIdConnect` | `openIdConnectUrl` | OpenID Connect discovery |

Swagger 2.0 has `basic`, `apiKey` and `oauth2`.

What the two lab specifications declare:

| Lab | Declared |
|---|---|
| crAPI 1.1.6 | `bearerAuth`: `type: http`, `scheme: bearer`, `bearerFormat: JWT` (one scheme) |
| Forgejo 14.0.5 | `BasicAuth` (`basic`); `AuthorizationHeaderToken` (`apiKey` in header `Authorization`, "API tokens must be prepended with `token` followed by a space"); `AccessToken` (`apiKey` in query `access_token`, deprecated); `SudoHeader`/`SudoParam`; `TOTPHeader` |

So the "sending" side is already described by the specification the tool reads: on crAPI it says `Bearer`; on
Forgejo it offers several schemes, and the tests use `Bearer`, which Forgejo also accepts (observed on the lab:
the tests pass with it), although its specification documents `token <value>`.

## 3. How credentials are obtained

| Method | What the tool needs | Login request? | Effect on the target | Lab case |
|---|---|---|---|---|
| **Static credential** (API key, long-lived token) | the value, from an environment variable | no | none | none yet (Forgejo tokens can be created by the lab setup) |
| **HTTP Basic** | username and password; they are the credential | no | none | Forgejo (`BasicAuth`) |
| **JSON login** (today `jwt_login`) | login path, field names, where the token is in the response | yes | none (stateless JWT) | crAPI |
| **Forgejo token API** (today `forgejo_token`) | username and password | yes | creates a token, deleted at teardown | Forgejo |
| **OAuth 2.0 client credentials** (RFC 6749, 4.4 [2]) | token endpoint, client id and secret, scope | yes | none | none |
| **Session cookie** | login request and cookie name | yes | a session | none |
| **Mutual TLS** | client certificate and key | no | none | none |

Usage data are weak: Postman's State of the API does not publish a split by method (its 2023 respondents ranked
"improper authentication, authorization, or access control" as the top API security risk [3]); a directory of 1,625
public APIs reports about 50% API key, 40% no authentication, 9% OAuth 2.0 [4], a sample of public APIs only.

## 4. Direction (to be decided point by point)

Like the gateway adapters, an **authentication method** component chosen in the configuration, with two
responsibilities:

- **obtain** the credential of each role (one method per row of section 3);
- **apply** it to a request (header and scheme, `apiKey` in header, query or cookie, Basic), ideally derived from the
  specification's security scheme, overridable in the configuration.

Tests ask "the headers (or parameters) for role user_a" and know nothing about Bearer or Forgejo. Candidate first set,
each proven on a lab: static credential, HTTP Basic, JSON login, Forgejo token API (as one method among others, not
a default). OAuth 2.0 client credentials, session cookie and mutual TLS when a lab provides a case.

## 5. Decisions

> Superseded in part by Phase E (2026-10-14, [`resources-design.md`](resources-design.md)): `json_login` and
> `forgejo_token` became one method, `login`, whose request is a prepared resource of `config.yaml`; the revocation
> of test 1.4 is the resource's delete request. The decisions below are kept as the record of 2026-10-11/12.

- 2026-10-11 (owner): direction accepted: an authentication method component with two responsibilities, obtain and
  apply; first set static credential, HTTP Basic, JSON login, Forgejo token API (not a default). OAuth 2.0 client
  credentials, session cookie and mutual TLS stay in view: the design must let them be added later with little
  change.
- 2026-10-11 (owner), **apply**: the format comes from the specification's security schemes: one scheme is used as
  is; with several, `credentials.security_scheme` names the one to use (otherwise `validate-config` stops listing the
  names); with none, `credentials.send_as` (`in`: header, query or cookie; `name`; optional `prefix`) is required;
  `oauth2` and `openIdConnect` schemes are sent as `Authorization: Bearer` (RFC 6750). New keys `security_scheme`,
  `send_as`. On the Forgejo lab the tests send `Bearer` today, which Forgejo accepts but does not document: its
  configuration will name a declared scheme; results to be verified unchanged.
- 2026-10-11 (owner), **obtain**: `credentials.auth_type` has no default and is required when accounts are
  configured; values `basic`, `static_token` (new: `admin_token`, `user_a_token`, `user_b_token` from `.env`),
  `json_login` (renamed from `jwt_login`: the method reads any token from a JSON response; the old name gives a clear
  error at startup), `forgejo_token`; each value requires its own keys, checked by `validate-config`; the other keys
  stay. Breaking (changelog). The second definition of `auth_type` in `RuntimeCredentials` goes. Forgejo lab adds
  `auth_type: forgejo_token`; cRAPI lab `json_login`.
- 2026-10-11 (owner), **revocation (test 1.4)**: revoking a credential is an optional capability of the
  authentication method; only `forgejo_token` offers it now (the procedure 1.4 runs today moves into the method); 1.4
  uses it when present, otherwise returns SKIP ("not applicable: the authentication method cannot revoke a
  credential"). Logout or password change are added to `json_login` when a lab provides a real case. Verified on the
  cRAPI lab (2026-10-11): crAPI has no logout endpoint; a token keeps working after a password change and after a new
  login (`GET /identity/api/v2/user/dashboard` 200 in both cases; restored afterwards); its code checks only the JWT
  signature (`JwtAuthTokenFilter`, `JwtProvider.validateJwtToken` at v1.1.6) and `resetPassword` does not touch tokens.
  Right after the change the old password was still accepted, then rejected minutes later: cause not verified. The
  methodology sub-test "token rejected after a password change" (Q-32) would give a real FAIL on crAPI.

- 2026-10-12 (owner delegated the choice), **prefix with a declared scheme**: `credentials.send_as` describes how
  the credential is sent, and every field left out is taken from the specification's scheme. With a declared
  `apiKey` scheme only `prefix` may be set (`in` and `name` come from the scheme; setting them differently is an
  error); schemes that define their own format (`http` basic or bearer, `oauth2`, `openIdConnect`) take no prefix
  (error). Reason: an `apiKey` scheme has no prefix field in OpenAPI, and APIs often describe one in words only;
  Forgejo declares `AuthorizationHeaderToken` (`apiKey`, header `Authorization`) and writes "API tokens must be
  prepended with "token" followed by a space" in its description. Writing the prefix into the value works only for
  a value typed by a person (Swagger UI, Schemathesis `api_key`), not for a token the tool obtains
  (`forgejo_token`, `json_login`); openapi-generator clients keep a prefix per scheme, separate from the key
  (`api_key_prefix`). Forgejo lab: `security_scheme: AuthorizationHeaderToken`, `send_as: {prefix: "token "}`.

## Sources

1. OpenAPI Specification 3.1.0, Security Scheme Object: https://spec.openapis.org/oas/v3.1.0#security-scheme-object
2. RFC 6749, The OAuth 2.0 Authorization Framework, section 4.4: https://www.rfc-editor.org/rfc/rfc6749#section-4.4
3. ReadMe, API authentication (citing Postman State of the API 2023): https://readme.com/resources/api-authentication
4. publicapis.dev, API authentication methods: https://publicapis.dev/blog/api-authentication-methods

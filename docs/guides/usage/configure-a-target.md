# Configure a Target

> **Audience:** users · **Status:** v0.1.0 · **Source of truth:** `src/config/schema/tool_config.py`,
> `src/config/loader.py`, `src/cli.py`, `src/core/tls.py`, per-test pages in [`tests/`](../../tests/README.md) ·
> **Verified:** 2026-10-15 (TLS and certificates: every command run against the labs), 2026-10-06
> (minimal configuration run against the lab, native tests only, and `generate-seed`; behaviour on a non-Forgejo target from the
> crAPI lab, see [test portability](../../reference/compatibility.md#test-portability))

How to point the tool at your own API. Do this **only against systems you are allowed to test**: the tool sends
unauthenticated requests to every endpoint, requests with invalid tokens, and SSRF payloads.

Previous page: [First assessment](../../getting-started/first-assessment.md), which uses the lab and the committed
`config.yaml`. Every key mentioned here is described in the [configuration reference](../../reference/configuration.md).

## What you need, and what it enables

The tool runs with only a URL and an OpenAPI specification. Each extra piece of information enables more tests;
without it those tests return SKIP (a missing precondition, not a pass).

| Information | Enables | Without it |
|---|---|---|
| Base URL of the API + its OpenAPI specification | 0.1, 0.2, 0.3, 1.1, 1.5, 1.6, 4.1, 6.2, 6.4 (sub-test A) | nothing runs |
| Accounts: an admin and an ordinary user (`user_a`) | 1.4 (admin, WHITE_BOX), 2.1 and 7.2 (`user_a`, GREY_BOX) | SKIP |
| Real identifiers of existing resources (`path_seed`) | meaningful results on endpoints with `{parameters}` (mainly 1.1) | those probes end `INCONCLUSIVE_PARAMETRIC` |
| Gateway Admin API (Kong or APISIX) | 3.3, 4.2, 4.3, 6.4 sub-test B | SKIP |

## 1. Create a configuration file

Keep `config.example.yaml` (repository root: every key with its description and default) as a reference and create
a separate file for your API, in the repository folder (the name is free, here `my-api.yaml`):

```yaml
target:
  base_url: "https://api.example.com"
specification:
  url: "https://api.example.com/openapi.json"
```

- `base_url`: the address clients use, i.e. **through the gateway** if there is one.
- The specification: `specification.url` (downloaded at every run) **or** `specification.path` (a local file,
  relative to the repository folder), not both.

Check it:

```bash
hatch run apiguard validate-config -c my-api.yaml
```

Expected: `Configuration valid. Target: https://api.example.com/`, followed by `6 of the 15 selected tests will SKIP
(what they need is not configured):` and one line per test with its reason (1.4 needs the admin account, 2.1 and 7.2
a user account and their parameters, 3.3, 4.2 and 4.3 a gateway). They are not errors: the next steps give the
tests what they need, and `apiguard list-tests -c my-api.yaml` shows the same for every test (verified
2026-10-17).

`validate-config` checks the file and the certificate files of the `tls` blocks: it does not contact the API and does
not check that the specification exists (that happens when the run starts).

## 2. TLS and certificates

Every connection of the tool (the API, the specification, the gateway's Admin API and health interface) checks the
server's certificate, as a browser does. Nothing to configure when the certificates are issued by a public authority,
or by your company's authority **installed in the operating system** (by the IT team): the tool trusts the
system's store plus certifi's list.

Each connection has its own optional `tls` block ([reference](../../reference/configuration.md#tls-certificates-of-a-connection)):

| You have | Set | The report says |
|---|---|---|
| a public certificate, or the company authority installed in the system | nothing | verified (system) |
| a certificate from a private authority not installed in the system | `tls.ca_bundle: <the authority's PEM file>` | verified (ca_bundle) |
| a server that asks for the client's certificate (mutual TLS) | `tls.client_cert` and `tls.client_key` | client certificate: yes |
| a quick test against a server whose certificate you cannot obtain | `tls.verify: false` | **not verified** (in red) |

`ca_bundle` **replaces** the default authorities for that connection (as `curl --cacert`): put in it every
authority the connection needs. `verify: false` accepts any certificate, an impostor's too; a report produced with it
cannot say it talked to the right server.

```yaml
target:
  base_url: "https://api.internal.example.com"
  tls:
    ca_bundle: certs/company-ca.pem
gateway:
  adapter: apisix
  admin:
    url: "https://gw-admin.internal.example.com:9180"
    tls:
      ca_bundle: certs/company-ca.pem
      client_cert: certs/apiguard.crt
      client_key: certs/apiguard.key
```

**Where the files come from.**

- **The authority** (`ca_bundle`): from who manages the certificates (the IT or security team), as a PEM file
  (text starting with `-----BEGIN CERTIFICATE-----`). To see which authority issued a server's certificate, so you
  know what to ask for:

  ```bash
  openssl s_client -connect api.internal.example.com:443 -servername api.internal.example.com </dev/null 2>/dev/null \
    | openssl x509 -noout -subject -issuer -enddate
  ```

  Then check the file before the run: `curl --cacert certs/company-ca.pem https://api.internal.example.com/` must
  answer without a certificate error.
- **The client certificate and its key** (`client_cert`, `client_key`): from who runs the server that asks for
  them (for a gateway's Admin API, its administrators). Both PEM, the key not encrypted.
- **A `.p12` / `.pfx` file** (certificate and key in one file with a password): convert it to the two PEM files, then
  make the key readable only by you:

  ```bash
  openssl pkcs12 -in apiguard.p12 -clcerts -nokeys -out certs/apiguard.crt
  openssl pkcs12 -in apiguard.p12 -nocerts -nodes -out certs/apiguard.key
  chmod 600 certs/apiguard.key
  ```

  With OpenSSL 3 an older `.p12` can fail with `unsupported` and `RC2-40-CBC`: add `-legacy` to both commands.
- **An encrypted key** (`-----BEGIN ENCRYPTED PRIVATE KEY-----`): the tool never asks for a password (a CI job would
  hang); decrypt it once, `openssl pkey -in encrypted.key -out certs/apiguard.key`, then `chmod 600`.

**Private keys.** A client key is a credential: keep it out of the repository, readable only by the user that runs
the tool (`chmod 600`; the tool warns otherwise). In CI, store it in the CI's secret manager, write it to a file at
job start with permissions `600`, and give its path through an environment variable:
`client_key: "${APIGUARD_ADMIN_CLIENT_KEY_FILE}"`. Only the path is in the configuration; the key's content is read
by the TLS library and never written to logs or reports.

**When it fails.** A certificate problem stops the run before any test (exit `10`) on the API and on the
specification, and makes the gateway audits SKIP on the Admin API; the message names the key to set. On screen:

```text
Exit 10   INFRA - the assessment did not run
Reason    Connection to the API failed before any test: the server's certificate is not trusted
          (unable to get local issuer certificate): set target.tls.ca_bundle to the authority that
          issued it (or install that authority in the system's store).
```

Every message and what to do: [TLS errors](../../reference/configuration.md#tls-errors).

**Test 1.5 on a non-standard port.** If the API listens for HTTPS on a non-standard port, test 1.5 cannot guess the
plain-HTTP address for its HTTP-to-HTTPS redirect probe: it sends plain HTTP to the HTTPS port and reports a FAIL
that is not real (on the lab: `GET http://localhost:8443/` → `400`, finding `HTTP Port Accessible Without HTTPS
Redirect`). Set the address explicitly
([`tests.domain_1.test_1_5.http_url`](../../reference/configuration.md#testsdomain_1test_1_5)),
e.g. `http://api.example.com:8000/`.

## 3. Credentials

Tests log in as `admin` (test 1.4, WHITE_BOX: the administrator account is full access) or `user_a` (tests 2.1
and 7.2, GREY_BOX). The configuration also accepts a third
role, `user_b`, but no v0.1.0 test uses it: it is reserved for tests that compare two users of the same level, such
as object-level authorization (BOLA, guarantee 2.2, planned). You can leave it out. Create the accounts on the target first, then
put the values in `.env` (repository folder, ignored by git) and refer to them with `${VAR}`. Never write a
password in the YAML file.

Add your own variables to `.env` (any uppercase name):

```bash
MYAPI_ADMIN_USER=...
MYAPI_ADMIN_PASSWORD=...
```

Two things to set: **how the tool obtains a credential** (`credentials.auth_type`, required) and, when your
specification does not settle it by itself, **how the credential is sent** (`security_scheme`, `send_as`).

| `auth_type` | For | How it obtains the credential |
|---|---|---|
| `basic` | an API that accepts HTTP Basic | username and password, sent as `Authorization: Basic ...` |
| `static_token` | an API key or a token you already have | `admin_token`, `user_a_token`, `user_b_token` (from `.env`) |
| `login` | an API that gives a token in exchange for a login request (a JSON login, a token API) | sends the request of a [prepared resource](../../reference/configuration.md#resources) named in `login_resource` and reads the token from its response; with a delete request, the tokens are deleted at the end of the run and test 1.4 can revoke one |

How the credential is sent comes from the security schemes your specification declares:

- **one** scheme that can carry a token (an `apiKey`, `http` bearer, OAuth 2.0, OpenID Connect): nothing to set;
- **several**: name the one to use in `security_scheme` (the tool stops and lists them if you do not);
- **none**: describe it in `send_as` (`in`: `header`, `query` or `cookie`; `name`; optional `prefix`);
- an `apiKey` scheme whose prefix is described only in words (e.g. "tokens must be prepended with `token`"): add
  `send_as: {prefix: "token "}`.

`apiguard validate-config` reads the specification and prints where the credentials will be sent.

Example of a JSON login (from `test-environments/crapi-kong/config.yaml`, where the login takes an email and returns
`{"token": "..."}`, and the specification declares one bearer scheme). The placeholders `{username}` and
`{password}` are the account of each role, and must be quoted:

```yaml
credentials:
  auth_type: login
  login_resource: api-login
  admin_username: "${MYAPI_ADMIN_USER}"
  admin_password: "${MYAPI_ADMIN_PASSWORD}"
  user_a_username: "${MYAPI_USER_A}"
  user_a_password: "${MYAPI_USER_A_PASSWORD}"
  user_b_username: "${MYAPI_USER_B}"
  user_b_password: "${MYAPI_USER_B_PASSWORD}"

resources:
  api-login:
    create:
      path: /identity/api/auth/login
      auth: none
      body:
        email: "{username}"
        password: "{password}"
    values:
      credential: token          # where the token is in the response
```

Example of a token API (from `test-environments/forgejo-kong/config.yaml`: Forgejo creates tokens with HTTP Basic,
declares several schemes, and its token header needs the `token ` prefix). The delete request removes each token at
the end of the run and lets test 1.4 revoke one:

```yaml
credentials:
  auth_type: login
  login_resource: forgejo-token
  security_scheme: AuthorizationHeaderToken
  send_as:
    prefix: "token "
  admin_username: "${ADMIN_USERNAME}"
  admin_password: "${ADMIN_PASSWORD}"
  user_a_username: "${USER_A_USERNAME}"
  user_a_password: "${USER_A_PASSWORD}"

resources:
  forgejo-token:
    create:
      path: "/api/v1/users/{username}/tokens"
      auth: basic
      body:
        name: "apiguard-{random}"
        scopes: ["read:repository", "read:user", "write:repository", "write:user"]
    values:
      credential: sha1
      id: id
    delete:
      path: "/api/v1/users/{username}/tokens/{id}"
      auth: basic
```

Example for `static_token` with an API key in a header the specification does not declare:

```yaml
credentials:
  auth_type: static_token
  user_a_token: "${MYAPI_USER_A_KEY}"
  send_as:
    in: header
    name: X-Api-Key
```

Rules:

- Username and password of a role go together, or the role is left out entirely; `static_token` takes tokens
  only, the other methods username and password only.
- A `${VAR}` without a value stops the tool with `Environment variable(s) not set`, **even inside a YAML comment**.
- Credentials rejected by the target (`401`/`403` at login) make the tests that log in return ERROR.

## 4. Real identifiers (`path_seed`)

Many endpoints contain parameters, such as `/repos/{owner}/{repo}/issues/{index}`. Without real values the tool
fills them with placeholders (usually `1`), the API answers `404` before checking authentication, and the probe
says nothing (`INCONCLUSIVE_PARAMETRIC`).

Generate the list of parameter names from the specification:

```bash
hatch run apiguard generate-seed https://api.example.com/openapi.json -o seed.yaml
```

`seed.yaml` contains a `path_seed:` block with every parameter set to `FILL_ME`. Replace each value with the
identifier of a resource that **exists** on the target (preferably owned by `user_a`), remove the ones you cannot
fill (they fall back to the placeholder), and paste the block under `target:` in `my-api.yaml`. Values can be
`${VAR}` too.

Only fill in what you can: the more parameters point to real resources, the fewer inconclusive probes. The lab's
`config.yaml` is a complete example. Measured on the lab, test 1.1: 335 inconclusive probes out of 482 without
`path_seed`, 63 with it.

**Use resources created for the test, never real data.** Test 1.1 also sends `DELETE` requests without
credentials to the seeded resources: on a correctly protected API they are rejected, but if authentication is
missing on that endpoint the resource is deleted.

## 5. Gateway Admin API (optional: Kong or APISIX)

If the API is behind **Kong** or **Apache APISIX** and you can reach its Admin API, the configuration-audit tests
can run:

```yaml
gateway:
  adapter: kong
  admin:
    url: "https://kong-admin.internal:8444"
```

For APISIX the Admin API needs a key (a key of role `viewer`, GET only, is enough), and the live health of the
backends is read from its Control API:

```yaml
gateway:
  adapter: apisix
  admin:
    url: "https://127.0.0.1:9180"
    headers:
      X-API-KEY: "${APISIX_VIEWER_KEY}"
  health:
    url: "http://127.0.0.1:9090"
```

An Admin API over HTTPS takes a `tls` block as the API does (step 2): APISIX can require a client certificate
(`admin_api_mtls`). With another gateway leave `gateway` out and those tests return SKIP. A complete example, with
HTTPS, client certificate and key: `test-environments/forgejo-apisix/config.yaml`.

## 6. Settings that assume Forgejo or Kong

Some test defaults are written for the lab. On another target review them:

| Test | Setting | What to do on another target |
|---|---|---|
| 7.2 | no endpoint that accepts a URL by default: SKIP until configured | set `url_accepting_endpoint` (its `path`, and its `body` with `"{ssrf_url}"`) to an endpoint of your API that accepts a URL; if the endpoint belongs to an object that must exist first, add a [prepared resource](../../reference/configuration.md#resources) and name it in the endpoint's `resource` ([reference](../../reference/configuration.md#testsdomain_7test_7_2)) |
| 2.1 | no admin path by default: SKIP until configured | list admin-only endpoints of your API; a path your API does not have answers `404`, counted as enforced, so the test can PASS without testing anything |
| 1.4 | needs `auth_type: login` with a login resource that has a delete request, and `protected_endpoint` (an endpoint that requires authentication) | SKIP otherwise, naming what is missing |
| 0.2, 6.4 | Kong-specific server identifiers and block message | review [`tests.domain_0.test_0_2`](../../reference/configuration.md#testsdomain_0test_0_2) and [`tests.domain_6.test_6_4`](../../reference/configuration.md#testsdomain_6test_6_4) |

Measured on cRAPI on 2026-10-06 (no gateway, `jwt_login`, now a `login` resource, 7.2 posting to a fixed path): 0.1, 0.2, 0.3, 1.1, 1.5, 1.6, 4.1, 6.2 and
6.4 ran normally, 7.2 worked, 2.1 passed only because the Forgejo admin paths do not exist there, 1.4 returned ERROR,
3.3, 4.2 and 4.3 returned SKIP. The current behaviour on the three labs is in
[test portability](../../reference/compatibility.md#test-portability).

## Effects on the target

The tool is not read-only. Before the first run on a system that matters, know what it does (details in the
"Prerequisites and effects on the target" section of each [test page](../../tests/README.md)):

| Test | Effect |
|---|---|
| 1.1 | `POST`/`PUT`/`PATCH`/`DELETE` without credentials on every protected endpoint, including the `path_seed` resources |
| 1.4 | creates a credential with the login resource on the admin account and revokes it |
| 2.1 | sends the configured method with a `user_a` token (default `GET`, read-only) |
| 4.1 | up to 300 requests in a burst against one endpoint: it can trip the rate limit for the tool's IP |
| 7.2 | up to 73 `POST` requests with a valid token. With the endpoint's `resource` the resource is deleted at teardown, and objects created under it usually go with it (Forgejo webhooks); without it, on a vulnerable API each request may create an object that is **not removed** afterwards |

## 7. First run

Start without the external tools (nuclei, testssl.sh, sslyze): the run takes seconds instead of minutes and shows
whether the configuration works. The external tools are off unless your file enables them; if you copied a section
from the lab's configuration (`test-environments/forgejo-kong/config.yaml`), set:

```yaml
external_tools:
  enabled: false
```

Run:

```bash
hatch run apiguard run -c my-api.yaml
```

Without `output.directory` the reports go to `outputs/` and replace those of the previous run (the labs write to
`outputs/forgejo/` and `outputs/crapi/`). To keep them apart, set a folder in your file
([`output.directory`](../../reference/configuration.md#output)), e.g. `outputs/my-api`.

Then check, in this order:

1. No test in **ERROR**: an ERROR means the check could not be completed (wrong URL, rejected credentials, a Forgejo
   default on another target). Its message says why.
2. The **SKIP** tests are the ones you expect from the table at the top.
3. Few `INCONCLUSIVE_PARAMETRIC` probes in test 1.1: if there are many, fill in more of `path_seed`.

Then enable the external tools ([reference](../../reference/configuration.md#external_tools)) for a complete
assessment.

## See also

- Next: [Select tests](select-tests.md), to run only part of the assessment.

- [Configuration reference](../../reference/configuration.md): every key, default and constraint.
- [CLI reference](../../reference/cli.md): `run`, `validate-config`, `list-tests`, `generate-seed`, `.env` loading.
- [Test catalogue](../../tests/README.md): what each test needs and checks.

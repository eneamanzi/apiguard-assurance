# Configure a Target

> **Audience:** users · **Status:** v0.1.0 · **Source of truth:** `src/config/schema/tool_config.py`,
> `src/config/loader.py`, `src/cli.py`, per-test pages in [`tests/`](../../tests/README.md) · **Verified:** 2026-10-06
> (minimal configuration run against the lab, native tests only, and `generate-seed`; behaviour on a non-Forgejo target from the cRAPI
> run recorded in Q-18)

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
| Gateway Admin API (Kong only) | 3.3, 4.2, 4.3, 6.4 sub-test B | SKIP |

## 1. Create a configuration file

Keep the committed `config.yaml` for the lab and create a separate file for your API, in the repository folder (the
name is free, here `my-api.yaml`):

```yaml
target:
  base_url: "https://api.example.com"
  openapi_spec_url: "https://api.example.com/openapi.json"
```

- `base_url`: the address clients use, i.e. **through the gateway** if there is one.
- The specification: `openapi_spec_url` (fetched at every run) **or** `openapi_spec_path` (a local file, relative to
  the repository folder), not both.

Check it:

```bash
hatch run apiguard validate-config -c my-api.yaml
```

Expected: `Configuration valid. Target: https://api.example.com/`, preceded by two `config_coherence_warning`
lines saying that there are no credentials and no Admin API. They are warnings, not errors; steps 3 and 5 remove
them.

`validate-config` checks only the file: it does not contact the API and does not check that the specification
exists (that happens when the run starts).

## 2. TLS

`verify_tls` is `true` by default. Set it to `false` only if the API uses a self-signed certificate (as the lab does):

```yaml
target:
  verify_tls: false
```

If the API listens for HTTPS on a non-standard port, test 1.5 cannot guess the plain-HTTP address for its
HTTP-to-HTTPS redirect probe: it sends plain HTTP to the HTTPS port and reports a FAIL that is not real (on the lab:
`GET http://localhost:8443/` → `400`, finding `HTTP Port Accessible Without HTTPS Redirect`). Set the address
explicitly
([`tests.domain_1.test_1_5.http_probe_url`](../../reference/configuration.md#testsdomain_1test_1_5---credentials-over-insecure-channels)),
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

The tool supports two ways of obtaining a token (`credentials.auth_type`):

| `auth_type` | For | How it gets a token |
|---|---|---|
| `forgejo_token` (default) | Forgejo and Gitea | `POST /users/{username}/tokens` with Basic Auth |
| `jwt_login` | an API with a JSON login endpoint | posts username and password to `login_endpoint`, reads the token from the response |

Example for `jwt_login` (from `config_crapi.yaml`, where the login takes an email and returns `{"token": "..."}`):

```yaml
credentials:
  auth_type: jwt_login
  login_endpoint: "/identity/api/auth/login"
  username_body_field: email
  password_body_field: password
  token_response_path: "token"
  admin_username: "${MYAPI_ADMIN_USER}"
  admin_password: "${MYAPI_ADMIN_PASSWORD}"
  user_a_username: "${MYAPI_USER_A}"
  user_a_password: "${MYAPI_USER_A_PASSWORD}"
  user_b_username: "${MYAPI_USER_B}"
  user_b_password: "${MYAPI_USER_B_PASSWORD}"
```

Rules:

- Username and password of a role go together, or the role is left out entirely.
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

## 5. Gateway Admin API (optional, Kong only)

If the API is behind **Kong** and you can reach its Admin API, the configuration-audit tests can run:

```yaml
target:
  admin_api_url: "http://kong-admin.internal:8001"
  gateway_adapter: kong
```

Both keys are needed. `kong` is the only supported adapter; with another gateway leave both out and those tests
return SKIP (Q-38, Q-43).

## 6. Settings that assume Forgejo or Kong

Some test defaults are written for the lab. On another target review them:

| Test | Setting | What to do on another target |
|---|---|---|
| 7.2 | `injection_mode: forgejo_webhook` (creates a Forgejo repository and a webhook) | set `injection_mode: fixed_path` and `injection_path_template`, `injection_url_field`, `injection_body_template` to an endpoint of your API that accepts a URL ([reference](../../reference/configuration.md#testsdomain_7test_7_2---ssrf-prevention)) |
| 2.1 | `admin_endpoint_paths` defaults to Forgejo admin paths | list admin-only endpoints of your API; on a target without those paths a `404` is counted as enforced, so the test can PASS without testing anything |
| 1.4 | always uses the Forgejo token API | not configurable: ERROR on any other target (Q-18) |
| 0.2, 6.4 | Kong-specific server identifiers and block message | review [`tests.domain_0.test_0_2`](../../reference/configuration.md#testsdomain_0test_0_2---deny-by-default) and [`tests.domain_6.test_6_4`](../../reference/configuration.md#testsdomain_6test_6_4---hardcoded-credentials-audit) |

Measured on cRAPI (no gateway, `jwt_login`, 7.2 in `fixed_path` mode): 0.1, 0.2, 0.3, 1.1, 1.5, 1.6, 4.1, 6.2 and
6.4 ran normally, 7.2 worked, 2.1 passed only because the Forgejo admin paths do not exist there, 1.4 returned ERROR,
3.3, 4.2 and 4.3 returned SKIP (Q-18). Making the tool fully independent of Forgejo and Kong is an open decision
(Q-43).

## Effects on the target

The tool is not read-only. Before the first run on a system that matters, know what it does (details in the
"Prerequisites and effects on the target" section of each [test page](../../tests/README.md)):

| Test | Effect |
|---|---|
| 1.1 | `POST`/`PUT`/`PATCH`/`DELETE` without credentials on every protected endpoint, including the `path_seed` resources |
| 1.4 | creates and deletes an API token on the admin account |
| 2.1 | sends the configured method with a `user_a` token (default `GET`, read-only) |
| 4.1 | up to 300 requests in a burst against one endpoint: it can trip the rate limit for the tool's IP |
| 7.2 | `fixed_path`: up to 73 `POST` requests with a valid token; on a vulnerable API each may create an object that is **not removed** afterwards |

## 7. First run

Start without the external tools (nuclei, testssl.sh, sslyze): the run takes seconds instead of minutes and shows
whether the configuration works. The external tools are off unless your file enables them; if you copied a section
from the lab's `config.yaml`, set:

```yaml
external_tools:
  enabled: false
```

Run:

```bash
hatch run apiguard run -c my-api.yaml
```

The reports go to `outputs/` and replace those of the previous run, the lab's included. To keep them apart, set a
different folder in your file ([`output.directory`](../../reference/configuration.md#output)), e.g.
`outputs-my-api`.

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
- [CLI reference](../../reference/cli.md): `run`, `validate-config`, `generate-seed`, `.env` loading.
- [Test catalogue](../../tests/README.md): what each test needs and checks.

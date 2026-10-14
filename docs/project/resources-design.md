# Prepared Resources - Design

> **Audience:** project owner, Claude Code · **Status:** decided with the owner point by point (section 5,
> 2026-10-14); implemented (E1-E4, 2026-10-14) · **Plan:** block 7+8 step 4, Phase E ([`plan.md`](plan.md)) · **Created:** 2026-10-14

## 1. Why

The last code tied to one application is Forgejo's, in three places:

| Where | What it does | Lines |
|---|---|---|
| `src/tests/helpers/auth_forgejo.py` (method `forgejo_token`) | logs in by creating an API token with HTTP Basic (`POST /api/v1/users/{username}/tokens`, token in `sha1`), deletes it at teardown (`DELETE .../tokens/{id}`); for test 1.4 creates a temporary token and revokes it (`DELETE .../tokens/{name}`) | 328 |
| `src/tests/helpers/forgejo_resources.py` | `create_repository` for test 7.2 (`POST /api/v1/user/repos`, values `owner.login` and `name`, teardown `DELETE /api/v1/repos/{owner}/{repo}`); three more functions no code calls (`get_authenticated_user`, `create_issue`, `list_repositories`) | 443 |
| `src/tests/domain_1/test_1_4_token_revocation.py:73` | the request that checks the revoked token, `GET /api/v1/user` | 1 |

They all follow one pattern: **a request creates something, values are taken from its response, a request deletes
it at the end**. The `json_login` method (`auth_json_login.py`) is the same pattern without the delete: a request,
the token taken from the response.

The owner's direction (2026-10-14): structure the tool as a new designer would, so that it is solid and extensible
before 1.0.0. One building block, the **prepared resource**, declared in `config.yaml` and used by name, replaces
the three places above, and serves the planned tests that create data: 2.2 (user A creates an object, user B tries
to read it), 2.3 (destructive operations on a resource), 7.3 (race conditions on created orders)
(`docs/knowledge/methodology/methodology.it.md`).

## 2. Boundaries

- A resource is **one create request, values taken from its JSON response, one delete request**. No chains of
  steps, conditions, loops or scripts.
- **A few placeholders**, all checked at startup (exit `10` before any test): values of the role's account, values
  taken from the response, a random value.
- **No inference from the specification** (which request creates what). It can come later on top of the same
  structure.
- What data cannot describe (request signing, multi-step logins) stays **a method in the code registry**
  (`AUTH_METHODS`), as gateways have adapters.

## 3. Prior art

The pattern is standard in API testing tools:

- **Nuclei** extractors take values from a response and reuse them in the next requests of a template
  ([extractors](https://docs.projectdiscovery.io/templates/reference/extractors)).
- **Schemathesis** links a "create" operation to the operations that use its result through OpenAPI links, with
  values extracted from the response ([stateful testing](https://schemathesis.readthedocs.io/en/stable/explanations/stateful/)).
- **RESTler** (Microsoft Research) infers producer-consumer dependencies: a request that produces a resource id runs
  before the requests that consume it, which run only if the resource was created
  ([RESTler](https://www.microsoft.com/en-us/research/publication/restler-stateful-rest-api-fuzzing)).

The tool takes the declarative part (Nuclei, Schemathesis links) and leaves inference (RESTler) out (section 2).

## 4. What exists today and is kept

- `TestContext.register_resource_for_teardown(method, path, headers)`: every created object is deleted in Phase 6,
  also when the test fails; teardown errors are logged as warnings (`TeardownError`).
- The credential placement (`src/core/auth_placement.py`): how a role's credential is sent, resolved once per run
  from the specification's security schemes.
- Secret registration (`TestContext.register_secret`): passwords, tokens and Basic values masked in every output.
- `json_login`'s dotted response paths (`data.token`); 7.2's body placeholders `$SSRF_URL$` and `$RANDOM_SECRET$`.

## 5. Decisions (one at a time with the owner)

Each point: the question, the proposal, the alternatives. Examples use the Forgejo labs and crAPI.

### 5.1 Shape of a resource and placeholders - decided

```yaml
resources:
  repository:                        # the name tests use
    create:
      method: POST                   # default POST
      path: /api/v1/user/repos
      body:
        name: "apiguard-{random}"
        private: true
        auto_init: true
    values:                          # name: dotted path in the JSON response
      owner: owner.login
      repo: name
    delete:                          # optional: nothing to delete (e.g. a login)
      method: DELETE                 # default DELETE
      path: /api/v1/repos/{owner}/{repo}
```

Placeholders, in `path` and in string values of `body`:

| Placeholder | Value |
|---|---|
| `{username}`, `{password}` | the account of the role the resource is created for |
| `{random}` | 8 hexadecimal characters, the same value in the create and delete request of one resource |
| `{<value name>}` | a value of `values`, only in `delete` (they exist after the create request) |

**Decided (2026-10-14):** the shape above (owner); **one syntax `{...}`** for every value the tool fills,
including the values a test injects (7.2: `{ssrf_url}`, `{random_secret}` replace `$SSRF_URL$`, `$RANDOM_SECRET$`)
(choice delegated by the owner). Reasons: `{...}` is already the syntax of 7.2's path templates and of OpenAPI path
parameters; 7.2's body can hold both a resource value and the injected URL, which with two syntaxes would mix two
rules in one string; one parser, one startup check of the names allowed at each place. Its two costs and how they
are handled:

- in YAML a value that **starts** with `{` is read as a mapping (`email: {username}` becomes `{"username": null}`,
  sent as an object without warning): a mapping whose single key is a known placeholder and whose value is null is
  rejected at startup, asking to quote it (`email: "{username}"`);
- literal braces are written doubled, `{{` and `}}` (Python's format rule).

`${VAR}` (environment variables, interpolated by the loader) is unchanged and distinct: the `$` makes the
difference.

### 5.2 Where resources live in the configuration - decided

**Decided (owner, 2026-10-14):** a top-level section `resources:` next to `credentials:`. A resource belongs to the
target, not to one test: credentials (5.4) and tests (5.5, 5.6) refer to it by name, and the section shows in one
place what the tool creates on the target. Not under `target:`, which holds addresses and connection settings.

### 5.3 Which credential each request uses - decided

The test decides **which role** a resource is created for (7.2: user A; 2.2 in the future: user A, read by user B).
Each request says **how** it authenticates:

| `auth:` | Request sent with |
|---|---|
| `credential` (default) | the role's credential, as the placement sends it |
| `basic` | HTTP Basic with the role's username and password (Forgejo's token API requires it) |
| `none` | nothing (a login request) |

The delete request uses the same role.

**Decided (owner, 2026-10-14):** as above. The test chooses the role (who), the resource says how each request
authenticates (`credential`, `basic`, `none`), the role that created a resource deletes it.

### 5.4 One login method on top of resources - decided

`forgejo_token` and `json_login` become one method: the credential is the value `credential` of a resource.

```yaml
credentials:
  auth_type: login                   # name to decide
  login_resource: forgejo_token
  # accounts as today: admin_username, admin_password, user_a_username, ...

resources:
  forgejo_token:                     # Forgejo labs
    create:
      path: /api/v1/users/{username}/tokens
      auth: basic
      body:
        name: "apiguard-{random}"
        scopes: [read:repository, read:user, write:repository, write:user]
    values:
      credential: sha1
      id: id
    delete:
      path: /api/v1/users/{username}/tokens/{id}
      auth: basic

  crapi_login:                       # crAPI lab
    create:
      path: /identity/api/auth/login
      auth: none
      body:
        email: "{username}"
        password: "{password}"
    values:
      credential: token
```

Removed keys: `auth_type` values `json_login` and `forgejo_token`, `login_endpoint`, `username_body_field`,
`password_body_field`, `token_response_path` (breaking, with an error naming the new form). `basic` and
`static_token` stay as they are (no request).

**Decided (owner, 2026-10-14):** one method, `auth_type: login`, with `credentials.login_resource`; the login
resource needs a value `credential`. Check made before deciding:

- what it touches: in `src/`, `auth_forgejo.py` and `auth_json_login.py` (removed), `src/core/models/runtime.py`,
  `src/tests/helpers/auth.py`, `auth_base.py`, test 1.4; the engine, the CLI and the placement do not depend on
  the two methods; then the three lab configurations, `config.example.yaml` and the docs (steps E3, E4);
- users: v0.1.0 had `forgejo_token` (default) and `jwt_login`; `json_login` was never released, so users see one
  change, to `login`; the old values are rejected with a message showing the new form;
- 1.4: the revoked token is deleted again at teardown, which accepts `404` (`src/engine.py`, acceptable codes
  200, 204, 404): no teardown error;
- extension without changing the shape: a token in a response header, or a form-encoded body (e.g. OAuth 2.0
  client credentials), are new fields of a resource when a target needs them;
- cost: crAPI's login is written in full (about 8 lines instead of 4 keys with hidden defaults).

### 5.5 Test 1.4: revocation and its check - decided

1.4 obtains a fresh credential for the admin role from the login resource, revokes it, then sends the check
request with it (PASS if rejected, as today).

- **Revoke:** the login resource's `delete` (Forgejo: deleting the token). An API that revokes with a logout
  instead (a request sent with the credential itself) would need a separate `revoke` request: proposed only when a
  lab needs it (none does today; crAPI has no logout).
- **Check request:** `tests.domain_1.test_1_4.verify_request` (method and path, e.g. `GET /api/v1/user`). No path
  left in the test.
- **Not applicable:** a login resource without `delete`, or `basic` / `static_token`: SKIP as today.
- **Token name:** `tests.domain_1.test_1_4.token_name` (fixed name, with a cleanup of a leftover before creating,
  kept by the owner in Q-64) goes: names are `apiguard-{random}`, so two runs never collide and leftovers of an
  interrupted run are found by the prefix. Q-64's decision to revisit with the owner.

**Decided (owner, 2026-10-14):** revoke with the login resource's `delete`; check request in
`tests.domain_1.test_1_4.verify_request` (`method`, `path`); no `delete` → SKIP "Not applicable"; `token_name` and
the cleanup before creating removed (revises the Q-64 decision: random names make them unnecessary); a `revoke`
request (logout) added only when a lab needs it.

Note for the test review (not part of this phase): with a check request in the configuration, 1.4 could also send
it **before** revoking, as a positive control (Q-29: today 1.4 PASSes with a credential the target rejects).

### 5.6 Test 7.2 - decided

```yaml
tests:
  domain_7:
    test_7_2:
      injection_resource: repository          # optional: created for user A before probing
      injection_path_template: /api/v1/repos/{owner}/{repo}/hooks
      injection_body_template: { ... }        # as today
```

`injection_mode` goes: with `injection_resource` the path is filled with the resource's values; without it, the
path is used as written (today's `fixed_path`). If the resource cannot be created: ERROR with the reason (today
SKIP, because the Forgejo mode was a default that could not apply; now the user configured it explicitly).

**Decided (owner, 2026-10-14):** as above. Placeholders allowed in the injection body: `{ssrf_url}` (required,
once), `{random_secret}`, the resource's values; in the path, the resource's values. The request method stays
POST (an `injection_method` key, default POST, can be added later without breaking anything).

**Decided (owner, 2026-10-14):** remove `injection_url_field`. No code reads it (its description says "for report clarity only"),
which goes against the owner's rule of Q-24 (no configuration option without effect), and it can contradict the
body; where the URL goes is known from the position of `{ssrf_url}` in the body.

### 5.7 Secrets - decided

The value `credential` is always registered as a secret; passwords and Basic values as today; other values are
not secrets (repository names, ids). A flag for further secret values only when a case needs it.

**Decided (owner, 2026-10-14):** as above: what gives access to the target is masked, what explains what the tool
created stays readable. 7.2's `{random_secret}` stays masked as today (registered as a secret by the test; the
draft of this point wrongly said it was not, corrected 2026-10-14 while writing E2).

### 5.8 Startup checks - decided

**Decided (owner, 2026-10-14).** At startup (and in `validate-config`), exit `10` before any test:

| Error | Example |
|---|---|
| a resource used but not defined | `injection_resource: repositori` |
| an unknown placeholder | `{repo}` in a path, no value `repo` in the resource |
| a response value used before the response | `{id}` in `create` |
| a placeholder not quoted in YAML | `email: {username}` instead of `email: "{username}"` |
| a login resource without the value `credential` | |
| `auth: credential` in the login resource's `create` | the credential is what it obtains |
| a password needed and missing | `auth: basic` or `{password}` for a role without a password |
| 7.2 body without `{ssrf_url}`, or with it twice | |
| removed keys and values | `auth_type: forgejo_token` / `jwt_login` / `json_login`, `injection_mode`, `injection_url_field`, `token_name`: a message showing the new form |

At run time, a value missing from the response gives an ERROR naming the resource and the field.

### 5.9 Execution rules - decided with the completeness check

Found by the completeness check of the design (2026-10-14), owner asked to complete the design:

- **Success** of a create request: any `2xx`; otherwise an error with the status and the start of the body
  (redacted as every output).
- **Values** are read from a JSON object response with dotted paths (`owner.login`), as `json_login` does today;
  no array indexes. A resource without values needs no JSON response.
- **Delete request** without a body: the teardown registry keeps method, path and headers only (the model has no
  `body` for it: a body is an unknown key at startup; found while writing E2).
- **Body** sent as JSON; no query parameters, form bodies or values from response headers yet (new fields when a
  target needs them, without changing the shape).
- **Teardown** registered right after the create request, as soon as the delete request can be built. If a value
  the delete request needs is missing, the error says what was created and that it is not deleted automatically.
  Teardown runs in reverse creation order (`TestContext.drain_resources`, LIFO): a repository created with a token
  is deleted before the token.
- **Instances:** the login resource is created once per role per run (as today); a test's resource once per use
  (7.2: once per run).
- **Evidence:** every request is recorded in the transaction log under the test that needs it (login: `auth_setup`,
  as today).
- **Configuration key check:** `scripts/check_config_keys.py` treats `resources` as a free mapping today; it learns
  named mappings of a model, so that `config.example.yaml` must document a resource's fields (E4).
- **`validate-config`** lists the resources and who uses them.
- **Not now:** a check of resource paths against the specification (the labs' specification paths are relative to
  a base path; a warning can come later).

## 6. Implementation steps

Done 2026-10-14 (log in [`plan.md`](plan.md)). As built: `src/core/templating.py`, `src/core/models/resources.py`,
`src/tests/helpers/resources.py` (`create_resource`, `delete_resource`), `src/tests/helpers/auth_login.py`; the
configuration reference documents the keys ([`resources`](../reference/configuration.md#resources)). Verified on the
three labs after each step: results identical to the references, nothing left on Forgejo, no secret in the outputs.

| Step | What | Check |
|---|---|---|
| E1 | Configuration models and startup checks (5.1-5.8), not used yet | `dev:check`; `validate-config` on good and broken examples; three labs identical |
| E2 | Resource executor (create, values, teardown, secrets) and 7.2; `forgejo_resources.py` removed | Forgejo + Kong and Forgejo + APISIX identical; no `apiguard` repository left; no secret in the outputs |
| E3 | Login method and 1.4; `auth_forgejo.py`, `auth_json_login.py` removed | three labs identical; no `apiguard` token left; negative control (wrong credential) |
| E4 | Docs, `config.example.yaml`, CHANGELOG (Breaking), neutral field descriptions (Q-43) | key check; `src/` mentions Forgejo only in examples |

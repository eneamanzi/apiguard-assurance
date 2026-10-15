# Design Decisions

> **Audience:** contributors, maintainers · **Status:** decisions in force · **Source of truth:** the code cited in
> each decision; the decisions were taken with the project owner point by point (2026-10-11 to 2026-10-15) ·
> **Verified:** 2026-10-15 (each consequence checked on the three labs)

Why the tool is built the way it is, where the reason is not visible in the code: the problem, the decision, the
alternatives left out and why, the consequences. What the tool does is described in [overview](overview.md) and in
the [reference](../reference/configuration.md); this page records the reasons.

The working documents in which each decision was discussed (facts checked, options, implementation steps) were
removed once the work was done; their full text is in git, at commit `49f6e12`:

```bash
git show 49f6e12:docs/project/connections-design.md   # D1-D4
git show 49f6e12:docs/project/auth-survey.md          # D5
git show 49f6e12:docs/project/resources-design.md     # D6
git show 49f6e12:docs/project/gateway-concepts.md     # D7 (also gateway-survey.md, agnosticism-analysis.md)
```

| | Decision | Since |
|---|---|---|
| [D1](#d1-configuration-organised-by-connection) | Configuration organised by connection | 2026-10-14 |
| [D2](#d2-certificate-trust-per-connection) | Certificate trust per connection | 2026-10-14 |
| [D3](#d3-the-tool-downloads-the-specification) | The tool downloads the specification | 2026-10-14 |
| [D4](#d4-labs-at-the-highest-protection-level) | Labs at the highest protection level | 2026-10-15 |
| [D5](#d5-a-credential-is-obtained-and-sent-separately) | A credential is obtained and sent separately | 2026-10-11 |
| [D6](#d6-prepared-resources) | Prepared resources | 2026-10-14 |
| [D7](#d7-neutral-gateway-concepts) | Neutral gateway concepts | 2026-10-11 |

## D1. Configuration organised by connection

**Problem.** The tool talks to up to four parties: the API, the server of the OpenAPI specification, the gateway's
Admin API, and its health interface. Their settings were keys with a prefix under `target` (`admin_api_url`,
`admin_connect_timeout_seconds`, ...) and under `execution` (`connect_timeout`, `openapi_fetch_timeout_seconds`), and
adding certificate settings would have repeated the prefix once more for each party.

**Decision.** One section per party, with the same shape: its address, its timeouts, its `tls` block, and what that
party needs. `target` is the API, `specification` the OpenAPI document, `gateway` the gateway (`adapter`, `admin`,
`health`). `execution` keeps only what the run does (`min_priority`, `strategies`, `test_ids`, `fail_fast`). The
previous keys are rejected at startup with a message naming their new place (`src/config/schema/tool_config.py`,
`_MOVED_TARGET_KEYS`, `_MOVED_EXECUTION_KEYS`).

**Alternatives left out.** Adding `tls` keys with prefixes under `target` (`admin_api_ca_bundle`, ...): fewer changes
for existing configurations, but the same idea written in a different way for each party, and the prefixes grow with
every setting. A `tls` block that inherits from another (the Admin API using the API's): an API with an internal
authority and a public specification would break; each block is independent.

**Consequences.** One breaking change of every configuration, accepted before 1.0.0 so that the structure is stable
afterwards. One connection model (`TlsSettings`) defined once and reused.

## D2. Certificate trust per connection

**Problem.** On real systems the connections are often protected: an internal certificate authority, a company proxy
that inspects HTTPS, an Admin API that asks for a client certificate. The tool only had `verify_tls` for the API, and
the Admin API was always checked against the public authorities, so a private certificate could not be used at all.

**Decision.** Each connection has an optional `tls` block (`verify`, `ca_bundle`, `client_cert`, `client_key`), turned
into one `ssl.SSLContext` at startup (`src/core/tls.py`).

- **Default trust:** the operating system's store, through `truststore`, plus certifi's list, as pip does since 24.2.
  A company authority installed by IT and a proxy inspecting HTTPS work without configuration, and the tool never
  trusts fewer authorities than before (a minimal container without a system store keeps working).
  `SSL_CERT_FILE` / `SSL_CERT_DIR` no longer change what the tool trusts: the configuration says it.
- **`ca_bundle` replaces the default trust** for that connection (as `curl --cacert`), so that an internal connection
  does not also trust every public authority.
- **`verify: false` is allowed but visible:** the report states for every connection how its certificate was checked
  (`connections`, `src/report/builder.py`), and a not verified one is red in the HTML report, because such a run
  cannot know it talked to the right server. `verify: false` with `ca_bundle` is a contradiction (rejected);
  with a client certificate it is allowed (`curl -k --cert`).
- **Failures:** a TLS failure is never retried; a preflight request to the API before the first test turns a
  certificate problem into one stop (exit 10) instead of an ERROR per test; on the Admin API the audits SKIP with the
  reason. Every message names the key to set. nginx-based servers (APISIX) complete the handshake without a client
  certificate and answer an HTTP 400 page: those pages are recognised too (`certificate_answer()`).
- **Private keys:** only the path is configuration; an encrypted key is refused, because Python's TLS library would
  prompt for its password and a CI job would hang; a key readable by other users gives a warning, as SSH does.
- **External TLS tools** receive `ca_bundle` (testssl.sh `--add-ca`, sslyze `custom_ca_file`) and add a note that
  trust came from it. An authority installed only in the system does not change their judgement: their job is to
  judge the certificate as clients without that authority see it.

**Alternatives left out**, each addable later without changing the shape: a password for the client key, a warning
before a certificate expires (the TLS error already names an expired one), certificate pinning, a minimum TLS version
per connection (checking versions is the tests' job), a proxy per connection, `validate-config` trying every
connection (the preflight covers the API).

**Consequences.** One new dependency (`truststore`, MIT, maintained by pip's maintainers). The external TLS tests no
longer report an untrusted chain for a private authority given in `ca_bundle` (changed results on the labs).

Sources: [httpx SSL](https://www.python-httpx.org/advanced/ssl/), [pip HTTPS
certificates](https://pip.pypa.io/en/latest/topics/https-certificates/), [truststore](https://pypi.org/project/truststore/),
[nginx error processing](https://nginx.org/en/docs/http/ngx_http_ssl_module.html#errors).

## D3. The tool downloads the specification

**Problem.** prance downloaded the specification itself, with its own HTTP client: no certificate settings, no timeout
of its own.

**Decision.** The tool downloads the specification with the settings of `specification` (`src/discovery/download.py`)
and gives the text to prance, with the URL as the base of external `$ref`. The watchdog thread around the
dereferencing stays, because prance still fetches external `$ref` itself, without a timeout: without the thread an
unresponsive host would hang the run.

**Consequences and limits.** External `$ref` with an absolute URL are fetched by prance with its defaults (no `tls`).
Relative `$ref` in a specification read from a URL were never resolved (prance's `absurl` refuses a non-file
reference, checked 2026-10-14): a multi-file specification is used from a local copy (`specification.path`), and the
error message says so. `generate-seed` uses the same download and accepts `-c` to take the configuration's
`specification`.

## D4. Labs at the highest protection level

**Problem.** The tool is meant for real systems, so its labs must exercise the paths real systems need, not only the
easy ones. The labs used a self-signed certificate committed with its private key, Admin APIs over plain HTTP, and
published Forgejo's own port for the specification download: the backend was reachable without the gateway (a
gateway bypass, CWE-288).

**Decision.**

- **One certificate authority for the three labs** (`test-environments/pki/gen-pki.sh`), generated at the first start
  of any lab by a one-shot `pki` service using the gateway's own image (it ships `openssl`: no new image), never
  committed. Leaf certificates of 180 days (the CA/Browser Forum limits public certificates to 200 days from March
  2026; testssl flags longer ones), renewed when fewer than 30 days remain, with the RFC 5280 extensions strict
  validators require (sslyze refused a chain without `keyUsage`). A lock makes two labs started together generate
  once; the files belong to the owner of the folder.
- **Each lab at the highest level its gateway offers:** every connection verified with the labs' authority; Kong's
  Admin API over HTTPS (Kong OSS has no client certificate or key for it); APISIX's Admin API over HTTPS with a
  mandatory client certificate, then the key; Admin APIs on `127.0.0.1` only. Each lab configuration says in comments
  how to lower each level.
- **No backend port:** the specification is served through the gateway (a route for `/swagger.v1.json` only), and the
  backend is reachable only through the gateway, as in production; Forgejo's `ROOT_URL` is the gateway's address.

**Consequences.** No private key in the repository. A test "the backend is reachable only through the gateway" does
not exist in the methodology: recorded as a candidate (Q-32, roadmap Ideas). Commands for the labs:
[maintainer commands](../project/maintainer-commands.md#test-labs).

## D5. A credential is obtained and sent separately

**Problem.** One setting, `auth_type`, mixed how a credential is obtained (a login) with how it is sent: every test
wrote `Authorization: Bearer`, the login methods were an `if` on a string, and Forgejo's token API was the default.

**Decision.** Two parts.

- **Obtain:** `credentials.auth_type`, required when an account or a token is configured, no default: `basic`,
  `static_token`, `login` (a [prepared resource](#d6-prepared-resources)). New methods are entries of a registry, as
  gateways have adapters.
- **Send** (the placement, `src/core/auth_placement.py`, resolved once per run before any test): from the
  specification's security schemes. One usable scheme is taken as is; with several, `security_scheme` names one
  (otherwise startup stops listing the names); with none, `send_as` (`in`, `name`) is required. `http` bearer,
  `oauth2` and `openIdConnect` are sent as `Authorization: Bearer` (RFC 6750). `basic` is always HTTP Basic (RFC
  7617).
- **A prefix with a declared `apiKey` scheme** (`send_as.prefix`): an `apiKey` scheme has no prefix field in OpenAPI,
  and APIs often describe one only in words (Forgejo: "API tokens must be prepended with "token" followed by a
  space"). Writing the prefix into the value works only for a value typed by a person, not for a token the tool
  obtains; generated clients keep a prefix per scheme too (openapi-generator `api_key_prefix`). Schemes that define
  their own format take no prefix.

**Alternatives left out.** Guessing the format from the token, or keeping `Bearer` for every API: Forgejo accepts
`Bearer` without documenting it, and an API using another scheme could not be tested at all.

**Consequences.** Breaking (`auth_type` required, `jwt_login` and `forgejo_token` replaced). OAuth 2.0 client
credentials and session cookies obtained by login are not implemented; the shape lets them be added. Mutual TLS is a
connection setting ([D2](#d2-certificate-trust-per-connection)), not an `auth_type`.

Sources: [OpenAPI 3.1 Security Scheme Object](https://spec.openapis.org/oas/v3.1.0#security-scheme-object),
[RFC 6750](https://www.rfc-editor.org/rfc/rfc6750), [RFC 7617](https://www.rfc-editor.org/rfc/rfc7617).

## D6. Prepared resources

**Problem.** Some tests need something to exist on the target first (7.2 a repository for its webhooks; 1.4 a
credential to revoke), and some APIs log in with a request. That knowledge was Forgejo code inside the tool
(`forgejo_resources.py`, `auth_forgejo.py`, a Forgejo path in 1.4).

**Decision.** One building block declared in `config.yaml` and used by name: a **prepared resource** is one create
request, values taken from its JSON response, and an optional delete request sent at teardown
(`src/tests/helpers/resources.py`, `src/core/models/resources.py`).

- **Where:** a top-level `resources` section: a resource belongs to the target, not to one test; credentials and
  tests refer to it by name, and the section shows in one place what the tool creates on the target.
- **Placeholders:** one syntax, `{...}`, for every value the tool fills (`{username}`, `{password}`, `{random}`, the
  response values in `delete`, and the values a test injects such as 7.2's `{ssrf_url}`). It is already the syntax of
  OpenAPI path parameters, and one body may hold a resource value and an injected value together. Its two costs are
  handled: a YAML value that starts with `{` is read as a mapping, so an unquoted placeholder is rejected at startup;
  literal braces are doubled. `${VAR}` (environment) stays distinct.
- **Who and how:** the test chooses the role a resource is created for; each request says how it authenticates
  (`credential`, `basic`, `none`); the role that created a resource deletes it.
- **Login on top of it:** `auth_type: login` with `login_resource`: the credential is the response value
  `credential`; a delete request, when present, deletes it at the end and lets 1.4 revoke one. 1.4 takes its check
  request from the configuration (`verify_request`); random names (`apiguard-{random}`) mean two runs never collide.
- **Secrets:** what gives access to the target (the value `credential`, passwords, Basic values) is masked; what
  explains what the tool created (names, ids) stays readable.
- **Checked at startup** (exit 10): a resource used but not defined, an unknown placeholder, a response value used
  before the response, an unquoted placeholder, a login resource without `credential`. Teardown runs in reverse
  creation order, so a repository created with a token is deleted before the token.

**Boundaries.** No chains of steps, conditions, loops or scripts; no inference from the specification. What data
cannot describe (request signing, multi-step logins) stays a method in the code registry. Prior art: the declarative
part of Nuclei extractors and Schemathesis OpenAPI links; RESTler's inference left out.

**Consequences.** No Forgejo code left in the tool; the Forgejo and crAPI logins are configuration (crAPI's in about 8
lines). Future tests that create data (2.2, 2.3, 7.3) reuse the block.

Sources: [Nuclei extractors](https://docs.projectdiscovery.io/templates/reference/extractors),
[Schemathesis stateful testing](https://schemathesis.readthedocs.io/en/stable/explanations/stateful/),
[RESTler](https://www.microsoft.com/en-us/research/publication/restler-stateful-rest-api-fuzzing).

## D7. Neutral gateway concepts

**Problem.** The configuration audits (3.3, 4.2, 4.3, 6.4 sub-test B) read Kong's objects directly: on any other
gateway they could not run.

**Decision.** The adapters expose **neutral concepts** (`src/core/gateway/concepts.py`): backend timeouts, health
checks, circuit breakers, request signing policies, routes, configuration text values, live target health. Rules:

- one reader per concept; a test asks only for what it needs;
- each reader answers **read**, **not supported** (the gateway has no such concept) or **not accessible** (it exists
  but cannot be read), with the reason; a test that cannot judge returns SKIP with that reason ("Not applicable to
  this gateway" / "Not verifiable: no access to ..."), a test that can judge only part adds an InfoNote; no new
  report status;
- a concept is read once per run and stored as evidence, configuration values masked (both Kong and APISIX return
  plugin secrets in clear through their Admin API);
- an adapter answers with the **effective** configuration: where a gateway returns only what was written, the
  adapter fills in the defaults it applies, preferably asking the running gateway (APISIX: its plugin and upstream
  schemas), so that, for example, an algorithm allowed by default is seen;
- a concept is implemented only when a test needs it (future: authentication per route, rate limiting, CORS, security
  headers, logging, listeners and TLS).
- **Access:** the Admin API takes generic headers (`gateway.admin.headers`): every gateway surveyed protects reads
  with a header (APISIX `X-API-KEY`, Kong Enterprise `Kong-Admin-Token`, Tyk `x-tyk-authorization`, Traefik
  `Authorization`), and Kong's own tools take generic headers too. A gateway that keeps live health outside its Admin
  API (APISIX's Control API) has a separate address (`gateway.health.url`), read without those headers.

**Alternatives left out.** One adapter method per Kong object (`get_plugins`, ...): every new gateway would have to
imitate Kong. The second gateway lab is APISIX, chosen because its concepts are the closest to Kong's (so the audits
can be compared), it has a real circuit breaker plugin, and its Admin API is protected by a key; its file-only
standalone mode has no Admin API, so its configuration could not be read.

**Consequences.** Adding a gateway is an adapter that maps these concepts ([add a gateway
adapter](../guides/extending/add-a-gateway-adapter.md), with the current Kong and APISIX mappings).

Sources: [Kong Admin API entities](https://developer.konghq.com/gateway/entities/service/),
[Kong health checks and circuit breakers](https://developer.konghq.com/gateway/traffic-control/health-checks-circuit-breakers/),
[APISIX Admin API](https://apisix.apache.org/docs/apisix/admin-api/),
[APISIX Control API](https://apisix.apache.org/docs/apisix/control-api/).

## See also

- [Overview](overview.md) · [Security model](security-model.md) · [Configuration reference](../reference/configuration.md)
- [`OPEN_QUESTIONS.md`](../../OPEN_QUESTIONS.md): what is still undecided

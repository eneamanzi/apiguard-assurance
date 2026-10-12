# Gateway Survey

> **Audience:** project owner, Claude Code · **Status:** working file for step 2 of block 7+8 (design of the
> neutral gateway adapter, choice of the second gateway lab), written 2026-10-11 · **Source of truth:** the official
> documentation linked in each row, read on 2026-10-11; anything not confirmed there is marked "not verified".

Purpose: before designing the neutral gateway concepts (Q-38), see how widely used gateways expose them, how their
configuration can be read, and how easily each can be run in a lab of ours.

Design decided with the owner (2026-10-11): one reader per concept in the adapter; each concept answers with a
neutral model, or "not supported by this gateway", or "not accessible" (with the reason); a concept is read once per
run, when a test first asks for it; every concept read is stored as evidence.

## 1. How the configuration is read

| Gateway | How | Protection of the read interface | Notes |
|---|---|---|---|
| **Kong** (OSS, DB-less) | Admin API, `GET /routes`, `/services`, `/upstreams`, `/plugins`, `/status` | none by default (RBAC in Kong Enterprise) | what the tool uses today |
| **Apache APISIX** | Admin API under `/apisix/admin`: `GET /routes`, `/services`, `/upstreams`, `/consumers`, `/global_rules`, `/plugin_configs`, `/plugins/list`, `/ssls`, ... [1] | **`X-API-KEY` header required** (`deployment.admin.admin_key`), plus an IP allow list; a key of role `viewer` allows GET only (APISIX source, `apisix/admin/init.lua` [13], used by the lab 2026-10-12) | in file-driven standalone mode the Admin API is off [2]; with etcd it is on |
| **Traefik** (OSS) | API, `GET /api/http/routers`, `/api/http/services`, `/api/http/middlewares`, `/api/entrypoints`, `/api/rawdata` [3] | none built in: protected by putting a router with basicAuth, forwardAuth or IP allow list in front of `api@internal` [3] | all endpoints are `GET`; read-only not stated explicitly [3] |
| **Envoy** | admin interface, `GET /config_dump` (the loaded configuration as JSON), `/clusters` (circuit breakers, outlier detection) [4] | none: "limit access to a secure network" [4]; tries to redact `private_key` and `password` [4] | output format marked not stable (v2alpha) [4] |
| **Tyk** (OSS Gateway) | Gateway API (API definitions and policies) when the Dashboard is not used [5] | shared secret in `x-tyk-authorization`; "no granular permissions system" [5] | endpoint paths in its Swagger file, not on the page read |
| **KrakenD** (CE) | the configuration file `krakend.json` only; no runtime API mentioned [6] | file access | Apache 2.0 [6] |
| **NGINX** | OSS: configuration file only; **NGINX Plus** (commercial): API, read-only by default [7] | file access / Plus API | the API is a paid feature [7] |
| **AWS API Gateway** | cloud API, e.g. `GetStage`: per-method throttling (`throttlingRateLimit`, `throttlingBurstLimit`), logging level, access log settings, client certificate, WAF ACL [8] | AWS IAM credentials | cloud only |
| **Azure API Management** | REST API, e.g. `GET .../apis/{apiId}/policies/policy` (policy XML) [9] | Azure credentials | cloud only; security settings are XML policies |

Three ways to read, then: an **admin API** (Kong, APISIX, Traefik, Envoy, Tyk, NGINX Plus), a **configuration file**
(KrakenD, NGINX OSS, APISIX standalone) and a **cloud API** (AWS, Azure). An adapter may need any of them.

A case to keep in mind (2026-10-12): **APISIX in standalone mode** cannot be audited by the current APISIX adapter.
File-driven standalone turns the Admin API off (the configuration lives in `apisix.yaml`); API-driven standalone keeps
the configuration in memory and serves only `GET/PUT /apisix/admin/configs`, the whole configuration in one block,
and its documentation warns against using it without understanding it [2][13]. On such a gateway the audits SKIP as
"not accessible"; reading `apisix.yaml` or `/configs` would be a further adapter mode, not needed now. The APISIX
lab uses the traditional mode with etcd.

## 2. Concepts of the methodology, gateway by gateway

✔ verified in the official documentation read on 2026-10-11 · ? not verified · - not offered (verified)

| Concept (tests) | Kong | APISIX | Traefik OSS | Envoy | Tyk OSS | KrakenD CE | AWS API GW |
|---|---|---|---|---|---|---|---|
| Routes (0.1 drift) | ✔ | ✔ routes [1] | ✔ routers [3] | ✔ in `config_dump` [4] | ? | ✔ endpoints in the file [6] | ? |
| Backend timeouts (4.2) | ✔ per service | ✔ upstream `timeout` connect/send/read, seconds [1] | ? | ? | ✔ enforced timeout, **per endpoint** [10] | ? | ? |
| Health checks / circuit breaking (4.3) | ✔ passive/active checks; no CB plugin in OSS | ✔ upstream `checks` [1], `api-breaker` plugin [11] | ✔ `CircuitBreaker` middleware [12] | ✔ circuit breakers, outlier detection [4] | ? | ? | - (?) |
| Request signing, HMAC (3.3) | ✔ `hmac-auth` | ✔ `hmac-auth`: `allowed_algorithms`, `clock_skew`, `signed_headers`, `validate_request_body` [11] | - (Hub only) [12] | ? | ? | ? | ? |
| Authentication per route (1.1, 2.x) | ✔ plugins | ✔ key-auth, jwt-auth, basic-auth, openid-connect, forward-auth, ... [11] | ✔ BasicAuth, DigestAuth, ForwardAuth; JWT Hub only [12] | ? | ? | ? | ? |
| Rate limiting (4.1, 0.3) | ✔ `rate-limiting` | ✔ limit-req, limit-count, limit-conn [11] | ✔ `RateLimit` [12] | ? | ? | ? | ✔ per-method throttling [8] |
| CORS (6.3) | ✔ `cors` | ✔ `cors` [11] | ? (`Headers`) | ? | ? | ? | ? |
| Security headers (6.2) | ✔ `response-transformer` | ? (response-rewrite) | ✔ `Headers` [12] | ? | ? | ? | ? |
| Logging (5.x) | ✔ log plugins | ✔ http-logger, file-logger, ... [11] | ? | ? | ? | ? | ✔ logging level, access log [8] |
| IP restriction | ✔ | ✔ `ip-restriction` [11] | ✔ `IPAllowList` [12] | ? | ? | ? | ✔ WAF ACL [8] |
| Listeners, TLS, HTTP→HTTPS (1.5) | ✔ | ✔ `ssls` [1] | ✔ entrypoints [3], `RedirectScheme` [12] | ✔ listeners [4] | ? | ? | ? |
| Installed extensions (6.3) | ✔ `/plugins` | ✔ `/plugins/list` [1] | ✔ middlewares [3] | ✔ filters in `config_dump` [4] | ? | ? | - |
| Status / metrics (4.3) | ✔ `/status` | ✔ prometheus, node-status [11] | ? | ✔ `/clusters`, stats [4] | ? | ? | ? |
| Text values to scan for secrets (6.4) | ✔ | ✔ (secrets stored encrypted, `/secrets`) [1][11] | ✔ `/api/rawdata` [3] | ✔ with partial redaction [4] | ? | ✔ the file | ? |

Readings:

- The concepts are common; their **shape** differs (timeouts per service in Kong and APISIX, per endpoint in Tyk;
  circuit breaking as a plugin in APISIX, a middleware in Traefik, a cluster setting in Envoy, absent as such in Kong
  OSS). The neutral models need a **scope** (global, backend, route) and must allow "not supported".
- Reading the configuration may need **credentials** (APISIX key, Tyk secret, cloud credentials): Q-34 is a general
  need of the adapters, not a Kong detail.
- Envoy and NGINX OSS have no gateway-level "plugins" or "consumers"; KrakenD and NGINX OSS need file access, not an
  API: "not accessible" is a normal answer.

## 3. Candidates for the second gateway lab

Requirements (owner, 2026-10-11): another case besides Kong, not necessarily one that passes; easy to deploy in our
labs; useful to prove the neutral adapter.

| Gateway | For | Against |
|---|---|---|
| **Apache APISIX** | closest concepts to Kong, so the same audits can run and be compared (timeouts, health checks, `hmac-auth` with the same parameters, a real circuit breaker plugin that Kong OSS lacks); Admin API **protected by a key**, a real case for Q-34; Apache 2.0 | its Admin API needs etcd (one more container); file-only standalone mode turns the Admin API off [2] |
| **Traefik** | very different model (routers, services, middlewares), read-only API: a strong test of "not supported" (no HMAC, no JWT in OSS); simple to run | fewer of our audits apply; its API has no protection of its own |
| Envoy | data-plane reference, many service meshes use it | not a full API gateway on its own; unstable dump format; most work for least coverage |
| Tyk OSS | full API gateway, MPL | needs Redis; read API endpoints not verified here |
| KrakenD CE | file-only: tests the "configuration file" reader | no runtime API |

Adoption (GitHub, 2026-10-11): Traefik 65,165 stars ("Application Proxy"), Kong 44,262 ("The API and AI Gateway"),
Envoy 29,063 ("edge/middle/service proxy"), APISIX 17,212 ("The Cloud-Native API Gateway"), Tyk 10,857, KrakenD CE
2,690.

**Decided (owner delegated the choice, 2026-10-11): APISIX** for the second lab, the most widely used project after
Kong among those that call themselves API gateways, Apache top-level project, actively maintained; Traefik, more
popular, is a proxy whose API-gateway features (JWT, HMAC, API keys) are in the commercial Traefik Hub.

Rationale: **APISIX** for the second lab (step 5 of the block): it changes only the gateway, its concepts map onto the
same audits, and it brings the protected Admin API case. **Traefik** as a later third case, to prove the "not
supported" path on a very different gateway. To verify when building: the official Docker images and compose
examples, the exact versions, the etcd setup.

## Sources

1. APISIX Admin API: https://apisix.apache.org/docs/apisix/admin-api/
2. APISIX deployment modes: https://apisix.apache.org/docs/apisix/deployment-modes/
3. Traefik API and dashboard: https://doc.traefik.io/traefik/reference/install-configuration/api-dashboard/
4. Envoy admin interface: https://www.envoyproxy.io/docs/envoy/latest/operations/admin
5. Tyk Gateway API: https://tyk.io/docs/tyk-gateway-api/ ; Tyk open source (MPL 2.0): https://tyk.io/docs/apim/open-source
6. KrakenD CE repository (Apache 2.0, `krakend.json`): https://github.com/krakend/krakend-ce
7. NGINX Plus API: https://docs.nginx.com/nginx/admin-guide/load-balancer/dynamic-configuration-api/
8. AWS API Gateway GetStage: https://docs.aws.amazon.com/apigateway/latest/api/API_GetStage.html
9. Azure API Management, Api Policy Get: https://learn.microsoft.com/en-us/rest/api/apimanagement/current-ga/api-policy/get
10. Tyk enforced timeouts: https://tyk.io/docs/5.12/planning-for-production/ensure-high-availability/enforced-timeouts.md
11. APISIX `hmac-auth` and plugin list: https://apisix.apache.org/docs/apisix/plugins/hmac-auth/ ; `api-breaker`:
    https://apisix.apache.org/docs/apisix/2.13/plugins/api-breaker
12. Traefik HTTP middlewares: https://doc.traefik.io/traefik/reference/routing-configuration/http/middlewares/overview/
13. APISIX 3.19.0 source, Admin API routes and roles: https://github.com/apache/apisix/blob/3.19.0/apisix/admin/init.lua

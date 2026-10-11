# Gateway Concepts

> **Audience:** project owner, Claude Code · **Status:** design in progress (step 2 of block 7+8, Q-38); each concept
> is decided with the owner before any code · **Sources:** `docs/project/gateway-survey.md` and the documentation
> linked below.

The neutral concepts the gateway adapters expose to the tests. Design rules (owner, 2026-10-11):

- one reader per concept; a test asks only for the concepts it needs;
- each reader answers with the neutral model, or **not supported** (the gateway has no such concept), or **not
  accessible** (the concept exists but cannot be read: permissions, configuration not exposed), with the reason;
- a concept is read once per run, the first time a test asks for it, and stored as evidence;
- how a test reports it (owner, 2026-10-11): PASS and FAIL only from concepts read; a test that cannot judge because
  a concept is not supported or not accessible returns SKIP, with a reason that says which ("not applicable to this
  gateway: <concept>" / "not verifiable: no access to <concept>: <why>"); a test that can judge only part adds an
  InfoNote for the rest; no new report status (a machine-readable SKIP category can be added later without breaking);
- what is stored as evidence goes through the tool's redaction (Q-31): values under secret-like keys and credentials
  found are masked as test 6.4 already does (first and last 4 characters); the evidence shows that a secret is there
  and where, never the secret (both Kong and APISIX return plugin secrets in clear through their Admin API);
- the full map of concepts is listed below; only the concepts used by a test are implemented, the others when a test
  needs them.

## Map

| Concept | Tests | Status |
|---|---|---|
| Backend timeouts | 4.2 | **decided** 2026-10-11 |
| Health checks and circuit breaking | 4.3 | **decided** 2026-10-11 |
| Request signing (HMAC) | 3.3 | **decided** 2026-10-11 |
| Configuration text values (secret scan) | 6.4 sub-test B | **decided** 2026-10-11 |
| Backend live health state | 4.3 (observability) | **decided** 2026-10-11 |
| Routes (minimal: name, paths, backend) | 3.3 (coverage), later 0.1 (documentation drift) | **decided** 2026-10-11 |
| Authentication per route | 1.1, 2.x | future |
| Rate limiting | 4.1, 0.3 | future |
| CORS, client-side timeouts | 6.3 | future |
| Security headers | 6.2 | future |
| Logging | 5.x, 0.3 | future |
| IP restriction | - | future |
| Listeners, TLS, HTTP-to-HTTPS | 1.5 | future |
| Installed extensions | 6.3 | future |

## Backend timeouts (decided 2026-10-11)

A list of timeout settings, one per place where timeouts are defined.

| Field | Meaning | Kong | APISIX |
|---|---|---|---|
| `scope` | what the values apply to: `backend` (all requests to that backend) or `route` (only that route, overriding the backend) | always `backend` (Service) | `backend` (Upstream) or `route` (Route `timeout` overrides the Upstream) |
| `name` | which backend or route, for findings and reports | Service name | Upstream or Route name or id |
| `connect_seconds` | maximum time to open the connection | `connect_timeout` / 1000 | `timeout.connect` |
| `send_seconds` | maximum time between two writes to the backend | `write_timeout` / 1000 | `timeout.send` |
| `read_seconds` | maximum time between two reads from the backend | `read_timeout` / 1000 | `timeout.read` |
| any of the three empty | not set: the gateway default applies | never (Kong returns its default, 60000 ms) | the field is optional |
| `source` | reference to the gateway's own object, for the evidence | `service <name>` | `upstream <id>` / `route <id>` |

Seconds are the common unit (Kong uses milliseconds, APISIX seconds); the test 4.2 configuration keys stay in
milliseconds (contract) and the test converts. An empty value is not zero: what 4.2 concludes from it is a question
for the test review. Sources: [Kong Service](https://developer.konghq.com/gateway/entities/service/), [APISIX Admin
API](https://apisix.apache.org/docs/apisix/admin-api/).

## Health checks and circuit breaking (decided 2026-10-11)

Two lists. An empty list means "read, nothing configured"; "not supported" is for a gateway without the concept.

**Circuit breakers**, one per configured breaker:

| Field | Meaning | Kong | APISIX `api-breaker` |
|---|---|---|---|
| `scope`, `name` | as for timeouts | from the plugin found | the Route |
| `enabled` | active or not | plugin field | plugin present |
| `failure_threshold` | failures before the circuit opens | plugin field | `unhealthy.failures` (default 3) |
| `failure_statuses` | responses counted as failures | plugin field | `unhealthy.http_statuses` (default [500]) |
| `open_seconds` | how long the circuit stays open (at most) | plugin field | `max_breaker_sec` (default 300; retries after 2, 4, 8 ... s) |
| `recovery_successes` | successes needed to close it | plugin field | `healthy.successes` (default 3) |

Kong OSS ships no circuit breaker plugin; which third-party plugin names and field names count as a breaker is Kong
knowledge and moves to the Kong adapter (today in test 4.3's configuration, whose keys stay: contract).

**Health checks**, one per backend:

| Field | Meaning | Kong and APISIX (same field names) |
|---|---|---|
| `scope`, `name` | the backend | Upstream |
| `passive` | failure thresholds observed on real traffic (HTTP failures, TCP failures, timeouts) and the statuses counted as failures | `checks.passive.unhealthy.*` (APISIX), `healthchecks.passive.unhealthy.*` (Kong) |
| `active` | periodic probe: interval for healthy and for unhealthy targets, path | `...active.*` |
| `recovers_automatically` | an excluded backend comes back by itself: only with active checks on unhealthy targets | derived: passive only = no |

`recovers_automatically` comes from Q-66: passive checks alone exclude a backend for good (Kong and APISIX
documentation). Whether test 4.3 uses it in its verdict is a question for the test review. Sources: [APISIX health
check](https://apisix.apache.org/docs/apisix/tutorials/health-check/), [APISIX
api-breaker](https://apisix.apache.org/docs/apisix/plugins/api-breaker/), [Kong health checks and circuit
breakers](https://developer.konghq.com/gateway/traffic-control/health-checks-circuit-breakers/).

## Request signing, HMAC (decided 2026-10-11)

One item per configured signing policy.

| Field | Meaning | Kong `hmac-auth` | APISIX `hmac-auth` |
|---|---|---|---|
| `scope`, `name` | where it applies: `global`, `backend` or `route` | plugin Service/Route; neither = global | plugin Route or Service |
| `enabled` | active or not | plugin field | plugin present |
| `algorithms` | allowed algorithms, standard names (`hmac-sha256` ...) | `algorithms` (default sha224, sha256, sha384, sha512; sha1 off) | `allowed_algorithms` (default sha1, sha256, sha512) |
| `replay_window_seconds` | replay window | `clock_skew` (default 300) | `clock_skew` (default 300) |
| `required_signed_headers` | headers the client must sign | `enforce_headers` (default none) | `signed_headers` (default `date`) |
| `body_signed` | the body is covered by the signature | `validate_request_body` (default false) | `validate_request_body` (default false) |

For the test review: the replay window is meaningful only if the date is signed (APISIX documentation); test 3.3
checks `clock_skew` but not the signed headers. Defaults differ: APISIX allows hmac-sha1 by default, which 3.3's
default configuration forbids. Test 3.3's coverage analysis needs the Routes concept. Sources: [Kong
hmac-auth](https://developer.konghq.com/plugins/hmac-auth/reference/), [APISIX
hmac-auth](https://apisix.apache.org/docs/apisix/plugins/hmac-auth/).

## Routes (decided 2026-10-11, minimal form)

| Field | Meaning | Kong | APISIX |
|---|---|---|---|
| `name` | route name, for reports | `name` | `name`, else the id |
| `paths` | paths the route exposes | `paths` | `uri` / `uris` |
| `methods` | allowed methods; empty = all | `methods` | `methods` (empty = all) |
| `backend` | the backend the route sends to, with the same `name` as in the other concepts | the Service | the Upstream, resolving inline `upstream`, `upstream_id` or `service_id` (a route-level upstream wins over the service's) |
| `enabled` | active or not | always | `status` (1 enabled, 0 disabled) |
| `source` | reference to the gateway's own object | `route <name>` | `route <id>` |

`backend` uses the same names as the other concepts so that test 3.3 can relate a signing policy on a backend to
the routes that send to it. For 0.1 (documentation drift, future) the concept will also have to say how a path is
matched: Kong matches path prefixes (`/api` also matches `/apiguard...`, seen on the lab), APISIX matches the full
path, and a prefix is written with a trailing `*` (`/blog/bar*`). Sources: [Kong
Route](https://developer.konghq.com/gateway/entities/route/), [APISIX Admin
API](https://apisix.apache.org/docs/apisix/admin-api/), [APISIX radixtree
router](https://apisix.apache.org/docs/apisix/router-radixtree/).

## Configuration text values (decided 2026-10-11)

A list of text values with their position, scanned by test 6.4 sub-test B for credentials written in clear.

| Field | Meaning | Kong | APISIX |
|---|---|---|---|
| `kind` | type of object: `backend`, `plugin`, `client_credential` | Service, Plugin | Upstream; plugin on Route, Service, global rule, plugin config; Consumer credential |
| `location` | which object | `service forgejo-service` | `route 5, plugin http-logger` |
| `key` | where the value is inside the object | `url`, `config.password` | `nodes`, `config.auth_header` |
| `value` | the text (never stored in the evidence unmasked) | | |

`kind` separates the credentials the gateway must keep for its clients (e.g. a consumer's HMAC key) from those it
uses itself towards other systems (credentials in a backend URL, an API key in a logging plugin), which 6.4 looks
for; whether client credentials are scanned is a question for the test review. Both gateways return secrets in
clear through their Admin API (APISIX encrypts them in etcd and decrypts them on read: its test suite,
`t/node/data_encrypt.t`). Sources: [APISIX data encryption
tests](https://apache.googlesource.com/apisix/+/refs/heads/master/t/node/data_encrypt.t), [API7 keyring
guide](https://docs.api7.ai/apisix/production/security/data-encryption-with-keyring).

## Backend live health state (decided 2026-10-11)

Answers "can an excluded backend be seen in real time?". One item per target of each backend.

| Field | Meaning | Kong | APISIX |
|---|---|---|---|
| `backend` | the backend | Upstream | Upstream |
| `target` | target address | `target` | `ip:port` |
| `state` | `healthy`, `unhealthy`, `partially_healthy`, `unknown` | `health` of `GET /upstreams/{name}/health` (seen on the labs: `HEALTHY`, `UNHEALTHY`) | `status` of the Control API `GET /v1/healthcheck` (`healthy`, `unhealthy`, `mostly_healthy`, `mostly_unhealthy`) |
| `counters` | observed successes and failures, when given | not in that response | `counter`: `success`, `http_failure`, `tcp_failure`, `timeout_failure` |

The APISIX Control API is a separate interface from the Admin API (default `127.0.0.1:9090`, no protection of its
own, "never configure the control API server to listen to public traffic"): the APISIX adapter needs its address (a
new configuration key, presented when the code is written), and without it the concept answers "not accessible".
Test 4.3 today looks for circuit-breaker keys in Kong's `/status`, which never has them, so it always reports an
observability gap although Kong exposes the backend health state; changing that verdict belongs to the test review.
Source: [APISIX Control API](https://apisix.apache.org/docs/apisix/control-api/).

## Access to the gateway's read interfaces (decided 2026-10-11, Q-34)

`target.admin_api_headers` (new configuration key): header name -> value, values from `${VAR}`, registered as secrets
(masked in logs and reports), sent on every read of the gateway. One mechanism covers the gateways surveyed (APISIX
`X-API-KEY`, Kong Enterprise `Kong-Admin-Token`, Tyk `x-tyk-authorization`, Traefik `Authorization`). The APISIX
Control API address will be a further key of the APISIX adapter, presented with its code. Admin API over TLS with a
private certificate: open in Q-34 until a lab provides a real case.


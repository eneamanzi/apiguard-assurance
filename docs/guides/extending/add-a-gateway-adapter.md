# Add a Gateway Adapter

> **Audience:** contributors · **Status:** neutral concepts since 2026-10 (only `kong` exists) · **Source of truth:**
> `src/core/gateway/base.py`, `src/core/gateway/concepts.py`, `src/core/gateway/kong.py`,
> `src/core/gateway/__init__.py` (`GATEWAY_ADAPTERS`), `src/engine.py` (Phase 3) · **Verified:** 2026-10-12

A gateway adapter gives the WHITE_BOX audit tests read-only access to the gateway's configuration. Tests use it as
`target.gateway` (`None` when no adapter is configured) and never see the gateway's own objects: they read
**neutral concepts**, and the adapter translates. Design and field mappings: [gateway
concepts](../../project/gateway-concepts.md).

## The contract (`BaseGatewayAdapter`)

| Concept reader (public, written once in the base) | Override in the adapter | Model | Used by |
|---|---|---|---|
| `backend_timeouts()` | `_read_backend_timeouts()` | `BackendTimeout` | 4.2 |
| `circuit_breakers()` | `_read_circuit_breakers()` | `CircuitBreaker` | 4.3 |
| `health_checks()` | `_read_health_checks()` | `HealthCheck` | 4.3 |
| `target_health()` | `_read_target_health()` | `TargetHealth` | 4.3 (observability) |
| `signing_policies()` | `_read_signing_policies()` | `SigningPolicy` | 3.3 |
| `routes()` | `_read_routes()` | `GatewayRoute` | 3.3 (coverage) |
| `config_values()` | `_read_config_values()` | `ConfigValue` | 6.4 sub-test B |

Plus the property `adapter_name` (short lowercase id, e.g. `"kong"`).

Each reader answers with a `ConceptRead` (`src/core/gateway/concepts.py`):

- `ConceptRead[Model].read(items)`: the items found; an empty tuple means "read, nothing configured";
- `ConceptRead[Model].not_supported(reason)`: the gateway has no such concept;
- `ConceptRead[Model].not_accessible(reason)`: it exists but cannot be read (permissions, an interface not
  configured).

Rules:

- **Override only what the gateway can serve.** A `_read_<concept>()` not overridden answers "not supported by this
  adapter"; the tests then SKIP with "Not applicable to this gateway: <concept>" or add a note.
- **Read once per run.** The public readers keep the answer for the rest of the run; one adapter instance per run.
- **Errors:** raise `GatewayAdapterError(message, path=..., status_code=...)` on a transport failure or an
  unexpected status: the base turns it into "not accessible" with the message, and the tests SKIP with "Not
  verifiable: no access to <concept>: ...".
- **Read-only.** Never change the gateway.
- **Names:** a backend has the same `name` in every concept (a route's `backend` too), so tests can relate them.
- **Secrets:** `ConfigValue.value` is a `SecretStr`; never log the values you read.
- **Protected interfaces:** send `admin_headers` (from `target.admin_api_headers`) on every request.

## Steps

1. **Implement** `src/core/gateway/<name>.py`, subclassing `BaseGatewayAdapter`, with `src/core/gateway/kong.py` as
   reference. The engine passes these keyword arguments: `admin_base_url`, `connect_timeout`, `read_timeout`,
   `admin_headers`, `signing_config` (test 3.3 configuration), `breaker_config` (test 4.3 configuration); accept and
   ignore the ones your gateway does not need.
2. **Register** it in `GATEWAY_ADAPTERS` (`src/core/gateway/__init__.py`): the configuration schema accepts its name
   and the engine builds it from there.
3. **Document:** `docs/reference/configuration.md` (`gateway_adapter` values), `docs/reference/compatibility.md`,
   and the mapping of each concept in `docs/project/gateway-concepts.md`.

## Current Kong adapter

| Concept | Admin API call | Notes |
|---|---|---|
| backend timeouts | `GET /services` | milliseconds to seconds |
| health checks | `GET /upstreams` | `healthchecks.passive` / `.active` |
| live target health | `GET /upstreams/{name}/health` | `HEALTHY` / `UNHEALTHY`, else unknown |
| routes | `GET /routes` (+ `/services` for names) | |
| circuit breakers | `GET /plugins` | plugins named in `tests.domain_4.test_4_3.accepted_cb_plugin_names`, in that order |
| signing policies | `GET /plugins` | plugins named in `tests.domain_3.test_3_3.plugin_names`, with its field names |
| configuration values | `GET /services`, `GET /plugins` | service `url` (absent in DB-less), plugin configuration strings |

Paginated (`next`), no redirects, certificate verification always on. Tested against Kong 3.9.3 in DB-less mode.

## Verify

1. `apiguard validate-config` with `target.gateway_adapter: <name>` and `target.admin_api_url` set.
2. Read every concept from a lab and compare with the gateway's own configuration.
3. Run the WHITE_BOX audits only (`execution.test_ids: ["3.3", "4.2", "4.3", "6.4"]`): no SKIP with "Gateway
   adapter not configured"; findings reflect the real configuration and point to the stored concepts
   (`evidence_ref`).
4. Make the interface unreachable (or remove its credential): the audits SKIP with "Not verifiable: no access to
   ...", 6.4 adds a note.

## See also

- [`../../architecture/overview.md`](../../architecture/overview.md#components)
- [`add-a-native-test.md`](add-a-native-test.md) (gateway access from a test)

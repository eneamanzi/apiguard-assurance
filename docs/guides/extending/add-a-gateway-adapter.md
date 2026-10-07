# Add a Gateway Adapter

> **Audience:** contributors · **Status:** v0.1.0 (only `kong` exists) · **Source of truth:**
> `src/core/gateway/base.py`, `src/core/gateway/kong.py`, `src/engine.py` (Phase 3),
> `src/config/schema/tool_config.py` (`TargetConfig`) · **Verified:** 2026-10-05

A gateway adapter gives WHITE_BOX tests read-only access to the gateway's configuration (Admin API). Tests use it
as `target.gateway`; it is `None` when no adapter is configured.

**Read this first.** The adapter interface is gateway-neutral, but the data is not: methods return the gateway's
own JSON objects, and the tests that use them (3.3, 4.2, 4.3, 6.4 sub-test B) read **Kong** field names. A new
adapter alone therefore does not make those tests work on another gateway: either it returns Kong-shaped
objects, or the tests must change. This design point is open (Q-38).

## The contract (`BaseGatewayAdapter`)

| Member | Returns | Used by |
|---|---|---|
| `adapter_name` (property) | short lowercase id, e.g. `"kong"` | logs |
| `check_connectivity()` | `bool`, must not raise | not called today |
| `get_routes()` | list of route objects | 3.3 (coverage note) |
| `get_plugins()` | list of plugin objects | 3.3, 4.3, 6.4 |
| `get_services()` | list of service objects | 3.3, 4.2, 6.4 |
| `get_upstreams()` | list of upstream objects | 4.3 |
| `get_plugin_by_name(name)` | first matching plugin or `None` | not called today |
| `get_status()` | status object | 4.3 (observability check) |

Rules:

- **Read-only.** Only reads; never change the gateway.
- **Errors:** raise `GatewayAdapterError(message, path=..., status_code=...)` on transport failure or unexpected
  status. Tests catch it and return ERROR.
- **No state:** one instance per run, shared by all tests; each call opens a short-lived connection (Kong uses
  `httpx.Client` per request, follows `next` pagination, no redirects).

## Steps

1. **Implement** `src/core/gateway/<name>.py` with a class subclassing `BaseGatewayAdapter`, using
   `src/core/gateway/kong.py` as reference. Constructor arguments used by the engine for Kong:
   `admin_base_url`, `connect_timeout`, `read_timeout`.
2. **Export** it from `src/core/gateway/__init__.py`.
3. **Accept the name in the configuration:** `TargetConfig.gateway_adapter_requires_admin_api_url` in
   `src/config/schema/tool_config.py` has `_supported = ("kong",)`; add the new name. Update the field
   description of `gateway_adapter`.
4. **Instantiate it in Phase 3** (`src/engine.py`, `_phase_3_build_contexts`), next to the existing branch:

   ```python
   gateway = None
   if config.target.gateway_adapter == "kong" and config.target.admin_api_url is not None:
       gateway = KongGatewayAdapter(
           admin_base_url=str(config.target.admin_api_url).rstrip("/"),
           connect_timeout=config.target.admin_connect_timeout_seconds,
           read_timeout=config.target.admin_read_timeout_seconds,
       )
   ```

5. **Decide how the tests read your data** (Q-38) and adapt the tests or the returned shape.
6. **Document:** `docs/reference/configuration.md` (`gateway_adapter` values), `docs/reference/compatibility.md`,
   and the affected test pages.

## Current Kong adapter

| Method | Admin API call |
|---|---|
| `get_routes()` | `GET /routes` |
| `get_plugins()` | `GET /plugins` |
| `get_services()` | `GET /services` |
| `get_upstreams()` | `GET /upstreams` |
| `get_status()` | `GET /status` |

It sends no credentials and always verifies TLS (Q-34). Tested against Kong 3.9 in DB-less mode.

## Verify

1. `apiguard validate-config` with `target.gateway_adapter: <name>` and `target.admin_api_url` set.
2. Run the WHITE_BOX audits only (`execution.test_ids: ["3.3", "4.2", "4.3", "6.4"]`) and check that they do not
   SKIP with "Gateway adapter not configured" and that their findings reflect the gateway's real configuration.
3. Stop the Admin API and check that the tests return ERROR, not FAIL.

## See also

- [`../../architecture/overview.md`](../../architecture/overview.md#components)
- [`add-a-native-test.md`](add-a-native-test.md) (gateway access from a test)

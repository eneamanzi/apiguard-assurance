"""
src/core/gateway: gateway adapter abstraction and concrete implementations.

GATEWAY_ADAPTERS is the single list of the adapters the tool offers, by the
value of gateway.adapter: the configuration schema checks the value
against it and engine.py Phase 3 builds the adapter from it. Adding a gateway
means writing its adapter and adding one entry here.
"""

from src.core.gateway.apisix import ApisixGatewayAdapter
from src.core.gateway.base import BaseGatewayAdapter, GatewayAdapterError
from src.core.gateway.kong import KongGatewayAdapter

GATEWAY_ADAPTERS: dict[str, type[BaseGatewayAdapter]] = {
    "kong": KongGatewayAdapter,
    "apisix": ApisixGatewayAdapter,
}

__all__ = [
    "GATEWAY_ADAPTERS",
    "ApisixGatewayAdapter",
    "BaseGatewayAdapter",
    "GatewayAdapterError",
    "KongGatewayAdapter",
]

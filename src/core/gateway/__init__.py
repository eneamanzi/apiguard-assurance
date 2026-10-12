"""
src/core/gateway: gateway adapter abstraction and concrete implementations.

GATEWAY_ADAPTERS is the single list of the adapters the tool offers, by the
value of target.gateway_adapter: the configuration schema checks the value
against it and engine.py Phase 3 builds the adapter from it. Adding a gateway
means writing its adapter and adding one entry here.
"""

from src.core.gateway.base import BaseGatewayAdapter, GatewayAdapterError
from src.core.gateway.kong import KongGatewayAdapter

GATEWAY_ADAPTERS: dict[str, type[KongGatewayAdapter]] = {
    "kong": KongGatewayAdapter,
}

__all__ = ["GATEWAY_ADAPTERS", "BaseGatewayAdapter", "GatewayAdapterError", "KongGatewayAdapter"]

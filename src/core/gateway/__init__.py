"""src/core/gateway — Gateway adapter abstraction and concrete implementations."""

from src.core.gateway.base import BaseGatewayAdapter, GatewayAdapterError
from src.core.gateway.kong import KongGatewayAdapter

__all__ = ["BaseGatewayAdapter", "GatewayAdapterError", "KongGatewayAdapter"]

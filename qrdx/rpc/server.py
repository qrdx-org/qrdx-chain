"""
QRDX JSON-RPC 2.0 Server

Implements the JSON-RPC 2.0 specification with support for:
- Method registration and namespacing
- Batch requests
- Error handling with standard codes
- HTTP and WebSocket transports
"""

import json
import asyncio
from typing import Any, Callable, Dict, List, Optional, Union
from dataclasses import dataclass
from enum import IntEnum

from ..logger import get_logger

logger = get_logger(__name__)


class RPCErrorCode(IntEnum):
    """Standard JSON-RPC 2.0 error codes."""
    
    # Standard errors
    PARSE_ERROR = -32700
    INVALID_REQUEST = -32600
    METHOD_NOT_FOUND = -32601
    INVALID_PARAMS = -32602
    INTERNAL_ERROR = -32603
    
    # Server errors (-32000 to -32099)
    SERVER_ERROR = -32000
    RESOURCE_NOT_FOUND = -32001
    RESOURCE_UNAVAILABLE = -32002
    TRANSACTION_REJECTED = -32003
    METHOD_NOT_SUPPORTED = -32004
    LIMIT_EXCEEDED = -32005
    
    # Ethereum-specific errors
    ACTION_NOT_ALLOWED = -32099
    EXECUTION_ERROR = -32015


@dataclass
class RPCError(Exception):
    """JSON-RPC error."""
    
    code: int
    message: str
    data: Optional[Any] = None
    
    def to_dict(self) -> dict:
        result = {
            "code": self.code,
            "message": self.message,
        }
        if self.data is not None:
            result["data"] = self.data
        return result


@dataclass
class RPCRequest:
    """JSON-RPC request."""
    
    jsonrpc: str
    method: str
    params: Union[List, Dict, None]
    id: Union[str, int, None]
    
    @classmethod
    def from_dict(cls, data: dict) -> "RPCRequest":
        return cls(
            jsonrpc=data.get("jsonrpc", "2.0"),
            method=data.get("method", ""),
            params=data.get("params"),
            id=data.get("id"),
        )
    
    @property
    def is_notification(self) -> bool:
        """Check if this is a notification (no id)."""
        return self.id is None


@dataclass
class RPCResponse:
    """JSON-RPC response."""
    
    jsonrpc: str = "2.0"
    result: Optional[Any] = None
    error: Optional[Dict] = None
    id: Union[str, int, None] = None
    
    def to_dict(self) -> dict:
        response = {"jsonrpc": self.jsonrpc, "id": self.id}
        if self.error is not None:
            response["error"] = self.error
        else:
            response["result"] = self.result
        return response
    
    def to_json(self) -> str:
        return json.dumps(self.to_dict())


# Type for RPC method handlers
RPCMethod = Callable[..., Any]


class RPCModule:
    """
    Base class for RPC modules.
    
    Subclass this to create method namespaces like eth_, net_, etc.
    """
    
    # Namespace prefix (e.g., "eth", "net")
    namespace: str = ""
    
    def __init__(self, context: Any = None):
        """
        Initialize module with optional context.
        
        Args:
            context: Application context (database, chain, etc.)
        """
        self.context = context
    
    def get_methods(self) -> Dict[str, RPCMethod]:
        """
        Get all public methods in this module.
        
        Methods starting with underscore are private.
        
        Returns:
            Dict mapping method names to callables
        """
        methods = {}
        for name in dir(self):
            if name.startswith("_"):
                continue
            attr = getattr(self, name)
            if callable(attr) and hasattr(attr, "__rpc_method__"):
                full_name = f"{self.namespace}_{name}" if self.namespace else name
                methods[full_name] = attr
        return methods


def rpc_method(func: RPCMethod) -> RPCMethod:
    """
    Decorator to mark a method as an RPC endpoint.
    
    Usage:
        @rpc_method
        async def getBlockNumber(self) -> int:
            return await self.context.chain.get_block_number()
    """
    func.__rpc_method__ = True
    return func


class RPCServer:
    """
    JSON-RPC 2.0 server.
    
    Manages method registration and request handling.
    Can be used with HTTP or WebSocket transports.
    """
    
    def __init__(self):
        self._methods: Dict[str, RPCMethod] = {}
        self._modules: Dict[str, RPCModule] = {}
    
    def register_method(self, name: str, handler: RPCMethod):
        """
        Register a single RPC method.
        
        Args:
            name: Method name (e.g., "eth_blockNumber")
            handler: Async function to handle the method
        """
        self._methods[name] = handler
        logger.debug(f"Registered RPC method: {name}")
    
    def register_module(self, module: RPCModule):
        """
        Register an RPC module.
        
        Args:
            module: RPCModule instance
        """
        methods = module.get_methods()
        self._methods.update(methods)
        self._modules[module.namespace] = module
        logger.info(f"Registered RPC module: {module.namespace} ({len(methods)} methods)")
    
    def unregister_module(self, namespace: str):
        """
        Unregister an RPC module.
        
        Args:
            namespace: Module namespace to remove
        """
        if namespace in self._modules:
            module = self._modules.pop(namespace)
            for name in module.get_methods():
                self._methods.pop(name, None)
            logger.info(f"Unregistered RPC module: {namespace}")
    
    def get_methods(self) -> List[str]:
        """Get list of registered method names."""
        return list(self._methods.keys())
    
    async def handle_request(self, data: Union[str, bytes, dict]) -> Optional[str]:
        """
        Handle a JSON-RPC request.
        
        Args:
            data: Request data (JSON string or dict)
            
        Returns:
            JSON response string, or None for notifications
        """
        # Parse request
        try:
            if isinstance(data, (str, bytes)):
                parsed = json.loads(data)
            else:
                parsed = data
        except json.JSONDecodeError as e:
            error = RPCError(RPCErrorCode.PARSE_ERROR, f"Parse error: {e}")
            return RPCResponse(error=error.to_dict()).to_json()
        
        # Handle batch request
        if isinstance(parsed, list):
            if not parsed:
                error = RPCError(RPCErrorCode.INVALID_REQUEST, "Empty batch")
                return RPCResponse(error=error.to_dict()).to_json()
            
            responses = await asyncio.gather(*[
                self._handle_single(req) for req in parsed
            ])
            
            # Filter out None responses (notifications)
            responses = [r for r in responses if r is not None]
            if not responses:
                return None
            return json.dumps(responses)
        
        # Handle single request
        response = await self._handle_single(parsed)
        if response is None:
            return None
        return json.dumps(response)
    
    async def _handle_single(self, data: dict) -> Optional[dict]:
        """Handle a single request and return response dict."""
        try:
            request = RPCRequest.from_dict(data)
        except Exception:
            return RPCResponse(
                error=RPCError(RPCErrorCode.INVALID_REQUEST, "Invalid request").to_dict()
            ).to_dict()
        
        # Validate request
        if request.jsonrpc != "2.0":
            return RPCResponse(
                id=request.id,
                error=RPCError(RPCErrorCode.INVALID_REQUEST, "Invalid JSON-RPC version").to_dict()
            ).to_dict()
        
        if not request.method:
            return RPCResponse(
                id=request.id,
                error=RPCError(RPCErrorCode.INVALID_REQUEST, "Missing method").to_dict()
            ).to_dict()
        
        # Find method
        handler = self._methods.get(request.method)
        if handler is None:
            if request.is_notification:
                return None
            return RPCResponse(
                id=request.id,
                error=RPCError(
                    RPCErrorCode.METHOD_NOT_FOUND,
                    f"Method not found: {request.method}"
                ).to_dict()
            ).to_dict()
        
        # Execute method
        try:
            # Convert params to args/kwargs
            if request.params is None:
                result = await handler()
            elif isinstance(request.params, list):
                result = await handler(*request.params)
            elif isinstance(request.params, dict):
                result = await handler(**request.params)
            else:
                raise RPCError(RPCErrorCode.INVALID_PARAMS, "Invalid params type")
            
            if request.is_notification:
                return None
            
            return RPCResponse(id=request.id, result=result).to_dict()
            
        except RPCError as e:
            if request.is_notification:
                return None
            return RPCResponse(id=request.id, error=e.to_dict()).to_dict()
            
        except Exception as e:
            logger.exception(f"Error handling RPC method {request.method}")
            if request.is_notification:
                return None
            return RPCResponse(
                id=request.id,
                error=RPCError(RPCErrorCode.INTERNAL_ERROR, str(e)).to_dict()
            ).to_dict()

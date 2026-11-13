"""
QRDX JSON-RPC 2.0 Server

Implements the JSON-RPC 2.0 specification with support for:
- Method registration and namespacing
- Batch requests
- Error handling with standard codes
- HTTP and WebSocket transports
"""

import asyncio
import json
import time
from contextvars import ContextVar
from dataclasses import dataclass
from enum import IntEnum
from typing import Any, Callable, Dict, List, Optional, Tuple, Union

from .. import fastjson
from ..logger import get_logger

logger = get_logger(__name__)

# The peer node behind the JSON-RPC request being handled — its signature verified by the
# HTTP endpoint (qrdx/node/main.py rpc_endpoint) — or None for an unsigned request.
rpc_caller: ContextVar[Optional[str]] = ContextVar("rpc_caller", default=None)
# What the verified caller's request said of it — its key, advertised URL and address (the
# HTTP endpoint sets it): a handshake admits the caller as a peer with them.
rpc_caller_meta: ContextVar[Optional[Dict[str, Any]]] = ContextVar("rpc_caller_meta", default=None)

# Best-effort metrics recording into the shared observability registry (imports only stdlib, so no
# cycle). Falls back to a no-op so RPC handling never depends on observability being importable.
try:
    from ..node.observability import record as _metric
except Exception:  # pragma: no cover

    def _metric(name: str, amount: float = 1.0, labels: Optional[Dict[str, Any]] = None) -> None:
        return None


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
        response: Dict[str, Any] = {"jsonrpc": self.jsonrpc, "id": self.id}
        if self.error is not None:
            response["error"] = self.error
        else:
            response["result"] = self.result
        return response

    def to_json(self) -> str:
        return fastjson.dumps(self.to_dict())


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


def _mark(func: Callable[..., Any], *flags: str) -> None:
    """Flag a function for the RPC registry, which reads the flags back with getattr()."""
    for flag in flags:
        setattr(func, flag, True)


def peer_only(func: RPCMethod) -> RPCMethod:
    """Mark an RPC method as callable only by a verified peer node: one that hands this node
    data to act on, or establishes who a peer is. The server refuses it unless the request was
    signed by a node (``rpc_caller`` is set). Apply under ``@rpc_method``."""
    _mark(func, "__rpc_peer_only__")
    return func


def batched_by(name: str) -> Callable[[RPCMethod], RPCMethod]:
    """Mark an RPC method as having a form for many calls at once: the module's method ``name``,
    given each call's params (a list each), returning each call's result, or an ``RPCError``, or
    ``NotImplemented`` for a call it does not take (which then runs alone, as any call). The
    server runs a JSON-RPC batch's calls of the method through it together. Apply under
    ``@rpc_method``."""

    def mark(func: RPCMethod) -> RPCMethod:
        func.__rpc_batch__ = name  # type: ignore[attr-defined]
        return func

    return mark


def rpc_method(func: RPCMethod) -> RPCMethod:
    """
    Decorator to mark a method as an RPC endpoint.

    Usage:
        @rpc_method
        async def getBlockNumber(self) -> int:
            return await self.context.chain.get_block_number()
    """
    _mark(func, "__rpc_method__")
    return func


def rpc_admin_method(func: RPCMethod) -> RPCMethod:
    """
    Decorator to mark an RPC method as admin-only.

    Admin methods require an ``admin_token`` parameter that must match
    the ``QRDX_RPC_ADMIN_TOKEN`` environment variable.  If the env var
    is not set, admin methods are disabled entirely.

    Usage:
        @rpc_admin_method
        async def addPeer(self, uri: str, admin_token: str = "") -> bool:
            ...
    """
    import functools
    import os

    @functools.wraps(func)
    async def wrapper(self, *args, admin_token: str = "", **kwargs):
        expected = os.environ.get("QRDX_RPC_ADMIN_TOKEN", "")
        if not expected:
            from .server import RPCError, RPCErrorCode  # deferred to avoid circular

            raise RPCError(
                RPCErrorCode.METHOD_NOT_FOUND,
                "Admin methods are disabled (QRDX_RPC_ADMIN_TOKEN not set)",
            )
        if not admin_token or admin_token != expected:
            from .server import RPCError, RPCErrorCode

            raise RPCError(
                RPCErrorCode.INVALID_PARAMS,
                "Invalid or missing admin_token",
            )
        return await func(self, *args, **kwargs)

    _mark(wrapper, "__rpc_method__", "__rpc_admin__")
    return wrapper


# The most calls one JSON-RPC batch may hold.
MAX_BATCH_SIZE = 100


class RPCRateLimiter:
    """
    Token-bucket rate limiter for JSON-RPC requests: per client, and in two global pools, one
    for this node's peers and one for everyone else.

    A request takes its client's token first and a global one only if it has one. It used to take
    the global token first: one IP flooding past its own limit still drained the global budget,
    and the node's peers (blocks, votes, transactions) were refused with everyone else
    (integration_tests/adversarial.py, the flood). Peers now draw on a pool of their own, which
    public traffic cannot reach.

    A peer's own limit is ``per_peer_rps``, not the public ``per_client_rps``. Peers gossip
    every transaction to each other, a call each, so a peer's traffic grows with the chain's:
    held to the public 50 a second, gossip was refused from about 50 transactions a second, and
    with it the peer's blocks and votes (docs/PERFORMANCE.md).
    Thread-safe via asyncio lock.
    """

    def __init__(
        self,
        per_client_rps: int = 50,
        global_rps: int = 500,
        burst_multiplier: float = 2.0,
        peer_rps: Optional[int] = None,
        per_peer_rps: Optional[int] = None,
    ):
        self.per_client_rps = per_client_rps
        self.global_rps = global_rps
        self.peer_rps = global_rps if peer_rps is None else peer_rps  # all peers together
        self.per_peer_rps = per_client_rps if per_peer_rps is None else per_peer_rps
        self.burst_multiplier = burst_multiplier
        self._clients: Dict[str, Dict[str, float]] = {}  # (made at the caller's rate)
        now = time.monotonic()
        self._pools: Dict[bool, Dict[str, float]] = {
            False: {"tokens": global_rps * burst_multiplier, "last": now},
            True: {"tokens": self.peer_rps * burst_multiplier, "last": now},
        }
        self._lock = asyncio.Lock()

    @property
    def _global_tokens(self) -> float:  # (the public pool, as before)
        return self._pools[False]["tokens"]

    @staticmethod
    def _refill(bucket: Dict[str, float], rate: float, cap: float, now: float) -> None:
        bucket["tokens"] = min(cap, bucket["tokens"] + (now - bucket["last"]) * rate)
        bucket["last"] = now

    async def check(self, client_id: str = "anonymous", peer: bool = False, cost: int = 1) -> bool:
        """
        Check if ``cost`` requests from client_id are allowed (``peer``: one of this node's
        peers; a batch costs one a call).

        Returns True if allowed, False if rate-limited.
        """
        async with self._lock:
            now = time.monotonic()
            own = self.per_peer_rps if peer else self.per_client_rps
            bucket = self._clients.get(client_id)
            if bucket is None:
                bucket = self._clients[client_id] = {
                    "tokens": own * self.burst_multiplier,
                    "last": now,
                }
            self._refill(bucket, own, own * self.burst_multiplier, now)
            if bucket["tokens"] < cost:
                return False
            rate = self.peer_rps if peer else self.global_rps
            pool = self._pools[peer]
            self._refill(pool, rate, rate * self.burst_multiplier, now)
            if pool["tokens"] < cost:
                return False
            bucket["tokens"] -= cost
            pool["tokens"] -= cost
            return True

    def cleanup(self, max_age: float = 600.0) -> int:
        """Remove stale client buckets older than max_age seconds."""
        now = time.monotonic()
        stale = [k for k, v in self._clients.items() if now - v["last"] > max_age]
        for k in stale:
            del self._clients[k]
        return len(stale)


class RPCServer:
    """
    JSON-RPC 2.0 server.

    Manages method registration and request handling.
    Can be used with HTTP or WebSocket transports.
    Includes built-in rate limiting per client and globally.
    """

    def __init__(
        self,
        rate_limit: bool = True,
        per_client_rps: int = 50,
        global_rps: int = 500,
        peer_rps: Optional[int] = None,
        per_peer_rps: Optional[int] = None,
    ):
        self._methods: Dict[str, RPCMethod] = {}
        self._modules: Dict[str, RPCModule] = {}
        self._rate_limiter: Optional[RPCRateLimiter] = (
            RPCRateLimiter(
                per_client_rps=per_client_rps,
                global_rps=global_rps,
                peer_rps=peer_rps,
                per_peer_rps=per_peer_rps,
            )
            if rate_limit
            else None
        )

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

    def peer_only_methods(self) -> List[str]:
        """The registered methods only a verified peer node may call."""
        return sorted(n for n, h in self._methods.items() if getattr(h, "__rpc_peer_only__", False))

    def get_methods(self) -> List[str]:
        """Get list of registered method names."""
        return list(self._methods.keys())

    async def handle_request(
        self,
        data: Union[str, bytes, dict, list],
        client_id: str = "anonymous",
        peer: bool = False,
    ) -> Optional[str]:
        """
        Handle a JSON-RPC request.

        Args:
            data: Request data (JSON string or dict)
            client_id: Client identifier for rate limiting (e.g. IP address)
            peer: the caller is one of this node's peers (its own global pool)

        Returns:
            JSON response string, or None for notifications
        """
        # Rate limit check
        if self._rate_limiter is not None:
            if not await self._rate_limiter.check(client_id, peer=peer):
                _metric("qrdx_rpc_ratelimited_total")
                error = RPCError(RPCErrorCode.LIMIT_EXCEEDED, "Rate limit exceeded")
                return RPCResponse(error=error.to_dict()).to_json()
        # Parse request
        try:
            if isinstance(data, (str, bytes)):
                parsed = fastjson.loads(data)
            else:
                parsed = data
        except json.JSONDecodeError as e:
            error = RPCError(RPCErrorCode.PARSE_ERROR, f"Parse error: {e}")
            return RPCResponse(error=error.to_dict()).to_json()

        # Handle batch request. Its calls run at once, so it is capped, and each costs what a
        # request does: a batch used to cost one, whatever it held, and was any size.
        if isinstance(parsed, list):
            if not parsed:
                error = RPCError(RPCErrorCode.INVALID_REQUEST, "Empty batch")
                return RPCResponse(error=error.to_dict()).to_json()
            if len(parsed) > MAX_BATCH_SIZE:
                error = RPCError(
                    RPCErrorCode.INVALID_REQUEST, f"A batch holds at most {MAX_BATCH_SIZE} calls"
                )
                return RPCResponse(error=error.to_dict()).to_json()
            if self._rate_limiter is not None and len(parsed) > 1:
                if not await self._rate_limiter.check(client_id, peer=peer, cost=len(parsed) - 1):
                    _metric("qrdx_rpc_ratelimited_total")
                    error = RPCError(RPCErrorCode.LIMIT_EXCEEDED, "Rate limit exceeded")
                    return RPCResponse(error=error.to_dict()).to_json()

            responses = await self._handle_batch(parsed)

            # Filter out None responses (notifications)
            responses = [r for r in responses if r is not None]
            if not responses:
                return None
            return fastjson.dumps(responses)

        # Handle single request
        response = await self._handle_single(parsed)
        if response is None:
            return None
        return fastjson.dumps(response)

    async def _handle_batch(self, parsed: List[Any]) -> List[Optional[dict]]:
        """A batch's responses, in its order. The calls of a method with a form for many
        (``batched_by``) go through it together; every other call runs as it would alone."""
        responses: List[Optional[dict]] = [None] * len(parsed)
        groups: Dict[str, List[Tuple[int, RPCRequest]]] = {}
        alone: List[int] = []
        for i, data in enumerate(parsed):
            try:
                request = RPCRequest.from_dict(data)
            except Exception:
                alone.append(i)
                continue
            handler = self._methods.get(request.method) if request.method else None
            if (
                handler is not None
                and getattr(handler, "__rpc_batch__", None)
                and not getattr(handler, "__rpc_peer_only__", False)
                and request.jsonrpc == "2.0"
                and isinstance(request.params, list)
            ):
                groups.setdefault(request.method, []).append((i, request))
            else:
                alone.append(i)

        async def together(method: str, calls: List[Tuple[int, RPCRequest]]) -> None:
            handler: Any = self._methods[method]
            many = getattr(handler.__self__, handler.__rpc_batch__)
            for _ in calls:
                _metric("qrdx_rpc_requests_total", labels={"method": method})
            try:
                outcomes = await many([list(r.params or []) for _, r in calls])
            except Exception as e:
                logger.exception(f"Error handling RPC method {method}")
                outcomes = [RPCError(RPCErrorCode.INTERNAL_ERROR, str(e))] * len(calls)
            for (i, request), outcome in zip(calls, outcomes, strict=True):
                if outcome is NotImplemented:
                    responses[i] = await self._handle_single(parsed[i])
                    continue
                if isinstance(outcome, RPCError):
                    _metric("qrdx_rpc_errors_total", labels={"method": method})
                if request.is_notification:
                    continue
                responses[i] = (
                    RPCResponse(id=request.id, error=outcome.to_dict()).to_dict()
                    if isinstance(outcome, RPCError)
                    else RPCResponse(id=request.id, result=outcome).to_dict()
                )

        async def single(i: int) -> None:
            responses[i] = await self._handle_single(parsed[i])

        await asyncio.gather(
            *[together(m, calls) for m, calls in groups.items()], *[single(i) for i in alone]
        )
        return responses

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
                error=RPCError(RPCErrorCode.INVALID_REQUEST, "Invalid JSON-RPC version").to_dict(),
            ).to_dict()

        if not request.method:
            return RPCResponse(
                id=request.id,
                error=RPCError(RPCErrorCode.INVALID_REQUEST, "Missing method").to_dict(),
            ).to_dict()

        # Find method
        handler = self._methods.get(request.method)
        if handler is None:
            # Fixed label — the requested method is unregistered/arbitrary, so never label by it
            # (unbounded cardinality); count under "_unknown".
            _metric("qrdx_rpc_requests_total", labels={"method": "_unknown"})
            _metric("qrdx_rpc_errors_total", labels={"method": "_unknown"})
            if request.is_notification:
                return None
            return RPCResponse(
                id=request.id,
                error=RPCError(
                    RPCErrorCode.METHOD_NOT_FOUND, f"Method not found: {request.method}"
                ).to_dict(),
            ).to_dict()

        # request.method is a REGISTERED method here → bounded label cardinality.
        _metric("qrdx_rpc_requests_total", labels={"method": request.method})

        # A peer-only method runs only for a verified peer node, whatever transport carried it.
        if getattr(handler, "__rpc_peer_only__", False) and rpc_caller.get() is None:
            _metric("qrdx_rpc_errors_total", labels={"method": request.method})
            if request.is_notification:
                return None
            return RPCResponse(
                id=request.id,
                error=RPCError(
                    RPCErrorCode.ACTION_NOT_ALLOWED,
                    "this method must be called by a peer node (signed request)",
                ).to_dict(),
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
            _metric("qrdx_rpc_errors_total", labels={"method": request.method})
            if request.is_notification:
                return None
            return RPCResponse(id=request.id, error=e.to_dict()).to_dict()

        except Exception as e:
            _metric("qrdx_rpc_errors_total", labels={"method": request.method})
            logger.exception(f"Error handling RPC method {request.method}")
            if request.is_notification:
                return None
            return RPCResponse(
                id=request.id, error=RPCError(RPCErrorCode.INTERNAL_ERROR, str(e)).to_dict()
            ).to_dict()
